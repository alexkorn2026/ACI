"""Vorverarbeitung von Quellcode - Aufsatz auf den ACI-Lexer.

Die Klasse :class:`Source` bündelt für eine Datei alles, was die Checks
benötigen. Die eigentliche lexikalische Analyse (Kommentare, Strings,
Dollar-Quotes, Statement-Grenzen, dynamische SQL-Ausführungen) leistet
das Modul :mod:`aci.lexer`; :class:`Source` reicht die Ergebnisse durch
und ergänzt Zeilen-/Spalten- und Kontext-Hilfen.

Bereitgestellt werden insbesondere zwei aufbereitete Code-Varianten:

* ``code_no_comments`` - Kommentare durch Leerzeichen ersetzt,
  String-Literale bleiben erhalten.
* ``code_masked``      - zusätzlich der *Inhalt* von String-Literalen
  durch Leerzeichen ersetzt (die Begrenzer bleiben stehen).

Beide Varianten sind exakt so lang wie das Original; Zeichen-Offsets
sind daher in allen Varianten identisch.

Neu (parsergestützt) sind die strukturierten Felder ``tokens``,
``statements`` und ``dynamic_sql``.
"""

from __future__ import annotations

import bisect

from .lexer import lex, StringSpan   # StringSpan: rückwärtskompatibler Re-Export
from .parser import parse_ir
from .ir import line_starts

__all__ = ["Source", "StringSpan"]


class Source:
    """Aufbereiteter Quelltext einer einzelnen Datei."""

    def __init__(self, text: str, filename: str, dialect: str = "oracle",
                 scan_root: "str | None" = None):
        self.text = text
        self.filename = filename
        # Wurzelverzeichnis des Scans - Grundlage des repo-relativen
        # Pfades im Finding-Fingerabdruck (None = unbekannt).
        self.scan_root = scan_root
        self.dialect = (dialect or "oracle").lower()
        # Zeilen-Offsets fuer die spaetere Offset->(Zeile,Spalte)-Umrechnung.
        self._line_starts = line_starts(text)

        # Lexikalische Analyse durch den Lexer.
        result = lex(text, self.dialect)
        self.lex_result = result
        self.code_no_comments = result.code_no_comments
        self.code_masked = result.code_masked
        self.string_spans = result.string_spans
        # Strukturierte Parser-Schicht (für künftige, parsergestützte Checks).
        self.tokens = result.tokens
        self.statements = result.statements
        # Sortierter Vektor der Statement-Startoffsets fuer bisect-basierte
        # O(log n)-Suche in ``statement_start_before``/``statement_end_after``.
        # Wichtig bei sehr grossen Dateien (z.B. Schema-Dumps mit tausenden
        # Statements): die naive lineare Suche pro Fund waere quadratisch.
        self._stmt_starts = [st.start for st in self.statements]
        self.dynamic_sql = result.dynamic_sql
        self.routines = result.routines
        self.assignments = result.assignments
        # Lightweight Parser/IR layer. Existing lexer-backed attributes stay
        # available for compatibility; selected checks use the IR helpers for
        # routine-/position-sensitive analysis. Das bereits berechnete
        # Lex-Ergebnis wird durchgereicht, damit dieselbe Datei nicht ein
        # zweites Mal lexikalisch analysiert wird.
        self.ir = parse_ir(text, self.dialect, lexed=result)
        # Lazily aufgebauter Index Ziel -> Zuweisungen (siehe
        # assignments_for); vermeidet wiederholte Volltext-Scans.
        self._assign_index: "dict | None" = None

    # ------------------------------------------------------------------
    # Zeilen-/Spaltenberechnung
    # ------------------------------------------------------------------
    def line_col(self, offset: int):
        """Rechnet einen Zeichen-Offset in (Zeile, Spalte) um (1-basiert)."""
        offset = max(0, min(offset, len(self.text)))
        line_idx = bisect.bisect_right(self._line_starts, offset) - 1
        if line_idx < 0:
            line_idx = 0
        col = offset - self._line_starts[line_idx]
        return line_idx + 1, col + 1

    def line_text(self, line: int) -> str:
        """Gibt den Text der angegebenen Zeile zurück (1-basiert)."""
        if line < 1 or line > len(self._line_starts):
            return ""
        start = self._line_starts[line - 1]
        end = self.text.find("\n", start)
        if end == -1:
            end = len(self.text)
        return self.text[start:end].rstrip("\r")

    def _statement_index_for(self, offset: int) -> "int | None":
        """Index des Statements in ``self.statements``, das ``offset`` enthaelt.

        Bisect-basiert: O(log n) statt linear. Wichtig bei grossen Dateien
        (z.B. Schema-Dumps mit tausenden Statements und ebenso vielen
        Findings) - die zuvor lineare Suche pro Fund war quadratisch und
        konnte einen Scan effektiv zum Stillstand bringen.
        """
        # bisect_right gibt den ersten Index, dessen ``stmt.start > offset``
        # ist; der Kandidat fuer "enthaelt offset" liegt eins davor.
        idx = bisect.bisect_right(self._stmt_starts, offset) - 1
        if idx < 0:
            return None
        stmt = self.statements[idx]
        if stmt.start <= offset < stmt.end:
            return idx
        return None

    def statement_start_before(self, offset: int) -> "int | None":
        """Anfangsposition des Statements, das ``offset`` enthaelt.

        Verwendet die vom Lexer berechneten Statement-Grenzen
        (``self.statements``); dort sind sowohl ``;`` als auch ``/`` auf
        eigener Zeile als Terminator beruecksichtigt. Geeignet, um den
        Statement-Anfang verlaesslich zu finden - auch wenn das vorherige
        Statement mit ``/`` statt mit ``;`` endete.

        Liefert die Startposition oder ``None``, wenn der Offset in keinem
        Statement liegt.
        """
        idx = self._statement_index_for(offset)
        return self.statements[idx].start if idx is not None else None

    def statement_end_after(self, offset: int) -> "int | None":
        """Endposition des Statements, das ``offset`` enthaelt.

        Verwendet die vom Lexer berechneten Statement-Grenzen
        (``self.statements``); dort sind sowohl ``;`` als auch ``/`` auf
        eigener Zeile als Terminator beruecksichtigt. Geeignet, um
        Snippet- und Kontext-Bereiche eines Findings auf den Umfang seiner
        Anweisung zu begrenzen - auch wenn diese mit ``/`` (SQL*Plus)
        statt mit ``;`` abschliesst.

        Liefert die Endposition (exklusiv) oder ``None``, wenn kein
        Statement gefunden wurde (z.B. Skriptfragment ohne Terminator).
        """
        idx = self._statement_index_for(offset)
        return self.statements[idx].end if idx is not None else None

    def snippet(self, offset: int, max_len: int = 200) -> str:
        """Gekürzter Ausschnitt der Codezeile am angegebenen Offset."""
        line, _ = self.line_col(offset)
        txt = self.line_text(line).strip()
        if len(txt) > max_len:
            txt = txt[: max_len - 3] + "..."
        return txt

    def context_lines(self, offset: int, before: int = 3, after: int = 3,
                      max_len: int = 200):
        """Liefert die Codezeilen rund um eine Fundstelle.

        Rückgabe: Liste von ``(Zeilennummer, Zeilentext, ist_Fundzeile)``
        für ``before`` Zeilen davor bis ``after`` Zeilen danach.
        """
        line, _ = self.line_col(offset)
        last = len(self._line_starts)
        result = []
        for ln in range(max(1, line - before), min(last, line + after) + 1):
            txt = self.line_text(ln)
            if len(txt) > max_len:
                txt = txt[: max_len - 3] + "..."
            result.append((ln, txt, ln == line))
        return result

    # ------------------------------------------------------------------
    # Zugriff auf String-Literale
    # ------------------------------------------------------------------
    def string_content(self, span: StringSpan) -> str:
        """Liefert den (rohen) Inhalt eines String-Literals."""
        return self.text[span.content_start:span.content_end]

    def statement_text(self, statement) -> str:
        """Liefert den Quelltext eines (lexikalischen) Statements."""
        return self.text[statement.start:statement.end]

    def routine_at(self, offset: int):
        """Liefert die Routine, die den Offset enthält (oder ``None``)."""
        for routine in self.routines:
            if routine.start <= offset < routine.end:
                return routine
        return None

    def assignments_for(self, target: str):
        """Liefert alle Zuweisungen an ein Ziel (case-insensitiv).

        Der Index wird beim ersten Aufruf einmalig aufgebaut - so
        entfällt der wiederholte Volltext-Scan, wenn Checks die
        Zuweisungen vieler Variablen nachschlagen.
        """
        if self._assign_index is None:
            index: dict = {}
            for a in self.assignments:
                index.setdefault(a.target.upper(), []).append(a)
            self._assign_index = index
        return self._assign_index.get(target.upper(), ())
