"""Gemeinsame Grundlage der ACI-Checks.

Enthält die Basisklasse :class:`Check` (Finding-Erzeugung, Kontext- und
Taint-Quellen-Steuerung) sowie die von mehreren Checks genutzten
Hilfsfunktionen und Regexe.
"""

from __future__ import annotations

import re
from functools import lru_cache

from ..finding import (Finding, RelatedLocation, Severity,
                       GROUP_SECURITY, compute_fingerprint,
                       stable_relative_path)
from ..source import Source
from ..ir import assignments_before as ir_assignments_before
from ..ir import IRConcat, routine_for_offset
from ..parser import parse_expression


# ----------------------------------------------------------------------
# Gemeinsame Hilfsfunktionen
# ----------------------------------------------------------------------

_IDENT = r'(?:"[^"\n]+"|[A-Za-z_][\w$#]*)'

# Regex-Fragment der gängigen SQL-/PL-Datentyp-Schlüsselworte. Von der
# Namens-Deklarationserkennung (lexical) und einem Detektor genutzt.
_DATATYPES = (
    r"VARCHAR2|NVARCHAR2|VARCHAR|NCHAR|CHARACTER|CHAR|NUMBER|NUMERIC|"
    r"DECIMAL|DEC|INTEGER|INT|SMALLINT|BIGINT|FLOAT|REAL|"
    r"DOUBLE\s+PRECISION|BINARY_FLOAT|BINARY_DOUBLE|BINARY_INTEGER|"
    r"PLS_INTEGER|SIMPLE_INTEGER|BOOLEAN|BOOL|DATE|TIMESTAMPTZ|TIMESTAMP|"
    r"INTERVAL|CLOB|NCLOB|BLOB|BFILE|LONG|RAW|ROWID|UROWID|XMLTYPE|"
    r"JSONB|JSON|UUID|BYTEA|TEXT|MONEY|BIGSERIAL|SERIAL|SYS_REFCURSOR"
)


@lru_cache(maxsize=4096)
def _split_concat(expr: str):
    """Zerlegt einen Ausdruck an den ``||``-Operatoren der obersten Ebene.

    Die Zerlegung stammt aus der Expression-IR
    (:func:`aci.parser.parse_expression`): ist der Ausdruck eine
    Top-Level-Konkatenation, werden die Teile des ``IRConcat``-Knotens
    geliefert, sonst der Ausdruck als einziges Element. Operatoren
    innerhalb von String-Literalen oder Klammern bleiben dabei - wie vom
    IR-Parser vorgesehen - unangetastet. Das Ergebnis wird gecacht
    (reine Funktion).
    """
    node = parse_expression(expr)
    if isinstance(node, IRConcat):
        return tuple(part.text for part in node.parts)
    return (expr,)


def _classify_operand(operand: str, sanitizers: list[str]) -> str:
    """Klassifiziert einen Konkatenations-Operanden.

    Rückgabe: ``literal`` (Konstante), ``sanitized`` (durch eine
    Schutzfunktion bereinigt), ``tainted`` (variable/ungeprüft) oder
    ``empty``.
    """
    op = operand.strip()
    if not op:
        return "empty"
    low = op.lower()
    if op.startswith("'") or re.match(r"^[nN]?[qQ]'", op):
        return "literal"
    # PostgreSQL-Dollar-Quote-Literal ($tag$...$tag$): ein konstanter
    # String, kein getainteter Wert. Ohne diese Erkennung wuerde ein
    # Dollar-Quote-Operand als ``tainted`` gewertet (False Positive).
    if op.startswith("$"):
        m = re.match(r"^\$(?:[A-Za-z_]\w*)?\$", op)
        if m and op.find(m.group(0), m.end()) != -1:
            return "literal"
    if re.match(r"^[0-9]", op):
        return "literal"
    if re.match(r"^(chr|to_char)\s*\(\s*[0-9]+\s*\)$", low):
        return "literal"
    # DBMS_ASSERT.NOOP fuehrt per Definition KEINE Pruefung durch ('No
    # Operation') und reicht den Wert unveraendert durch. Es steht zwar unter
    # dem ``dbms_assert.``-Praefix der Sanitizer-Liste, darf aber NICHT als
    # absichernd gelten - sonst wuerde eine echte Injection auf Warning
    # heruntergestuft. Vor der Sanitizer-Praefixpruefung aussortieren.
    if re.match(r"^(?:sys\s*\.\s*)?dbms_assert\s*\.\s*noop\b", low):
        return "tainted"
    for sanitizer in sanitizers:
        if low.startswith(sanitizer.lower()):
            return "sanitized"
    return "tainted"


# Top-Level-DDL-Schluesselworte am Zeilenanfang. Wird vom
# Statement-Anfangs-Detektor genutzt, um robust auch ueber vergessene
# ``;`` hinweg den naechsten echten Anweisungsbeginn zu finden (z.B.
# ``DROP DIRECTORY xyz`` ohne abschliessendes ``;`` direkt vor einem
# ``CREATE USER ...``-Statement).
_TOP_DDL_LINESTART_RE = re.compile(
    r"(?m)^[ \t]*\b(?:CREATE|ALTER|DROP|GRANT|REVOKE|TRUNCATE|RENAME)\b",
    re.IGNORECASE)

# Wie weit zurueck im Quelltext nach einem Top-Level-DDL-Schluesselwort
# gesucht wird (siehe Heuristik in ``_finding``). 32 KB sind mehr als genug
# fuer realistische Statements; ohne dieses Limit waere der pro-Fund-
# Aufwand bei sehr grossen Dateien quadratisch in der Dateigroesse.
_DDL_BACKSCAN_LIMIT = 32 * 1024


# DDL-Objektvokabular je Schlüsselwort. Bewusst datengetrieben: die Listen
# bilden die Default-Vorgabe; eine Regeldatei kann sie unter
# ``ddl_in_code.ddl_objects`` (Schlüssel create/alter/drop/truncate) je
# Dialekt überschreiben/erweitern, ohne dass Code geändert werden muss.
DEFAULT_DDL_OBJECTS = {
    "create": [
        "TABLE", "TABLESPACE", "USER", "ROLE", "DIRECTORY",
        "MATERIALIZED VIEW", "VIEW", "INDEX", "SEQUENCE", "SYNONYM",
        "PROCEDURE", "FUNCTION", "PACKAGE BODY", "PACKAGE", "TRIGGER",
        "TYPE BODY", "TYPE", "JAVA", "LIBRARY", "DATABASE LINK", "CONTEXT",
        "PROFILE", "CLUSTER", "EXTENSION", "SCHEMA", "DATABASE", "OPERATOR",
        "DBLINK",
    ],
    "alter": [
        "TABLE", "USER", "ROLE", "SESSION", "SYSTEM", "DATABASE", "INDEX",
        "PROCEDURE", "PACKAGE", "FUNCTION", "TRIGGER", "VIEW", "PROFILE",
        "TABLESPACE", "SEQUENCE", "TYPE",
    ],
    "drop": [
        "TABLE", "USER", "ROLE", "VIEW", "INDEX", "SEQUENCE", "SYNONYM",
        "PROCEDURE", "FUNCTION", "PACKAGE", "TRIGGER", "TYPE", "DIRECTORY",
        "DATABASE LINK", "TABLESPACE", "PROFILE", "CONTEXT", "EXTENSION",
        "SCHEMA",
    ],
    "truncate": ["TABLE", "CLUSTER"],
}

# CREATE-Syntax-Modifizierer (kein Objektvokabular) - bleiben fest.
_CREATE_MOD = (r"(?:OR\s+REPLACE\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
               r"(?:GLOBAL\s+TEMPORARY\s+|PRIVATE\s+TEMPORARY\s+|PUBLIC\s+)?")


def _ddl_object_alternation(objects) -> str:
    """Baut die ``(obj1|obj2|...)``-Alternation aus einer Objektliste.

    Längere Phrasen kommen zuerst (``PACKAGE BODY`` vor ``PACKAGE``,
    ``MATERIALIZED VIEW`` vor ``VIEW``), interner Whitespace wird zu ``\\s+``.
    """
    parts = []
    for obj in sorted({str(o).strip() for o in objects if str(o).strip()},
                      key=lambda s: (-len(s), s)):
        parts.append(r"\s+".join(re.escape(w) for w in obj.split()))
    return "|".join(parts)


def build_ddl_regex(objects: "dict | None" = None):
    """Kompiliert das DDL-Erkennungs-Regex aus dem Objektvokabular.

    ``objects`` ist ein Dict mit den Schlüsseln ``create``/``alter``/
    ``drop``/``truncate`` (Listen von Objektarten). Fehlende Schlüssel
    fallen auf :data:`DEFAULT_DDL_OBJECTS` zurück, sodass bestehendes
    Verhalten erhalten bleibt. ``GRANT``/``REVOKE``/``RENAME``/``COMMENT ON``
    sind strukturell und bleiben fest. Eine DDL wird weiterhin nur erkannt,
    wenn auf das Schlüsselwort ein plausibles Objekt folgt (``\\b``-Grenze) -
    das vermeidet Fehlalarme bei normalem Text wie ``create a report``.
    """
    obj = dict(DEFAULT_DDL_OBJECTS)
    if isinstance(objects, dict):
        for key in ("create", "alter", "drop", "truncate"):
            val = objects.get(key)
            if isinstance(val, list) and val:
                obj[key] = val
    pattern = (
        r"\b("
        r"GRANT\b"
        r"|REVOKE\b"
        r"|CREATE\s+" + _CREATE_MOD +
        r"(?:" + _ddl_object_alternation(obj["create"]) + r")\b"
        r"|ALTER\s+(?:" + _ddl_object_alternation(obj["alter"]) + r")\b"
        r"|DROP\s+(?:" + _ddl_object_alternation(obj["drop"]) + r")\b"
        r"|TRUNCATE\s+(?:" + _ddl_object_alternation(obj["truncate"]) + r")\b"
        r"|RENAME\s+\w"
        r"|COMMENT\s+ON\b"
        r")"
    )
    return re.compile(pattern, re.IGNORECASE)


# Default-DDL-Regex (ohne dialektspezifische Überschreibung). Wird von
# Checks ohne ``ddl_objects``-Konfiguration sowie von Hilfsfunktionen genutzt.
_DDL_RE = build_ddl_regex(None)

# Objekttypen, deren CREATE-Anweisung als "zu prüfendes Objekt" gilt und
# bei der Standalone-Erkennung übersprungen werden kann.
_OBJECT_DEF_RE = re.compile(
    r"\b(PROCEDURE|FUNCTION|PACKAGE|TRIGGER|TYPE|VIEW|LIBRARY|JAVA)\b",
    re.IGNORECASE,
)


def _ddl_keyword(match_text: str) -> str:
    """Liefert das führende DDL-Schlüsselwort eines Treffers."""
    return re.split(r"\s+", match_text.strip())[0].upper()


# Externe Tabelle: CREATE TABLE ... ORGANIZATION EXTERNAL.
_EXTERNAL_TABLE_RE = re.compile(r"\bORGANIZATION\s+EXTERNAL\b", re.IGNORECASE)

# CREATE-Modifizierer, die für den Vergleich mit der Allowlist entfernt
# werden (OR REPLACE, EDITIONABLE, TEMPORARY, ...).
_CREATE_MODIFIERS_RE = re.compile(
    r"^CREATE (?:OR REPLACE )?(?:EDITIONABLE |NONEDITIONABLE )?"
    r"(?:GLOBAL TEMPORARY |PRIVATE TEMPORARY |PUBLIC )?")


def _norm_ws(text: str) -> str:
    """Großschreibung, Mehrfach-Whitespace zu genau einem Leerzeichen."""
    return re.sub(r"\s+", " ", str(text).strip().upper())


def _normalize_ddl(text: str) -> str:
    """Normalisiert eine DDL-Anweisung auf ``SCHLÜSSELWORT OBJEKT``.

    Großschreibung, genau ein Leerzeichen, CREATE-Modifizierer entfernt -
    so lässt sich ein DDL-Treffer mit der konfigurierten Allowlist
    (``allowed_statements``) vergleichen. Beispiele:
    ``CREATE OR REPLACE PACKAGE BODY`` -> ``CREATE PACKAGE BODY``,
    ``CREATE GLOBAL TEMPORARY TABLE`` -> ``CREATE TABLE``.
    """
    return _CREATE_MODIFIERS_RE.sub("CREATE ", _norm_ws(text)).strip()


def _external_table_at(text: str, pos: int) -> bool:
    """True, wenn das DDL-Statement ab ``pos`` eine externe Tabelle ist.

    Geprüft wird, ob bis zum nächsten Statement-Ende (``;``) die Klausel
    ``ORGANIZATION EXTERNAL`` folgt.
    """
    semi = text.find(";", pos)
    region = text[pos:semi if semi != -1 else len(text)]
    return bool(_EXTERNAL_TABLE_RE.search(region))


# ALTER SESSION SET NLS_*: harmlose Sitzungs-/NLS-Einstellung. Kein
# sicherheitsrelevantes DDL - eine etwaige Konkatenation wird vom
# SQL-Injection-Check erfasst.
_ALTER_SESSION_NLS_RE = re.compile(
    r"ALTER\s+SESSION\s+SET\s+NLS_", re.IGNORECASE)

# Ende der Privilegien-/Rollenliste eines GRANT (vor TO) bzw. REVOKE
# (vor FROM).
_GRANT_END_RE = re.compile(r"\b(?:TO|FROM)\b", re.IGNORECASE)


def _assignments_before(source, var, cut, routine):
    """Liefert relevante Zuweisungen an ``var`` IR-basiert.

    Die Parser-/IR-Schicht ist die zentrale Wahrheit für Positions- und
    Routine-Sensitivität: nur Zuweisungen *vor* der Ausführungsstelle und
    - sofern bekannt - in derselben Routine zählen. ``Source`` baut die IR
    immer auf (siehe :class:`aci.source.Source`), daher ist dies der einzige
    Pfad.
    """
    routine_name = (getattr(routine, "name", None)
                    if routine is not None else None)
    return list(ir_assignments_before(source.ir, var, cut, routine_name))


# ----------------------------------------------------------------------
# Basisklasse
# ----------------------------------------------------------------------

class Check:
    """Basisklasse für alle Checks."""

    config_key = ""
    group = GROUP_SECURITY      # Prüfgruppe, der die Findings zugeordnet werden
    # Vom Scanner gesetzt: ob ein Finding Quelltext-Kontext trägt und wie
    # viele Zeilen vor/nach der Fundstelle gezeigt werden. So lässt sich
    # die Codepreisgabe in Reports zentral steuern (--no-context).
    report_context = True
    context_lines = 3
    # Vom Scanner gesetzt: ob der SqlInjectionCheck die Taint-Quelle
    # (aufbauende Zuweisungen bzw. Routinenkopf) als zusätzliche
    # Fundstelle ausweist. Nur der SqlInjectionCheck wertet das aus.
    show_taint_sources = True

    def __init__(self, config: dict, dialect: str):
        self.config = config or {}
        self.dialect = dialect
        self.id = self.config.get("id", "ACI")
        self.name = self.config.get("name", self.config_key)

    def run(self, source: Source) -> list[Finding]:  # pragma: no cover
        raise NotImplementedError

    def _finding(self, source: Source, offset: int, severity, message: str,
                 recommendation: str = "", rule_ref: str = "",
                 url: str = "", related=None,
                 context_n: "int | None" = None,
                 span_end: "int | None" = None,
                 clip_to_statement: bool = False,
                 span_start: "int | None" = None) -> Finding:
        """Baut ein Finding.

        ``context_n`` überschreibt - falls gesetzt - die Zahl der
        Kontextzeilen am Fundort (Sink). ``span_end`` ist - falls gesetzt -
        das Ende der zugehörigen Anweisung; Snippet und Kontext umfassen
        dann die *vollständige* Anweisung (auch mehrzeilig), nicht nur die
        Fundzeile. ``related`` ist eine Liste von ``(label, offset)``-
        Paaren für zusätzliche, beschriftete Fundstellen (z.B. die
        Taint-Quelle); sie unterliegen denselben ``--no-context``-Regeln
        wie der Fundort.

        ``clip_to_statement`` (default ``False``) erzwingt zusammen mit
        ``span_end``, dass der Kontext genau die Statement-Zeilen umfasst -
        ohne ``±n``-Padding davor/danach. Damit werden unmittelbar
        benachbarte fremde Statements (z.B. ein vorangehendes ``DROP TABLE``
        vor einem ``CREATE TABLE``) und reine Kommentar-/Trennzeilen aus dem
        Kontext herausgehalten. Geeignet fuer DDL-/MITRE-/Guideline-Checks,
        bei denen das beanstandete Statement genau abgrenzbar ist.
        SQLI-Findings setzen das Flag nicht und behalten ihr ``±n``-Padding.
        """
        line, column = source.line_col(offset)
        n = max(0, self.context_lines if context_n is None else context_n)
        # Inhaltsgebundener Fingerabdruck. Bewusst *unabhängig* von
        # ``report_context`` berechnet, damit --no-context den Hash und
        # damit die Waiver-Bindung nicht verändert. Grundlage ist - falls
        # bekannt - die vollständige beanstandete Anweisung, sonst die
        # Fundzeile.
        if span_end is not None and span_end > offset:
            fp_text = source.text[offset:span_end]
        else:
            fp_text = source.line_text(line)
        # Repo-relativer, vom absoluten CI-/Runner-Pfad unabhängiger Pfad:
        # so deckt ein Waiver für eine Datei keine gleichnamige Datei in
        # einem anderen Verzeichnis mit ab.
        rel_path = stable_relative_path(
            source.filename, getattr(source, "scan_root", None))
        # S14: umgebende Routine in den Fingerabdruck einbeziehen, damit ein
        # identischer Befund in zwei verschiedenen Routinen nicht denselben
        # Fingerabdruck traegt (und ein Waiver/Baseline-Eintrag nicht beide
        # unbeabsichtigt mitdeckt).
        routine = None
        routine_at = getattr(source, "routine_at", None)
        if callable(routine_at):
            routine = routine_at(offset)
        routine_name = getattr(routine, "name", "") if routine else ""
        fingerprint = compute_fingerprint(self.id, rule_ref, rel_path,
                                          fp_text, dialect=self.dialect,
                                          routine=routine_name)
        related_locs: list = []
        statement_end_line = line
        if self.report_context:
            after = n
            before = n
            if span_end is not None and span_end > offset:
                statement_end_line = source.line_col(span_end)[0]
                # ``context_n`` (per-Item-Override z.B. aus der Regeldatei
                # ueber ``"context_lines": 0``) hat Vorrang vor
                # ``clip_to_statement``: explizit gesetzte Kontextgroesse
                # bleibt verbindlich, auch wenn der Check sonst auf
                # Statement-Spanne klemmen wuerde.
                if clip_to_statement and context_n is None:
                    # Statement-Anfang bestimmen:
                    #   - Wenn ``span_start`` explizit gesetzt ist (z.B. von
                    #     ``DdlCheck``, wo das DDL-Keyword zugleich der
                    #     Statement-Anfang ist), genau diese Position nehmen.
                    #     Damit werden vorgelagerte SQL*Plus-Direktiven
                    #     (``PROMPT``, ``SET``, ``SPOOL``) und Trenn-/
                    #     Kommentarzeilen verlaesslich aus dem Kontext
                    #     gehalten - selbst wenn dazwischen kein ``;`` steht.
                    #   - Sonst Auto-Detect: Position hinter dem vorhergehenden
                    #     ``;`` in ``code_masked`` (String-/Kommentar-Inhalte
                    #     dort maskiert, sodass nur echte Statement-Trenner
                    #     gefunden werden); Whitespace direkt nach dem ``;``
                    #     wird uebersprungen. Auto-Detect ist passend fuer
                    #     Detektoren, die in der Mitte eines Statements
                    #     matchen koennen (z.B. T1098 IDENTIFIED BY).
                    if span_start is not None and span_start <= offset:
                        stmt_start = span_start
                    else:
                        # Lexer-Statement-Grenzen kennen sowohl ``;`` als
                        # auch ``/`` auf eigener Zeile als Terminator und
                        # ueberspringen ``;`` innerhalb von PL/SQL-/Java-
                        # Koerpern. Damit landet ``stmt_start`` zuverlaessig
                        # auf dem Anfang der umgebenden SQL-Anweisung.
                        lex_start = source.statement_start_before(offset)
                        masked = source.code_masked
                        if lex_start is not None:
                            stmt_start = lex_start
                        else:
                            prev_semi = masked.rfind(";", 0, offset)
                            stmt_start = prev_semi + 1 if prev_semi != -1 else 0
                        while (stmt_start < offset
                               and masked[stmt_start] in " \t\r\n"):
                            stmt_start += 1
                        # Robuster Statement-Anfang bei fehlerhaft formatierten
                        # Skripten: wenn ZWISCHEN ``lex_start`` und dem Fund
                        # ein klar erkennbarer Top-Level-DDL-Anweisungsbeginn
                        # (CREATE/ALTER/DROP/GRANT/REVOKE/TRUNCATE/RENAME) am
                        # Zeilenanfang steht, gilt dessen Zeile als
                        # eigentlicher Statement-Start - auch wenn das
                        # vorhergehende Statement ohne ``;`` blieb (z.B. ein
                        # vergessenes Semikolon nach einem DROP DIRECTORY).
                        # Damit fallen unmittelbar vorgelagerte, syntaktisch
                        # eigenstaendige DDL-Anweisungen aus dem Kontext.
                        #
                        # Performance: der Scan-Bereich wird auf hoechstens
                        # ``_DDL_BACKSCAN_LIMIT`` Bytes vor der Fundstelle
                        # begrenzt, damit der pro-Fund-Aufwand in grossen
                        # Dateien nicht quadratisch wird. Sinnvolle Statements
                        # sind selten >8 KB lang; tritt die Heuristik nicht in
                        # Kraft, bleibt der lex_start-basierte Anfang gueltig.
                        scan_from = max(stmt_start, offset - _DDL_BACKSCAN_LIMIT)
                        last_kw = None
                        for km in _TOP_DDL_LINESTART_RE.finditer(
                                masked, scan_from, offset):
                            last_kw = km
                        if last_kw is not None:
                            pos = last_kw.start()
                            while (pos < offset
                                   and masked[pos] in " \t"):
                                pos += 1
                            stmt_start = pos
                    statement_start_line = source.line_col(stmt_start)[0]
                    # Kontextfenster genau auf die Statement-Zeilen klemmen.
                    # Damit fallen Padding-Inhalte heraus, die nicht zum
                    # beanstandeten Statement gehoeren: vorangehende
                    # Kommentare ("-- ..." vor einem GRANT), unmittelbar
                    # benachbarte andere Statements (DROP TABLE vor CREATE
                    # TABLE, weitere DDL nach einer externen Tabelle) usw.
                    before = max(0, line - statement_start_line)
                    after = max(0, statement_end_line - line)
                    # Snippet auf den vollstaendigen Statement-Umfang
                    # (Statement-Anfang .. span_end) ausweiten - sonst sieht
                    # man bei Detektoren, die mitten im Statement matchen
                    # (DBMS_ASSERT.NOOP innerhalb einer Konkatenation,
                    # IDENTIFIED BY in einem mehrzeiligen CREATE USER usw.),
                    # nur den Teil hinter der Fundstelle.
                    snippet_from = stmt_start
                else:
                    # Bisheriges Verhalten: Statement vollstaendig zeigen
                    # plus ``±n``-Padding (von SQLI-Findings genutzt).
                    after = n + max(0, statement_end_line - line)
                    snippet_from = offset
                stmt = " ".join(source.text[snippet_from:span_end].split())
                snippet = stmt if len(stmt) <= 200 else stmt[:197] + "..."
            else:
                snippet = source.snippet(offset)
            context = source.context_lines(offset, before=before, after=after)
            rn = max(0, self.context_lines)
            for label, rel_off in (related or []):
                rl, rc = source.line_col(rel_off)
                related_locs.append(RelatedLocation(
                    label=label, file=source.filename, line=rl, column=rc,
                    snippet=source.snippet(rel_off),
                    context=source.context_lines(rel_off, before=rn,
                                                  after=rn)))
        else:
            snippet = ""
            context = []
        return Finding(
            check_id=self.id,
            check_name=self.name,
            group=self.group,
            severity=Severity.parse(severity),
            file=source.filename,
            line=line,
            column=column,
            message=message,
            snippet=snippet,
            context=context,
            related=related_locs,
            recommendation=recommendation,
            rule_ref=rule_ref,
            url=url,
            fingerprint=fingerprint,
            statement_end_line=statement_end_line,
        )

    @staticmethod
    def collapse_sibling_context(findings):
        """Reduziert den Kontext bei benachbarten Findings desselben Checks.

        Stehen mehrere Findings desselben Checks dicht beieinander (etwa eine
        Reihe von ``GRANT ... TO PUBLIC`` oder eine Kette ``DROP TYPE ...``),
        zeigt das Kontextfenster eines Findings sonst die Nachbar-Fundstellen
        mit - die wiederum eigene Findings sind. Faellt eine Nachbar-Fundzeile
        in den **Padding**-Bereich eines Findings (also ausserhalb dessen
        eigentlicher Statement-Zeilen), wird der Kontext dieses Findings auf
        die Statement-Spanne reduziert. Mehrzeilige Statements bleiben damit
        komplett sichtbar (z.B. ein ``CREATE DATABASE LINK ... USING '...'``
        ueber mehrere Zeilen), waehrend Cluster gleichartiger einzeiliger
        Funde (GRANT/REVOKE-Ketten, Base64-Bloecke u.ae.) wie bisher auf die
        eigene Fundzeile zusammenfallen.

        In-place: Findings werden direkt veraendert.
        """
        # Per-Datei Set aller Fundzeilen einmalig vorberechnen.
        # Die alte Variante hat fuer JEDE Finding ein eigenes Set
        # ``padding_siblings`` aus diesem Set erzeugt - mit F Findings ist
        # das O(F^2). Bei sehr grossen Dateien (z.B. Schema-Dumps mit
        # tausenden ``perform``-Aufrufen) machte das den Scan praktisch
        # quadratisch. Hier reicht eine einzige Set-Lookups pro Kontextzeile.
        lines_by_file: dict = {}
        for f in findings:
            lines_by_file.setdefault(f.file, set()).add(f.line)
        for f in findings:
            if not f.context:
                continue
            siblings = lines_by_file.get(f.file)
            if not siblings or len(siblings) <= 1:
                continue
            # Statement-Spanne ``[stmt_lo, stmt_hi]``: die Zeilen der eigenen
            # Anweisung. Bei einzeiligen Statements ist stmt_hi == stmt_lo.
            stmt_lo = f.line
            stmt_hi = max(f.line, f.statement_end_line or f.line)
            # Trigger den Kollaps, sobald irgendeine Kontextzeile eine
            # Nachbar-Fundzeile AUSSERHALB der eigenen Statement-Spanne ist.
            has_padding_sibling = any(
                ln != f.line and ln in siblings
                and not (stmt_lo <= ln <= stmt_hi)
                for ln, _t, _is in f.context
            )
            if has_padding_sibling:
                # Nur die Statement-Zeilen behalten, Padding fallen lassen.
                f.context = [(ln, txt, isf) for ln, txt, isf in f.context
                             if stmt_lo <= ln <= stmt_hi]


def _collect_var_writes(source, var, cut):
    """Liefert die routine-lokalen Schreibzugriffe auf ``var`` vor ``cut``.

    Rückgabe je Schreibzugriff: ``(pos, rhs_code, rhs_masked, kind)`` mit
    ``kind`` = ``assignment`` (``:=``), ``select_into``/``fetch_into``
    oder ``parameter`` (die Variable ist Routine-Parameter, modelliert als
    impliziter Schreibzugriff am Routinenkopf). Gemeinsame Grundlage der
    Taint-Quellen-Verfolgung von SqlInjectionCheck und DdlCheck.
    """
    masked = source.code_masked
    # ``Source`` baut die IR immer auf; der frühere Lexer-Fallback war damit
    # toter Code und wurde entfernt.
    routine = routine_for_offset(source.ir, cut) if cut is not None else None
    rname = routine.name if routine is not None else None
    items = (list(ir_assignments_before(source.ir, var, cut, rname))
             if cut is not None else [])
    out = [(a.target_start, a.expression, masked[a.expr_start:a.expr_end],
            getattr(a, "kind", "assignment"))
           for a in items]
    if routine is not None and var.upper() in {
            p.upper() for p in getattr(routine, "parameters", ())}:
        out.append((routine.start, "", "", "parameter"))
    out.sort(key=lambda t: t[0])
    return out


def _origin_related(source, origins):
    """Macht aus ``[(offset, kind)]`` beschriftete Taint-Quellen-Fundstellen.

    Liefert ``(label, offset)``-Paare für das Reporting; mehrere Quellen
    in derselben Zeile werden zusammengefasst, die Reihenfolge folgt der
    Position im Quelltext.
    """
    related, seen = [], set()
    for off, kind in sorted(origins):
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        if kind == "parameter":
            label = ("Taint-Quelle: Definition der Prozedur/Funktion - "
                     "ungeprüfter Routine-Parameter")
        elif kind in ("select_into", "fetch_into", "returning_into"):
            label = ("Taint-Quelle: Wert aus einem "
                     "SELECT/FETCH/RETURNING ... INTO")
        else:
            label = "Taint-Quelle: Zuweisung des verwendeten Wertes"
        related.append((label, off))
    return related
