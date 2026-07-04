"""Lexikalische Sicherheits-Checks: Namen, Packages, Obfuskation."""

from __future__ import annotations

import re

from ..finding import (Finding)
from ..ir import dynamic_sql_executions

from .base import (Check, _IDENT, _DATATYPES,
                    _collect_var_writes, _origin_related)


# ----------------------------------------------------------------------
# Check 1 - Namenskonventionen / reservierte Worte
# ----------------------------------------------------------------------

_OBJECT_NAME_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
    r"(?:GLOBAL\s+TEMPORARY\s+|PUBLIC\s+)?"
    r"(?:TABLE|MATERIALIZED\s+VIEW|VIEW|PROCEDURE|FUNCTION|PACKAGE\s+BODY|"
    r"PACKAGE|TRIGGER|TYPE\s+BODY|TYPE|SEQUENCE|INDEX|SYNONYM)\s+"
    # Optionale Kopf-Schlüsselworte überspringen, nicht als Namen werten:
    # CONCURRENTLY (CREATE INDEX) und IF NOT EXISTS.
    r"(?:CONCURRENTLY\s+)?(?:IF\s+NOT\s+EXISTS\s+)?"
    # ``CREATE INDEX ON tab (...)`` ist ein unbenannter Index - ``ON`` ist
    # dann kein Objektname, sondern Syntax und darf kein Finding erzeugen.
    # ``CONCURRENTLY`` darf ebenfalls nicht als Name gewertet werden, falls
    # der optionale Block oben zuruckgesetzt wird (``... CONCURRENTLY ON``).
    # ``TO`` / ``FROM`` treten in System-Privilegien innerhalb von
    # GRANT/REVOKE auf (z.B. ``GRANT CREATE TABLE TO user``,
    # ``REVOKE CREATE VIEW FROM user``) - hier ist ``CREATE <objekttyp>``
    # der Privilegname, nicht der Beginn einer Objektdefinition; das
    # folgende ``TO``/``FROM`` ist Syntax und kein Objektname.
    r"(?!(?:ON|CONCURRENTLY|TO|FROM)\b)"
    r"(" + _IDENT + r"(?:\s*\.\s*" + _IDENT + r")?)",
    re.IGNORECASE,
)

_DECL_RE = re.compile(
    r"(?:[;(,]|\bDECLARE\b|\bIS\b|\bAS\b)\s*"
    r"(" + _IDENT + r")\s+"
    r"(?:CONSTANT\s+)?"
    r"(?:IN\s+OUT\s+NOCOPY|IN\s+OUT|IN|OUT|NOCOPY)?\s*"
    r"(?:(?:" + _DATATYPES + r")\b|" + _IDENT + r"\s*%\s*(?:TYPE|ROWTYPE))",
    re.IGNORECASE,
)


class NamingCheck(Check):
    """Erkennt Bezeichner, die reservierte Worte sind oder gegen
    Namenskonventionen verstoßen (z.B. zu lang)."""

    config_key = "naming_conventions"

    def __init__(self, config, dialect):
        super().__init__(config, dialect)
        words = config.get("reserved_words", []) or []
        self.reserved = {w.upper() for w in words}
        self.level = config.get("level", "Warning")
        self.max_len = int(config.get("max_identifier_length", 0) or 0)
        self.flag_quoted = bool(config.get("flag_quoted_reserved", True))

    @staticmethod
    def _last_component(name: str) -> str:
        """Liefert bei schemaqualifizierten Namen die letzte Komponente."""
        return re.split(r"\s*\.\s*", name.strip())[-1].strip()

    def _inspect(self, source, raw_name, offset, kind, findings, seen):
        comp = self._last_component(raw_name)
        quoted = comp.startswith('"') and comp.endswith('"')
        bare = comp.strip('"')
        if not bare:
            return
        key = (source.line_col(offset)[0], bare.upper(), kind)
        if key in seen:
            return
        seen.add(key)

        # Namens-Findings betreffen genau einen Bezeichner in einer
        # Deklarationszeile; das umgebende DECLARE/IS-Block oder die
        # Spaltenliste wuerde sonst ein grosses, irrelevantes Padding
        # einblenden. ``context_n=0`` klemmt den Kontext auf die eigene
        # Fundzeile - genau das, was der Auditor sehen will.
        upper = bare.upper()
        if upper in self.reserved:
            if quoted and self.flag_quoted:
                findings.append(self._finding(
                    source, offset, self.level,
                    f"{kind} \"{bare}\" verwendet das reservierte Wort "
                    f"'{upper}' als gequoteten Bezeichner",
                    recommendation=(
                        "Gequotete Bezeichner mit reservierten Worten "
                        "vermeiden - sie umgehen die Schutzwirkung der "
                        "Namensregeln und erschweren die Wartung."),
                    rule_ref=upper,
                    context_n=0,
                ))
            elif not quoted:
                findings.append(self._finding(
                    source, offset, self.level,
                    f"{kind} '{bare}' ist ein reserviertes Wort "
                    f"({self.dialect})",
                    recommendation=(
                        "Bezeichner umbenennen; reservierte Worte als "
                        "Namen führen zu Mehrdeutigkeiten und Fehlern."),
                    rule_ref=upper,
                    context_n=0,
                ))
        if self.max_len and len(bare) > self.max_len:
            findings.append(self._finding(
                source, offset, self.level,
                f"{kind} '{bare}' überschreitet die maximale "
                f"Bezeichnerlänge ({len(bare)} > {self.max_len} Zeichen)",
                recommendation="Bezeichner kürzen.",
                rule_ref="LENGTH",
                context_n=0,
            ))

    def run(self, source):
        findings: list[Finding] = []
        seen: set = set()
        code = source.code_masked

        for m in _OBJECT_NAME_RE.finditer(code):
            self._inspect(source, m.group(1), m.start(1),
                          "Objektname", findings, seen)
        for m in _DECL_RE.finditer(code):
            self._inspect(source, m.group(1), m.start(1),
                          "Bezeichner", findings, seen)
        # Bei Ketten benachbarter Namens-Findings Kontext auf die eigene
        # Fundzeile reduzieren (analog zu DDL/Guidelines/Obfuscation).
        Check.collapse_sibling_context(findings)
        return findings


# ----------------------------------------------------------------------
# Check 2 - Unerwünschte Packages
# ----------------------------------------------------------------------

# Element hinter einem Paketnamen: ``.MEMBER`` (optional Leerraum um den
# Punkt). Dient dem Ausblenden gutartiger Paket-Member (ignore_members).
_MEMBER_AFTER_RE = re.compile(r"\s*\.\s*([A-Za-z_][\w$#]*)")

# Einfaches Funktions-Argument: ``( <Bezeichner> )`` direkt hinter einem
# Match. Erfasst nur den simplen Fall ``DBMS_ASSERT.NOOP(VAR)`` - dort
# laesst sich die Taint-Quelle des Wertes verlaesslich nachvollziehen.
# Komplexe Argumente (Ausdruecke, verschachtelte Aufrufe) werden
# bewusst nicht analysiert, um keine Halbwahrheiten zu liefern.
_SIMPLE_CALL_ARG_RE = re.compile(r"\s*\(\s*([A-Za-z_][\w$#]*)\s*\)")


class PackagesCheck(Check):
    """Erkennt die Verwendung unerwünschter / sicherheitskritischer
    Packages, Funktionen oder Sprachen."""

    config_key = "undesired_packages"

    def __init__(self, config, dialect):
        super().__init__(config, dialect)
        self.items = []
        for item in config.get("items", []) or []:
            name = item.get("name", "")
            if not name:
                continue
            pattern = re.compile(
                r"(?<![\w$#.])(?:sys\s*\.\s*)?" + re.escape(name) + r"(?![\w$#])",
                re.IGNORECASE,
            )
            # Gutartige Member dieses Pakets (z.B. DBMS_LOB.INSTR), die
            # kein Finding erzeugen sollen - reine Lese-/Hilfsfunktionen.
            ignore = {
                str(s).upper()
                for s in item.get("ignore_members", []) or []
                if isinstance(s, str) and s.strip()
            }
            self.items.append((name, pattern, item, ignore))

    def _scan(self, source, text, base, findings, seen):
        """Sucht die Paketmuster in ``text`` (Offsets relativ zu ``base``)."""
        for name, pattern, item, ignore in self.items:
            for m in pattern.finditer(text):
                # Gutartige Member (ignore_members) ausblenden: folgt auf
                # den Paketnamen ein ".MEMBER" aus der Ausnahmeliste,
                # entsteht kein Finding (z.B. DBMS_LOB.SUBSTR).
                if ignore:
                    after = _MEMBER_AFTER_RE.match(text, m.end())
                    if after and after.group(1).upper() in ignore:
                        continue
                offset = base + m.start()
                line = source.line_col(offset)[0]
                key = (name.lower(), line)
                if key in seen:
                    continue
                seen.add(key)
                # Optional pro Eintrag: ``context_lines`` ueberschreibt die
                # globale Anzahl Kontextzeilen am Fundort. Sinnvoll fuer
                # punktuelle Befehle wie ``set_config``, bei denen mehrere
                # benachbarte Aufrufe sonst zu stark ueberlappenden Kontext-
                # bloecken fuehren - hier ist nur die betroffene Zeile von
                # Interesse (``"context_lines": 0``).
                ctx_n = item.get("context_lines")
                if ctx_n is not None:
                    try:
                        ctx_n = int(ctx_n)
                    except (TypeError, ValueError):
                        ctx_n = None
                # Snippet und Kontext umfassen das gesamte umgebende
                # Statement (nicht nur die Zeile mit dem Paketnamen).
                # Die Lexer-Statement-Grenzen beruecksichtigen sowohl ``;``
                # als auch ``/`` auf eigener Zeile als Terminator - das ist
                # wichtig fuer SQL*Plus-DDL wie ``ALTER PROFILE ... /``.
                span_end = source.statement_end_after(offset)
                # Optional: Taint-Quellen-Verfolgung fuer Items, die das
                # via ``"track_taint": true`` anfordern. Sinnvoll z.B. bei
                # ``DBMS_ASSERT.NOOP(<var>)`` - NOOP fuehrt KEINE Pruefung
                # durch und ueberreicht den Wert unveraendert; der Report
                # soll daher zeigen, woher der "NOOP-validierte" Wert
                # stammt (Zuweisung bzw. Routine-Parameter).
                related = []
                if item.get("track_taint") and self.show_taint_sources:
                    arg_match = _SIMPLE_CALL_ARG_RE.match(text, m.end())
                    if arg_match:
                        var = arg_match.group(1)
                        origins = [(pos, kind) for pos, _rc, _rm, kind
                                   in _collect_var_writes(
                                       source, var, offset)]
                        related = _origin_related(source, origins)
                findings.append(self._finding(
                    source, offset,
                    item.get("level", "High"),
                    item.get("message", f"Verwendung des Pakets {name}"),
                    recommendation=item.get("recommendation", ""),
                    rule_ref=name,
                    context_n=ctx_n,
                    span_end=span_end,
                    clip_to_statement=True,
                    related=related,
                ))

    def run(self, source):
        findings: list[Finding] = []
        seen: set = set()
        # (a) Normaler Code - String-Literale sind ausmaskiert. Ein
        #     Paketname in einem Ausgabe-/Meldungstext (z.B.
        #     DBMS_OUTPUT.PUT_LINE('... DBMS_LOB ...')) löst damit
        #     KEIN Finding aus.
        self._scan(source, source.code_masked, 0, findings, seen)
        # (b) Ausdrücke dynamischer SQL-Statements - dort eingebettete
        #     Paketaufrufe werden zur Laufzeit tatsächlich ausgeführt
        #     und sollen weiterhin erkannt werden.
        code = source.code_no_comments
        dyn_items = dynamic_sql_executions(source.ir)
        for dyn in dyn_items:
            self._scan(source, code[dyn.expr_start:dyn.expr_end],
                       dyn.expr_start, findings, seen)
        # Benachbarte Pakettreffer desselben Pakets bekommen ihren
        # Kontext auf die eigene Fundzeile reduziert.
        Check.collapse_sibling_context(findings)
        return findings


# ----------------------------------------------------------------------
# Check 3 - Verschlüsselter / obfuskierter Code
# ----------------------------------------------------------------------

def _string_is_insert_data(source, content_start: int) -> bool:
    """True, wenn das umschließende Statement ein ``INSERT`` ist.

    String-Literale in ``INSERT ... VALUES``-Datenzeilen sind Daten, kein
    Code. Lange Hex-/Base64-Blöcke darin (z.B. PostGIS-WKB-Geometrie,
    serialisierte BLOBs) sind keine Code-Verschleierung und sollen kein
    Obfuskations-Finding erzeugen. Es wird vom Beginn des String-Literals
    bis zum letzten Statement-Trenner (``;``) zurückgeschaut; String-
    Inhalte und Kommentare sind in ``code_masked`` bereits maskiert, so
    dass dort kein irreführendes ``;`` steht.
    """
    masked = source.code_masked
    start = masked.rfind(";", 0, content_start) + 1
    return bool(masked[start:content_start].lstrip()[:6].upper() == "INSERT")


class ObfuscationCheck(Check):
    """Erkennt gewrappten, verschlüsselten oder verschleierten Code:
    Oracle-WRAP, Base64-Blöcke, CHR()-Ketten u.a."""

    config_key = "obfuscation"

    _WRAPPED_RE = re.compile(r"\bWRAPPED\b[ \t]*\r?$", re.IGNORECASE | re.MULTILINE)

    def __init__(self, config, dialect):
        super().__init__(config, dialect)
        self.detect_wrapped = bool(config.get("detect_wrapped", True))
        self.wrapped_level = config.get("wrapped_level", "High")
        self.detect_chr = bool(config.get("detect_chr_chain", True))
        self.chr_min = int(config.get("chr_chain_min", 4) or 4)
        self.chr_level = config.get("chr_chain_level", "High")
        self.patterns = []
        for pat in config.get("patterns", []) or []:
            regex = pat.get("regex")
            if not regex:
                continue
            # Muster wurden beim Laden der Regeldatei validiert
            # (aci.rules) - ein Fehler hier wird nicht still verschluckt.
            compiled = re.compile(regex, re.IGNORECASE)
            self.patterns.append((compiled, pat))

    def run(self, source):
        findings: list[Finding] = []
        code = source.code_no_comments

        # Oracle WRAP-Marker (Schlüsselwort WRAPPED am Zeilenende).
        if self.detect_wrapped:
            for m in self._WRAPPED_RE.finditer(code):
                findings.append(self._finding(
                    source, m.start(), self.wrapped_level,
                    "Gewrappter Code erkannt (Oracle-WRAP). Der Quelltext "
                    "ist verschleiert und kann nicht inhaltlich geprüft "
                    "werden.",
                    recommendation=(
                        "Ungewrappten Originalquelltext zur Prüfung "
                        "anfordern. Gewrappter Code lässt sich "
                        "entschlüsseln und bietet keinen echten Schutz."),
                    rule_ref="WRAPPED",
                ))
                break  # ein Treffer pro Datei genügt

        # CHR()-Ketten (typische String-Verschleierung).
        if self.detect_chr and self.chr_min > 1:
            chain = re.compile(
                r"(?:\bCHR\s*\(\s*\d+\s*\)\s*\|\|\s*){%d,}\bCHR\s*\(\s*\d+\s*\)"
                % (self.chr_min - 1),
                re.IGNORECASE,
            )
            for m in chain.finditer(code):
                findings.append(self._finding(
                    source, m.start(), self.chr_level,
                    "Verschleierte Zeichenkette: lange CHR()-Konkatenation. "
                    "Solche Ketten werden genutzt, um Schlüsselworte oder "
                    "Zeichenketten vor einer Prüfung zu verbergen.",
                    recommendation=(
                        "Klartext-Zeichenketten verwenden; den Zweck der "
                        "CHR()-Kette auflösen und prüfen."),
                    rule_ref="CHR-CHAIN",
                ))

        # Konfigurierbare Regex-Muster (Base64-Blöcke, Hex-Blöcke,
        # Aufrufe von Dekodierfunktionen, ...).
        for compiled, pat in self.patterns:
            target = pat.get("target", "code")
            level = pat.get("level", "High")
            message = pat.get("message", "Verschleiertes Muster erkannt")
            recommendation = pat.get("recommendation", "")
            ref = pat.get("id", "PATTERN")
            skip_insert = bool(pat.get("skip_in_insert", False))
            if target == "string":
                for span in source.string_spans:
                    content = source.string_content(span)
                    sm = compiled.search(content)
                    if not sm:
                        continue
                    if skip_insert and _string_is_insert_data(
                            source, span.content_start):
                        continue
                    findings.append(self._finding(
                        source, span.content_start + sm.start(),
                        level, message,
                        recommendation=recommendation, rule_ref=ref))
            else:
                for sm in compiled.finditer(code):
                    findings.append(self._finding(
                        source, sm.start(), level, message,
                        recommendation=recommendation, rule_ref=ref))
        # Bei mehreren benachbarten Treffern desselben Musters (z.B. eine
        # Reihe ``base64-blob``- oder ``hex-blob``-Funde aus PostGIS-
        # Test-Daten oder einer Migration mit kodierten Geometrien) zeigt
        # das Kontextfenster eines Findings sonst die Nachbar-Fundstellen
        # mit - die wiederum eigene Findings sind. Den Kontext fuer solche
        # Cluster auf die eigene Fundzeile reduzieren.
        Check.collapse_sibling_context(findings)
        return findings


