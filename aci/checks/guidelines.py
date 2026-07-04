"""GuidelineCheck und MitreCheck - regel-/detektorgesteuerte Checks."""

from __future__ import annotations

import re

from ..finding import (GROUP_SECURITY, GROUP_GUIDELINES)

from .base import (Check)
from .detectors import _BUILTIN_DETECTORS


# ======================================================================
# Coding Guidelines (Oracle: Trivadis-Regeln, PostgreSQL: ACI-eigene)
# ======================================================================

class GuidelineCheck(Check):
    """Prüft eine einzelne Coding-Guideline-Regel.

    Die Regeln stammen für Oracle aus den Trivadis PL/SQL & SQL Coding
    Guidelines und für PostgreSQL aus ACI-eigenen PL/pgSQL-Guidelines.
    Gesteuert wird die Regel über eine Detektor-Beschreibung: entweder
    ein regulärer Ausdruck (``type: regex``) oder ein eingebauter
    Detektor mit Sonderlogik (``type: builtin``).
    """

    group = GROUP_GUIDELINES

    def __init__(self, rule: dict, dialect: str):
        self.config = rule
        self.dialect = dialect
        self.id = rule.get("id", "G-?")
        self.name = rule.get("title", self.id)
        self.severity = rule.get("severity", "Minor")
        self.message = rule.get("message", self.name)
        self.recommendation = rule.get("recommendation", "")
        self.url = rule.get("url", "")
        self.category = rule.get("category", "")
        self.detector = rule.get("detector", {}) or {}
        # Regex-Detektoren werden einmalig vorab kompiliert. Ungültige
        # Muster werden bereits beim Laden der Regeln abgewiesen
        # (siehe aci.rules) - hier wird kein Fehler still verschluckt.
        self._regex = None
        if (self.detector.get("type") == "regex"
                and self.detector.get("pattern")):
            self._regex = re.compile(self.detector["pattern"], re.IGNORECASE)

    @staticmethod
    def _stmt_end(source, offset: int):
        """Endposition des Statements, das ``offset`` enthaelt.

        Nutzt die Lexer-Statement-Grenzen (``source.statement_end_after``);
        dort sind sowohl ``;`` als auch ``/`` auf eigener Zeile als
        Statement-Terminator beruecksichtigt. Liefert ``None``, wenn der
        Offset in keinem Statement liegt (z.B. Skriptfragment ohne
        Terminator).
        """
        return source.statement_end_after(offset)

    @staticmethod
    def _line_bounds(source, offset):
        """``(zeilenanfang, zeilenende)`` der Zeile, die ``offset`` enthaelt."""
        start = source.text.rfind("\n", 0, offset) + 1
        end = source.text.find("\n", offset)
        if end == -1:
            end = len(source.text)
        return start, end

    def _gf(self, source, offset, message=None, single_line=False):
        """Erzeugt ein Guideline-Finding.

        ``span_end`` wird auf das naechste statement-trennende ``;`` gesetzt
        und ``clip_to_statement=True`` haengt den Kontext exakt an die
        Statement-Zeilen. Damit umfasst Snippet/Kontext bei mehrzeiligen
        Statements (etwa einem ``CREATE USER ... IDENTIFIED BY ...``-Block
        oder ``CREATE DATABASE LINK ... USING '...'``) das gesamte
        Statement, ohne Nachbar-Statements oder umgebende Kommentare ins
        Bild zu nehmen.

        ``single_line=True`` begrenzt Snippet/Kontext auf die Fundzeile -
        genutzt fuer zeilenorientierte Client-/Skript-Direktiven
        (``@``/``@@``/``START``/``\\``-Meta), die sonst mangels ``;`` mit
        nachfolgenden Direktivenzeilen zu einem Snippet verschmelzen.
        """
        if single_line:
            ls, le = self._line_bounds(source, offset)
            return self._finding(
                source, offset, self.severity, message or self.message,
                recommendation=self.recommendation, rule_ref=self.id,
                url=self.url, span_start=ls, span_end=le,
                clip_to_statement=True)
        return self._finding(
            source, offset, self.severity, message or self.message,
            recommendation=self.recommendation, rule_ref=self.id, url=self.url,
            span_end=self._stmt_end(source, offset),
            clip_to_statement=True)

    def run(self, source):
        dtype = self.detector.get("type")
        if dtype == "regex":
            findings = self._run_regex(source)
        elif dtype == "builtin":
            fn = _BUILTIN_DETECTORS.get(self.detector.get("name"))
            findings = fn(self, source) if fn else []
        else:
            return []
        # Bei einer Kette benachbarter Treffer derselben Regel (z.B.
        # mehrere ``GRANT ... TO PUBLIC`` direkt untereinander) zeigt das
        # Kontextfenster eines Findings sonst die Nachbar-Fundstellen mit -
        # die wiederum eigene Findings sind. Den Kontext fuer solche
        # Cluster auf die eigene Fundzeile reduzieren; isolierte Findings
        # behalten ihren vollen Kontext.
        Check.collapse_sibling_context(findings)
        return findings

    def _run_regex(self, source):
        compiled = self._regex
        if compiled is None:
            return []
        target = self.detector.get("target", "code")
        findings, seen = [], set()
        if target == "string":
            for span in source.string_spans:
                for m in compiled.finditer(source.string_content(span)):
                    off = span.content_start + m.start()
                    ln = source.line_col(off)[0]
                    if ln in seen:
                        continue
                    seen.add(ln)
                    findings.append(self._gf(source, off))
        else:
            text = (source.code_masked if target == "masked"
                    else source.code_no_comments)
            for m in compiled.finditer(text):
                ln = source.line_col(m.start())[0]
                if ln in seen:
                    continue
                seen.add(ln)
                findings.append(self._gf(source, m.start()))
        return findings


def build_guideline_checks(guideline_rules, dialect) -> list[Check]:
    """Erzeugt aus den geladenen Guideline-Regeln die aktiven Checks."""
    return [GuidelineCheck(rule, dialect)
            for rule in guideline_rules
            if rule.get("enabled", False)]


# ======================================================================
# MITRE-ATT&CK-Angriffsindikatoren (Gruppe Sicherheit)
# ======================================================================

class MitreCheck(GuidelineCheck):
    """Prueft eine einzelne MITRE-ATT&CK-Angriffsindikator-Regel.

    Technisch identisch zu GuidelineCheck (regex-/builtin-Detektoren).
    Die Findings werden jedoch der Gruppe 'Sicherheit' zugeordnet und
    mit MITRE-Taktik und -Technik versehen. Die MITRE-Regeln decken
    gezielt Indikatoren ab, die die fuenf Sicherheits-Checks noch nicht
    erfassen - es entstehen keine Doppel-Findings.
    """

    group = GROUP_SECURITY

    def __init__(self, rule: dict, dialect: str):
        super().__init__(rule, dialect)
        self.tactic = rule.get("tactic", "")
        self.technique = rule.get("technique", self.id)

    def _gf(self, source, offset, message=None, single_line=False):
        """Erzeugt ein MITRE-Finding mit Taktik-/Technik-Label.

        Wie in :meth:`GuidelineCheck._gf` wird ``span_end`` auf das
        naechste Statement-Semikolon gesetzt und ``clip_to_statement=True``
        haengt den Kontext exakt an die Statement-Zeilen, damit
        mehrzeilige Statements (z.B. ``CREATE DATABASE LINK ... CONNECT
        TO ... IDENTIFIED BY ... USING '...'`` oder ein ``GRANT`` mit
        mehrteiliger Privilegienliste) im Report vollstaendig sichtbar
        sind - ohne Nachbar-Statements oder Pre-/Post-Kommentare.

        ``single_line=True`` begrenzt Snippet/Kontext auf die Fundzeile
        (zeilenorientierte Client-/Skript-Direktiven, siehe Basisklasse).
        """
        base = message or self.message
        label = f"MITRE ATT&CK {self.id}"
        if self.tactic:
            label += f" ({self.tactic})"
        if single_line:
            ls, le = self._line_bounds(source, offset)
            return self._finding(
                source, offset, self.severity, f"{label}: {base}",
                recommendation=self.recommendation, rule_ref=self.id,
                url=self.url, span_start=ls, span_end=le,
                clip_to_statement=True)
        return self._finding(
            source, offset, self.severity, f"{label}: {base}",
            recommendation=self.recommendation, rule_ref=self.id, url=self.url,
            span_end=self._stmt_end(source, offset),
            clip_to_statement=True)


def build_mitre_checks(mitre_rules, dialect) -> list[Check]:
    """Erzeugt aus den geladenen MITRE-Regeln die aktiven Checks."""
    return [MitreCheck(rule, dialect)
            for rule in mitre_rules
            if rule.get("enabled", False)]
