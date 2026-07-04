"""Datenmodell des Scan-Reports.

:class:`ScanReport` bündelt die Findings eines Laufs samt Kennzahlen,
Scan-Konfiguration, Regelintegrität und Waiver-Ergebnis. Die vier
Reporter (console/json/html/sarif) lesen ausschließlich aus diesem
Objekt - sie berechnen selbst nichts nach.
"""

from __future__ import annotations

import datetime

from ..finding import (Finding, GROUP_SCALES,
                        GROUP_SECURITY, GROUP_GUIDELINES, GROUP_INTERNAL)


class ScanReport:
    """Bündelt die Ergebnisse eines Scans über eine oder mehrere Dateien."""

    def __init__(self, results: dict[str, list[Finding]], ruleset, target: str,
                 active_groups=None, guideline_rules=None,
                 scanner_config=None, scanner_defaults=None,
                 scanned_bytes: int = 0,
                 scanned_loc: int = 0, duration=None,
                 html_group_by: str = "rule", waiver_report=None,
                 integrity=None, command_line: str = "",
                 ruleset_verification=None, runtime=None, gate=None,
                 config_info=None, scan_completeness=None,
                 reproducible: bool = False):
        self.results = results
        self.ruleset = ruleset
        self.target = target
        # S12: strukturierte Scan-Vollstaendigkeit (dict) oder None.
        self.scan_completeness = scan_completeness
        # S3: reproduzierbarer Report - nicht-deterministische Felder
        # (Zeitstempel) werden in den Reportern weggelassen.
        self.reproducible = bool(reproducible)
        # Ergebnis des Waiver-/Ausnahmeprozesses (aci.waivers.WaiverReport)
        # oder None, wenn keine Waiver-Datei angegeben wurde.
        self.waiver_report = waiver_report
        # Regelintegrität (aci.integrity.RulesetIntegrity): Ruleset-Hash
        # und Vertrauensstatus der geladenen Regeldateien, oder None.
        self.integrity = integrity
        # Soll-/Ist-Hash-Verifikation (--expected-ruleset-sha256/--ruleset-lock):
        # {actual_sha256, expected_sha256, verified, source} oder None.
        self.ruleset_verification = ruleset_verification
        # Audit-Metadaten (CI/CD): Laufzeitumgebung, Gate-Konfiguration,
        # Config-Herkunft. Jeweils dict oder None.
        self.runtime = runtime
        self.gate = gate
        self.config_info = config_info
        self.active_groups = (list(active_groups) if active_groups
                              else [GROUP_SECURITY, GROUP_GUIDELINES])
        self.guideline_rules = guideline_rules or []
        # Reproduzierbare Scan-Konfiguration (für Audit/CI); enthält
        # bewusst keine Pfade und keine sensiblen Daten. scanner_config
        # sind die tatsächlich verwendeten Werte, scanner_defaults die
        # in aci.ini hinterlegten Vorgaben.
        self.scanner_config = dict(scanner_config) if scanner_config else {}
        self.scanner_defaults = (dict(scanner_defaults)
                                 if scanner_defaults else {})
        # Originaler Kommandozeilenaufruf (Programmname + Argumente, jeweils
        # shell-escaped). Wird im HTML-Report als Scan-Aufruf-Block angezeigt
        # und erleichtert Audit/Reproduktion ("Womit wurde dieser Report
        # erzeugt?"). Leer, wenn nicht aus der CLI gesetzt.
        self.command_line = str(command_line or "")
        # Gruppierung der Findings im HTML-Report: "rule" oder "file".
        self.html_group_by = (html_group_by
                              if html_group_by in ("rule", "file")
                              else "rule")
        # Kennzahlen des Scans: gescannte Datenmenge, Codezeilen und
        # Laufzeit (Sekunden, ``None`` wenn nicht gemessen).
        self.scanned_bytes = int(scanned_bytes or 0)
        self.scanned_loc = int(scanned_loc or 0)
        self.duration = duration
        self.created = datetime.datetime.now()

    # ------------------------------------------------------------------
    def all_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for items in self.results.values():
            findings.extend(items)
        return findings

    def groups(self) -> list[str]:
        """Aktive Gruppen in fester Reihenfolge.

        Die Gruppe *Interner Fehler* erscheint nur, wenn tatsächlich ein
        Check fehlgeschlagen ist - sie ist keine inhaltliche Prüfgruppe.
        """
        result = [g for g in (GROUP_SECURITY, GROUP_GUIDELINES)
                  if g in self.active_groups]
        if self.findings_in_group(GROUP_INTERNAL):
            result.append(GROUP_INTERNAL)
        return result

    def internal_errors(self) -> list[Finding]:
        """Liefert die Findings fehlgeschlagener Checks (interne Fehler)."""
        return self.findings_in_group(GROUP_INTERNAL)

    def waived_findings(self) -> list[Finding]:
        """Findings, die ein gültiger Waiver deckt (im Report sichtbar,
        zählen aber nicht für ``--fail-on``)."""
        return [f for f in self.all_findings() if f.waived]

    def findings_in_group(self, group: str) -> list[Finding]:
        return [f for f in self.all_findings() if f.group == group]

    def counts_for_group(self, group: str) -> dict:
        """Anzahl Findings je Schweregrad innerhalb einer Gruppe."""
        counts = {sev: 0 for sev in GROUP_SCALES[group]}
        for finding in self.findings_in_group(group):
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def total(self) -> int:
        return len(self.all_findings())

    def total_in_group(self, group: str) -> int:
        return len(self.findings_in_group(group))

    def file_count(self) -> int:
        return len(self.results)

    def files_with_findings(self) -> int:
        return sum(1 for items in self.results.values() if items)

    def scanned_kb(self) -> int:
        """Gescannte Datenmenge in Kilobyte (kaufmännisch gerundet)."""
        return (self.scanned_bytes + 512) // 1024

    def loc(self) -> int:
        """Gescannte Codezeilen (LOC)."""
        return self.scanned_loc

    def duration_str(self) -> str:
        """Laufzeit als ``MM:SS:HH`` (Minuten:Sekunden:Hundertstel).

        Ohne gemessene Laufzeit wird ``-`` geliefert.
        """
        if self.duration is None:
            return "-"
        hundredths = max(0, int(round(float(self.duration) * 100)))
        return (f"{hundredths // 6000:02d}:"
                f"{(hundredths // 100) % 60:02d}:"
                f"{hundredths % 100:02d}")

    def guideline_coverage(self):
        """(aktive, dokumentierte) Anzahl Guideline-Regeln."""
        active = sum(1 for r in self.guideline_rules if r.get("enabled"))
        documented = sum(1 for r in self.guideline_rules if not r.get("enabled"))
        return active, documented
