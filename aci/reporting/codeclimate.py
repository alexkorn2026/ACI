"""CodeClimate-Report (GitLab Code Quality Widget).

GitLab liest im CI-Job ein ``codequality``-Artefakt im CodeClimate-
Subset-Format ein und zeigt die Issues direkt im Merge-Request-Widget
sowie im Diff an. Pflichtfelder laut GitLab-Dokumentation:
``description``, ``check_name``, ``fingerprint``, ``severity`` sowie
``location.path`` und ``location.lines.begin``.

Schweregrad-Abbildung über das ACI-Gewicht (beide Skalen konsistent):

====== ==================== ===============
Gewicht ACI                  CodeClimate
====== ==================== ===============
1      Info                 info
2      Minor / Warning      minor
3      Major / High         major
4      Critical             critical
5      Blocker              blocker
====== ==================== ===============

GitLab dedupliziert Issues anhand des ``fingerprint``. Der inhalts-
gebundene ACI-Fingerabdruck kann bei identischem Code mehrfach
auftreten (Multiset-Semantik); für den Report wird deshalb bei
Wiederholungen ein deterministischer Zähler angehängt, damit kein
Finding im Widget verschwindet.
"""

from __future__ import annotations

import hashlib
import json

from ..finding import GROUP_SECURITY, Finding, Severity
from .report import ScanReport

# Abbildung ACI-Gewicht -> CodeClimate-Schweregrad.
_CC_SEVERITY = {1: "info", 2: "minor", 3: "major", 4: "critical",
                5: "blocker"}


def _cc_severity(severity: Severity) -> str:
    return _CC_SEVERITY.get(severity.weight, "major")


def _cc_path(path: str) -> str:
    """Normalisiert den Pfad für GitLab (relativ, Forward-Slashes)."""
    norm = str(path).replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def _base_fingerprint(finding: Finding) -> str:
    """Fingerabdruck des Findings (Fallback: stabiler Hash der Kerndaten)."""
    if finding.fingerprint:
        return finding.fingerprint
    raw = "\x1f".join((finding.check_id, finding.rule_ref or "",
                       _cc_path(finding.file), str(finding.line),
                       finding.message))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def render_codeclimate(report: ScanReport) -> str:
    """Erzeugt einen CodeClimate-Report (GitLab Code Quality).

    Ausgabe ist ein JSON-Array von Issues. Gewaiverte Findings bleiben
    sichtbar (Beschreibung nennt das Waiver-Ticket), zählen aber wie
    überall in ACI nicht für das Gate - das Gate selbst wird über den
    Exit-Code entschieden, nicht über dieses Artefakt.
    """
    issues = []
    seen: dict = {}
    for path, file_findings in sorted(report.results.items()):
        for f in file_findings:
            fingerprint = _base_fingerprint(f)
            # GitLab dedupliziert identische Fingerprints - Wiederholungen
            # deterministisch eindeutig machen (sortierte Iteration).
            count = seen.get(fingerprint, 0)
            seen[fingerprint] = count + 1
            if count:
                fingerprint = f"{fingerprint}-{count + 1}"
            description = f.message
            if f.waiver is not None:
                description += f" (Waiver {f.waiver.ticket})"
            check_name = f.check_id
            ref = (f.rule_ref or "").strip()
            if ref and ref != f.check_id:
                check_name = f"{f.check_id}:{ref}"
            issue: dict = {
                "type": "issue",
                "check_name": check_name,
                "description": description,
                "categories": ["Security"] if f.group == GROUP_SECURITY
                              else ["Style"],
                "severity": _cc_severity(f.severity),
                "fingerprint": fingerprint,
                "location": {
                    "path": _cc_path(f.file),
                    "lines": {"begin": max(1, f.line)},
                },
            }
            if f.recommendation:
                issue["content"] = {"body": f.recommendation}
            issues.append(issue)
    return json.dumps(issues, indent=2, ensure_ascii=False)
