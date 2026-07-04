"""SARIF-2.1.0-Report (z.B. für GitHub/GitLab Code Scanning)."""

from __future__ import annotations

import json

from .._version import __version__
from ..finding import Finding, Severity
from .report import ScanReport


# Abbildung der ACI-Schweregrade auf die vier SARIF-Stufen
# (error, warning, note, none).
_SARIF_LEVEL = {
    Severity.BLOCKER: "error",
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MAJOR: "warning",
    Severity.WARNING: "warning",
    Severity.MINOR: "note",
    Severity.INFO: "note",
}


def _sarif_level(severity: Severity) -> str:
    return _SARIF_LEVEL.get(severity, "warning")


def _sarif_uri(path: str) -> str:
    """Normalisiert einen Dateipfad für die SARIF-``artifactLocation``."""
    return str(path).replace("\\", "/")


def _sarif_rule_id(finding: Finding) -> str:
    """SARIF-``ruleId`` eines Findings.

    Der Regelkatalog wird je *konkreter* Regelreferenz geführt
    (``check_id:rule_ref``), nicht nur je ``check_id``. So verfolgen
    GitHub-/GitLab-Security-Dashboards einzelne Regeln getrennt - etwa
    die verschiedenen unerwünschten Pakete unter ``ACI-PKG`` oder die
    einzelnen MITRE-Indikatoren. Fehlt ``rule_ref`` oder gleicht sie der
    ``check_id``, bleibt es bei der reinen ``check_id``.
    """
    ref = (finding.rule_ref or "").strip()
    if ref and ref != finding.check_id:
        return f"{finding.check_id}:{ref}"
    return finding.check_id


def render_sarif(report: ScanReport) -> str:
    """Erzeugt einen SARIF-2.1.0-Report.

    SARIF (Static Analysis Results Interchange Format) ist ein
    standardisiertes JSON-Format für Static-Analysis-Werkzeuge und wird
    u.a. von GitHub Code Scanning eingelesen. Der Report enthält genau
    einen ``run`` mit dem Werkzeug-Treiber, dem Regelkatalog
    (``rules``) und den Findings (``results``).
    """
    # Regelkatalog (reportingDescriptor) aufbauen - je konkreter
    # Regelreferenz (check_id:rule_ref) einmal, damit Dashboards einzelne
    # Regeln getrennt verfolgen.
    rule_index: dict = {}
    rules: list = []
    for finding in report.all_findings():
        rid = _sarif_rule_id(finding)
        if rid in rule_index:
            # helpUri nachtragen, falls erst später eine URL auftaucht.
            existing = rules[rule_index[rid]]
            if finding.url and not existing.get("helpUri"):
                existing["helpUri"] = finding.url
            continue
        rule_index[rid] = len(rules)
        descriptor: dict = {"id": rid, "name": finding.check_name or rid}
        ref = (finding.rule_ref or "").strip()
        # Kurzbeschreibung: bei eigener Regelreferenz wird sie ergänzt,
        # sodass die einzelnen Regeln im Dashboard unterscheidbar sind.
        if finding.check_name and ref and ref != finding.check_id:
            descriptor["shortDescription"] = {
                "text": f"{finding.check_name} – {ref}"}
        elif finding.check_name:
            descriptor["shortDescription"] = {"text": finding.check_name}
        rule_props: dict = {"check_id": finding.check_id}
        if ref:
            rule_props["rule_ref"] = ref
        descriptor["properties"] = rule_props
        if finding.url:
            descriptor["helpUri"] = finding.url
        rules.append(descriptor)

    results = []
    for path, file_findings in sorted(report.results.items()):
        for f in file_findings:
            region: dict = {
                "startLine": max(1, f.line),
                "startColumn": max(1, f.column),
            }
            if f.snippet:
                region["snippet"] = {"text": f.snippet}
            properties: dict = {
                "aci_severity": f.severity.label,
                "group": f.group,
            }
            if f.recommendation:
                properties["recommendation"] = f.recommendation
            if f.rule_ref:
                properties["rule_ref"] = f.rule_ref
            if f.fingerprint:
                properties["aci_fingerprint"] = f.fingerprint
            rid = _sarif_rule_id(f)
            result: dict = {
                "ruleId": rid,
                "ruleIndex": rule_index[rid],
                "level": _sarif_level(f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(f.file)},
                        "region": region,
                    },
                }],
                "properties": properties,
            }
            # Inhaltsgebundener Fingerabdruck für stabiles Finding-
            # Tracking in GitHub/GitLab-Dashboards.
            if f.fingerprint:
                result["partialFingerprints"] = {
                    "aciFingerprint/v1": f.fingerprint,
                }
            # Gewaiverte Findings als SARIF-Suppression ausweisen - das
            # Security-Dashboard erkennt die kontrollierte Ausnahme nativ.
            if f.waiver is not None:
                w = f.waiver
                result["suppressions"] = [{
                    "kind": "external",
                    "status": "accepted",
                    "justification": (
                        f"Waiver {w.ticket} (Owner {w.owner}, gültig bis "
                        f"{w.expires_str}): {w.reason}"),
                }]
            # Taint-Quellen als SARIF-relatedLocations (Sink + Quelle).
            related_locations = []
            for rel in f.related:
                rel_region: dict = {
                    "startLine": max(1, rel.line),
                    "startColumn": max(1, rel.column or 1),
                }
                if rel.snippet:
                    rel_region["snippet"] = {"text": rel.snippet}
                related_locations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(rel.file)},
                        "region": rel_region,
                    },
                    "message": {"text": rel.label},
                })
            if related_locations:
                result["relatedLocations"] = related_locations
            results.append(result)

    run: dict = {
        "tool": {
            "driver": {
                "name": "ACI",
                "fullName": "ACI - Automated Code Inspection",
                "version": __version__,
                "rules": rules,
            },
        },
        "columnKind": "unicodeCodePoints",
        "results": results,
    }
    # Audit-/Gate-Metadaten als run-Properties (SARIF-konform): Ruleset-Hash,
    # Integritäts-Verifikation, Laufzeit-, Gate- und Config-Herkunft machen
    # den Lauf im Security-Dashboard nachvollziehbar.
    props: dict = {}
    if report.integrity is not None:
        props["aci_ruleset_hash"] = report.integrity.ruleset_hash
        props["aci_ruleset_trusted"] = report.integrity.trusted
    if report.ruleset_verification is not None:
        props["aci_ruleset_integrity"] = report.ruleset_verification
    if report.runtime is not None:
        props["aci_runtime"] = report.runtime
    if report.gate is not None:
        props["aci_gate"] = report.gate
    if report.scan_completeness is not None:
        props["aci_scan_completeness"] = report.scan_completeness
    if report.config_info is not None:
        props["aci_config"] = report.config_info
    if props:
        run["properties"] = props
    log = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }
    return json.dumps(log, indent=2, ensure_ascii=False)
