"""Tests fuer den CodeClimate-Report (aci.reporting.render_codeclimate).

Geprueft werden die von GitLab geforderten Pflichtfelder
(description, check_name, fingerprint, severity, location.path,
location.lines.begin), die Schweregrad-Abbildung ueber das ACI-Gewicht,
die Eindeutigkeit der Fingerprints bei Mehrfach-Vorkommen sowie die
Waiver-Kennzeichnung in der Beschreibung.
"""

import datetime
import json

from aci.scanner import Scanner
from aci.reporting import ScanReport, render_codeclimate
from aci.finding import GROUP_SECURITY, Severity
from aci.waivers import Waiver

_VULN = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
# Zwei identische Bloecke -> identischer inhaltsgebundener Fingerabdruck.
_VULN_TWICE = (
    "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
    "/\n"
    "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
)
_CLEAN = "BEGIN\n  NULL;\nEND;\n"


def _report(code, oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(code, "mem.sql")
    return ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                      active_groups={GROUP_SECURITY})


def _issues(code, oracle_rules):
    return json.loads(render_codeclimate(_report(code, oracle_rules)))


# -- Grundstruktur --------------------------------------------------------

def test_codeclimate_is_json_array(oracle_rules):
    issues = _issues(_VULN, oracle_rules)
    assert isinstance(issues, list) and issues


def test_codeclimate_empty_without_findings(oracle_rules):
    assert _issues(_CLEAN, oracle_rules) == []


def test_codeclimate_required_fields(oracle_rules):
    """GitLab-Pflichtfelder laut Code-Quality-Dokumentation."""
    for issue in _issues(_VULN, oracle_rules):
        assert issue["type"] == "issue"
        assert issue["description"]
        assert issue["check_name"]
        assert issue["fingerprint"]
        assert issue["severity"] in ("info", "minor", "major",
                                     "critical", "blocker")
        assert issue["location"]["path"] == "mem.sql"
        assert issue["location"]["lines"]["begin"] >= 1


def test_codeclimate_check_name_includes_rule_ref(oracle_rules):
    names = {i["check_name"] for i in _issues(_VULN, oracle_rules)}
    assert any(n.startswith("ACI-SQLI") for n in names)


def test_codeclimate_security_category(oracle_rules):
    for issue in _issues(_VULN, oracle_rules):
        assert issue["categories"] == ["Security"]


# -- Schweregrad-Abbildung ------------------------------------------------

def test_codeclimate_severity_mapping():
    from aci.reporting.codeclimate import _cc_severity
    assert _cc_severity(Severity.INFO) == "info"
    assert _cc_severity(Severity.MINOR) == "minor"
    assert _cc_severity(Severity.WARNING) == "minor"
    assert _cc_severity(Severity.MAJOR) == "major"
    assert _cc_severity(Severity.HIGH) == "major"
    assert _cc_severity(Severity.CRITICAL) == "critical"
    assert _cc_severity(Severity.BLOCKER) == "blocker"


# -- Fingerprints ---------------------------------------------------------

def test_codeclimate_fingerprints_unique_for_duplicates(oracle_rules):
    """Identischer Code an zwei Stellen: GitLab dedupliziert nach
    Fingerprint - der Report muss die Wiederholung eindeutig machen."""
    issues = _issues(_VULN_TWICE, oracle_rules)
    fingerprints = [i["fingerprint"] for i in issues]
    assert len(fingerprints) == len(set(fingerprints))


def test_codeclimate_fingerprints_deterministic(oracle_rules):
    a = render_codeclimate(_report(_VULN_TWICE, oracle_rules))
    b = render_codeclimate(_report(_VULN_TWICE, oracle_rules))
    assert a == b


# -- Waiver ---------------------------------------------------------------

def test_codeclimate_waiver_visible_in_description(oracle_rules):
    report = _report(_VULN, oracle_rules)
    finding = report.all_findings()[0]
    finding.waiver = Waiver(
        fingerprint=finding.fingerprint or "x", ticket="SEC-123",
        owner="alex", expires=datetime.date(2099, 1, 1),
        reason="akzeptiertes Restrisiko")
    issues = json.loads(render_codeclimate(report))
    waived = [i for i in issues if "SEC-123" in i["description"]]
    assert len(waived) == 1


# -- Pfad-Normalisierung --------------------------------------------------

def test_codeclimate_path_normalisation(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "./sub\\dir/mem.sql")
    report = ScanReport({"./sub\\dir/mem.sql": findings}, oracle_rules,
                        "mem.sql", active_groups={GROUP_SECURITY})
    issues = json.loads(render_codeclimate(report))
    assert issues
    for issue in issues:
        assert issue["location"]["path"] == "sub/dir/mem.sql"
