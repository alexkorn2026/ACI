"""Tests fuer den JSON-Report (aci.reporting.render_json)."""

import json

import aci
from aci.scanner import Scanner
from aci.reporting import ScanReport, render_json
from aci.finding import GROUP_SECURITY, Severity

_VULN = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
_CLEAN = "BEGIN\n  NULL;\nEND;\n"


def _report(code, oracle_rules, report_context=True):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY},
                      report_context=report_context)
    findings = scanner.scan_text(code, "mem.sql")
    return ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                      active_groups={GROUP_SECURITY})


def test_render_json_is_valid_json(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    assert data["tool"].startswith("ACI")
    assert data["dialect"] == "oracle"
    assert "summary" in data and "files" in data


def test_json_version_matches_package(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    assert data["version"] == aci.__version__


def test_json_reports_findings(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    assert data["summary"]["findings_total"] >= 1
    assert data["files"][0]["findings"]


def test_json_finding_has_required_keys(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    finding = data["files"][0]["findings"][0]
    for key in ("check_id", "check_name", "group", "severity", "file",
                "line", "column", "message", "snippet", "context"):
        assert key in finding


def test_json_severity_labels_are_valid(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    valid = {s.label for s in Severity}
    for fileblock in data["files"]:
        for finding in fileblock["findings"]:
            assert finding["severity"] in valid


def test_json_context_structure(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    context = data["files"][0]["findings"][0]["context"]
    assert isinstance(context, list) and context
    assert {"line", "text", "finding"} <= set(context[0].keys())
    assert any(row["finding"] for row in context)


def test_json_no_context_when_disabled(oracle_rules):
    data = json.loads(render_json(
        _report(_VULN, oracle_rules, report_context=False)))
    for fileblock in data["files"]:
        for finding in fileblock["findings"]:
            assert finding["context"] == []
            assert finding["snippet"] == ""


def test_json_clean_code_has_no_findings(oracle_rules):
    data = json.loads(render_json(_report(_CLEAN, oracle_rules)))
    assert data["summary"]["findings_total"] == 0
    assert data["files"][0]["findings"] == []


def test_json_preserves_umlauts(oracle_rules):
    raw = render_json(_report(_VULN, oracle_rules))
    # ensure_ascii=False -> echte Umlaute statt \uXXXX-Escapes
    assert "\\u00" not in raw
    assert ("ö" in raw or "ü" in raw or "ä" in raw)


def test_json_contains_scanner_config_key(oracle_rules):
    data = json.loads(render_json(_report(_VULN, oracle_rules)))
    assert "scanner_config" in data


def test_json_scanner_config_is_passed_through(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "mem.sql")
    config = {"dialect": "oracle", "group": "security", "fail_on": "high"}
    report = ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        scanner_config=config)
    data = json.loads(render_json(report))
    assert data["scanner_config"]["dialect"] == "oracle"
    assert data["scanner_config"]["fail_on"] == "high"


def test_json_includes_scanner_defaults(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "mem.sql")
    report = ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        scanner_config={"fail_on": "high"},
                        scanner_defaults={"fail_on": "none"})
    data = json.loads(render_json(report))
    assert data["scanner_defaults"]["fail_on"] == "none"
    assert data["scanner_config"]["fail_on"] == "high"
