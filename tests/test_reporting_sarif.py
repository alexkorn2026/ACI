"""Tests fuer den SARIF-Report (aci.reporting.render_sarif).

Geprueft werden die SARIF-2.1.0-Grundstruktur (Schema, Tool-Treiber,
Regelkatalog), die Schweregrad-Abbildung auf SARIF-Stufen sowie die
Fundstellen-Angaben (locations/region).
"""

import json

import aci
from aci.scanner import Scanner
from aci.reporting import ScanReport, render_sarif
from aci.finding import GROUP_SECURITY

_VULN = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
_CLEAN = "BEGIN\n  NULL;\nEND;\n"


def _report(code, oracle_rules, report_context=True):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY},
                      report_context=report_context)
    findings = scanner.scan_text(code, "mem.sql")
    return ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                      active_groups={GROUP_SECURITY})


def _sarif(code, oracle_rules, report_context=True):
    return json.loads(render_sarif(_report(code, oracle_rules,
                                           report_context)))


# -- Grundstruktur --------------------------------------------------------

def test_sarif_is_valid_json_and_versioned(oracle_rules):
    data = _sarif(_VULN, oracle_rules)
    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert isinstance(data["runs"], list) and len(data["runs"]) == 1


def test_sarif_tool_driver(oracle_rules):
    driver = _sarif(_VULN, oracle_rules)["runs"][0]["tool"]["driver"]
    assert driver["name"] == "ACI"
    assert driver["version"] == aci.__version__
    assert isinstance(driver["rules"], list) and driver["rules"]


def test_sarif_results_reference_valid_rule_index(oracle_rules):
    run = _sarif(_VULN, oracle_rules)["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["results"]
    for result in run["results"]:
        idx = result["ruleIndex"]
        assert 0 <= idx < len(rules)
        # ruleId und der per ruleIndex referenzierte Eintrag passen.
        assert rules[idx]["id"] == result["ruleId"]


def test_sarif_result_has_location(oracle_rules):
    result = _sarif(_VULN, oracle_rules)["runs"][0]["results"][0]
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "mem.sql"
    region = loc["region"]
    assert region["startLine"] >= 1 and region["startColumn"] >= 1


def test_sarif_result_message_and_rule_id(oracle_rules):
    result = _sarif(_VULN, oracle_rules)["runs"][0]["results"][0]
    # ruleId ist je konkreter Regelreferenz geführt (check_id:rule_ref).
    assert result["ruleId"].split(":")[0] == "ACI-SQLI"
    assert result["message"]["text"]


def test_sarif_rule_id_includes_rule_ref(oracle_rules):
    # Der Regelkatalog trennt je rule_ref - die SQL-Injection-Regel
    # erscheint als "ACI-SQLI:EXECUTE IMMEDIATE".
    run = _sarif(_VULN, oracle_rules)["runs"][0]
    ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert "ACI-SQLI:EXECUTE IMMEDIATE" in ids
    descr = next(r for r in run["tool"]["driver"]["rules"]
                 if r["id"] == "ACI-SQLI:EXECUTE IMMEDIATE")
    assert descr["properties"]["check_id"] == "ACI-SQLI"
    assert descr["properties"]["rule_ref"] == "EXECUTE IMMEDIATE"


# -- Schweregrad-Abbildung -----------------------------------------------

def test_sarif_level_is_valid(oracle_rules):
    valid = {"error", "warning", "note", "none"}
    for result in _sarif(_VULN, oracle_rules)["runs"][0]["results"]:
        assert result["level"] in valid


def test_sarif_critical_maps_to_error(oracle_rules):
    # Die ungepruefte Konkatenation ist Critical -> SARIF-Level "error".
    results = _sarif(_VULN, oracle_rules)["runs"][0]["results"]
    sqli = [r for r in results if r["ruleId"].split(":")[0] == "ACI-SQLI"]
    assert sqli and any(r["level"] == "error" for r in sqli)
    assert any(r["properties"]["aci_severity"] == "Critical" for r in sqli)


# -- Kontext / Sonderfaelle ----------------------------------------------

def test_sarif_clean_code_has_empty_results(oracle_rules):
    data = _sarif(_CLEAN, oracle_rules)
    assert data["runs"][0]["results"] == []


def test_sarif_snippet_omitted_without_context(oracle_rules):
    data = _sarif(_VULN, oracle_rules, report_context=False)
    for result in data["runs"][0]["results"]:
        region = result["locations"][0]["physicalLocation"]["region"]
        assert "snippet" not in region


def test_sarif_preserves_umlauts(oracle_rules):
    raw = render_sarif(_report(_VULN, oracle_rules))
    assert "\\u00" not in raw
