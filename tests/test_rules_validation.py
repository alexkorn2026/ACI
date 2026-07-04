"""Tests fuer die harte Regelvalidierung (aci.rules).

Geprueft wird, dass die ausgelieferten Regeldateien sauber laden und
dass fehlerhafte Regeln (ungueltiges JSON, doppelte ID, unbekannter
Schweregrad, nicht kompilierbares Regex, unbekannter Detector-Typ,
fehlende Pflichtfelder) zuverlaessig zu einem RuleError fuehren.
"""

import json
import os
import re
import shutil

import pytest

from aci.finding import Severity
from aci.rules import (RuleError, load_ruleset, find_ruleset,
                       load_guideline_rules, find_guidelines_dir,
                       load_mitre_rules, find_mitre_dir)


def _write_guideline(tmp_path, rules, category="Test"):
    """Schreibt eine Guideline-Datei und gibt das Verzeichnis zurueck."""
    (tmp_path / "rule.json").write_text(
        json.dumps({"category": category, "rules": rules}),
        encoding="utf-8")
    return str(tmp_path)


# -- Release-/Test-Infrastruktur -----------------------------------------

def test_required_fixtures_available(project_root, rules_dir,
                                     guidelines_base, mitre_base,
                                     samples_dir):
    """Die zentralen Test-Fixtures verweisen auf vorhandene Pfade -
    schlägt fehl, falls das Source-Archiv unvollständig ausgeliefert
    wurde."""
    for path in (project_root, rules_dir, guidelines_base, mitre_base,
                 samples_dir):
        assert os.path.isdir(path), path
    assert os.path.isfile(os.path.join(project_root, "aci.ini"))


# -- Ausgelieferte Regeldateien laden sauber -----------------------------

def test_oracle_ruleset_loads(rules_dir):
    rs = load_ruleset(find_ruleset("oracle", rules_dir))
    assert rs.dialect == "oracle" and rs.checks


def test_postgres_ruleset_loads(rules_dir):
    rs = load_ruleset(find_ruleset("postgresql", rules_dir))
    assert rs.dialect == "postgresql" and rs.checks


def test_shipped_guideline_rules_load(guidelines_base):
    rules = load_guideline_rules(
        find_guidelines_dir("oracle", guidelines_base), "oracle")
    assert rules
    for rule in rules:
        assert rule.get("id")
        Severity.parse(rule.get("severity", "Minor"))


def test_shipped_mitre_rules_load(mitre_base):
    rules = load_mitre_rules(find_mitre_dir("oracle", mitre_base), "oracle")
    assert rules
    for rule in rules:
        assert rule.get("id")


def test_all_shipped_rule_files_are_valid_json(rules_dir):
    count = 0
    for root, _dirs, files in os.walk(rules_dir):
        for name in files:
            if name.endswith(".json"):
                count += 1
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    json.load(fh)
    assert count >= 2


def test_shipped_guideline_builtin_detectors_are_registered(guidelines_base):
    from aci.checks import _BUILTIN_DETECTORS
    rules = load_guideline_rules(
        find_guidelines_dir("oracle", guidelines_base), "oracle")
    for rule in rules:
        det = rule.get("detector", {}) or {}
        if rule.get("enabled") and det.get("type") == "builtin":
            assert det.get("name") in _BUILTIN_DETECTORS


def test_shipped_regex_detectors_compile(guidelines_base, mitre_base):
    for loader, base, finder in (
            (load_guideline_rules, guidelines_base, find_guidelines_dir),
            (load_mitre_rules, mitre_base, find_mitre_dir)):
        for rule in loader(finder("oracle", base), "oracle"):
            det = rule.get("detector", {}) or {}
            if det.get("type") == "regex" and det.get("pattern"):
                re.compile(det["pattern"])      # darf nicht werfen


# -- Fehlerhafte Regeln fuehren zu RuleError -----------------------------

def test_unknown_dialect_raises(rules_dir):
    with pytest.raises(RuleError):
        find_ruleset("mysql", rules_dir)


def test_missing_ruleset_file_raises(tmp_path):
    with pytest.raises(RuleError):
        load_ruleset(str(tmp_path / "does_not_exist.json"))


def test_malformed_json_raises(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("{ kein gueltiges json", encoding="utf-8")
    with pytest.raises(RuleError):
        load_ruleset(str(bad))


def test_invalid_severity_in_ruleset_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "dialect": "oracle",
        "checks": {"naming_conventions": {"id": "X", "level": "Banana"}},
    }), encoding="utf-8")
    with pytest.raises(RuleError):
        load_ruleset(str(bad))


def test_invalid_obfuscation_regex_in_ruleset_raises(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "dialect": "oracle",
        "checks": {"obfuscation": {
            "id": "ACI-OBF", "enabled": True,
            "patterns": [{"id": "broken", "regex": "[abc", "level": "High"}],
        }},
    }), encoding="utf-8")
    with pytest.raises(RuleError):
        load_ruleset(str(bad))


def test_invalid_regex_rule_sample_raises(samples_dir, tmp_path):
    shutil.copy(os.path.join(samples_dir, "invalid_rule_regex.json"),
                tmp_path / "rule.json")
    with pytest.raises(RuleError):
        load_guideline_rules(str(tmp_path), "oracle")


def test_duplicate_id_sample_raises(samples_dir, tmp_path):
    shutil.copy(os.path.join(samples_dir, "invalid_rule_duplicate_id.json"),
                tmp_path / "rule.json")
    with pytest.raises(RuleError):
        load_guideline_rules(str(tmp_path), "oracle")


def test_unknown_severity_in_guideline_raises(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-BADSEV", "title": "x", "severity": "banana",
        "message": "m", "enabled": True,
        "detector": {"type": "regex", "pattern": "select"}}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_unknown_detector_type_raises(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-BADDET", "title": "x", "severity": "Minor",
        "message": "m", "enabled": True,
        "detector": {"type": "magic", "pattern": "select"}}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_empty_regex_pattern_raises(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-EMPTY", "title": "x", "severity": "Minor",
        "message": "m", "enabled": True,
        "detector": {"type": "regex", "pattern": ""}}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_missing_message_in_active_rule_raises(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-NOMSG", "title": "x", "severity": "Minor",
        "enabled": True,
        "detector": {"type": "regex", "pattern": "select"}}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_missing_id_raises(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "title": "ohne id", "severity": "Minor", "message": "m",
        "enabled": False}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_disabled_rule_without_detector_is_allowed(tmp_path):
    # Deaktivierte Regeln dokumentieren nur - kein Detector noetig.
    gdir = _write_guideline(tmp_path, [{
        "id": "G-DOC", "title": "dokumentiert", "severity": "Minor",
        "enabled": False, "coverage": "needs-parser"}])
    rules = load_guideline_rules(gdir, "oracle")
    assert len(rules) == 1


# -- Severity-Modell ------------------------------------------------------

def test_severity_parse_roundtrip():
    for sev in Severity:
        assert Severity.parse(sev.label) is sev


def test_severity_parse_invalid_raises():
    with pytest.raises(ValueError):
        Severity.parse("Nonexistent")


def test_severity_weight_ordering():
    assert (Severity.WARNING.weight < Severity.HIGH.weight
            < Severity.CRITICAL.weight)
    assert (Severity.INFO.weight < Severity.MINOR.weight
            < Severity.MAJOR.weight < Severity.BLOCKER.weight)


# -- Builtin-Detektor-Validierung ----------------------------------------

def test_unknown_builtin_detector_fails_validation(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-BADBUILTIN", "title": "x", "severity": "Minor",
        "message": "m", "enabled": True,
        "detector": {"type": "builtin", "name": "does_not_exist"}}])
    with pytest.raises(RuleError):
        load_guideline_rules(gdir, "oracle")


def test_unknown_builtin_detector_error_names_rule_and_detector(tmp_path):
    gdir = _write_guideline(tmp_path, [{
        "id": "G-BADBUILTIN", "title": "x", "severity": "Minor",
        "message": "m", "enabled": True,
        "detector": {"type": "builtin", "name": "totally_unknown"}}])
    with pytest.raises(RuleError) as exc:
        load_guideline_rules(gdir, "oracle")
    message = str(exc.value)
    assert "G-BADBUILTIN" in message and "totally_unknown" in message


def test_known_builtin_detector_passes_validation(tmp_path):
    # 'commit_in_loop' ist ein registrierter Builtin-Detektor.
    gdir = _write_guideline(tmp_path, [{
        "id": "G-OKBUILTIN", "title": "x", "severity": "Minor",
        "message": "m", "enabled": True,
        "detector": {"type": "builtin", "name": "commit_in_loop"}}])
    rules = load_guideline_rules(gdir, "oracle")
    assert len(rules) == 1


# -- Tiefe Validierung von ddl_in_code (L3) ------------------------------

def _ddl_ruleset(tmp_path, ddl_cfg):
    """Schreibt eine minimale Oracle-Regeldatei mit gegebenem
    ``ddl_in_code``-Block und gibt den Pfad zurueck."""
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(
        {"dialect": "oracle", "checks": {"ddl_in_code": ddl_cfg}}),
        encoding="utf-8")
    return str(p)


def test_critical_statement_requires_statement_field(tmp_path):
    path = _ddl_ruleset(tmp_path, {"critical_statements": [{"level": "Critical"}]})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_critical_statement_invalid_level_raises(tmp_path):
    path = _ddl_ruleset(tmp_path,
                        {"critical_statements": [{"statement": "ALTER USER",
                                                  "level": "Banana"}]})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_critical_statement_message_must_be_string(tmp_path):
    path = _ddl_ruleset(tmp_path,
                        {"critical_statements": [{"statement": "ALTER USER",
                                                  "level": "High",
                                                  "message": 123}]})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_external_table_requires_valid_level(tmp_path):
    path = _ddl_ruleset(tmp_path, {"external_table": {"message": "m"}})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_privilege_grant_requires_valid_level(tmp_path):
    path = _ddl_ruleset(tmp_path, {"privilege_grant": {"system_message": "m"}})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_privilege_grant_optional_message_must_be_string(tmp_path):
    path = _ddl_ruleset(tmp_path,
                        {"privilege_grant": {"level": "High",
                                             "role_message": 5}})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_standard_roles_must_be_string_list(tmp_path):
    path = _ddl_ruleset(tmp_path, {"standard_roles": ["DBA", ""]})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_system_privileges_must_be_list(tmp_path):
    path = _ddl_ruleset(tmp_path, {"system_privileges": "CREATE ANY TABLE"})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_harmless_object_privileges_must_be_string_list(tmp_path):
    path = _ddl_ruleset(tmp_path, {"harmless_object_privileges": ["SELECT", 7]})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_ddl_objects_must_be_string_lists(tmp_path):
    path = _ddl_ruleset(tmp_path, {"ddl_objects": {"create": ["TABLE", 1]}})
    with pytest.raises(RuleError):
        load_ruleset(path)


def test_valid_ddl_in_code_block_loads(tmp_path):
    path = _ddl_ruleset(tmp_path, {
        "critical_statements": [{"statement": "ALTER USER", "level": "Critical",
                                 "message": "m", "recommendation": "r"}],
        "external_table": {"level": "High", "message": "m"},
        "privilege_grant": {"level": "High", "system_message": "s",
                            "role_message": "r"},
        "standard_roles": ["DBA", "RESOURCE"],
        "system_privileges": ["CREATE ANY TABLE"],
        "harmless_object_privileges": ["SELECT", "INSERT"],
        "ddl_objects": {"create": ["TABLE", "PUBLICATION"]},
    })
    assert load_ruleset(path).checks


# -- Ausgelieferte Regeldateien (Package-Data) ---------------------------

def test_packaged_rule_files_are_available(rules_dir, guidelines_base,
                                           mitre_base):
    # Laden ueber denselben Mechanismus, den ACI zur Laufzeit nutzt.
    assert load_ruleset(find_ruleset("oracle", rules_dir)).checks
    assert load_ruleset(find_ruleset("postgresql", rules_dir)).checks
    assert load_guideline_rules(
        find_guidelines_dir("oracle", guidelines_base), "oracle")
    assert load_guideline_rules(
        find_guidelines_dir("postgresql", guidelines_base), "postgresql")
    assert load_mitre_rules(
        find_mitre_dir("oracle", mitre_base), "oracle")
    assert load_mitre_rules(
        find_mitre_dir("postgresql", mitre_base), "postgresql")
