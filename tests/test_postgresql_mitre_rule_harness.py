"""Generic rule-test harness for PostgreSQL MITRE rules.

Every active PostgreSQL MITRE rule must have a positive and negative SQL
example. The harness keeps rule examples close to the rule IDs and prevents
silent regressions when MITRE files are reorganized by tactic.
"""

import json
from pathlib import Path

import pytest

from aci.source import Source
from aci.checks import build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir


CASES_PATH = Path(__file__).parent / "rules" / "postgresql" / "mitre" / "cases.json"


def _pg_mitre(code, mitre_base):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base), "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "rule_case.sql", "postgresql")
    findings = []
    for check in checks:
        findings.extend(check.run(source))
    return findings


@pytest.fixture(scope="module")
def mitre_cases():
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def test_every_active_postgresql_mitre_rule_has_a_case(mitre_base, mitre_cases):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base), "postgresql")
    active_ids = {rule["id"] for rule in rules if rule.get("enabled", False)}
    case_ids = {case["rule_id"] for case in mitre_cases}
    assert active_ids <= case_ids


@pytest.mark.parametrize("case", json.loads(CASES_PATH.read_text(encoding="utf-8")))
def test_postgresql_mitre_positive_case_triggers_rule(case, mitre_base):
    findings = _pg_mitre(case["positive"], mitre_base)
    assert any(f.check_id == case["rule_id"] for f in findings), case["rule_id"]


@pytest.mark.parametrize("case", json.loads(CASES_PATH.read_text(encoding="utf-8")))
def test_postgresql_mitre_negative_case_does_not_trigger_rule(case, mitre_base):
    findings = _pg_mitre(case["negative"], mitre_base)
    assert not any(f.check_id == case["rule_id"] for f in findings), case["rule_id"]
