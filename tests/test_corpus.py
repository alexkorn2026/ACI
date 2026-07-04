"""Corpus-/Snapshot-Tests (TODO 8): realistische SQL-Dateien gegen erwartete
Findings.

Jede ``*.sql`` unter ``tests/corpus/`` hat eine ``*.expected.json``-Datei::

    {
      "dialect": "oracle" | "postgresql",
      "group":   "security" | "guidelines" | "all",
      "findings": [ {"rule_ref": "...", "severity": "...", "line": N?} ],
      "absent":   ["RULE-ID", ...],   # optional: diese IDs duerfen NICHT auftreten
      "allow_extra": true,            # optional: weitere Findings sind ok
      "must_not_crash": true          # optional: nur Robustheit pruefen
    }

Die ``findings`` werden als *Teilmenge* geprueft (jeder erwartete Eintrag muss
vorkommen) - das haelt die Snapshots robust gegen das Hinzufuegen neuer Regeln.
Ist ``findings`` leer und ``allow_extra`` nicht gesetzt, wird auf *keine*
echten Findings geprueft (Clean-Case). ``broken.sql`` darf nur nicht crashen.
"""

import json
import os

import pytest

import aci
from aci.rules import (load_ruleset, find_ruleset, has_guidelines,
                       find_guidelines_dir, load_guideline_rules, has_mitre,
                       find_mitre_dir, load_mitre_rules)
from aci.scanner import Scanner
from aci.finding import GROUP_SECURITY, GROUP_GUIDELINES, INTERNAL_CHECK_ID

_PKG = os.path.dirname(os.path.abspath(aci.__file__))
_RULES = os.path.join(_PKG, "rules")
_GUIDE = os.path.join(_RULES, "guidelines")
_MITRE = os.path.join(_RULES, "mitre")
_CORPUS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")

_GROUPS = {
    "security": {GROUP_SECURITY},
    "guidelines": {GROUP_GUIDELINES},
    "all": {GROUP_SECURITY, GROUP_GUIDELINES},
}


def _discover():
    cases = []
    for root, _dirs, files in os.walk(_CORPUS):
        for name in sorted(files):
            if name.endswith(".sql"):
                cases.append(os.path.join(root, name))
    return sorted(cases)


def _build_scanner(dialect: str, group: str) -> Scanner:
    ruleset = load_ruleset(find_ruleset(dialect, _RULES))
    groups = _GROUPS[group]
    guideline_rules = []
    if GROUP_GUIDELINES in groups and has_guidelines(dialect):
        guideline_rules = load_guideline_rules(
            find_guidelines_dir(dialect, _GUIDE), dialect)
    mitre_rules = []
    if GROUP_SECURITY in groups and has_mitre(dialect):
        mitre_rules = load_mitre_rules(find_mitre_dir(dialect, _MITRE), dialect)
    return Scanner(ruleset, guideline_rules, mitre_rules, groups=groups)


def _matches(expected: dict, finding) -> bool:
    rid = expected.get("rule_ref")
    if rid is not None and finding.rule_ref != rid and finding.check_id != rid:
        return False
    sev = expected.get("severity")
    if sev is not None and finding.severity.label != sev:
        return False
    line = expected.get("line")
    if line is not None and finding.line != line:
        return False
    frag = expected.get("message_contains")
    if frag is not None and frag not in finding.message:
        return False
    return True


@pytest.mark.parametrize("sql_path", _discover(),
                         ids=lambda p: os.path.relpath(p, _CORPUS))
def test_corpus_case(sql_path):
    with open(sql_path[:-4] + ".expected.json", encoding="utf-8") as fh:
        spec = json.load(fh)
    scanner = _build_scanner(spec["dialect"], spec.get("group", "security"))
    # Robustheit: der Scan darf bei keiner Corpus-Datei eine Ausnahme werfen.
    results = scanner.scan_path(sql_path)
    findings = [f for fs in results.values() for f in fs]

    for expected in spec.get("findings", []):
        assert any(_matches(expected, f) for f in findings), (
            f"erwartetes Finding fehlt: {expected}\n"
            f"erhalten: {[(f.check_id, f.rule_ref, f.severity.label, f.line) for f in findings]}")

    for absent in spec.get("absent", []):
        assert not any(f.rule_ref == absent or f.check_id == absent
                       for f in findings), f"unerwartetes Finding: {absent}"

    if not spec.get("findings") and not spec.get("allow_extra"):
        real = [f for f in findings if f.check_id != INTERNAL_CHECK_ID]
        assert real == [], (
            "Clean-Case erwartet keine Findings, erhalten: "
            f"{[(f.check_id, f.rule_ref, f.line) for f in real]}")
