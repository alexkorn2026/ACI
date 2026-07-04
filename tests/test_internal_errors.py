"""Tests fuer die Behandlung interner Check-Fehler.

Schlaegt ein Check selbst fehl, erscheint das als ACI-INTERNAL-Finding
der Gruppe 'Interner Fehler' (Schweregrad mindestens High). Mit
``--strict-internal-errors`` fuehrt ein interner Fehler zu Exit-Code 2.
"""

import os

from aci.scanner import Scanner
from aci.finding import (GROUP_SECURITY, GROUP_INTERNAL, INTERNAL_CHECK_ID,
                         Severity)
from aci.cli import main


class BoomCheck:
    """Ein Check, der absichtlich immer fehlschlaegt."""

    id = "BOOM-1"
    name = "Absichtlich fehlerhafter Check"
    group = GROUP_SECURITY
    report_context = True
    context_lines = 3

    def run(self, source):
        raise RuntimeError("absichtlicher Testfehler")


def _boom_run(self, source):
    raise RuntimeError("absichtlicher Testfehler im Check")


def test_internal_error_becomes_finding(oracle_rules):
    sc = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    sc.checks.append(BoomCheck())
    findings = sc.scan_text("BEGIN\n  NULL;\nEND;\n", "t.sql")
    internal = [f for f in findings if f.group == GROUP_INTERNAL]
    assert internal
    assert internal[0].check_id == INTERNAL_CHECK_ID
    assert internal[0].severity == Severity.HIGH


def test_internal_error_does_not_abort_other_checks(oracle_rules):
    sc = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    sc.checks.append(BoomCheck())
    findings = sc.scan_text(
        "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n",
        "t.sql")
    # Trotz des fehlerhaften Checks liefert die SQL-Injection-Erkennung.
    assert any(f.check_id == "ACI-SQLI" for f in findings)
    assert any(f.group == GROUP_INTERNAL for f in findings)


def test_internal_error_severity_at_least_high(oracle_rules):
    sc = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    sc.checks.append(BoomCheck())
    findings = sc.scan_text("BEGIN\n  NULL;\nEND;\n", "t.sql")
    internal = [f for f in findings if f.group == GROUP_INTERNAL]
    assert internal
    assert all(f.severity.weight >= Severity.HIGH.weight for f in internal)


def test_clean_scan_has_no_internal_errors(oracle_rules):
    sc = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = sc.scan_text("BEGIN\n  NULL;\nEND;\n", "t.sql")
    assert [f for f in findings if f.group == GROUP_INTERNAL] == []


def test_strict_internal_errors_returns_exit_code_two(samples_dir,
                                                      monkeypatch):
    import aci.checks as checks
    monkeypatch.setattr(checks.NamingCheck, "run", _boom_run)
    rc = main([os.path.join(samples_dir, "oracle_safe.sql"),
               "-g", "security", "--strict-internal-errors"])
    assert rc == 2


def test_without_strict_internal_error_does_not_force_failure(samples_dir,
                                                              monkeypatch):
    import aci.checks as checks
    monkeypatch.setattr(checks.NamingCheck, "run", _boom_run)
    # Ohne --strict und ohne --fail-on bleibt der Exit-Code 0.
    rc = main([os.path.join(samples_dir, "oracle_safe.sql"), "-g", "security"])
    assert rc == 0


def test_internal_error_survives_min_level_filter(samples_dir, monkeypatch):
    import aci.checks as checks
    monkeypatch.setattr(checks.NamingCheck, "run", _boom_run)
    # --min-level critical wuerde HIGH-Findings normalerweise herausfiltern;
    # interne Fehler bleiben dennoch erhalten und loesen --strict aus.
    rc = main([os.path.join(samples_dir, "oracle_safe.sql"), "-g", "security",
               "--min-level", "critical", "--strict-internal-errors"])
    assert rc == 2
