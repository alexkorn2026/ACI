"""S13: Governance fuer Inline-Suppressions (Metadaten + Ablauf)."""

import datetime

from aci.source import Source
from aci.suppressions import (governance_problems, apply_suppressions,
                              parse_directives)
from aci.finding import Finding, Severity, GROUP_SECURITY


def _src(text):
    return Source(text, "t.sql", "oracle")


def _f(line, rule="ACI-SQLI"):
    return Finding(check_id=rule, check_name="x", group=GROUP_SECURITY,
                   severity=Severity.CRITICAL, file="t.sql", line=line,
                   column=1, message="m", rule_ref=rule)


def test_missing_metadata_is_reported():
    src = _src("v := a;  -- aci:ignore[ACI-SQLI]\n")
    probs = governance_problems(src)
    assert any(kind == "missing_metadata" for _, kind, _ in probs)


def test_full_metadata_has_no_problem():
    src = _src('v := a;  -- aci:ignore[ACI-SQLI] ticket=SEC-1 '
               'reason="legacy" expires=2999-01-01\n')
    assert governance_problems(src) == []


def test_invalid_expires_is_reported():
    src = _src('v := a;  -- aci:ignore ticket=T reason="r" expires=not-a-date\n')
    assert any(k == "invalid_expires" for _, k, _ in governance_problems(src))


def test_expired_directive_does_not_suppress():
    src = _src('v := a;  -- aci:ignore[ACI-SQLI] ticket=T reason="r" '
               'expires=2000-01-01\n')
    kept, supp = apply_suppressions([_f(1)], src)
    assert supp == [] and len(kept) == 1        # abgelaufen => nicht mehr still


def test_valid_future_directive_suppresses():
    src = _src('v := a;  -- aci:ignore[ACI-SQLI] ticket=T reason="r" '
               'expires=2999-01-01\n')
    kept, supp = apply_suppressions([_f(1)], src)
    assert len(supp) == 1 and kept == []


def test_expired_reported_by_governance():
    src = _src('v := a;  -- aci:ignore ticket=T reason="r" expires=2000-01-01\n')
    today = datetime.date(2026, 1, 1)
    probs = governance_problems(src, today=today)
    assert any(k == "expired" for _, k, _ in probs)


def test_parse_directives_reads_metadata():
    src = _src('v := a;  -- aci:ignore[ACI-SQLI] ticket=SEC-9 owner=alex '
               'reason="weil"\n')
    ds = parse_directives(src.text, src.tokens, src.code_no_comments)
    assert ds and ds[0]["ticket"] == "SEC-9" and ds[0]["owner"] == "alex"
    assert ds[0]["reason"] == "weil"
