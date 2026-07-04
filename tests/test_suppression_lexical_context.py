"""M1: Inline-Suppressions werden nur in echten Kommentaren erkannt.

Eine identische Zeichenfolge in einem String-Literal (einfaches Literal,
q-Quote, Dollar-Quote, quoted identifier, dynamisches SQL, RAISE NOTICE)
darf keine Suppression ausloesen.
"""

from aci.source import Source
from aci.suppressions import apply_suppressions
from aci.finding import Finding, Severity, GROUP_SECURITY


def _f(line, rule_ref="ACI-SQLI", check_id="ACI-SQLI"):
    return Finding(check_id=check_id, check_name="x", group=GROUP_SECURITY,
                   severity=Severity.CRITICAL, file="t.sql", line=line,
                   column=1, message="m", rule_ref=rule_ref,
                   fingerprint="0123456789abcdef")


def _suppressed(code, line, dialect="oracle", rule_ref="ACI-SQLI"):
    src = Source(code, "t.sql", dialect)
    kept, supp = apply_suppressions([_f(line, rule_ref)], src)
    return len(supp) == 1 and kept == []


# -- Positivtests: echte Kommentare --------------------------------------

def test_line_comment_own_line_suppresses_next_code():
    assert _suppressed("-- aci:ignore\nEXECUTE IMMEDIATE p_sql;\n", 2)


def test_line_comment_end_of_code_line():
    assert _suppressed("EXECUTE IMMEDIATE p_sql; -- aci:ignore\n", 1)


def test_block_comment_own_line_suppresses_next_code():
    assert _suppressed("/* aci:ignore */\nEXECUTE IMMEDIATE p_sql;\n", 2)


# -- Negativtests: Literale duerfen nie unterdruecken --------------------

def test_string_literal_does_not_suppress():
    assert not _suppressed("v_text := '-- aci:ignore';\n", 1)


def test_block_comment_text_in_string_does_not_suppress():
    assert not _suppressed("v_text := '/* aci:ignore */';\n", 1)


def test_dynamic_sql_concat_string_does_not_suppress():
    code = ("EXECUTE IMMEDIATE\n"
            "  'SELECT * FROM t WHERE id=' || p_id || ' -- aci:ignore';\n")
    # Finding auf der EXECUTE-Zeile (1) bzw. der Ausdruckszeile (2) - keines
    # darf durch die Zeichenfolge im String unterdrueckt werden.
    assert not _suppressed(code, 1)
    assert not _suppressed(code, 2)


def test_select_string_literal_does_not_suppress():
    assert not _suppressed("SELECT '-- aci:ignore' FROM dual;\n", 1)


def test_raise_notice_string_does_not_suppress():
    code = ("CREATE FUNCTION f() RETURNS void AS $$\n"
            "BEGIN\n"
            "  RAISE NOTICE '-- aci:ignore';\n"
            "END; $$ LANGUAGE plpgsql;\n")
    assert not _suppressed(code, 3, dialect="postgresql")


def test_oracle_q_quote_does_not_suppress():
    assert not _suppressed("v_text := q'[-- aci:ignore]';\n", 1)


def test_dollar_quote_does_not_suppress():
    assert not _suppressed("v_text := $tag$-- aci:ignore$tag$;\n", 1,
                           dialect="postgresql")


def test_nested_quote_in_string_does_not_suppress():
    assert not _suppressed("v_text := '\"-- aci:ignore\"';\n", 1)


# -- Regel-Filter, Wildcard, ungueltig, ACI-INTERNAL ---------------------

def test_rule_specific_only_matches_that_rule():
    src = Source("risky; -- aci:ignore[ACI-SQLI]\n", "t.sql", "oracle")
    kept, supp = apply_suppressions(
        [_f(1, "ACI-SQLI", "ACI-SQLI"), _f(1, "ACI-DDL", "ACI-DDL")], src)
    assert len(supp) == 1 and supp[0].rule_ref == "ACI-SQLI"
    assert len(kept) == 1 and kept[0].rule_ref == "ACI-DDL"


def test_wildcard_suppresses_all_on_line():
    src = Source("risky; -- aci:ignore\n", "t.sql", "oracle")
    kept, supp = apply_suppressions(
        [_f(1, "ACI-SQLI", "ACI-SQLI"), _f(1, "ACI-DDL", "ACI-DDL")], src)
    assert kept == [] and len(supp) == 2


def test_invalid_directive_is_ignored():
    # "aci:ignoreall" ist keine gueltige Direktive (\b nach ignore fehlt).
    assert not _suppressed("risky; -- aci:ignoreall\n", 1)


def test_internal_error_not_suppressed():
    src = Source("boom -- aci:ignore\n", "t.sql", "oracle")
    kept, supp = apply_suppressions(
        [_f(1, "ACI-INTERNAL", "ACI-INTERNAL")], src)
    assert supp == [] and len(kept) == 1
