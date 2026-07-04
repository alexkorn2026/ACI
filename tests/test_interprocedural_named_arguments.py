"""S2: Oracle Named Arguments in der interprozeduralen Analyse.

``sink(p_sql => p_input)`` und gemischte Aufrufe muessen dem korrekten
Parameter zugeordnet werden.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.parser import parse_expression  # noqa: F401  (Import-Sanity)
from aci.checks.sqli import CallArgument, _parse_call_args, _bind_arguments


def _ip(code, oracle_rules, dialect="oracle"):
    s = Source(code, "t.sql", dialect)
    findings = SqlInjectionCheck(
        oracle_rules.check("sql_injection"), dialect).run(s)
    return [f for f in findings if f.rule_ref == "ACI-SQLI-IP"]


def _pkg(call):
    return (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_mode VARCHAR2, p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle(p_user VARCHAR2) IS\n"
        "  BEGIN\n"
        f"    {call}\n"
        "  END;\n"
        "END;\n/\n")


# -- Argument-Parsing (Unit) ---------------------------------------------

def test_parse_named_argument():
    masked = "run_sql(p_sql => p_input)"
    code = masked
    start = masked.index("(") + 1
    end = len(masked) - 1
    args = _parse_call_args(masked, code, start, end)
    assert args == [CallArgument("P_SQL", "p_input")]


def test_parse_mixed_arguments():
    masked = "run_sql('A', p_sql => p_input)"
    code = masked
    start = masked.index("(") + 1
    end = len(masked) - 1
    args = _parse_call_args(masked, code, start, end)
    assert args[0] == CallArgument(None, "'A'")
    assert args[1] == CallArgument("P_SQL", "p_input")


def test_bind_named_and_positional():
    args = [CallArgument(None, "'A'"), CallArgument("P_SQL", "p_input")]
    bound = _bind_arguments(args, ["P_MODE", "P_SQL"])
    assert bound == {0: "'A'", 1: "p_input"}


def test_bind_unknown_name_ignored():
    args = [CallArgument("P_UNKNOWN", "x")]
    assert _bind_arguments(args, ["P_MODE", "P_SQL"]) == {}


# -- End-to-end interprozedural ------------------------------------------

def test_positional_call(oracle_rules):
    assert len(_ip(_pkg("run_sql('A', p_user);"), oracle_rules)) == 1


def test_named_call(oracle_rules):
    assert len(_ip(_pkg("run_sql(p_mode => 'A', p_sql => p_user);"),
                   oracle_rules)) == 1


def test_named_reversed_order(oracle_rules):
    assert len(_ip(_pkg("run_sql(p_sql => p_user, p_mode => 'A');"),
                   oracle_rules)) == 1


def test_mixed_positional_then_named(oracle_rules):
    assert len(_ip(_pkg("run_sql('A', p_sql => p_user);"), oracle_rules)) == 1


def test_named_case_insensitive(oracle_rules):
    assert len(_ip(_pkg("run_sql(P_SQL => p_user);"), oracle_rules)) == 1


def test_literal_named_arg_is_safe(oracle_rules):
    assert _ip(_pkg("run_sql(p_sql => 'constant');"), oracle_rules) == []


def test_sanitized_named_arg_is_safe(oracle_rules):
    assert _ip(_pkg("run_sql(p_sql => DBMS_ASSERT.ENQUOTE_NAME(p_user));"),
               oracle_rules) == []


def test_taint_to_nonsink_named_param_is_safe(oracle_rules):
    # p_user fliesst nur in p_mode (kein Sink) -> kein interproz. Finding.
    assert _ip(_pkg("run_sql(p_mode => p_user, p_sql => 'x');"),
               oracle_rules) == []
