"""Tests fuer die interprozedurale Taint-Analyse (Charge a).

Erkannt wird, wenn ein ungeprueftes Argument ueber einen Routinenaufruf in
das dynamische SQL einer Hilfsroutine derselben Datei fliesst.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.finding import Severity


def _sqli(code, oracle_rules, dialect="oracle"):
    s = Source(code, "t.sql", dialect)
    return SqlInjectionCheck(
        oracle_rules.check("sql_injection"), dialect).run(s)


def _interproc(findings):
    return [f for f in findings if f.rule_ref == "ACI-SQLI-IP"]


def test_interprocedural_parameter_passthrough(oracle_rules):
    code = (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle(p_user VARCHAR2) IS\n"
        "  BEGIN\n"
        "    run_sql(p_user);\n"
        "  END;\n"
        "END;\n/\n")
    ip = _interproc(_sqli(code, oracle_rules))
    assert len(ip) == 1
    assert ip[0].severity == Severity.CRITICAL
    # Der Befund sitzt an der Aufrufstelle (Zeile 8), nicht am Sink (Zeile 4).
    assert ip[0].line == 8
    assert "run_sql" in ip[0].message.lower()


def test_interprocedural_literal_arg_is_safe(oracle_rules):
    code = (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle IS\n"
        "  BEGIN\n"
        "    run_sql('constant');\n"
        "  END;\n"
        "END;\n/\n")
    assert _interproc(_sqli(code, oracle_rules)) == []


def test_interprocedural_sanitized_arg_is_safe(oracle_rules):
    code = (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle(p_user VARCHAR2) IS\n"
        "  BEGIN\n"
        "    run_sql(DBMS_ASSERT.ENQUOTE_NAME(p_user));\n"
        "  END;\n"
        "END;\n/\n")
    assert _interproc(_sqli(code, oracle_rules)) == []


def test_interprocedural_disabled_via_config(oracle_rules):
    code = (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle(p_user VARCHAR2) IS\n"
        "  BEGIN\n"
        "    run_sql(p_user);\n"
        "  END;\n"
        "END;\n/\n")
    cfg = dict(oracle_rules.check("sql_injection"))
    cfg["interprocedural"] = False
    s = Source(code, "t.sql", "oracle")
    findings = SqlInjectionCheck(cfg, "oracle").run(s)
    assert [f for f in findings if f.rule_ref == "ACI-SQLI-IP"] == []
