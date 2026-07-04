"""Tests fuer Charge b: XML-generierende SQLi-Sinks (Oracle) und die
Session-/GUC-Taint-Quelle (PostgreSQL)."""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.finding import Severity


def _sqli(code, rules, dialect):
    s = Source(code, "t.sql", dialect)
    return SqlInjectionCheck(rules.check("sql_injection"), dialect).run(s)


def test_dbms_xmlgen_newcontext_is_sqli_sink(oracle_rules):
    code = (
        "CREATE OR REPLACE PROCEDURE p(p_name VARCHAR2) IS\n"
        "  ctx NUMBER;\n"
        "BEGIN\n"
        "  ctx := DBMS_XMLGEN.newContext("
        "'SELECT * FROM emp WHERE name=''' || p_name || '''');\n"
        "END;\n/\n")
    findings = _sqli(code, oracle_rules, "oracle")
    crit = [f for f in findings
            if f.severity == Severity.CRITICAL and f.check_id == "ACI-SQLI"]
    assert crit, "DBMS_XMLGEN.newContext mit Konkatenation muss Critical sein"
    assert any("NEWCONTEXT" in f.message.upper() for f in crit)


def test_dbms_xmlgen_literal_query_is_not_critical(oracle_rules):
    code = (
        "CREATE OR REPLACE PROCEDURE p IS\n"
        "  ctx NUMBER;\n"
        "BEGIN\n"
        "  ctx := DBMS_XMLGEN.newContext('SELECT * FROM emp');\n"
        "END;\n/\n")
    findings = _sqli(code, oracle_rules, "oracle")
    assert all(f.severity != Severity.CRITICAL for f in findings)


def test_current_setting_is_session_taint_source(pg_rules):
    code = (
        "CREATE FUNCTION f() RETURNS void AS $$\n"
        "BEGIN\n"
        "  EXECUTE 'SELECT * FROM t WHERE u = ' "
        "|| current_setting('app.uid');\n"
        "END; $$ LANGUAGE plpgsql;\n")
    findings = _sqli(code, pg_rules, "postgresql")
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert crit, "current_setting-Konkatenation muss als Injection gelten"
    assert any("GUC" in f.message or "Session" in f.message for f in crit)
