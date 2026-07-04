"""Oracle-SQL-Injection-Tests.

Prueft die Risikoklassifikation dynamischen SQLs: unsichere
Konkatenation ist kritisch, Bindevariablen und DBMS_ASSERT-Sanitizer
sind es nicht, und dynamisches SQL unbekannter Herkunft wird gesondert
als UNKNOWN_DYNAMIC gemeldet.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.finding import Severity


def sqli(code, oracle_rules):
    s = Source(code, "t.sql", "oracle")
    return SqlInjectionCheck(
        oracle_rules.check("sql_injection"), "oracle").run(s)


def only(findings):
    assert len(findings) == 1, f"erwartet 1 Finding, erhalten {len(findings)}"
    return findings[0]


def test_unsafe_concatenation_is_critical(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p(p_name IN VARCHAR2) AS\n"
            "BEGIN\n"
            "  EXECUTE IMMEDIATE 'select * from users where name = ''' "
            "|| p_name || '''';\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert f.check_id == "ACI-SQLI"


def test_bind_variable_is_not_critical(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p(p_id IN NUMBER) AS\n"
            "BEGIN\n"
            "  EXECUTE IMMEDIATE 'select * from users where id = :1' "
            "USING p_id;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(f.severity != Severity.CRITICAL for f in findings)
    # Bindevariable ohne variable Anteile -> idealerweise gar kein Finding
    assert findings == []


def test_enquote_literal_sanitizer_is_not_critical(oracle_rules):
    code = ("DECLARE l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from t where c = ' "
            "|| DBMS_ASSERT.ENQUOTE_LITERAL(x);\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(f.severity != Severity.CRITICAL for f in findings)


def test_sql_object_name_sanitizer_is_not_critical(oracle_rules):
    code = ("DECLARE l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from ' "
            "|| DBMS_ASSERT.SQL_OBJECT_NAME(p_table);\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(f.severity != Severity.CRITICAL for f in findings)


def test_simple_sql_name_sanitizer_is_not_critical(oracle_rules):
    code = ("DECLARE l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select ' || DBMS_ASSERT.SIMPLE_SQL_NAME(p_col) "
            "|| ' from t';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(f.severity != Severity.CRITICAL for f in findings)


def test_unvalidated_variable_concatenation_is_critical(oracle_rules):
    code = ("DECLARE l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from users where ' || p_where;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity in (Severity.CRITICAL, Severity.HIGH)


def test_unknown_dynamic_sql_is_flagged(oracle_rules):
    code = ("DECLARE l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := get_sql_from_somewhere();\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    # UNKNOWN_DYNAMIC -> High (oder Warning), aber kein falscher Literal-Befund
    assert f.severity in (Severity.HIGH, Severity.WARNING)
    assert "literal" not in f.message.lower()


def test_literal_only_concatenation_is_warning(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'CREATE TABLE t ' || 'AS SELECT 1 "
            "FROM dual';\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.WARNING


def test_open_for_static_select_is_safe(oracle_rules):
    code = "BEGIN\n  OPEN c FOR SELECT * FROM dual;\nEND;\n/\n"
    assert sqli(code, oracle_rules) == []


def test_open_for_with_concatenation_is_critical(oracle_rules):
    code = ("BEGIN\n  OPEN c FOR 'SELECT * FROM emp WHERE id = ' || p_id;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_dbms_sql_parse_with_concatenation_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  DBMS_SQL.PARSE(l_c, 'GRANT DBA TO ' || p_user, "
            "DBMS_SQL.NATIVE);\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_plain_static_sql_has_no_finding(oracle_rules):
    code = ("BEGIN\n"
            "  SELECT salary INTO l_sal FROM emp WHERE id = p_id;\n"
            "END;\n/\n")
    assert sqli(code, oracle_rules) == []


def test_sanitized_variable_then_concatenation_is_not_critical(oracle_rules):
    # a wird mit DBMS_ASSERT abgesichert und danach konkateniert -
    # die Taint-Verfolgung loest das auf -> kein Critical.
    code = ("DECLARE a VARCHAR2(100); l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  a := DBMS_ASSERT.ENQUOTE_LITERAL(p_in);\n"
            "  l_sql := 'select * from t where c = ' || a;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(f.severity != Severity.CRITICAL for f in findings)


def test_tainted_variable_then_concatenation_stays_critical(oracle_rules):
    # a haelt ungeprueften Input -> die Konkatenation bleibt kritisch.
    code = ("DECLARE a VARCHAR2(100); l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  a := p_in;\n"
            "  l_sql := 'select * from t where c = ' || a;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_finding_reports_trigger_line(oracle_rules):
    code = ("BEGIN\n"
            "  NULL;\n"
            "  EXECUTE IMMEDIATE 'SELECT ' || p_col || ' FROM emp';\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.line == 3


# -- Positionssensitive Zuweisungsanalyse --------------------------------

def test_dangerous_assignment_after_execution_is_ignored(oracle_rules):
    # Die gefaehrliche Zuweisung steht NACH der Ausfuehrung - sie darf
    # das Finding nicht kritisch machen.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


def test_dangerous_assignment_before_execution_is_critical(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from ' || p_table;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_branching_assignments_before_execution_are_conservative(oracle_rules):
    # Beide Zuweisungen liegen vor der Ausfuehrung und koennen sie
    # erreichen -> konservativ als kritisch bewerten.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from ' || p_table;\n"
            "  IF p_table IS NOT NULL THEN\n"
            "    l_sql := 'select * from safe_table';\n"
            "  END IF;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_assignment_in_other_routine_does_not_leak(oracle_rules):
    # Die gefaehrliche l_sql-Zuweisung in Prozedur a darf das Finding
    # in Prozedur b nicht beeinflussen (routine-lokale Analyse).
    code = ("CREATE OR REPLACE PROCEDURE a(p VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'drop table ' || p;\n"
            "  NULL;\n"
            "END;\n/\n"
            "CREATE OR REPLACE PROCEDURE b AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    findings = sqli(code, oracle_rules)
    assert all(x.severity != Severity.CRITICAL for x in findings)


# -- Dead-Assignment-Elimination (geradliniger Code) ---------------------

def test_straight_line_overwrite_is_not_critical(oracle_rules):
    # Geradliniger Code: die gefaehrliche Zuweisung wird vor der
    # Ausfuehrung bedingungslos durch eine harmlose ueberschrieben -
    # sie ist toter Code und darf das Finding nicht kritisch machen.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "  l_sql := 'select * from safe_table';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


def test_straight_line_last_assignment_dangerous_is_critical(oracle_rules):
    # Spiegelbild: die letzte (wirksame) Zuweisung ist die gefaehrliche.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_conditional_overwrite_keeps_conservative_critical(oracle_rules):
    # Die gefaehrliche Zuweisung steht in einem IF-Zweig und kann
    # ausfallen - sie ueberschreibt die harmlose nicht bedingungslos,
    # also bleibt es konservativ bei Critical.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  IF p_table IS NOT NULL THEN\n"
            "    l_sql := 'drop table ' || p_table;\n"
            "  END IF;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL


def test_self_referencing_last_assignment_keeps_taint(oracle_rules):
    # Die letzte Zuweisung liest die Variable selbst (l_sql := l_sql
    # || ...) - der frueher eingebrachte Taint fliesst weiter ein und
    # darf nicht durch Dead-Assignment-Elimination verloren gehen.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table VARCHAR2) AS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "  l_sql := l_sql || ' cascade';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
