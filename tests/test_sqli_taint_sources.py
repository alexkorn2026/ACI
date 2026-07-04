"""Tests fuer die Taint-Quellen-Erkennung des SqlInjectionCheck.

Deckt ab:
* Package-interne Routinen (PROCEDURE/FUNCTION ohne CREATE) samt Parametern,
* 1st-order-Taint  - ungepruefter Routine-Parameter in dynamischem SQL,
* 2nd-order-Taint  - SELECT/FETCH ... INTO-Wert in dynamischem SQL,
* routine-lokale Analyse innerhalb eines Package-Bodys.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.finding import Severity
from aci.parser import parse_ir


def sqli(code, oracle_rules):
    return SqlInjectionCheck(oracle_rules.check("sql_injection"), "oracle").run(
        Source(code, "t.plb", "oracle"))


def only(findings):
    assert len(findings) == 1, f"erwartet 1 Finding, erhalten {len(findings)}"
    return findings[0]


# -- IR: Package-interne Routinen, Parameter, INTO ----------------------

def test_ir_detects_package_inner_routine_with_parameters():
    sql = ("PACKAGE BODY pkg AS\n"
           "  PROCEDURE run_it(p_sql IN VARCHAR2) IS\n"
           "  BEGIN\n"
           "    EXECUTE IMMEDIATE p_sql;\n"
           "  END;\n"
           "END;\n")
    ir = parse_ir(sql, dialect="oracle")
    inner = [r for r in ir.routines if r.kind == "procedure"]
    assert len(inner) == 1
    assert inner[0].name.upper() == "RUN_IT"
    assert inner[0].parameters == ("P_SQL",)


def test_ir_records_select_into_as_write():
    sql = ("PACKAGE BODY pkg AS\n"
           "  PROCEDURE p IS\n"
           "    v VARCHAR2(100);\n"
           "  BEGIN\n"
           "    SELECT col INTO v FROM t;\n"
           "  END;\n"
           "END;\n")
    ir = parse_ir(sql, dialect="oracle")
    assert any(a.kind == "select_into" and a.target.upper() == "V"
               for a in ir.assignments)


def test_ir_records_returning_into_as_write():
    # Regression: RETURNING ... INTO ist eine 2nd-order-Schreibquelle
    # (Wert kommt aus dem DML zurueck), nicht bloss "keine Zuweisung".
    sql = ("PACKAGE BODY pkg AS\n"
           "  PROCEDURE p IS\n"
           "    v VARCHAR2(100);\n"
           "  BEGIN\n"
           "    INSERT INTO t(x) VALUES (1) RETURNING name INTO v;\n"
           "  END;\n"
           "END;\n")
    ir = parse_ir(sql, dialect="oracle")
    assert any(a.kind == "returning_into" and a.target.upper() == "V"
               for a in ir.assignments)


def test_returning_into_value_in_concatenation_is_2nd_order(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    v_tab VARCHAR2(100);\n"
            "    v_sql VARCHAR2(4000);\n"
            "  BEGIN\n"
            "    INSERT INTO log(x) VALUES (1) RETURNING tabname INTO v_tab;\n"
            "    v_sql := 'SELECT * FROM ' || v_tab;\n"
            "    EXECUTE IMMEDIATE v_sql;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


# -- 1st-order: ungepruefter Routine-Parameter --------------------------

def test_bare_parameter_execution_is_critical(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE run_it(p_sql IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE p_sql;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "1st-order" in f.message


def test_parameter_in_concatenation_is_critical_and_typed(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE run_it(p_obj IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE 'drop table ' || p_obj;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "1st-order" in f.message


def test_local_variable_without_write_stays_unknown(oracle_rules):
    # Lokale Variable, kein Parameter, kein Schreibzugriff -> Herkunft
    # unklar (High/UNKNOWN), aber nicht als Injection kritisch.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    l_sql VARCHAR2(100);\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE l_sql;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


# -- 2nd-order: Wert aus Tabelle/Cursor ---------------------------------

def test_select_into_value_executed_bare_is_2nd_order(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    l_v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT ddl_text INTO l_v FROM meta_table;\n"
            "    EXECUTE IMMEDIATE l_v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


def test_select_into_value_in_concatenation_is_2nd_order(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    l_tab VARCHAR2(100);\n"
            "  BEGIN\n"
            "    SELECT tabname INTO l_tab FROM meta;\n"
            "    EXECUTE IMMEDIATE 'select * from ' || l_tab;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


def test_fetch_into_value_is_2nd_order(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    l_v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    FETCH c INTO l_v;\n"
            "    EXECUTE IMMEDIATE l_v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


# -- routine-lokale Analyse innerhalb eines Package-Bodys ----------------

def test_assignment_in_other_package_routine_does_not_leak(oracle_rules):
    # Die gefaehrliche l_sql-Zuweisung in Prozedur a darf die Ausfuehrung
    # in Prozedur b nicht beeinflussen.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE a IS\n"
            "    l_sql VARCHAR2(100);\n"
            "  BEGIN\n"
            "    l_sql := 'drop user x';\n"
            "  END;\n"
            "  PROCEDURE b IS\n"
            "    l_sql VARCHAR2(100);\n"
            "  BEGIN\n"
            "    l_sql := 'select 1 from dual';\n"
            "    EXECUTE IMMEDIATE l_sql;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


def test_parameter_taint_does_not_leak_into_other_routine(oracle_rules):
    # Prozedur a fuehrt ihren Parameter aus (kritisch); Prozedur b fuehrt
    # nur ein Literal aus (unkritisch) - kein Uebergriff.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE a(p_sql IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE p_sql;\n"
            "  END;\n"
            "  PROCEDURE b IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE 'select 1 from dual';\n"
            "  END;\n"
            "END;\n")
    findings = sqli(code, oracle_rules)
    crit = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(crit) == 1
    assert "1st-order" in crit[0].message


# -- 2.7.1: SELECT ... INTO nach Quelle differenziert --------------------

def test_select_literal_into_then_execute_is_not_critical(oracle_rules):
    # Die SELECT-Quelle ist ein konstantes Literal -> kein Injection-Risiko.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT 'select 1 from dual' INTO v FROM dual;\n"
            "    EXECUTE IMMEDIATE v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


def test_select_sanitized_value_into_then_execute_is_sanitized(oracle_rules):
    # Die SELECT-Quelle ist über DBMS_ASSERT abgesichert -> sanitized.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p(p_t IN VARCHAR2) IS\n"
            "    v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT DBMS_ASSERT.SQL_OBJECT_NAME(p_t) INTO v FROM dual;\n"
            "    EXECUTE IMMEDIATE v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL
    assert "validierte" in f.message       # SANITIZED-Meldungstext


def test_select_table_column_into_then_execute_is_critical(oracle_rules):
    # Die SELECT-Quelle ist eine Tabellenspalte -> 2nd-order, kritisch.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT ddl_text INTO v FROM meta_table;\n"
            "    EXECUTE IMMEDIATE v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


# -- 2.8.0: zusammengesetzte SELECT-Quellen ueber die Expression-IR ------

def test_select_concat_of_literals_into_is_not_critical(oracle_rules):
    # Eine SELECT-Quelle nur aus Literalen bleibt unkritisch.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT 'select 1' || ' from dual' INTO v FROM dual;\n"
            "    EXECUTE IMMEDIATE v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity != Severity.CRITICAL


def test_select_concat_with_column_into_is_critical(oracle_rules):
    # Enthaelt die SELECT-Quelle eine Tabellenspalte -> 2nd-order.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p IS\n"
            "    v VARCHAR2(200);\n"
            "  BEGIN\n"
            "    SELECT 'select * from ' || tab_name INTO v FROM meta;\n"
            "    EXECUTE IMMEDIATE v;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.severity == Severity.CRITICAL
    assert "2nd-order" in f.message


# -- Taint-Quellen als zusätzliche Fundstellen (Related Locations) ------

def test_variable_execution_reports_all_building_assignments(oracle_rules):
    # v_cmd wird in Zeile 5 und 7 aufgebaut - beide Zuweisungen sollen
    # als Taint-Quellen am Finding hängen.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p(p_tab IN VARCHAR2) IS\n"
            "    v_cmd VARCHAR2(400);\n"
            "  BEGIN\n"
            "    v_cmd := 'ALTER TABLE ' || p_tab;\n"
            "    IF 1 = 1 THEN\n"
            "      v_cmd := v_cmd || ' ADD c NUMBER';\n"
            "    END IF;\n"
            "    EXECUTE IMMEDIATE v_cmd;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.line == 9                              # Sink: EXECUTE IMMEDIATE
    assert sorted(r.line for r in f.related) == [5, 7]
    assert all("Zuweisung" in r.label for r in f.related)
    # Sink-Kontext auf eine Zeile davor/danach reduziert
    assert [c[0] for c in f.context] == [8, 9, 10]


def test_parameter_execution_reports_routine_definition(oracle_rules):
    # Stammt der String aus einem Parameter, zeigt die Taint-Quelle den
    # Prozedur-/Funktionskopf.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE run_it(p_sql IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE p_sql;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert len(f.related) == 1
    rel = f.related[0]
    assert rel.line == 2                            # Routinenkopf
    assert "Definition der Prozedur" in rel.label
    assert "run_it" in rel.snippet


def test_related_location_is_serialised(oracle_rules):
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE run_it(p_sql IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE p_sql;\n"
            "  END;\n"
            "END;\n")
    d = only(sqli(code, oracle_rules)).to_dict()
    assert d["related"] and d["related"][0]["line"] == 2
    assert d["related"][0]["context"]


def test_direct_concat_clips_context_to_execute_statement(oracle_rules):
    # Konkatenation direkt im EXECUTE - keine separate Quelle. Mit
    # ``clip_to_statement=True`` zeigt der Kontext genau die Statement-
    # Zeile (das EXECUTE IMMEDIATE selbst), nicht die umliegenden
    # BEGIN/END-Zeilen.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE p(p_tab IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE 'DROP TABLE ' || p_tab;\n"
            "  END;\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.related == []
    assert [ln for ln, _, _ in f.context] == [4]


def test_multiline_dynamic_sql_statement_shown_completely(oracle_rules):
    # Mehrzeiliges EXECUTE IMMEDIATE: Snippet und Kontext umfassen die
    # vollständige Anweisung, nicht nur die Trigger-Zeile.
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE\n"
            "    'SELECT count(*) FROM '\n"
            "    || p_table\n"
            "    || ' WHERE x = 1';\n"
            "END;\n")
    f = only(sqli(code, oracle_rules))
    assert f.line == 2                               # Trigger-Zeile
    # Snippet trägt die ganze Anweisung (auf eine Zeile gefaltet).
    assert f.snippet.upper().startswith("EXECUTE IMMEDIATE")
    assert "WHERE x = 1" in f.snippet
    # Kontext reicht bis zur letzten Zeile der Anweisung (Zeile 5).
    assert max(c[0] for c in f.context) >= 5


def test_taint_sources_can_be_disabled(oracle_rules):
    # Mit show_taint_sources = False (Option --no-taint-sources) wird
    # keine Taint-Quelle ausgewiesen; der Sink behält den vollen Kontext.
    code = ("PACKAGE BODY pkg AS\n"
            "  PROCEDURE run_it(p_sql IN VARCHAR2) IS\n"
            "  BEGIN\n"
            "    EXECUTE IMMEDIATE p_sql;\n"
            "  END;\n"
            "END;\n")
    check = SqlInjectionCheck(oracle_rules.check("sql_injection"), "oracle")
    check.show_taint_sources = False
    f = only(check.run(Source(code, "t.plb", "oracle")))
    assert f.related == []


# -- PL/SQL-Injection (anonymer Block startet mit BEGIN/DECLARE) ---------
# PL/SQL-Injection ist eine besonders kritische Variante der SQL-Injection:
# es wird kein einzelnes Statement, sondern ein ganzer anonymer PL/SQL-Block
# injiziert (inkl. DDL/DCL und mehrerer Statements). Der Check vergibt eine
# eigene Regel-ID ``ACI-PLSQLI`` und eine eigene Meldung.


def test_plsql_injection_begin_block_is_flagged_as_plsqli(oracle_rules):
    code = (
        "CREATE OR REPLACE PROCEDURE p(p_user VARCHAR2) IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'BEGIN dbms_output.put_line(' "
        "|| p_user || '); END;';\n"
        "END;\n"
    )
    f = only(sqli(code, oracle_rules))
    assert f.rule_ref == "ACI-PLSQLI"
    assert "PL/SQL-Injection" in f.message
    assert f.severity == Severity.CRITICAL


def test_plsql_injection_declare_block_is_flagged_as_plsqli(oracle_rules):
    code = (
        "CREATE OR REPLACE PROCEDURE p(p_user VARCHAR2) IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'DECLARE v INTEGER; BEGIN v := ' "
        "|| p_user || '; END;';\n"
        "END;\n"
    )
    f = only(sqli(code, oracle_rules))
    assert f.rule_ref == "ACI-PLSQLI"
    assert "PL/SQL-Injection" in f.message


def test_regular_sql_injection_keeps_existing_rule_ref(oracle_rules):
    # Eine klassische SQL-Injection (kein BEGIN/DECLARE-Block) bleibt ein
    # SQL-Injection-Finding mit dem bisherigen rule_ref (``EXECUTE IMMEDIATE``).
    code = (
        "CREATE OR REPLACE PROCEDURE p(p_user VARCHAR2) IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\n"
        "END;\n"
    )
    f = only(sqli(code, oracle_rules))
    assert f.rule_ref != "ACI-PLSQLI"
    assert "PL/SQL-Injection" not in f.message
    assert "SQL-Injection" in f.message


def test_plsql_injection_with_q_quote_oracle_literal(oracle_rules):
    # Oracle q-Quote-Notation: q'[BEGIN ... END;]'. Der Check muss den
    # PL/SQL-Block-Praefix auch hier erkennen.
    code = (
        "CREATE OR REPLACE PROCEDURE p(p_user VARCHAR2) IS\n"
        "BEGIN\n"
        "  EXECUTE IMMEDIATE q'[BEGIN dbms_output.put_line(]' "
        "|| p_user || q'[); END;]';\n"
        "END;\n"
    )
    f = only(sqli(code, oracle_rules))
    assert f.rule_ref == "ACI-PLSQLI"


# -- PostgreSQL Dollar-Quotes als String-Literale ------------------------
# ``$tag$...$tag$`` (auch ``$$...$$``) ist in PostgreSQL ein
# String-Literal - typische Form in PL/pgSQL fuer statische SQL-Texte in
# EXECUTE/format(). Der Klassifizierer muss sie als Literale anerkennen,
# sonst landen statische ``EXECUTE $sql$...$sql$;`` als ``UNKNOWN_DYNAMIC``
# (High) statt als ``LITERAL_ONLY`` (Warning).


def _pg_sqli(code, pg_rules):
    from aci.source import Source
    from aci.checks import SqlInjectionCheck
    return SqlInjectionCheck(
        pg_rules.check("sql_injection"), "postgresql").run(
            Source(code, "t.sql", "postgresql"))


def test_pg_dollar_quoted_execute_is_literal_only(pg_rules):
    code = (
        "CREATE OR REPLACE FUNCTION f() RETURNS void AS $func$\n"
        "BEGIN\n"
        "  execute $sql$select timetable.delete_job('x')$sql$;\n"
        "END;\n"
        "$func$ LANGUAGE plpgsql;\n"
    )
    findings = _pg_sqli(code, pg_rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.label == "Warning"
    assert "ausschließlich aus einem String-Literal" in f.message


def test_pg_empty_dollar_quote_is_recognized_as_literal(pg_rules):
    code = (
        "CREATE OR REPLACE FUNCTION g() RETURNS void AS $$\n"
        "BEGIN\n"
        "  execute $$select 1$$;\n"
        "END;\n"
        "$$ LANGUAGE plpgsql;\n"
    )
    findings = _pg_sqli(code, pg_rules)
    assert len(findings) == 1
    assert findings[0].severity.label == "Warning"


def test_pg_format_with_dollar_quoted_static_format_and_unsafe_s(pg_rules):
    # ``format($sql$ ... %s ... $sql$, v_table)``: der Format-String IST
    # literal (Dollar-Quote), aber ``%s`` interpoliert v_table OHNE
    # Quoting -> TAINTED_CONCAT (Critical). Vor dem Dollar-Quote-Fix wurde
    # das faelschlich als UNKNOWN_DYNAMIC bewertet.
    code = (
        "CREATE OR REPLACE FUNCTION g(v_table text) RETURNS void AS $$\n"
        "DECLARE\n"
        "  v_count int;\n"
        "BEGIN\n"
        "  execute format($sql$select count(*) from %s$sql$, v_table)\n"
        "    into v_count;\n"
        "END;\n"
        "$$ LANGUAGE plpgsql;\n"
    )
    findings = _pg_sqli(code, pg_rules)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.label == "Critical"
