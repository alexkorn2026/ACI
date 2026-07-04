"""Tests fuer die DDL-Erkennung.

DDL muss als eigenstaendige Anweisung *und* in dynamischem SQL erkannt
werden - aber niemals, wenn das DDL-Schluesselwort nur in einem
Kommentar, einem String-Argument oder einem Dollar-Quote-String steht.
"""

from aci.source import Source
from aci.checks import DdlCheck
from aci.finding import Severity


def ddl(code, rules, dialect="oracle"):
    s = Source(code, "t.sql", dialect)
    return DdlCheck(rules.check("ddl_in_code"), dialect).run(s)


def kws(findings):
    return sorted(f.rule_ref for f in findings)


# -- L4: DDL-Vokabular datengetrieben ------------------------------------

def test_new_ddl_object_type_via_rule_config(oracle_rules):
    # Ein per Regeldatei ergaenzter CREATE-Objekttyp (PUBLICATION) wird ohne
    # Codeaenderung erkannt; das Default-Regex kennt ihn nicht.
    code = "CREATE PUBLICATION p FOR ALL TABLES;\n"
    assert "CREATE" not in kws(ddl(code, oracle_rules))   # Default: unbekannt
    cfg = dict(oracle_rules.check("ddl_in_code"))
    cfg["ddl_objects"] = {"create": ["TABLE", "PUBLICATION"]}
    f = DdlCheck(cfg, "oracle").run(Source(code, "t.sql", "oracle"))
    assert "CREATE" in kws(f)


def test_ddl_objects_config_does_not_break_prose(oracle_rules):
    # FP-Schutz bleibt: normaler Text loest auch mit Config kein DDL aus.
    cfg = dict(oracle_rules.check("ddl_in_code"))
    cfg["ddl_objects"] = {"create": ["TABLE", "PUBLICATION"]}
    s = Source("Please create a new publication next week.\n", "t.sql", "oracle")
    assert DdlCheck(cfg, "oracle").run(s) == []


# -- Oracle: eigenstaendige DDL muss erkannt werden ----------------------

def test_create_user_is_detected(oracle_rules):
    f = ddl("CREATE USER test IDENTIFIED BY x;\n", oracle_rules)
    assert "CREATE" in kws(f)


def test_drop_user_is_detected(oracle_rules):
    f = ddl("DROP USER test;\n", oracle_rules)
    assert "DROP" in kws(f)


def test_alter_system_is_detected(oracle_rules):
    f = ddl("ALTER SYSTEM SET audit_trail = DB;\n", oracle_rules)
    assert "ALTER" in kws(f)


def test_create_directory_is_detected(oracle_rules):
    f = ddl("CREATE DIRECTORY demo_dir AS '/tmp';\n", oracle_rules)
    assert "CREATE" in kws(f)


def test_grant_is_detected(oracle_rules):
    f = ddl("GRANT DBA TO test;\n", oracle_rules)
    assert f
    assert all(x.check_id == "ACI-DDL" for x in f)
    assert any(x.rule_ref.startswith("GRANT") for x in f)


# -- PostgreSQL: eigenstaendige DDL --------------------------------------

def test_create_extension_is_detected(pg_rules):
    f = ddl("CREATE EXTENSION dblink;\n", pg_rules, "postgresql")
    assert "CREATE" in kws(f)


def test_drop_role_is_detected(pg_rules):
    f = ddl("DROP ROLE test;\n", pg_rules, "postgresql")
    assert "DROP" in kws(f)


def test_pg_alter_system_is_detected(pg_rules):
    f = ddl("ALTER SYSTEM SET log_statement = 'all';\n",
            pg_rules, "postgresql")
    assert "ALTER" in kws(f)


def test_create_role_is_detected(pg_rules):
    f = ddl("CREATE ROLE test LOGIN;\n", pg_rules, "postgresql")
    assert "CREATE" in kws(f)


# -- Dynamische DDL muss erkannt werden ----------------------------------

def test_dynamic_ddl_in_execute_immediate(oracle_rules):
    code = "BEGIN\n  EXECUTE IMMEDIATE 'DROP USER ' || p_user;\nEND;\n"
    f = ddl(code, oracle_rules)
    assert "DROP" in kws(f)
    assert any("dynamischem SQL" in x.message for x in f)


def test_dynamic_ddl_via_variable_assignment(oracle_rules):
    code = ("BEGIN\n"
            "  l_sql := 'DROP USER ' || p_user;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n")
    f = ddl(code, oracle_rules)
    assert "DROP" in kws(f)


def test_dynamic_ddl_in_pg_execute(pg_rules):
    code = ("CREATE FUNCTION f(p_table text) RETURNS void AS $func$\n"
            "BEGIN\n  EXECUTE 'DROP TABLE ' || p_table;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    f = ddl(code, pg_rules, "postgresql")
    assert "DROP" in kws(f)


# -- DDL-Schluesselworte ohne echte DDL duerfen kein Finding erzeugen ----

def test_ddl_in_single_line_comment_not_detected(oracle_rules):
    assert ddl("-- DROP USER test;\nSELECT 1 FROM dual;\n", oracle_rules) == []


def test_ddl_in_multiline_comment_not_detected(oracle_rules):
    assert ddl("/* DROP USER test; CREATE USER x; */\n", oracle_rules) == []


def test_ddl_in_select_string_not_detected(pg_rules):
    assert ddl("SELECT 'DROP USER test';\n", pg_rules, "postgresql") == []


def test_ddl_in_dbms_output_string_not_detected(oracle_rules):
    code = "BEGIN\n  DBMS_OUTPUT.PUT_LINE('DROP USER test');\nEND;\n"
    assert ddl(code, oracle_rules) == []


def test_ddl_in_raise_notice_string_not_detected(pg_rules):
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "BEGIN\n  RAISE NOTICE 'DROP USER test';\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    assert ddl(code, pg_rules, "postgresql") == []


def test_ddl_in_dollar_quote_string_not_detected(pg_rules):
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "BEGIN\n  RAISE NOTICE $msg$DROP USER test$msg$;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    assert ddl(code, pg_rules, "postgresql") == []


def test_object_definition_not_flagged_as_ddl(oracle_rules):
    # CREATE PROCEDURE/FUNCTION/PACKAGE ist eine Objektdefinition,
    # keine zu meldende DDL-Anweisung im Code.
    code = ("CREATE OR REPLACE PROCEDURE p IS\nBEGIN\n  NULL;\nEND;\n/\n")
    assert ddl(code, oracle_rules) == []


def test_plain_dml_is_not_flagged(oracle_rules):
    code = ("BEGIN\n"
            "  UPDATE employees SET salary = 0 WHERE id = 1;\n"
            "  INSERT INTO logs VALUES (1);\n"
            "  DELETE FROM temp;\n"
            "END;\n")
    assert ddl(code, oracle_rules) == []


# -- Konfigurierbare Allowlist (in CI/CD erlaubte DDL) -------------------

def test_create_table_is_allowed(oracle_rules):
    assert ddl("CREATE TABLE kunden (id NUMBER, name VARCHAR2(100));\n",
               oracle_rules) == []


def test_create_sequence_is_allowed(oracle_rules):
    assert ddl("CREATE SEQUENCE kunden_seq START WITH 1;\n",
               oracle_rules) == []


def test_create_index_is_allowed(oracle_rules):
    assert ddl("CREATE INDEX kunden_idx ON kunden (name);\n",
               oracle_rules) == []


def test_alter_table_is_allowed(oracle_rules):
    assert ddl("ALTER TABLE kunden ADD (plz VARCHAR2(5));\n",
               oracle_rules) == []


def test_drop_table_is_allowed(oracle_rules):
    assert ddl("DROP TABLE kunden;\n", oracle_rules) == []


def test_create_or_replace_view_is_allowed(oracle_rules):
    assert ddl("CREATE OR REPLACE VIEW v_kunden AS SELECT * FROM kunden;\n",
               oracle_rules) == []


def test_create_user_still_flagged_despite_allowlist(oracle_rules):
    # CREATE USER steht NICHT auf der Allowlist und bleibt meldepflichtig.
    assert "CREATE" in kws(ddl("CREATE USER test IDENTIFIED BY x;\n",
                               oracle_rules))


def test_alter_system_still_flagged_despite_allowlist(oracle_rules):
    assert "ALTER" in kws(ddl("ALTER SYSTEM SET audit_trail = DB;\n",
                              oracle_rules))


def test_allowlist_does_not_apply_to_dynamic_ddl(oracle_rules):
    # Dynamisch zusammengesetzte DDL bleibt meldepflichtig, auch wenn
    # CREATE TABLE als eigenstaendige Anweisung erlaubt ist.
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'CREATE TABLE tmp_x (id NUMBER)';\n"
            "END;\n")
    assert "CREATE" in kws(ddl(code, oracle_rules))


# -- Externe Tabellen bleiben trotz Allowlist meldepflichtig -------------

_EXT_TABLE = (
    "CREATE TABLE ext_data (\n"
    "  id   NUMBER,\n"
    "  name VARCHAR2(100)\n"
    ")\n"
    "ORGANIZATION EXTERNAL (\n"
    "  TYPE ORACLE_LOADER\n"
    "  DEFAULT DIRECTORY data_dir\n"
    "  ACCESS PARAMETERS (RECORDS DELIMITED BY NEWLINE)\n"
    "  LOCATION ('data.csv')\n"
    ");\n")


def test_external_table_is_flagged(oracle_rules):
    f = ddl(_EXT_TABLE, oracle_rules)
    assert len(f) == 1
    assert f[0].rule_ref == "EXTERNAL TABLE"
    assert "Externe Tabelle" in f[0].message


def test_external_table_in_dynamic_sql_is_flagged(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'CREATE TABLE ext_x (c VARCHAR2(10)) "
            "ORGANIZATION EXTERNAL (TYPE ORACLE_LOADER DEFAULT DIRECTORY d "
            "LOCATION (''f.csv''))';\n"
            "END;\n")
    f = ddl(code, oracle_rules)
    assert any(x.rule_ref == "EXTERNAL TABLE" for x in f)


# -- ALTER USER ist Critical (Benutzerverwaltung) ------------------------

def test_oracle_alter_user_is_critical(oracle_rules):
    f = ddl("ALTER USER dbsec QUOTA UNLIMITED ON users;\n", oracle_rules)
    assert len(f) == 1
    assert f[0].severity == Severity.CRITICAL
    assert "ALTER USER" in f[0].message
    assert f[0].rule_ref == "ALTER USER"


def test_oracle_alter_user_variants_are_critical(oracle_rules):
    variants = [
        'ALTER USER app IDENTIFIED BY "secret";',
        "ALTER USER app ACCOUNT UNLOCK;",
        "ALTER USER app DEFAULT TABLESPACE users;",
        "ALTER USER app TEMPORARY TABLESPACE temp;",
        "ALTER USER app QUOTA 100M ON users;",
        "ALTER USER app PROFILE app_profile;",
        "ALTER USER app DEFAULT ROLE connect;",
    ]
    for sql in variants:
        f = ddl(sql + "\n", oracle_rules)
        assert any(x.severity == Severity.CRITICAL
                   and x.rule_ref == "ALTER USER" for x in f), sql


def test_oracle_alter_user_in_comment_is_ignored(oracle_rules):
    code = ("-- ALTER USER dbsec QUOTA UNLIMITED ON users;\n"
            "SELECT 1 FROM dual;\n")
    assert ddl(code, oracle_rules) == []


def test_oracle_alter_user_in_string_is_ignored(oracle_rules):
    code = "SELECT 'ALTER USER dbsec QUOTA UNLIMITED ON users' FROM dual;\n"
    assert ddl(code, oracle_rules) == []


def test_oracle_alter_user_in_dynamic_sql_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'ALTER USER app ACCOUNT UNLOCK';\n"
            "END;\n")
    f = ddl(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL for x in f)


def test_oracle_dynamic_grant_standard_role_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'GRANT DBA TO app_user';\n"
            "END;\n/\n")
    f = ddl(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL
               and x.rule_ref == "GRANT STANDARD ROLE" for x in f)


def test_oracle_dynamic_grant_system_privilege_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'GRANT CREATE SESSION TO app_user';\n"
            "END;\n/\n")
    f = ddl(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL
               and x.rule_ref == "GRANT SYSTEM PRIVILEGE" for x in f)


def test_oracle_dynamic_revoke_standard_role_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'REVOKE DBA FROM app_user';\n"
            "END;\n/\n")
    f = ddl(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL
               and x.rule_ref == "REVOKE STANDARD ROLE" for x in f)


def test_oracle_dynamic_admin_sql_in_comment_is_ignored(oracle_rules):
    code = ("-- EXECUTE IMMEDIATE 'ALTER USER app ACCOUNT UNLOCK';\n"
            "SELECT 1 FROM dual;\n")
    assert ddl(code, oracle_rules) == []


def test_oracle_dynamic_admin_sql_in_string_is_ignored(oracle_rules):
    code = "SELECT 'EXECUTE IMMEDIATE ''GRANT DBA TO app_user''' FROM dual;\n"
    assert ddl(code, oracle_rules) == []


# -- GRANT/REVOKE von Systemprivilegien und Standardrollen ist Critical --

def test_oracle_grant_system_privileges_multiline_is_critical(oracle_rules):
    code = ("GRANT  ALTER USER\n"
            "    ,  CREATE PROCEDURE\n"
            "    ,  CREATE ROLE\n"
            "    ,  CREATE SESSION\n"
            "TO app_user;\n")
    f = ddl(code, oracle_rules)
    assert len(f) == 1                       # ein Statement -> ein Finding
    assert f[0].severity == Severity.CRITICAL
    assert f[0].rule_ref == "GRANT SYSTEM PRIVILEGE"


def test_oracle_grant_single_system_privilege_is_critical(oracle_rules):
    for sql in ("GRANT CREATE SESSION TO app_user;",
                "GRANT ALTER USER TO app_admin;",
                "GRANT CREATE ANY TABLE TO app_owner;",
                "grant create session to app_user;"):
        f = ddl(sql + "\n", oracle_rules)
        assert any(x.severity == Severity.CRITICAL
                   and x.rule_ref == "GRANT SYSTEM PRIVILEGE"
                   for x in f), sql


def test_oracle_grant_standard_roles_is_critical(oracle_rules):
    code = "GRANT CONNECT, RESOURCE, DBA TO app_user;\n"
    f = ddl(code, oracle_rules)
    assert len(f) == 1
    assert f[0].severity == Severity.CRITICAL
    assert f[0].rule_ref == "GRANT STANDARD ROLE"


def test_oracle_grant_standard_roles_multiline_is_critical(oracle_rules):
    code = "GRANT CONNECT,\n      RESOURCE,\n      DBA\nTO app_user;\n"
    f = ddl(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL for x in f)


def test_oracle_revoke_system_privileges_is_critical(oracle_rules):
    code = "REVOKE ALTER USER, CREATE SESSION FROM app_user;\n"
    f = ddl(code, oracle_rules)
    assert len(f) == 1
    assert f[0].severity == Severity.CRITICAL
    assert f[0].rule_ref == "REVOKE SYSTEM PRIVILEGE"


def test_oracle_revoke_standard_roles_is_critical(oracle_rules):
    code = "REVOKE CONNECT, DBA FROM app_user;\n"
    f = ddl(code, oracle_rules)
    assert len(f) == 1
    assert f[0].severity == Severity.CRITICAL
    assert f[0].rule_ref == "REVOKE STANDARD ROLE"


def test_oracle_grant_standard_role_in_string_is_ignored(oracle_rules):
    code = "SELECT 'GRANT DBA TO app_user' FROM dual;\n"
    assert ddl(code, oracle_rules) == []


def test_oracle_grant_in_comment_is_ignored(oracle_rules):
    code = "/*\nGRANT CREATE SESSION TO app_user;\n*/\nSELECT 1 FROM dual;\n"
    assert ddl(code, oracle_rules) == []


def test_grant_object_privilege_keeps_base_classification(oracle_rules):
    # GRANT ... ON <Objekt> ... ist ein Objektprivileg, keine
    # System-/Rollenvergabe.
    f = ddl("GRANT SELECT ON hr.employees TO app_role;\n", oracle_rules)
    assert all(x.rule_ref == "GRANT" for x in f)


# -- ALTER SESSION SET NLS_*: harmlos (False Positive) -------------------

def test_alter_session_set_nls_dynamic_is_not_flagged(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'ALTER SESSION SET NLS_DATE_FORMAT="
            "''YYYY-MM-DD''';\n"
            "END;\n")
    assert ddl(code, oracle_rules) == []


def test_alter_session_set_nls_standalone_is_not_flagged(oracle_rules):
    assert ddl("ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD';\n",
               oracle_rules) == []


def test_alter_session_non_nls_is_still_flagged(oracle_rules):
    f = ddl("ALTER SESSION SET CURRENT_SCHEMA = hr;\n", oracle_rules)
    assert any(x.rule_ref == "ALTER" for x in f)


# -- Dynamische DDL: positions- und routinesensitiv ----------------------

def test_dynamic_ddl_ignores_assignment_after_execution(oracle_rules):
    # Die gefaehrliche Zuweisung steht NACH dem EXECUTE IMMEDIATE -
    # sie darf kein DDL-Finding erzeugen.
    code = ("CREATE OR REPLACE PROCEDURE p(p_table varchar2) AS\n"
            "  l_sql varchar2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "END;\n/\n")
    assert "DROP" not in kws(ddl(code, oracle_rules))


def test_dynamic_ddl_detects_assignment_before_execution(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p(p_table varchar2) AS\n"
            "  l_sql varchar2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'drop table ' || p_table;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    assert "DROP" in kws(ddl(code, oracle_rules))


def test_dynamic_ddl_ignores_assignment_in_other_routine(oracle_rules):
    # Die l_sql-Zuweisung in Prozedur b darf das EXECUTE in Prozedur a
    # nicht beeinflussen (routine-lokale Analyse).
    code = ("CREATE OR REPLACE PROCEDURE a AS\n"
            "  l_sql varchar2(1000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from safe_table';\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n"
            "CREATE OR REPLACE PROCEDURE b(p_user varchar2) AS\n"
            "  l_sql varchar2(1000);\n"
            "BEGIN\n"
            "  l_sql := 'DROP USER ' || p_user;\n"
            "END;\n/\n")
    assert "DROP" not in kws(ddl(code, oracle_rules))


def test_dynamic_ddl_detects_prior_assignment_in_same_routine(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p(p_user varchar2) AS\n"
            "  l_sql varchar2(1000);\n"
            "BEGIN\n"
            "  l_sql := 'DROP USER ' || p_user;\n"
            "  EXECUTE IMMEDIATE l_sql;\n"
            "END;\n/\n")
    assert "DROP" in kws(ddl(code, oracle_rules))


# -- Mehrere DDL-/GRANT-/REVOKE-Anweisungen pro Zeile --------------------

def test_multiple_creates_on_one_line_yield_two_findings(oracle_rules):
    code = "CREATE USER a IDENTIFIED BY x; CREATE DIRECTORY d AS '/tmp';\n"
    f = ddl(code, oracle_rules)
    assert len(f) == 2


def test_multiple_grants_on_one_line_yield_two_findings(oracle_rules):
    f = ddl("GRANT CONNECT TO a; GRANT DBA TO b;\n", oracle_rules)
    assert len(f) == 2
    assert all(x.severity == Severity.CRITICAL for x in f)


def test_multiple_revokes_on_one_line_yield_two_findings(oracle_rules):
    f = ddl("REVOKE CONNECT FROM a; REVOKE DBA FROM b;\n", oracle_rules)
    assert len(f) == 2
    assert all(x.severity == Severity.CRITICAL for x in f)


# -- Harmlose Objektprivilegien-GRANTs (CI/CD) ---------------------------

def test_harmless_object_grant_select_is_not_flagged(oracle_rules):
    # SELECT-GRANT auf ein Objekt an eine Rolle ist in CI/CD gewollt.
    code = ("GRANT SELECT on castor_stager.BaseAddress to castor_read;\n"
            "GRANT SELECT on castor_stager.Client to castor_read;\n")
    assert ddl(code, oracle_rules) == []


def test_harmless_object_grant_dml_combination_is_not_flagged(oracle_rules):
    code = "GRANT INSERT, UPDATE, DELETE ON app.orders TO app_write;\n"
    assert ddl(code, oracle_rules) == []


def test_object_grant_with_execute_is_still_flagged(oracle_rules):
    # EXECUTE ist kein harmloses DML-Recht -> weiterhin Finding.
    f = ddl("GRANT EXECUTE ON app.secret_pkg TO app_role;\n", oracle_rules)
    assert "GRANT" in kws(f)


def test_object_grant_with_alter_is_still_flagged(oracle_rules):
    # Eine Mischung mit ALTER ist nicht mehr harmlos.
    f = ddl("GRANT SELECT, ALTER ON app.orders TO app_role;\n", oracle_rules)
    assert "GRANT" in kws(f)


def test_role_grant_is_still_flagged(oracle_rules):
    # GRANT einer Rolle (kein Objektprivileg, kein ON) bleibt Finding.
    f = ddl("GRANT DBA TO app_user;\n", oracle_rules)
    assert f


def test_dynamic_object_grant_is_still_flagged(oracle_rules):
    # In dynamischem SQL gebildete GRANTs bleiben meldepflichtig.
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'GRANT SELECT ON app.orders TO app_read';\n"
            "END;\n")
    assert "GRANT" in kws(ddl(code, oracle_rules))


def test_harmless_object_revoke_is_not_flagged(oracle_rules):
    # REVOKE harmloser DML-Rechte auf ein Objekt ist - wie das GRANT -
    # in CI/CD gewollt und kein Finding.
    code = ("REVOKE SELECT ON castor_stager.BaseAddress FROM castor_read;\n"
            "REVOKE INSERT, UPDATE, DELETE ON app.orders FROM app_write;\n")
    assert ddl(code, oracle_rules) == []


def test_object_revoke_with_execute_is_still_flagged(oracle_rules):
    f = ddl("REVOKE EXECUTE ON app.secret_pkg FROM app_role;\n", oracle_rules)
    assert "REVOKE" in kws(f)


def test_role_revoke_is_still_flagged(oracle_rules):
    # REVOKE einer Rolle (kein Objektprivileg) bleibt Finding.
    f = ddl("REVOKE DBA FROM app_user;\n", oracle_rules)
    assert f


# -- PostgreSQL: COPY ... FROM stdin Datenblöcke sind kein Code ----------

def test_grant_in_postgresql_copy_data_is_not_flagged(pg_rules):
    # 'GRANT' als Namensbestandteil in COPY-FROM-stdin-Daten ist kein DDL.
    code = ("COPY public.actor (actor_id, first_name, last_name) FROM stdin;\n"
            "9471\tADAM\tGRANT\n"
            "9673\tGARY\tPENN\n"
            "\\.\n")
    assert ddl(code, pg_rules, "postgresql") == []


def test_real_grant_after_copy_data_is_still_flagged(pg_rules):
    # Nach dem COPY-Datenblock (\\.) wird echtes DDL wieder erkannt.
    code = ("COPY t (a) FROM stdin;\n"
            "GRANT\n"
            "\\.\n"
            "GRANT ALL ON public.secret TO PUBLIC;\n")
    assert "GRANT" in kws(ddl(code, pg_rules, "postgresql"))


def test_create_schema_is_allowed_in_postgresql(pg_rules):
    # CREATE SCHEMA gehoert in PostgreSQL zu den erlaubten Deployment-DDL.
    assert ddl("CREATE SCHEMA app;\n", pg_rules, "postgresql") == []
    assert ddl("CREATE SCHEMA IF NOT EXISTS app;\n",
               pg_rules, "postgresql") == []


def test_create_extension_still_flagged_in_postgresql(pg_rules):
    # Nicht erlaubte CREATE-DDL bleibt gemeldet.
    assert "CREATE" in kws(ddl("CREATE EXTENSION dblink;\n",
                               pg_rules, "postgresql"))


def test_chained_ddl_context_collapses_to_finding_line(oracle_rules):
    # Eine Reihe gleichartiger DROP-Anweisungen: jedes Finding zeigt im
    # Kontext nur die eigene Zeile - die Nachbarn sind eigene Findings.
    code = ("DROP TYPE t1 FORCE;\n"
            "DROP TYPE t2 FORCE;\n"
            "DROP TYPE t3 FORCE;\n"
            "DROP TYPE t4 FORCE;\n")
    findings = ddl(code, oracle_rules)
    assert len(findings) == 4
    for f in findings:
        assert [c[0] for c in f.context] == [f.line]


def test_isolated_ddl_keeps_full_context(oracle_rules):
    # DDL-Findings klemmen den Kontext auf die Statement-Zeilen
    # (``clip_to_statement=True``): ein einzeiliges DROP TYPE zeigt nur
    # seine eigene Zeile, nicht das umgebende PL/SQL-Padding.
    code = ("BEGIN\n"
            "  NULL;\n"
            "END;\n"
            "/\n"
            "DROP TYPE lonely_type FORCE;\n"
            "BEGIN\n"
            "  NULL;\n"
            "END;\n"
            "/\n")
    drop = [f for f in ddl(code, oracle_rules) if f.line == 5]
    assert len(drop) == 1
    assert [ln for ln, _, _ in drop[0].context] == [5]


# -- Taint-Quelle bei DDL in dynamischem SQL -----------------------------

_DYN_DDL = ("CREATE OR REPLACE PROCEDURE p(p_idx VARCHAR2) IS\n"
            "  l_idx VARCHAR2(64);\n"
            "BEGIN\n"
            "  l_idx := p_idx;\n"
            "  EXECUTE IMMEDIATE 'DROP INDEX ' || l_idx;\n"
            "END;\n")


def test_dynamic_ddl_shows_variable_taint_source(oracle_rules):
    # DDL in dynamischem SQL: die Herkunft der konkatenierten Variable
    # wird als Taint-Quelle ausgewiesen.
    drop = [f for f in ddl(_DYN_DDL, oracle_rules) if f.rule_ref == "DROP"]
    assert len(drop) == 1
    assert any(r.line == 4 for r in drop[0].related)   # l_idx := p_idx;


def test_dynamic_ddl_taint_can_be_disabled(oracle_rules):
    # Mit show_taint_sources = False (Option --no-taint-sources) wird
    # keine Taint-Quelle ausgewiesen.
    check = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle")
    check.show_taint_sources = False
    drop = [f for f in check.run(Source(_DYN_DDL, "t.sql", "oracle"))
            if f.rule_ref == "DROP"]
    assert len(drop) == 1 and drop[0].related == []


def test_dynamic_ddl_via_variable_shows_concat_operands(oracle_rules):
    # Wird der DROP-String erst zusammengebaut und dann ausgeführt,
    # erscheinen die Herkunfts-Zeilen der Konkatenations-Variablen.
    code = ("CREATE OR REPLACE PROCEDURE p IS\n"
            "  v_sql    VARCHAR2(400);\n"
            "  v_schema VARCHAR2(64);\n"
            "  v_name   VARCHAR2(64);\n"
            "BEGIN\n"
            "  v_schema := get_schema();\n"
            "  v_name := get_name();\n"
            "  v_sql := 'drop view ' || v_schema || '.' || v_name;\n"
            "  EXECUTE IMMEDIATE v_sql;\n"
            "END;\n")
    drop = [f for f in ddl(code, oracle_rules) if f.rule_ref == "DROP"]
    assert len(drop) == 1
    rel_lines = sorted(r.line for r in drop[0].related)
    assert rel_lines == [6, 7]


def test_standalone_ddl_has_no_taint_source(oracle_rules):
    # Eigenständige (nicht dynamische) DDL trägt keine Taint-Quelle.
    f = ddl("TRUNCATE TABLE audit_log;\n", oracle_rules)
    assert len(f) == 1 and f[0].related == []


# -- Mehrzeilige dynamische DDL: vollstaendiger Snippet und Kontext ------
# Ein DDL in einem mehrzeiligen ``format(...)``-/Konkatenations-Ausdruck
# soll im Report nicht nach dem Komma der Fundzeile abbrechen; Snippet und
# Kontext muessen das gesamte Statement umfassen.


def test_multiline_dynamic_ddl_snippet_covers_whole_statement(pg_rules):
    code = (
        "CREATE OR REPLACE FUNCTION rotate_pw(p_user text) "
        "RETURNS void AS $func$\n"
        "DECLARE\n"
        "  sql text;\n"
        "BEGIN\n"
        "  sql := format('alter role %I%s',\n"
        "                p_user,\n"
        "                ' password X');\n"
        "  EXECUTE sql;\n"
        "END;\n"
        "$func$ LANGUAGE plpgsql;\n"
    )
    findings = ddl(code, pg_rules, "postgresql")
    alter = [f for f in findings if f.rule_ref == "ALTER"]
    assert len(alter) == 1
    f = alter[0]
    # Snippet enthaelt den vollstaendigen Statement-Inhalt (normalisiert),
    # nicht nur die Fundzeile mit dem Komma am Ende.
    assert f.snippet.rstrip("') ").endswith("password X") or "password" in f.snippet
    assert f.snippet.endswith(")") or "X')" in f.snippet
    assert "," in f.snippet  # mehrteilige format-Argumente
    # Kontext erstreckt sich bis zur Zeile mit dem Statement-Ende
    # (Zeile 7: ``                ' password X');``).
    ctx_lines = [ln for ln, _, _ in f.context]
    assert 7 in ctx_lines
