"""Tests fuer die EPAS/PostgreSQL Audit-Tampering / Audit-Bypass-Regeln
(ACI 2.18.0):

* ALTER SYSTEM auf edb_audit*/Logging-Parameter (disable/weaken)
* SET / set_config-Logging-Abschwaechung
* pg_reload_conf() (plain vs. nach audit-sensitiver Aenderung)
* Manipulation von postgresql.auto.conf / pg_hba.conf aus Skripten
* SECURITY DEFINER mit privilegierter DDL + Audit-Bypass-Aufrufmuster
"""

from aci.source import Source
from aci.checks import build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir
from aci.finding import Severity


def _pg(code, mitre_base):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base),
                             "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def _ids(findings):
    return {f.check_id for f in findings}


def _sev(findings, rule_id):
    hits = [f for f in findings if f.check_id == rule_id]
    return hits[0].severity if hits else None


# -- edb_audit ALTER SYSTEM ---------------------------------------------

def test_edb_audit_statement_none_is_critical(mitre_base):
    assert _sev(_pg("ALTER SYSTEM SET edb_audit_statement = 'none';\n",
                    mitre_base),
                "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM") is Severity.CRITICAL


def test_edb_audit_none_is_critical(mitre_base):
    assert _sev(_pg("ALTER SYSTEM SET edb_audit = 'none';\n", mitre_base),
                "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM") is Severity.CRITICAL


def test_edb_audit_to_none_unquoted_is_critical(mitre_base):
    assert "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM" in _ids(
        _pg("ALTER SYSTEM SET edb_audit_statement TO none;\n", mitre_base))


def test_edb_audit_statement_all_is_not_disable(mitre_base):
    ids = _ids(_pg("ALTER SYSTEM SET edb_audit_statement = 'all';\n",
                   mitre_base))
    assert "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM" not in ids
    assert "ACI-EPAS-AUDIT-WEAKEN-ALTER-SYSTEM" not in ids


def test_edb_audit_csv_is_not_disable(mitre_base):
    assert "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM" not in _ids(
        _pg("ALTER SYSTEM SET edb_audit = 'csv';\n", mitre_base))


def test_edb_audit_statement_ddl_is_weaken_not_disable(mitre_base):
    ids = _ids(_pg("ALTER SYSTEM SET edb_audit_statement = 'ddl';\n",
                   mitre_base))
    assert "ACI-EPAS-AUDIT-WEAKEN-ALTER-SYSTEM" in ids
    assert "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM" not in ids


def test_edb_audit_disable_in_comment_is_not_flagged(mitre_base):
    code = ("-- ALTER SYSTEM SET edb_audit_statement = 'none';\n"
            "SELECT 1;\n")
    assert "ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM" not in _ids(
        _pg(code, mitre_base))


# -- Logging-Parameter ---------------------------------------------------

def test_log_statement_none_is_critical(mitre_base):
    assert _sev(_pg("ALTER SYSTEM SET log_statement = 'none';\n", mitre_base),
                "ACI-PG-AUDIT-LOGGING-DISABLE-ALTER-SYSTEM") is Severity.CRITICAL


def test_logging_collector_off_is_critical(mitre_base):
    assert "ACI-PG-AUDIT-LOGGING-DISABLE-ALTER-SYSTEM" in _ids(
        _pg("ALTER SYSTEM SET logging_collector = off;\n", mitre_base))


def test_log_statement_all_is_not_disable(mitre_base):
    assert "ACI-PG-AUDIT-LOGGING-DISABLE-ALTER-SYSTEM" not in _ids(
        _pg("ALTER SYSTEM SET log_statement = 'all';\n", mitre_base))


def test_set_log_statement_none_is_weaken(mitre_base):
    assert "ACI-PG-AUDIT-LOGGING-WEAKEN-SET" in _ids(
        _pg("SET log_statement = 'none';\n", mitre_base))


def test_set_config_log_statement_none_is_weaken(mitre_base):
    assert "ACI-PG-AUDIT-LOGGING-WEAKEN-SET" in _ids(
        _pg("SELECT set_config('log_statement','none',false);\n", mitre_base))


# -- pg_reload_conf Kontext ---------------------------------------------

def test_reload_alone_is_plain_high(mitre_base):
    f = _pg("SELECT pg_reload_conf();\n", mitre_base)
    assert _sev(f, "ACI-EPAS-AUDIT-CONFIG-RELOAD") is Severity.HIGH
    assert "ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE" not in _ids(f)


def test_reload_after_audit_change_is_critical(mitre_base):
    code = ("ALTER SYSTEM SET edb_audit_statement = 'none';\n"
            "SELECT pg_reload_conf();\n")
    f = _pg(code, mitre_base)
    assert _sev(f, "ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE") is Severity.CRITICAL
    # Plain- und Kontext-Regel schliessen sich gegenseitig aus.
    assert "ACI-EPAS-AUDIT-CONFIG-RELOAD" not in _ids(f)


def test_reload_in_comment_is_not_flagged(mitre_base):
    code = "-- SELECT pg_reload_conf();\nSELECT 1;\n"
    ids = _ids(_pg(code, mitre_base))
    assert "ACI-EPAS-AUDIT-CONFIG-RELOAD" not in ids
    assert "ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE" not in ids


# -- Konfig-Datei-Manipulation ------------------------------------------

def test_sed_inplace_autoconf_is_critical(mitre_base):
    code = "\\! sed -i \"s/all/none/\" postgresql.auto.conf\n"
    assert _sev(_pg(code, mitre_base),
                "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING") is Severity.CRITICAL


def test_vi_autoconf_is_critical(mitre_base):
    assert "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING" in _ids(
        _pg("\\! vi postgresql.auto.conf\n", mitre_base))


def test_echo_append_autoconf_is_critical(mitre_base):
    code = "\\! echo \"edb_audit_statement = 'none'\" >> postgresql.auto.conf\n"
    assert "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING" in _ids(_pg(code, mitre_base))


def test_cat_autoconf_readonly_is_not_flagged(mitre_base):
    assert "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING" not in _ids(
        _pg("\\! cat postgresql.auto.conf\n", mitre_base))


def test_autoconf_in_comment_is_not_flagged(mitre_base):
    code = "-- sed -i s/a/b/ postgresql.auto.conf\nSELECT 1;\n"
    assert "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING" not in _ids(
        _pg(code, mitre_base))


def test_pg_hba_vi_is_generic_config_tampering(mitre_base):
    f = _pg("\\! vi pg_hba.conf\n", mitre_base)
    assert "ACI-PG-CONFIG-FILE-TAMPERING" in _ids(f)
    # auto.conf-Regel feuert hier NICHT (disjunkte Dateimengen).
    assert "ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING" not in _ids(f)


# -- SECURITY DEFINER + privilegierte DDL -------------------------------

_SECDEF_CREATE_USER = (
    "CREATE OR REPLACE FUNCTION fn_acc(dummy int) RETURNS int\n"
    "LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
    "BEGIN\n"
    "  CREATE USER superman_2025 WITH PASSWORD 'X34290upa' SUPERUSER;\n"
    "  RETURN dummy;\n"
    "END;\n$$;\n")


def test_secdef_create_user_is_critical(mitre_base):
    assert _sev(_pg(_SECDEF_CREATE_USER, mitre_base),
                "ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION") is Severity.CRITICAL


def test_secdef_dynamic_alter_role_is_critical(mitre_base):
    code = ("CREATE FUNCTION f() RETURNS void SECURITY DEFINER AS $$\n"
            "BEGIN\n"
            "  EXECUTE 'ALTER ROLE ' || p_user || ' SUPERUSER';\n"
            "END;\n$$ LANGUAGE plpgsql;\n")
    assert "ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION" in _ids(
        _pg(code, mitre_base))


def test_security_invoker_with_create_user_is_not_secdef_rule(mitre_base):
    code = ("CREATE FUNCTION f() RETURNS void SECURITY INVOKER AS $$\n"
            "BEGIN\n  CREATE USER hacker;\nEND;\n$$ LANGUAGE plpgsql;\n")
    assert "ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION" not in _ids(
        _pg(code, mitre_base))


def test_secdef_without_privileged_op_is_not_flagged(mitre_base):
    code = ("CREATE FUNCTION f() RETURNS int SECURITY DEFINER\n"
            "SET search_path = app, pg_temp AS $$\n"
            "BEGIN\n  RETURN 1;\nEND;\n$$ LANGUAGE plpgsql;\n")
    assert "ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION" not in _ids(
        _pg(code, mitre_base))


# -- Audit-Bypass-Kandidat (Kontext) ------------------------------------

def test_secdef_then_call_is_bypass_candidate(mitre_base):
    code = _SECDEF_CREATE_USER + "SELECT fn_acc(6);\n"
    assert _sev(_pg(code, mitre_base),
                "ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE") is Severity.HIGH


def test_secdef_without_call_is_not_bypass_candidate(mitre_base):
    assert "ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE" not in _ids(
        _pg(_SECDEF_CREATE_USER, mitre_base))


def test_call_to_other_function_is_not_bypass_candidate(mitre_base):
    code = _SECDEF_CREATE_USER + "SELECT some_other_fn(6);\n"
    assert "ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE" not in _ids(
        _pg(code, mitre_base))


def test_schema_qualified_secdef_call_is_bypass_candidate(mitre_base):
    code = ("CREATE FUNCTION admin.fn_acc() RETURNS void\n"
            "LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
            "BEGIN\n  CREATE USER hacker SUPERUSER;\nEND;\n$$;\n"
            "SELECT admin.fn_acc();\n")
    assert "ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE" in _ids(
        _pg(code, mitre_base))


# -- EPAS-Superuser-Account (bestehende Regel deckt ab) -----------------

def test_create_superuser_is_covered_by_existing_privileged_role_rule(mitre_base):
    # Keine neue Regel; ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED deckt EPAS-
    # Superuser-Erstellung ab.
    f = _pg("CREATE USER name WITH PASSWORD 'x' SUPERUSER;\n", mitre_base)
    assert "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED" in _ids(f)


def test_alter_role_superuser_is_covered_by_existing_rule(mitre_base):
    f = _pg("ALTER ROLE name WITH SUPERUSER;\n", mitre_base)
    assert "ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED" in _ids(f)


# -- F6: pg_reload_conf Deduplizierung (CLI-Ebene) ----------------------

def _scan_ids_by_line(tmp_path, code):
    import json
    from aci.cli import main
    src = tmp_path / "r.sql"
    src.write_text(code, encoding="utf-8")
    out = tmp_path / "out"
    main([str(src), "-d", "postgresql", "-g", "all", "-f", "json",
          "-o", str(out)])
    data = json.loads((out / "aci_report_r.json").read_text(encoding="utf-8"))
    pairs = []
    for fb in data["files"]:
        for f in fb["findings"]:
            pairs.append((f["line"], f["check_id"]))
    return pairs


def test_reload_alone_has_no_generic_pkg_duplicate(tmp_path):
    pairs = _scan_ids_by_line(tmp_path, "SELECT pg_reload_conf();\n")
    line1 = {cid for ln, cid in pairs if ln == 1}
    assert "ACI-EPAS-AUDIT-CONFIG-RELOAD" in line1
    # Generische pg_reload_conf-Warnung (ACI-PKG) auf derselben Zeile entfernt.
    assert "ACI-PKG" not in line1


def test_reload_after_audit_change_has_no_pkg_duplicate(tmp_path):
    code = ("ALTER SYSTEM SET edb_audit_statement = 'none';\n"
            "SELECT pg_reload_conf();\n")
    pairs = _scan_ids_by_line(tmp_path, code)
    line2 = {cid for ln, cid in pairs if ln == 2}
    assert "ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE" in line2
    assert "ACI-PKG" not in line2


def test_other_pkg_finding_is_not_removed(tmp_path):
    # FP-Schutz: andere generische ACI-PKG-Funktionsmeldungen bleiben.
    pairs = _scan_ids_by_line(tmp_path, "SELECT pg_terminate_backend(1);\n")
    assert any(cid == "ACI-PKG" for _ln, cid in pairs)
