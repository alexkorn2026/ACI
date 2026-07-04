"""PostgreSQL CI/CD policy rules introduced after ACI 2.5.0."""

from aci.source import Source
from aci.checks import build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir
from aci.finding import Severity


def pg_mitre(code, mitre_base):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base), "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def has(findings, check_id, severity=None):
    hits = [f for f in findings if f.check_id == check_id]
    if severity is not None:
        hits = [f for f in hits if f.severity == severity]
    return bool(hits)


def test_pg_create_role_privileged_is_critical(mitre_base):
    f = pg_mitre("CREATE ROLE app_admin SUPERUSER LOGIN;\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED", Severity.CRITICAL)


def test_pg_alter_role_privileged_is_critical(mitre_base):
    f = pg_mitre("ALTER ROLE app_user BYPASSRLS;\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED", Severity.CRITICAL)


def test_pg_alter_role_negative_privileged_change_is_critical(mitre_base):
    f = pg_mitre("ALTER ROLE app_user NOBYPASSRLS;\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED", Severity.CRITICAL)


def test_pg_grant_system_role_is_critical(mitre_base):
    f = pg_mitre("GRANT pg_execute_server_program TO app_user;\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE", Severity.CRITICAL)


def test_pg_grant_system_roles_multiline_is_critical(mitre_base):
    f = pg_mitre(
        "GRANT pg_execute_server_program,\n"
        "      pg_read_server_files,\n"
        "      pg_write_server_files\n"
        "TO app_user;\n",
        mitre_base,
    )
    assert has(f, "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE", Severity.CRITICAL)


def test_pg_revoke_system_role_is_critical(mitre_base):
    f = pg_mitre("REVOKE pg_read_server_files FROM app_user;\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-REVOKE-SYSTEM-ROLE", Severity.CRITICAL)


def test_pg_create_user_mapping_with_password_is_critical(mitre_base):
    code = (
        "CREATE USER MAPPING FOR app_user\n"
        "SERVER remote_pg\n"
        "OPTIONS (user 'remote_user', password 'secret');\n"
    )
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-FDW-USER-MAPPING-PASSWORD", Severity.CRITICAL)


def test_pg_create_server_fdw_is_high(mitre_base):
    code = (
        "CREATE SERVER remote_pg\n"
        "FOREIGN DATA WRAPPER postgres_fdw\n"
        "OPTIONS (host 'remote', dbname 'prod');\n"
    )
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-FDW-CREATE-SERVER", Severity.HIGH)


def test_pg_create_subscription_with_password_is_critical(mitre_base):
    code = (
        "CREATE SUBSCRIPTION sub1\n"
        "CONNECTION 'host=remote dbname=prod user=repl password=secret'\n"
        "PUBLICATION pub1;\n"
    )
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-REPLICATION-SUBSCRIPTION-CREDENTIALS", Severity.CRITICAL)


def test_pg_create_subscription_uri_with_password_is_critical(mitre_base):
    code = (
        "CREATE SUBSCRIPTION sub1\n"
        "CONNECTION 'postgresql://repl:secret@remote/prod'\n"
        "PUBLICATION pub1;\n"
    )
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-REPLICATION-SUBSCRIPTION-CREDENTIALS", Severity.CRITICAL)


def test_pg_create_event_trigger_is_high(mitre_base):
    code = "CREATE EVENT TRIGGER ddl_backdoor ON ddl_command_end EXECUTE FUNCTION backdoor_func();\n"
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-PERSISTENCE-EVENT-TRIGGER", Severity.HIGH)


def test_pg_create_function_language_c_is_critical(mitre_base):
    code = (
        "CREATE FUNCTION evil()\n"
        "RETURNS void\n"
        "AS '/tmp/evil.so', 'entrypoint'\n"
        "LANGUAGE C;\n"
    )
    f = pg_mitre(code, mitre_base)
    assert has(f, "ACI-PG-EXECUTION-LANGUAGE-C", Severity.CRITICAL)


def test_pg_copy_to_server_file_is_high(mitre_base):
    f = pg_mitre("COPY sensitive_table TO '/tmp/dump.csv';\n", mitre_base)
    assert has(f, "ACI-PG-COPY-SERVER-FILE-TO", Severity.HIGH)


def test_pg_copy_from_server_file_is_high(mitre_base):
    f = pg_mitre("COPY sensitive_table FROM '/tmp/input.csv';\n", mitre_base)
    assert has(f, "ACI-PG-COPY-SERVER-FILE-FROM", Severity.HIGH)


def test_pg_copy_stdin_stdout_are_not_server_file_findings(mitre_base):
    f = pg_mitre("COPY t TO STDOUT;\nCOPY t FROM STDIN;\n", mitre_base)
    assert not has(f, "ACI-PG-COPY-SERVER-FILE-TO")
    assert not has(f, "ACI-PG-COPY-SERVER-FILE-FROM")


def test_pg_policy_rules_ignore_comments_and_string_literals(mitre_base):
    code = (
        "-- GRANT pg_execute_server_program TO app_user;\n"
        "/* CREATE USER MAPPING FOR app_user SERVER r OPTIONS (password 'secret'); */\n"
        "SELECT 'CREATE FUNCTION evil() RETURNS void LANGUAGE C';\n"
        "SELECT 'COPY sensitive_table TO ''/tmp/dump.csv''';\n"
    )
    f = pg_mitre(code, mitre_base)
    forbidden = {
        "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE",
        "ACI-PG-FDW-USER-MAPPING-PASSWORD",
        "ACI-PG-EXECUTION-LANGUAGE-C",
        "ACI-PG-COPY-SERVER-FILE-TO",
    }
    assert not any(x.check_id in forbidden for x in f)


def test_pg_policy_rule_detects_dynamic_sql(mitre_base):
    f = pg_mitre("EXECUTE 'GRANT pg_read_server_files TO app_user';\n", mitre_base)
    assert has(f, "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE", Severity.CRITICAL)
