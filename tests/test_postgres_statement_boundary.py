"""Statement-Grenzen-Tests für PostgreSQL-MITRE-Regeln.

Die ``regex_static_and_dynamic``-Detektoren mit ``[\\s\\S]*?``-Mustern
durften früher über das Semikolon hinweg matchen: ein privilegiertes
Schlüsselwort in einem *späteren* Statement konnte einem früheren,
harmlosen Statement zugeordnet werden. In Deployment-Skripten mit vielen
Statements führte das zu False Positives.

Seit ACI 2.10.1 wird der Detektor je ``;``-begrenztem Statement
ausgewertet; ein Treffer kann eine Statement-Grenze nicht mehr
überschreiten. Diese Tests sichern das Verhalten ab.
"""

from aci.source import Source
from aci.checks import build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir


def pg_mitre(code, mitre_base):
    """Scannt PL/pgSQL-Code mit den PostgreSQL-MITRE-Checks."""
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base),
                             "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    out = []
    for check in checks:
        out.extend(check.run(source))
    return out


def lines(findings, check_id):
    """Menge der Zeilennummern, in denen ``check_id`` gemeldet wurde."""
    return {f.line for f in findings if f.check_id == check_id}


# ----------------------------------------------------------------------
# Der ausdrückliche Review-Fall
# ----------------------------------------------------------------------

def test_create_role_login_then_alter_superuser(mitre_base):
    """CREATE ROLE ... LOGIN gefolgt von ALTER ROLE ... SUPERUSER:
    die CREATE-Regel darf NICHT durch das SUPERUSER im nächsten
    Statement ausgelöst werden."""
    code = "CREATE ROLE app_user LOGIN;\nALTER ROLE admin SUPERUSER;\n"
    f = pg_mitre(code, mitre_base)
    # Kein False Positive auf das harmlose CREATE ROLE (Zeile 1).
    assert lines(f, "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED") == set()
    # Das echte ALTER ROLE ... SUPERUSER wird weiterhin erkannt (Zeile 2).
    assert lines(f, "ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED") == {2}


def test_alter_role_login_then_create_superuser(mitre_base):
    code = "ALTER ROLE app_user LOGIN;\nCREATE ROLE evil SUPERUSER;\n"
    f = pg_mitre(code, mitre_base)
    # ALTER ROLE ... LOGIN ist harmlos - keine ALTER-Regel.
    assert lines(f, "ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED") == set()
    # Das echte CREATE ROLE ... SUPERUSER wird erkannt (Zeile 2).
    assert lines(f, "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED") == {2}


# ----------------------------------------------------------------------
# Weitere Cross-Statement-Regeln: Treffer nur im richtigen Statement
# ----------------------------------------------------------------------

def test_grant_system_role_not_attached_to_prior_grant(mitre_base):
    code = ("GRANT SELECT ON orders TO analyst;\n"
            "GRANT pg_monitor TO ops;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE") == {2}


def test_revoke_system_role_not_attached_to_prior_revoke(mitre_base):
    code = ("REVOKE SELECT ON orders FROM analyst;\n"
            "REVOKE pg_monitor FROM ops;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-ADMIN-REVOKE-SYSTEM-ROLE") == {2}


def test_grant_with_option_not_attached_to_prior_grant(mitre_base):
    code = ("GRANT SELECT ON orders TO app;\n"
            "GRANT admin_role TO app WITH ADMIN OPTION;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-GRANT-WITH-OPTION") == {2}


def test_rls_disable_not_attached_to_prior_alter_table(mitre_base):
    code = ("ALTER TABLE orders ADD COLUMN note text;\n"
            "ALTER TABLE orders DISABLE ROW LEVEL SECURITY;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-RLS-DISABLE") == {2}


def test_disable_trigger_not_attached_to_prior_alter_table(mitre_base):
    code = ("ALTER TABLE orders ADD COLUMN note text;\n"
            "ALTER TABLE orders DISABLE TRIGGER audit_trg;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-DISABLE-TRIGGER") == {2}


def test_fdw_create_server_not_attached_to_prior_server(mitre_base):
    code = ("CREATE SERVER s1 FOREIGN DATA WRAPPER my_safe_wrapper;\n"
            "CREATE SERVER s2 FOREIGN DATA WRAPPER postgres_fdw;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-FDW-CREATE-SERVER") == {2}


def test_language_c_not_attached_to_prior_function(mitre_base):
    code = ("CREATE FUNCTION safe() RETURNS int LANGUAGE sql "
            "AS 'SELECT 1';\n"
            "CREATE FUNCTION risky() RETURNS int LANGUAGE C "
            "AS 'obj', 'sym';\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-EXECUTION-LANGUAGE-C") == {2}


def test_publication_all_tables_not_attached_to_prior_publication(mitre_base):
    code = ("CREATE PUBLICATION p1 FOR TABLE orders;\n"
            "CREATE PUBLICATION p2 FOR ALL TABLES;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-PUBLICATION-ALL-TABLES") == {2}


def test_user_mapping_password_not_attached_to_prior_mapping(mitre_base):
    code = ("CREATE USER MAPPING FOR app SERVER s OPTIONS (\"user\" 'u');\n"
            "CREATE USER MAPPING FOR adm SERVER s OPTIONS (password 'p');\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-FDW-USER-MAPPING-PASSWORD") == {2}


# ----------------------------------------------------------------------
# Einzelstatement-Positivfälle bleiben erhalten
# ----------------------------------------------------------------------

def test_single_statement_privileged_create_role_still_fires(mitre_base):
    f = pg_mitre("CREATE ROLE evil SUPERUSER LOGIN;\n", mitre_base)
    assert lines(f, "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED") == {1}


def test_multiline_single_statement_still_matches(mitre_base):
    # Ein über mehrere Zeilen verteiltes *einzelnes* Statement (kein
    # Semikolon dazwischen) wird weiterhin als Treffer erkannt.
    code = ("CREATE ROLE svc\n"
            "  WITH LOGIN\n"
            "       SUPERUSER;\n")
    f = pg_mitre(code, mitre_base)
    assert lines(f, "ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED") == {1}
