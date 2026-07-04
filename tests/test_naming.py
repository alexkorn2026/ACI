"""Tests fuer NamingCheck - reservierte Worte als Bezeichner.

Schwerpunkt: ``CREATE INDEX ON tab (...)`` ist ein unbenannter Index.
``ON`` (und ein eventuell zurueckgesetztes ``CONCURRENTLY``) sind dort
Syntax-Schluesselworte und duerfen kein Reserved-Word-Finding ausloesen.
"""

from aci.source import Source
from aci.checks import NamingCheck


def naming(code, rules, dialect="postgresql"):
    s = Source(code, "t.sql", dialect)
    return NamingCheck(rules.check("naming_conventions"), dialect).run(s)


def test_unnamed_index_on_keyword_is_not_flagged(pg_rules):
    # CREATE INDEX ON tab (...) - 'ON' ist hier kein Objektname.
    code = "CREATE INDEX ON rbac_permissions (lft);\n"
    assert naming(code, pg_rules) == []


def test_unnamed_concurrent_index_is_not_flagged(pg_rules):
    # CREATE INDEX CONCURRENTLY ON tab (...) - weder 'CONCURRENTLY'
    # noch 'ON' duerfen als Name gewertet werden.
    code = "CREATE INDEX CONCURRENTLY ON rbac_permissions (rgt);\n"
    assert naming(code, pg_rules) == []


def test_named_index_produces_no_reserved_word_finding(pg_rules):
    code = "CREATE INDEX idx_lft ON rbac_permissions (lft);\n"
    assert naming(code, pg_rules) == []


def test_named_concurrent_index_produces_no_reserved_word_finding(pg_rules):
    code = "CREATE INDEX CONCURRENTLY idx_rgt ON rbac_permissions (rgt);\n"
    assert naming(code, pg_rules) == []


def test_quoted_reserved_index_name_is_still_flagged(pg_rules):
    # Ein bewusst gequoteter reservierter Bezeichner bleibt ein Finding.
    code = 'CREATE INDEX "on" ON rbac_permissions (lft);\n'
    f = naming(code, pg_rules)
    assert any("'ON'" in x.message for x in f)


# ----------------------------------------------------------------------
# GRANT / REVOKE: System-Privilegien sind keine Objektdefinitionen
# ----------------------------------------------------------------------
# ``GRANT CREATE <obj> TO user`` und ``REVOKE CREATE <obj> FROM user``
# nennen einen Privilegnamen, kein neues Objekt; ``TO``/``FROM`` sind hier
# Syntax-Schluesselworte und duerfen kein Reserved-Word-Finding erzeugen.


def test_grant_system_privilege_to_user_is_not_flagged(oracle_rules):
    code = (
        "GRANT CREATE TABLE TO test_user;\n"
        "GRANT CREATE TRIGGER TO test_user;\n"
        "GRANT CREATE TYPE TO test_user;\n"
        "GRANT CREATE VIEW TO test_user;\n"
        "GRANT CREATE PROCEDURE TO test_user;\n"
        "GRANT CREATE FUNCTION TO test_user;\n"
        "GRANT CREATE SEQUENCE TO test_user;\n"
    )
    assert naming(code, oracle_rules, dialect="oracle") == []


def test_grant_create_table_to_public_is_not_flagged(oracle_rules):
    code = "GRANT CREATE TABLE TO PUBLIC;\n"
    assert naming(code, oracle_rules, dialect="oracle") == []


def test_revoke_system_privilege_from_user_is_not_flagged(oracle_rules):
    code = (
        "REVOKE CREATE TABLE FROM test_user;\n"
        "REVOKE CREATE VIEW FROM test_user;\n"
    )
    assert naming(code, oracle_rules, dialect="oracle") == []


def test_create_table_with_to_prefix_name_is_not_falsely_excluded(oracle_rules):
    # ``TO_DO``/``FROM_TO_LIST`` sind keine reservierten Worte; sie duerfen
    # weder als reserviertes Wort gemeldet werden, noch durch den
    # ``TO``/``FROM``-Ausschluss des GRANT/REVOKE-Fixes verschluckt werden.
    code = (
        "CREATE TABLE TO_DO (id NUMBER);\n"
        "CREATE TABLE FROM_TO_LIST (id NUMBER);\n"
    )
    assert naming(code, oracle_rules, dialect="oracle") == []


# -- Bezeichnerlänge: Oracle-Limit 128 (12.2+), nicht mehr 30 ------------

def _length_hits(findings):
    return [f for f in findings if f.rule_ref == "LENGTH"]


def test_oracle_identifier_up_to_128_is_not_flagged(oracle_rules):
    # 35-Zeichen-Name war unter dem alten 30er-Limit ein Falsch-Positiv;
    # modernes Oracle (12.2+) erlaubt bis 128 Zeichen.
    name = "l_" + "a" * 33   # 35 Zeichen
    code = f"DECLARE\n  {name} NUMBER;\nBEGIN\n  NULL;\nEND;\n"
    assert _length_hits(naming(code, oracle_rules, dialect="oracle")) == []


def test_oracle_identifier_over_128_is_flagged(oracle_rules):
    name = "l_" + "a" * 130   # 132 Zeichen > 128
    code = f"DECLARE\n  {name} NUMBER;\nBEGIN\n  NULL;\nEND;\n"
    hits = _length_hits(naming(code, oracle_rules, dialect="oracle"))
    assert len(hits) == 1
    assert "128" in hits[0].message


def test_oracle_max_identifier_length_is_128(oracle_rules):
    assert oracle_rules.check("naming_conventions")["max_identifier_length"] == 128
