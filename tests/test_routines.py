"""Tests fuer die Routine- und Zuweisungserkennung des Lexers.

Routinen (Funktion/Prozedur/Trigger/Package/anonymer Block/DO-Block)
und einfache Zuweisungen ``ziel := ausdruck`` bilden die strukturierte
Datenflussgrundlage von ACI.
"""

from aci.lexer import lex
from aci.source import Source


# -- Routinen: Oracle ----------------------------------------------------

def test_oracle_procedure_routine():
    r = lex("CREATE OR REPLACE PROCEDURE p AS\nBEGIN\n  NULL;\nEND;\n/\n",
            "oracle")
    assert len(r.routines) == 1
    assert r.routines[0].kind == "procedure"
    assert r.routines[0].name == "p"


def test_oracle_function_routine():
    r = lex("CREATE FUNCTION get_x RETURN NUMBER IS\nBEGIN\n  RETURN 1;\n"
            "END;\n/\n", "oracle")
    assert len(r.routines) == 1
    assert r.routines[0].kind == "function"
    assert r.routines[0].name == "get_x"


def test_oracle_package_body_routine():
    r = lex("CREATE OR REPLACE PACKAGE BODY pkg AS\nBEGIN\n  NULL;\n"
            "END;\n/\n", "oracle")
    assert any(x.kind == "package_body" and x.name == "pkg"
               for x in r.routines)


def test_oracle_trigger_routine():
    r = lex("CREATE OR REPLACE TRIGGER trg BEFORE INSERT ON t\n"
            "BEGIN\n  NULL;\nEND;\n/\n", "oracle")
    assert any(x.kind == "trigger" and x.name == "trg" for x in r.routines)


def test_oracle_anonymous_block():
    r = lex("BEGIN\n  NULL;\nEND;\n/\n", "oracle")
    assert any(x.kind == "anonymous_block" and x.name is None
               for x in r.routines)


def test_oracle_schema_qualified_name():
    r = lex("CREATE PROCEDURE hr.cleanup AS\nBEGIN\n  NULL;\nEND;\n/\n",
            "oracle")
    assert r.routines[0].name == "hr.cleanup"


# -- Routinen: PostgreSQL ------------------------------------------------

def test_postgres_function_routine():
    code = ("CREATE OR REPLACE FUNCTION f(p text) RETURNS void AS $$\n"
            "BEGIN\n  NULL;\nEND;\n$$ LANGUAGE plpgsql;\n")
    r = lex(code, "postgresql")
    assert len(r.routines) == 1
    assert r.routines[0].kind == "function" and r.routines[0].name == "f"


def test_postgres_do_block_routine():
    r = lex("DO $$\nBEGIN\n  PERFORM 1;\nEND;\n$$;\n", "postgresql")
    assert any(x.kind == "do_block" for x in r.routines)


def test_postgres_function_body_begin_is_not_a_separate_routine():
    code = ("CREATE FUNCTION f() RETURNS void AS $$\n"
            "BEGIN\n  NULL;\nEND;\n$$ LANGUAGE plpgsql;\n")
    r = lex(code, "postgresql")
    # Nur EINE Routine - der innere BEGIN ist kein eigener anonymer Block.
    assert len(r.routines) == 1


# -- Routinen: Abgrenzung & Negativfaelle --------------------------------

def test_two_routines_are_separated_without_overlap():
    code = ("CREATE FUNCTION a() RETURNS int AS $$ SELECT 1 $$;\n"
            "CREATE FUNCTION b() RETURNS int AS $$ SELECT 2 $$;\n")
    r = lex(code, "postgresql")
    assert [x.name for x in r.routines] == ["a", "b"]
    # PG-Routinen enden am Statement-Terminator (``;``), nicht erst am
    # Beginn der naechsten Routine. Die Bereiche ueberlappen daher nicht und
    # die erste Routine endet direkt hinter ihrem ``;`` (vor dem Zeilenumbruch).
    assert r.routines[0].end <= r.routines[1].start
    assert code[r.routines[0].end - 1] == ";"
    # Code nach dem ersten ``;`` gehoert NICHT mehr zur ersten Routine.
    assert r.routines[0].end < code.index("CREATE FUNCTION b")


def test_statement_after_pg_function_is_outside_routine():
    # F2-Regression: ein Block NACH der Funktion darf nicht zur (SECURITY
    # DEFINER-) Routine gezaehlt werden.
    code = ("CREATE FUNCTION f() RETURNS void AS $$\n"
            "BEGIN NULL; END;\n$$ LANGUAGE plpgsql SECURITY DEFINER;\n"
            "BEGIN EXECUTE 'x'; END;\n")
    r = lex(code, "postgresql")
    fn = [x for x in r.routines if x.name == "f"][0]
    assert fn.end <= code.index("BEGIN EXECUTE")


def test_plain_sql_has_no_routine():
    r = lex("SELECT 1 FROM dual;\n", "oracle")
    assert r.routines == []


def test_create_function_in_comment_is_not_a_routine():
    r = lex("-- CREATE FUNCTION f() RETURNS void\nSELECT 1;\n", "postgresql")
    assert r.routines == []


def test_routine_at_returns_containing_routine():
    code = ("CREATE PROCEDURE p AS\nBEGIN\n"
            "  EXECUTE IMMEDIATE 'select 1';\nEND;\n/\n")
    s = Source(code, "t.sql", "oracle")
    routine = s.routine_at(code.index("EXECUTE"))
    assert routine is not None
    assert routine.kind == "procedure" and routine.name == "p"


# -- Zuweisungen ---------------------------------------------------------

def test_simple_assignment():
    r = lex("BEGIN\n  v_sql := 'select 1';\nEND;\n", "oracle")
    assert len(r.assignments) == 1
    a = r.assignments[0]
    assert a.target == "v_sql"
    assert a.expression == "'select 1'"


def test_concatenation_assignment_expression():
    r = lex("BEGIN\n  v := v || p_in;\nEND;\n", "oracle")
    assert r.assignments[0].expression == "v || p_in"


def test_multiple_assignments_keep_source_order():
    r = lex("BEGIN\n  a := 1;\n  b := 2;\n  a := 3;\nEND;\n", "oracle")
    assert [x.target for x in r.assignments] == ["a", "b", "a"]


def test_assignment_operator_inside_string_is_not_counted():
    r = lex("BEGIN\n  v := 'a := b := c';\nEND;\n", "oracle")
    assert len(r.assignments) == 1
    assert r.assignments[0].target == "v"


def test_qualified_assignment_target():
    r = lex("BEGIN\n  rec.field := 'x';\nEND;\n", "oracle")
    assert r.assignments[0].target == "rec.field"


def test_declaration_default_type_word_is_skipped():
    r = lex("DECLARE\n  pi NUMBER := 3.14;\nBEGIN\n  NULL;\nEND;\n", "oracle")
    assert not any(a.target.upper() == "NUMBER" for a in r.assignments)


def test_postgres_assignment_in_function_body():
    code = ("CREATE FUNCTION f(p text) RETURNS void AS $$\n"
            "DECLARE v_sql text;\n"
            "BEGIN\n  v_sql := 'select * from ' || p;\n"
            "  EXECUTE v_sql;\nEND;\n$$ LANGUAGE plpgsql;\n")
    r = lex(code, "postgresql")
    assert any(a.target == "v_sql" and "||" in a.expression
               for a in r.assignments)


def test_assignment_in_comment_is_not_counted():
    r = lex("BEGIN\n  -- v := 'x';\n  NULL;\nEND;\n", "oracle")
    assert r.assignments == []
