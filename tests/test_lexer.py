"""Tests fuer den ACI-Lexer (aci.lexer).

Geprueft werden Tokenisierung (Kommentare, Strings, Dollar-Quotes),
die abgeleiteten maskierten Code-Varianten, die Statement-Grenzen und
die Erkennung dynamischer SQL-Ausfuehrungen.
"""

from aci.lexer import (lex, TOK_LINE_COMMENT,
                       TOK_BLOCK_COMMENT, TOK_STRING)


# -- Tokenstruktur -------------------------------------------------------

def test_tokens_cover_text_contiguously():
    code = "x := 'str'; -- c\n/* b */ y := q'[z]';\n"
    r = lex(code, "oracle")
    assert r.tokens
    assert r.tokens[0].start == 0
    assert r.tokens[-1].end == len(code)
    for a, b in zip(r.tokens, r.tokens[1:]):
        assert a.end == b.start


def test_empty_input():
    r = lex("", "oracle")
    assert r.tokens == []
    assert r.code_masked == ""
    assert r.statements == []
    assert r.dynamic_sql == []


# -- Kommentare ----------------------------------------------------------

def test_line_comment_token():
    r = lex("a := 1; -- Kommentar\nb := 2;\n", "oracle")
    comments = [t for t in r.tokens if t.type == TOK_LINE_COMMENT]
    assert len(comments) == 1
    assert "Kommentar" not in r.code_no_comments
    assert "b := 2;" in r.code_no_comments


def test_block_comment_token():
    r = lex("a := 1;\n/* mehr\n  zeilen */\nb := 2;\n", "oracle")
    blocks = [t for t in r.tokens if t.type == TOK_BLOCK_COMMENT]
    assert len(blocks) == 1
    assert "zeilen" not in r.code_no_comments
    assert r.code_no_comments.count("\n") == r.text.count("\n")


def test_unterminated_block_comment_runs_to_eof():
    r = lex("SELECT 1;\n/* niemals geschlossen", "oracle")
    assert "niemals" not in r.code_no_comments


def test_oracle_block_comment_does_not_nest():
    code = "/* x /* y */ ZZZ */ SELECT 1;\n"
    r = lex(code, "oracle")
    assert "ZZZ" in r.code_no_comments          # nach erstem */ wieder Code
    assert "SELECT 1" in r.code_no_comments


def test_postgres_block_comment_nests():
    code = "/* x /* y */ ZZZ */ SELECT 1;\n"
    r = lex(code, "postgresql")
    assert "ZZZ" not in r.code_no_comments      # gehoert noch zum Kommentar
    assert "SELECT 1" in r.code_no_comments


def test_comment_marker_inside_string_is_not_a_comment():
    r = lex("v := 'wert -- kein kommentar' || tail;\n", "oracle")
    assert "|| tail;" in r.code_no_comments
    assert len([t for t in r.tokens if t.type == TOK_LINE_COMMENT]) == 0


def test_quote_inside_comment_does_not_open_string():
    r = lex("-- it's a comment\nx := 1;\n", "oracle")
    assert r.string_spans == []


# -- String-Literale -----------------------------------------------------

def test_standard_string_token():
    r = lex("v := 'hello world';\n", "oracle")
    strings = [t for t in r.tokens if t.type == TOK_STRING]
    assert len(strings) == 1
    assert r.string_spans[0].content_start >= 0
    assert "hello world" not in r.code_masked
    assert "hello world" in r.code_no_comments


def test_escaped_quotes_in_string():
    r = lex("v := 'it''s fine';\n", "oracle")
    assert len(r.string_spans) == 1
    sp = r.string_spans[0]
    assert r.text[sp.content_start:sp.content_end] == "it''s fine"


def test_oracle_q_quote_bracket_delimiter():
    r = lex("v := q'[a ' b]' || x;\n", "oracle")
    assert len(r.string_spans) == 1
    sp = r.string_spans[0]
    assert r.text[sp.content_start:sp.content_end] == "a ' b"
    assert "|| x;" in r.code_masked


def test_oracle_nq_quote_literal():
    r = lex("v := nq'#wert#';\n", "oracle")
    assert len(r.string_spans) == 1
    sp = r.string_spans[0]
    assert r.text[sp.content_start:sp.content_end] == "wert"
    assert "wert" not in r.code_masked


def test_unterminated_string_runs_to_eof():
    r = lex("v := 'kein ende\n", "oracle")
    assert len(r.string_spans) == 1
    assert "kein ende" not in r.code_masked


# -- PostgreSQL-Dollar-Quotes -------------------------------------------

def test_dollar_quote_code_body_is_not_a_string():
    code = ("CREATE FUNCTION f() RETURNS int AS $$\n"
            "BEGIN\n  RETURN 1;\nEND;\n$$ LANGUAGE plpgsql;\n")
    r = lex(code, "postgresql")
    assert r.string_spans == []                 # Rumpf ist Code, kein String
    assert "RETURN 1;" in r.code_masked


def test_dollar_quote_string_is_a_string():
    r = lex("RAISE NOTICE $$geheimer text$$;\n", "postgresql")
    assert len(r.string_spans) == 1
    sp = r.string_spans[0]
    assert r.text[sp.content_start:sp.content_end] == "geheimer text"
    assert "geheimer text" not in r.code_masked


def test_dollar_quote_distinct_nested_tags():
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "BEGIN\n  RAISE NOTICE $msg$inner$msg$;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    r = lex(code, "postgresql")
    assert "RAISE NOTICE" in r.code_masked
    assert "inner" not in r.code_masked


# -- Maskierungs-Invarianten --------------------------------------------

def test_masking_preserves_length():
    code = "x := 'abc'; -- k\n/* b */ y := 1;\n"
    r = lex(code, "oracle")
    assert len(r.code_no_comments) == len(code)
    assert len(r.code_masked) == len(code)


# -- Statement-Grenzen ---------------------------------------------------

def test_statements_split_on_semicolon():
    r = lex("a := 1; b := 2; c := 3;\n", "oracle")
    assert len(r.statements) == 3


def test_semicolon_inside_string_is_no_boundary():
    r = lex("v := 'a;b;c';\n", "oracle")
    assert len(r.statements) == 1


def test_semicolon_inside_comment_is_no_boundary():
    r = lex("a := 1 /* ; ; ; */ + 2;\n", "oracle")
    assert len(r.statements) == 1


def test_slash_line_terminates_statement():
    r = lex("BEGIN NULL; END;\n/\n", "oracle")
    assert len(r.statements) >= 1
    assert "BEGIN" in r.text[r.statements[0].start:r.statements[0].end]


def test_division_operator_is_no_statement_boundary():
    r = lex("x := a / b / c;\n", "oracle")
    assert len(r.statements) == 1


# -- Dynamische SQL-Ausfuehrungen ---------------------------------------

def test_execute_immediate_is_detected():
    r = lex("BEGIN EXECUTE IMMEDIATE 'select 1'; END;\n", "oracle")
    kinds = [d.kind for d in r.dynamic_sql]
    assert "execute_immediate" in kinds


def test_open_for_is_detected():
    r = lex("BEGIN OPEN c FOR 'select 1'; END;\n", "oracle")
    assert any(d.kind == "open_for" for d in r.dynamic_sql)


def test_dbms_sql_parse_is_detected():
    r = lex("BEGIN DBMS_SQL.PARSE(c, 'select 1', 1); END;\n", "oracle")
    assert any(d.kind == "dbms_sql_parse" for d in r.dynamic_sql)


def test_dbms_sys_sql_parse_as_user_is_detected():
    r = lex("BEGIN DBMS_SYS_SQL.PARSE_AS_USER(c, s, 1, 5); END;\n", "oracle")
    assert any(d.kind == "dbms_sys_sql_parse" for d in r.dynamic_sql)


def test_pg_execute_is_detected():
    r = lex("BEGIN EXECUTE 'select 1'; END;\n", "postgresql")
    assert any(d.kind == "pg_execute" for d in r.dynamic_sql)


def test_grant_execute_is_not_a_dynamic_sql():
    r = lex("GRANT EXECUTE ON FUNCTION f() TO PUBLIC;\n", "postgresql")
    assert r.dynamic_sql == []


def test_execute_immediate_in_comment_is_not_detected():
    r = lex("-- EXECUTE IMMEDIATE 'drop user x';\nSELECT 1;\n", "oracle")
    assert r.dynamic_sql == []


def test_execute_immediate_in_string_is_not_detected():
    r = lex("v := 'EXECUTE IMMEDIATE here';\n", "oracle")
    assert r.dynamic_sql == []


def test_dynamic_sql_expression_bounds_are_sane():
    code = "BEGIN EXECUTE IMMEDIATE 'select ' || x; END;\n"
    r = lex(code, "oracle")
    d = r.dynamic_sql[0]
    assert d.trigger_start < d.expr_start <= d.expr_end
    assert code[d.trigger_start:d.trigger_end].upper() == "EXECUTE IMMEDIATE"
