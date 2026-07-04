"""Tests fuer die Vorverarbeitung in aci/source.py.

Geprueft werden Kommentar-Entfernung, String-Maskierung, das
PostgreSQL-Dollar-Quoting, Laengen-/Offset-Invarianten sowie die
Tatsache, dass Kommentare und Strings keine falschen Findings erzeugen.
"""

from aci.source import Source
from aci.checks import DdlCheck, SqlInjectionCheck
from aci.finding import Severity


def src(code, dialect="oracle"):
    return Source(code, "test.sql", dialect)


# -- Laengen-/Offset-Invarianten -----------------------------------------

def test_masking_preserves_length():
    code = "x := 'abc'; -- Kommentar\n/* Block */ y := 1;\n"
    s = src(code)
    assert len(s.code_no_comments) == len(s.text)
    assert len(s.code_masked) == len(s.text)


def test_masking_preserves_newlines():
    code = "a := 1;\n/* mehrzeilig\n   weiter */\nb := 2;\n"
    s = src(code)
    assert s.code_masked.count("\n") == code.count("\n")
    assert s.code_no_comments.count("\n") == code.count("\n")


def test_offsets_stable_across_variants():
    code = "/* xx */ FOO := 1; -- tail\nBAR := 2;\n"
    s = src(code)
    idx = s.text.index("FOO")
    assert s.code_no_comments[idx:idx + 3] == "FOO"
    assert s.code_masked[idx:idx + 3] == "FOO"
    line, col = s.line_col(idx)
    assert (line, col) == (1, idx + 1)


def test_line_col_basic():
    s = src("erste\nzweite\ndritte\n")
    assert s.line_col(0) == (1, 1)
    assert s.line_col(6) == (2, 1)
    line, col = s.line_col(10 ** 6)          # Offset hinter dem Text
    assert line >= 1 and col >= 1


def test_context_lines_marks_finding_line():
    code = "\n".join(f"L{i}" for i in range(1, 11)) + "\n"
    s = src(code)
    ctx = s.context_lines(s.text.index("L5"), before=2, after=2)
    assert [ln for ln, _t, _f in ctx] == [3, 4, 5, 6, 7]
    assert [ln for ln, _t, is_f in ctx if is_f] == [5]


# -- Oracle-Kommentare ---------------------------------------------------

def test_oracle_single_line_comment_blanked():
    s = src("v_x := 1;  -- geheime notiz\nv_y := 2;\n")
    assert "geheime" not in s.code_no_comments
    assert "geheime" not in s.code_masked
    assert "v_x := 1;" in s.code_no_comments
    assert "v_y := 2;" in s.code_no_comments


def test_oracle_multiline_comment_blanked():
    code = "a := 1;\n/* DROP USER evil;\n   noch text */\nb := 2;\n"
    s = src(code)
    assert "DROP USER" not in s.code_no_comments
    assert "DROP USER" not in s.code_masked
    assert "a := 1;" in s.code_no_comments
    assert "b := 2;" in s.code_no_comments


def test_quote_inside_comment_does_not_open_string():
    s = src("-- it's only a comment\nx := 1;\n")
    assert s.string_spans == []
    assert "x := 1;" in s.code_no_comments


# -- String-Literale -----------------------------------------------------

def test_string_kept_in_no_comments_masked_in_masked():
    s = src("v := 'PAYLOAD';\n")
    assert "PAYLOAD" in s.code_no_comments
    assert "PAYLOAD" not in s.code_masked


def test_escaped_quotes_masking():
    s = src("msg := 'it''s a trap';\n")
    assert "it''s a trap" in s.code_no_comments
    assert "trap" not in s.code_masked
    # nur die aeusseren Anfuehrungszeichen bleiben stehen
    assert s.code_masked.count("'") == 2


def test_string_span_content():
    s = src("msg := 'it''s a trap';\n")
    assert len(s.string_spans) == 1
    assert s.string_content(s.string_spans[0]) == "it''s a trap"


def test_comment_marker_inside_string_is_literal():
    s = src("v := 'value -- not a comment' || tail;\n")
    assert len(s.string_spans) == 1
    assert "|| tail;" in s.code_masked          # Code nach dem String erhalten
    assert "not a comment" not in s.code_masked


def test_oracle_q_quote_literal():
    s = src("v := q'[it's fine]' || x;\n")
    assert len(s.string_spans) == 1
    assert s.string_content(s.string_spans[0]) == "it's fine"
    assert "it's fine" not in s.code_masked
    assert "|| x;" in s.code_masked


# -- PostgreSQL-Dollar-Quoting -------------------------------------------

def test_postgres_dollar_quote_function_body_is_code():
    code = ("CREATE FUNCTION f() RETURNS int AS $$\n"
            "BEGIN\n  RETURN 42;\nEND;\n$$ LANGUAGE plpgsql;\n")
    s = src(code, "postgresql")
    # Funktionsrumpf bleibt als Code stehen, wird nicht maskiert
    assert "RETURN 42;" in s.code_masked
    assert "BEGIN" in s.code_masked
    assert "$$" in s.code_masked


def test_postgres_dollar_quote_string_is_masked():
    # $$ nach RAISE NOTICE ist ein String-Literal, kein Code-Rumpf
    s = src("RAISE NOTICE $$secret payload text$$;\n", "postgresql")
    assert "secret payload text" not in s.code_masked
    assert len(s.string_spans) == 1
    assert s.string_content(s.string_spans[0]) == "secret payload text"


def test_postgres_dollar_quote_distinct_tags():
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "BEGIN\n  RAISE NOTICE $msg$inner text$msg$;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    s = src(code, "postgresql")
    assert "RAISE NOTICE" in s.code_masked          # Rumpf = Code
    assert "inner text" not in s.code_masked        # innerer $msg$ = String
    assert "inner text" in [s.string_content(sp) for sp in s.string_spans]


# -- Kommentare/Strings erzeugen keine falschen Findings -----------------

def test_ddl_in_single_line_comment_no_finding(oracle_rules):
    code = "-- EXECUTE IMMEDIATE 'DROP USER X';\nSELECT 1 FROM dual;\n"
    s = src(code)
    assert DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s) == []
    assert SqlInjectionCheck(
        oracle_rules.check("sql_injection"), "oracle").run(s) == []


def test_ddl_in_multiline_comment_no_finding(oracle_rules):
    code = ("/*\nEXECUTE IMMEDIATE 'DROP USER X';\nDROP USER evil;\n*/\n"
            "SELECT 1 FROM dual;\n")
    s = src(code)
    assert DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s) == []


def test_oracle_string_literal_no_ddl_finding(oracle_rules):
    # 'DROP USER X' nur als Text in einem String-Argument
    code = "BEGIN\n  DBMS_OUTPUT.PUT_LINE('DROP USER X');\nEND;\n/\n"
    s = src(code)
    assert DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s) == []


def test_postgres_select_string_no_ddl_finding(pg_rules):
    s = src("SELECT 'DROP USER X';\n", "postgresql")
    assert DdlCheck(
        pg_rules.check("ddl_in_code"), "postgresql").run(s) == []


def test_postgres_dollar_quote_string_no_ddl_finding(pg_rules):
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "BEGIN\n  RAISE NOTICE $msg$DROP USER X$msg$;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    s = src(code, "postgresql")
    assert DdlCheck(
        pg_rules.check("ddl_in_code"), "postgresql").run(s) == []


def test_postgres_dollar_quote_body_detects_concat(pg_rules):
    # Der Funktionsrumpf wird analysiert -> unsichere Konkatenation faellt auf.
    code = ("CREATE FUNCTION f(p_table text) RETURNS void AS $func$\n"
            "BEGIN\n  EXECUTE 'DROP TABLE ' || p_table;\nEND;\n"
            "$func$ LANGUAGE plpgsql;\n")
    s = src(code, "postgresql")
    findings = SqlInjectionCheck(
        pg_rules.check("sql_injection"), "postgresql").run(s)
    assert any(f.severity == Severity.CRITICAL for f in findings)
