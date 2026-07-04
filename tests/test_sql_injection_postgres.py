"""PostgreSQL-SQL-Injection-Tests.

Prueft die Risikoklassifikation fuer PL/pgSQL: unsichere Konkatenation
und ``format()`` mit ``%s`` sind kritisch, ``EXECUTE ... USING`` sowie
``format()`` mit ``%I``/``%L`` und ``quote_ident``/``quote_literal``
sind es nicht.
"""

from aci.source import Source
from aci.checks import SqlInjectionCheck
from aci.finding import Severity

_FUNC = ("CREATE OR REPLACE FUNCTION f({params}) RETURNS void AS $func$\n"
         "BEGIN\n  {body}\nEND;\n$func$ LANGUAGE plpgsql;\n")


def wrap(params, body):
    return _FUNC.format(params=params, body=body)


def sqli(code, pg_rules):
    s = Source(code, "t.sql", "postgresql")
    return SqlInjectionCheck(
        pg_rules.check("sql_injection"), "postgresql").run(s)


def no_critical(findings):
    return all(f.severity != Severity.CRITICAL for f in findings)


def has_critical(findings):
    return any(f.severity == Severity.CRITICAL for f in findings)


def test_unsafe_concatenation_is_critical(pg_rules):
    code = wrap("p_name text",
                "EXECUTE 'select * from users where name = ''' "
                "|| p_name || '''';")
    assert has_critical(sqli(code, pg_rules))


def test_execute_using_is_not_critical(pg_rules):
    code = wrap("p_id int",
                "EXECUTE 'select * from users where id = $1' USING p_id;")
    findings = sqli(code, pg_rules)
    assert no_critical(findings)
    assert findings == []          # reines Literal + Bind -> kein Finding


def test_format_percent_i_is_not_critical(pg_rules):
    code = wrap("p_table text, p_id int",
                "EXECUTE format('select * from %I where id = $1', p_table) "
                "USING p_id;")
    assert no_critical(sqli(code, pg_rules))


def test_format_percent_l_is_not_critical(pg_rules):
    code = wrap("p_name text",
                "EXECUTE format('select * from users where name = %L', "
                "p_name);")
    assert no_critical(sqli(code, pg_rules))


def test_format_percent_s_is_dangerous(pg_rules):
    code = wrap("p_where text",
                "EXECUTE format('select * from users where %s', p_where);")
    assert has_critical(sqli(code, pg_rules))


def test_format_with_concatenated_format_string_is_dangerous(pg_rules):
    code = wrap("p_table text",
                "EXECUTE format('select * from ' || p_table);")
    assert has_critical(sqli(code, pg_rules))


def test_format_with_parameter_format_string_is_critical(pg_rules):
    # Der Formatstring selbst ist ein ungeprüfter Routine-Parameter -
    # der Aufrufer steuert die Platzhalter-Politik: kein harmloser Fall.
    code = wrap("p_fmt text, p_table text",
                "EXECUTE format(p_fmt, p_table);")
    findings = sqli(code, pg_rules)
    assert has_critical(findings)
    msg = " ".join(f.message for f in findings).lower()
    assert "nicht-literal" in msg


def test_format_literal_identifier_placeholders_not_critical(pg_rules):
    # Literaler Formatstring mit %I/%L bleibt entschärft.
    code = wrap("p_table text, p_id text",
                "EXECUTE format('SELECT * FROM %I WHERE id = %L', "
                "p_table, p_id);")
    assert no_critical(sqli(code, pg_rules))


def test_format_string_from_select_into_is_tainted(pg_rules):
    # Formatstring stammt aus einer Tabelle -> 2nd-order-Taint.
    code = ("CREATE FUNCTION f() RETURNS void AS $func$\n"
            "DECLARE\n  v_fmt text;\n  v_value text;\n"
            "BEGIN\n"
            "  SELECT template INTO v_fmt FROM sql_templates "
            "WHERE name = 'x';\n"
            "  EXECUTE format(v_fmt, v_value);\n"
            "END;\n$func$ LANGUAGE plpgsql;\n")
    sev = [f.severity for f in sqli(code, pg_rules)
           if f.check_id == "ACI-SQLI"]
    assert sev and any(s in (Severity.HIGH, Severity.CRITICAL)
                       for s in sev)


def test_quote_ident_is_not_critical(pg_rules):
    code = wrap("p_table text",
                "EXECUTE 'select * from ' || quote_ident(p_table);")
    assert no_critical(sqli(code, pg_rules))


def test_quote_literal_is_not_critical(pg_rules):
    code = wrap("p_name text",
                "EXECUTE 'select * from users where name = ' "
                "|| quote_literal(p_name);")
    assert no_critical(sqli(code, pg_rules))


def test_tainted_variable_then_execute_is_critical(pg_rules):
    code = wrap("p_name text",
                "l_sql := 'DROP TABLE ' || p_name;\n  EXECUTE l_sql;")
    assert has_critical(sqli(code, pg_rules))


def test_static_query_has_no_finding(pg_rules):
    code = wrap("p_id int", "PERFORM 1 FROM users WHERE id = p_id;")
    assert sqli(code, pg_rules) == []


def test_grant_execute_is_not_treated_as_dynamic_sql(pg_rules):
    # "GRANT EXECUTE ON ..." darf nicht als PL/pgSQL-EXECUTE gewertet werden.
    code = "GRANT EXECUTE ON FUNCTION f() TO PUBLIC;\n"
    findings = sqli(code, pg_rules)
    assert findings == []


# -- Regression: format() als Konkatenations-Operand --------------------
# Frueher wurde 'format(' als Konkatenations-Operand pauschal als Sanitizer
# (Warning) gewertet - unabhaengig vom Platzhalter. Ein '%s' escaped aber
# NICHT, sodass '... ' || format('%s', x) eine uebersehene Injection war.

def test_format_percent_s_in_concatenation_is_critical(pg_rules):
    code = wrap("p_id text",
                "EXECUTE 'SELECT * FROM t WHERE n = ' "
                "|| format('%s', p_id);")
    assert has_critical(sqli(code, pg_rules))


def test_format_percent_i_in_concatenation_not_critical(pg_rules):
    # Gegenprobe: %I escaped Bezeichner -> auch als Operand entschaerft.
    code = wrap("p_table text",
                "EXECUTE 'SELECT * FROM ' || format('%I', p_table);")
    assert no_critical(sqli(code, pg_rules))


# -- Regression: Dollar-Quote-Literale beim Split nicht zerteilen --------
# Frueher zerteilte _split_top_level ein Dollar-Quote-Literal an einem '||'
# in seinem Inhalt; die Fragmente galten als getaintet -> False Positive.

def test_dollar_quote_literal_with_inner_concat_not_critical(pg_rules):
    code = wrap("", "EXECUTE 'PRE ' || $q$a || b$q$;")
    assert no_critical(sqli(code, pg_rules))


def test_dollar_quote_literal_plus_sanitizer_not_critical(pg_rules):
    code = wrap("p_col text",
                "EXECUTE $q$SELECT a || b FROM t WHERE c = $q$ "
                "|| quote_ident(p_col);")
    assert no_critical(sqli(code, pg_rules))
