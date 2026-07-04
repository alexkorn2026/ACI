import json

from aci.ir import assignments_before, ir_to_dict, routine_for_offset
from aci.parser import parse_ir, _split_top_level
from aci.cli import main


def _split(text):
    return [text[a:b] for a, b in _split_top_level(text, "||")]


def test_split_top_level_keeps_dollar_quote_literal_intact():
    # Ein '||' INNERHALB eines Dollar-Quote-Literals ist kein Top-Level-
    # Trenner; nur das aeussere '||' zerlegt den Ausdruck.
    assert _split("'PRE ' || $q$a || b$q$") == ["'PRE ' ", " $q$a || b$q$"]


def test_split_top_level_keeps_qquote_literal_intact():
    # Oracle-q-Quote mit eingebettetem '||' (und ') bleibt ungeteilt.
    assert _split("q'[a || b]' || x") == ["q'[a || b]' ", " x"]


def test_split_top_level_ignores_inner_comma_in_dollar_quote():
    parts = [t.strip() for a, b in _split_top_level("$q$a, b$q$, c", ",")
             for t in [("$q$a, b$q$, c")[a:b]]]
    assert parts == ["$q$a, b$q$", "c"]


def test_ir_nested_routine_boundaries_via_end_name():
    # 'END <name>;' begrenzt die Routine; eine lokale Subroutine liegt
    # vollstaendig in der aeusseren, und Code wird der innersten
    # Routine zugeordnet.
    sql = ("PACKAGE BODY pkg AS\n"
           "  PROCEDURE outer_p IS\n"
           "    PROCEDURE inner_p IS\n"
           "    BEGIN\n"
           "      EXECUTE IMMEDIATE 'select 1 from dual';\n"
           "    END inner_p;\n"
           "  BEGIN\n"
           "    EXECUTE IMMEDIATE 'select 2 from dual';\n"
           "  END outer_p;\n"
           "END pkg;\n")
    ir = parse_ir(sql, dialect="oracle")
    outer = next(r for r in ir.routines if r.name == "outer_p")
    inner = next(r for r in ir.routines if r.name == "inner_p")
    assert outer.range.start.offset <= inner.range.start.offset
    assert inner.range.end.offset <= outer.range.end.offset
    by_expr = {d.expression: routine_for_offset(ir, d.range.start.offset).name
               for d in ir.dynamic_sql}
    assert by_expr["'select 1 from dual'"] == "inner_p"
    assert by_expr["'select 2 from dual'"] == "outer_p"


def test_ir_detects_oracle_procedure():
    sql = """
    CREATE OR REPLACE PROCEDURE p AS
    BEGIN
      NULL;
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    assert len(ir.routines) == 1
    assert ir.routines[0].name.upper() == "P"
    assert ir.routines[0].kind == "procedure"


def test_ir_detects_oracle_execute_immediate():
    sql = """
    BEGIN
      EXECUTE IMMEDIATE 'DROP USER x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    assert len(ir.dynamic_sql) == 1
    assert ir.dynamic_sql[0].kind == "execute_immediate"


def test_ir_detects_postgresql_function():
    sql = """
    CREATE OR REPLACE FUNCTION f()
    RETURNS void
    LANGUAGE plpgsql
    AS $$
    BEGIN
      NULL;
    END;
    $$;
    """
    ir = parse_ir(sql, dialect="postgresql")
    assert len(ir.routines) == 1
    assert ir.routines[0].name == "f"
    assert ir.routines[0].kind == "function"


def test_ir_detects_postgresql_assignment_and_execute():
    sql = """
    CREATE OR REPLACE FUNCTION f(p_table text)
    RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
      v_sql text;
    BEGIN
      v_sql := 'select * from ' || p_table;
      EXECUTE v_sql;
    END;
    $$;
    """
    ir = parse_ir(sql, dialect="postgresql")
    assert any(a.target.lower() == "v_sql" for a in ir.assignments)
    assert any(d.kind == "execute" for d in ir.dynamic_sql)


def test_ir_ignores_admin_ddl_in_comments():
    sql = """
    -- ALTER USER app ACCOUNT UNLOCK;
    SELECT 1 FROM dual;
    """
    ir = parse_ir(sql, dialect="oracle")
    assert not any("ALTER USER" in s.text.upper() for s in ir.statements)


def test_ir_ignores_admin_ddl_in_string_literals():
    sql = "SELECT 'GRANT DBA TO app_user' FROM dual;"
    ir = parse_ir(sql, dialect="oracle")
    assert not any(s.kind == "grant" for s in ir.statements)


def test_ir_assignments_before_ignores_later_assignment():
    sql = """
    CREATE OR REPLACE PROCEDURE p AS
      l_sql varchar2(4000);
    BEGIN
      l_sql := 'select * from safe_table';
      EXECUTE IMMEDIATE l_sql;
      l_sql := 'drop table x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    exec_ = ir.dynamic_sql[0]
    assigns = assignments_before(ir, "l_sql", exec_.range.start.offset, exec_.routine_name)
    assert len(assigns) == 1
    assert "safe_table" in assigns[0].expression


def test_ir_assignments_before_respects_routine_boundaries():
    sql = """
    CREATE OR REPLACE PROCEDURE a AS
      l_sql varchar2(1000);
    BEGIN
      l_sql := 'select * from safe_table';
      EXECUTE IMMEDIATE l_sql;
    END;
    /
    CREATE OR REPLACE PROCEDURE b AS
      l_sql varchar2(1000);
    BEGIN
      l_sql := 'drop user x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    exec_ = ir.dynamic_sql[0]
    assigns = assignments_before(ir, "l_sql", exec_.range.start.offset, exec_.routine_name)
    assert all("drop user" not in a.expression.lower() for a in assigns)


def test_ir_to_dict_is_json_serializable():
    ir = parse_ir("BEGIN EXECUTE IMMEDIATE 'select 1 from dual'; END; /", "oracle")
    json.dumps(ir_to_dict(ir))


def test_dump_ir_outputs_json(tmp_path, capsys):
    sql_file = tmp_path / "sample.sql"
    sql_file.write_text("BEGIN EXECUTE IMMEDIATE 'select 1 from dual'; END; /", encoding="utf-8")
    rc = main([str(sql_file), "--dump-ir"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["dialect"] == "oracle"
    assert data["dynamic_sql"]


def test_ir_expression_models_concat_and_call():
    ir = parse_ir("""
    BEGIN
      l_sql := 'select * from ' || DBMS_ASSERT.SQL_OBJECT_NAME(p_table);
      EXECUTE IMMEDIATE l_sql;
    END;
    /
    """, dialect="oracle")
    expr = next(a.expression_ir for a in ir.assignments if a.target.lower() == "l_sql")
    assert expr.kind == "concat"
    assert any(getattr(part, "function_name", "").upper() == "DBMS_ASSERT.SQL_OBJECT_NAME"
               for part in expr.parts)


def test_ir_expression_models_postgresql_format_call():
    ir = parse_ir("EXECUTE format('select * from %I where id = %L', p_table, p_id);", dialect="postgresql")
    expr = ir.dynamic_sql[0].expression_ir
    assert expr.kind == "format_call"
    assert expr.function_name.lower() == "format"
    assert len(expr.arguments) == 3


def test_ir_control_blocks_are_recorded():
    sql = """
    BEGIN
      IF flag THEN
        NULL;
      ELSE
        NULL;
      END IF;
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    kinds = {block.kind for block in ir.control_blocks}
    assert "if" in kinds
    assert "else" in kinds
