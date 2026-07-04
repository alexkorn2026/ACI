"""S1: ``aci:ignore-next-line`` bezieht sich auf die naechste *tatsaechliche*
Codezeile - Leer- und reine Kommentarzeilen werden uebersprungen."""

from aci.source import Source
from aci.suppressions import parse_suppressions, apply_suppressions
from aci.finding import Finding, Severity, GROUP_SECURITY


def _targets(code, dialect="oracle"):
    src = Source(code, "t.sql", dialect)
    return parse_suppressions(src.text, src.tokens, src.code_no_comments)


def _f(line):
    return Finding(check_id="ACI-SQLI", check_name="x", group=GROUP_SECURITY,
                   severity=Severity.CRITICAL, file="t.sql", line=line,
                   column=1, message="m", rule_ref="ACI-SQLI",
                   fingerprint="0123456789abcdef")


def test_next_line_direct():
    t = _targets("-- aci:ignore-next-line\nEXECUTE IMMEDIATE p_sql;\n")
    assert 2 in t


def test_skips_blank_line():
    t = _targets("-- aci:ignore-next-line\n\nEXECUTE IMMEDIATE p_sql;\n")
    assert 3 in t and 2 not in t


def test_skips_comment_line():
    code = ("-- aci:ignore-next-line\n"
            "-- Begruendung zum folgenden Code\n"
            "EXECUTE IMMEDIATE p_sql;\n")
    t = _targets(code)
    assert 3 in t and 1 not in t and 2 not in t


def test_skips_blank_and_comment_mix():
    code = ("-- aci:ignore-next-line\n"
            "\n"
            "-- fachliche Erklaerung\n"
            "EXECUTE IMMEDIATE p_sql;\n")
    assert 4 in _targets(code)


def test_skips_block_comment_lines():
    code = ("-- aci:ignore-next-line\n"
            "/* mehrzeiliger\n"
            "   Blockkommentar */\n"
            "EXECUTE IMMEDIATE p_sql;\n")
    assert 4 in _targets(code)


def test_code_with_trailing_comment_is_not_skipped():
    # Zeile 2 traegt Code UND Kommentar -> gilt als Codezeile.
    code = ("-- aci:ignore-next-line\n"
            "EXECUTE IMMEDIATE p_sql; -- hinweis\n")
    assert 2 in _targets(code)


def test_end_of_file_without_following_code():
    # Keine folgende Codezeile -> keine Zielzeile, kein Fehler.
    t = _targets("EXECUTE IMMEDIATE p_sql;\n-- aci:ignore-next-line\n")
    assert t == {} or all(v for v in t.values())


def test_multiple_consecutive_directives():
    code = ("-- aci:ignore-next-line\n"
            "-- aci:ignore-next-line\n"
            "EXECUTE IMMEDIATE p_sql;\n")
    # Beide Direktiven zeigen auf die naechste Codezeile (3).
    assert 3 in _targets(code)


def test_rule_id_on_next_line_directive():
    src = Source("-- aci:ignore-next-line[ACI-SQLI]\nrisky;\n", "t.sql",
                 "oracle")
    kept, supp = apply_suppressions([_f(2)], src)
    assert len(supp) == 1 and kept == []


def test_next_line_applies_over_blank_end_to_end():
    src = Source("-- aci:ignore-next-line\n\nrisky;\n", "t.sql", "oracle")
    kept, supp = apply_suppressions([_f(3)], src)
    assert len(supp) == 1 and kept == []


def test_crlf_line_endings():
    t = _targets("-- aci:ignore-next-line\r\n\r\nEXECUTE IMMEDIATE p_sql;\r\n")
    assert 3 in t


def test_postgresql_dialect():
    code = ("-- aci:ignore-next-line\n"
            "\n"
            "EXECUTE 'drop table ' || p;\n")
    assert 3 in _targets(code, dialect="postgresql")
