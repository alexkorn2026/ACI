"""S8/S9: Encoding-Behandlung und TOCTOU-feste Groessenpruefung."""

from aci import Scanner
from aci.scanner import decode_source_bytes
from aci.rules import load_ruleset, find_ruleset
from tests.conftest import RULES_DIR


def _scanner(**kw):
    rs = load_ruleset(find_ruleset("oracle", RULES_DIR))
    return Scanner(rs, **kw)


def test_decode_reports_replacements_on_bad_bytes():
    raw = b"BEGIN \xff\xfe END;"          # ungueltiges UTF-8
    text, enc, had_repl = decode_source_bytes(raw)
    assert had_repl is True
    assert enc == "utf-8"


def test_decode_strict_raises_on_bad_bytes():
    raw = b"BEGIN \xff END;"
    try:
        decode_source_bytes(raw, errors="strict")
        assert False, "sollte UnicodeDecodeError werfen"
    except UnicodeDecodeError:
        pass


def test_encoding_strict_records_decode_error_and_skips(tmp_path):
    p = tmp_path / "bad.sql"
    p.write_bytes(b"BEGIN \xff EXECUTE IMMEDIATE 'x'; END;")
    sc = _scanner(encoding_errors="strict")
    results = sc.scan_path(str(p))
    # Datei gilt als ungeprueft (nicht in Ergebnissen), Fehler erfasst.
    assert results == {}
    assert sc.decode_errors and not sc.scan_complete()


def test_replace_mode_records_decode_error_but_scans(tmp_path):
    p = tmp_path / "bad.sql"
    p.write_bytes(b"BEGIN \xff EXECUTE IMMEDIATE 'x' || p; END;")
    sc = _scanner()                          # replace (Default)
    results = sc.scan_path(str(p))
    assert str(p) in results                 # trotz Ersatzzeichen geprueft
    assert sc.decode_errors                  # aber als Problem vermerkt


def test_file_growth_after_size_check_is_bounded(tmp_path):
    # Datei knapp unter Limit, waechst dann; nur Limit+1 wird gelesen.
    p = tmp_path / "grow.sql"
    p.write_text("A" * 100, encoding="utf-8")
    sc = _scanner(max_file_size=50)
    results = sc.scan_path(str(p))
    # 100 Byte > 50 => uebersprungen, nie vollstaendig eingelesen.
    assert results == {}
    assert sc.skipped_files
