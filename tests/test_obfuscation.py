"""Tests fuer die Obfuskations-Erkennung.

Geprueft werden gewrappter Oracle-Code, CHR()-Ketten, Base64-Bloecke,
Aufrufe von De-/Kodierfunktionen sowie das dynamische Ausfuehren
dekodierter Inhalte.
"""

import string

from aci.source import Source
from aci.checks import ObfuscationCheck
from aci.finding import Severity


def obf(code, rules, dialect="oracle"):
    s = Source(code, "t.sql", dialect)
    return ObfuscationCheck(rules.check("obfuscation"), dialect).run(s)


def _base64_blob(n=80):
    """Liefert einen langen, variantenreichen Base64-Block."""
    chars = (string.ascii_uppercase + string.ascii_lowercase
             + string.digits + "+/")
    return (chars * 2)[:n]


def test_wrapped_code_is_detected(oracle_rules):
    code = ("CREATE OR REPLACE PROCEDURE secret WRAPPED\n"
            "a000000\nabcd ef 12 34\n")
    f = obf(code, oracle_rules)
    assert any(x.rule_ref == "WRAPPED" for x in f)


def test_chr_chain_is_detected(oracle_rules):
    code = ("BEGIN\n  l_x := CHR(83)||CHR(69)||CHR(76)||CHR(69)||CHR(67);\n"
            "END;\n")
    f = obf(code, oracle_rules)
    assert any(x.rule_ref == "CHR-CHAIN" for x in f)


def test_short_chr_chain_is_not_detected(oracle_rules):
    code = "BEGIN\n  l_x := CHR(65) || CHR(66);\nEND;\n"
    f = obf(code, oracle_rules)
    assert not any(x.rule_ref == "CHR-CHAIN" for x in f)


def _hex_blob(n=120):
    """Liefert einen langen, variantenreichen Hex-Block."""
    return ("0123456789abcdef" * 16)[:n]


def test_base64_blob_in_string_is_detected(oracle_rules):
    blob = _base64_blob(80)
    code = f"BEGIN\n  l_data := '{blob}';\nEND;\n"
    f = obf(code, oracle_rules)
    assert any(x.rule_ref == "base64-blob" for x in f)


def test_hex_blob_in_assignment_is_detected(pg_rules):
    blob = _hex_blob()
    code = f"BEGIN\n  v := '{blob}';\nEND;\n"
    f = obf(code, pg_rules, "postgresql")
    assert any(x.rule_ref == "hex-blob" for x in f)


def test_hex_blob_in_insert_values_is_not_flagged(pg_rules):
    # Lange Hex-Bloecke in INSERT-Datenzeilen (z.B. PostGIS-WKB-Geometrie,
    # serialisierte BLOBs) sind Daten, kein verschleierter Code.
    blob = _hex_blob()
    code = f"INSERT INTO geo(id, wkb) VALUES (1, '{blob}');\n"
    f = obf(code, pg_rules, "postgresql")
    assert not any(x.rule_ref == "hex-blob" for x in f)


def test_hex_blob_in_multirow_insert_is_not_flagged(pg_rules):
    blob = _hex_blob()
    code = (
        "INSERT INTO geo(id, wkb) VALUES\n"
        f"  (1, '{blob}'),\n"
        f"  (2, '{blob}');\n"
    )
    f = obf(code, pg_rules, "postgresql")
    assert not any(x.rule_ref == "hex-blob" for x in f)


def test_base64_blob_in_insert_values_is_not_flagged(oracle_rules):
    blob = _base64_blob(80)
    code = f"INSERT INTO t(id, data) VALUES (1, '{blob}');\n"
    f = obf(code, oracle_rules)
    assert not any(x.rule_ref == "base64-blob" for x in f)


def test_base64_decode_call_is_detected(oracle_rules):
    code = "BEGIN\n  l_raw := utl_encode.base64_decode(p_in);\nEND;\n"
    f = obf(code, oracle_rules)
    assert any(x.rule_ref == "base64-decode-call" for x in f)


def test_dynamic_decode_exec_is_critical(oracle_rules):
    code = "BEGIN\n  EXECUTE IMMEDIATE convert(l_payload, 'AL32UTF8');\nEND;\n"
    f = obf(code, oracle_rules)
    crit = [x for x in f if x.rule_ref == "dynamic-decode-exec"]
    assert crit and crit[0].severity == Severity.CRITICAL


def test_clean_code_has_no_obfuscation_findings(oracle_rules):
    code = ("BEGIN\n"
            "  SELECT name INTO l_name FROM employees WHERE id = p_id;\n"
            "  l_total := l_total + 1;\n"
            "END;\n")
    assert obf(code, oracle_rules) == []


def test_postgres_chr_chain_is_detected(pg_rules):
    code = ("BEGIN\n  x := chr(83)||chr(69)||chr(76)||chr(69)||chr(67);\n"
            "END;\n")
    f = obf(code, pg_rules, "postgresql")
    assert any(x.rule_ref == "CHR-CHAIN" for x in f)


def test_postgres_wrapped_keyword_is_ignored(pg_rules):
    # PostgreSQL kennt kein WRAP -> 'WRAPPED' darf nichts ausloesen.
    code = "SELECT col AS WRAPPED\nFROM t;\n"
    f = obf(code, pg_rules, "postgresql")
    assert not any(x.rule_ref == "WRAPPED" for x in f)
