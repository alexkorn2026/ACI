"""End-to-End-Tests ueber die CLI fuer Inline-Suppression und Baseline
(ACI 2.22.1). Ergaenzt die Unit-Tests in den dedizierten Modulen.
"""

import json
import glob

from aci.cli import main

_VULN = ("CREATE OR REPLACE PROCEDURE p(p_id VARCHAR2) AS\n"
         "BEGIN\n"
         "  EXECUTE IMMEDIATE 'SELECT * FROM t WHERE x=' || p_id;\n"
         "END;\n/\n")

# gleiche vulnerable Zeile mit Suppression-Zeichenfolge INNERHALB des Strings
_VULN_STRING_DIRECTIVE = (
    "CREATE OR REPLACE PROCEDURE p(p_id VARCHAR2) AS\n"
    "BEGIN\n"
    "  EXECUTE IMMEDIATE 'SELECT x=' || p_id || ' -- aci:ignore';\n"
    "END;\n/\n")

# vulnerable Zeile mit ECHTER Kommentar-Suppression
_VULN_SUPPRESSED = (
    "CREATE OR REPLACE PROCEDURE p(p_id VARCHAR2) AS\n"
    "BEGIN\n"
    "  EXECUTE IMMEDIATE 'SELECT x=' || p_id;  -- aci:ignore[ACI-SQLI]\n"
    "END;\n/\n")


def _write(tmp_path, name, code):
    p = tmp_path / name
    p.write_text(code, encoding="utf-8")
    return str(p)


def _json_total(out_dir):
    path = sorted(glob.glob(f"{out_dir}/*.json"))[-1]
    return json.load(open(path, encoding="utf-8"))["summary"]["findings_total"]


def test_scan_without_suppression_fails_gate(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN)
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--fail-on", "high"])
    assert rc == 1


def test_real_comment_suppression_removes_finding(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN_SUPPRESSED)
    out = str(tmp_path / "rep")
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--fail-on", "high", "--format", "json", "--output-dir", out])
    assert rc == 0
    assert _json_total(out) == 0


def test_string_directive_does_not_remove_finding(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN_STRING_DIRECTIVE)
    out = str(tmp_path / "rep")
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--fail-on", "high", "--format", "json", "--output-dir", out])
    assert rc == 1
    assert _json_total(out) >= 1


def test_write_baseline_v2_and_reuse(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN)
    bl = str(tmp_path / "bl.json")
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--write-baseline", bl])
    assert rc == 0
    data = json.loads(open(bl, encoding="utf-8").read())
    assert data["baseline_version"] == 2 and data["findings"]
    # Zweiter Lauf mit Baseline: keine neuen Findings -> Gate gruen.
    rc2 = main([f, "--dialect", "oracle", "--group", "security",
                "--fail-on", "high", "--baseline", bl])
    assert rc2 == 0


def test_legacy_baseline_is_read(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN)
    # Fingerabdruck ueber einen Schreiblauf gewinnen ...
    out = str(tmp_path / "rep")
    main([f, "--dialect", "oracle", "--group", "security",
          "--format", "json", "--output-dir", out])
    rep = json.load(open(sorted(glob.glob(f"{out}/*.json"))[-1],
                         encoding="utf-8"))
    fps = [x["fingerprint"] for fi in rep["files"] for x in fi["findings"]]
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({"fingerprints": fps}), encoding="utf-8")
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--fail-on", "high", "--baseline", str(legacy)])
    assert rc == 0


def test_copied_identical_finding_stays_visible(tmp_path):
    # Baseline aus einer Datei mit EINEM Vorkommen; danach zweite identische
    # Instanz derselben verwundbaren Zeile -> bleibt sichtbar (Gate rot).
    f1 = _write(tmp_path, "one.sql", _VULN)
    bl = str(tmp_path / "bl.json")
    main([f1, "--dialect", "oracle", "--group", "security",
          "--write-baseline", bl])
    two = _VULN + "\n" + _VULN.replace("PROCEDURE p", "PROCEDURE p2")
    # p2 hat anderen Namen -> anderer Fingerprint; nutze exakt dieselbe Proc
    # zweimal in derselben Datei fuer identische Fingerabdruecke:
    same = _VULN + _VULN
    f2 = _write(tmp_path, "one.sql", same)  # gleicher Pfad/Name wie Baseline
    out = str(tmp_path / "rep")
    rc = main([f2, "--dialect", "oracle", "--group", "security",
               "--fail-on", "high", "--baseline", bl,
               "--format", "json", "--output-dir", out])
    assert rc == 1  # das zweite (kopierte) Vorkommen bleibt neu
    _ = two


def test_named_argument_interprocedural_via_cli(tmp_path):
    code = (
        "CREATE OR REPLACE PACKAGE BODY pkg IS\n"
        "  PROCEDURE run_sql(p_mode VARCHAR2, p_sql VARCHAR2) IS\n"
        "  BEGIN\n"
        "    EXECUTE IMMEDIATE 'SELECT ' || p_sql;\n"
        "  END;\n"
        "  PROCEDURE handle(p_user VARCHAR2) IS\n"
        "  BEGIN\n"
        "    run_sql(p_sql => p_user, p_mode => 'A');\n"
        "  END;\n"
        "END;\n/\n")
    f = _write(tmp_path, "pkg.sql", code)
    out = str(tmp_path / "rep")
    main([f, "--dialect", "oracle", "--group", "security",
          "--format", "json", "--output-dir", out])
    rep = json.load(open(sorted(glob.glob(f"{out}/*.json"))[-1],
                         encoding="utf-8"))
    refs = [x["rule_ref"] for fi in rep["files"] for x in fi["findings"]]
    assert "ACI-SQLI-IP" in refs


def test_invalid_baseline_controlled_error(tmp_path):
    f = _write(tmp_path, "v.sql", _VULN)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    rc = main([f, "--dialect", "oracle", "--group", "security",
               "--baseline", str(bad)])
    assert rc == 2
