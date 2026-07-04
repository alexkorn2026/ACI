"""Tests fuer Runtime-/Gate-/Integritaets-Metadaten im Report (TODO 3)."""

import json

from aci.cli import main


def _scan(tmp_path, sql, fmt="json", extra=None, name="a"):
    src = tmp_path / f"{name}.sql"
    src.write_text(sql, encoding="utf-8")
    argv = [str(src), "-d", "oracle", "-g", "security", "-f", fmt,
            "-o", str(tmp_path), "--no-context"]
    if extra:
        argv += extra
    rc = main(argv)
    return rc, src


_CLEAN = "select 1 from dual;\n"
_VULN = ("CREATE OR REPLACE PROCEDURE p(p_x IN VARCHAR2) IS\nBEGIN\n"
         "  EXECUTE IMMEDIATE 'drop table ' || p_x;\nEND;\n/\n")


def _json(tmp_path, name="a"):
    return json.loads(
        (tmp_path / f"aci_report_{name}.json").read_text(encoding="utf-8"))


def test_json_has_runtime_and_gate(tmp_path):
    _scan(tmp_path, _CLEAN)
    d = _json(tmp_path)
    assert set(["aci_version", "python", "platform", "executable", "cwd",
                "started_at_utc", "duration_ms"]) <= set(d["runtime"].keys())
    assert set(["profile", "fail_on", "passed", "exit_code",
                "actual_ruleset_sha256"]) <= set(d["gate"].keys())


def test_gate_passed_when_clean(tmp_path):
    rc, _ = _scan(tmp_path, _CLEAN, extra=["--fail-on", "high"])
    d = _json(tmp_path)
    assert rc == 0
    assert d["gate"]["passed"] is True and d["gate"]["exit_code"] == 0


def test_gate_failed_above_threshold(tmp_path):
    rc, _ = _scan(tmp_path, _VULN, extra=["--fail-on", "high"])
    d = _json(tmp_path)
    assert rc == 1
    assert d["gate"]["passed"] is False and d["gate"]["exit_code"] == 1


def test_safe_report_redacts_runtime_paths(tmp_path):
    _scan(tmp_path, _CLEAN, extra=["--safe-report"])
    rt = _json(tmp_path)["runtime"]
    assert rt["cwd"] == "<redacted>" and rt["executable"] == "<redacted>"


def test_sarif_has_runtime_and_gate(tmp_path):
    _scan(tmp_path, _VULN, fmt="sarif", extra=["--fail-on", "high"])
    sarif = json.loads(
        (tmp_path / "aci_report_a.sarif").read_text(encoding="utf-8"))
    props = sarif["runs"][0]["properties"]
    assert "aci_runtime" in props and "aci_gate" in props
    assert props["aci_gate"]["exit_code"] == 1
