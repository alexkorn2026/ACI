"""Tests fuer die Ruleset-Integritaetspruefung (--expected-ruleset-sha256 /
--ruleset-lock), TODO 1 fuer ACI 2.16.0."""

import json

from aci.cli import main


def _scan_to_json(tmp_path, name="a.sql", sql="select 1 from dual;\n", extra=None):
    src = tmp_path / name
    src.write_text(sql, encoding="utf-8")
    argv = [str(src), "-d", "oracle", "-g", "security", "-f", "json",
            "-o", str(tmp_path), "--no-context"]
    if extra:
        argv += extra
    rc = main(argv)
    report = json.loads(
        (tmp_path / f"aci_report_{name.rsplit('.', 1)[0]}.json")
        .read_text(encoding="utf-8"))
    return rc, report


def _actual_hash(tmp_path):
    _rc, report = _scan_to_json(tmp_path)
    return report["ruleset_integrity"]["actual_sha256"]


def test_expected_hash_match_passes(tmp_path):
    h = _actual_hash(tmp_path)
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--expected-ruleset-sha256", h])
    assert rc == 0


def test_expected_hash_case_insensitive(tmp_path):
    h = _actual_hash(tmp_path).upper()
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--expected-ruleset-sha256", h])
    assert rc == 0


def test_expected_hash_mismatch_exits_2(tmp_path):
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--expected-ruleset-sha256", "0" * 64])
    assert rc == 2


def test_invalid_expected_hash_exits_2(tmp_path):
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--expected-ruleset-sha256", "deadbeef"])
    assert rc == 2


def test_report_contains_expected_and_actual(tmp_path):
    h = _actual_hash(tmp_path)
    _rc, report = _scan_to_json(tmp_path, name="b.sql",
                                extra=["--expected-ruleset-sha256", h])
    ri = report["ruleset_integrity"]
    assert ri["actual_sha256"] == h
    assert ri["expected_sha256"] == h
    assert ri["verified"] is True
    assert ri["source"] == "cli"


def test_ruleset_lock_match_passes(tmp_path):
    h = _actual_hash(tmp_path)
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"ruleset_sha256": h}), encoding="utf-8")
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--ruleset-lock", str(lock)])
    assert rc == 0


def test_ruleset_lock_missing_exits_2(tmp_path):
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--ruleset-lock", str(tmp_path / "nope.json")])
    assert rc == 2


def test_lock_and_cli_conflict_exits_2(tmp_path):
    lock = tmp_path / "lock.json"
    lock.write_text(json.dumps({"ruleset_sha256": "a" * 64}), encoding="utf-8")
    src = tmp_path / "x.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    rc = main([str(src), "-d", "oracle", "-g", "security", "--no-context",
               "--ruleset-lock", str(lock),
               "--expected-ruleset-sha256", "b" * 64])
    assert rc == 2
