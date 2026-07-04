"""M2/S12: Scan-Vollstaendigkeit wirkt aufs Gate und steht im Report."""

import json
import os

import pytest

from aci.cli import main


def _sql(p):
    p.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n", encoding="utf-8")
    return p


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Rechte")
def test_strict_profile_fails_on_unreadable_file(tmp_path):
    f = _sql(tmp_path / "a.sql")
    os.chmod(f, 0o000)
    try:
        rc = main([str(tmp_path), "--scan-completeness", "strict",
                   "-g", "security", "-f", "console"])
        assert rc == 2
    finally:
        os.chmod(f, 0o644)


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Rechte")
def test_advisory_passes_on_unreadable_file(tmp_path):
    f = _sql(tmp_path / "a.sql")
    os.chmod(f, 0o000)
    try:
        rc = main([str(tmp_path), "-g", "security", "-f", "console"])
        assert rc == 0
    finally:
        os.chmod(f, 0o644)


def test_strict_fails_on_skipped_large_file(tmp_path):
    _sql(tmp_path / "a.sql")
    rc = main([str(tmp_path), "--scan-completeness", "strict",
               "--max-file-size", "3", "-g", "security", "-f", "console"])
    assert rc == 2


def test_fail_on_skipped_file_flag(tmp_path):
    _sql(tmp_path / "a.sql")
    rc = main([str(tmp_path), "--fail-on-skipped-file",
               "--max-file-size", "3", "-g", "security", "-f", "console"])
    assert rc == 2


def test_scan_completeness_block_in_json(tmp_path):
    _sql(tmp_path / "a.sql")
    out = tmp_path / "out"
    main([str(tmp_path / "a.sql"), "-f", "json", "-o", str(out),
          "-g", "security"])
    data = json.loads((out / "aci_report_a.json").read_text("utf-8"))
    assert "scan_completeness" in data
    assert data["scan_completeness"]["complete"] is True
    assert set(data["scan_completeness"]) >= {
        "complete", "access_errors", "skipped_too_large", "decode_errors"}
