"""M5: Reportdateien werden atomar geschrieben."""

import os

import pytest

import aci._io as _io
from aci.cli import main


def _sql(tmp_path):
    p = tmp_path / "a.sql"
    p.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n", encoding="utf-8")
    return p


@pytest.mark.parametrize("fmt,ext", [("json", "json"), ("sarif", "sarif"),
                                     ("codeclimate", "codeclimate.json")])
def test_report_atomic_write_creates_file(tmp_path, fmt, ext):
    _sql(tmp_path)
    out = tmp_path / "out"
    main([str(tmp_path / "a.sql"), "-f", fmt, "-o", str(out), "-g", "security"])
    assert (out / f"aci_report_a.{ext}").is_file()
    # Keine Temp-Reste des atomaren Schreibens.
    leftovers = [n for n in os.listdir(out) if n.startswith(".aci-")]
    assert leftovers == []


def test_report_write_failure_preserves_previous_report(tmp_path, monkeypatch):
    _sql(tmp_path)
    out = tmp_path / "out"
    main([str(tmp_path / "a.sql"), "-f", "json", "-o", str(out),
          "-g", "security"])
    target = out / "aci_report_a.json"
    original = target.read_text("utf-8")

    def boom(*a, **k):
        raise OSError("simulierter Schreibfehler")

    # fsync scheitern lassen -> atomarer Schreibpfad bricht ab.
    monkeypatch.setattr(_io.os, "fsync", boom)
    with pytest.raises(OSError):
        _io.atomic_write_text(str(target), "KAPUTT")
    # Zieldatei unveraendert, keine Temp-Reste.
    assert target.read_text("utf-8") == original
    assert [n for n in os.listdir(out) if n.startswith(".aci-")] == []
