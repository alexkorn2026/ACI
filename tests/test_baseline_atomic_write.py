"""S4: Baselines werden atomar geschrieben (kein beschaedigtes Ziel)."""

import json
import os

import pytest

from collections import Counter

import aci.baseline as baseline
from aci.baseline import write_baseline, load_baseline
from aci.finding import Finding, Severity, GROUP_SECURITY

FP = "0123456789abcdef"


def _f(fp=FP):
    return Finding(check_id="ACI-SQLI", check_name="x", group=GROUP_SECURITY,
                   severity=Severity.CRITICAL, file="t.sql", line=1, column=1,
                   message="m", rule_ref="ACI-SQLI", fingerprint=fp)


def test_write_creates_valid_v2(tmp_path):
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f()]})
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["baseline_version"] == 2
    assert data["findings"] == {FP: 1}
    assert open(path, encoding="utf-8").read().endswith("\n")


def test_write_replaces_existing(tmp_path):
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f()]})
    write_baseline(path, {"t.sql": [_f(), _f()]})
    assert load_baseline(path) == Counter({FP: 2})


def test_no_tempfiles_left_after_success(tmp_path):
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f()]})
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".aci-baseline-")]
    assert leftovers == []


def test_replace_failure_keeps_existing_and_cleans_temp(tmp_path, monkeypatch):
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f()]})           # gueltige Vorversion
    original = open(path, encoding="utf-8").read()

    def boom(src, dst):
        raise OSError("simulierter os.replace-Fehler")

    monkeypatch.setattr(baseline.os, "replace", boom)
    with pytest.raises(OSError):
        write_baseline(path, {"t.sql": [_f(), _f()]})
    # Zieldatei unveraendert, keine Temp-Reste.
    assert open(path, encoding="utf-8").read() == original
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".aci-baseline-")]
    assert leftovers == []


def test_write_failure_cleans_temp(tmp_path, monkeypatch):
    path = str(tmp_path / "bl.json")

    real_replace = baseline.os.replace

    def boom(*a, **k):
        raise OSError("simulierter Schreibfehler")

    # fsync scheitern lassen -> Schreibpfad bricht ab, Temp muss weg.
    monkeypatch.setattr(baseline.os, "fsync", boom)
    with pytest.raises(OSError):
        write_baseline(path, {"t.sql": [_f()]})
    assert not os.path.exists(path)
    leftovers = [n for n in os.listdir(tmp_path) if n.startswith(".aci-baseline-")]
    assert leftovers == []
    # os.replace unangetastet
    assert baseline.os.replace is real_replace
