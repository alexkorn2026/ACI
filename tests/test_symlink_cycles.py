"""M1: Symlink-Zyklen fuehren nicht zu endloser Rekursion."""

import os

import pytest

from aci import Scanner
from aci.rules import load_ruleset, find_ruleset
from tests.conftest import RULES_DIR


def _scanner(**kw):
    rs = load_ruleset(find_ruleset("oracle", RULES_DIR))
    return Scanner(rs, follow_symlinks=True, **kw)


def _mk(tmp_path, rel, text="CREATE TABLE t (x NUMBER);\n"):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Symlinks")
def test_follow_symlink_direct_cycle_does_not_recurse_forever(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _mk(tmp_path, "src/a.sql")
    os.symlink(src, src / "loop")            # src/loop -> src (Selbstzyklus)
    results = _scanner().scan_path(str(tmp_path))
    # Terminiert und findet die Datei genau einmal (kein loop/loop/... ).
    assert any(k.endswith("a.sql") for k in results)
    assert all("loop/loop" not in k for k in results)


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Symlinks")
def test_follow_symlink_indirect_cycle_does_not_recurse_forever(tmp_path):
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir()
    b.mkdir()
    _mk(tmp_path, "a/x.sql")
    os.symlink(b, a / "tob")                 # a/tob -> b
    os.symlink(a, b / "toa")                 # b/toa -> a (indirekter Zyklus)
    results = _scanner().scan_path(str(tmp_path))
    assert any(k.endswith("x.sql") for k in results)


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Symlinks")
def test_follow_symlink_duplicate_target_scanned_once(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    _mk(tmp_path, "real/only.sql")
    os.symlink(real, tmp_path / "link1")     # zwei Symlinks auf dasselbe Ziel
    os.symlink(real, tmp_path / "link2")
    results = _scanner().scan_path(str(tmp_path))
    hits = [k for k in results if k.endswith("only.sql")]
    # Dieselbe reale Datei wird nur einmal geprueft (Device/Inode-Erkennung).
    assert len(hits) == 1
