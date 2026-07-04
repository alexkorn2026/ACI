"""M4: Schutzgrenzen gelten auch fuer explizit uebergebene Einzeldateien."""

import os

import pytest

from aci import Scanner
from aci.rules import load_ruleset, find_ruleset
from tests.conftest import RULES_DIR


def _scanner(**kw):
    rs = load_ruleset(find_ruleset("oracle", RULES_DIR))
    return Scanner(rs, **kw)


def _f(tmp_path, name="big.sql"):
    p = tmp_path / name
    p.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n" * 5,
                 encoding="utf-8")
    return p


def test_explicit_file_respects_max_file_size(tmp_path):
    p = _f(tmp_path)
    sc = _scanner(max_file_size=5)
    results = sc.scan_path(str(p))
    assert results == {}                    # uebersprungen, nicht in Ergebnis
    assert sc.skipped_files and sc.skipped_files[0][0] == str(p)


def test_force_file_bypasses_max_file_size(tmp_path):
    p = _f(tmp_path)
    sc = _scanner(max_file_size=5, limits_apply_to_explicit_files=False)
    results = sc.scan_path(str(p))
    assert str(p) in results                # trotz Limit geprueft
    assert not sc.skipped_files


def test_explicit_file_respects_exclude(tmp_path):
    p = _f(tmp_path, "generated.sql")
    sc = _scanner(exclude=["generated.sql"])
    results = sc.scan_path(str(p))
    assert results == {}
    assert sc.rejected_files and "exclude" in sc.rejected_files[0][1]


def test_explicit_file_under_default_exclude_dir_is_still_scanned(tmp_path):
    # Wer eine Datei ausdruecklich benennt, will sie geprueft haben - auch
    # wenn sie unter einem Default-Exclude-Verzeichnis (dist/) liegt. Nur
    # benutzerdefinierte --exclude-Muster duerfen sie ablehnen.
    d = tmp_path / "dist"
    d.mkdir()
    p = _f(d, "app.sql")
    sc = _scanner()
    results = sc.scan_path(str(p))
    assert str(p) in results
    assert not sc.rejected_files


@pytest.mark.skipif(os.name == "nt", reason="POSIX-Symlinks")
def test_explicit_symlink_respects_no_follow_symlinks(tmp_path):
    target = _f(tmp_path, "target.sql")
    link = tmp_path / "link.sql"
    os.symlink(target, link)
    sc = _scanner(follow_symlinks=False)
    results = sc.scan_path(str(link))
    assert results == {}
    assert sc.rejected_files and "Symlink" in sc.rejected_files[0][1]
