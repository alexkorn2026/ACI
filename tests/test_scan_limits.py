"""Tests fuer Scan-Limits: Default-Excludes, eigene Exclude-Muster,
Groessenlimit und Symlink-Schutz beim rekursiven Verzeichnis-Scan.
"""

import os

import pytest

from aci.scanner import Scanner, DEFAULT_EXCLUDES, _matches_exclude
from aci.finding import GROUP_SECURITY

_SQL = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p;\nEND;\n"


def _scanner(oracle_rules, **kwargs):
    return Scanner(oracle_rules, [], [], groups={GROUP_SECURITY}, **kwargs)


def _write(path, text=_SQL):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


# -- _matches_exclude ----------------------------------------------------

def test_matches_exclude_component():
    assert _matches_exclude("a/.git/hooks/x.sql", [".git"])
    assert _matches_exclude("node_modules/x.sql", ["node_modules"])
    assert not _matches_exclude("src/app.sql", [".git", "node_modules"])


def test_matches_exclude_glob():
    assert _matches_exclude("build/gen.sql", ["build"])
    assert _matches_exclude("a/b/temp.sql", ["*.sql"])


# -- Default-Excludes ----------------------------------------------------

def test_default_excludes_skip_git_directory(oracle_rules, tmp_path):
    _write(str(tmp_path / ".git" / "hooks" / "evil.sql"))
    _write(str(tmp_path / "src" / "good.sql"))
    results = _scanner(oracle_rules).scan_path(str(tmp_path))
    scanned = list(results)
    assert any("good.sql" in p for p in scanned)
    assert not any(".git" in p for p in scanned)


def test_default_excludes_skip_node_modules(oracle_rules, tmp_path):
    _write(str(tmp_path / "node_modules" / "pkg" / "dep.sql"))
    _write(str(tmp_path / "app.sql"))
    results = _scanner(oracle_rules).scan_path(str(tmp_path))
    assert not any("node_modules" in p for p in results)
    assert any("app.sql" in p for p in results)


def test_default_excludes_constant_is_nonempty():
    assert ".git" in DEFAULT_EXCLUDES
    assert "node_modules" in DEFAULT_EXCLUDES


# -- Eigene Exclude-Muster ----------------------------------------------

def test_explicit_exclude_pattern(oracle_rules, tmp_path):
    _write(str(tmp_path / "generated" / "bad.sql"))
    _write(str(tmp_path / "manual" / "ok.sql"))
    results = _scanner(oracle_rules, exclude=["generated"]).scan_path(
        str(tmp_path))
    assert not any("generated" in p for p in results)
    assert any("ok.sql" in p for p in results)


# -- Groessenlimit -------------------------------------------------------

def test_oversized_file_is_skipped(oracle_rules, tmp_path):
    big = tmp_path / "big.sql"
    big.write_text(_SQL + "-- Fueller\n" * 5000, encoding="utf-8")
    small = tmp_path / "small.sql"
    small.write_text(_SQL, encoding="utf-8")
    scanner = _scanner(oracle_rules, max_file_size=1024)   # 1 KB
    results = scanner.scan_path(str(tmp_path))
    assert any("small.sql" in p for p in results)
    assert not any("big.sql" in p for p in results)
    assert any("big.sql" in p for p, _size in scanner.skipped_files)


def test_file_under_limit_is_scanned(oracle_rules, tmp_path):
    src = tmp_path / "ok.sql"
    src.write_text(_SQL, encoding="utf-8")
    scanner = _scanner(oracle_rules, max_file_size=1024 * 1024)
    results = scanner.scan_path(str(tmp_path))
    assert any("ok.sql" in p for p in results)
    assert scanner.skipped_files == []


# -- Symlink-Schutz ------------------------------------------------------

def test_symlinked_directory_is_not_followed(oracle_rules, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.sql").write_text(_SQL, encoding="utf-8")
    link = tmp_path / "link"
    try:
        os.symlink(str(real), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks werden auf diesem System nicht unterstuetzt")
    results = _scanner(oracle_rules).scan_path(str(tmp_path))
    # Die echte Datei wird gescannt, der Symlink-Pfad nicht.
    assert any(os.path.join("real", "a.sql") in p for p in results)
    assert not any(os.path.join("link", "a.sql") in p for p in results)


def test_follow_symlinks_option_descends(oracle_rules, tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (real / "a.sql").write_text(_SQL, encoding="utf-8")
    link = tmp_path / "link"
    try:
        os.symlink(str(real), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks werden auf diesem System nicht unterstuetzt")
    results = _scanner(oracle_rules, follow_symlinks=True).scan_path(
        str(tmp_path))
    assert any(os.path.join("link", "a.sql") in p for p in results)


# -- Dateiendung: Verzeichnis vs. explizite Einzeldatei ------------------

def test_directory_scan_ignores_unknown_extension(oracle_rules, tmp_path):
    _write(str(tmp_path / "good.sql"))
    _write(str(tmp_path / "ignored.weirdext"))
    results = _scanner(oracle_rules).scan_path(str(tmp_path))
    assert any("good.sql" in p for p in results)
    assert not any("weirdext" in p for p in results)


def test_explicit_file_is_scanned_regardless_of_extension(oracle_rules,
                                                          tmp_path):
    src = tmp_path / "script.weirdext"
    _write(str(src))
    results = _scanner(oracle_rules).scan_path(str(src))
    assert str(src) in results
