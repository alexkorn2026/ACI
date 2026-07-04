"""Tests fuer die Paket- und Python-Versions-Metadaten.

Stellt sicher, dass die deklarierte Python-Mindestversion, die Werkzeug-
Konfiguration (ruff) und die Paketversion konsistent sind.
"""

import os
import re

import aci


def test_package_version_format():
    assert re.fullmatch(r"\d+\.\d+\.\d+", aci.__version__), aci.__version__


def test_version_module_matches_package(project_root):
    text = open(os.path.join(project_root, "aci", "_version.py"),
                encoding="utf-8").read()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', text)
    assert m and m.group(1) == aci.__version__


def test_requires_python_declared_and_consistent(project_root):
    pyproject = open(os.path.join(project_root, "pyproject.toml"),
                     encoding="utf-8").read()
    # requires-python ist vorhanden und eine Untergrenze (>=3.x).
    req = re.search(r'requires-python\s*=\s*"\s*>=\s*3\.(\d+)"', pyproject)
    assert req, "requires-python (>=3.x) fehlt in pyproject.toml"
    min_minor = int(req.group(1))
    # ruff-Zielversion muss zur deklarierten Mindestversion passen.
    rt = re.search(r'target-version\s*=\s*"py3(\d+)"', pyproject)
    assert rt, "ruff target-version fehlt"
    assert int(rt.group(1)) == min_minor, (
        f"ruff py3{rt.group(1)} passt nicht zu requires-python 3.{min_minor}")
    # Fuer die Mindestversion existiert ein Trove-Classifier.
    assert f'"Programming Language :: Python :: 3.{min_minor}"' in pyproject


def test_manifest_excludes_release_unworthy_artifacts(project_root):
    """MANIFEST.in muss Cache- und generierte Report-Artefakte vom
    Quellarchiv ausschliessen (Release-Hygiene)."""
    manifest = open(os.path.join(project_root, "MANIFEST.in"),
                    encoding="utf-8").read()
    required = [
        "global-exclude *.py[cod]",
        "global-exclude aci_report_*.json",
        "global-exclude aci_report_*.html",
        "global-exclude aci_report_*.sarif",
        "prune .pytest_cache",
    ]
    for line in required:
        assert line in manifest, f"MANIFEST.in fehlt: {line}"
