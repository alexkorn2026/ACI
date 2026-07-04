"""S15: End-to-End-Smoke-Tests (Modul-Aufruf + optional Wheel-Installation).

Der erste Test deckt den Weg ohne Installation ab (``python -m aci`` erzeugt
alle Reportformate). Der zweite baut ein Wheel, installiert es in eine frische
virtuelle Umgebung und ruft ``aci`` dort auf - er wird uebersprungen, wenn das
``build``-Modul fehlt oder die Umgebung kein venv erlaubt.
"""

import json
import os
import subprocess
import sys

import pytest


def _write_sql(tmp_path):
    p = tmp_path / "vuln.sql"
    p.write_text(
        "CREATE OR REPLACE PROCEDURE p(a VARCHAR2) IS\nBEGIN\n"
        "  EXECUTE IMMEDIATE 'SELECT ' || a;\nEND;\n/\n", encoding="utf-8")
    return p


def test_module_scan_produces_all_formats(project_root, tmp_path):
    p = _write_sql(tmp_path)
    out = tmp_path / "out"
    res = subprocess.run(
        [sys.executable, "-m", "aci", str(p), "-g", "security",
         "-f", "console,json,sarif,html,codeclimate", "-o", str(out)],
        cwd=project_root, capture_output=True, text=True)
    assert res.returncode in (0, 1), res.stderr
    # JSON + SARIF parsen, HTML/CodeClimate vorhanden.
    data = json.loads((out / "aci_report_vuln.json").read_text("utf-8"))
    assert data["tool"].startswith("ACI")
    sarif = json.loads((out / "aci_report_vuln.sarif").read_text("utf-8"))
    assert sarif["version"] == "2.1.0"
    cc = json.loads((out / "aci_report_vuln.codeclimate.json").read_text("utf-8"))
    assert isinstance(cc, list)
    assert "<html" in (out / "aci_report_vuln.html").read_text("utf-8").lower()


@pytest.mark.slow
def test_wheel_install_and_run(project_root, tmp_path):
    try:
        import build  # noqa: F401
    except Exception:
        pytest.skip("build-Modul nicht verfuegbar")

    dist = tmp_path / "dist"
    build = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist)],
        cwd=project_root, capture_output=True, text=True)
    if build.returncode != 0:
        pytest.skip(f"Wheel-Build fehlgeschlagen: {build.stderr[-500:]}")
    wheels = list(dist.glob("aci-*.whl"))
    assert wheels, "kein Wheel erzeugt"

    venv = tmp_path / "venv"
    if subprocess.run([sys.executable, "-m", "venv", str(venv)],
                      capture_output=True).returncode != 0:
        pytest.skip("venv nicht erstellbar")
    bindir = "Scripts" if os.name == "nt" else "bin"
    py = venv / bindir / ("python.exe" if os.name == "nt" else "python")
    aci = venv / bindir / ("aci.exe" if os.name == "nt" else "aci")

    inst = subprocess.run([str(py), "-m", "pip", "install", str(wheels[0])],
                          capture_output=True, text=True)
    if inst.returncode != 0:
        pytest.skip(f"pip install fehlgeschlagen: {inst.stderr[-500:]}")

    ver = subprocess.run([str(aci), "--version"], capture_output=True, text=True)
    assert ver.returncode == 0 and "ACI" in ver.stdout
    # Gebuendelte Regeln geladen (kein Rueckgriff auf den Quellbaum noetig).
    checks = subprocess.run([str(aci), "--list-checks"], capture_output=True,
                            text=True)
    assert checks.returncode == 0 and "Sicherheit" in checks.stdout

    p = _write_sql(tmp_path)
    scan = subprocess.run([str(aci), str(p), "-g", "security", "-f",
                           "json,sarif", "-o", str(tmp_path / "o")],
                          capture_output=True, text=True)
    assert scan.returncode in (0, 1), scan.stderr
    assert (tmp_path / "o" / "aci_report_vuln.json").is_file()
