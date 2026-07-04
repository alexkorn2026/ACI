"""Tests für den Waiver-/Ausnahmeprozess (aci.waivers).

Geprüft werden das Datenmodell (:class:`Waiver`), das Laden und
Validieren der Waiver-Datei (:func:`load_waivers`), die Zuordnung zu
Findings (:func:`apply_waivers`), die CLI-Anbindung (``--waivers`` /
``--strict-waivers``) sowie die Darstellung in den vier Reportformaten.
"""

import datetime
import json
import os

from aci.scanner import Scanner
from aci.reporting import (ScanReport, render_json, render_sarif,
                           render_console, render_html)
from aci.finding import (Finding, Severity, GROUP_SECURITY, GROUP_INTERNAL,
                         compute_fingerprint, stable_relative_path)
from aci.waivers import Waiver, load_waivers, apply_waivers, SOON_DAYS
from aci.cli import main

TODAY = datetime.date(2026, 5, 24)


def sp(samples_dir, name):
    return os.path.join(samples_dir, name)


def _finding(fp, sev=Severity.HIGH, check_id="ACI-SQLI"):
    """Baut ein minimales Finding mit vorgegebenem Fingerabdruck."""
    return Finding(check_id=check_id, check_name="Test", group=GROUP_SECURITY,
                   severity=sev, file="x.sql", line=1, column=1,
                   message="m", fingerprint=fp)


def _waiver(fp, expires, ticket="SEC-1", owner="a@example.com",
            reason="Test-Begründung"):
    return Waiver(fingerprint=fp, ticket=ticket, owner=owner,
                  expires=expires, reason=reason)


# ----------------------------------------------------------------------
# compute_fingerprint
# ----------------------------------------------------------------------

def test_fingerprint_is_stable_and_short():
    fp = compute_fingerprint("ACI-SQLI", "exec", "dir/file.sql", "x := 1;")
    assert fp == compute_fingerprint("ACI-SQLI", "exec", "dir/file.sql",
                                     "x := 1;")
    assert len(fp) == 16


def test_fingerprint_normalizes_statement_whitespace():
    # Mehrfach-Whitespace im Code-Ausschnitt wird normalisiert.
    a = compute_fingerprint("ACI-SQLI", "", "f.sql", "x  :=   1;")
    b = compute_fingerprint("ACI-SQLI", "", "f.sql", "x := 1;")
    assert a == b


def test_fingerprint_distinguishes_directory():
    # Gleicher Basisname, aber anderes Verzeichnis -> anderer
    # Fingerabdruck. So deckt ein Waiver fuer db/admin/install.sql kein
    # Finding in db/app/install.sql mit ab.
    a = compute_fingerprint("ACI-PG", "", "db/admin/install.sql", "x;")
    b = compute_fingerprint("ACI-PG", "", "db/app/install.sql", "x;")
    assert a != b


def test_fingerprint_changes_with_statement():
    a = compute_fingerprint("ACI-SQLI", "", "f.sql", "x := 1;")
    b = compute_fingerprint("ACI-SQLI", "", "f.sql", "x := 2;")
    assert a != b


def test_fingerprint_changes_with_dialect():
    a = compute_fingerprint("ACI-DDL", "", "f.sql", "GRANT;",
                            dialect="oracle")
    b = compute_fingerprint("ACI-DDL", "", "f.sql", "GRANT;",
                            dialect="postgresql")
    assert a != b


# ----------------------------------------------------------------------
# stable_relative_path
# ----------------------------------------------------------------------

def test_stable_relative_path_uses_scan_root():
    assert stable_relative_path(
        "/repo/db/admin/install.sql", "/repo") == "db/admin/install.sql"


def test_stable_relative_path_independent_of_absolute_root():
    # Gleicher Scan-Root-relativer Pfad -> gleiches Ergebnis, egal wo
    # das Repository ausgecheckt ist.
    a = stable_relative_path("/tmp/run1/repo/db/admin/install.sql",
                             "/tmp/run1/repo")
    b = stable_relative_path("/tmp/run2/repo/db/admin/install.sql",
                             "/tmp/run2/repo")
    assert a == b == "db/admin/install.sql"


def test_stable_relative_path_without_root_keeps_path():
    # Ohne Scan-Root: normalisierte Darstellung, nicht nur der Basename.
    assert stable_relative_path("db/admin/install.sql") == \
        "db/admin/install.sql"
    assert stable_relative_path("db\\admin\\install.sql") == \
        "db/admin/install.sql"


# ----------------------------------------------------------------------
# Waiver-Datenmodell
# ----------------------------------------------------------------------

def test_waiver_expiry_logic():
    w = _waiver("abc", datetime.date(2026, 6, 1))
    assert not w.is_expired(TODAY)
    assert w.days_left(TODAY) == 8
    past = _waiver("abc", datetime.date(2020, 1, 1))
    assert past.is_expired(TODAY)
    assert past.days_left(TODAY) < 0


def test_waiver_to_dict_roundtrip_fields():
    w = _waiver("abc", datetime.date(2026, 12, 31))
    d = w.to_dict()
    assert d["fingerprint"] == "abc"
    assert d["expires"] == "2026-12-31"
    assert set(d) == {"fingerprint", "ticket", "owner", "expires",
                      "reason", "created", "risk_accepted"}


# ----------------------------------------------------------------------
# load_waivers
# ----------------------------------------------------------------------

def test_load_waivers_empty_path():
    assert load_waivers("") == ([], [])


def test_load_waivers_missing_file(tmp_path):
    waivers, errors = load_waivers(str(tmp_path / "nope.json"))
    assert waivers == []
    assert errors and "nicht gefunden" in errors[0]


def test_load_waivers_invalid_json(tmp_path):
    p = tmp_path / "w.json"
    p.write_text("nicht json", encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    assert waivers == [] and errors


def test_load_waivers_not_a_list(tmp_path):
    p = tmp_path / "w.json"
    p.write_text('{"fingerprint": "x"}', encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    assert waivers == [] and "JSON-Liste" in errors[0]


def test_load_waivers_valid_entry(tmp_path):
    p = tmp_path / "w.json"
    p.write_text(json.dumps([{
        "fingerprint": "ABC123", "ticket": "SEC-9",
        "owner": "a@example.com", "expires": "2026-12-31",
        "reason": "ok", "risk_accepted": True}]), encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    assert errors == []
    assert len(waivers) == 1
    # Fingerprint wird normalisiert (klein geschrieben).
    assert waivers[0].fingerprint == "abc123"
    assert waivers[0].expires == datetime.date(2026, 12, 31)
    assert waivers[0].risk_accepted is True


def test_load_waivers_missing_required_fields(tmp_path):
    p = tmp_path / "w.json"
    p.write_text(json.dumps([
        {"fingerprint": "a", "ticket": "T1", "owner": "o",
         "expires": "2026-12-31", "reason": "r"},
        {"fingerprint": "b"}]), encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    # Der gültige Eintrag wird geladen, der defekte gemeldet.
    assert len(waivers) == 1
    assert errors and "Pflichtfeld" in errors[0]


def test_load_waivers_invalid_date(tmp_path):
    p = tmp_path / "w.json"
    p.write_text(json.dumps([{
        "fingerprint": "a", "ticket": "T", "owner": "o",
        "expires": "31.12.2026", "reason": "r"}]), encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    assert waivers == [] and "Ablaufdatum" in errors[0]


def test_load_waivers_duplicate_fingerprint(tmp_path):
    p = tmp_path / "w.json"
    entry = {"fingerprint": "dup", "ticket": "T", "owner": "o",
             "expires": "2026-12-31", "reason": "r"}
    p.write_text(json.dumps([entry, dict(entry)]), encoding="utf-8")
    waivers, errors = load_waivers(str(p))
    assert len(waivers) == 1
    assert errors and "doppelt" in errors[0]


# ----------------------------------------------------------------------
# apply_waivers - Lebenszyklus
# ----------------------------------------------------------------------

def test_apply_waivers_valid_marks_finding():
    f = _finding("fp1")
    results = {"x.sql": [f]}
    rep = apply_waivers(results, [_waiver("fp1", datetime.date(2026, 12, 31))],
                        today=TODAY)
    assert f.waived is True
    assert f.waiver is not None and f.waiver.ticket == "SEC-1"
    assert rep.applied == 1
    assert len(rep.active) == 1 and not rep.expired and not rep.orphaned


def test_apply_waivers_expired_does_not_suppress():
    f = _finding("fp1")
    rep = apply_waivers({"x.sql": [f]},
                        [_waiver("fp1", datetime.date(2020, 1, 1))],
                        today=TODAY)
    assert f.waived is False
    assert rep.applied == 0
    assert len(rep.expired) == 1 and not rep.active


def test_apply_waivers_orphaned_when_no_match():
    f = _finding("fp1")
    rep = apply_waivers({"x.sql": [f]},
                        [_waiver("other", datetime.date(2026, 12, 31))],
                        today=TODAY)
    assert f.waived is False
    assert len(rep.orphaned) == 1 and not rep.active


def test_apply_waivers_soon_expiring_is_flagged():
    f = _finding("fp1")
    soon = TODAY + datetime.timedelta(days=SOON_DAYS - 1)
    rep = apply_waivers({"x.sql": [f]}, [_waiver("fp1", soon)], today=TODAY)
    assert f.waived is True
    assert len(rep.soon) == 1 and len(rep.active) == 1


def test_apply_waivers_empty_fingerprint_not_waivable():
    # Interne Werkzeugfehler tragen keinen Fingerabdruck.
    internal = Finding(check_id="ACI-INTERNAL", check_name="x",
                       group=GROUP_INTERNAL, severity=Severity.HIGH,
                       file="x.sql", line=1, column=1, message="m",
                       fingerprint="")
    rep = apply_waivers({"x.sql": [internal]},
                        [_waiver("", datetime.date(2026, 12, 31))],
                        today=TODAY)
    assert internal.waived is False
    # Ein Waiver auf den leeren Fingerprint trifft nichts -> verwaist.
    assert len(rep.orphaned) == 1


def test_apply_waivers_match_count_set():
    f1, f2 = _finding("shared"), _finding("shared")
    rep = apply_waivers({"x.sql": [f1, f2]},
                        [_waiver("shared", datetime.date(2026, 12, 31))],
                        today=TODAY)
    assert rep.applied == 2
    assert rep.active[0].match_count == 2


def test_waiver_report_warning_lines_and_dict():
    f = _finding("fp1")
    rep = apply_waivers(
        {"x.sql": [f]},
        [_waiver("fp1", datetime.date(2020, 1, 1)),
         _waiver("ghost", datetime.date(2026, 12, 31), ticket="SEC-2")],
        today=TODAY, path="w.json")
    assert rep.has_warnings
    assert any("abgelaufen" in line.lower() for line in rep.warning_lines())
    d = rep.to_dict()
    assert d["path"] == "w.json"
    assert len(d["expired"]) == 1 and len(d["orphaned"]) == 1


# ----------------------------------------------------------------------
# Scanner - Fingerprint stabil gegenüber --no-context
# ----------------------------------------------------------------------

_VULN = ("BEGIN\n"
         "  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\n"
         "END;\n")


def test_scanner_assigns_fingerprints(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "mem.sql")
    assert findings
    assert all(f.fingerprint for f in findings)


def test_fingerprint_independent_of_report_context(oracle_rules):
    with_ctx = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY},
                       report_context=True).scan_text(_VULN, "mem.sql")
    without = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY},
                      report_context=False).scan_text(_VULN, "mem.sql")
    assert [f.fingerprint for f in with_ctx] == \
           [f.fingerprint for f in without]


# ----------------------------------------------------------------------
# Reportintegration
# ----------------------------------------------------------------------

def _waived_report(oracle_rules):
    """ScanReport, in dem das erste Finding gewaivert ist."""
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "mem.sql")
    results = {"mem.sql": findings}
    fp = findings[0].fingerprint
    wrep = apply_waivers(results,
                         [_waiver(fp, datetime.date(2099, 12, 31))],
                         today=TODAY, path="w.json")
    report = ScanReport(results, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY}, waiver_report=wrep)
    return report, findings[0]


def test_json_report_contains_waivers_section(oracle_rules):
    report, waived = _waived_report(oracle_rules)
    data = json.loads(render_json(report))
    assert data["waivers"]["applied"] == 1
    finding = data["files"][0]["findings"][0]
    assert finding["waived"] is True
    assert finding["fingerprint"] == waived.fingerprint
    assert finding["waiver"]["ticket"] == "SEC-1"


def test_json_report_no_waivers_when_unused(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    findings = scanner.scan_text(_VULN, "mem.sql")
    report = ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY})
    data = json.loads(render_json(report))
    assert data["waivers"] is None


def test_sarif_report_has_suppression(oracle_rules):
    report, _ = _waived_report(oracle_rules)
    data = json.loads(render_sarif(report))
    results = data["runs"][0]["results"]
    suppressed = [r for r in results if r.get("suppressions")]
    assert len(suppressed) == 1
    sup = suppressed[0]["suppressions"][0]
    assert sup["kind"] == "external"
    assert "SEC-1" in sup["justification"]
    # Fingerabdruck als partialFingerprints im SARIF.
    assert all("partialFingerprints" in r for r in results)


def test_console_report_shows_waiver_and_fingerprint(oracle_rules):
    report, waived = _waived_report(oracle_rules)
    text = render_console(report, use_color=False)
    assert "[WAIVED]" in text
    assert "Waiver / Ausnahmen" in text
    assert waived.fingerprint in text


def test_html_report_shows_waiver_section(oracle_rules):
    report, _ = _waived_report(oracle_rules)
    out = render_html(report)
    assert 'class="waivers"' in out
    assert "Waiver / Ausnahmen" in out
    assert 'class="wbadge"' in out


# ----------------------------------------------------------------------
# CLI-Anbindung
# ----------------------------------------------------------------------

def _all_fingerprints(samples_dir, tmp_path):
    """Scannt oracle_vulnerable.sql und liefert alle Fingerabdrücke."""
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text("utf-8"))
    fps = []
    for fobj in data["files"]:
        for f in fobj["findings"]:
            if f["fingerprint"]:
                fps.append(f["fingerprint"])
    return fps


def _write_waivers(path, fingerprints, expires="2099-12-31"):
    path.write_text(json.dumps([
        {"fingerprint": fp, "ticket": "SEC-100", "owner": "a@example.com",
         "expires": expires, "reason": "CI-Test-Waiver"}
        for fp in fingerprints]), encoding="utf-8")
    return str(path)


def test_cli_waivers_suppress_fail_on(samples_dir, tmp_path):
    fps = _all_fingerprints(samples_dir, tmp_path)
    wfile = _write_waivers(tmp_path / "w.json", fps)
    # Ohne Waiver blockiert --fail-on high.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
                 "--fail-on", "high"]) == 1
    # Mit vollständigem Waiver-Satz läuft das Gate durch.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
                 "--fail-on", "high", "--waivers", wfile]) == 0


def test_cli_partial_waiver_still_fails(samples_dir, tmp_path):
    fps = _all_fingerprints(samples_dir, tmp_path)
    # Nur einen einzigen Befund waivern - der Rest blockt weiter.
    wfile = _write_waivers(tmp_path / "w.json", fps[:1])
    assert main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
                 "--fail-on", "high", "--waivers", wfile]) == 1


def test_cli_expired_waiver_does_not_suppress(samples_dir, tmp_path):
    fps = _all_fingerprints(samples_dir, tmp_path)
    wfile = _write_waivers(tmp_path / "w.json", fps, expires="2020-01-01")
    # Abgelaufene Waiver greifen nicht - Gate blockt weiter.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
                 "--fail-on", "high", "--waivers", wfile]) == 1


def test_cli_strict_waivers_breaks_on_bad_file(samples_dir, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("kein json", encoding="utf-8")
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "--waivers", str(bad), "--strict-waivers"])
    assert rc == 2


def test_cli_bad_waiver_file_only_warns_without_strict(samples_dir, tmp_path,
                                                       capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("kein json", encoding="utf-8")
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "--fail-on", "none", "--waivers", str(bad)])
    assert rc == 0
    assert "Waiver" in capsys.readouterr().err


def test_cli_waivers_section_in_json_report(samples_dir, tmp_path):
    fps = _all_fingerprints(samples_dir, tmp_path)
    wfile = _write_waivers(tmp_path / "w.json", fps[:1])
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "--waivers", wfile, "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text("utf-8"))
    assert data["waivers"] is not None
    assert data["waivers"]["applied"] == 1


def test_cli_aci_ini_provides_strict_waivers(samples_dir, tmp_path,
                                             monkeypatch):
    (tmp_path / "aci.ini").write_text(
        "[defaults]\nstrict_waivers = true\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("kein json", encoding="utf-8")
    # strict_waivers aus aci.ini -> Exit-Code 2 ohne CLI-Flag.
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "--waivers", str(bad)])
    assert rc == 2


def test_waiver_does_not_leak_across_identical_basenames(tmp_path):
    """Regression: gleicher Basisname in verschiedenen Verzeichnissen.

    Mit der frueheren basename-only-Fingerprint-Logik haette ein Waiver
    fuer db/admin/install.sql faelschlich auch das gleiche Finding in
    db/app/install.sql gedeckt. Der repo-relative Pfad verhindert das.
    """
    stmt = "GRANT pg_read_server_files TO app_user;\n"
    for sub in ("admin", "app"):
        d = tmp_path / "db" / sub
        d.mkdir(parents=True)
        (d / "install.sql").write_text(stmt, encoding="utf-8")
    out = tmp_path / "out"
    rid = "ACI-PG-ADMIN-GRANT-SYSTEM-ROLE"
    report = out / f"aci_report_{tmp_path.name}.json"

    def scan(extra=None):
        argv = [str(tmp_path), "-d", "postgresql", "-g", "security",
                "-f", "json", "-o", str(out)] + (extra or [])
        rc = main(argv)
        return rc, json.loads(report.read_text(encoding="utf-8"))

    def by_dir(data, field):
        out_map = {}
        for fb in data["files"]:
            key = "admin" if "admin" in fb["file"] else "app"
            for f in fb["findings"]:
                if f["check_id"] == rid:
                    out_map[key] = f[field]
        return out_map

    # 1. Erster Scan: beide Dateien melden dasselbe Finding - aber mit
    #    UNTERSCHIEDLICHEN Fingerabdruecken (verschiedene Verzeichnisse).
    _rc, data = scan()
    fp = by_dir(data, "fingerprint")
    assert fp.get("admin") and fp.get("app")
    assert fp["admin"] != fp["app"]

    # 2. Waiver nur fuer db/admin/install.sql.
    wfile = tmp_path / "w.json"
    wfile.write_text(json.dumps([{
        "fingerprint": fp["admin"], "ticket": "SEC-1",
        "owner": "a@example.com", "expires": "2099-12-31",
        "reason": "Test"}]), encoding="utf-8")

    # 3. Zweiter Scan mit Waiver: nur admin ist waived, app nicht.
    rc, data = scan(["--waivers", str(wfile), "--fail-on", "critical"])
    waived = by_dir(data, "waived")
    assert waived["admin"] is True
    assert waived["app"] is False
    # Das nicht gewaivte Critical-Finding blockt den Gate weiterhin.
    assert rc == 1
