"""Tests fuer die Kommandozeilen-Schnittstelle (aci.cli).

Geprueft werden Exit-Codes, Reportausgabe, der ``--fail-on``-Mechanismus
fuer CI/CD, der ``python -m aci``-Aufruf sowie die neuen Optionen
``--no-context`` und ``--redact-secrets``.
"""

import json
import os
import subprocess
import sys

import pytest

from aci.cli import (main, _redact_text, _redact_results, _redact_path,
                     _redact_command_line)


def sp(samples_dir, name):
    return os.path.join(samples_dir, name)


# -- python -m aci (Modul-Einstiegspunkt) --------------------------------

def test_module_help_exits_zero(project_root):
    res = subprocess.run([sys.executable, "-m", "aci", "--help"],
                         cwd=project_root, capture_output=True, text=True)
    assert res.returncode == 0
    assert "ACI" in res.stdout


def test_module_version_reports_version(project_root):
    from aci import __version__
    res = subprocess.run([sys.executable, "-m", "aci", "--version"],
                         cwd=project_root, capture_output=True, text=True)
    assert res.returncode == 0
    assert __version__ in res.stdout


# -- Grundlegende CLI-Faelle ---------------------------------------------

def test_version_action_exits_zero():
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0


def test_list_checks_returns_zero(capsys):
    rc = main(["--list-checks"])
    assert rc == 0
    assert "Sicherheit" in capsys.readouterr().out


def test_missing_path_argument_exits_two():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_nonexistent_path_returns_two():
    assert main(["/nonexistent/path/xyz.sql", "-g", "security"]) == 2


def test_unknown_format_returns_two(samples_dir):
    rc = main([sp(samples_dir, "oracle_safe.sql"), "-g", "security",
               "-f", "xml"])
    assert rc == 2


# -- fail-on / Akzeptanzkriterien ----------------------------------------

def test_scan_safe_oracle_returns_zero(samples_dir):
    assert main([sp(samples_dir, "oracle_safe.sql"), "-g", "security"]) == 0


def test_fail_on_critical_oracle_vulnerable(samples_dir):
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"),
               "--fail-on", "critical"])
    assert rc == 1


def test_fail_on_critical_oracle_safe(samples_dir):
    rc = main([sp(samples_dir, "oracle_safe.sql"), "--fail-on", "critical"])
    assert rc == 0


def test_fail_on_critical_postgres_vulnerable(samples_dir):
    rc = main([sp(samples_dir, "postgres_vulnerable.sql"),
               "-d", "postgresql", "--fail-on", "critical"])
    assert rc == 1


def test_fail_on_critical_postgres_safe(samples_dir):
    rc = main([sp(samples_dir, "postgres_safe.sql"),
               "-d", "postgresql", "--fail-on", "critical"])
    assert rc == 0


def test_fail_on_critical_dollar_quote_safe(samples_dir):
    rc = main([sp(samples_dir, "postgres_dollar_quote_safe.sql"),
               "-d", "postgresql", "--fail-on", "critical"])
    assert rc == 0


def test_fail_on_critical_dollar_quote_vulnerable(samples_dir):
    rc = main([sp(samples_dir, "postgres_dollar_quote_vulnerable.sql"),
               "-d", "postgresql", "--fail-on", "critical"])
    assert rc == 1


# -- Reportausgabe -------------------------------------------------------

def test_json_report_is_written(samples_dir, tmp_path):
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "-f", "json", "-o", str(tmp_path)])
    assert rc == 0
    report = tmp_path / "aci_report_oracle_vulnerable.json"
    assert report.is_file()
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["summary"]["findings_total"] >= 1


def test_aci_ini_provides_defaults_in_report(samples_dir, tmp_path,
                                             monkeypatch):
    # Eine aci.ini im Arbeitsverzeichnis aendert den Default - der
    # JSON-Report weist verwendeten Wert und Default getrennt aus.
    (tmp_path / "aci.ini").write_text(
        "[defaults]\nfail_on = high\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text(
            encoding="utf-8"))
    assert data["scanner_defaults"]["fail_on"] == "high"
    assert data["scanner_config"]["fail_on"] == "high"


def test_cli_flag_overrides_aci_ini_default(samples_dir, tmp_path,
                                            monkeypatch):
    # Die aci.ini setzt fail_on=high, der CLI-Schalter ueberschreibt es.
    (tmp_path / "aci.ini").write_text(
        "[defaults]\nfail_on = high\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "--fail-on", "critical", "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text(
            encoding="utf-8"))
    assert data["scanner_defaults"]["fail_on"] == "high"
    assert data["scanner_config"]["fail_on"] == "critical"


def test_invalid_aci_ini_returns_two(samples_dir, tmp_path, monkeypatch):
    (tmp_path / "aci.ini").write_text(
        "[defaults]\ndialect = mysql\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security"])
    assert rc == 2


def test_json_report_includes_scan_metrics(samples_dir, tmp_path):
    import re as _re
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "-f", "json", "-o", str(tmp_path)])
    assert rc == 0
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text(
            encoding="utf-8"))
    summary = data["summary"]
    assert summary["scanned_bytes"] > 0
    assert summary["lines_of_code"] > 0
    assert summary["duration_seconds"] is not None
    assert _re.fullmatch(r"\d\d:\d\d:\d\d", summary["duration"])


def test_html_report_is_written(samples_dir, tmp_path):
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "-f", "html", "-o", str(tmp_path)])
    assert rc == 0
    report = tmp_path / "aci_report_oracle_vulnerable.html"
    assert report.is_file()
    assert "<html" in report.read_text(encoding="utf-8").lower()


def test_sarif_report_is_written(samples_dir, tmp_path):
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "-f", "sarif", "-o", str(tmp_path)])
    assert rc == 0
    report = tmp_path / "aci_report_oracle_vulnerable.sarif"
    assert report.is_file()
    data = json.loads(report.read_text(encoding="utf-8"))
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["tool"]["driver"]["name"] == "ACI"
    assert data["runs"][0]["results"]


def test_scan_directory(samples_dir):
    assert main([samples_dir, "-g", "security"]) == 0


def test_guidelines_available_for_postgres(samples_dir):
    # Seit ACI 2.1 hat auch PostgreSQL eigene PL/pgSQL-Coding-Guidelines.
    rc = main([sp(samples_dir, "postgres_safe.sql"),
               "-d", "postgresql", "-g", "guidelines"])
    assert rc == 0


# -- Report-Kontext ------------------------------------------------------

def _json_findings(tmp_path, base):
    data = json.loads((tmp_path / f"aci_report_{base}.json")
                      .read_text(encoding="utf-8"))
    return [f for fb in data["files"] for f in fb["findings"]]


def test_default_report_contains_context(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path)])
    findings = _json_findings(tmp_path, "oracle_vulnerable")
    assert any(f["context"] for f in findings)


def test_no_context_removes_code(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path), "--no-context"])
    findings = _json_findings(tmp_path, "oracle_vulnerable")
    assert findings
    for f in findings:
        assert f["context"] == []
        assert f["snippet"] == ""


def test_context_lines_zero_equals_no_context(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path), "--context-lines", "0"])
    findings = _json_findings(tmp_path, "oracle_vulnerable")
    assert findings
    assert all(f["context"] == [] for f in findings)


def test_redact_text_masks_password_assignment():
    assert "topsecret" not in _redact_text("password := 'topsecret';")
    assert "<redacted>" in _redact_text("password := 'topsecret';")


def test_redact_text_masks_identified_by():
    out = _redact_text("CREATE USER x IDENTIFIED BY hunter2;")
    assert "hunter2" not in out and "<redacted>" in out


def test_redact_text_masks_bearer_token():
    out = _redact_text("auth := 'Bearer abc123def456ghi';")
    assert "abc123def456ghi" not in out


def test_redact_text_masks_connection_string_password():
    out = _redact_text("conn := 'host=db password=geheim dbname=p';")
    assert "geheim" not in out


def test_redact_text_keeps_normal_code():
    code = "l_count := l_count + 1;"
    assert _redact_text(code) == code


def test_redact_text_masks_secret_in_concatenation():
    # A2-Regression: Geheimnis per || an das Schlüsselwort angehängt
    # (typisch in dynamischem SQL).
    out = _redact_text(
        "v := 'CREATE USER ' || u || ' IDENTIFIED BY ' || 'SuperSecret123';")
    assert "SuperSecret123" not in out and "<redacted>" in out


def test_redact_text_masks_secret_with_doubled_quote_escape():
    # A2-Regression: in dynamisches SQL eingebettetes Literal mit
    # ''-Escapes (password => ''geheim'').
    out = _redact_text("dbms_x.set( password => ''TopSecretValue'' );")
    assert "TopSecretValue" not in out and "<redacted>" in out


def test_redact_text_masks_postgres_password_keyword():
    # Regression: PostgreSQL/EPAS 'PASSWORD ''wert''' (Schluesselwort +
    # Whitespace, KEIN Operator) wurde trotz --redact-secrets nicht maskiert.
    out = _redact_text(
        "CREATE USER superman_2025 WITH PASSWORD 'X34290upa' SUPERUSER;")
    assert "X34290upa" not in out and "<redacted>" in out


def test_redact_text_masks_encrypted_password():
    out = _redact_text("CREATE ROLE r LOGIN ENCRYPTED PASSWORD 'AnotherSecret';")
    assert "AnotherSecret" not in out and "<redacted>" in out


def test_redact_text_masks_unencrypted_password():
    out = _redact_text("ALTER ROLE r UNENCRYPTED PASSWORD 'ThirdSecret';")
    assert "ThirdSecret" not in out and "<redacted>" in out


def test_redact_text_masks_fdw_password_option():
    out = _redact_text("CREATE USER MAPPING ... OPTIONS (password 'remoteSecret');")
    assert "remoteSecret" not in out and "<redacted>" in out


def test_redact_text_password_keyword_does_not_overredact_select():
    # 'PASSWORD' als Spaltenname ohne quotiertes Literal darf NICHT maskieren
    # (sonst wuerde z.B. FROM verschluckt).
    code = "SELECT password FROM users WHERE id = 1;"
    assert _redact_text(code) == code


# -- F5: Pfadmaskierung ---------------------------------------------------

def test_redact_path_unix_absolute():
    assert _redact_path("/home/alex/customer/project/a.sql") == "<PATH>/a.sql"


def test_redact_path_windows_absolute():
    assert _redact_path("C:\\Users\\alex\\project\\a.sql") == "<PATH>\\a.sql"


def test_redact_path_unc():
    assert _redact_path("\\\\server\\share\\project\\a.sql") == "<PATH>\\a.sql"


def test_redact_path_unc_forward():
    assert _redact_path("//server/share/a.sql") == "<PATH>/a.sql"


def test_redact_path_relative_is_unchanged():
    assert _redact_path("sql/a.sql") == "sql/a.sql"
    assert _redact_path("a.sql") == "a.sql"


def test_redact_command_line_masks_absolute_tokens():
    cl = "aci /home/alex/p/a.sql -o /tmp/out -d postgresql"
    out = _redact_command_line(cl)
    assert "/home/alex" not in out and "/tmp/out" not in out
    assert "<PATH>/a.sql" in out and "<PATH>/out" in out
    assert "-d postgresql" in out


def _scan_json(tmp_path, extra):
    src = tmp_path / "deploy.sql"
    src.write_text("CREATE USER u WITH PASSWORD 'PWLeakZ' SUPERUSER;\n",
                   encoding="utf-8")
    out = tmp_path / "out"
    rc = main([str(src), "-d", "postgresql", "-g", "security",
               "-f", "json", "-o", str(out)] + extra)
    report = out / f"aci_report_{src.stem}.json"
    return rc, report.read_text(encoding="utf-8")


def test_redact_paths_removes_absolute_unix_paths(tmp_path):
    _rc, raw = _scan_json(tmp_path, ["--redact-paths"])
    assert str(tmp_path) not in raw
    assert "<PATH>" in raw


def test_safe_report_implies_path_redaction(tmp_path):
    _rc, raw = _scan_json(tmp_path, ["--safe-report"])
    assert str(tmp_path) not in raw


def test_without_redact_paths_absolute_path_is_present(tmp_path):
    # Standardverhalten unveraendert: ohne Flag bleibt der Pfad sichtbar.
    _rc, raw = _scan_json(tmp_path, ["--redact-secrets"])
    assert str(tmp_path) in raw


def test_redact_results_masks_related_taint_source():
    # A1-Regression: Geheimnisse in den Taint-Quellen (related) muessen
    # ebenso redigiert werden wie im Fundort selbst.
    from aci.finding import (Finding, RelatedLocation, Severity,
                             GROUP_SECURITY)
    line = "l_sql := 'x'; password := 'TopSecret';"
    rel = RelatedLocation(label="Taint-Quelle", file="t.sql", line=4,
                          snippet=line, context=[(4, line, True)])
    f = Finding(check_id="ACI-SQLI", check_name="SQLI", group=GROUP_SECURITY,
                severity=Severity.CRITICAL, file="t.sql", line=5, column=3,
                message="m", snippet=line, context=[(5, line, True)],
                related=[rel])
    _redact_results({"t.sql": [f]})
    assert "TopSecret" not in f.related[0].snippet
    assert "TopSecret" not in f.related[0].context[0][1]


def test_redact_secrets_masks_passwords(tmp_path):
    src = tmp_path / "with_secret.sql"
    src.write_text(
        "DECLARE\n"
        "  password VARCHAR2(100);\n"
        "BEGIN\n"
        "  password := 'topsecret';\n"
        "  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\n"
        "END;\n",
        encoding="utf-8")
    rc = main([str(src), "-g", "security", "-f", "json",
               "-o", str(tmp_path), "--redact-secrets"])
    assert rc == 0
    raw = (tmp_path / "aci_report_with_secret.json").read_text(
        encoding="utf-8")
    assert "topsecret" not in raw
    assert "<redacted>" in raw


# -- Report-Sicherheit: Warnung, --safe-report, scanner_config -----------

def test_json_report_warns_without_redaction(samples_dir, tmp_path, capsys):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path)])
    assert "Warnung" in capsys.readouterr().err


def test_no_context_suppresses_report_warning(samples_dir, tmp_path, capsys):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path), "--no-context"])
    assert "Warnung" not in capsys.readouterr().err


def test_console_format_does_not_warn(samples_dir, capsys):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security"])
    assert "Warnung" not in capsys.readouterr().err


def test_safe_report_disables_context_and_suppresses_warning(
        samples_dir, tmp_path, capsys):
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "-f", "json", "-o", str(tmp_path), "--safe-report"])
    assert rc == 0
    assert "Warnung" not in capsys.readouterr().err
    data = json.loads((tmp_path / "aci_report_oracle_vulnerable.json")
                      .read_text(encoding="utf-8"))
    findings = [f for fb in data["files"] for f in fb["findings"]]
    assert findings and all(f["context"] == [] for f in findings)


def test_json_report_contains_scanner_config(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path), "--no-context",
          "--fail-on", "high"])
    data = json.loads((tmp_path / "aci_report_oracle_vulnerable.json")
                      .read_text(encoding="utf-8"))
    cfg = data["scanner_config"]
    assert cfg["dialect"] == "oracle"
    assert cfg["group"] == "security"
    assert cfg["fail_on"] == "high"
    assert cfg["no_context"] is True
    assert "redact_secrets" in cfg and "follow_symlinks" in cfg
    assert cfg["html_group_by"] in ("rule", "file")


def test_scanner_config_shows_effective_safe_report_values(samples_dir,
                                                           tmp_path):
    # --safe-report aktiviert no_context und redact_secrets implizit; der
    # Report muss die *effektiven* Werte zeigen, nicht die rohen Schalter.
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path), "--safe-report"])
    cfg = json.loads((tmp_path / "aci_report_oracle_vulnerable.json")
                     .read_text(encoding="utf-8"))["scanner_config"]
    assert cfg["no_context"] is True
    assert cfg["redact_secrets"] is True
    assert cfg["safe_report"] is True
    # Die strengen CI-Schalter sind ebenfalls Teil der Konfiguration.
    assert "strict_internal_errors" in cfg
    assert "require_trusted_rules" in cfg


# -- CI/CD-Profile -------------------------------------------------------

def test_profile_ci_blocks_vulnerable(samples_dir):
    # Profil "ci" setzt --fail-on high -> verwundbare Datei blockt.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"),
                 "--profile", "ci"]) == 1


def test_profile_advisory_never_blocks(samples_dir):
    # Profil "advisory" setzt --fail-on none -> blockiert nie.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"),
                 "--profile", "advisory"]) == 0


def test_explicit_flag_overrides_profile(samples_dir):
    # Ein ausdrücklich gesetzter Schalter hat Vorrang vor dem Profil.
    assert main([sp(samples_dir, "oracle_vulnerable.sql"),
                 "--profile", "ci", "--fail-on", "none"]) == 0


def test_invalid_profile_exits_two(samples_dir):
    with pytest.raises(SystemExit) as exc:
        main([sp(samples_dir, "oracle_vulnerable.sql"), "--profile", "xyz"])
    assert exc.value.code == 2


def test_profile_appears_in_scanner_config(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "--profile", "ci",
          "-f", "json", "-o", str(tmp_path)])
    cfg = json.loads((tmp_path / "aci_report_oracle_vulnerable.json")
                     .read_text(encoding="utf-8"))["scanner_config"]
    assert cfg["profile"] == "ci"
    # Das Profil hat die Voreinstellungen gesetzt.
    assert cfg["group"] == "security"
    assert cfg["fail_on"] == "high"
    assert cfg["safe_report"] is True


def test_html_report_shows_scan_parameters(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "html", "-o", str(tmp_path), "--safe-report"])
    html = (tmp_path / "aci_report_oracle_vulnerable.html").read_text(
        encoding="utf-8")
    assert "Scan-Details:" in html
    assert "Scan-Parameter:" in html


def test_html_group_by_file_option(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "html", "-o", str(tmp_path), "--html-group-by", "file"])
    html = (tmp_path / "aci_report_oracle_vulnerable.html").read_text(
        encoding="utf-8")
    assert '<h3 class="file">' in html


def test_html_group_by_rule_is_default(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "html", "-o", str(tmp_path)])
    html = (tmp_path / "aci_report_oracle_vulnerable.html").read_text(
        encoding="utf-8")
    assert '<h3 class="rule">' in html
