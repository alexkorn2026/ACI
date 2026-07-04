"""M3: Safe-Report maskiert Messages/Exceptions/Konsole und reduziert Plattform."""

import datetime

from aci.finding import Finding, Severity, GROUP_SECURITY, GROUP_INTERNAL
from aci.cli import (_redact_results, _sanitize_internal_messages,
                     _build_runtime, main)


def _finding(msg, rec=""):
    return Finding(check_id="ACI-SQLI", check_name="x", group=GROUP_SECURITY,
                   severity=Severity.CRITICAL, file="t.sql", line=1, column=1,
                   message=msg, recommendation=rec, rule_ref="ACI-SQLI")


def test_safe_report_redacts_message_secret():
    f = _finding("dynamisches SQL: password = 'geheim123'")
    results = {"t.sql": [f]}
    _redact_results(results)
    assert "geheim123" not in f.message
    assert "<redacted>" in f.message


def test_safe_report_redacts_recommendation_secret():
    f = _finding("m", rec="setze token=abcdef12345 im Header")
    results = {"t.sql": [f]}
    _redact_results(results)
    assert "abcdef12345" not in f.recommendation


def test_safe_report_standardizes_internal_exception_message():
    intern = Finding(
        check_id="ACI-INTERNAL", check_name="Interner Fehler (X)",
        group=GROUP_INTERNAL, severity=Severity.HIGH, file="t.sql",
        line=1, column=1,
        message=("Interner Fehler im Check 'X' [ACI-SQLI]: ValueError: "
                 "/home/alex/secret/path.sql kaputt"),
        rule_ref="ACI-SQLI")
    results = {"t.sql": [intern]}
    _sanitize_internal_messages(results)
    # Kein Pfad/Detail mehr, nur standardisierte Kurzform mit Exception-Typ.
    assert "/home/alex" not in intern.message
    assert "ValueError" in intern.message
    assert intern.message.startswith("Interner Fehler im Check")


def test_safe_runtime_reduces_platform():
    now = datetime.datetime.now(datetime.timezone.utc)
    rt = _build_runtime(now, 0.01, want_redact=True)
    # Grobe OS-Familie statt vollem platform.platform() (kein Kernel-Release).
    assert "-" not in rt["platform"] or rt["platform"].count("-") <= 1
    assert rt["executable"] == "<redacted>"
    assert rt["cwd"] == "<redacted>"


def test_safe_console_masks_paths(tmp_path, capsys):
    # Eine zu grosse Datei erzeugt einen Hinweis; --safe-console maskiert Pfad.
    f = tmp_path / "a.sql"
    f.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n" * 3, "utf-8")
    main([str(f), "--max-file-size", "3", "--safe-console", "-g", "security",
          "-f", "console"])
    err = capsys.readouterr().err
    assert "<PATH>" in err
    assert str(tmp_path) not in err
