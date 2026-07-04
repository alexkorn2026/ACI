"""F7: Harte Report-Leakage-Tests.

Stellt sicher, dass mit ``--redact-secrets`` (bzw. ``--safe-report``) KEIN
Geheimnis in einem der erzeugten Report-Artefakte (JSON, SARIF, HTML,
Console) auftaucht - in keinem Feld (snippet, context, message, properties).
Die Tests sind formatunabhaengig: sie durchsuchen die rohe Ausgabe per
Volltext. Schlaegt die Redaction irgendwo zurueck, schlagen diese Tests fehl.

Zusaetzlich (Finding 5): unter ``--safe-report`` duerfen keine absoluten
Pfade im Report stehen.
"""

import json

import pytest

from aci.cli import main


# Eindeutige Testsecrets - duerfen in keinem Report vorkommen.
_PG_SECRETS = ["SecretPgUser1", "SecretPgRole2", "SecretPgRole3",
               "SecQuoteSecret", "SecretGeneric5"]
_PG_SCRIPT = (
    "CREATE USER u1 WITH PASSWORD 'SecretPgUser1' SUPERUSER;\n"
    "CREATE ROLE r1 LOGIN ENCRYPTED PASSWORD 'SecretPgRole2';\n"
    "ALTER ROLE r1 UNENCRYPTED PASSWORD 'SecretPgRole3';\n"
    "ALTER ROLE r1 PASSWORD 'Sec''QuoteSecret';\n"
    "CREATE FUNCTION f() RETURNS void AS $$ BEGIN\n"
    "  PERFORM 'password = ''SecretGeneric5''';\nEND; $$ LANGUAGE plpgsql;\n"
)

_ORA_SECRETS = ["SecretOracle4", "SecretGeneric5"]
_ORA_SCRIPT = (
    "CREATE USER oracle_style IDENTIFIED BY SecretOracle4;\n"
    "v_x := 'password = ''SecretGeneric5''';\n"
)

_FLAG_COMBOS = [
    ["--redact-secrets"],
    ["--safe-report"],
    ["--safe-report", "--redact-secrets"],
]
_FILE_FORMATS = ["json", "sarif", "html"]


def _run(tmp_path, dialect, script, flags, fmt):
    src = tmp_path / "deploy.sql"
    src.write_text(script, encoding="utf-8")
    out = tmp_path / "out"
    main([str(src), "-d", dialect, "-g", "all", "-f", fmt, "-o", str(out)]
         + flags)
    return (out / f"aci_report_{src.stem}.{fmt}").read_text(encoding="utf-8")


@pytest.mark.parametrize("dialect,script,secrets", [
    ("postgresql", _PG_SCRIPT, _PG_SECRETS),
    ("oracle", _ORA_SCRIPT, _ORA_SECRETS),
])
@pytest.mark.parametrize("flags", _FLAG_COMBOS)
@pytest.mark.parametrize("fmt", _FILE_FORMATS)
def test_no_secret_leaks_in_file_report(tmp_path, dialect, script, secrets,
                                        flags, fmt):
    raw = _run(tmp_path, dialect, script, flags, fmt)
    for secret in secrets:
        assert secret not in raw, (
            f"Secret {secret!r} leaked in {fmt} report "
            f"(dialect={dialect}, flags={flags})")
    # Marker nur pruefen, wenn Kontext ueberhaupt im Report steht:
    # --safe-report impliziert --no-context, dann gibt es keinen Snippet
    # (und damit auch keinen Redaction-Marker) - das Fehlen des Secrets ist
    # dort bereits der Beweis.
    if "--safe-report" not in flags:
        assert "<redacted>" in raw or "&lt;redacted&gt;" in raw


@pytest.mark.parametrize("flags", _FLAG_COMBOS)
def test_findings_and_rule_ids_remain_visible(tmp_path, flags):
    raw = _run(tmp_path, "postgresql", _PG_SCRIPT, flags, "json")
    data = json.loads(raw)
    all_ids = {f["check_id"]
               for fb in data["files"] for f in fb["findings"]}
    # Trotz Redaction bleiben Findings + Rule-IDs sichtbar.
    assert all_ids
    assert any(i.startswith("T1552") or i == "ACI-DDL"
               or i.startswith("ACI-PG") for i in all_ids)


@pytest.mark.parametrize("fmt", _FILE_FORMATS)
def test_safe_report_has_no_absolute_paths(tmp_path, fmt):
    raw = _run(tmp_path, "postgresql", _PG_SCRIPT, ["--safe-report"], fmt)
    # Der absolute Pfad des Scan-Ziels darf nicht im Report stehen.
    assert str(tmp_path) not in raw


def test_no_secret_leaks_in_console(tmp_path, capsys):
    src = tmp_path / "deploy.sql"
    src.write_text(_PG_SCRIPT, encoding="utf-8")
    main([str(src), "-d", "postgresql", "-g", "all", "-f", "console",
          "--redact-secrets"])
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    for secret in _PG_SECRETS:
        assert secret not in combined


def test_password_null_is_not_redacted_as_secret():
    # PASSWORD NULL ist kein Geheimnis -> kein <redacted>.
    from aci.cli import _redact_text
    out = _redact_text("ALTER ROLE r PASSWORD NULL;")
    assert out == "ALTER ROLE r PASSWORD NULL;"
