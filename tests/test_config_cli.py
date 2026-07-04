"""Tests fuer explizite Config-Steuerung (--config/--no-config/
--print-effective-config) und boolesche Negativ-Flags (TODO 2 + 4)."""

import json

from aci.cli import main


def _effective(capsys, argv):
    rc = main(argv)
    out = capsys.readouterr().out
    return rc, json.loads(out)["config"]


# -- TODO 2: Config-Steuerung -------------------------------------------

def test_no_config_disables_config(capsys):
    rc, cfg = _effective(capsys, ["--no-config", "--print-effective-config"])
    assert rc == 0
    assert cfg["mode"] == "disabled" and cfg["file"] is None


def test_auto_config_reports_file(capsys):
    rc, cfg = _effective(capsys, ["--print-effective-config"])
    assert rc == 0 and cfg["mode"] == "auto"  # gebuendelte aci.ini wird gefunden


def test_explicit_config_loads_only_given_file(tmp_path, capsys):
    ini = tmp_path / "my.ini"
    ini.write_text("[defaults]\nfail_on = high\n", encoding="utf-8")
    rc, cfg = _effective(
        capsys, ["--config", str(ini), "--print-effective-config"])
    assert rc == 0
    assert cfg["mode"] == "explicit" and cfg["file"] == str(ini)
    assert cfg["effective"]["fail_on"] == "high"


def test_missing_explicit_config_exits_2(tmp_path):
    assert main(["--config", str(tmp_path / "nope.ini"),
                 str(tmp_path / "x.sql")]) == 2


def test_config_and_no_config_conflict_exits_2(tmp_path):
    ini = tmp_path / "my.ini"
    ini.write_text("[defaults]\n", encoding="utf-8")
    assert main(["--config", str(ini), "--no-config",
                 str(tmp_path / "x.sql")]) == 2


def test_report_contains_config_block(tmp_path):
    src = tmp_path / "a.sql"
    src.write_text("select 1 from dual;\n", encoding="utf-8")
    main([str(src), "-d", "oracle", "-g", "security", "-f", "json",
          "-o", str(tmp_path), "--no-context", "--no-config"])
    report = json.loads(
        (tmp_path / "aci_report_a.json").read_text(encoding="utf-8"))
    assert report["config"]["mode"] == "disabled"
    assert report["config"]["file"] is None


# -- TODO 4: boolesche Negativ-Flags + Praezedenz -----------------------

def test_profile_strict_sets_strict_waivers(capsys):
    _rc, cfg = _effective(
        capsys, ["--profile", "strict", "--print-effective-config"])
    assert cfg["effective"]["strict_waivers"] is True


def test_no_strict_waivers_overrides_profile(capsys):
    _rc, cfg = _effective(
        capsys, ["--profile", "strict", "--no-strict-waivers",
                 "--print-effective-config"])
    assert cfg["effective"]["strict_waivers"] is False


# -- L2: effektive Safe-Report-Werte in --print-effective-config --------

def test_effective_config_profile_ci_shows_bundled_safe_values(capsys):
    # --profile ci aktiviert safe_report -> no_context/redact_secrets/
    # redact_paths effektiv true (statt roher argparse-Defaults).
    _rc, cfg = _effective(
        capsys, ["--profile", "ci", "--print-effective-config"])
    eff = cfg["effective"]
    assert eff["safe_report"] is True
    assert eff["no_context"] is True
    assert eff["redact_secrets"] is True
    assert eff["redact_paths"] is True


def test_effective_config_profile_strict_shows_bundled_safe_values(capsys):
    _rc, cfg = _effective(
        capsys, ["--profile", "strict", "--print-effective-config"])
    eff = cfg["effective"]
    assert (eff["no_context"], eff["redact_secrets"], eff["redact_paths"]) \
        == (True, True, True)


def test_effective_config_unsafe_report_disables_bundle(capsys):
    # --unsafe-report hebt safe_report (und damit das Bündel) auf.
    _rc, cfg = _effective(
        capsys, ["--profile", "ci", "--unsafe-report",
                 "--print-effective-config"])
    eff = cfg["effective"]
    assert eff["safe_report"] is False
    assert eff["no_context"] is False
    assert eff["redact_secrets"] is False
    assert eff["redact_paths"] is False


def test_effective_config_context_does_not_unbundle_safe_report(capsys):
    # --context allein hebt ein aktives safe_report NICHT auf (nur
    # --unsafe-report tut das) - effektiv bleibt no_context true, wie auch
    # der echte Report es anwendet.
    _rc, cfg = _effective(
        capsys, ["--profile", "ci", "--context", "--print-effective-config"])
    assert cfg["effective"]["no_context"] is True


def test_effective_config_no_redact_paths_does_not_unbundle_safe_report(capsys):
    _rc, cfg = _effective(
        capsys, ["--profile", "ci", "--no-redact-paths",
                 "--print-effective-config"])
    # safe_report (Profil) erzwingt weiterhin Pfadmaskierung.
    assert cfg["effective"]["redact_paths"] is True


def test_effective_config_context_lines_zero_implies_no_context(capsys):
    _rc, cfg = _effective(
        capsys, ["--context-lines", "0", "--print-effective-config"])
    assert cfg["effective"]["no_context"] is True


def test_effective_config_plain_run_keeps_defaults(capsys):
    # Ohne Profil/safe-report bleiben die Schalter false.
    _rc, cfg = _effective(capsys, ["--print-effective-config"])
    eff = cfg["effective"]
    assert eff["safe_report"] is False
    assert eff["redact_paths"] is False
    assert eff["redact_secrets"] is False


def test_config_true_overridden_by_cli_false(tmp_path, capsys):
    ini = tmp_path / "my.ini"
    ini.write_text("[defaults]\nfollow_symlinks = true\n", encoding="utf-8")
    _rc, cfg = _effective(
        capsys, ["--config", str(ini), "--no-follow-symlinks",
                 "--print-effective-config"])
    assert cfg["effective"]["follow_symlinks"] is False


def test_config_false_overridden_by_cli_true(tmp_path, capsys):
    ini = tmp_path / "my.ini"
    ini.write_text("[defaults]\nstrict_internal_errors = false\n",
                   encoding="utf-8")
    _rc, cfg = _effective(
        capsys, ["--config", str(ini), "--strict-internal-errors",
                 "--print-effective-config"])
    assert cfg["effective"]["strict_internal_errors"] is True


def test_unsafe_report_overrides_profile_safe(capsys):
    _rc, cfg = _effective(
        capsys, ["--profile", "ci", "--unsafe-report",
                 "--print-effective-config"])
    assert cfg["effective"]["safe_report"] is False


def test_context_overrides_no_context(tmp_path, capsys):
    ini = tmp_path / "my.ini"
    ini.write_text("[defaults]\nno_context = true\n", encoding="utf-8")
    _rc, cfg = _effective(
        capsys, ["--config", str(ini), "--context",
                 "--print-effective-config"])
    assert cfg["effective"]["no_context"] is False


def test_legacy_positive_flags_still_work(capsys):
    # Bestehende positive Flags duerfen weiter funktionieren.
    _rc, cfg = _effective(
        capsys, ["--strict-waivers", "--safe-report",
                 "--print-effective-config"])
    assert cfg["effective"]["strict_waivers"] is True
    assert cfg["effective"]["safe_report"] is True


def test_help_lists_negative_options(capsys):
    import pytest
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for opt in ("--no-strict-waivers", "--no-require-trusted-rules",
                "--unsafe-report", "--no-redact-secrets", "--context",
                "--no-follow-symlinks", "--no-config",
                "--print-effective-config"):
        assert opt in out
