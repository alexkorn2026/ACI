"""Tests für die Regelintegrität (aci.integrity).

Geprüft werden der Vertrauensstatus einzelner Pfade
(:func:`is_trusted_path`), die Berechnung des Ruleset-Hashes
(:func:`compute_ruleset_integrity`) sowie die CLI-Anbindung
(``--require-trusted-rules``, Report-Ausgabe).
"""

import json
import os
import shutil

from aci.integrity import (is_trusted_path, compute_ruleset_integrity,
                           RulesetIntegrity)
from aci.cli import main


def sp(samples_dir, name):
    return os.path.join(samples_dir, name)


# ----------------------------------------------------------------------
# is_trusted_path
# ----------------------------------------------------------------------

def test_bundled_rule_file_is_trusted(rules_dir):
    assert is_trusted_path(os.path.join(rules_dir, "oracle.json")) is True


def test_external_path_is_untrusted(tmp_path):
    p = tmp_path / "oracle.json"
    p.write_text("{}", encoding="utf-8")
    assert is_trusted_path(str(p)) is False


def test_trusted_path_resolves_relative(rules_dir):
    # Auch ein relativer/symlink-behafteter Pfad wird korrekt aufgelöst.
    nested = os.path.join(rules_dir, "..", "rules", "postgresql.json")
    assert is_trusted_path(nested) is True


# ----------------------------------------------------------------------
# compute_ruleset_integrity
# ----------------------------------------------------------------------

def test_integrity_of_bundled_files_is_trusted(rules_dir):
    files = [("security", os.path.join(rules_dir, "oracle.json")),
             ("security", os.path.join(rules_dir, "postgresql.json"))]
    intg = compute_ruleset_integrity(files)
    assert isinstance(intg, RulesetIntegrity)
    assert intg.trusted is True
    assert intg.untrusted_files == []
    assert len(intg.ruleset_hash) == 64
    assert all(len(f.sha256) == 64 for f in intg.files)


def test_integrity_hash_is_order_independent(rules_dir):
    a = [("security", os.path.join(rules_dir, "oracle.json")),
         ("security", os.path.join(rules_dir, "postgresql.json"))]
    b = list(reversed(a))
    assert (compute_ruleset_integrity(a).ruleset_hash ==
            compute_ruleset_integrity(b).ruleset_hash)


def test_integrity_hash_changes_with_content(rules_dir, tmp_path):
    orig = os.path.join(rules_dir, "oracle.json")
    base = compute_ruleset_integrity([("security", orig)]).ruleset_hash
    altered = tmp_path / "oracle.json"
    data = json.loads((open(orig, encoding="utf-8")).read())
    data["description"] = "geändert"
    altered.write_text(json.dumps(data), encoding="utf-8")
    changed = compute_ruleset_integrity(
        [("security", str(altered))]).ruleset_hash
    assert base != changed


def test_integrity_detects_untrusted_file(rules_dir, tmp_path):
    custom = tmp_path / "oracle.json"
    shutil.copy(os.path.join(rules_dir, "oracle.json"), custom)
    intg = compute_ruleset_integrity([("security", str(custom))])
    assert intg.trusted is False
    assert len(intg.untrusted_files) == 1
    assert intg.untrusted_files[0].name == "oracle.json"


def test_integrity_unreadable_file_has_empty_hash(tmp_path):
    intg = compute_ruleset_integrity(
        [("security", str(tmp_path / "fehlt.json"))])
    assert intg.files[0].sha256 == ""


def test_integrity_to_dict(rules_dir):
    intg = compute_ruleset_integrity(
        [("security", os.path.join(rules_dir, "oracle.json"))])
    d = intg.to_dict()
    assert set(d) == {"ruleset_hash", "trusted", "files"}
    assert d["files"][0]["category"] == "security"


# ----------------------------------------------------------------------
# CLI-Anbindung
# ----------------------------------------------------------------------

def test_cli_json_report_has_integrity(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text("utf-8"))
    intg = data["ruleset"]["integrity"]
    assert intg is not None
    assert intg["trusted"] is True
    assert len(intg["ruleset_hash"]) == 64


def test_cli_sarif_run_has_ruleset_hash(samples_dir, tmp_path):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "-f", "sarif", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.sarif").read_text("utf-8"))
    props = data["runs"][0]["properties"]
    assert len(props["aci_ruleset_hash"]) == 64
    assert props["aci_ruleset_trusted"] is True


def test_cli_console_shows_ruleset_hash(samples_dir, capsys):
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security"])
    out = capsys.readouterr().out
    assert "Regeln  :" in out
    assert "vertrauenswürdig" in out


def test_cli_custom_rules_are_untrusted(samples_dir, tmp_path, capsys):
    custom = tmp_path / "oracle.json"
    pkg_dir = os.path.dirname(os.path.abspath(__import__("aci").__file__))
    shutil.copy(os.path.join(pkg_dir, "rules", "oracle.json"), custom)
    main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
          "--rules", str(custom), "-f", "json", "-o", str(tmp_path)])
    data = json.loads(
        (tmp_path / "aci_report_oracle_vulnerable.json").read_text("utf-8"))
    assert data["ruleset"]["integrity"]["trusted"] is False
    assert "untrusted" in capsys.readouterr().err


def test_cli_require_trusted_rules_blocks_custom(samples_dir, tmp_path):
    custom = tmp_path / "oracle.json"
    pkg_dir = os.path.dirname(os.path.abspath(__import__("aci").__file__))
    shutil.copy(os.path.join(pkg_dir, "rules", "oracle.json"), custom)
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "--rules", str(custom), "--require-trusted-rules"])
    assert rc == 2


def test_cli_require_trusted_rules_passes_for_bundled(samples_dir):
    # Gebündelte Regeln -> --require-trusted-rules blockiert nicht.
    rc = main([sp(samples_dir, "oracle_safe.sql"), "-g", "security",
               "--require-trusted-rules"])
    assert rc == 0


def test_cli_aci_ini_provides_require_trusted_rules(samples_dir, tmp_path,
                                                    monkeypatch):
    (tmp_path / "aci.ini").write_text(
        "[defaults]\nrequire_trusted_rules = true\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    custom = tmp_path / "oracle.json"
    pkg_dir = os.path.dirname(os.path.abspath(__import__("aci").__file__))
    shutil.copy(os.path.join(pkg_dir, "rules", "oracle.json"), custom)
    rc = main([sp(samples_dir, "oracle_vulnerable.sql"), "-g", "security",
               "--rules", str(custom)])
    assert rc == 2
