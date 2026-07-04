"""M6: Strict-Profil verlangt eine feste Regelsatz-Bindung (Pin/Lock)."""

import json

from aci.cli import main


def _sql(tmp_path):
    p = tmp_path / "a.sql"
    p.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n", encoding="utf-8")
    return p


def test_strict_profile_requires_pinned_ruleset(tmp_path):
    p = _sql(tmp_path)
    # strict ohne Pin/Lock => Exit 2.
    rc = main([str(p), "--profile", "strict"])
    assert rc == 2


def test_require_ruleset_pin_satisfied_by_expected_hash(tmp_path):
    p = _sql(tmp_path)
    # Zuerst den tatsaechlichen Hash aus einem normalen Lauf beziehen.
    out = tmp_path / "out"
    main([str(p), "-f", "json", "-o", str(out), "-g", "security"])
    data = json.loads((out / "aci_report_a.json").read_text("utf-8"))
    actual = data["ruleset"]["integrity"]["ruleset_hash"]
    # Mit korrektem Pin laeuft --require-ruleset-pin durch (kein Exit 2).
    rc = main([str(p), "-g", "security", "--require-ruleset-pin",
               "--expected-ruleset-sha256", actual, "-f", "console"])
    assert rc in (0, 1)   # kein 2 (Gate/Findings egal, nur nicht Pin-Fehler)


def test_require_ruleset_pin_wrong_hash_fails(tmp_path):
    p = _sql(tmp_path)
    rc = main([str(p), "-g", "security", "--require-ruleset-pin",
               "--expected-ruleset-sha256", "0" * 64, "-f", "console"])
    assert rc == 2
