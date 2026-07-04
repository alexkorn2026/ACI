"""S3/S5: Reproduzierbarer Report und zentrale Dialekt-Normalisierung."""

import json

from aci.cli import main, _normalize_dialect


def _sql(tmp_path):
    p = tmp_path / "a.sql"
    p.write_text("BEGIN EXECUTE IMMEDIATE 'x' || p; END;\n", encoding="utf-8")
    return p


def test_reproducible_report_is_byte_identical(tmp_path):
    p = _sql(tmp_path)
    o1, o2 = tmp_path / "o1", tmp_path / "o2"
    main([str(p), "-f", "json", "-o", str(o1), "-g", "security",
          "--reproducible-report"])
    main([str(p), "-f", "json", "-o", str(o2), "-g", "security",
          "--reproducible-report"])
    t1 = (o1 / "aci_report_a.json").read_text("utf-8")
    t2 = (o2 / "aci_report_a.json").read_text("utf-8")
    # Nach Normalisierung des output-abhaengigen absoluten Ziels identisch.
    assert t1.replace(str(o1), "X") == t2.replace(str(o2), "X")


def test_reproducible_report_has_no_timestamp(tmp_path):
    p = _sql(tmp_path)
    out = tmp_path / "o"
    main([str(p), "-f", "json", "-o", str(out), "-g", "security",
          "--reproducible-report"])
    data = json.loads((out / "aci_report_a.json").read_text("utf-8"))
    assert data["generated"] is None
    assert data["runtime"].get("reproducible") is True


def test_normalize_dialect_alias():
    assert _normalize_dialect("postgres") == "postgresql"
    assert _normalize_dialect("pg") == "postgresql"
    assert _normalize_dialect("POSTGRES") == "postgresql"
    assert _normalize_dialect("oracle") == "oracle"
    assert _normalize_dialect(None) == ""


def test_postgres_alias_normalized_in_report(tmp_path):
    p = tmp_path / "p.sql"
    p.write_text("DO $$ BEGIN EXECUTE 'x' || v; END $$;\n", encoding="utf-8")
    out = tmp_path / "o"
    main([str(p), "--dialect", "postgres", "-f", "json", "-o", str(out),
          "-g", "security"])
    data = json.loads((out / "aci_report_p.json").read_text("utf-8"))
    assert data["dialect"] == "postgresql"
