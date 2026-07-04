"""M2: Baseline mit Multiset-/Counter-Semantik.

Zwei identische Findings (gleicher Fingerabdruck) in einer Datei duerfen
nicht durch ein einzelnes Baseline-Vorkommen gemeinsam unterdrueckt werden.
"""

from collections import Counter

from aci.baseline import (write_baseline, load_baseline, apply_baseline,
                          collect_fingerprints)
from aci.finding import Finding, Severity, GROUP_SECURITY, GROUP_INTERNAL

FP = "0123456789abcdef"
FP2 = "fedcba9876543210"


def _f(fp=FP, check_id="ACI-SQLI", group=GROUP_SECURITY, line=1):
    return Finding(check_id=check_id, check_name="x", group=group,
                   severity=Severity.CRITICAL, file="t.sql", line=line,
                   column=1, message="m", rule_ref="ACI-SQLI", fingerprint=fp)


def test_one_known_one_current_no_new():
    filtered, supp = apply_baseline({"t.sql": [_f()]}, Counter({FP: 1}))
    assert supp == 1
    assert [f for fs in filtered.values() for f in fs] == []


def test_one_known_two_current_one_new():
    filtered, supp = apply_baseline(
        {"t.sql": [_f(line=1), _f(line=5)]}, Counter({FP: 1}))
    assert supp == 1
    remaining = [f for fs in filtered.values() for f in fs]
    assert len(remaining) == 1


def test_two_known_two_current_no_new():
    filtered, supp = apply_baseline(
        {"t.sql": [_f(line=1), _f(line=5)]}, Counter({FP: 2}))
    assert supp == 2
    assert [f for fs in filtered.values() for f in fs] == []


def test_two_known_three_current_one_new():
    filtered, supp = apply_baseline(
        {"t.sql": [_f(line=1), _f(line=5), _f(line=9)]}, Counter({FP: 2}))
    assert supp == 2
    assert len([f for fs in filtered.values() for f in fs]) == 1


def test_internal_never_suppressed_despite_match():
    filtered, supp = apply_baseline(
        {"t.sql": [_f(check_id="ACI-INTERNAL", group=GROUP_INTERNAL)]},
        Counter({FP: 5}))
    assert supp == 0
    assert len(filtered["t.sql"]) == 1


def test_deterministic_across_file_order():
    a = {"b.sql": [_f(line=1)], "a.sql": [_f(line=1)]}
    b = {"a.sql": [_f(line=1)], "b.sql": [_f(line=1)]}
    fa, sa = apply_baseline(a, Counter({FP: 1}))
    fb, sb = apply_baseline(b, Counter({FP: 1}))
    # deterministisch: a.sql (sortiert zuerst) behaelt das unterdrueckte
    assert sa == sb == 1
    assert fa["a.sql"] == [] and fb["a.sql"] == []
    assert len(fa["b.sql"]) == 1 and len(fb["b.sql"]) == 1


def test_collect_fingerprints_counts():
    results = {"a.sql": [_f(fp="aaaaaaaaaaaaaaaa"), _f(fp="bbbbbbbbbbbbbbbb")],
               "c.sql": [_f(fp="aaaaaaaaaaaaaaaa")]}
    c = collect_fingerprints(results)
    assert c == Counter({"aaaaaaaaaaaaaaaa": 2, "bbbbbbbbbbbbbbbb": 1})


def test_write_load_roundtrip_v2(tmp_path):
    results = {"t.sql": [_f(fp=FP, line=1), _f(fp=FP, line=5),
                         _f(fp=FP2, line=9)]}
    path = str(tmp_path / "bl.json")
    n = write_baseline(path, results)
    assert n == 3
    known = load_baseline(path)
    assert known == Counter({FP: 2, FP2: 1})


def test_line_shift_is_baseline_stable(tmp_path):
    # Gleicher Fingerabdruck (kein Zeilenanteil) -> nach Verschiebung bekannt.
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f(fp=FP, line=1)]})
    known = load_baseline(path)
    _filtered, supp = apply_baseline({"t.sql": [_f(fp=FP, line=42)]}, known)
    assert supp == 1


def test_different_fingerprint_is_new(tmp_path):
    path = str(tmp_path / "bl.json")
    write_baseline(path, {"t.sql": [_f(fp=FP)]})
    known = load_baseline(path)
    _filtered, supp = apply_baseline({"t.sql": [_f(fp=FP2)]}, known)
    assert supp == 0
