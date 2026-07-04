"""S3 / Rückwärtskompatibilität: strenge Validierung von Baseline-Dateien."""

import json

import pytest

from collections import Counter

from aci.baseline import load_baseline, BaselineError

FP = "0123456789abcdef"
FP2 = "fedcba9876543210"


def _write(tmp_path, obj):
    p = tmp_path / "bl.json"
    p.write_text(json.dumps(obj), encoding="utf-8")
    return str(p)


# -- gueltige Formate ----------------------------------------------------

def test_v2_dict_findings(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2,
                             "findings": {FP: 2, FP2: 1}})
    assert load_baseline(path) == Counter({FP: 2, FP2: 1})


def test_v2_list_findings(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": [
        {"fingerprint": FP, "count": 3}]})
    assert load_baseline(path) == Counter({FP: 3})


def test_legacy_fingerprint_list_object(tmp_path):
    path = _write(tmp_path, {"fingerprints": [FP, FP2, FP]})
    # doppelte Legacy-Eintraege werden gezaehlt
    assert load_baseline(path) == Counter({FP: 2, FP2: 1})


def test_legacy_bare_list(tmp_path):
    path = _write(tmp_path, [FP, FP2])
    assert load_baseline(path) == Counter({FP: 1, FP2: 1})


def test_fingerprint_case_normalized(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2,
                             "findings": {FP.upper(): 1}})
    assert load_baseline(path) == Counter({FP: 1})


# -- Fehlerfaelle (fail-closed) ------------------------------------------

def test_missing_file(tmp_path):
    with pytest.raises(BaselineError):
        load_baseline(str(tmp_path / "nope.json"))


def test_invalid_json(tmp_path):
    p = tmp_path / "bl.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(str(p))


def test_unknown_future_version_rejected(tmp_path):
    path = _write(tmp_path, {"baseline_version": 99, "findings": {}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_missing_version_and_no_legacy_key(tmp_path):
    path = _write(tmp_path, {"foo": "bar"})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_bad_fingerprint_length(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": {"abc": 1}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_non_hex_fingerprint(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2,
                             "findings": {"zzzzzzzzzzzzzzzz": 1}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_count_zero_rejected(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": {FP: 0}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_count_negative_rejected(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": {FP: -1}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_bool_count_rejected(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": {FP: True}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_version_bool_rejected(tmp_path):
    path = _write(tmp_path, {"baseline_version": True, "findings": {}})
    with pytest.raises(BaselineError):
        load_baseline(path)


def test_findings_wrong_type(tmp_path):
    path = _write(tmp_path, {"baseline_version": 2, "findings": 5})
    with pytest.raises(BaselineError):
        load_baseline(path)
