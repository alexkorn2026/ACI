"""Tests fuer die Scan-Kennzahlen im Report.

Geprueft werden die gescannte Datenmenge (Bytes/KB), die gezaehlten
Codezeilen (LOC) und die Laufzeit - sowohl die Erfassung im Scanner als
auch die Darstellung in Konsolen-, JSON- und HTML-Report.
"""

import json

from aci.scanner import Scanner, _count_lines
from aci.reporting import (ScanReport, render_console, render_json,
                           render_html)
from aci.finding import GROUP_SECURITY


# -- LOC-Zaehlung ---------------------------------------------------------

def test_count_lines_empty_is_zero():
    assert _count_lines("") == 0


def test_count_lines_counts_trailing_newline_once():
    assert _count_lines("a\nb\nc\n") == 3


def test_count_lines_counts_line_without_newline():
    assert _count_lines("a\nb\nc") == 3
    assert _count_lines("abc") == 1


# -- Scanner erfasst Bytes und LOC ---------------------------------------

def test_scanner_tracks_bytes_and_loc(oracle_rules, tmp_path):
    f1 = tmp_path / "a.sql"
    f1.write_text("BEGIN\n  NULL;\nEND;\n", encoding="utf-8")
    f2 = tmp_path / "b.sql"
    f2.write_text("SELECT 1;\nSELECT 2;\n", encoding="utf-8")
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    scanner.scan_path(str(tmp_path))
    assert scanner.scanned_loc == 5      # 3 + 2 Zeilen
    assert scanner.scanned_bytes == (len(f1.read_bytes())
                                     + len(f2.read_bytes()))


def test_scanner_metrics_reset_between_scans(oracle_rules, tmp_path):
    f = tmp_path / "a.sql"
    f.write_text("BEGIN\n  NULL;\nEND;\n", encoding="utf-8")
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    scanner.scan_path(str(f))
    first_loc, first_bytes = scanner.scanned_loc, scanner.scanned_bytes
    scanner.scan_path(str(f))            # zweiter Lauf - kein Aufaddieren
    assert scanner.scanned_loc == first_loc
    assert scanner.scanned_bytes == first_bytes


# -- ScanReport-Hilfsmethoden --------------------------------------------

def _metrics_report(oracle_rules):
    return ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                      active_groups={GROUP_SECURITY},
                      scanned_bytes=239616, scanned_loc=45700,
                      duration=143.0)


def test_scanned_kb_rounds_to_nearest(oracle_rules):
    report = _metrics_report(oracle_rules)
    assert report.scanned_kb() == 234    # 239616 Bytes -> 234 KB
    assert report.loc() == 45700


def test_duration_str_formats_mm_ss_hh(oracle_rules):
    assert ScanReport({}, oracle_rules, "x",
                      duration=143.0).duration_str() == "02:23:00"
    assert ScanReport({}, oracle_rules, "x",
                      duration=2.23).duration_str() == "00:02:23"


def test_duration_str_without_measurement_is_dash(oracle_rules):
    assert ScanReport({}, oracle_rules, "x",
                      duration=None).duration_str() == "-"


# -- Darstellung in den drei Reportformaten ------------------------------

def test_console_shows_scan_metrics(oracle_rules):
    text = render_console(_metrics_report(oracle_rules), use_color=False)
    assert "Gescannt" in text
    assert "234 KB" in text
    assert "45.700 LOC" in text
    assert "Laufzeit" in text and "02:23:00" in text


def test_json_summary_has_scan_metrics(oracle_rules):
    data = json.loads(render_json(_metrics_report(oracle_rules)))
    summary = data["summary"]
    assert summary["scanned_bytes"] == 239616
    assert summary["scanned_kb"] == 234
    assert summary["lines_of_code"] == 45700
    assert summary["duration"] == "02:23:00"
    assert summary["duration_seconds"] == 143.0


def test_html_meta_shows_scan_metrics(oracle_rules):
    html = render_html(_metrics_report(oracle_rules))
    assert "gescannte KB:" in html
    assert "45.700" in html              # LOC mit Tausenderpunkt
    assert "Laufzeit:" in html and "02:23:00" in html
