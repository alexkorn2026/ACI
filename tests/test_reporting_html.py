"""Tests fuer den HTML-Report (aci.reporting.render_html)."""

import aci
from aci.scanner import Scanner
from aci.reporting import ScanReport, render_html
from aci.finding import GROUP_SECURITY

_VULN = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"
_CLEAN = "BEGIN\n  NULL;\nEND;\n"


def _report(code, oracle_rules, report_context=True):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY},
                      report_context=report_context)
    findings = scanner.scan_text(code, "mem.sql")
    return ScanReport({"mem.sql": findings}, oracle_rules, "mem.sql",
                      active_groups={GROUP_SECURITY})


def test_html_is_wellformed(oracle_rules):
    html = render_html(_report(_VULN, oracle_rules))
    assert html.lstrip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "<title>" in html


def test_html_contains_package_version(oracle_rules):
    html = render_html(_report(_VULN, oracle_rules))
    assert aci.__version__ in html


def test_html_renders_findings(oracle_rules):
    html = render_html(_report(_VULN, oracle_rules))
    # Schweregrad-Badge eines kritischen Findings
    assert "badge critical" in html
    assert "ACI-SQLI" in html


def test_html_with_context_shows_code_block(oracle_rules):
    html = render_html(_report(_VULN, oracle_rules))
    assert 'class="snippet' in html


def test_html_no_context_omits_code_block(oracle_rules):
    html = render_html(_report(_VULN, oracle_rules, report_context=False))
    # Ohne Kontext darf kein Quelltext-Block im Report stehen.
    assert 'class="snippet' not in html


def test_html_clean_code_reports_no_findings(oracle_rules):
    html = render_html(_report(_CLEAN, oracle_rules))
    assert "Keine Findings" in html


def test_html_escapes_dangerous_characters(oracle_rules):
    # Ein <script>-Fragment im Code darf nicht ungefiltert im HTML landen.
    code = ("BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || "
            "x_script_tag;\nEND;\n")
    html = render_html(_report(code, oracle_rules))
    assert "<!DOCTYPE html>" in html


# -- Scan-Parameter: Inline-Zeile mit Default-Abgleich -------------------

def test_html_scan_parameter_line_shows_default_on_deviation(oracle_rules):
    config = {"dialect": "oracle", "context_lines": 5}
    defaults = {"dialect": "oracle", "context_lines": 3}
    report = ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        scanner_config=config, scanner_defaults=defaults)
    html = render_html(report)
    assert "Scan-Details:" in html
    assert "Scan-Parameter:" in html
    # context_lines (5) weicht vom Default (3) ab -> Default in Klammern.
    assert "(default: 3)" in html
    assert 'class="cfg-changed"' in html


def test_html_scan_parameter_omits_default_when_value_equals(oracle_rules):
    config = {"dialect": "oracle", "context_lines": 3}
    defaults = {"dialect": "oracle", "context_lines": 3}
    report = ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        scanner_config=config, scanner_defaults=defaults)
    html = render_html(report)
    assert "Scan-Parameter:" in html
    assert "(default:" not in html
    assert 'class="cfg-changed"' not in html


# -- Scan-Aufruf: dritter Block mit dem originalen Kommandozeilenaufruf --

def test_html_scan_aufruf_block_renders_command_line(oracle_rules):
    cmd = "aci samples/vulnerable_oracle.sql --format html -o reports/"
    report = ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        command_line=cmd)
    html = render_html(report)
    assert "Scan-Aufruf:" in html
    assert 'class="meta scancmd"' in html
    # Der Aufruf erscheint als <code>-Block (kein roher Text).
    assert f"<code>{cmd}</code>" in html
    # Reihenfolge: Scan-Details -> Scan-Parameter -> Scan-Aufruf
    i_details = html.index("Scan-Details:")
    i_aufruf = html.index("Scan-Aufruf:")
    assert i_details < i_aufruf


def test_html_scan_aufruf_block_absent_when_command_line_missing(oracle_rules):
    # Ohne command_line darf kein Scan-Aufruf-Block erscheinen
    # (Aufrufe aus Bibliothekscode setzen das Feld nicht).
    report = ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY})
    html = render_html(report)
    assert "Scan-Aufruf:" not in html
    assert 'class="meta scancmd"' not in html


def test_html_scan_aufruf_escapes_html_special_chars(oracle_rules):
    # Argumente mit HTML-Sonderzeichen duerfen nicht ungeescaped im
    # Report landen (XSS-Schutz auch fuer den Aufrufstring).
    cmd = "aci '<script>alert(1)</script>' --format html"
    report = ScanReport({"mem.sql": []}, oracle_rules, "mem.sql",
                        active_groups={GROUP_SECURITY},
                        command_line=cmd)
    html = render_html(report)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# -- Findings-Gruppierung: nach Regel (Default) bzw. nach Datei ----------

_GRP = "BEGIN\n  EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user;\nEND;\n"


def test_html_groups_findings_by_rule_by_default(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    report = ScanReport(
        {"a.sql": scanner.scan_text(_GRP, "a.sql"),
         "b.sql": scanner.scan_text(_GRP, "b.sql")},
        oracle_rules, "x", active_groups={GROUP_SECURITY})
    html = render_html(report)
    assert '<h3 class="rule">' in html      # Abschnitt je Regel
    assert '<th class="file">Datei</th>' in html  # Dateipfad-Spalte je Finding
    assert "a.sql" in html and "b.sql" in html


def test_html_file_column_has_min_width_32ch(oracle_rules):
    # Lange Dateipfade sollen nicht unschoen umgebrochen werden: die
    # Datei-Spalte hat eine Mindestbreite von 32 Zeichen und bricht
    # nur bei tatsaechlichem Ueberlauf - dann graceful (overflow-wrap),
    # nicht mitten im Wort (kein ``word-break:break-all`` mehr auf td.file).
    html = render_html(_report(_VULN, oracle_rules))
    assert "th.file, td.file { min-width:32ch; }" in html
    assert "overflow-wrap:anywhere" in html
    assert "word-break:normal" in html


def test_html_groups_findings_by_file_when_requested(oracle_rules):
    scanner = Scanner(oracle_rules, [], [], groups={GROUP_SECURITY})
    report = ScanReport(
        {"a.sql": scanner.scan_text(_GRP, "a.sql")},
        oracle_rules, "x", active_groups={GROUP_SECURITY},
        html_group_by="file")
    html = render_html(report)
    assert '<h3 class="file">' in html      # Abschnitt je Datei
    assert "<th>Regel</th>" in html
