"""Konsolen-Report - farbiger Textreport für das Terminal."""

from __future__ import annotations

from ..finding import Severity, GROUP_SCALES
from .report import ScanReport
from ._common import _thousands


_ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    Severity.BLOCKER: "\033[1;97;41m",   # weiß auf rot
    Severity.CRITICAL: "\033[1;31m",     # rot
    Severity.HIGH: "\033[1;31m",         # rot
    Severity.MAJOR: "\033[1;33m",        # gelb
    Severity.WARNING: "\033[1;33m",      # gelb
    Severity.MINOR: "\033[1;36m",        # cyan
    Severity.INFO: "\033[1;34m",         # blau
}


def _c(text: str, code: str, use_color: bool) -> str:
    return f"{code}{text}{_ANSI['reset']}" if use_color else text


def render_console(report: ScanReport, use_color: bool = True) -> str:
    """Erzeugt den farbigen Textreport."""
    lines: list[str] = []
    bold, dim = _ANSI["bold"], _ANSI["dim"]

    def head(text):
        return _c(text, bold, use_color)

    lines.append("")
    lines.append(head("=" * 74))
    lines.append(head("  ACI - Automated Code Inspection"))
    lines.append(head("=" * 74))
    lines.append(f"  Ziel    : {report.target}")
    lines.append(f"  Dialekt : {report.ruleset.dialect}")
    lines.append(f"  Gruppen : {', '.join(report.groups())}")
    lines.append(f"  Datum   : {report.created:%Y-%m-%d %H:%M:%S}")
    if report.integrity is not None:
        intg = report.integrity
        if intg.trusted:
            trust = _c("[vertrauenswürdig]", dim, use_color)
        else:
            trust = _c(f"[{len(intg.untrusted_files)} Datei(en) untrusted]",
                       _ANSI[Severity.WARNING], use_color)
        lines.append(f"  Regeln  : {intg.ruleset_hash} {trust}")

    for group in report.groups():
        lines.append("")
        lines.append(head("#" * 74))
        lines.append(head(f"#  GRUPPE: {group}"))
        lines.append(head("#" * 74))
        group_has = False
        for path, findings in sorted(report.results.items()):
            group_findings = [f for f in findings if f.group == group]
            if not group_findings:
                continue
            group_has = True
            lines.append("")
            lines.append(_c(f"  Datei: {path}", bold, use_color))
            lines.append(_c("  " + "-" * 70, dim, use_color))
            for finding in group_findings:
                badge = _c(f" {finding.severity.label.upper()} ",
                           _ANSI[finding.severity], use_color)
                loc = _c(f"Zeile {finding.line}:{finding.column}",
                         dim, use_color)
                wmark = (_c(" [WAIVED]", bold, use_color)
                         if finding.waived else "")
                lines.append(f"  {badge} [{finding.check_id}] {loc}{wmark}")
                lines.append(f"      {finding.message}")
                if finding.waiver is not None:
                    w = finding.waiver
                    lines.append(_c(
                        f"      Waiver: Ticket {w.ticket} · Owner {w.owner}"
                        f" · gültig bis {w.expires_str}", dim, use_color))
                    lines.append(_c(f"      Begründung: {w.reason}",
                                    dim, use_color))
                if finding.snippet:
                    lines.append(_c(f"      | {finding.snippet}",
                                    dim, use_color))
                for rel in finding.related:
                    lines.append(_c(f"      ↪ {rel.label} "
                                    f"(Zeile {rel.line})", dim, use_color))
                    if rel.snippet:
                        lines.append(_c(f"        | {rel.snippet}",
                                        dim, use_color))
                if finding.recommendation:
                    lines.append(_c(f"      -> {finding.recommendation}",
                                    dim, use_color))
                if finding.url:
                    lines.append(_c(f"      ? {finding.url}", dim, use_color))
                if finding.fingerprint:
                    lines.append(_c(f"      Fingerprint: "
                                    f"{finding.fingerprint}", dim, use_color))
        if not group_has:
            lines.append("")
            lines.append(_c("  Keine Findings in dieser Gruppe.",
                            dim, use_color))
        # Gruppen-Zusammenfassung
        counts = report.counts_for_group(group)
        lines.append("")
        lines.append(_c(f"  Zusammenfassung {group}:", bold, use_color))
        for sev in GROUP_SCALES[group]:
            count = counts.get(sev, 0)
            colour = _ANSI[sev] if count else dim
            lines.append("    " + _c(f"{sev.label:9s}: {count}",
                                     colour, use_color))

    lines.append("")
    lines.append(head("-" * 74))
    lines.append(head("  Gesamt"))
    lines.append(head("-" * 74))
    lines.append(f"  Geprüft      : {report.file_count()} Datei(en)")
    lines.append(f"  Mit Findings : {report.files_with_findings()} Datei(en)")
    lines.append(f"  Gescannt     : {_thousands(report.scanned_kb())} KB  /  "
                 f"{_thousands(report.loc())} LOC")
    lines.append(f"  Findings     : {report.total()}")
    lines.append(f"  Laufzeit     : {report.duration_str()} (mm:ss:hh)")
    lines.append(head("-" * 74))
    if report.total() == 0:
        lines.append(_c("  Keine Findings - keine bekannten Muster gefunden.",
                        bold, use_color))

    # Waiver-/Ausnahmen-Block - nur, wenn eine Waiver-Datei angegeben war.
    wr = report.waiver_report
    if wr is not None and wr.path:
        lines.append("")
        lines.append(head("-" * 74))
        lines.append(head("  Waiver / Ausnahmen"))
        lines.append(head("-" * 74))
        lines.append(f"  Datei          : {wr.path}")
        lines.append(f"  Angewendet     : {wr.applied} Finding(s) gewaivert "
                     f"(zählen nicht für --fail-on)")
        lines.append(f"  Aktiv          : {len(wr.active)} Waiver")
        if wr.soon:
            lines.append(_c(f"  Läuft bald ab  : {len(wr.soon)} Waiver",
                            _ANSI[Severity.WARNING], use_color))
        if wr.expired:
            lines.append(_c(f"  Abgelaufen     : {len(wr.expired)} Waiver "
                            f"(Findings zählen wieder)",
                            _ANSI[Severity.HIGH], use_color))
        if wr.orphaned:
            lines.append(_c(f"  Verwaist       : {len(wr.orphaned)} Waiver "
                            f"(ohne passendes Finding)", dim, use_color))
        if wr.errors:
            lines.append(_c(f"  Datei-Fehler   : {len(wr.errors)}",
                            _ANSI[Severity.HIGH], use_color))
        for warn in wr.warning_lines():
            lines.append(_c(f"    ! {warn}", dim, use_color))
        lines.append(head("-" * 74))

    lines.append("")
    return "\n".join(lines)
