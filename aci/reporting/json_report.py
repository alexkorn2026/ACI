"""JSON-Report - maschinenlesbarer Report (z.B. für CI/CD)."""

from __future__ import annotations

import json

from .._version import __version__
from ..finding import GROUP_SCALES
from .report import ScanReport


def render_json(report: ScanReport) -> str:
    """Erzeugt den maschinenlesbaren JSON-Report."""
    by_group = {}
    for group in report.groups():
        counts = report.counts_for_group(group)
        by_group[group] = {
            "findings": report.total_in_group(group),
            "by_severity": {sev.label: counts.get(sev, 0)
                            for sev in GROUP_SCALES[group]},
        }
    data = {
        "tool": "ACI - Automated Code Inspection",
        "version": __version__,
        "generated": report.created.isoformat(timespec="seconds"),
        "target": report.target,
        "dialect": report.ruleset.dialect,
        "groups": report.groups(),
        "ruleset": {
            "path": report.ruleset.path,
            "version": report.ruleset.version,
            "integrity": (report.integrity.to_dict()
                          if report.integrity is not None else None),
        },
        "ruleset_integrity": report.ruleset_verification,
        "runtime": report.runtime,
        "gate": report.gate,
        "config": report.config_info,
        "scanner_config": report.scanner_config,
        "scanner_defaults": report.scanner_defaults,
        "waivers": (report.waiver_report.to_dict()
                    if report.waiver_report is not None else None),
        "summary": {
            "files_scanned": report.file_count(),
            "files_with_findings": report.files_with_findings(),
            "scanned_bytes": report.scanned_bytes,
            "scanned_kb": report.scanned_kb(),
            "lines_of_code": report.loc(),
            "duration_seconds": (round(float(report.duration), 3)
                                 if report.duration is not None else None),
            "duration": report.duration_str(),
            "findings_total": report.total(),
            "by_group": by_group,
        },
        "files": [
            {
                "file": path,
                "findings": [f.to_dict() for f in findings],
            }
            for path, findings in sorted(report.results.items())
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)
