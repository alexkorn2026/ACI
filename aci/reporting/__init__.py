"""Aufbereitung und Ausgabe der Scan-Ergebnisse.

Die Findings werden nach Prüfgruppe getrennt dargestellt - jede Gruppe
mit ihrer eigenen Schweregrad-Skala:

* Sicherheit        - Warning < High < Critical
* Coding Guidelines - Info < Minor < Major < Critical < Blocker

Fünf Reportformate stehen zur Verfügung:

* :func:`render_console`     - farbiger Textreport für das Terminal
* :func:`render_json`        - maschinenlesbarer JSON-Report (z.B. für CI/CD)
* :func:`render_html`        - übersichtlicher HTML-Report zum Teilen
* :func:`render_sarif`       - SARIF 2.1.0 (z.B. für GitHub Code Scanning)
* :func:`render_codeclimate` - CodeClimate (GitLab Code Quality Widget)

Das Modul ist als Paket organisiert: je ein Untermodul für das
Datenmodell (:mod:`.report`) und für jedes der fünf Reportformate.
Dieses ``__init__`` re-exportiert die öffentliche Schnittstelle, sodass
``from aci.reporting import ...`` unverändert funktioniert.
"""

from .report import ScanReport
from .console import render_console
from .json_report import render_json
from .sarif import render_sarif
from .html import render_html
from .codeclimate import render_codeclimate

__all__ = [
    "ScanReport",
    "render_console",
    "render_json",
    "render_sarif",
    "render_html",
    "render_codeclimate",
]
