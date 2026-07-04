#!/usr/bin/env python3
"""ACI - Automated Code Inspection - Starter für die Ausführung aus dem
Quellverzeichnis.

Dieser schlanke Starter ermöglicht den Aufruf ``python aci.py …`` ohne
vorherige Installation. Die eigentliche Logik liegt im Paket ``aci.cli``.
Nach einer Installation (``pip install .``) steht zusätzlich das
Kommando ``aci`` zur Verfügung.
"""

import os
import sys

# Projektverzeichnis in den Suchpfad aufnehmen, damit das Paket "aci"
# auch ohne Installation gefunden wird.
_PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_DIR not in sys.path:
    sys.path.insert(0, _PROJECT_DIR)

from aci.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
