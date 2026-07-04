"""Modul-Einstiegspunkt - ermöglicht den Aufruf ``python -m aci``."""

import sys

from aci.cli import main

if __name__ == "__main__":
    sys.exit(main())
