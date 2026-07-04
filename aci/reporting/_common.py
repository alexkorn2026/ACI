"""Von mehreren Reportern gemeinsam genutzte Hilfsfunktionen."""

from __future__ import annotations


def _thousands(value: int) -> str:
    """Formatiert eine Ganzzahl mit Punkt als Tausendertrennzeichen."""
    return f"{int(value):,}".replace(",", ".")
