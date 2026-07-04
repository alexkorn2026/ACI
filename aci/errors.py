"""Strukturierte ACI-Ausnahmen mit Quellposition (S6).

Statt eines unstrukturierten Exception-Strings als Fehler-Interface tragen
diese Ausnahmen eine 1-basierte Zeile/Spalte (und optional einen Byte-Offset
sowie einen ``error_code``). :meth:`aci.scanner.Scanner._internal_finding`
uebernimmt Zeile/Spalte, wenn vorhanden, sodass ein Parse-/Lex-Fehler nicht
pauschal auf Zeile 1 zeigt, sondern auf die tatsaechliche Fundstelle.
"""

from __future__ import annotations


class AciParseError(Exception):
    """Fehler beim Aufbau der Quell-/IR-Schicht mit bekannter Position."""

    def __init__(self, message: str, *, line: int = 1, column: int = 1,
                 offset: "int | None" = None, error_code: str = ""):
        super().__init__(message)
        self.line = int(line) if line and line > 0 else 1
        self.column = int(column) if column and column > 0 else 1
        self.offset = offset
        self.error_code = error_code
