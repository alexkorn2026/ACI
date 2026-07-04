"""Leichte Normalisierung von psql-Meta-Kommandos.

Bewusst KEIN vollstaendiger psql-Parser - nur genug Struktur, damit
Detektoren robust gegen Whitespace-/Tab-Varianten arbeiten und gefaehrliche
Merkmale (Shell-Escape ``\\!``, ``PROGRAM``-Klausel, Backquote-Substitution,
Pipe-Ziel) klar abfragbar sind, statt sie jeweils per Roh-Regex zu raten.

Die Erkennung ist zeilenorientiert: ein Meta-Kommando steht am Zeilenanfang
(optional fuehrender Whitespace) und beginnt mit ``\\``. ``\\!`` ist der
Shell-Escape; sein Kommandoname ist ``"!"``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

# Zeilenanfang (optional Whitespace), dann \<cmd>. Kommandoname ist entweder
# ``!``/``?`` (Sigil-Kommandos) oder eine Folge von Buchstaben/Unterstrichen.
_META_RE = re.compile(r"^[ \t]*\\(!|\?|[A-Za-z_]+)(.*)$")
_PROGRAM_RE = re.compile(r"\bPROGRAM\b", re.IGNORECASE)


@dataclass
class PsqlMetaCommand:
    """Normalisierte Sicht auf ein psql-Meta-Kommando einer Zeile."""

    command: str            # Kommandoname in Kleinschreibung, z.B. "copy", "!"
    args: str               # Argumentteil (getrimmt)
    raw: str                # Originalzeile
    normalized: str         # "\<cmd> <args>" mit normalisiertem Whitespace
    has_shell_escape: bool  # \! - die Zeile IST ein Shell-Escape
    has_program: bool       # args enthaelt die PROGRAM-Klausel (\copy ... PROGRAM)
    has_backtick: bool      # args enthaelt eine Backquote (` ... `)
    has_pipe_target: bool   # args beginnt mit | (Ausgabe an ein Programm)


def parse_psql_meta_line(line: str) -> Optional[PsqlMetaCommand]:
    """Parst eine einzelne Zeile als psql-Meta-Kommando.

    Liefert ``None``, wenn die Zeile kein Meta-Kommando am Zeilenanfang ist
    (z.B. eine normale SQL-Zeile oder ein Kommentar).
    """
    m = _META_RE.match(line)
    if not m:
        return None
    command = m.group(1).lower()
    args = (m.group(2) or "").strip()
    normalized = "\\" + command + ((" " + " ".join(args.split())) if args else "")
    return PsqlMetaCommand(
        command=command,
        args=args,
        raw=line,
        normalized=normalized,
        has_shell_escape=(command == "!"),
        has_program=bool(_PROGRAM_RE.search(args)),
        has_backtick=("`" in args),
        has_pipe_target=args.lstrip().startswith("|"),
    )
