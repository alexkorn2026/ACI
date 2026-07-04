"""Gemeinsame Datei-I/O-Hilfen.

Enthaelt insbesondere das **atomare** Schreiben von Textdateien. Reports
(JSON/HTML/SARIF/CodeClimate) und die Baseline werden darueber geschrieben,
damit ein Prozessabbruch, ein Dateisystemfehler, ein voller Datentraeger
oder ein parallel laufender Job keine halb geschriebene, ungueltige Datei
hinterlaesst (M5): geschrieben wird in eine Temporaerdatei im Zielverzeichnis,
mit ``flush``+``fsync`` gesichert und per ``os.replace`` atomar an den
endgueltigen Pfad bewegt. Eine bereits vorhandene Zieldatei bleibt bis zum
erfolgreichen Replace unveraendert.
"""

from __future__ import annotations

import contextlib
import os
import tempfile


def atomic_write_text(path: str, content: str, *,
                      encoding: str = "utf-8", newline: str = "\n") -> None:
    """Schreibt ``content`` atomar nach ``path``.

    Temporaerdatei im Zielverzeichnis (damit ``os.replace`` auf demselben
    Dateisystem und somit atomar ist), ``flush``+``fsync``, dann
    ``os.replace``. Bei Fehlern wird die Temporaerdatei entfernt; die
    Zieldatei bleibt bis zum erfolgreichen Replace unangetastet. Die Rechte
    einer bereits vorhandenen Zieldatei werden - soweit moeglich - beibehalten.
    """
    target_dir = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".aci-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline=newline) as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if os.path.exists(path):
            with contextlib.suppress(OSError):
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise
