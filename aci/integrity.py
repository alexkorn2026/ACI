"""Regelintegrität: Hash und Vertrauensstatus der geladenen Regeldateien.

Die Regeldateien (Sicherheits-Regelsatz, Coding-Guidelines, MITRE-
Indikatoren) bestimmen, *was* ACI prüft. Über ``--rules``,
``--rules-dir``, ``--guidelines-dir`` und ``--mitre-dir`` lassen sie
sich austauschen - flexibel, in einer CI/CD-Pipeline aber auch ein
Manipulationsrisiko: Wer die Regeln verändert, kann den Gate
schwächen.

Dieses Modul macht den verwendeten Regelstand überprüfbar:

* Es berechnet einen **Ruleset-Hash** über den Inhalt *aller*
  tatsächlich geladenen Regeldateien. Der Hash ist stabil und
  reproduzierbar; ein Team kann ihn in der Pipeline gegen einen
  erwarteten Wert prüfen.
* Es bestimmt je Datei, ob sie **vertrauenswürdig** ist - also Teil
  der mit ACI ausgelieferten, gebündelten Regeln (innerhalb des
  installierten ``aci``-Pakets) - oder aus einem benutzerdefinierten
  Pfad stammt (*untrusted*).

Der Report zeigt Hash und Vertrauensstatus; ``--require-trusted-rules``
lässt ACI abbrechen, sobald eine Regeldatei von außerhalb des Pakets
geladen würde.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field

# Verzeichnis des installierten ``aci``-Pakets. Regeldateien innerhalb
# dieses Verzeichnisses gelten als gebündelt und vertrauenswürdig.
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))


def is_trusted_path(path: str) -> bool:
    """True, wenn ``path`` innerhalb des installierten ``aci``-Pakets liegt.

    Damit sind genau die mit ACI ausgelieferten, gebündelten Regeln
    vertrauenswürdig. Eine Regeldatei aus einem beliebigen anderen
    Verzeichnis (eigener ``--rules``-Pfad) gilt als *untrusted*.
    Symlinks werden über :func:`os.path.realpath` aufgelöst.
    """
    try:
        pkg = os.path.realpath(_PKG_DIR)
        real = os.path.realpath(path)
    except OSError:
        return False
    return real == pkg or real.startswith(pkg + os.sep)


@dataclass
class RuleFileInfo:
    """Hash und Vertrauensstatus einer einzelnen Regeldatei."""

    name: str          # Basisname der Datei (ohne Verzeichnis)
    category: str      # "security" | "guidelines" | "mitre"
    sha256: str        # SHA-256 des Dateiinhalts ("" wenn nicht lesbar)
    trusted: bool      # Datei innerhalb des aci-Pakets?

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "category": self.category,
            "sha256": self.sha256,
            "trusted": self.trusted,
        }


@dataclass
class RulesetIntegrity:
    """Integritäts-Gesamtbild über alle geladenen Regeldateien."""

    ruleset_hash: str              # kombinierter SHA-256 über alle Dateien
    files: list = field(default_factory=list)   # list[RuleFileInfo]

    @property
    def trusted(self) -> bool:
        """True, wenn *alle* Regeldateien aus dem ACI-Paket stammen."""
        return all(f.trusted for f in self.files)

    @property
    def untrusted_files(self) -> list:
        """Regeldateien aus benutzerdefinierten Pfaden (untrusted)."""
        return [f for f in self.files if not f.trusted]

    def to_dict(self) -> dict:
        return {
            "ruleset_hash": self.ruleset_hash,
            "trusted": self.trusted,
            "files": [f.to_dict() for f in self.files],
        }


def compute_ruleset_integrity(rule_files, content_by_realpath=None
                              ) -> RulesetIntegrity:
    """Berechnet Hash und Vertrauensstatus für die geladenen Regeldateien.

    ``rule_files`` ist eine Liste von ``(category, path)``-Paaren. Je
    Datei werden Inhalt-Hash und Vertrauensstatus ermittelt; der
    kombinierte ``ruleset_hash`` entsteht deterministisch aus den
    nach ``(category, name)`` sortierten Einzel-Hashes - die Reihenfolge
    der Eingabe spielt also keine Rolle.

    ``content_by_realpath`` ist ein optionaler ``{realpath: bytes}``-Cache
    der beim Laden tatsaechlich gelesenen Datei-Inhalte (siehe
    :data:`aci.rules._RULE_CONTENT_CACHE`). Ist er gesetzt, wird der Hash
    ueber genau diese Bytes gebildet - **hash what you load** - statt die
    Datei ein zweites Mal von der Platte zu lesen. Das schliesst das
    TOCTOU-Fenster: sonst koennte eine Regeldatei zwischen Laden und
    Hashen ausgetauscht werden und der Report den *erwarteten* Hash zeigen,
    obwohl mit anderen Regeln gescannt wurde.
    """
    cache = content_by_realpath or {}
    infos: list = []
    for category, path in rule_files:
        content = cache.get(os.path.realpath(path))
        if content is None:
            try:
                with open(path, "rb") as fh:
                    content = fh.read()
            except OSError:
                content = None
        digest = hashlib.sha256(content).hexdigest() if content is not None else ""
        infos.append(RuleFileInfo(
            name=os.path.basename(path),
            category=str(category),
            # Eine nicht lesbare Datei (leerer Hash) ist nicht ueberpruefbar
            # und darf daher nicht als vertrauenswuerdig gelten.
            sha256=digest,
            trusted=is_trusted_path(path) and bool(digest)))
    infos.sort(key=lambda info: (info.category, info.name))
    combined = hashlib.sha256()
    for info in infos:
        combined.update(info.category.encode("utf-8"))
        combined.update(b"\x00")
        combined.update(info.name.encode("utf-8"))
        combined.update(b"\x00")
        combined.update(info.sha256.encode("utf-8"))
        combined.update(b"\x00")
    return RulesetIntegrity(ruleset_hash=combined.hexdigest(), files=infos)
