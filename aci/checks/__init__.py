"""Die Prüf-Checks von ACI.

Fünf Sicherheits-Checks (NamingCheck, PackagesCheck, ObfuscationCheck,
SqlInjectionCheck, DdlCheck) sowie die regelgesteuerten GuidelineCheck
und MitreCheck. Jeder Check liefert für eine vorverarbeitete
:class:`~aci.source.Source` eine Liste von :class:`~aci.finding.Finding`.

Das Modul ist als Paket organisiert:

* :mod:`.base`       - Check-Basisklasse und gemeinsame Hilfsfunktionen
* :mod:`.lexical`    - NamingCheck, PackagesCheck, ObfuscationCheck
* :mod:`.sqli`       - SqlInjectionCheck (Datenfluss-Analyse)
* :mod:`.ddl`        - DdlCheck (Datenfluss-Analyse)
* :mod:`.detectors`  - Bibliothek der eingebauten Detektoren
* :mod:`.guidelines` - GuidelineCheck, MitreCheck

Dieses ``__init__`` re-exportiert die öffentliche Schnittstelle und
stellt die Check-Factory :func:`build_checks` bereit, sodass
``from aci.checks import ...`` unverändert funktioniert.
"""

from __future__ import annotations

from .base import Check
from .lexical import NamingCheck, PackagesCheck, ObfuscationCheck
from .sqli import SqlInjectionCheck
from .ddl import DdlCheck
from .detectors import _BUILTIN_DETECTORS
from .guidelines import (GuidelineCheck, MitreCheck,
                         build_guideline_checks, build_mitre_checks)


# Registry / Factory der fünf Sicherheits-Checks. Hier verortet, weil
# build_checks() alle Check-Klassen aus den Untermodulen benötigt.
_CHECK_CLASSES = {
    NamingCheck.config_key: NamingCheck,
    PackagesCheck.config_key: PackagesCheck,
    ObfuscationCheck.config_key: ObfuscationCheck,
    SqlInjectionCheck.config_key: SqlInjectionCheck,
    DdlCheck.config_key: DdlCheck,
}


def build_checks(ruleset) -> list[Check]:
    """Erzeugt alle in der Regeldatei aktivierten Sicherheits-Checks."""
    checks: list[Check] = []
    for key, cls in _CHECK_CLASSES.items():
        cfg = ruleset.check(key)
        if cfg and cfg.get("enabled", False):
            checks.append(cls(cfg, ruleset.dialect))
    return checks


__all__ = [
    "Check",
    "NamingCheck",
    "PackagesCheck",
    "ObfuscationCheck",
    "SqlInjectionCheck",
    "DdlCheck",
    "GuidelineCheck",
    "MitreCheck",
    "build_checks",
    "build_guideline_checks",
    "build_mitre_checks",
    "_BUILTIN_DETECTORS",
]
