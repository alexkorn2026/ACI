"""Laden der ACI-Standardparameter aus einer optionalen ``aci.ini``.

ACI funktioniert ohne Konfigurationsdatei - dann gelten die in
:data:`BUILTIN_DEFAULTS` festgelegten Werte. Liegt im aktuellen
Arbeitsverzeichnis (oder im Projektverzeichnis oberhalb des
``aci``-Pakets) eine ``aci.ini``, so überschreiben deren Werte die
Vorgaben. Ein ausdrücklich gesetzter Kommandozeilen-Schalter hat
weiterhin Vorrang vor der Datei.

Die Datei nutzt das INI-Format der Standardbibliothek
(:mod:`configparser`) mit einem Abschnitt ``[defaults]``.
"""

from __future__ import annotations

import configparser
import os


class ConfigError(Exception):
    """Fehler beim Lesen oder Validieren der ``aci.ini``."""


# Werkseitige Vorgaben - gelten, wenn keine aci.ini gefunden wird. Die
# ausgelieferte aci.ini bildet exakt diese Werte ab.
BUILTIN_DEFAULTS = {
    "dialect": "oracle",
    "group": "all",
    "format": "console",
    "min_level": "info",
    "fail_on": "none",
    "context_lines": 3,
    "no_context": False,
    "redact_secrets": False,
    "redact_paths": False,
    "safe_report": False,
    "taint_sources": True,
    "follow_symlinks": False,
    "max_file_size": "",
    "output_dir": ".",
    "html_group_by": "rule",
    # Bei true endet der Lauf mit Exit-Code 2, sobald ein Check intern
    # fehlschlägt (sonst nur Hinweis). Als aci.ini-Schlüssel geführt, um
    # mit den übrigen strengen CI-Schaltern konsistent zu sein.
    "strict_internal_errors": False,
    # Waiver-/Ausnahmeprozess: Pfad zur Waiver-Datei (leer = keine) und
    # ob fehlerhafte Waiver-Dateien zum Abbruch (Exit-Code 2) führen.
    "waivers": "",
    "strict_waivers": False,
    # Regelintegrität: bei true bricht ACI ab, wenn eine Regeldatei aus
    # einem benutzerdefinierten (nicht gebündelten) Pfad geladen würde.
    "require_trusted_rules": False,
}

# Erlaubte Werte für die auswahlbeschränkten Parameter. argparse prüft
# nur Werte aus der Kommandozeile, nicht die Defaults aus der Datei -
# daher hier eine eigene Validierung.
_CHOICES = {
    "dialect": ("oracle", "postgresql", "postgres"),
    "group": ("all", "security", "guidelines"),
    "min_level": ("info", "minor", "warning", "major",
                  "high", "critical", "blocker"),
    "fail_on": ("none", "info", "minor", "warning", "major",
                "high", "critical", "blocker"),
    "html_group_by": ("rule", "file"),
}

_BOOL_KEYS = ("no_context", "redact_secrets", "redact_paths", "safe_report",
              "taint_sources", "follow_symlinks", "strict_internal_errors",
              "strict_waivers", "require_trusted_rules")

CONFIG_FILENAME = "aci.ini"


def find_config(start_dir: "str | None" = None) -> "str | None":
    """Sucht eine ``aci.ini`` und liefert ihren Pfad - oder ``None``.

    Reihenfolge: das angegebene Verzeichnis (Standard: aktuelles
    Arbeitsverzeichnis), danach das Projektverzeichnis oberhalb des
    ``aci``-Pakets (für den Aufruf aus dem Quellbaum).
    """
    candidates = [os.path.join(start_dir or os.getcwd(), CONFIG_FILENAME)]
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates.append(os.path.join(pkg_parent, CONFIG_FILENAME))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def load_defaults(path: "str | None" = None) -> dict:
    """Liest die Standardparameter.

    Ohne ``path`` wird über :func:`find_config` gesucht. Wird keine
    Datei gefunden, gelten die :data:`BUILTIN_DEFAULTS`. Eine
    ausdrücklich angegebene, fehlende Datei sowie eine vorhandene, aber
    fehlerhafte Datei führen zu :class:`ConfigError`.
    """
    defaults = dict(BUILTIN_DEFAULTS)
    cfg_path = path or find_config()
    if not cfg_path:
        return defaults
    if not os.path.isfile(cfg_path):
        raise ConfigError(f"Konfigurationsdatei nicht gefunden: {cfg_path}")

    # interpolation=None: ein ``%`` in einem Wert (z.B. ``format = console%``
    # oder ein Muster mit ``%``) ist sonst configparser-Interpolation und
    # loest erst beim ``section.get()`` unten - ausserhalb des read_file-
    # try/except - einen ungefangenen ``InterpolationSyntaxError`` (roher
    # Traceback, Exit 1) aus. Ohne Interpolation wird der Wert literal gelesen.
    parser = configparser.ConfigParser(interpolation=None)
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            parser.read_file(fh)
    except (OSError, UnicodeDecodeError, configparser.Error) as exc:
        raise ConfigError(f"aci.ini nicht lesbar ({cfg_path}): {exc}")

    if not parser.has_section("defaults"):
        raise ConfigError(
            f"aci.ini ({cfg_path}) benötigt einen Abschnitt [defaults].")
    section = parser["defaults"]

    for key in section:
        if key not in BUILTIN_DEFAULTS:
            raise ConfigError(
                f"aci.ini ({cfg_path}): unbekannter Parameter '{key}'. "
                f"Erlaubt: {', '.join(sorted(BUILTIN_DEFAULTS))}.")

    for key in BUILTIN_DEFAULTS:
        if key not in section:
            continue
        raw = section.get(key, "").strip()
        if key in _BOOL_KEYS:
            try:
                defaults[key] = section.getboolean(key)
            except ValueError:
                raise ConfigError(
                    f"aci.ini ({cfg_path}): '{key}' erwartet true/false, "
                    f"nicht {raw!r}.")
        elif key == "context_lines":
            try:
                defaults[key] = int(raw)
            except ValueError:
                raise ConfigError(
                    f"aci.ini ({cfg_path}): 'context_lines' erwartet eine "
                    f"Ganzzahl, nicht {raw!r}.")
        else:
            defaults[key] = raw

    for key, allowed in _CHOICES.items():
        if defaults[key] not in allowed:
            raise ConfigError(
                f"aci.ini ({cfg_path}): '{key}' = {defaults[key]!r} ist "
                f"unzulässig. Erlaubt: {', '.join(allowed)}.")
    return defaults
