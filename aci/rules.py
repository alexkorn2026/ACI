"""Laden und Validieren der externen JSON-Regeldateien.

Die Regeln werden bewusst außerhalb des Programmcodes gepflegt. Eine
Regeldatei beschreibt für genau einen SQL-Dialekt (Oracle oder
PostgreSQL), welche Checks aktiv sind und mit welchen Wortlisten,
Mustern und Schweregraden sie arbeiten.

Regeldateien werden **früh und hart** validiert: ungültiges JSON, eine
fehlende oder doppelte Regel-ID, ein unbekannter Schweregrad, ein
unbekannter Detector-Typ oder ein nicht kompilierbares Regex-Muster
führen zu einem :class:`RuleError`. Fehler werden nicht still ignoriert -
so kann eine kaputte Regel nicht unbemerkt die halbe Analyse abschalten.
"""

from __future__ import annotations

import json
import os
import re

from .finding import Level

# Standard-Dateiendungen, falls eine Regeldatei keine eigene Liste angibt.
DEFAULT_EXTENSIONS = [
    ".sql", ".pks", ".pkb", ".prc", ".fnc", ".trg",
    ".pls", ".plb", ".bdy", ".tps", ".pkg", ".pck",
]

# Zuordnung Dialekt -> Regeldateiname.
_DIALECT_FILES = {
    "oracle": "oracle.json",
    "postgres": "postgresql.json",
    "postgresql": "postgresql.json",
    "pg": "postgresql.json",
}

# Bekannte Detector-Typen und -Targets für Guideline-/MITRE-Regeln.
_DETECTOR_TYPES = {"regex", "builtin"}
_DETECTOR_TARGETS = {"code", "masked", "string"}


class RuleError(Exception):
    """Fehler beim Laden oder Validieren einer Regeldatei."""


# ----------------------------------------------------------------------
# Hilfsfunktionen
# ----------------------------------------------------------------------

# Cache der beim Laden tatsaechlich gelesenen Regeldatei-Bytes, keyed auf
# ``os.path.realpath``. Die Integritaetspruefung hasht daraus - **hash what
# you load** - statt die Dateien fuer den Hash erneut von der Platte zu
# lesen (schliesst das TOCTOU-Fenster, s. :func:`aci.integrity.
# compute_ruleset_integrity`).
_RULE_CONTENT_CACHE: "dict[str, bytes]" = {}


def rule_content_cache() -> "dict[str, bytes]":
    """Öffentlicher Zugriff auf den Regel-Inhalts-Cache (``{realpath: bytes}``).

    Kapselt das interne ``_RULE_CONTENT_CACHE`` (K2), sodass Aufrufer nicht
    auf ein privates Symbol zugreifen müssen. Wird von der Integritätsprüfung
    genutzt, um "hash what you load" zu garantieren.
    """
    return _RULE_CONTENT_CACHE


def clear_rule_content_cache() -> None:
    """Leert den Regel-Inhalts-Cache (Tests/lang laufende Prozesse)."""
    _RULE_CONTENT_CACHE.clear()


def _load_json(path: str, kind: str = "Datei"):
    """Lädt eine JSON-Datei und wandelt Lesefehler in RuleError um.

    Die gelesenen Roh-Bytes werden zusaetzlich in :data:`_RULE_CONTENT_CACHE`
    abgelegt, damit die Integritaetspruefung exakt den geladenen Inhalt
    hasht.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RuleError(
            f"{kind} {path} konnte nicht gelesen werden: {exc}") from exc
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise RuleError(
            f"{kind} {path} ist nicht UTF-8-kodiert: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuleError(
            f"{kind} {path} ist kein gültiges JSON: {exc}") from exc
    _RULE_CONTENT_CACHE[os.path.realpath(path)] = raw
    return data


def _builtin_detector_names() -> set:
    """Namen aller registrierten Builtin-Detektoren.

    Der Import erfolgt verzögert (innerhalb der Funktion), um einen
    Importzyklus zwischen :mod:`aci.rules` und :mod:`aci.checks` zu
    vermeiden.
    """
    from .checks import _BUILTIN_DETECTORS
    return set(_BUILTIN_DETECTORS)


def _validate_rule(rule: dict, path: str, default_severity: str) -> None:
    """Validiert eine einzelne Guideline- oder MITRE-Regel.

    Geprüft werden: vorhandene, nicht-leere ``id``; gültige ``severity``;
    bei aktiven Regeln zusätzlich ``message`` sowie ein vollständiger,
    bekannter Detector (Typ, Target, kompilierbares Regex bzw.
    Builtin-Name). Deaktivierte Regeln dokumentieren nur, dass eine
    Guideline bekannt, aber (noch) nicht prüfbar ist - sie brauchen
    keinen Detector.
    """
    rid = rule.get("id")
    if not isinstance(rid, str) or not rid.strip():
        raise RuleError(
            f"{path}: jede Regel benötigt eine nicht-leere 'id'.")
    try:
        Level.parse(rule.get("severity", default_severity))
    except ValueError as exc:
        raise RuleError(f"{path}, Regel '{rid}': {exc}") from exc

    if not rule.get("enabled", False):
        return  # deaktivierte Regel - nur Dokumentation, kein Detector nötig

    if not str(rule.get("message", "")).strip():
        raise RuleError(
            f"{path}, Regel '{rid}': aktive Regel ohne 'message'.")

    detector = rule.get("detector")
    if not isinstance(detector, dict):
        raise RuleError(
            f"{path}, Regel '{rid}': aktive Regel ohne 'detector'-Objekt.")
    dtype = detector.get("type")
    if dtype not in _DETECTOR_TYPES:
        raise RuleError(
            f"{path}, Regel '{rid}': unbekannter Detector-Typ {dtype!r} "
            f"(erlaubt: {', '.join(sorted(_DETECTOR_TYPES))}).")
    target = detector.get("target", "code")
    if target not in _DETECTOR_TARGETS:
        raise RuleError(
            f"{path}, Regel '{rid}': unbekanntes Detector-Target "
            f"{target!r} (erlaubt: {', '.join(sorted(_DETECTOR_TARGETS))}).")
    if dtype == "regex":
        pattern = detector.get("pattern")
        if not pattern or not str(pattern).strip():
            raise RuleError(
                f"{path}, Regel '{rid}': regex-Detector ohne 'pattern'.")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise RuleError(
                f"{path}, Regel '{rid}': ungültiges Regex {pattern!r}: "
                f"{exc}") from exc
    else:  # builtin
        name = str(detector.get("name", "")).strip()
        if not name:
            raise RuleError(
                f"{path}, Regel '{rid}': builtin-Detector ohne 'name'.")
        if name not in _builtin_detector_names():
            raise RuleError(
                f"{path}, Regel '{rid}': unbekannter builtin-Detektor "
                f"{name!r}.")


class RuleSet:
    """Repräsentiert eine geladene Sicherheits-Regeldatei."""

    def __init__(self, data: dict, path: str):
        self.path = path
        self.dialect = str(data.get("dialect", "oracle")).lower()
        self.version = str(data.get("version", "?"))
        self.description = str(data.get("description", ""))
        exts = data.get("file_extensions") or DEFAULT_EXTENSIONS
        self.file_extensions = [e.lower() for e in exts]
        self.checks: dict = data.get("checks", {})

    def check(self, key: str) -> dict:
        """Konfiguration eines Checks (leeres Dict, falls nicht vorhanden)."""
        cfg: dict = self.checks.get(key, {})
        return cfg

    def is_enabled(self, key: str) -> bool:
        """True, wenn der Check in der Regeldatei aktiviert ist."""
        return bool(self.checks.get(key, {}).get("enabled", False))

    def __repr__(self) -> str:  # pragma: no cover - nur Diagnose
        return (f"<RuleSet dialect={self.dialect} version={self.version} "
                f"path={self.path}>")


def load_ruleset(path: str) -> RuleSet:
    """Lädt eine Sicherheits-Regeldatei und validiert sie hart."""
    if not os.path.isfile(path):
        raise RuleError(f"Regeldatei nicht gefunden: {path}")
    data = _load_json(path, "Regeldatei")
    if not isinstance(data, dict):
        raise RuleError(
            f"Regeldatei {path}: erwartet ein JSON-Objekt auf oberster Ebene.")
    ruleset = RuleSet(data, path)
    _validate(ruleset)
    return ruleset


def find_ruleset(dialect: str, rules_dir: str) -> str:
    """Ermittelt den Pfad der Regeldatei für den gewünschten Dialekt."""
    fname = _DIALECT_FILES.get((dialect or "").lower())
    if not fname:
        raise RuleError(
            f"Unbekannter Dialekt: {dialect!r} "
            f"(erlaubt: oracle, postgresql, postgres, pg)"
        )
    return os.path.join(rules_dir, fname)


def _require_str_list(value, path, where):
    """Erzwingt eine Liste nicht-leerer Strings (sonst RuleError)."""
    if not isinstance(value, list):
        raise RuleError(f"Regeldatei {path}, {where}: erwartet eine Liste.")
    for entry in value:
        if not isinstance(entry, str) or not entry.strip():
            raise RuleError(
                f"Regeldatei {path}, {where}: jeder Eintrag muss ein "
                f"nicht-leerer String sein (gefunden: {entry!r}).")


def _opt_str(value, path, where):
    """Optionales Feld: falls vorhanden, muss es ein String sein."""
    if value is not None and not isinstance(value, str):
        raise RuleError(
            f"Regeldatei {path}, {where}: muss - falls gesetzt - ein "
            f"String sein (gefunden: {type(value).__name__}).")


def _check_level(value, path, where):
    try:
        Level.parse(value)
    except ValueError as exc:
        raise RuleError(f"Regeldatei {path}, {where}: {exc}") from exc


def _validate_ddl_in_code(path, cfg) -> None:
    """Tiefe Validierung der ``ddl_in_code``-Substrukturen (fail-closed)."""
    where0 = "Check 'ddl_in_code'"

    cs = cfg.get("critical_statements")
    if cs is not None:
        if not isinstance(cs, list):
            raise RuleError(f"Regeldatei {path}, {where0}.critical_statements: "
                            f"erwartet eine Liste.")
        for i, item in enumerate(cs):
            w = f"{where0}.critical_statements[{i}]"
            if not isinstance(item, dict):
                raise RuleError(f"Regeldatei {path}, {w}: erwartet ein Objekt.")
            stmt = item.get("statement")
            if not isinstance(stmt, str) or not stmt.strip():
                raise RuleError(f"Regeldatei {path}, {w}: Pflichtfeld "
                                f"'statement' (nicht-leerer String) fehlt.")
            _check_level(item.get("level"), path, f"{w}.level")
            _opt_str(item.get("message"), path, f"{w}.message")
            _opt_str(item.get("recommendation"), path, f"{w}.recommendation")

    et = cfg.get("external_table")
    if isinstance(et, dict) and et:
        w = f"{where0}.external_table"
        _check_level(et.get("level"), path, f"{w}.level")
        _opt_str(et.get("message"), path, f"{w}.message")
        _opt_str(et.get("recommendation"), path, f"{w}.recommendation")
    elif et is not None and not isinstance(et, dict):
        raise RuleError(f"Regeldatei {path}, {where0}.external_table: "
                        f"erwartet ein Objekt.")

    pg = cfg.get("privilege_grant")
    if isinstance(pg, dict) and pg:
        w = f"{where0}.privilege_grant"
        _check_level(pg.get("level"), path, f"{w}.level")
        _opt_str(pg.get("system_message"), path, f"{w}.system_message")
        _opt_str(pg.get("role_message"), path, f"{w}.role_message")
        _opt_str(pg.get("recommendation"), path, f"{w}.recommendation")
    elif pg is not None and not isinstance(pg, dict):
        raise RuleError(f"Regeldatei {path}, {where0}.privilege_grant: "
                        f"erwartet ein Objekt.")

    for key in ("standard_roles", "system_privileges",
                "harmless_object_privileges"):
        if cfg.get(key) is not None:
            _require_str_list(cfg[key], path, f"{where0}.{key}")

    objs = cfg.get("ddl_objects")
    if objs is not None:
        if not isinstance(objs, dict):
            raise RuleError(f"Regeldatei {path}, {where0}.ddl_objects: "
                            f"erwartet ein Objekt.")
        for key, val in objs.items():
            _require_str_list(val, path, f"{where0}.ddl_objects.{key}")


def _validate(ruleset: RuleSet) -> None:
    """Validiert eine Sicherheits-Regeldatei.

    Geprüft werden alle Schweregrad-Angaben sowie die Kompilierbarkeit
    aller in der Datei hinterlegten Regex-Muster (Obfuskations-Check) und
    - für ``ddl_in_code`` - die tieferen Substrukturen
    (critical_statements, external_table, privilege_grant, Rollen-/
    Privilegienlisten, ddl_objects).
    """
    if not isinstance(ruleset.checks, dict):
        raise RuleError(
            f"Regeldatei {ruleset.path}: 'checks' muss ein Objekt sein.")

    for check_key, cfg in ruleset.checks.items():
        if not isinstance(cfg, dict):
            raise RuleError(
                f"Regeldatei {ruleset.path}: Check '{check_key}' "
                f"muss ein Objekt sein.")
        # Alle möglichen Stellen einsammeln, an denen ein Level steht.
        level_values = []
        for key in ("level", "wrapped_level", "chr_chain_level",
                    "tainted_level", "literal_only_level",
                    "sanitized_level", "unknown_dynamic_level",
                    "plsql_injection_level", "interprocedural_level"):
            if key in cfg:
                level_values.append(cfg[key])
        for item in cfg.get("items", []) or []:
            if isinstance(item, dict) and "level" in item:
                level_values.append(item["level"])
        for item in cfg.get("keywords", []) or []:
            if isinstance(item, dict) and "level" in item:
                level_values.append(item["level"])
        for item in cfg.get("patterns", []) or []:
            if not isinstance(item, dict):
                continue
            if "level" in item:
                level_values.append(item["level"])
            regex = item.get("regex")
            if regex:
                try:
                    re.compile(regex)
                except re.error as exc:
                    raise RuleError(
                        f"Regeldatei {ruleset.path}, Check '{check_key}', "
                        f"Muster '{item.get('id', '?')}': ungültiges "
                        f"Regex {regex!r}: {exc}") from exc

        for value in level_values:
            try:
                Level.parse(value)
            except ValueError as exc:
                raise RuleError(
                    f"Regeldatei {ruleset.path}, Check '{check_key}': {exc}"
                ) from exc

        if check_key == "ddl_in_code":
            _validate_ddl_in_code(ruleset.path, cfg)


# ----------------------------------------------------------------------
# Coding Guidelines (Oracle: Trivadis, PostgreSQL: ACI-eigen)
# - eine JSON-Datei je Kategorie
# ----------------------------------------------------------------------

# Dialekte, für die Coding-Guidelines vorliegen: Oracle (Trivadis) und
# PostgreSQL (ACI-eigene PL/pgSQL-Guidelines).
_GUIDELINE_DIALECTS = {"oracle", "postgres", "postgresql", "pg"}
# MITRE-Angriffsindikatoren liegen für Oracle und PostgreSQL vor.
_MITRE_DIALECTS = {"oracle", "postgres", "postgresql", "pg"}


def _dialect_subdir(dialect: str) -> str:
    """Unterverzeichnisname je Dialekt (oracle / postgresql)."""
    if (dialect or "").lower() in ("postgres", "postgresql", "pg"):
        return "postgresql"
    return "oracle"


def has_guidelines(dialect: str) -> bool:
    """True, wenn für den Dialekt Coding-Guidelines verfügbar sind."""
    return (dialect or "").lower() in _GUIDELINE_DIALECTS


def find_guidelines_dir(dialect: str, base_dir: str) -> str:
    """Verzeichnis mit den Guideline-Kategoriedateien für den Dialekt."""
    return os.path.join(base_dir, _dialect_subdir(dialect))


def load_guideline_rules(guidelines_dir: str, dialect: str) -> list:
    """Lädt und validiert alle Guideline-Kategoriedateien eines Dialekts.

    Jede Datei hat die Form ``{"category": ..., "rules": [...]}``. Alle
    Regeln werden zu einer flachen Liste zusammengeführt. Deaktivierte
    Regeln (``enabled: false``) bleiben enthalten - sie dokumentieren,
    welche Guidelines bekannt, aber (noch) nicht geprüft werden.

    Guideline-Regel-IDs müssen dateiübergreifend eindeutig sein.
    """
    if not has_guidelines(dialect):
        return []
    if not os.path.isdir(guidelines_dir):
        raise RuleError(
            f"Guideline-Verzeichnis nicht gefunden: {guidelines_dir}")
    rules: list = []
    seen_ids: dict = {}
    for fname in sorted(os.listdir(guidelines_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(guidelines_dir, fname)
        data = _load_json(path, "Guideline-Datei")
        if not isinstance(data, dict):
            raise RuleError(
                f"Guideline-Datei {path}: erwartet ein JSON-Objekt.")
        file_rules = data.get("rules")
        if not isinstance(file_rules, list):
            raise RuleError(
                f"Guideline-Datei {path}: 'rules' muss eine Liste sein.")
        category = data.get("category", fname)
        for rule in file_rules:
            if not isinstance(rule, dict):
                raise RuleError(
                    f"Guideline-Datei {path}: jede Regel muss ein "
                    f"Objekt sein.")
            _validate_rule(rule, path, default_severity="Minor")
            rid = rule["id"]
            if rid in seen_ids:
                raise RuleError(
                    f"Guideline-Regel-ID '{rid}' ist nicht eindeutig "
                    f"(bereits in {seen_ids[rid]}, erneut in {path}).")
            seen_ids[rid] = path
            rule.setdefault("category", category)
            rule["_source_file"] = fname
            rules.append(rule)
    return rules


# ----------------------------------------------------------------------
# MITRE-ATT&CK-Angriffsindikatoren (eine JSON-Datei je Taktik)
# ----------------------------------------------------------------------

def has_mitre(dialect: str) -> bool:
    """True, wenn für den Dialekt MITRE-Angriffsindikatoren vorliegen."""
    return (dialect or "").lower() in _MITRE_DIALECTS


def find_mitre_dir(dialect: str, base_dir: str) -> str:
    """Verzeichnis mit den MITRE-Taktikdateien für den Dialekt."""
    return os.path.join(base_dir, _dialect_subdir(dialect))


def load_mitre_rules(mitre_dir: str, dialect: str) -> list:
    """Lädt und validiert alle MITRE-Taktikdateien eines Dialekts.

    Jede Datei hat die Form ``{"tactic": ..., "rules": [...]}``. Alle
    Regeln werden zu einer flachen Liste zusammengeführt.

    Anders als bei den Guidelines werden MITRE-Regel-IDs *nicht* auf
    Eindeutigkeit geprüft: eine ATT&CK-Technik-ID (z.B. ``T1059.007``)
    kann bewusst mehrere Detektoren tragen.
    """
    if not has_mitre(dialect):
        return []
    if not os.path.isdir(mitre_dir):
        raise RuleError(f"MITRE-Verzeichnis nicht gefunden: {mitre_dir}")
    rules: list = []
    for fname in sorted(os.listdir(mitre_dir)):
        if not fname.endswith(".json"):
            continue
        path = os.path.join(mitre_dir, fname)
        data = _load_json(path, "MITRE-Datei")
        if not isinstance(data, dict):
            raise RuleError(f"MITRE-Datei {path}: erwartet ein JSON-Objekt.")
        file_rules = data.get("rules")
        if not isinstance(file_rules, list):
            raise RuleError(
                f"MITRE-Datei {path}: 'rules' muss eine Liste sein.")
        tactic = data.get("tactic", fname)
        for rule in file_rules:
            if not isinstance(rule, dict):
                raise RuleError(
                    f"MITRE-Datei {path}: jede Regel muss ein Objekt sein.")
            _validate_rule(rule, path, default_severity="High")
            rule.setdefault("tactic", tactic)
            rule["_source_file"] = fname
            rules.append(rule)
    return rules
