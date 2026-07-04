#!/usr/bin/env python3
"""ACI - Automated Code Inspection - Kommandozeilen-Schnittstelle.

Prüft übergebenen Oracle- (PL/SQL) oder PostgreSQL-Code (PL/pgSQL) und
gibt das Ergebnis als Konsolen-, JSON-, HTML- und/oder SARIF-Report aus.

ACI prüft in zwei Gruppen:

* Gruppe **Sicherheit**        - fünf Sicherheits-Checks plus
                                 MITRE-ATT&CK-Angriffsindikatoren
* Gruppe **Coding Guidelines** - PL/SQL-/PL/pgSQL-Coding-Guidelines
                                 (Oracle nach Trivadis, PostgreSQL eigene)

Aufruf nach der Installation über das Kommando ``aci``, aus dem
Quellverzeichnis über ``python -m aci`` oder ``python aci.py``:

    aci samples/vulnerable_oracle.sql
    python -m aci src/ --dialect oracle --format console,html
    aci code.sql --group security --fail-on high
    aci ./src --exclude generated --max-file-size 5MB --no-context
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import re
import shlex
import sys
import time

from aci import Scanner, __version__
from aci.config import (ConfigError, load_defaults, find_config,
                        BUILTIN_DEFAULTS)
from aci.finding import (Severity, GROUP_SECURITY, GROUP_GUIDELINES,
                         GROUP_INTERNAL)
from aci.rules import (RuleError, find_ruleset, load_ruleset,
                       find_guidelines_dir, load_guideline_rules,
                       has_guidelines, find_mitre_dir, load_mitre_rules,
                       has_mitre, _RULE_CONTENT_CACHE)
from aci.reporting import (ScanReport, render_codeclimate, render_console,
                           render_html, render_json, render_sarif)
from aci.parser import parse_ir
from aci.ir import ir_to_dict
from aci.waivers import load_waivers, apply_waivers
from aci.baseline import (write_baseline, load_baseline, apply_baseline,
                          BaselineError)
from aci.integrity import compute_ruleset_integrity

# Die Regeldateien werden mit dem Paket ausgeliefert (aci/rules/).
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_RULES_DIR = os.path.join(_PKG_DIR, "rules")
_DEFAULT_GUIDELINES_BASE = os.path.join(_PKG_DIR, "rules", "guidelines")
_DEFAULT_MITRE_BASE = os.path.join(_PKG_DIR, "rules", "mitre")

_GROUP_SETS = {
    "all": {GROUP_SECURITY, GROUP_GUIDELINES},
    "security": {GROUP_SECURITY},
    "guidelines": {GROUP_GUIDELINES},
}

# CI/CD-Profile: benannte Bündel sinnvoller Voreinstellungen, damit man
# in der Pipeline nicht jedes Mal eine lange Schalter-Kette schreiben
# muss. Ein Profil legt eine Vorgabe-Schicht zwischen aci.ini und die
# expliziten Kommandozeilen-Schalter; ein ausdrücklich gesetzter
# Schalter hat also weiterhin Vorrang vor dem Profil.
_PROFILES = {
    # Beratend: scannt und berichtet, blockiert aber nie den Build.
    "advisory": {
        "group": "security", "fail_on": "none",
        "format": "console,json,sarif", "safe_report": True,
    },
    # Empfohlener harter CI/CD-Gate: blockiert ab Schweregrad High.
    "ci": {
        "group": "security", "fail_on": "high",
        "format": "console,json,sarif", "safe_report": True,
        "strict_internal_errors": True,
    },
    # Strengster Gate: ci plus strenge Waiver- und Regelintegritätsprüfung.
    "strict": {
        "group": "security", "fail_on": "high",
        "format": "console,json,sarif", "safe_report": True,
        "strict_internal_errors": True, "strict_waivers": True,
        "require_trusted_rules": True,
    },
    # Vollständige Prüfung (Sicherheit + Coding Guidelines) für ein
    # manuelles Review - mit Quelltext-Kontext, ohne Build-Blockade.
    "audit": {
        "group": "all", "fail_on": "none",
        "format": "console,html", "taint_sources": True,
    },
    # APEX-/ORDS-Review: Sicherheitsgruppe (inkl. APEX/ORDS-Regeln und der
    # APEX-bewussten SQL-Injection-Erkennung) mit Quelltext-Kontext und
    # Taint-Quellen, ohne Build-Blockade - fuer das gezielte Review von
    # APEX-/ORDS-Backend-Code (Oracle).
    "apex": {
        "group": "security", "fail_on": "none",
        "format": "console,html", "taint_sources": True,
    },
}
_SEVERITY_CHOICES = ["info", "minor", "warning", "major",
                     "high", "critical", "blocker"]

# Geheimnis-Wert: ein doppelt-escapter SQL-Literal (``''...''`` - so steht
# ein Literal *innerhalb* von dynamischem SQL), ein normaler Literal (mit
# ``''``-Escapes), ein doppelt-gequoteter Bezeichner oder ein blanker Token.
# Die ``''...''``-Alternative steht zuerst, damit sie den escapten Fall
# vollständig greift, bevor die einfache Literal-Alternative nur das innere
# Leer-Literal sieht.
_SECRET_VALUE = r"(?:''[^']*''|'(?:[^']|'')*'|\"[^\"]*\"|[^\s,;)]+)"
# Wie ``_SECRET_VALUE``, aber NUR die quotierten Alternativen (kein bare
# Token). Wird dort verwendet, wo das Schlüsselwort ohne Zuweisungsoperator
# vor dem Wert steht (z.B. PostgreSQL/EPAS ``PASSWORD 'geheim'``); ein bare
# Token wäre dort mehrdeutig (``SELECT password FROM t`` würde sonst ``FROM``
# verschlucken), daher bewusst auf String-Literale beschränkt.
_QUOTED_SECRET_VALUE = r"(?:''[^']*''|'(?:[^']|'')*'|\"[^\"]*\")"
# Optionaler Konkatenations-Kleber zwischen Schlüsselwort und Wert: ein
# schließendes Quote und/oder ein ``||``. Deckt den Fall ab, dass das
# Schlüsselwort am Ende eines String-Literals steht und der eigentliche
# Wert per ``||`` angehängt wird, z.B. ``... IDENTIFIED BY ' || 'geheim'``.
_SECRET_GLUE = r"(?:'\s*)?(?:\|\|\s*)?"

# Heuristische Geheimnis-Muster für die optionale Redaction des
# Report-Kontexts. Die Liste ist bewusst NICHT vollständig - sie deckt
# häufige Fälle ab (inkl. in dynamisches SQL eingebetteter Literale mit
# ``''``-Escapes und ``||``-Konkatenation) und ersetzt keine echte
# Secrets-Erkennung.
_REDACT_RULES = [
    # Schlüsselwort := / = / => 'Wert' (auch ohne Anführungszeichen,
    # damit z.B. "password=geheim" in Connection-Strings greift; auch
    # ``password => '' || 'geheim'`` in dynamischem SQL).
    # Fuehrende Grenze ``(?<![A-Za-z0-9])`` statt ``\b``: bei den ueblichen
    # PL/SQL-Namenskonventionen steht vor dem Schluesselwort ein ``_``
    # (``v_password``, ``l_pwd``, ``the_token``). ``\bpassword`` matcht dort
    # NICHT, weil ``_`` ein Wortzeichen ist - das Geheimnis bliebe im Klartext.
    # ``(?<![A-Za-z0-9])`` erlaubt ein fuehrendes ``_``/Namenspraefix, das
    # abschliessende ``(?![A-Za-z0-9])`` verhindert Treffer mitten in einem
    # laengeren Wort (``mypwdfield``).
    # Der optionale Teil ``(?:CONSTANT ...)?TYP(...)`` zwischen Schluesselwort
    # und ``:=`` deckt die PL/SQL-Deklarationsform ab
    # (``v_password VARCHAR2(30) := 'geheim'``), bei der ein Typ zwischen Name
    # und Zuweisung steht. Fuer ``=>``/``=`` (Named-Arg/Connection-String) gibt
    # es keinen Typ; der Zwischenteil bleibt dort ungenutzt.
    (re.compile(
        r"(?i)(?<![A-Za-z0-9])(password|passwd|pwd|passphrase|secret|"
        r"client[_-]?secret|token|auth[_-]?token|access[_-]?token|"
        r"refresh[_-]?token|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
        r"private[_-]?key|credentials?)(?![A-Za-z0-9])"
        r"(\s*(?:(?:CONSTANT\s+)?[A-Za-z][\w]*(?:\s*\([^)\n]*\))?\s+)?"
        r"(?::=|=>|=)\s*)"
        + _SECRET_GLUE + r"(" + _SECRET_VALUE + r")"),
     lambda m: f"{m.group(1)}{m.group(2)}'<redacted>'"),
    # Oracle: IDENTIFIED BY <Wert> (auch ``IDENTIFIED BY ' || 'geheim'`` und
    # ``IDENTIFIED BY VALUES '<hash>'``). Ohne das optionale ``VALUES``
    # verschluckt der bare-Token-Zweig von ``_SECRET_VALUE`` nur das Wort
    # ``VALUES`` und liesse den nachfolgenden Hash im Klartext stehen.
    (re.compile(r"(?i)\b(IDENTIFIED\s+BY\s+(?:VALUES\s+)?)" + _SECRET_GLUE
                + r"(?:" + _SECRET_VALUE + r")"),
     lambda m: f"{m.group(1)}<redacted>"),
    # PostgreSQL/EPAS: PASSWORD '<wert>' (Schlüsselwort + Whitespace, KEIN
    # Operator) - z.B. ``CREATE USER u WITH PASSWORD 'x'``,
    # ``CREATE ROLE r LOGIN ENCRYPTED PASSWORD 'x'``,
    # ``ALTER ROLE r UNENCRYPTED PASSWORD 'x'`` sowie FDW-Optionen
    # ``OPTIONS (password 'x')``. Nur quotierte Literale (s.
    # ``_QUOTED_SECRET_VALUE``), damit ``SELECT password FROM t`` nicht
    # fälschlich maskiert wird. Auch der dynamische Fall
    # ``PASSWORD ' || 'geheim'`` wird über ``_SECRET_GLUE`` abgedeckt.
    (re.compile(r"(?i)\b(PASSWORD\s+)" + _SECRET_GLUE
                + r"(?:" + _QUOTED_SECRET_VALUE + r")"),
     lambda m: f"{m.group(1)}<redacted>"),
    # Bearer-Token in Headern/Strings
    (re.compile(r"(?i)\b(bearer\s+)[A-Za-z0-9._\-]{8,}"),
     lambda m: f"{m.group(1)}<redacted>"),
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     lambda _m: "<redacted>"),
]

_SIZE_UNITS = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3}


def _parse_size(text: str) -> int:
    """Wandelt eine Größenangabe (``5MB``, ``500KB``, ``1048576``) in Bytes.

    Unterstützt die Einheiten B, KB, MB, GB. Ohne Einheit gelten Bytes.
    """
    t = str(text).strip().upper().replace(" ", "")
    m = re.match(r"^(\d+(?:\.\d+)?)([KMG]?B)?$", t)
    if not m:
        raise ValueError(
            f"ungültige Größenangabe: {text!r} "
            f"(erlaubt z.B. 1048576, 500KB, 5MB, 1GB)")
    return int(float(m.group(1)) * _SIZE_UNITS[m.group(2) or "B"])


def _build_parser(defaults: dict) -> argparse.ArgumentParser:
    """Baut den Argument-Parser. Die Vorgabewerte stammen aus ``aci.ini``
    (bzw. den werkseitigen Defaults) - ein Kommandozeilen-Schalter
    überschreibt sie."""
    parser = argparse.ArgumentParser(
        prog="aci",
        description="ACI - Automated Code Inspection: statischer "
                    "Sicherheits- und Coding-Guidelines-Scanner für "
                    "Oracle- und PostgreSQL-Code. Vorgabewerte stammen "
                    "aus aci.ini.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("path", nargs="?",
                        help="zu prüfende Datei oder Verzeichnis")
    parser.add_argument("-d", "--dialect", default=defaults["dialect"],
                        choices=["oracle", "postgresql", "postgres"],
                        help="SQL-Dialekt (Default aus aci.ini)")
    parser.add_argument("-g", "--group", default=defaults["group"],
                        choices=["all", "security", "guidelines"],
                        help="zu prüfende Gruppe(n): all, security, "
                             "guidelines (Default aus aci.ini)")
    parser.add_argument("--profile", choices=sorted(_PROFILES),
                        help="CI/CD-Voreinstellung statt langer "
                             "Schalter-Kette: advisory (nur berichten, "
                             "blockiert nie), ci (harter Gate ab High), "
                             "strict (ci + strenge Waiver-/"
                             "Regelintegritätsprüfung), audit "
                             "(vollständige Prüfung für manuelles "
                             "Review). Explizite Schalter haben Vorrang.")
    parser.add_argument("--rules",
                        help="explizite Sicherheits-Regeldatei "
                             "(überschreibt --rules-dir)")
    parser.add_argument("--rules-dir", default=_DEFAULT_RULES_DIR,
                        help="Verzeichnis mit oracle.json / postgresql.json")
    parser.add_argument("--guidelines-dir", default=_DEFAULT_GUIDELINES_BASE,
                        help="Basisverzeichnis der Guideline-Kategoriedateien")
    parser.add_argument("--mitre-dir", default=_DEFAULT_MITRE_BASE,
                        help="Basisverzeichnis der MITRE-Taktikdateien")
    parser.add_argument("-f", "--format", default=defaults["format"],
                        help="Ausgabeformate, kommagetrennt: console, "
                             "json, html, sarif, codeclimate (GitLab "
                             "Code Quality; Default aus aci.ini)")
    parser.add_argument("-o", "--output-dir", default=defaults["output_dir"],
                        help="Zielverzeichnis für JSON-/HTML-Reports "
                             "(Default aus aci.ini)")
    parser.add_argument("--html-group-by", default=defaults["html_group_by"],
                        choices=["rule", "file"],
                        help="Gruppierung der Findings im HTML-Report: "
                             "rule (nach Regel) oder file (nach Datei); "
                             "Default aus aci.ini")
    parser.add_argument("--min-level", default=defaults["min_level"],
                        choices=_SEVERITY_CHOICES,
                        help="nur Findings ab diesem Schweregrad ausgeben "
                             "(Default aus aci.ini)")
    parser.add_argument("--fail-on", default=defaults["fail_on"],
                        choices=["none"] + _SEVERITY_CHOICES,
                        help="Exit-Code 1, wenn Findings >= Schweregrad "
                             "(für CI/CD; Default aus aci.ini)")
    parser.add_argument("--strict-internal-errors",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["strict_internal_errors"],
                        help="Exit-Code 2, wenn ein Check intern fehlschlägt "
                             "(Default aus aci.ini; Gegenschalter "
                             "--no-strict-internal-errors)")
    parser.add_argument("--waivers", metavar="DATEI",
                        default=(defaults["waivers"] or None),
                        help="JSON-Datei mit kontrollierten Ausnahmen "
                             "(Waiver); gewaiverte Findings bleiben "
                             "sichtbar, zählen aber nicht für --fail-on "
                             "(Default aus aci.ini)")
    parser.add_argument("--baseline", metavar="DATEI",
                        help="JSON-Baseline mit bekannten Finding-Finger"
                             "abdrücken; darin enthaltene (bereits bekannte) "
                             "Findings werden unterdrückt, sodass nur NEUE "
                             "Findings gemeldet werden (Adoption auf "
                             "Legacy-Code)")
    parser.add_argument("--write-baseline", metavar="DATEI",
                        help="aktuelle Findings als Baseline-Datei schreiben "
                             "und ohne Gate beenden (Exit 0). Danach meldet "
                             "--baseline nur noch neu hinzugekommene Findings")
    parser.add_argument("--strict-waivers",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["strict_waivers"],
                        help="Exit-Code 2, wenn die Waiver-Datei fehlerhaft "
                             "ist (Default: nur warnen; Gegenschalter "
                             "--no-strict-waivers)")
    parser.add_argument("--require-trusted-rules",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["require_trusted_rules"],
                        help="Exit-Code 2, wenn eine Regeldatei aus einem "
                             "benutzerdefinierten (nicht gebündelten) Pfad "
                             "geladen würde - schützt den CI-Gate vor "
                             "manipulierten Regeln (Gegenschalter "
                             "--no-require-trusted-rules)")
    parser.add_argument("--expected-ruleset-sha256", metavar="SHA256",
                        help="erwarteter SHA256 des aktiven Regelsatzes; bei "
                             "Abweichung Abbruch mit Exit-Code 2 (harte "
                             "Integritätsprüfung für CI/CD). 64 Hex-Zeichen, "
                             "Vergleich case-insensitiv")
    parser.add_argument("--ruleset-lock", metavar="PFAD",
                        help="JSON-Lock-Datei mit Feld 'ruleset_sha256' als "
                             "erwartetem Regelsatz-Hash (Alternative/Ergänzung "
                             "zu --expected-ruleset-sha256)")
    parser.add_argument("--context-lines", type=int,
                        default=defaults["context_lines"], metavar="N",
                        help="Zeilen Quelltext-Kontext pro Finding "
                             "(Default aus aci.ini; 0 = kein Kontext)")
    ctx_grp = parser.add_mutually_exclusive_group()
    ctx_grp.add_argument("--no-context", dest="no_context",
                         action="store_true",
                         default=defaults["no_context"],
                         help="keinen Quelltext-Kontext in den Report "
                              "aufnehmen (entspricht --context-lines 0)")
    ctx_grp.add_argument("--context", dest="no_context", action="store_false",
                         help="Quelltext-Kontext aufnehmen (Gegenschalter zu "
                              "--no-context; überschreibt Profil/Config)")
    parser.add_argument("--redact-secrets",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["redact_secrets"],
                        help="einfache Geheimnis-Muster (password, token, "
                             "...) im Report-Kontext maskieren (Gegenschalter "
                             "--no-redact-secrets)")
    parser.add_argument("--redact-paths",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["redact_paths"],
                        help="absolute Pfade im Report anonymisieren "
                             "(Verzeichnis -> <PATH>, Dateiname bleibt "
                             "erhalten); von --safe-report impliziert "
                             "(Gegenschalter --no-redact-paths)")
    safe_grp = parser.add_mutually_exclusive_group()
    safe_grp.add_argument("--safe-report", dest="safe_report",
                          action="store_true",
                          default=defaults["safe_report"],
                          help="sichere CI-Artefakte: aktiviert --no-context, "
                               "--redact-secrets und --redact-paths gemeinsam")
    safe_grp.add_argument("--unsafe-report", dest="safe_report",
                          action="store_false",
                          help="Gegenschalter zu --safe-report (überschreibt "
                               "Profil/Config)")
    taint_grp = parser.add_mutually_exclusive_group()
    taint_grp.add_argument("--taint-sources", dest="taint_sources",
                           action="store_true",
                           default=defaults["taint_sources"],
                           help="bei SQL-Injection- und dynamischen "
                                "DDL-Findings die Taint-Quelle (aufbauende "
                                "Zuweisungen bzw. Routinenkopf) als "
                                "zusätzliche Fundstelle zeigen (Standard)")
    taint_grp.add_argument("--no-taint-sources", dest="taint_sources",
                           action="store_false",
                           help="die Taint-Quelle bei SQL-Injection- und "
                                "dynamischen DDL-Findings nicht als "
                                "zusätzliche Fundstelle zeigen")
    parser.add_argument("--exclude", action="append", default=[],
                        metavar="MUSTER",
                        help="Datei-/Verzeichnismuster vom Scan ausschließen "
                             "(mehrfach möglich)")
    parser.add_argument("--max-file-size", metavar="GRÖSSE",
                        default=(defaults["max_file_size"] or None),
                        help="Dateien über dieser Größe überspringen "
                             "(z.B. 5MB, 500KB, 1048576)")
    parser.add_argument("--follow-symlinks",
                        action=argparse.BooleanOptionalAction,
                        default=defaults["follow_symlinks"],
                        help="symbolischen Verknüpfungen folgen "
                             "(Default aus aci.ini; Gegenschalter "
                             "--no-follow-symlinks)")
    cfg_grp = parser.add_mutually_exclusive_group()
    cfg_grp.add_argument("--config", metavar="PFAD",
                         help="ausschließlich diese aci.ini laden (fehlt sie "
                              "oder ist sie ungültig: Exit-Code 2)")
    cfg_grp.add_argument("--no-config", action="store_true",
                         help="keine aci.ini laden (weder aus cwd noch aus "
                              "dem Paketpfad); nur Defaults/Profil/CLI nutzen")
    parser.add_argument("--print-effective-config", action="store_true",
                        help="effektive Konfiguration (Defaults + Config + "
                             "Profil + CLI) als JSON ausgeben und beenden")
    parser.add_argument("--no-color", action="store_true",
                        help="Konsolenausgabe ohne Farben")
    parser.add_argument("--debug", action="store_true",
                        help="bei unerwarteten Fehlern den vollen "
                             "Python-Traceback zeigen")
    parser.add_argument("--dump-ir", action="store_true",
                        help="Parser-/IR-Debugausgabe als JSON erzeugen "
                             "und ohne normalen Scan beenden")
    parser.add_argument("--list-checks", action="store_true",
                        help="aktive Checks/Regeln anzeigen und beenden")
    parser.add_argument("--version", action="version",
                        version=f"ACI {__version__}")
    return parser


def _resolve_ruleset_path(args) -> str:
    path = args.rules or find_ruleset(args.dialect, args.rules_dir)
    return str(path)


def _load_guidelines(args, active_groups):
    """Lädt die Guideline-Regeln, falls für Dialekt/Gruppe relevant."""
    if GROUP_GUIDELINES not in active_groups:
        return []
    if not has_guidelines(args.dialect):
        return []
    gdir = find_guidelines_dir(args.dialect, args.guidelines_dir)
    return load_guideline_rules(gdir, args.dialect)


def _load_mitre(args, active_groups):
    """Lädt die MITRE-Angriffsindikatoren (Gruppe Sicherheit).

    Verfügbar für Oracle und PostgreSQL (siehe :func:`aci.rules.has_mitre`);
    für andere Dialekte liefert die Funktion eine leere Liste.
    """
    if GROUP_SECURITY not in active_groups:
        return []
    if not has_mitre(args.dialect):
        return []
    mdir = find_mitre_dir(args.dialect, args.mitre_dir)
    return load_mitre_rules(mdir, args.dialect)


def _collect_rule_files(args, ruleset, guideline_rules, mitre_rules) -> list:
    """Liste der ``(Kategorie, Pfad)``-Paare aller tatsächlich geladenen
    Regeldateien - Grundlage für den Ruleset-Hash der Regelintegrität.

    Erfasst werden der Sicherheits-Regelsatz sowie - sofern geladen -
    die Guideline-Kategoriedateien und die MITRE-Taktikdateien (je
    Datei einmal, ermittelt über das ``_source_file``-Feld der Regeln).
    """
    files = [("security", ruleset.path)]
    if guideline_rules:
        gdir = find_guidelines_dir(args.dialect, args.guidelines_dir)
        for fname in sorted({r.get("_source_file") for r in guideline_rules
                             if r.get("_source_file")}):
            files.append(("guidelines", os.path.join(gdir, fname)))
    if mitre_rules:
        mdir = find_mitre_dir(args.dialect, args.mitre_dir)
        for fname in sorted({r.get("_source_file") for r in mitre_rules
                             if r.get("_source_file")}):
            files.append(("mitre", os.path.join(mdir, fname)))
    return files


def _filter(results: dict, min_weight: int) -> dict:
    """Behält Findings ab dem geforderten Schweregrad - interne Fehler immer."""
    return {
        path: [f for f in findings
               if f.group == GROUP_INTERNAL or f.severity.weight >= min_weight]
        for path, findings in results.items()
    }


_RELOAD_SPECIFIC_IDS = ("ACI-EPAS-AUDIT-CONFIG-RELOAD",
                        "ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE")


def _dedupe_reload_findings(results: dict) -> None:
    """Entfernt die generische ``pg_reload_conf``-Meldung (``ACI-PKG``,
    Warning) auf einer Zeile, auf der bereits eine spezifischere
    EPAS-Audit-Reload-Regel (High/Critical) greift.

    Damit entsteht fuer ``pg_reload_conf()`` genau ein aussagekraeftiges
    Finding statt einer redundanten Low-Value-Doppelmeldung. Andere
    generische ``ACI-PKG``-Findings (andere Funktionen, andere Zeilen)
    bleiben unveraendert. Minimal-invasiv: spezifischer schlaegt generisch.
    """
    for path, findings in results.items():
        specific_lines = {f.line for f in findings
                          if f.check_id in _RELOAD_SPECIFIC_IDS}
        if not specific_lines:
            continue
        results[path] = [
            f for f in findings
            if not (f.check_id == "ACI-PKG" and f.line in specific_lines
                    and "pg_reload_conf" in (f.message or ""))]


def _redact_text(text: str) -> str:
    """Maskiert einfache Geheimnis-Muster in einer Codezeile.

    Heuristisch und bewusst nicht vollständig - reduziert die
    versehentliche Preisgabe von Geheimnissen im Report-Kontext.
    """
    for pattern, repl in _REDACT_RULES:
        text = pattern.sub(repl, text)
    return text


def _redact_text_context(context):
    """Redigiert die Textspalte einer Kontextliste ``[(ln, text, is_find)]``."""
    return [(ln, _redact_text(txt), is_find) for (ln, txt, is_find) in context]


def _redact_results(results: dict) -> None:
    """Maskiert Geheimnisse in Snippet und Kontext aller Findings.

    Erfasst werden Fundort (Sink) *und* die zusätzlichen Fundstellen
    (``related`` - z.B. die Taint-Quellen des SQL-Injection-Checks).
    Letztere tragen eigene ``snippet``/``context``-Felder; würden sie
    übersprungen, könnte ein Geheimnis aus einer Taint-Quell-Zeile trotz
    ``--redact-secrets`` in den Report gelangen.
    """
    for findings in results.values():
        for f in findings:
            if f.snippet:
                f.snippet = _redact_text(f.snippet)
            if f.context:
                f.context = _redact_text_context(f.context)
            for rel in f.related:
                if rel.snippet:
                    rel.snippet = _redact_text(rel.snippet)
                if rel.context:
                    rel.context = _redact_text_context(rel.context)


_ABS_WIN_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _redact_path(path: str) -> str:
    """Anonymisiert einen *absoluten* Pfad: das Verzeichnis wird durch
    ``<PATH>`` ersetzt, der Dateiname bleibt erhalten (z.B.
    ``/home/alex/kunde/a.sql`` -> ``<PATH>/a.sql``,
    ``C:\\Users\\alex\\a.sql`` -> ``<PATH>\\a.sql``,
    ``\\\\server\\share\\a.sql`` -> ``<PATH>\\a.sql``).

    Relative Pfade bleiben unveraendert - sie enthalten keine sensiblen
    absoluten Pfadbestandteile (Benutzername, Kunden-/Projektpfade). Nur
    die Ausgabe wird maskiert; die Scanlogik arbeitet weiter auf dem
    Original.
    """
    if not isinstance(path, str) or not path:
        return path
    is_unc = path.startswith("\\\\") or path.startswith("//")
    is_abs = (path.startswith("/") or is_unc
              or bool(_ABS_WIN_RE.match(path)))
    if not is_abs:
        return path
    # Trennzeichen-bewusst den letzten Bestandteil (Dateiname) bestimmen.
    tail = re.split(r"[\\/]", path.rstrip("\\/"))[-1]
    sep = "\\" if ("\\" in path) else "/"
    if not tail:
        return "<PATH>"
    return f"<PATH>{sep}{tail}"


def _redact_result_paths(results: dict) -> dict:
    """Maskiert absolute Pfade in den Finding-Dateipfaden (Schluessel der
    Ergebnis-Map sowie ``finding.file`` und ``related.file``)."""
    redacted: dict = {}
    for path, findings in results.items():
        for f in findings:
            if getattr(f, "file", None):
                f.file = _redact_path(f.file)
            for rel in getattr(f, "related", []) or []:
                if getattr(rel, "file", None):
                    rel.file = _redact_path(rel.file)
        redacted[_redact_path(path)] = findings
    return redacted


def _print_checks(ruleset, guideline_rules, mitre_rules, active_groups) -> None:
    if GROUP_SECURITY in active_groups:
        print(f"Gruppe 'Sicherheit'  -  Regeldatei: {ruleset.path}")
        print(f"  Dialekt: {ruleset.dialect} (v{ruleset.version})")
        for key, cfg in ruleset.checks.items():
            state = "aktiv  " if cfg.get("enabled") else "inaktiv"
            print(f"    [{state}] {cfg.get('id', '?'):10s} "
                  f"{cfg.get('name', key)}")
        if mitre_rules:
            by_tactic: dict = {}
            for rule in mitre_rules:
                tac = rule.get("tactic", "?")
                by_tactic.setdefault(tac, 0)
                if rule.get("enabled"):
                    by_tactic[tac] += 1
            total = sum(by_tactic.values())
            print(f"  MITRE-ATT&CK-Angriffsindikatoren: {total} aktiv")
            for tac in sorted(by_tactic):
                print(f"    {tac:34s} {by_tactic[tac]:2d}")
    if GROUP_GUIDELINES in active_groups and guideline_rules:
        print()
        src = ("Trivadis PL/SQL & SQL Coding Guidelines"
               if ruleset.dialect == "oracle"
               else "ACI PL/pgSQL Coding Guidelines")
        print(f"Gruppe 'Coding Guidelines'  -  {src}")
        by_cat: dict = {}
        for rule in guideline_rules:
            cat = rule.get("category", "?")
            by_cat.setdefault(cat, [0, 0])
            if rule.get("enabled"):
                by_cat[cat][0] += 1
            else:
                by_cat[cat][1] += 1
        total_on = total_off = 0
        for cat, (on, off) in by_cat.items():
            total_on += on
            total_off += off
            print(f"    {cat:24s} {on:2d} aktiv / "
                  f"{off:2d} dokumentiert (needs-parser)")
        print(f"    {'INSGESAMT':24s} {total_on:2d} aktiv / "
              f"{total_off:2d} dokumentiert")


# Schlüssel der reproduzierbaren Scan-Konfiguration, die der Report als
# Gegenüberstellung "verwendeter Wert" vs. "aci.ini-Default" ausweist -
# bewusst ohne Pfade und ohne sensible Daten.
_CONFIG_KEYS = (
    "profile", "dialect", "group", "format", "min_level", "fail_on",
    "context_lines", "no_context", "redact_secrets", "redact_paths",
    "safe_report", "taint_sources", "follow_symlinks", "max_file_size",
    "html_group_by", "strict_internal_errors", "strict_waivers",
    "require_trusted_rules",
)


class _CliExit(Exception):
    """Vorzeitiger Abbruch eines :func:`_run`-Teilschritts mit Exit-Code.

    Erlaubt es, :func:`_run` in kleine, einzeln nachvollziehbare
    Teilfunktionen zu zerlegen, ohne den Exit-Code durch jede Signatur
    zu fädeln. :func:`main` übersetzt die Ausnahme in den Rückgabewert.
    """

    def __init__(self, code: int):
        super().__init__(f"exit {code}")
        self.code = code


def _dump_ir(args) -> int:
    """Führt ``--dump-ir`` aus: die IR einer einzelnen Datei als JSON."""
    if not os.path.isfile(args.path):
        print("FEHLER: --dump-ir erwartet eine einzelne Datei.",
              file=sys.stderr)
        return 2
    with open(args.path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    ir = parse_ir(text, args.dialect)
    print(json.dumps(ir_to_dict(ir), indent=2, ensure_ascii=False))
    return 0


def _parse_formats(args) -> list:
    """Zerlegt ``--format`` in eine Liste und validiert die Formatnamen.

    Wirft :class:`_CliExit` (Code 2) bei einem unbekannten Format.
    """
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    unknown = [f for f in formats
               if f not in ("console", "json", "html", "sarif",
                            "codeclimate")]
    if unknown:
        print(f"FEHLER: unbekanntes Ausgabeformat: {', '.join(unknown)} "
              f"(erlaubt: console, json, html, sarif, codeclimate)",
              file=sys.stderr)
        raise _CliExit(2)
    return formats


def _resolve_max_file_size(args):
    """Wertet ``--max-file-size`` aus (``None`` = kein Limit)."""
    if not args.max_file_size:
        return None
    try:
        return _parse_size(args.max_file_size)
    except ValueError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        raise _CliExit(2) from None


def _resolve_report_safety(args, formats):
    """Bestimmt die effektiven Report-Sicherheitsoptionen.

    Liefert ``(want_redact, no_context, context_lines)``. ``--safe-report``
    bündelt ``--no-context`` und ``--redact-secrets``; ``--no-context``
    bzw. ``--context-lines 0`` schalten den Quelltext-Kontext ab. Bei
    einem maschinenlesbaren Report mit Kontext, aber ohne Redaction,
    warnt ACI vor einem möglichen Datenschutzrisiko.
    """
    want_redact = args.redact_secrets or args.safe_report
    no_context = (args.no_context or args.safe_report
                  or args.context_lines <= 0)
    context_lines = max(0, args.context_lines)
    if ({"json", "html", "sarif"} & set(formats)) and not no_context \
            and not want_redact:
        print("Warnung: Der Report enthält Quelltext-Kontext und "
              "--redact-secrets ist nicht aktiv. Für sichere CI-Artefakte "
              "--redact-secrets, --no-context oder --safe-report verwenden.",
              file=sys.stderr)
    return want_redact, no_context, context_lines


_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _read_ruleset_lock(path: str) -> str:
    """Liest den erwarteten Ruleset-Hash aus einer JSON-Lock-Datei.

    Fail-closed: fehlende/ungültige Datei oder fehlender/ungültiger
    ``ruleset_sha256`` führen zu Exit-Code 2.
    """
    if not os.path.isfile(path):
        print(f"FEHLER: Ruleset-Lock-Datei nicht gefunden: {path}",
              file=sys.stderr)
        raise _CliExit(2)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"FEHLER: Ruleset-Lock-Datei nicht lesbar ({path}): {exc}",
              file=sys.stderr)
        raise _CliExit(2) from None
    value = str((data or {}).get("ruleset_sha256", "")).strip().lower()
    if not _HEX64_RE.match(value):
        print(f"FEHLER: Ruleset-Lock-Datei {path}: 'ruleset_sha256' fehlt "
              f"oder ist kein gültiger 64-stelliger Hex-Hash.",
              file=sys.stderr)
        raise _CliExit(2)
    return value


def _resolve_expected_ruleset_hash(args):
    """Ermittelt den erwarteten Ruleset-Hash und seine Quelle.

    Liefert ``(expected_hash_lower, source)`` mit ``source`` ``"cli"`` oder
    ``"ruleset_lock"`` - oder ``(None, None)``. Validiert hart (Exit-Code 2):
    ungültiger CLI-Hash (nicht 64 Hex), defekte Lock-Datei, oder Widerspruch,
    wenn beide Quellen einen abweichenden Hash nennen.
    """
    cli_hash = None
    if args.expected_ruleset_sha256:
        cli_hash = str(args.expected_ruleset_sha256).strip().lower()
        if not _HEX64_RE.match(cli_hash):
            print("FEHLER: --expected-ruleset-sha256 muss aus exakt 64 "
                  "Hex-Zeichen bestehen (0-9, a-f).", file=sys.stderr)
            raise _CliExit(2)
    lock_hash = _read_ruleset_lock(args.ruleset_lock) if args.ruleset_lock \
        else None
    if cli_hash and lock_hash and cli_hash != lock_hash:
        print(f"FEHLER: --expected-ruleset-sha256 ({cli_hash}) und "
              f"--ruleset-lock ({lock_hash}) widersprechen sich.",
              file=sys.stderr)
        raise _CliExit(2)
    if cli_hash:
        return cli_hash, "cli"
    if lock_hash:
        return lock_hash, "ruleset_lock"
    return None, None


def _verify_rule_integrity(args, ruleset, guideline_rules, mitre_rules,
                           expected_hash=None, expected_source=None):
    """Berechnet den Ruleset-Hash und prüft Vertrauensstatus + Soll-Hash.

    ``--require-trusted-rules`` bricht (Code 2) ab, wenn eine Regeldatei
    aus einem benutzerdefinierten, nicht gebündelten Pfad stammt. Ist ein
    erwarteter Hash gesetzt (``--expected-ruleset-sha256``/``--ruleset-lock``)
    und weicht der tatsächliche Hash ab, bricht ACI fail-closed (Code 2) ab
    und nennt erwarteten/tatsächlichen Hash sowie die eingeflossenen Dateien.

    Liefert ``(integrity, verification)`` mit ``verification`` =
    ``{actual_sha256, expected_sha256, verified, source}``.
    """
    # Den beim Laden gefuellten Inhalts-Cache mitgeben, damit der Hash ueber
    # exakt die geladenen Bytes gebildet wird (hash what you load, kein
    # TOCTOU-Zweitzugriff auf die Platte).
    integrity = compute_ruleset_integrity(
        _collect_rule_files(args, ruleset, guideline_rules, mitre_rules),
        content_by_realpath=_RULE_CONTENT_CACHE)
    actual = integrity.ruleset_hash.lower()
    verified = False
    if expected_hash is not None:
        if actual != expected_hash:
            names = ", ".join(f.name for f in integrity.files) or "(keine)"
            print("FEHLER: Ruleset-Integritätsprüfung fehlgeschlagen - der "
                  "tatsächliche Regelsatz-Hash weicht vom erwarteten ab.\n"
                  f"  erwartet:     {expected_hash}\n"
                  f"  tatsächlich:  {actual}\n"
                  f"  Quelle:       {expected_source}\n"
                  f"  Regeldateien: {names}", file=sys.stderr)
            raise _CliExit(2)
        verified = True
    if args.require_trusted_rules and not integrity.trusted:
        names = ", ".join(f.name for f in integrity.untrusted_files)
        print(f"FEHLER: --require-trusted-rules ist gesetzt, aber folgende "
              f"Regeldatei(en) stammen aus einem benutzerdefinierten Pfad: "
              f"{names}. Gebündelte Regeln verwenden oder das Flag "
              f"entfernen.", file=sys.stderr)
        raise _CliExit(2)
    if not integrity.trusted:
        print(f"Warnung: {len(integrity.untrusted_files)} Regeldatei(en) "
              f"stammen aus einem benutzerdefinierten Pfad (untrusted). "
              f"Ruleset-Hash: {integrity.ruleset_hash}", file=sys.stderr)
    verification = {
        "actual_sha256": actual,
        "expected_sha256": expected_hash,
        "verified": verified,
        "source": expected_source,
    }
    return integrity, verification


def _invocation_command_line() -> str:
    """Rekonstruiert den ursprünglichen Kommandozeilenaufruf für den Report.

    Verwendet ``sys.argv``; Argumente werden mit ``shlex.quote`` korrekt
    escaped, sodass das Ergebnis ohne Änderung wieder ausführbar ist.
    ``sys.argv[0]`` wird normalisiert: Bei einem Aufruf über
    ``python -m aci`` (``__main__.py``) erscheint ``python -m aci``;
    sonst der reine Basename des Skripts (z.B. ``aci`` oder ``aci.py``).
    """
    argv = list(sys.argv) if sys.argv else []
    if not argv:
        return ""
    prog = os.path.basename(argv[0] or "")
    if prog in ("__main__.py", "__main__"):
        prog_repr = "python -m aci"
    else:
        prog_repr = prog or "aci"
    parts = [prog_repr] + [shlex.quote(a) for a in argv[1:]]
    return " ".join(parts)


def _redact_command_line(command_line: str) -> str:
    """Maskiert absolute Pfad-Token in der rekonstruierten Kommandozeile
    (z.B. das Scan-Ziel oder ``-o /abs/out``), damit sie unter
    ``--redact-paths`` nicht ueber das ``command_line``-Feld des Reports
    leaken. Token-weise via :func:`shlex.split`; nur absolute Pfade werden
    ersetzt, der Rest bleibt unveraendert und re-quotiert."""
    if not command_line:
        return command_line
    try:
        tokens = shlex.split(command_line)
    except ValueError:
        return command_line
    out = [shlex.quote(_redact_path(t)) for t in tokens]
    return " ".join(out)


def _scanner_config(args, no_context: bool, want_redact: bool) -> dict:
    """Effektiv verwendete Scan-Konfiguration für den Report (ohne Pfade).

    ``no_context`` und ``redact_secrets`` sind die *effektiven* Werte
    nach Auflösung von ``--safe-report`` - der Report zeigt damit die
    tatsächliche Wirkung, nicht nur die rohen Schalter.
    """
    values = {
        "profile": args.profile or "",
        "dialect": args.dialect, "group": args.group, "format": args.format,
        "min_level": args.min_level, "fail_on": args.fail_on,
        "context_lines": args.context_lines, "no_context": no_context,
        "redact_secrets": want_redact,
        "redact_paths": args.redact_paths or args.safe_report,
        "safe_report": args.safe_report,
        "taint_sources": args.taint_sources,
        "follow_symlinks": args.follow_symlinks,
        "max_file_size": args.max_file_size or "",
        "html_group_by": args.html_group_by,
        "strict_internal_errors": args.strict_internal_errors,
        "strict_waivers": args.strict_waivers,
        "require_trusted_rules": args.require_trusted_rules,
    }
    return {key: values[key] for key in _CONFIG_KEYS}


def _write_reports(report, formats, args, base: str) -> None:
    """Gibt den Konsolen-Report aus und schreibt die Datei-Reports."""
    if "console" in formats or not formats:
        print(render_console(report, use_color=not args.no_color))
    file_renderers = (("json", render_json), ("html", render_html),
                      ("sarif", render_sarif),
                      ("codeclimate", render_codeclimate))
    # GitLab erwartet fuer das Code-Quality-Artefakt eine .json-Datei.
    extensions = {"codeclimate": "codeclimate.json"}
    for fmt, render in file_renderers:
        if fmt not in formats:
            continue
        os.makedirs(args.output_dir, exist_ok=True)
        ext = extensions.get(fmt, fmt)
        out = os.path.join(args.output_dir, f"aci_report_{base}.{ext}")
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(render(report))
        print(f"{fmt.upper()}-Report geschrieben: {out}")


def _print_runtime_hints(scanner, waiver_report, internal) -> None:
    """Meldet übersprungene Dateien, interne Fehler und wirksame Waiver
    auf der Standard-Fehlerausgabe (rein informativ, kein Exit-Code)."""
    if scanner.skipped_files:
        print(f"Hinweis: {len(scanner.skipped_files)} Datei(en) wegen "
              f"Größenlimit übersprungen.", file=sys.stderr)
        for path, size in scanner.skipped_files[:10]:
            print(f"  übersprungen ({size} Bytes): {path}", file=sys.stderr)
    # Nicht lesbare Dateien/Verzeichnisse sichtbar machen - ein CI-Gate soll
    # nicht stumm ueber ungeprueften Code "bestanden" melden.
    access_errors = getattr(scanner, "access_errors", None)
    if access_errors:
        print(f"WARNUNG: {len(access_errors)} Pfad(e) konnten nicht gelesen "
              f"werden und wurden NICHT geprüft.", file=sys.stderr)
        for path, msg in access_errors[:10]:
            print(f"  nicht geprüft: {path} ({msg})", file=sys.stderr)
    if getattr(scanner, "suppressed_count", 0):
        print(f"Hinweis: {scanner.suppressed_count} Finding(s) durch Inline-"
              f"Direktiven (-- aci:ignore) unterdrückt.", file=sys.stderr)
    if internal:
        print(f"Hinweis: {len(internal)} interne(r) Check-Fehler aufgetreten "
              f"(Gruppe '{GROUP_INTERNAL}').", file=sys.stderr)
    if waiver_report.applied:
        print(f"Hinweis: {waiver_report.applied} Finding(s) durch gültige "
              f"Waiver abgedeckt - sichtbar im Report, zählen nicht für "
              f"--fail-on.", file=sys.stderr)


def _compute_exit_code(args, all_findings, internal, waiver_report) -> int:
    """Bestimmt den Exit-Code aus der Findings-Liste (vor dem Report-Aufbau).

    Strenge Modi (Exit-Code 2) haben Vorrang vor dem ``--fail-on``-Gate
    (Exit-Code 1). Gewaiverte Findings sind durch eine kontrollierte
    Ausnahme gedeckt und zählen nicht für das Gate.
    """
    if args.strict_internal_errors and internal:
        return 2
    if args.strict_waivers and waiver_report.errors:
        print("FEHLER: --strict-waivers ist gesetzt und die Waiver-Datei "
              "ist fehlerhaft.", file=sys.stderr)
        return 2
    if args.fail_on != "none":
        threshold = Severity.parse(args.fail_on).weight
        if any(f.severity.weight >= threshold
               for f in all_findings if not f.waived):
            return 1
    return 0


def _build_runtime(started_at, duration_seconds, want_redact) -> dict:
    """Laufzeit-Metadaten fuer den Report (Audit/CI). Unter ``want_redact``
    (safe-report/redact-secrets) werden umgebungsverratende Pfade (cwd,
    executable) maskiert."""
    return {
        "aci_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "executable": "<redacted>" if want_redact else sys.executable,
        "cwd": "<redacted>" if want_redact else os.getcwd(),
        "started_at_utc": started_at.isoformat(timespec="seconds"),
        "duration_ms": (int(round(duration_seconds * 1000))
                        if duration_seconds is not None else None),
    }


def _build_gate(args, ruleset_verification, exit_code) -> dict:
    """Gate-Metadaten fuer den Report (welche Gate-Regeln galten + Ergebnis)."""
    return {
        "profile": args.profile or None,
        "fail_on": args.fail_on,
        "strict_internal_errors": args.strict_internal_errors,
        "strict_waivers": args.strict_waivers,
        "require_trusted_rules": args.require_trusted_rules,
        "expected_ruleset_sha256": ruleset_verification.get("expected_sha256"),
        "actual_ruleset_sha256": ruleset_verification.get("actual_sha256"),
        "passed": exit_code == 0,
        "exit_code": exit_code,
    }


def _run(args, defaults, config_info) -> int:
    """Eigentliche Programmlogik (von :func:`main` umschlossen).

    Der Ablauf ist in kleine Teilschritte zerlegt: Regeln laden, Formate
    und Optionen prüfen, Regelintegrität verifizieren, scannen, Waiver
    anwenden, Reports schreiben, Exit-Code bestimmen. ``defaults`` sind
    die aus der Config geladenen Vorgabewerte; ``config_info`` beschreibt
    deren Herkunft (Modus/Datei).
    """
    # Effektive Konfiguration für Report und --print-effective-config.
    config_info = {**config_info, "effective": _effective_config(args)}
    if args.print_effective_config:
        print(json.dumps({"config": config_info}, indent=2,
                         ensure_ascii=False, default=str))
        return 0

    active_groups = set(_GROUP_SETS[args.group])

    # Coding Guidelines liegen nur für unterstützte Dialekte vor
    # (Oracle und PostgreSQL).
    if GROUP_GUIDELINES in active_groups and not has_guidelines(args.dialect):
        active_groups.discard(GROUP_GUIDELINES)
        if args.group == "guidelines":
            print(f"Hinweis: Für den Dialekt '{args.dialect}' liegen keine "
                  f"Coding Guidelines vor.", file=sys.stderr)
            return 0

    # Regeln laden (RuleError wird von main() sauber abgefangen).
    ruleset = load_ruleset(_resolve_ruleset_path(args))
    guideline_rules = _load_guidelines(args, active_groups)
    mitre_rules = _load_mitre(args, active_groups)

    if args.list_checks:
        _print_checks(ruleset, guideline_rules, mitre_rules, active_groups)
        return 0

    if not args.path:
        # parser.error beendet mit Exit-Code 2.
        _build_parser(defaults).error(
            "Es muss eine Datei oder ein Verzeichnis angegeben werden.")

    if args.dump_ir:
        return _dump_ir(args)

    # Optionen prüfen und effektive Werte bestimmen (die Teilschritte
    # brechen via _CliExit mit Exit-Code 2 ab, falls etwas ungültig ist).
    formats = _parse_formats(args)
    max_file_size = _resolve_max_file_size(args)
    want_redact, no_context, context_lines = _resolve_report_safety(
        args, formats)
    # Pfadanonymisierung: explizit via --redact-paths oder impliziert durch
    # --safe-report.
    want_redact_paths = args.redact_paths or args.safe_report
    expected_hash, expected_source = _resolve_expected_ruleset_hash(args)
    integrity, ruleset_verification = _verify_rule_integrity(
        args, ruleset, guideline_rules, mitre_rules,
        expected_hash=expected_hash, expected_source=expected_source)

    scanner = Scanner(
        ruleset, guideline_rules, mitre_rules, groups=active_groups,
        report_context=not no_context, context_lines=context_lines,
        show_taint_sources=args.taint_sources,
        exclude=args.exclude, max_file_size=max_file_size,
        follow_symlinks=args.follow_symlinks)

    started_at = datetime.datetime.now(datetime.timezone.utc)
    scan_start = time.monotonic()
    results = scanner.scan_path(args.path)   # FileNotFoundError -> main()
    scan_duration = time.monotonic() - scan_start

    results = _filter(results, Severity.parse(args.min_level).weight)
    # Redundante generische pg_reload_conf-Warnung entfernen, wenn eine
    # spezifischere EPAS-Audit-Reload-Regel dieselbe Zeile meldet (F6).
    _dedupe_reload_findings(results)

    # Baseline: aktuellen Stand festschreiben (und ohne Gate beenden) bzw.
    # bekannte Findings gegenueber einer Baseline unterdruecken.
    if getattr(args, "write_baseline", None):
        try:
            n = write_baseline(args.write_baseline, results)
        except OSError as exc:
            print(f"FEHLER: Baseline konnte nicht geschrieben werden: {exc}",
                  file=sys.stderr)
            raise _CliExit(2)
        print(f"Baseline geschrieben: {args.write_baseline} "
              f"({n} Finding(s), Format v2).")
        return 0
    if getattr(args, "baseline", None):
        try:
            known = load_baseline(args.baseline)
        except BaselineError as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            raise _CliExit(2)
        results, base_suppressed = apply_baseline(results, known)
        if base_suppressed:
            print(f"Hinweis: {base_suppressed} bekannte(s) Finding(s) über "
                  f"die Baseline unterdrückt - es werden nur neue gemeldet.",
                  file=sys.stderr)

    # Waiver anwenden: gültige (nicht abgelaufene) Ausnahmen markieren
    # passende Findings als "Waived" - sie bleiben im Report sichtbar,
    # zählen aber nicht mehr für --fail-on. Abgelaufene Waiver greifen
    # nicht; defekte, abgelaufene, bald fällige und verwaiste Waiver
    # werden als Warnung gemeldet.
    waivers, waiver_errors = load_waivers(args.waivers or "")
    waiver_report = apply_waivers(results, waivers, errors=waiver_errors,
                                  path=args.waivers or "")
    for line in waiver_report.warning_lines():
        print(f"Warnung: {line}", file=sys.stderr)

    if want_redact:
        _redact_results(results)
    if want_redact_paths:
        results = _redact_result_paths(results)

    # Exit-Code (und damit das Gate-Ergebnis) VOR dem Report-Aufbau bestimmen,
    # damit gate.passed/exit_code in den Report einfliessen koennen.
    all_findings = [f for fs in results.values() for f in fs]
    internal = [f for f in all_findings if f.group == GROUP_INTERNAL]
    exit_code = _compute_exit_code(args, all_findings, internal, waiver_report)
    runtime = _build_runtime(started_at, scan_duration,
                             want_redact or want_redact_paths)
    gate = _build_gate(args, ruleset_verification, exit_code)

    # Report-Zielpfad und Config-Dateipfad anonymisieren (nur Ausgabe).
    report_target = os.path.abspath(args.path)
    if want_redact_paths:
        report_target = _redact_path(report_target)
        # Auch den absoluten Regeldatei-Pfad maskieren - er steht sonst roh im
        # JSON-/Console-Report (``ruleset.path``) und verraet trotz aktiver
        # Anonymisierung den Installations-/Deploy-Pfad (ggf. mit Benutzer-
        # namen). Der Scan ist abgeschlossen; die Mutation beeinflusst nur die
        # Ausgabe (Integritaet nutzt ohnehin nur Basenames).
        ruleset.path = _redact_path(ruleset.path)
        config_info = dict(config_info)
        if config_info.get("file"):
            config_info["file"] = _redact_path(config_info["file"])
        # Pfadtragende Felder der effektiven Konfiguration maskieren.
        eff = config_info.get("effective")
        if isinstance(eff, dict):
            eff = dict(eff)
            for k in ("output_dir", "rules_dir", "guidelines_dir",
                      "mitre_dir", "rules", "waivers"):
                if eff.get(k):
                    eff[k] = _redact_path(eff[k])
            config_info["effective"] = eff

    # Reproduzierbare Scan-Konfiguration für Audit/CI: scanner_config =
    # effektiv verwendete Werte, scanner_defaults = aci.ini-Vorgaben.
    # Der Report stellt beide gegenüber (Spalten "Wert" und "Default").
    report = ScanReport(results, ruleset, report_target,
                        active_groups=active_groups,
                        guideline_rules=guideline_rules,
                        scanner_config=_scanner_config(
                            args, no_context, want_redact),
                        scanner_defaults={k: defaults.get(k, "")
                                          for k in _CONFIG_KEYS},
                        scanned_bytes=scanner.scanned_bytes,
                        scanned_loc=scanner.scanned_loc,
                        duration=scan_duration,
                        html_group_by=args.html_group_by,
                        waiver_report=waiver_report,
                        integrity=integrity,
                        ruleset_verification=ruleset_verification,
                        config_info=config_info,
                        runtime=runtime, gate=gate,
                        command_line=(
                            _redact_command_line(_invocation_command_line())
                            if want_redact_paths
                            else _invocation_command_line()))

    base = (os.path.splitext(os.path.basename(args.path.rstrip("/\\")))[0]
            or "aci")
    _write_reports(report, formats, args, base)

    _print_runtime_hints(scanner, waiver_report, internal)
    return exit_code


def _preparse(argv):
    """Liest ``--profile``/``--config``/``--no-config`` vorab aus ``argv``.

    Diese drei müssen vor dem Hauptparser bekannt sein, weil sie bestimmen,
    welche Config-Datei (und damit welche Defaults) der Hauptparser nutzt.
    Ungültige Werte beanstandet später der Hauptparser.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--profile")
    pre.add_argument("--config")
    pre.add_argument("--no-config", action="store_true")
    known, _ = pre.parse_known_args(argv)
    return known


def _resolve_config(pre):
    """Bestimmt Defaults + Config-Herkunft gemäß --config/--no-config.

    Fail-closed: ``--config`` + ``--no-config`` zusammen sowie eine fehlende
    oder ungültige explizite Config-Datei führen zu Exit-Code 2 (Letzteres
    über :class:`ConfigError` aus :func:`load_defaults`). Liefert
    ``(defaults, config_info)`` mit ``config_info = {mode, file}``.
    """
    if pre.config and pre.no_config:
        print("FEHLER: --config und --no-config schließen sich gegenseitig "
              "aus.", file=sys.stderr)
        raise _CliExit(2)
    if pre.no_config:
        return dict(BUILTIN_DEFAULTS), {"mode": "disabled", "file": None}
    if pre.config:
        defaults = load_defaults(pre.config)       # ConfigError -> Exit 2
        return defaults, {"mode": "explicit",
                          "file": os.path.abspath(pre.config)}
    found = find_config()
    if found:
        return load_defaults(found), {"mode": "auto",
                                      "file": os.path.abspath(found)}
    return dict(BUILTIN_DEFAULTS), {"mode": "auto", "file": None}


_EFFECTIVE_KEYS = (
    "dialect", "group", "profile", "format", "output_dir", "html_group_by",
    "min_level", "fail_on", "context_lines", "no_context", "redact_secrets",
    "redact_paths", "safe_report", "taint_sources", "follow_symlinks",
    "max_file_size", "strict_internal_errors", "strict_waivers",
    "require_trusted_rules",
    "waivers", "exclude", "rules", "rules_dir", "guidelines_dir", "mitre_dir",
    "expected_ruleset_sha256", "ruleset_lock", "no_color",
)


def _effective_config(args) -> dict:
    """Effektive Konfiguration nach Defaults/Config/Profil/CLI-Overrides.

    Enthält ausschließlich Steuer-/Pfadangaben - keine Secrets. (Die
    Konfiguration von ACI trägt keine Geheimnisse; daher ist hier nichts zu
    redaktieren.)

    Wichtig: ``no_context``/``redact_secrets``/``redact_paths`` werden als
    *effektive* Werte ausgegeben - ``--safe-report`` bündelt alle drei und
    ``--context-lines 0`` impliziert ``no_context``. So zeigt
    ``--print-effective-config`` exakt das Verhalten, das auch der echte
    Report (und damit ein CI-Gate mit ``--profile ci``/``strict``) anwendet,
    statt der rohen argparse-Schalter.
    """
    eff = {k: getattr(args, k, None) for k in _EFFECTIVE_KEYS}
    safe = bool(getattr(args, "safe_report", False))
    raw_no_ctx = bool(getattr(args, "no_context", False))
    ctx_lines = getattr(args, "context_lines", 0) or 0
    eff["no_context"] = raw_no_ctx or safe or ctx_lines <= 0
    eff["redact_secrets"] = bool(getattr(args, "redact_secrets", False)) or safe
    eff["redact_paths"] = bool(getattr(args, "redact_paths", False)) or safe
    return eff


def main(argv=None) -> int:
    pre = _preparse(argv)
    try:
        defaults, config_info = _resolve_config(pre)
    except ConfigError as exc:
        print(f"FEHLER: Konfiguration ungültig:\n  {exc}", file=sys.stderr)
        return 2
    except _CliExit as exc:
        return exc.code
    # CI/CD-Profil als Vorgabe-Schicht über die Config-Werte legen. Die
    # expliziten Schalter überschreiben das Profil danach automatisch
    # (argparse nutzt einen Default nur, wenn der Schalter fehlt; für
    # Booleans liefern die --no-*-Gegenschalter den expliziten False-Wert).
    parser_defaults = dict(defaults)
    if pre.profile in _PROFILES:
        parser_defaults.update(_PROFILES[pre.profile])
    parser = _build_parser(parser_defaults)
    args = parser.parse_args(argv)
    try:
        return _run(args, defaults, config_info)
    except _CliExit as exc:
        # Geordneter Abbruch aus einem _run-Teilschritt (Exit-Code 2).
        return exc.code
    except RuleError as exc:
        print(f"FEHLER: Regelvalidierung fehlgeschlagen:\n  {exc}",
              file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"FEHLER: Zugriff verweigert: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        # Sonstige Datei-/IO-Fehler (FileNotFoundError/PermissionError sind
        # oben bereits abgedeckt) klar melden statt als "unerwartet".
        print(f"FEHLER: Datei- oder Zugriffsfehler: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:                       # pragma: no cover
        print("Abgebrochen.", file=sys.stderr)
        return 130
    except Exception as exc:                        # pragma: no cover
        if getattr(args, "debug", False):
            raise
        print(f"FEHLER (unerwartet): {type(exc).__name__}: {exc}\n"
              f"Mit --debug erscheint der vollständige Traceback.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
