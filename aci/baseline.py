"""Baseline-/Diff-Modus: nur *neue* Findings gegenueber einem gespeicherten
Stand melden.

Auf gewachsenem Legacy-Code liefert ein Security-Scanner beim ersten Lauf
oft hunderte Findings - zu viele, um ein Gate scharf zu schalten. Der
Baseline-Modus loest das: ``--write-baseline`` schreibt die aktuellen
Findings (ueber ihre inhaltsgebundenen Fingerabdruecke) als akzeptierten
Ausgangsstand fest; ``--baseline`` unterdrueckt bei spaeteren Laeufen genau
diese bekannten Findings, sodass nur **neu hinzugekommene** gemeldet werden
und fuers Gate zaehlen.

Die Bindung erfolgt ueber :attr:`aci.finding.Finding.fingerprint` - denselben
inhaltsgebundenen Hash, den auch die Waiver nutzen. Er ist unabhaengig von
absolutem Pfad und Report-Kontext, sodass eine Baseline zwischen CI-Laeufen
stabil bleibt, solange sich der beanstandete Code nicht aendert.

**Multiset-Semantik (ACI 2.22.1).** Da der Fingerabdruck keine Zeilennummer
enthaelt, koennen zwei identische Befunde in einer Datei denselben
Fingerabdruck haben. Die Baseline fuehrt daher **je Fingerabdruck eine
Anzahl** (Counter): sind in der Baseline *k* Vorkommen bekannt und treten
aktuell *m* auf, gelten genau ``min(k, m)`` als bekannt; die uebrigen
``max(0, m - k)`` bleiben als neue Findings sichtbar. Wird verwundbarer
Code also an eine zweite Stelle kopiert, meldet ACI die neue Instanz.

**Format.** Geschrieben wird Version 2::

    {
      "baseline_version": 2,
      "generated_by": "ACI 2.22.1",
      "findings": { "<fingerprint>": 1, "<fingerprint2>": 3 }
    }

Legacy-Dateien aus ACI 2.22.0 (``{"fingerprints": [...]}`` bzw. eine blanke
JSON-Liste) bleiben lesbar; dort zaehlt jedes Vorkommen als eins.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import tempfile
from collections import Counter

from ._version import __version__

# Aktuell geschriebene Version; unterstuetzte Lese-Versionen.
BASELINE_VERSION = 2
_SUPPORTED_VERSIONS = frozenset({1, 2})

# Fingerabdruck = 16 Hex-Zeichen (sha256[:16], siehe finding.compute_fingerprint).
_FP_RE = re.compile(r"^[0-9a-fA-F]{16}$")

# Missbrauchsschranken (Schutz vor absurd grossen/praeparierten Dateien).
_MAX_ENTRIES = 1_000_000
_MAX_COUNT = 10_000_000


class BaselineError(Exception):
    """Fehler beim Laden/Validieren einer Baseline-Datei."""


# ----------------------------------------------------------------------
# Sammeln / Schreiben
# ----------------------------------------------------------------------

def collect_fingerprints(results: "dict") -> "Counter[str]":
    """Zaehlt die Fingerabdruecke aller Findings (Multiset)."""
    counts: "Counter[str]" = Counter()
    for findings in results.values():
        for f in findings:
            fp = getattr(f, "fingerprint", "") or ""
            if fp:
                counts[fp] += 1
    return counts


def _atomic_write_text(path: str, payload: str) -> None:
    """Schreibt ``payload`` atomar nach ``path``.

    Temporaerdatei im Zielverzeichnis, ``flush``+``fsync``, dann
    ``os.replace`` (atomar auf POSIX und Windows). Bei Fehlern wird die
    Temporaerdatei entfernt; eine vorhandene Zieldatei bleibt bis zum
    erfolgreichen Replace unveraendert. Bestehende Dateirechte werden
    - soweit vorhanden - uebernommen.
    """
    target_dir = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(target_dir, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target_dir, prefix=".aci-baseline-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        # Rechte einer bereits vorhandenen Zieldatei uebernehmen.
        if os.path.exists(path):
            with contextlib.suppress(OSError):
                os.chmod(tmp, os.stat(path).st_mode & 0o777)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(tmp)
        raise


def write_baseline(path: str, results: "dict") -> int:
    """Schreibt die aktuelle Baseline (Format v2) atomar.

    Liefert die Gesamtzahl der festgeschriebenen Findings (Summe ueber die
    Counter). Die Ausgabe ist deterministisch (Fingerabdruecke sortiert) und
    endet mit einem Zeilenumbruch.
    """
    counts = collect_fingerprints(results)
    data = {
        "baseline_version": BASELINE_VERSION,
        "generated_by": f"ACI {__version__}",
        "findings": {fp: counts[fp] for fp in sorted(counts)},
    }
    payload = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    _atomic_write_text(path, payload)
    return int(sum(counts.values()))


# ----------------------------------------------------------------------
# Laden / Validieren
# ----------------------------------------------------------------------

def _valid_fingerprint(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BaselineError(
            f"Fingerabdruck muss ein nicht-leerer String sein: {value!r}.")
    fp = value.strip()
    if not _FP_RE.match(fp):
        raise BaselineError(
            f"Fingerabdruck {fp!r} hat nicht das erwartete Format "
            f"(16 Hex-Zeichen).")
    return fp.lower()


def _valid_count(value) -> int:
    # bool ist eine int-Unterklasse - ausdruecklich ablehnen.
    if isinstance(value, bool) or not isinstance(value, int):
        raise BaselineError(
            f"'count' muss eine positive Ganzzahl sein: {value!r}.")
    if value < 1:
        raise BaselineError(
            f"'count' muss >= 1 sein: {value!r}.")
    if value > _MAX_COUNT:
        raise BaselineError(
            f"'count' {value} ueberschreitet das Maximum {_MAX_COUNT}.")
    return value


def _counter_from_findings(findings) -> "Counter[str]":
    """Baut den Counter aus dem ``findings``-Feld (Dict oder Liste, v2)."""
    counts: "Counter[str]" = Counter()
    items: "list[tuple]" = []
    if isinstance(findings, dict):
        items = list(findings.items())
    elif isinstance(findings, list):
        for entry in findings:
            if not isinstance(entry, dict):
                raise BaselineError(
                    "Baseline-'findings'-Liste erwartet Objekte mit "
                    "'fingerprint' und 'count'.")
            items.append((entry.get("fingerprint"), entry.get("count", 1)))
    else:
        raise BaselineError(
            "Baseline-'findings' muss ein Objekt oder eine Liste sein.")
    for fp, count in items:
        counts[_valid_fingerprint(fp)] += _valid_count(count)
        if len(counts) > _MAX_ENTRIES:
            raise BaselineError(
                f"Baseline enthaelt mehr als {_MAX_ENTRIES} Eintraege.")
    return counts


def _counter_from_fingerprint_list(values) -> "Counter[str]":
    """Legacy (2.22.0): blanke Fingerabdruck-Liste; jedes Vorkommen zaehlt."""
    counts: "Counter[str]" = Counter()
    for v in values:
        counts[_valid_fingerprint(v)] += 1
        if len(counts) > _MAX_ENTRIES:
            raise BaselineError(
                f"Baseline enthaelt mehr als {_MAX_ENTRIES} Eintraege.")
    return counts


def load_baseline(path: str) -> "Counter[str]":
    """Laedt und validiert eine Baseline-Datei; liefert einen Counter.

    Unterstuetzt das Format v2 (``{"baseline_version": 2, "findings":
    {...}}`` bzw. Liste von ``{"fingerprint", "count"}``) sowie die
    Legacy-Formate aus 2.22.0 (``{"fingerprints": [...]}`` und blanke Liste).
    Wirft :class:`BaselineError` fail-closed bei fehlender, fehlerhafter oder
    zukuenftig-versionierter Datei - eine defekte Baseline wird **nicht**
    stillschweigend wie eine leere behandelt.
    """
    if not os.path.isfile(path):
        raise BaselineError(f"Baseline-Datei nicht gefunden: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise BaselineError(f"Baseline-Datei nicht lesbar ({path}): {exc}")

    # Legacy: blanke JSON-Liste von Fingerabdruecken.
    if isinstance(data, list):
        return _counter_from_fingerprint_list(data)

    if not isinstance(data, dict):
        raise BaselineError(
            f"Baseline-Datei {path}: erwartet ein JSON-Objekt oder eine Liste.")

    version = data.get("baseline_version")
    if version is None:
        # Legacy 2.22.0-Objekt ohne Versionsfeld: benoetigt 'fingerprints'.
        if "fingerprints" in data:
            fps = data["fingerprints"]
            if not isinstance(fps, list):
                raise BaselineError(
                    f"Baseline-Datei {path}: 'fingerprints' muss eine Liste "
                    f"sein.")
            return _counter_from_fingerprint_list(fps)
        raise BaselineError(
            f"Baseline-Datei {path}: 'baseline_version' fehlt und kein "
            f"bekanntes Legacy-Format ('fingerprints').")

    if isinstance(version, bool) or not isinstance(version, int):
        raise BaselineError(
            f"Baseline-Datei {path}: 'baseline_version' muss eine Ganzzahl "
            f"sein (gefunden: {version!r}).")
    if version not in _SUPPORTED_VERSIONS:
        raise BaselineError(
            f"Baseline-Datei {path}: nicht unterstuetzte 'baseline_version' "
            f"{version} (unterstuetzt: {sorted(_SUPPORTED_VERSIONS)}).")

    # Version 1: Legacy-Objekt mit 'fingerprints'. Version 2: 'findings'.
    if version == 1:
        fps = data.get("fingerprints", [])
        if not isinstance(fps, list):
            raise BaselineError(
                f"Baseline-Datei {path}: 'fingerprints' muss eine Liste sein.")
        return _counter_from_fingerprint_list(fps)

    if "findings" not in data:
        raise BaselineError(
            f"Baseline-Datei {path}: Feld 'findings' fehlt (Version 2).")
    return _counter_from_findings(data["findings"])


# ----------------------------------------------------------------------
# Anwenden
# ----------------------------------------------------------------------

def apply_baseline(results: "dict", known: "Counter[str]"):
    """Entfernt bekannte Findings gemaess Multiset ``known`` aus ``results``.

    Liefert ``(filtered_results, suppressed_count)``. Je Fingerabdruck werden
    hoechstens so viele aktuelle Findings unterdrueckt, wie die Baseline
    Vorkommen kennt; weitere identische Findings bleiben sichtbar.
    ``ACI-INTERNAL`` (Werkzeugfehler) wird nie unterdrueckt. Deterministisch
    ueber die nach Pfad sortierte Verarbeitung.
    """
    remaining: "Counter[str]" = Counter(known)
    filtered: dict = {}
    suppressed = 0
    for path in sorted(results):
        kept = []
        for f in results[path]:
            fp = (getattr(f, "fingerprint", "") or "").lower()
            if (fp and remaining.get(fp, 0) > 0
                    and getattr(f, "check_id", "") != "ACI-INTERNAL"):
                remaining[fp] -= 1
                suppressed += 1
                continue
            kept.append(f)
        filtered[path] = kept
    return filtered, suppressed
