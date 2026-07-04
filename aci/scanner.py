"""Scanner-Engine: orchestriert die Checks für Dateien und Verzeichnisse.

Neben der eigentlichen Analyse übernimmt der Scanner zwei Schutz-
funktionen für den rekursiven Verzeichnis-Scan:

* **Exclude-Muster und Größenlimit** - Build-Artefakte, Tool-Caches und
  übergroße Dateien werden ausgelassen, Symlinks werden nicht blind
  verfolgt.
* **Interne Fehlerbehandlung** - schlägt ein Check selbst fehl, wird das
  als ``ACI-INTERNAL``-Finding der Gruppe *Interner Fehler* sichtbar
  gemacht, statt es als gewöhnliches Code-Finding zu tarnen.
"""

from __future__ import annotations

import fnmatch
import os

from .checks import build_checks, build_guideline_checks, build_mitre_checks
from .finding import (Finding, Severity, GROUP_SECURITY, GROUP_GUIDELINES,
                      GROUP_INTERNAL, INTERNAL_CHECK_ID)
from .rules import RuleSet
from .source import Source
from .suppressions import apply_suppressions


# Verzeichnisse, die beim rekursiven Scan standardmäßig übersprungen
# werden - Versionsverwaltung, Build-Artefakte und Werkzeug-Caches.
DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "target", "dist", "build", "node_modules",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".idea", ".eggs",
)


def _decode_source_bytes(raw: bytes) -> str:
    """Dekodiert Quelltext-Bytes und erkennt dabei die haeufigen BOM-Kodie-
    rungen.

    Ohne BOM-Behandlung bleibt ein UTF-8-BOM (``\\ufeff``) im Text stehen und
    stoert ``^``-verankerte Regexe (erstes Statement, SQL*Plus-Maskierung);
    UTF-16-Dumps (bei Windows-Tools ueblich) wuerden mit ``utf-8`` zu
    Ersetzungszeichen-Brei und die Datei scheinbar "sauber" (0 Findings)
    durchlaufen - ein Angreifer koennte damit den Scanner blenden.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw.decode("utf-8-sig", errors="replace")
    if raw.startswith(b"\xff\xfe\x00\x00") or raw.startswith(b"\x00\x00\xfe\xff"):
        return raw.decode("utf-32", errors="replace")
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8", errors="replace")


def _count_lines(text: str) -> int:
    """Zählt die physischen Zeilen (LOC) eines Quelltexts.

    Eine letzte Zeile ohne abschließenden Zeilenumbruch wird mitgezählt.
    """
    if not text:
        return 0
    return text.count("\n") + (0 if text.endswith("\n") else 1)


def _matches_exclude(rel_path: str, patterns) -> bool:
    """True, wenn ein relativer Pfad auf ein Exclude-Muster passt.

    Geprüft wird gegen jeden einzelnen Pfadbestandteil und gegen den
    gesamten relativen Pfad (glob-Syntax über :mod:`fnmatch`).
    """
    norm = rel_path.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    for pat in patterns:
        if fnmatch.fnmatch(norm, pat):
            return True
        if any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
    return False


class Scanner:
    """Führt die aktiven Checks beider Prüfgruppen aus.

    * Gruppe **Sicherheit**        - die fünf Sicherheits-Checks
    * Gruppe **Coding Guidelines** - PL/SQL-/PL/pgSQL-Guideline-Regeln
      (Oracle nach Trivadis, PostgreSQL ACI-eigene Regeln)
    """

    def __init__(self, ruleset: RuleSet, guideline_rules=None,
                 mitre_rules=None, groups=None, *,
                 report_context: bool = True, context_lines: int = 3,
                 show_taint_sources: bool = True,
                 exclude=None, max_file_size=None,
                 follow_symlinks: bool = False):
        self.ruleset = ruleset
        self.guideline_rules = guideline_rules or []
        self.mitre_rules = mitre_rules or []
        self.active_groups = (set(groups) if groups
                              else {GROUP_SECURITY, GROUP_GUIDELINES})
        self.report_context = report_context
        self.context_lines = context_lines
        self.show_taint_sources = show_taint_sources
        # Default-Excludes plus die vom Aufrufer ergänzten Muster.
        self.exclude = list(DEFAULT_EXCLUDES) + list(exclude or [])
        self.max_file_size = max_file_size
        self.follow_symlinks = follow_symlinks
        # Dateien, die wegen des Größenlimits übersprungen wurden.
        self.skipped_files: list = []
        # Nicht lesbare Dateien/Verzeichnisse (Rechte, I/O) beim
        # Verzeichnis-Scan: (Pfad, Fehlermeldung). Sichtbar als Hinweis,
        # damit ein CI-Gate nicht stumm ueber ungeprueften Code hinweggeht.
        self.access_errors: list = []
        # Anzahl per Inline-Direktive (``-- aci:ignore``) unterdrueckter
        # Findings im letzten scan_path()-Lauf (Hinweis-Ausgabe).
        self.suppressed_count: int = 0
        # Kennzahlen des letzten scan_path()-Laufs (für den Report).
        self.scanned_bytes: int = 0
        self.scanned_loc: int = 0
        # Wurzelverzeichnis des laufenden Scans - Grundlage des
        # repo-relativen Pfades im Finding-Fingerabdruck. Wird in
        # scan_path() gesetzt; bei direktem scan_text() bleibt es None.
        self._scan_root: "str | None" = None

        self.checks = []
        if GROUP_SECURITY in self.active_groups:
            self.checks.extend(build_checks(ruleset))
            # MITRE-ATT&CK-Angriffsindikatoren gehören zur Gruppe Sicherheit.
            if self.mitre_rules:
                self.checks.extend(
                    build_mitre_checks(self.mitre_rules, ruleset.dialect))
        if GROUP_GUIDELINES in self.active_groups and self.guideline_rules:
            self.checks.extend(
                build_guideline_checks(self.guideline_rules, ruleset.dialect))

        # Report-Kontext-Einstellung an alle Checks durchreichen.
        for chk in self.checks:
            chk.report_context = self.report_context
            chk.context_lines = self.context_lines
            chk.show_taint_sources = self.show_taint_sources

    # ------------------------------------------------------------------
    def scan_text(self, text: str, filename: str) -> list[Finding]:
        """Untersucht einen Quelltext und liefert die Findings.

        Schlägt ein einzelner Check fehl, stoppt das den Scan nicht: der
        Fehler wird als ``ACI-INTERNAL``-Finding (Gruppe *Interner
        Fehler*, Schweregrad High) festgehalten.
        """
        try:
            source = Source(text, filename, self.ruleset.dialect,
                            scan_root=self._scan_root)
        except Exception as exc:
            # Schon der IR-/Source-Aufbau kann bei pathologischem Input
            # scheitern (z.B. RecursionError bei extrem tief verschachtelten
            # Ausdruecken). Das darf den Scan der ganzen Datei/des
            # Verzeichnisses NICHT abbrechen - als internes Finding melden.
            return [self._internal_finding(None, filename, exc)]
        findings: list[Finding] = []
        for check in self.checks:
            try:
                findings.extend(check.run(source))
            except Exception as exc:  # ein fehlerhafter Check stoppt nicht alles
                findings.append(self._internal_finding(check, filename, exc))
        findings = self._dedupe(findings)
        # Inline-Suppression (``-- aci:ignore``) direkt am Code anwenden -
        # ausschliesslich in echten Kommentarbereichen (aus dem Lexer), damit
        # eine identische Zeichenfolge in einem String-Literal keine
        # Suppression ausloest.
        findings, suppressed = apply_suppressions(findings, source)
        self.suppressed_count += len(suppressed)
        return findings

    @staticmethod
    def _internal_finding(check, filename: str, exc: Exception) -> Finding:
        """Erzeugt ein Finding für einen fehlgeschlagenen Check."""
        name = getattr(check, "name", "Check")
        cid = getattr(check, "id", "?")
        return Finding(
            check_id=INTERNAL_CHECK_ID,
            check_name=f"Interner Fehler ({name})",
            group=GROUP_INTERNAL,
            severity=Severity.HIGH,
            file=filename,
            line=1,
            column=1,
            message=(f"Interner Fehler im Check '{name}' [{cid}]: "
                     f"{type(exc).__name__}: {exc}. Dies ist ein "
                     f"Werkzeugfehler, kein Code-Finding."),
            recommendation=("Dieses Finding weist auf einen Fehler in ACI "
                            "selbst oder in einer Regeldatei hin - bitte als "
                            "ACI-Fehler melden, nicht als Code-Mangel werten."),
            rule_ref=cid,
        )

    def scan_file(self, path: str) -> list[Finding]:
        """Untersucht eine einzelne Datei.

        Nebenbei werden die Kennzahlen ``scanned_bytes`` und
        ``scanned_loc`` fortgeschrieben - die Reset-Stelle ist
        :meth:`scan_path`.
        """
        with open(path, "rb") as fh:
            text = _decode_source_bytes(fh.read())
        try:
            self.scanned_bytes += os.path.getsize(path)
        except OSError:
            self.scanned_bytes += len(text.encode("utf-8", errors="replace"))
        self.scanned_loc += _count_lines(text)
        return self.scan_text(text, path)

    def scan_path(self, path: str) -> dict[str, list[Finding]]:
        """Untersucht eine Datei oder rekursiv ein ganzes Verzeichnis.

        Beim Verzeichnis-Scan greifen Exclude-Muster, das Größenlimit und
        der Symlink-Schutz. Eine explizit angegebene Einzeldatei wird
        dagegen immer untersucht.
        """
        results: dict[str, list[Finding]] = {}
        self.skipped_files = []
        self.access_errors = []
        self.suppressed_count = 0
        self.scanned_bytes = 0
        self.scanned_loc = 0
        # Scan-Wurzel für den repo-relativen Fingerabdruck-Pfad: bei
        # einem Verzeichnis-Scan das Verzeichnis selbst, bei einer
        # Einzeldatei deren Verzeichnis.
        self._scan_root = (path if os.path.isdir(path)
                           else os.path.dirname(path))
        if os.path.isdir(path):
            for root, dirs, files in os.walk(
                    path, followlinks=self.follow_symlinks,
                    onerror=self._on_walk_error):
                # Ausgeschlossene Verzeichnisse aus der Rekursion entfernen.
                dirs[:] = [
                    d for d in sorted(dirs)
                    if not _matches_exclude(
                        os.path.relpath(os.path.join(root, d), path),
                        self.exclude)
                ]
                for name in sorted(files):
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, path)
                    ext = os.path.splitext(name)[1].lower()
                    if ext not in self.ruleset.file_extensions:
                        continue
                    if _matches_exclude(rel, self.exclude):
                        continue
                    if (not self.follow_symlinks
                            and os.path.islink(full)):
                        continue
                    if self._too_large(full):
                        continue
                    try:
                        results[full] = self.scan_file(full)
                    except OSError as exc:
                        # Nicht lesbare Einzeldatei im Baum: vermerken und
                        # weiterlaufen (nicht den ganzen Scan abbrechen).
                        self.access_errors.append((full, str(exc)))
        elif os.path.isfile(path):
            results[path] = self.scan_file(path)
        else:
            raise FileNotFoundError(f"Pfad nicht gefunden: {path}")
        return results

    def _on_walk_error(self, exc: OSError) -> None:
        """Callback fuer :func:`os.walk`: nicht betretbare Verzeichnisse
        (Rechte, I/O) vermerken, statt sie stumm zu ueberspringen."""
        self.access_errors.append(
            (getattr(exc, "filename", None) or "?", str(exc)))

    def _too_large(self, path: str) -> bool:
        """True, wenn die Datei das Größenlimit überschreitet (und merkt sie vor)."""
        if self.max_file_size is None:
            return False
        try:
            size = os.path.getsize(path)
        except OSError:
            return False
        if size > self.max_file_size:
            self.skipped_files.append((path, size))
            return True
        return False

    # ------------------------------------------------------------------
    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        """Entfernt identische Findings und sortiert nach Datei/Schweregrad."""
        seen: set = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.check_id, finding.group, finding.file,
                   finding.line, finding.column, finding.message)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        unique.sort(key=lambda f: f.sort_key())
        return unique
