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
from .suppressions import apply_suppressions, governance_problems


# Verzeichnisse, die beim rekursiven Scan standardmäßig übersprungen
# werden - Versionsverwaltung, Build-Artefakte und Werkzeug-Caches.
DEFAULT_EXCLUDES = (
    ".git", ".hg", ".svn", "target", "dist", "build", "node_modules",
    ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".idea", ".eggs",
)


def _detect_encoding(raw: bytes) -> str:
    """Bestimmt die zu verwendende Kodierung anhand eines BOM (Default utf-8)."""
    if raw.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if raw.startswith(b"\xff\xfe\x00\x00") or raw.startswith(b"\x00\x00\xfe\xff"):
        return "utf-32"
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        return "utf-16"
    return "utf-8"


def decode_source_bytes(raw: bytes, encoding: "str | None" = None,
                        errors: str = "replace") -> "tuple[str, str, bool]":
    """Dekodiert Quelltext-Bytes und meldet Kodierung + Dekodierprobleme.

    Ohne BOM-Behandlung bleibt ein UTF-8-BOM (``\\ufeff``) im Text stehen und
    stoert ``^``-verankerte Regexe (erstes Statement, SQL*Plus-Maskierung);
    UTF-16-Dumps (bei Windows-Tools ueblich) wuerden mit ``utf-8`` zu
    Ersetzungszeichen-Brei und die Datei scheinbar "sauber" (0 Findings)
    durchlaufen - ein Angreifer koennte damit den Scanner blenden.

    ``encoding`` erzwingt eine Kodierung (``--encoding``); ``None`` = Auto
    (BOM-Erkennung, sonst utf-8). ``errors`` ist die Fehlerstrategie
    (``replace`` = Ersatzzeichen, ``strict`` = :class:`UnicodeDecodeError`).

    Rueckgabe: ``(text, used_encoding, had_replacements)``. ``had_replacements``
    ist ``True``, wenn beim ``replace``-Fallback mindestens ein Zeichen nicht
    dekodierbar war (U+FFFD eingefuegt) - ein Hinweis auf eine
    Kodierungs-Fehlannahme, die die Analyse verfaelschen kann (S8).
    """
    used = encoding or _detect_encoding(raw)
    if errors == "strict":
        # Wirft UnicodeDecodeError bei Fehlern (fail-closed, --encoding-errors
        # strict). Der Aufrufer behandelt das als Scan-Vollstaendigkeitsproblem.
        text = raw.decode(used, errors="strict")
        return text, used, False
    # replace: nicht dekodierbare Bytes werden U+FFFD; wir merken, ob das
    # passiert ist, damit ein CI-Gate das als unvollstaendige Analyse werten
    # kann. Vergleich ueber die U+FFFD-Zahl vor/nach (das Original kann selbst
    # legitime U+FFFD enthalten).
    text = raw.decode(used, errors="replace")
    had_replacements = text.count("�") > raw.count(b"\xef\xbf\xbd")
    return text, used, had_replacements


# Rueckwaertskompatibler Alias (frueher: nur Text-Rueckgabe).
def _decode_source_bytes(raw: bytes) -> str:
    return decode_source_bytes(raw)[0]


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
                 follow_symlinks: bool = False,
                 limits_apply_to_explicit_files: bool = True,
                 encoding: "str | None" = None,
                 encoding_errors: str = "replace",
                 strict_suppressions: bool = False):
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
        # M4: gelten Groessenlimit/Exclude/Symlink-Schutz auch fuer eine
        # explizit uebergebene Einzeldatei? Sicherer Default: ja. Nur eine
        # bewusste Ausnahme (--force-file) hebt das auf.
        self.limits_apply_to_explicit_files = limits_apply_to_explicit_files
        # S8: erzwungene Kodierung (None = Auto/BOM) und Fehlerstrategie
        # (replace|strict) fuer das Dekodieren der Quelltexte.
        self.encoding = encoding
        self.encoding_errors = encoding_errors
        # S13: Governance-Pruefung fuer Inline-Suppressions einschalten.
        self.strict_suppressions = strict_suppressions
        # (Datei, Zeile, Art, Detail) je beanstandeter Inline-Suppression.
        self.suppression_problems: list = []
        # Dateien, die wegen des Größenlimits übersprungen wurden.
        self.skipped_files: list = []
        # Dateien, die wegen Exclude-Muster oder Symlink-Schutz als explizites
        # Argument abgelehnt wurden: (Pfad, Grund). Teil der Scan-Vollstaendig-
        # keit (M4) - ein CI-Gate soll das nicht stumm ignorieren.
        self.rejected_files: list = []
        # S8: Dateien mit Dekodierproblemen (Ersatzzeichen bzw. strict-Fehler):
        # (Pfad, Kodierung, Meldung). Zaehlen als Scan-Vollstaendigkeitsproblem.
        self.decode_errors: list = []
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
        except MemoryError:
            # S7: Ressourcenmangel nicht zu einem gewoehnlichen Finding
            # degradieren - nach oben propagieren.
            raise
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
            except MemoryError:
                raise
            except Exception as exc:  # ein fehlerhafter Check stoppt nicht alles
                findings.append(self._internal_finding(check, filename, exc))
        findings = self._dedupe(findings)
        # Inline-Suppression (``-- aci:ignore``) direkt am Code anwenden -
        # ausschliesslich in echten Kommentarbereichen (aus dem Lexer), damit
        # eine identische Zeichenfolge in einem String-Literal keine
        # Suppression ausloest.
        findings, suppressed = apply_suppressions(findings, source)
        self.suppressed_count += len(suppressed)
        # S13: bei aktiver Governance ungueltige/abgelaufene/metadatenlose
        # Suppressions je Datei erfassen (fuer Report und --fail-on).
        if self.strict_suppressions:
            for line, kind, detail in governance_problems(source):
                self.suppression_problems.append((filename, line, kind, detail))
        return findings

    @staticmethod
    def _internal_finding(check, filename: str, exc: Exception) -> Finding:
        """Erzeugt ein Finding für einen fehlgeschlagenen Check.

        S6: Kennt die Ausnahme eine Quellposition (Attribute ``line``/
        ``column``, z.B. eine :class:`AciParseError`), wird sie uebernommen,
        statt pauschal auf Zeile 1/Spalte 1 zu zeigen.
        """
        name = getattr(check, "name", "Check")
        cid = getattr(check, "id", "?")
        line = getattr(exc, "line", None)
        column = getattr(exc, "column", None)
        return Finding(
            check_id=INTERNAL_CHECK_ID,
            check_name=f"Interner Fehler ({name})",
            group=GROUP_INTERNAL,
            severity=Severity.HIGH,
            file=filename,
            line=int(line) if isinstance(line, int) and line > 0 else 1,
            column=int(column) if isinstance(column, int) and column > 0 else 1,
            message=(f"Interner Fehler im Check '{name}' [{cid}]: "
                     f"{type(exc).__name__}: {exc}. Dies ist ein "
                     f"Werkzeugfehler, kein Code-Finding."),
            recommendation=("Dieses Finding weist auf einen Fehler in ACI "
                            "selbst oder in einer Regeldatei hin - bitte als "
                            "ACI-Fehler melden, nicht als Code-Mangel werten."),
            rule_ref=cid,
        )

    def scan_file(self, path: str, apply_limits: bool = True
                  ) -> "list[Finding] | None":
        """Untersucht eine einzelne Datei.

        Rueckgabe: die Findings-Liste, oder ``None``, wenn die Datei
        **nicht geprueft** wurde (Groessenlimit ueberschritten oder unter
        ``--encoding-errors strict`` nicht dekodierbar). ``None`` unterscheidet
        so "geprueft, keine Findings" (``[]``) von "gar nicht geprueft".

        Nebenbei werden die Kennzahlen ``scanned_bytes`` und
        ``scanned_loc`` fortgeschrieben - die Reset-Stelle ist
        :meth:`scan_path`.

        TOCTOU-fest (S9): die Datei wird **einmal** geoeffnet; Groesse und
        Inhalt stammen aus demselben Deskriptor (``os.fstat`` statt eines
        separaten ``getsize``-Vorabblicks). Bei gesetztem Groessenlimit wird
        hoechstens ``max_file_size + 1`` Byte gelesen; eine nachtraeglich
        gewachsene Datei kann so weder das Limit umgehen noch den Speicher
        sprengen. Ist das Limit ueberschritten, wird die Datei vermerkt und
        uebersprungen (Rueckgabe leere Findings-Liste).
        """
        with open(path, "rb") as fh:
            if self.max_file_size is not None and apply_limits:
                try:
                    size = os.fstat(fh.fileno()).st_size
                except OSError:
                    size = -1
                if size > self.max_file_size:
                    self.skipped_files.append((path, size))
                    return None
                # Nur bis Limit+1 lesen: waechst die Datei nach dem fstat,
                # bleibt der Speicher beschraenkt und die Ueberschreitung
                # wird erkannt.
                raw = fh.read(self.max_file_size + 1)
                if len(raw) > self.max_file_size:
                    self.skipped_files.append((path, len(raw)))
                    return None
            else:
                raw = fh.read()
        if self.encoding_errors == "strict":
            try:
                text, used_enc, _ = decode_source_bytes(
                    raw, encoding=self.encoding, errors="strict")
            except UnicodeDecodeError as exc:
                # Fail-closed pro Datei: nicht dekodierbar => nicht geprueft,
                # als Vollstaendigkeitsproblem vermerken (kein Absturz).
                self.decode_errors.append(
                    (path, self.encoding or "auto", str(exc)))
                self.scanned_bytes += len(raw)
                return None
        else:
            text, used_enc, had_repl = decode_source_bytes(
                raw, encoding=self.encoding, errors="replace")
            if had_repl:
                self.decode_errors.append(
                    (path, used_enc,
                     "nicht dekodierbare Bytes durch Ersatzzeichen ersetzt"))
        self.scanned_bytes += len(raw)
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
        self.rejected_files = []
        self.decode_errors = []
        self.access_errors = []
        self.suppression_problems = []
        self.suppressed_count = 0
        self.scanned_bytes = 0
        self.scanned_loc = 0
        # Scan-Wurzel für den repo-relativen Fingerabdruck-Pfad: bei
        # einem Verzeichnis-Scan das Verzeichnis selbst, bei einer
        # Einzeldatei deren Verzeichnis.
        self._scan_root = (path if os.path.isdir(path)
                           else os.path.dirname(path))
        if os.path.isdir(path):
            # M1: reale Verzeichnisidentitaeten (dev, ino) merken, um
            # Symlink-Zyklen (loop -> ../) zu erkennen und die Rekursion
            # nicht endlos laufen zu lassen. Nur relevant bei followlinks.
            visited_dirs: "set[tuple[int, int]]" = set()
            for root, dirs, files in os.walk(
                    path, followlinks=self.follow_symlinks,
                    onerror=self._on_walk_error):
                if self.follow_symlinks and self._is_cycle(root, visited_dirs):
                    # Bereits besuchtes reales Verzeichnis: Teilbaum kappen.
                    dirs[:] = []
                    continue
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
                    try:
                        found = self.scan_file(full)
                    except OSError as exc:
                        # Nicht lesbare Einzeldatei im Baum: vermerken und
                        # weiterlaufen (nicht den ganzen Scan abbrechen).
                        self.access_errors.append((full, str(exc)))
                        continue
                    if found is not None:
                        results[full] = found
        elif os.path.isfile(path):
            # M4: dieselben Schutzgrenzen wie beim Verzeichnis-Scan auch fuer
            # eine explizit uebergebene Einzeldatei anwenden - Exclude,
            # Symlink-Schutz und (in scan_file) das Groessenlimit. Nur mit
            # --force-file (limits_apply_to_explicit_files=False) werden sie
            # bewusst uebergangen. Andernfalls koennte man saemtliche
            # Sicherheitsschalter umgehen, indem man die Datei statt ihres
            # Verzeichnisses uebergibt.
            if self.limits_apply_to_explicit_files:
                if _matches_exclude(os.path.basename(path), self.exclude) \
                        or _matches_exclude(path, self.exclude):
                    self.rejected_files.append((path, "exclude-Muster"))
                    return results
                if not self.follow_symlinks and os.path.islink(path):
                    self.rejected_files.append((path, "Symlink (--no-follow-"
                                                "symlinks)"))
                    return results
            try:
                found = self.scan_file(
                    path, apply_limits=self.limits_apply_to_explicit_files)
            except OSError as exc:
                self.access_errors.append((path, str(exc)))
            else:
                if found is not None:
                    results[path] = found
        else:
            raise FileNotFoundError(f"Pfad nicht gefunden: {path}")
        return results

    def _is_cycle(self, root: str, visited: "set[tuple[int, int]]") -> bool:
        """True, wenn ``root`` ein bereits besuchtes reales Verzeichnis ist.

        Grundlage der Symlink-Zykluserkennung (M1): ueber ``os.stat`` (mit
        Symlink-Aufloesung) wird die Geraet/Inode-Identitaet bestimmt. Ist
        sie schon bekannt, liegt ein Zyklus (oder eine Zweitverlinkung auf
        denselben Baum) vor. Nicht statbare Verzeichnisse werden als
        Zugriffsfehler vermerkt und uebersprungen.
        """
        try:
            st = os.stat(root)
        except OSError as exc:
            self.access_errors.append((root, str(exc)))
            return True
        identity = (st.st_dev, st.st_ino)
        if identity in visited:
            return True
        visited.add(identity)
        return False

    def _on_walk_error(self, exc: OSError) -> None:
        """Callback fuer :func:`os.walk`: nicht betretbare Verzeichnisse
        (Rechte, I/O) vermerken, statt sie stumm zu ueberspringen."""
        self.access_errors.append(
            (getattr(exc, "filename", None) or "?", str(exc)))

    def scan_complete(self) -> bool:
        """True, wenn der letzte Lauf vollstaendig war - keine Datei wegen
        Groessenlimit/Exclude/Symlink uebersprungen, kein Zugriffs- oder
        Dekodierfehler (M2/S12). Grundlage des ``scan_completeness``-Blocks
        im Report und der ``--fail-on-*``-Gates."""
        return not (self.skipped_files or self.rejected_files
                    or self.access_errors or self.decode_errors)

    def completeness(self) -> dict:
        """Strukturierte Scan-Vollstaendigkeit fuer den Report (S12)."""
        return {
            "complete": self.scan_complete(),
            "access_errors": len(self.access_errors),
            "skipped_too_large": len(self.skipped_files),
            "rejected_files": len(self.rejected_files),
            "decode_errors": len(self.decode_errors),
        }

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
