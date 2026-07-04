"""Datenmodell für Findings, Schweregrade und Gruppen.

ACI kennt zwei Prüfgruppen mit jeweils eigener Schweregrad-Skala:

* Gruppe **Sicherheit**        - Skala Warning < High < Critical
* Gruppe **Coding Guidelines** - Skala Info < Minor < Major < Critical < Blocker
  (entspricht der Trivadis-Skala)

Beide Skalen werden über ein gemeinsames :class:`Severity`-Enum
abgebildet. Jeder Schweregrad trägt ein numerisches Gewicht, das eine
gruppenübergreifende Ordnung (für Sortierung und ``--fail-on``)
ermöglicht.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # nur für die Typprüfung - kein Laufzeit-Import
    from .waivers import Waiver

# Prüfgruppen
GROUP_SECURITY = "Sicherheit"
GROUP_GUIDELINES = "Coding Guidelines"
# Gruppe für interne Werkzeugfehler (fehlgeschlagene Checks). Sie ist
# keine inhaltliche Prüfgruppe, sondern macht Werkzeugprobleme im Report
# sichtbar - getrennt von echten Code-Findings.
GROUP_INTERNAL = "Interner Fehler"
GROUPS = (GROUP_SECURITY, GROUP_GUIDELINES, GROUP_INTERNAL)


class Severity(Enum):
    """Schweregrad eines Findings.

    Der Wert ist ein Tupel ``(Anzeigetext, Gewicht)``. Das Gewicht
    erlaubt den Vergleich über beide Skalen hinweg.
    """

    INFO = ("Info", 1)
    MINOR = ("Minor", 2)
    WARNING = ("Warning", 2)
    MAJOR = ("Major", 3)
    HIGH = ("High", 3)
    CRITICAL = ("Critical", 4)
    BLOCKER = ("Blocker", 5)

    @property
    def label(self) -> str:
        """Anzeigetext des Schweregrads."""
        return self.value[0]

    @property
    def weight(self) -> int:
        """Numerisches Gewicht für die gruppenübergreifende Ordnung."""
        return self.value[1]

    # Alias - frühere Versionen sprachen von 'rank'.
    @property
    def rank(self) -> int:
        return self.value[1]

    @classmethod
    def parse(cls, value) -> "Severity":
        """Wandelt einen String (z.B. aus einer Regeldatei) in ein Severity."""
        if isinstance(value, cls):
            return value
        key = str(value).strip().lower()
        for severity in cls:
            if severity.label.lower() == key:
                return severity
        raise ValueError(
            f"Unbekannter Schweregrad: {value!r} "
            f"(erlaubt: Info, Minor, Warning, Major, High, Critical, Blocker)"
        )


# Rückwärtskompatibler Alias - die Sicherheits-Checks sprachen von 'Level'.
Level = Severity

# Schweregrad-Skala je Gruppe, jeweils absteigend nach Kritikalität.
SECURITY_SCALE = (Severity.CRITICAL, Severity.HIGH, Severity.WARNING)
GUIDELINE_SCALE = (Severity.BLOCKER, Severity.CRITICAL, Severity.MAJOR,
                   Severity.MINOR, Severity.INFO)
# Interne Fehler werden mindestens als HIGH gemeldet.
INTERNAL_SCALE = (Severity.CRITICAL, Severity.HIGH)
GROUP_SCALES = {
    GROUP_SECURITY: SECURITY_SCALE,
    GROUP_GUIDELINES: GUIDELINE_SCALE,
    GROUP_INTERNAL: INTERNAL_SCALE,
}

# Kennung der Findings, die einen internen Werkzeugfehler darstellen.
INTERNAL_CHECK_ID = "ACI-INTERNAL"


def stable_relative_path(path: str, scan_root: "str | None" = None) -> str:
    """Liefert einen stabilen, reproduzierbaren Pfad für den Fingerabdruck.

    Ist ein Scan-Wurzelverzeichnis bekannt, wird der Pfad relativ dazu
    gebildet (mit Forward-Slashes). So bleiben gleichnamige Dateien in
    verschiedenen Verzeichnissen (z.B. ``db/admin/install.sql`` vs.
    ``db/app/install.sql``) unterscheidbar, und der Fingerabdruck ist
    unabhängig vom absoluten CI-/Runner-/Temp-Pfad.

    Ohne brauchbares Scan-Root wird der Pfad lediglich auf
    Forward-Slashes normalisiert zurückgegeben - bewusst **nicht** auf
    den reinen Dateinamen reduziert.
    """
    if not path:
        return ""
    norm = str(path).replace("\\", "/")
    if scan_root:
        root = str(scan_root).replace("\\", "/")
        try:
            rel = os.path.relpath(norm, root).replace("\\", "/")
        except (ValueError, OSError):
            return norm
        # Ein 'rel' mit '..' heißt: 'path' liegt nicht unterhalb von
        # 'root' - dann ist die normalisierte Originaldarstellung stabiler.
        if rel and rel != ".." and not rel.startswith("../"):
            return rel
    return norm


def compute_fingerprint(check_id: str, rule_ref: str, file: str,
                        statement: str, dialect: str = "") -> str:
    """Stabiler, inhaltsgebundener Fingerabdruck eines Findings.

    Grundlage des Waiver-/Ausnahmeprozesses. Bewusst **ohne**
    Zeilennummer: verschiebt sich Code an anderer Stelle, bleibt der
    Fingerabdruck gleich; ändert sich der beanstandete Code selbst,
    ändert er sich - ein Waiver überlebt damit keine Änderung an genau
    dem Code, den er deckt.

    Es gehen Check-ID, Regelreferenz, SQL-Dialekt, der **repo-relative
    Dateipfad** sowie der auf einfache Leerzeichen normalisierte
    Code-Ausschnitt ein. ``file`` ist bereits der stabile, repo-relative
    Pfad (siehe :func:`stable_relative_path`) - hier wird er nur auf
    Forward-Slashes normalisiert. Der vollständige Pfad (statt nur des
    Dateinamens) verhindert, dass ein Waiver für ``db/admin/install.sql``
    versehentlich ein Finding in ``db/app/install.sql`` mitdeckt.
    """
    norm = " ".join((statement or "").split())
    path = str(file or "").replace("\\", "/").strip()
    basis = "\x00".join((check_id or "", rule_ref or "", dialect or "",
                         path, norm))
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


@dataclass
class RelatedLocation:
    """Eine zusätzliche, beschriftete Fundstelle eines Findings.

    Dient dazu, neben dem eigentlichen Fundort (dem *Sink*) eine zweite,
    erklärende Stelle anzuzeigen. Beim SQL-Injection-Check ist das die
    *Taint-Quelle*: die Zuweisung(en), die den dynamischen SQL-String
    aufbauen, bzw. der Prozedur-/Funktionskopf, wenn der String aus einem
    ungeprüften Routine-Parameter stammt.
    """

    label: str             # Beschriftung der Zusatzstelle
    file: str              # Pfad der Datei
    line: int              # Zeilennummer (1-basiert)
    column: int = 0        # Spaltennummer (1-basiert)
    snippet: str = ""      # betroffene Codezeile (gekürzt)
    context: list = field(default_factory=list)   # (Zeilennr, Text, ist_Fund)

    def to_dict(self) -> dict:
        return {
            "label": self.label,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "snippet": self.snippet,
            "context": [{"line": ln, "text": txt, "finding": is_find}
                        for (ln, txt, is_find) in self.context],
        }


@dataclass
class Finding:
    """Ein einzelnes Finding im untersuchten Code."""

    check_id: str          # technische Check-/Regel-ID, z.B. "ACI-SQLI" oder "G-2320"
    check_name: str        # lesbarer Name
    group: str             # Prüfgruppe (GROUP_SECURITY / GROUP_GUIDELINES)
    severity: Severity     # Schweregrad
    file: str              # Pfad der untersuchten Datei
    line: int              # Zeilennummer (1-basiert)
    column: int            # Spaltennummer (1-basiert)
    message: str           # Beschreibung des Findings
    snippet: str = ""      # betroffene Codezeile (gekürzt)
    recommendation: str = ""   # Handlungsempfehlung
    rule_ref: str = ""     # auslösende Regel (Paketname, Schlüsselwort, G-ID)
    url: str = ""          # optionaler Verweis (z.B. Trivadis-Regelseite)
    context: list = field(default_factory=list)   # Zeilen ringsum:
    #                        Liste von (Zeilennummer, Text, ist_Fundzeile)
    related: list = field(default_factory=list)   # Liste von RelatedLocation
    #                        (z.B. die Taint-Quelle eines SQLI-Findings)
    fingerprint: str = ""  # inhaltsgebundener Hash (Bindung an Waiver)
    waiver: "Optional[Waiver]" = None  # zugeordneter Waiver o. None
    # Letzte Zeile der beanstandeten Anweisung (1-basiert). 0 oder gleich
    # ``line`` bedeutet "einzeiliges Statement". Wird gesetzt, wenn der
    # Check beim Erzeugen des Findings ein Statement-Ende (``span_end``)
    # angibt - typisch fuer mehrzeilige DDL (z.B. ``CREATE DATABASE LINK
    # ... USING '...'``) oder DDL in mehrzeilig zusammengesetztem dynamischem
    # SQL. Wird vom Cluster-Kollaps-Mechanismus genutzt, um Statement-Zeilen
    # gegen das Wegfalten zu schuetzen.
    statement_end_line: int = 0

    @property
    def waived(self) -> bool:
        """True, wenn ein gültiger (nicht abgelaufener) Waiver dieses
        Finding deckt. Gewaiverte Findings bleiben im Report sichtbar,
        zählen aber nicht für ``--fail-on``."""
        return self.waiver is not None

    def to_dict(self) -> dict:
        """Serialisierbare Darstellung (für den JSON-Report)."""
        return {
            "check_id": self.check_id,
            "check_name": self.check_name,
            "group": self.group,
            "severity": self.severity.label,
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "snippet": self.snippet,
            "recommendation": self.recommendation,
            "rule_ref": self.rule_ref,
            "url": self.url,
            "context": [{"line": ln, "text": txt, "finding": is_find}
                        for (ln, txt, is_find) in self.context],
            "related": [r.to_dict() for r in self.related],
            "fingerprint": self.fingerprint,
            "waived": self.waived,
            "waiver": self.waiver.to_dict() if self.waiver is not None else None,
        }

    def sort_key(self):
        """Sortierung: Datei, dann Schweregrad absteigend, dann Position."""
        return (self.file, -self.severity.weight, self.line,
                self.column, self.check_id)
