"""Waiver-/Ausnahmeprozess für die CI/CD-Integration.

Ein Waiver hebt **nicht** das Finding auf, sondern nur dessen Wirkung
auf das Gate (``--fail-on``). Gewaiverte Findings bleiben im Report
sichtbar und sind über Ticket-ID, Owner, Ablaufdatum und Begründung
auditierbar. So muss ein Team bei False Positives weder ``--fail-on``
global abschwächen noch Regeln deaktivieren.

Die Bindung Waiver -> Finding erfolgt über den inhaltsgebundenen
Fingerabdruck eines Findings (siehe :func:`aci.finding.compute_fingerprint`):
bewusst **ohne** Zeilenbezug, sodass ein Waiver harmlose
Code-Verschiebungen überlebt, aber automatisch verfällt, sobald sich
der beanstandete Code selbst ändert.

Lebenszyklus eines Waivers:

* **gültig**     - Ablaufdatum >= heute und Fingerprint trifft ein
  Finding: das Finding wird als *Waived* markiert und zählt nicht für
  ``--fail-on``.
* **abgelaufen** - Ablaufdatum < heute: der Waiver greift nicht mehr,
  das Finding zählt wieder voll; ACI warnt über abgelaufene Waiver.
* **bald fällig**- noch gültig, aber Ablaufdatum <= :data:`SOON_DAYS`
  Tage entfernt: ACI weist im Report darauf hin.
* **verwaist**   - noch gültig, aber kein Finding trägt den
  Fingerprint: Hinweis, dass der Waiver entfernt werden kann.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from dataclasses import dataclass, field

# Vorlaufzeit (Tage): noch gültige Waiver, die innerhalb dieser Frist
# ablaufen, werden im Report als "läuft bald ab" gemeldet.
SOON_DAYS = 14

# Pflichtfelder eines Waiver-Eintrags.
REQUIRED_FIELDS = ("fingerprint", "ticket", "owner", "expires", "reason")


@dataclass
class Waiver:
    """Eine einzelne, kontrollierte Ausnahme.

    ``fingerprint`` bindet den Waiver an einen konkreten Code-Befund,
    ``ticket``/``owner`` machen ihn nachvollziehbar, ``expires`` erzwingt
    eine Wiedervorlage: sobald das Datum ueberschritten ist, greift der
    Waiver nicht mehr und der Befund zaehlt wieder fuers Gate. Eine
    Obergrenze fuer das Ablaufdatum wird bewusst nicht erzwungen - die
    zulaessige Frist ist eine Prozess-/Policy-Entscheidung des Teams.
    """

    fingerprint: str
    ticket: str
    owner: str
    expires: _dt.date
    reason: str
    created: str = ""
    risk_accepted: bool = False
    # Von :func:`apply_waivers` gesetzt: Anzahl der gedeckten Findings.
    match_count: int = 0

    @property
    def expires_str(self) -> str:
        """Ablaufdatum als ISO-String (``YYYY-MM-DD``)."""
        return self.expires.isoformat()

    def is_expired(self, today: _dt.date) -> bool:
        """True, wenn der Waiver am Stichtag ``today`` abgelaufen ist."""
        return self.expires < today

    def days_left(self, today: _dt.date) -> int:
        """Verbleibende Tage bis zum Ablauf (negativ, wenn abgelaufen)."""
        return (self.expires - today).days

    def to_dict(self) -> dict:
        """Serialisierbare Darstellung (für den JSON-Report)."""
        return {
            "fingerprint": self.fingerprint,
            "ticket": self.ticket,
            "owner": self.owner,
            "expires": self.expires_str,
            "reason": self.reason,
            "created": self.created,
            "risk_accepted": self.risk_accepted,
        }


@dataclass
class WaiverReport:
    """Ergebnis der Waiver-Anwendung - Grundlage für Report und Hinweise.

    ``applied`` zählt die tatsächlich gewaiverten Findings; die übrigen
    Listen enthalten :class:`Waiver`-Objekte für die jeweiligen
    Lebenszyklus-Zustände.
    """

    path: str = ""
    applied: int = 0
    errors: list = field(default_factory=list)     # Klartext-Fehler
    active: list = field(default_factory=list)     # genutzte, gültige Waiver
    expired: list = field(default_factory=list)    # abgelaufene Waiver
    soon: list = field(default_factory=list)       # bald ablaufende Waiver
    orphaned: list = field(default_factory=list)   # Waiver ohne Finding

    @property
    def has_warnings(self) -> bool:
        """True, wenn es defekte, abgelaufene, bald fällige oder
        verwaiste Waiver gibt - also Punkte, auf die ACI hinweist."""
        return bool(self.errors or self.expired
                    or self.soon or self.orphaned)

    def warning_lines(self) -> list:
        """Menschenlesbare Hinweiszeilen (für Konsole/Logs)."""
        lines: list = []
        for err in self.errors:
            lines.append(f"Waiver-Fehler: {err}")
        for w in self.expired:
            lines.append(
                f"Waiver abgelaufen: {w.ticket} (Owner {w.owner}, "
                f"abgelaufen am {w.expires_str}) - Finding zählt wieder.")
        for w in self.soon:
            lines.append(
                f"Waiver läuft bald ab: {w.ticket} (Owner {w.owner}, "
                f"fällig am {w.expires_str}).")
        for w in self.orphaned:
            lines.append(
                f"Waiver ohne Treffer: {w.ticket} (Owner {w.owner}) - "
                f"Fingerprint {w.fingerprint} passt zu keinem Finding.")
        return lines

    def to_dict(self) -> dict:
        """Serialisierbare Darstellung (für den JSON-Report)."""
        return {
            "path": self.path,
            "applied": self.applied,
            "errors": list(self.errors),
            "active": [w.to_dict() for w in self.active],
            "expired": [w.to_dict() for w in self.expired],
            "soon": [w.to_dict() for w in self.soon],
            "orphaned": [w.to_dict() for w in self.orphaned],
        }


def _parse_date(value) -> _dt.date:
    """Parst ein ISO-Datum (``YYYY-MM-DD``); wirft ``ValueError`` sonst."""
    if isinstance(value, _dt.date):
        return value
    return _dt.date.fromisoformat(str(value).strip())


def load_waivers(path: str):
    """Lädt und validiert eine Waiver-Datei.

    Liefert ``(waivers, errors)``: ``waivers`` ist die Liste sauber
    geparster :class:`Waiver`, ``errors`` eine Liste von Klartext-
    Fehlermeldungen für defekte Einträge. Ein leerer ``path`` liefert
    ``([], [])``. Defekte Einzeleinträge führen zu einem Fehlereintrag,
    stoppen aber nicht das Laden der übrigen.
    """
    if not path:
        return [], []
    if not os.path.isfile(path):
        return [], [f"Waiver-Datei nicht gefunden: {path}"]
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        return [], [f"Waiver-Datei nicht lesbar ({path}): {exc}"]
    if not isinstance(raw, list):
        return [], [f"Waiver-Datei {path}: erwartet wird eine JSON-Liste "
                    f"von Waiver-Objekten."]
    waivers: list = []
    errors: list = []
    seen: set = set()
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            errors.append(f"Waiver #{idx}: kein JSON-Objekt.")
            continue
        missing = [k for k in REQUIRED_FIELDS
                   if not str(item.get(k, "")).strip()]
        if missing:
            errors.append(f"Waiver #{idx}: Pflichtfeld(er) fehlen: "
                          f"{', '.join(missing)}.")
            continue
        try:
            expires = _parse_date(item["expires"])
        except ValueError:
            errors.append(
                f"Waiver #{idx} ({item.get('ticket')}): ungültiges "
                f"Ablaufdatum {item.get('expires')!r} "
                f"(erwartet wird YYYY-MM-DD).")
            continue
        fingerprint = str(item["fingerprint"]).strip().lower()
        if fingerprint in seen:
            errors.append(f"Waiver #{idx} ({item.get('ticket')}): "
                          f"doppelter Fingerprint {fingerprint}.")
            continue
        seen.add(fingerprint)
        waivers.append(Waiver(
            fingerprint=fingerprint,
            ticket=str(item["ticket"]).strip(),
            owner=str(item["owner"]).strip(),
            expires=expires,
            reason=str(item["reason"]).strip(),
            created=str(item.get("created", "")).strip(),
            risk_accepted=bool(item.get("risk_accepted", False)),
        ))
    return waivers, errors


def _iter_findings(results):
    """Liefert alle Findings - akzeptiert ein dict (Datei -> Findings),
    eine Liste von Findings oder ein Objekt mit ``all_findings()``."""
    if hasattr(results, "all_findings"):
        yield from results.all_findings()
        return
    if isinstance(results, dict):
        for items in results.values():
            yield from items
        return
    for item in results:
        if hasattr(item, "fingerprint"):
            yield item
        else:  # z.B. (datei, findings)-Paar oder verschachtelte Liste
            yield from item


def apply_waivers(results, waivers, errors=None, today=None,
                  path: str = "") -> WaiverReport:
    """Ordnet Waiver den Findings zu und klassifiziert sie.

    Gültige, nicht abgelaufene Waiver setzen ``finding.waiver`` - das
    Finding bleibt sichtbar, zählt aber nicht mehr für ``--fail-on``.
    Abgelaufene Waiver greifen nicht. ``errors`` (aus :func:`load_waivers`)
    werden unverändert in den :class:`WaiverReport` übernommen.

    Liefert einen :class:`WaiverReport` mit den vier Lebenszyklus-Listen.
    """
    today = today or _dt.date.today()
    report = WaiverReport(path=path, errors=list(errors or []))
    # Findings nach Fingerabdruck indizieren (leere Fingerprints - etwa
    # bei internen Werkzeugfehlern - sind nicht waiverbar).
    by_fingerprint: dict = {}
    for finding in _iter_findings(results):
        if finding.fingerprint:
            by_fingerprint.setdefault(finding.fingerprint, []).append(finding)
    for waiver in waivers:
        matched = by_fingerprint.get(waiver.fingerprint, [])
        waiver.match_count = len(matched)
        if waiver.is_expired(today):
            report.expired.append(waiver)
            continue
        if not matched:
            report.orphaned.append(waiver)
            continue
        for finding in matched:
            # Erstzuordnung gewinnt - ein Finding wird nicht doppelt
            # gewaivert (relevant nur bei doppelten Fingerprints).
            if finding.waiver is None:
                finding.waiver = waiver
                report.applied += 1
        report.active.append(waiver)
        if 0 <= waiver.days_left(today) <= SOON_DAYS:
            report.soon.append(waiver)
    return report
