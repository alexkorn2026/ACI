"""Inline-Suppression: gezielte Ausnahmen direkt im Quelltext.

Ergaenzend zur zentralen Waiver-Datei (:mod:`aci.waivers`) koennen einzelne
Fundstellen mit einem Kommentar direkt am Code stummgeschaltet werden -
ergonomisch und im Diff sichtbar. Zwei Formen:

* ``-- aci:ignore``            - unterdrueckt Findings der zugehoerigen
  Codezeile (steht der Kommentar am Ende einer Codezeile, ist es diese
  Zeile; steht er allein auf einer reinen Kommentarzeile, die naechste
  tatsaechliche Codezeile);
* ``-- aci:ignore-next-line``  - unterdrueckt Findings der naechsten
  tatsaechlichen Codezeile (Leer- und reine Kommentarzeilen werden
  uebersprungen).

Optional laesst sich die Unterdrueckung auf bestimmte Regeln beschraenken,
indem in eckigen Klammern eine kommagetrennte Liste von Regel-Referenzen
oder Check-IDs angegeben wird (Gross-/Kleinschreibung egal), z.B.::

    v_sql := '...' || p_name;  -- aci:ignore[ACI-SQLI] Ticket SEC-42: geprueft

Ohne Klammerangabe werden **alle** Findings der Zielzeile unterdrueckt.

**Wichtig (ACI 2.22.1):** Direktiven werden ausschliesslich innerhalb
*echter* Kommentare erkannt - der Lexer liefert die Kommentarbereiche. Eine
identische Zeichenfolge in einem String-Literal (einfaches Literal, Oracle-
q-Quote, PostgreSQL-Dollar-Quote, quoted identifier, dynamisches SQL,
``RAISE NOTICE``-Text usw.) loest daher **keine** Suppression aus.

Anders als ein Waiver ist eine Inline-Suppression bewusst schlank (kein
Ablaufdatum, kein Owner). Der unterdrueckte Befund wird nicht mitgezaehlt
(zaehlt nicht fuer ``--fail-on``); die Anzahl wird als Hinweis gemeldet.
Werkzeugfehler (``ACI-INTERNAL``) werden nie unterdrueckt.
"""

from __future__ import annotations

import datetime
import re

from .lexer import TOK_LINE_COMMENT, TOK_BLOCK_COMMENT

# Direktive *innerhalb* eines Kommentars. Der Kommentar-Leader (``--``/``/*``)
# ist bereits durch den Lexer-Kommentarbereich garantiert und daher hier
# nicht mehr Teil des Musters. ``kind`` = ignore | ignore-next-line;
# ``rules`` = optionaler Klammerinhalt (kommagetrennte Regel-/Check-Liste).
_DIRECTIVE_RE = re.compile(
    r"(?<![A-Za-z0-9_.])aci:(ignore(?:-next-line)?)\b[ \t]*"
    r"(?:\[([^\]\n]*)\])?",
    re.IGNORECASE,
)

# Governance-Metadaten hinter der Direktive (S13):
#   -- aci:ignore[ACI-SQLI] ticket=SEC-123 expires=2026-12-31 reason="..."
# Schluessel: ticket, expires, reason, owner. Werte optional gequotet.
_META_RE = re.compile(
    r"(?i)\b(ticket|expires|reason|owner)\s*=\s*"
    r"(\"[^\"]*\"|'[^']*'|[^\s]+)")


def _parse_meta(segment: str) -> dict:
    """Liest die Governance-Metadaten aus dem Text hinter der Direktive."""
    meta: dict = {}
    for m in _META_RE.finditer(segment):
        key = m.group(1).lower()
        val = m.group(2).strip()
        if len(val) >= 2 and val[0] in "\"'" and val[-1] == val[0]:
            val = val[1:-1]
        meta[key] = val
    return meta


def _parse_expires(value: str):
    """Wandelt ``YYYY-MM-DD`` in ein ``date`` oder liefert ``None`` (ungueltig)."""
    try:
        return datetime.date.fromisoformat(str(value).strip())
    except (ValueError, TypeError):
        return None


def comment_spans(tokens) -> "list[tuple[int, int]]":
    """(start, end)-Offsets aller Kommentar-Token (Zeilen- und Block-)."""
    return [(t.start, t.end) for t in tokens
            if t.type in (TOK_LINE_COMMENT, TOK_BLOCK_COMMENT)]


def _line_of(text: str, offset: int) -> int:
    """1-basierte Zeilennummer des Zeichens an ``offset``."""
    return text.count("\n", 0, offset) + 1


def _line_has_code(nc_lines: "list[str]", line: int) -> bool:
    """True, wenn Zeile ``line`` (1-basiert) in ``code_no_comments`` echten
    Code traegt (Kommentare sind dort ausgeblendet; ein leerer bzw. nur aus
    Whitespace bestehender Eintrag ist eine Leer-/reine Kommentarzeile)."""
    return 1 <= line <= len(nc_lines) and bool(nc_lines[line - 1].strip())


def _next_code_line(nc_lines: "list[str]", start: int) -> "int | None":
    """Naechste tatsaechliche Codezeile ab ``start`` (1-basiert) oder ``None``.

    Uebersprungen werden Leerzeilen, reine Whitespace-Zeilen sowie reine
    Kommentar-/Blockkommentarzeilen (in ``code_no_comments`` ausgeblendet).
    """
    ln = max(1, start)
    while ln <= len(nc_lines):
        if nc_lines[ln - 1].strip():
            return ln
        ln += 1
    return None


def parse_directives(text: str, tokens, code_no_comments: str) -> "list[dict]":
    """Liest alle Inline-Direktiven inkl. Governance-Metadaten (S13).

    Liefert eine Liste von Direktiven-Dicts mit ``target`` (Zielzeile),
    ``rules`` (Set), ``ticket``/``reason``/``owner`` (str, evtl. leer),
    ``expires`` (``date`` oder ``None``) und ``expires_raw``/``expires_valid``.
    """
    nc_lines = code_no_comments.split("\n")
    out: "list[dict]" = []
    for cs, ce in comment_spans(tokens):
        segment = text[cs:ce]
        for m in _DIRECTIVE_RE.finditer(segment):
            kind = m.group(1).lower()
            raw_rules = m.group(2)
            rules = ({t.strip().upper() for t in raw_rules.split(",")
                      if t.strip()} if raw_rules else {"*"})
            directive_line = _line_of(text, cs + m.start())
            if kind == "ignore-next-line":
                target = _next_code_line(nc_lines, directive_line + 1)
            elif _line_has_code(nc_lines, directive_line):
                target = directive_line
            else:
                target = _next_code_line(nc_lines, directive_line + 1)
            if target is None:
                continue
            # Metadaten aus dem Rest des Kommentar-Segments hinter der Direktive
            # (bis Zeilenende) lesen.
            tail = segment[m.end():]
            nl = tail.find("\n")
            if nl != -1:
                tail = tail[:nl]
            meta = _parse_meta(tail)
            expires_raw = meta.get("expires", "")
            expires = _parse_expires(expires_raw) if expires_raw else None
            out.append({
                "target": target,
                "line": directive_line,
                "rules": rules,
                "ticket": meta.get("ticket", ""),
                "reason": meta.get("reason", ""),
                "owner": meta.get("owner", ""),
                "expires_raw": expires_raw,
                "expires": expires,
                "expires_valid": (not expires_raw) or (expires is not None),
            })
    return out


def parse_suppressions(text: str, tokens, code_no_comments: str
                       ) -> "dict[int, set]":
    """Liest alle Inline-Direktiven aus den echten Kommentarbereichen.

    Liefert ``{ziel_zeile: {regel_token_gross, ...}}``. Ein Set ``{"*"}``
    steht fuer alle Regeln der Zeile. Die Zielzeile ergibt sich aus der
    Kommentarposition und - bei ``ignore-next-line`` bzw. reinen
    Kommentarzeilen - der naechsten tatsaechlichen Codezeile.
    """
    result: "dict[int, set]" = {}
    for d in parse_directives(text, tokens, code_no_comments):
        result.setdefault(d["target"], set()).update(d["rules"])
    return result


def governance_problems(source, today=None) -> "list[tuple]":
    """Meldet Direktiven ohne Governance-Metadaten bzw. mit Ablauf (S13).

    Liefert ``[(zeile, art, detail), ...]`` mit ``art`` aus
    ``missing_metadata`` (kein ticket/reason), ``invalid_expires`` (kein
    gueltiges Datum) und ``expired`` (Ablaufdatum in der Vergangenheit).
    """
    today = today or datetime.date.today()
    problems: "list[tuple]" = []
    for d in parse_directives(source.text, source.tokens,
                              source.code_no_comments):
        if not d["ticket"] or not d["reason"]:
            problems.append((d["line"], "missing_metadata",
                             "ticket= und reason= erforderlich"))
        if not d["expires_valid"]:
            problems.append((d["line"], "invalid_expires",
                             f"ungueltiges Datum: {d['expires_raw']!r}"))
        elif d["expires"] is not None and d["expires"] < today:
            problems.append((d["line"], "expired",
                             f"abgelaufen am {d['expires_raw']}"))
    return problems


def _matches(finding, rules: set) -> bool:
    """True, wenn die Regel-Auswahl ``rules`` auf ``finding`` passt."""
    if "*" in rules:
        return True
    ref = str(getattr(finding, "rule_ref", "") or "").upper()
    cid = str(getattr(finding, "check_id", "") or "").upper()
    return ref in rules or cid in rules


def apply_suppressions(findings: list, source, today=None):
    """Filtert per Inline-Direktive unterdrueckte Findings heraus.

    ``source`` ist ein :class:`aci.source.Source` (bzw. jedes Objekt mit
    ``text``, ``tokens`` und ``code_no_comments``). Liefert
    ``(kept, suppressed)``; ``kept`` behaelt die Reihenfolge. Interne
    Werkzeugfehler (``ACI-INTERNAL``) werden nie unterdrueckt - ein
    Werkzeugfehler soll nicht per Kommentar verschwinden.

    S13: Eine **abgelaufene** Direktive (``expires=`` in der Vergangenheit)
    unterdrueckt **nicht** mehr - der Befund wird wieder sichtbar. So kann
    eine Inline-Suppression nicht unbegrenzt lange still ein Finding decken.
    """
    today = today or datetime.date.today()
    # Nur nicht-abgelaufene Direktiven wirken; abgelaufene fallen heraus.
    directives: "dict[int, set]" = {}
    for d in parse_directives(source.text, source.tokens,
                              source.code_no_comments):
        if d["expires"] is not None and d["expires"] < today:
            continue
        directives.setdefault(d["target"], set()).update(d["rules"])
    if not directives:
        return list(findings), []
    kept: list = []
    suppressed: list = []
    for f in findings:
        rules = directives.get(getattr(f, "line", -1))
        if (rules is not None
                and getattr(f, "check_id", "") != "ACI-INTERNAL"
                and _matches(f, rules)):
            suppressed.append(f)
        else:
            kept.append(f)
    return kept, suppressed
