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


def parse_suppressions(text: str, tokens, code_no_comments: str
                       ) -> "dict[int, set]":
    """Liest alle Inline-Direktiven aus den echten Kommentarbereichen.

    Liefert ``{ziel_zeile: {regel_token_gross, ...}}``. Ein Set ``{"*"}``
    steht fuer alle Regeln der Zeile. Die Zielzeile ergibt sich aus der
    Kommentarposition und - bei ``ignore-next-line`` bzw. reinen
    Kommentarzeilen - der naechsten tatsaechlichen Codezeile.
    """
    nc_lines = code_no_comments.split("\n")
    result: "dict[int, set]" = {}
    for cs, ce in comment_spans(tokens):
        segment = text[cs:ce]
        for m in _DIRECTIVE_RE.finditer(segment):
            kind = m.group(1).lower()
            raw_rules = m.group(2)
            if raw_rules:
                rules = {t.strip().upper() for t in raw_rules.split(",")
                         if t.strip()}
            else:
                rules = {"*"}
            directive_line = _line_of(text, cs + m.start())
            if kind == "ignore-next-line":
                target = _next_code_line(nc_lines, directive_line + 1)
            elif _line_has_code(nc_lines, directive_line):
                # Kommentar am Ende einer Codezeile -> diese Zeile.
                target = directive_line
            else:
                # Reine Kommentar-/Blockkommentarzeile -> naechste Codezeile.
                target = _next_code_line(nc_lines, directive_line + 1)
            if target is not None:
                result.setdefault(target, set()).update(rules)
    return result


def _matches(finding, rules: set) -> bool:
    """True, wenn die Regel-Auswahl ``rules`` auf ``finding`` passt."""
    if "*" in rules:
        return True
    ref = str(getattr(finding, "rule_ref", "") or "").upper()
    cid = str(getattr(finding, "check_id", "") or "").upper()
    return ref in rules or cid in rules


def apply_suppressions(findings: list, source):
    """Filtert per Inline-Direktive unterdrueckte Findings heraus.

    ``source`` ist ein :class:`aci.source.Source` (bzw. jedes Objekt mit
    ``text``, ``tokens`` und ``code_no_comments``). Liefert
    ``(kept, suppressed)``; ``kept`` behaelt die Reihenfolge. Interne
    Werkzeugfehler (``ACI-INTERNAL``) werden nie unterdrueckt - ein
    Werkzeugfehler soll nicht per Kommentar verschwinden.
    """
    directives = parse_suppressions(
        source.text, source.tokens, source.code_no_comments)
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
