"""Datenfluss-Check: SQL-Injection durch dynamisches SQL.

Klassifiziert dynamisch zusammengesetztes SQL und folgt der Taint-Quelle
(aufbauende Zuweisungen bzw. ungeprüfter Routine-Parameter).
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, field, replace
from enum import Enum
from functools import lru_cache

from ..finding import (Finding)
from ..ir import dynamic_sql_executions, IRCall, IRConcat
from ..parser import parse_expression, _split_top_level

from .base import (Check, _split_concat,
                    _classify_operand, _collect_var_writes,
                    _origin_related)


# ----------------------------------------------------------------------
# Check 4 - SQL Injection (Klassifikation dynamischen SQLs)
# ----------------------------------------------------------------------

# Ein "reiner Bezeichner" - eine Variable, die dynamisches SQL trägt.
_BARE_VAR_RE = re.compile(r'^"?[A-Za-z_][\w$#]*"?$')

# Maximale Tiefe der rekursiven Variablen-/Taint-Verfolgung. Zu klein (frueher
# 2) erzeugte False Positives bei Literal-Ketten ueber mehrere Zwischen-
# variablen (``v1:='x'; v2:=v1; v3:=v2; v4:=v3`` -> faelschlich Critical),
# weil am Cutoff konservativ ``tainted`` angenommen wird. Der Wert ist per
# (operand, depth) memoisiert, daher bleibt der Aufwand beschraenkt.
_MAX_TAINT_RESOLVE_DEPTH = 16


def _prev_word_upper(text: str, idx: int) -> str:
    """Wort unmittelbar vor ``idx`` (Whitespace uebersprungen), gross."""
    j = idx - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    end = j + 1
    while j >= 0 and (text[j].isalnum() or text[j] in "_$#"):
        j -= 1
    return text[j + 1:end].upper()


def _paren_end_str(text: str, open_pos: int) -> int:
    """Offset der zu ``text[open_pos] == '('`` passenden ``)`` (auf ``masked``,
    String-Inhalte ausgeblendet). Liefert das Textende, wenn unbalanciert."""
    depth = 0
    n = len(text)
    i = open_pos
    while i < n:
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _routine_at(routines, offset: int):
    """Die IR-Routine, deren Bereich ``offset`` enthaelt (oder ``None``).

    Routinen sind konsekutive, nicht ueberlappende Bereiche; die
    innerste/most-specific ist die mit dem groessten Start <= offset, deren
    Ende ``offset`` noch einschliesst. Ohne Cache (Aufrufzahl ist gering)."""
    best = None
    for r in routines:
        if r.start <= offset < r.end:
            if best is None or r.start > best.start:
                best = r
    return best


@dataclass
class CallArgument:
    """Ein einzelnes Aufrufargument. ``name`` ist bei Oracle-Named-Argument-
    Syntax (``p_name => expr``) der normalisierte (grosse) Parametername,
    sonst ``None`` (Positionsargument). ``expression`` ist der Ausdruckstext
    (aus ``code_no_comments``, getrimmt)."""

    name: "str | None"
    expression: str


# Oracle/PL/SQL Named-Argument-Einleitung ``parameter_name =>``. Auf der
# maskierten Variante gematcht, damit ein ``=>`` in einem String nicht zaehlt.
_NAMED_ARG_RE = re.compile(r"\s*([A-Za-z_][\w$#]*)\s*=>\s*")


def _parse_call_args(masked: str, code: str, start: int, end: int
                     ) -> "list[CallArgument]":
    """Zerlegt die Argumentliste ``(start, end)`` (Offsets in ``masked``/
    ``code``, exklusive der Klammern) in :class:`CallArgument`.

    Top-Level-Trennung an Kommata ausserhalb von Strings/Klammern (siehe
    :func:`_split_top_level`); je Argument wird die Named-Argument-Syntax
    erkannt. ``masked`` und ``code`` sind zeichenweise ausgerichtet, daher
    gelten die auf ``masked`` bestimmten Offsets auch fuer ``code``.
    """
    args: "list[CallArgument]" = []
    for a0, a1 in _split_top_level(masked[start:end], ","):
        seg_masked = masked[start + a0:start + a1]
        seg_code = code[start + a0:start + a1]
        if not seg_code.strip():
            continue
        mnamed = _NAMED_ARG_RE.match(seg_masked)
        if mnamed:
            args.append(CallArgument(
                mnamed.group(1).upper(), seg_code[mnamed.end():].strip()))
        else:
            args.append(CallArgument(None, seg_code.strip()))
    return args


def _bind_arguments(args: "list[CallArgument]", params_upper: "list[str]"
                    ) -> "dict[int, str]":
    """Ordnet Argumente ihren Parameter-Indizes zu.

    Positionsargumente belegen der Reihe nach die Positionen 0, 1, ...;
    Named Arguments werden ueber den (grossen) Parameternamen dem korrekten
    Index zugeordnet. Ein unbekannter Parametername wird konservativ
    ignoriert (keine Zuordnung allein per Listenindex)."""
    bound: "dict[int, str]" = {}
    pos = 0
    for a in args:
        if a.name is None:
            bound[pos] = a.expression
            pos += 1
        elif a.name in params_upper:
            bound[params_upper.index(a.name)] = a.expression
    return bound


_DOLLAR_QUOTE_RE = re.compile(r"\$(?:[A-Za-z_][\w]*)?\$")


def _is_string_literal(expr: str) -> bool:
    """True, wenn ein (konkatenationsfreier) Ausdruck ein String-Literal ist.

    Anerkannt werden:
    - Standard-Literale ``'...'`` (alle Dialekte)
    - Oracle-q-Quotes ``q'X...X'``, ``nq'X...X'``
    - PostgreSQL-Dollar-Quotes ``$tag$...$tag$`` (auch ``$$...$$``) -
      typische Form in PL/pgSQL fuer statische SQL-Texte in EXECUTE bzw.
      ``format(...)``. Solche Strings sind statisch (literal) und sollen
      nicht als ``UNKNOWN_DYNAMIC`` klassifiziert werden.
    """
    e = expr.lstrip()
    if not e:
        return False
    if e.startswith("'") or re.match(r"[nN]?[qQ]'", e):
        return True
    m = _DOLLAR_QUOTE_RE.match(e)
    if m:
        # Geschlossener Dollar-Quote-Block mit dem identischen Tag.
        tag = m.group(0)
        return e.find(tag, m.end()) != -1
    return False


_PLSQL_BLOCK_PREFIX_RE = re.compile(
    r"(?:BEGIN|DECLARE)\b", re.IGNORECASE)


def _starts_with_plsql_block(expr_code: str) -> bool:
    """True, wenn der dynamische SQL-Ausdruck mit ``BEGIN`` oder ``DECLARE``
    beginnt - also einen anonymen PL/SQL-Block ausfuehrt.

    Untersucht das erste String-Literal in ``expr_code``: ist es ein
    Standard-Literal ``'...'``, wird sein Inhalt nach fuehrendem Whitespace
    auf das Anfangs-Schluesselwort geprueft. Auch das Oracle-q-Quote-Format
    ``q'[...]'`` und PostgreSQL-Dollar-Quotes werden erkannt. Eingebettete
    ``''``-Escape-Folgen werden vor der Pruefung normalisiert.

    PL/SQL-Injection ist eine besonders kritische Variante der SQL-Injection:
    ein anonymer Block kann beliebige DDL/DCL und mehrere Statements
    ausfuehren - nicht nur ein einzelnes SELECT/INSERT/...
    """
    if not expr_code:
        return False
    s = expr_code.lstrip()
    if not s:
        return False
    # Standard-String-Literal '...'
    if s[0] == "'":
        m = re.match(r"'((?:[^']|'')*)", s)
        if not m:
            return False
        content = m.group(1).replace("''", "'").lstrip()
        return bool(_PLSQL_BLOCK_PREFIX_RE.match(content))
    # Oracle q-Quote: q'X...X' / nq'X...X'
    m = re.match(r"[nN]?[qQ]'(.)", s)
    if m:
        delim = m.group(1)
        close_map = {"(": ")", "[": "]", "{": "}", "<": ">"}
        close_ch = close_map.get(delim, delim)
        body_start = m.end()
        end_idx = s.find(close_ch + "'", body_start)
        body = s[body_start:end_idx] if end_idx != -1 else s[body_start:]
        return bool(_PLSQL_BLOCK_PREFIX_RE.match(body.lstrip()))
    # PostgreSQL Dollar-Quote: $tag$...$tag$
    m = re.match(r"\$([A-Za-z_][\w]*)?\$", s)
    if m:
        tag = m.group(0)
        body_start = m.end()
        end_idx = s.find(tag, body_start)
        body = s[body_start:end_idx] if end_idx != -1 else s[body_start:]
        return bool(_PLSQL_BLOCK_PREFIX_RE.match(body.lstrip()))
    return False


@lru_cache(maxsize=2048)
def _format_first_arg(expr: str) -> str:
    """Extrahiert das erste Argument eines ``format(...)``-Aufrufs.

    Das ist der Format-String. Die Zerlegung stammt aus der
    Expression-IR: ``parse_expression`` liefert für einen Funktionsaufruf
    einen :class:`~aci.ir.IRCall` mit strukturierten Argumenten - das
    erste davon ist der Format-String. Klammern und String-Literale
    werden dabei vom IR-Parser korrekt übersprungen.
    """
    node = parse_expression(expr)
    if isinstance(node, IRCall) and node.arguments:
        return node.arguments[0].text
    return ""


@lru_cache(maxsize=2048)
def _concat_func_operands(expr_code: str) -> tuple:
    """Liefert die Argumente aller ``concat(...)``-Aufrufe in einem Ausdruck.

    ``concat()`` ist neben ``||`` die zweite Möglichkeit, in Oracle
    Zeichenketten zu verketten. Gearbeitet wird auf der Expression-IR:
    jeder :class:`~aci.ir.IRCall`-Knoten mit Funktionsname ``concat``
    trägt seine Argumente bei. Verschachtelte ``concat()``-Aufrufe werden
    rekursiv aufgelöst - das jeweilige innere ``concat()`` zählt nicht
    als eigener Operand. Das Ergebnis wird gecacht (reine Funktion).
    """
    operands: list[str] = []

    def visit(node):
        if isinstance(node, IRCall):
            if node.function_name.lower() == "concat":
                for arg in node.arguments:
                    if (isinstance(arg, IRCall)
                            and arg.function_name.lower() == "concat"):
                        visit(arg)
                    else:
                        operands.append(arg.text)
            else:
                for arg in node.arguments:
                    visit(arg)
        elif isinstance(node, IRConcat):
            for part in node.parts:
                visit(part)

    visit(parse_expression(expr_code))
    return tuple(operands)


class DynamicSqlRisk(Enum):
    """Grobe Risikoklassifikation für dynamische SQL-Ausdrücke.

    Bewusst heuristisch - ACI führt keine vollständige Datenflussanalyse
    durch. Die Stufen sind nach steigendem Risiko geordnet.
    """

    NONE = "none"                       # kein dynamisches SQL / unkritisch
    BIND_SAFE = "bind_safe"             # statischer Text + Bindevariablen
    LITERAL_ONLY = "literal_only"       # nur aus String-Literalen gebildet
    SANITIZED_CONCAT = "sanitized_concat"   # variable Anteile, aber escaped
    UNKNOWN_DYNAMIC = "unknown_dynamic"     # Herkunft des SQL-Strings unbekannt
    TAINTED_CONCAT = "tainted_concat"   # Konkatenation ungeprüfter Werte


# Reihenfolge nach Risiko - für die Auswahl der kritischsten Zuweisung.
_RISK_ORDER = {
    DynamicSqlRisk.NONE: 0,
    DynamicSqlRisk.BIND_SAFE: 1,
    DynamicSqlRisk.LITERAL_ONLY: 2,
    DynamicSqlRisk.SANITIZED_CONCAT: 3,
    DynamicSqlRisk.UNKNOWN_DYNAMIC: 4,
    DynamicSqlRisk.TAINTED_CONCAT: 5,
}

# Schlüsselworte, die einen bedingten oder iterativen Kontrollfluss
# eröffnen. Tauchen sie zwischen den Zuweisungen einer Variable und ihrer
# Ausführung auf, kann eine frühere Zuweisung weiterhin wirksam sein -
# dann wird konservativ die kritischste Zuweisung bewertet, statt die
# letzte als alleinverbindlich ("dead-assignment elimination") anzunehmen.
_CONTROL_FLOW_RE = re.compile(
    r"\b(?:IF|ELSIF|ELSE|LOOP|CASE|WHEN|EXCEPTION|GOTO|FORALL)\b", re.I)


@dataclass
class DynamicSqlAssessment:
    """Ergebnis der Klassifikation eines dynamischen SQL-Ausdrucks.

    ``source`` typisiert die Taint-Herkunft, sofern bestimmbar:
    ``"parameter"`` (1st-order - ungeprüfter Routine-Parameter) oder
    ``"table"`` (2nd-order - Wert aus Tabelle/Cursor via SELECT/FETCH INTO).
    """

    risk: DynamicSqlRisk
    reason: str
    has_concat: bool = False
    has_bind: bool = False
    has_sanitizer: bool = False
    has_unknown_variable: bool = False
    assign_line: "int | None" = None
    source: "str | None" = None
    # Offsets der Taint-Quellen: jede ``(offset, kind)`` ist eine Stelle,
    # die den dynamischen SQL-String aufbaut - eine ``:=``-Zuweisung, ein
    # ``SELECT/FETCH ... INTO`` oder (kind ``parameter``) der Routinenkopf.
    # Wird nur bei reiner Variablen-Ausführung gefüllt (_classify_variable)
    # und vom Reporting als zusätzliche Fundstellen ausgewiesen.
    origins: list = field(default_factory=list)


class SqlInjectionCheck(Check):
    """Erkennt SQL-Injection-Risiken in dynamischem SQL.

    Statt einer groben tainted/literal-Unterscheidung klassifiziert der
    Check jeden dynamischen SQL-Ausdruck über :class:`DynamicSqlRisk`.
    Bindevariablen und Sanitizer (DBMS_ASSERT, quote_ident/quote_literal,
    ``format()`` mit ``%I``/``%L``) werden ausdrücklich nicht als
    kritisch gewertet; ungeprüfte Konkatenation dagegen schon.
    """

    config_key = "sql_injection"

    def __init__(self, config, dialect):
        super().__init__(config, dialect)
        self.tainted_level = config.get("tainted_level", "Critical")
        # PL/SQL-Injection (dynamisches SQL beginnt mit ``BEGIN``/``DECLARE``)
        # ist eine besonders kritische Variante: hier wird kein einzelnes
        # Statement, sondern ein anonymer PL/SQL-Block injiziert - inklusive
        # eigener DDL/DCL und mehrfacher Statements. Severity bleibt im
        # Sicherheits-Skala-Limit ``Critical``, der Befund ist aber explizit
        # ausgewiesen (rule_ref ``ACI-PLSQLI``).
        self.plsql_injection_level = config.get(
            "plsql_injection_level", "Critical")
        self.literal_level = config.get("literal_only_level", "Warning")
        self.sanitized_level = config.get("sanitized_level", "Warning")
        self.unknown_level = config.get("unknown_dynamic_level", "High")
        self.sanitizers = [s.lower() for s in config.get("sanitizers", []) or []]
        # APEX/ORDS: benutzerkontrollierte Page Items / Session State als
        # eigene, praezise benannte Taint-Quelle. Rein konfigurationsgetrieben
        # (``apex_taint_patterns`` in der Regeldatei, nur Oracle) - ohne diese
        # Liste bleibt das Verhalten unveraendert. Ein passender Operand wird
        # weiterhin als ``tainted`` gewertet, aber mit Quelle ``apex`` typisiert
        # (1st-order, benutzerkontrolliert), sodass die Meldung das APEX Item
        # statt einer generischen Quelle ausweist.
        apex_pats = config.get("apex_taint_patterns", []) or []
        self._apex_re = (re.compile("|".join(apex_pats), re.I)
                         if apex_pats else None)
        # PostgreSQL: sitzungs-/GUC-getragene Benutzereingabe als eigene,
        # praezise benannte Taint-Quelle (z.B. ``current_setting('app.uid')``
        # oder ``set_config(...)``-Rueckgaben). Rein konfigurationsgetrieben
        # (``session_taint_patterns`` in der Regeldatei); ohne die Liste
        # bleibt das Verhalten unveraendert. Ein passender Operand galt schon
        # bisher als ``tainted`` (Funktionsaufruf), wird nun aber mit Quelle
        # ``session`` typisiert, sodass die Meldung die GUC-Quelle ausweist.
        session_pats = config.get("session_taint_patterns", []) or []
        self._session_re = (re.compile("|".join(session_pats), re.I)
                            if session_pats else None)
        # Interprozedurale Taint (Call-Graph innerhalb der Datei): erkennt,
        # wenn eine Hilfsroutine dynamisches SQL aus einem ihrer Parameter
        # baut und eine andere Routine dabei einen ungeprueften Wert (ihren
        # eigenen Parameter bzw. eine Session-/GUC-Quelle) an genau diesen
        # Parameter uebergibt. Konservativ und additiv; per Regeldatei
        # abschaltbar (``interprocedural: false``).
        self.interprocedural = bool(config.get("interprocedural", True))
        self.interprocedural_level = config.get(
            "interprocedural_level", self.tainted_level)
        # Offset der gerade analysierten Ausführungsstelle. Begrenzt die
        # Variablenverfolgung auf Zuweisungen DAVOR (gesetzt in run()).
        self._exec_offset = None
        # Memoisierung von _operand_kind je Ausführungsstelle. Wird in
        # run() vor jeder Stelle geleert (der Offset ist dann konstant,
        # sodass (operand, depth) als Cache-Schlüssel genügt).
        self._operand_cache: dict = {}
        # Aufsteigend sortierte Offsets der Kontrollfluss-Schlüsselworte
        # (einmal je Datei in run() ermittelt - siehe _classify_variable).
        self._cf_positions: list = []
        # Je Ausführungsstelle gesammelte Taint-Quellen (parameter/table),
        # für die Typisierung der Findings (gesetzt/geleert in run()).
        self._taint_sources: set = set()

    # -- SQL-Ausdruck eines dynamischen Statements einsammeln -------------
    @staticmethod
    def _extract_expr(source, dyn):
        """Liefert ``(expr_code, expr_masked, has_using)`` zu einer vom
        Lexer gelieferten dynamischen SQL-Stelle.

        Die Ausdrucksgrenze (``dyn.expr_end``) stammt aus den
        Statement-Grenzen des Lexers - sie ersetzt die frühere
        Heuristik "bis zum nächsten ``;``". Eine OUT-Bindung
        (INTO / USING / BULK COLLECT) wird abgeschnitten.
        """
        masked = source.code_masked
        code = source.code_no_comments
        expr_start = dyn.expr_start
        region = masked[expr_start:dyn.expr_end]
        cut = len(region)
        for m in re.finditer(r"\b(INTO|USING|BULK\s+COLLECT)\b", region, re.I):
            cut = min(cut, m.start())
        has_using = bool(re.search(r"\bUSING\b", region, re.I))
        expr_code = code[expr_start:expr_start + cut].strip()
        # Gleicher Bereich, gleiche Strip-Logik: expr_code und
        # expr_masked bleiben dadurch zeichenweise ausgerichtet.
        expr_masked = masked[expr_start:expr_start + cut].strip()
        return expr_code, expr_masked, has_using

    # -- Klassifikation ---------------------------------------------------
    def _classify(self, source, expr_code, expr_masked, has_using):
        """Klassifiziert den Ausdruck eines dynamischen SQL-Statements."""
        expr = expr_code.strip()
        if not expr:
            return DynamicSqlAssessment(DynamicSqlRisk.NONE, "leerer Ausdruck")
        if (self.dialect in ("postgres", "postgresql")
                and re.match(r"format\s*\(", expr, re.I)):
            return self._classify_format(source, expr, has_using)
        if "||" in expr_masked:
            return self._classify_concat(source, expr_code, has_using)
        if re.search(r"\bconcat\s*\(", expr_masked, re.I):
            return self._classify_concat_call(
                source, expr_code, expr_masked, has_using)
        if _is_string_literal(expr):
            if has_using:
                return DynamicSqlAssessment(
                    DynamicSqlRisk.BIND_SAFE,
                    "statischer SQL-Text, Werte über Bindevariablen (USING)",
                    has_bind=True)
            return DynamicSqlAssessment(
                DynamicSqlRisk.LITERAL_ONLY,
                "ausschließlich aus einem String-Literal gebildet")
        if _BARE_VAR_RE.match(expr):
            return self._classify_variable(source, expr.strip('"'), has_using)
        return DynamicSqlAssessment(
            DynamicSqlRisk.UNKNOWN_DYNAMIC,
            "dynamischer SQL-Ausdruck unbekannter Herkunft (z.B. "
            "Funktionsaufruf)", has_unknown_variable=True)

    def _variable_assignments(self, source, var):
        """Routine-lokale Schreibzugriffe auf ``var`` vor der aktuellen
        Ausführungsstelle (``self._exec_offset``).

        Dünner Wrapper um :func:`_collect_var_writes` - berücksichtigt
        positionssensitiv nur Schreibzugriffe *vor* der Ausführung und
        innerhalb derselben Routine.
        """
        return _collect_var_writes(source, var, self._exec_offset)

    def _operand_kind(self, source, operand, depth=0):
        """Klassifiziert einen Konkatenations-Operanden.

        Ist der Operand eine reine Variable, werden ihre Zuweisungen bis
        zu :data:`_MAX_TAINT_RESOLVE_DEPTH` Ebenen tief verfolgt (einfache
        Taint-Verfolgung): hält die Variable nur Literale bzw. sanitisierte
        Werte, gilt sie nicht als ``tainted``. Das vermeidet Fehlalarme,
        wenn z.B. ein zuvor mit DBMS_ASSERT abgesicherter Wert konkateniert
        wird oder ein Literal ueber mehrere Zwischenvariablen weiterge-
        reicht wird (``v1:='x'; v2:=v1; v3:=v2; ...``). Am Tiefenlimit wird
        konservativ ``tainted`` angenommen.

        Die Ergebnisse werden je Ausführungsstelle gecacht
        (``_operand_cache``): ohne diese Memoisierung würde die
        rekursive Variablenverfolgung bei großen Dateien mit vielen
        verschachtelten Konkatenationen exponentiell teuer.
        """
        cache_key = (operand, depth)
        cached = self._operand_cache.get(cache_key)
        if cached is not None:
            kind, sources = cached
            self._taint_sources |= sources       # Quellen-Info mitführen
            return kind
        before = set(self._taint_sources)
        kind = self._operand_kind_uncached(source, operand, depth)
        self._operand_cache[cache_key] = (
            kind, frozenset(self._taint_sources - before))
        return kind

    def _operand_kind_uncached(self, source, operand, depth=0):
        op = operand.strip()
        # PostgreSQL ``format()`` NICHT pauschal als Sanitizer werten: ob der
        # Aufruf entschaerft, entscheiden die Platzhalter (%I/%L escapen,
        # %s nicht). ``format(`` steht zwar in der Sanitizer-Liste (greift fuer
        # den Top-Level-Fall in _classify_format), aber als Konkatenations-
        # Operand wuerde ``... || format('%s', x)`` sonst faelschlich als
        # ``sanitized`` gelten - eine uebersehene Injection. Hier wird der
        # Operand ueber dieselbe Platzhalter-Logik wie ein Top-Level-format()
        # bewertet.
        if (self.dialect in ("postgres", "postgresql")
                and re.match(r"format\s*\(", op, re.I)):
            fa = self._classify_format(source, op, False)
            return {
                DynamicSqlRisk.SANITIZED_CONCAT: "sanitized",
                DynamicSqlRisk.LITERAL_ONLY: "literal",
            }.get(fa.risk, "tainted")
        kind = _classify_operand(op, self.sanitizers)
        # APEX Page Item / Session State als praezise Taint-Quelle markieren
        # (bleibt 'tainted', wird aber als benutzerkontrollierte APEX-Quelle
        # typisiert). z.B. :P1_NAME, V('P1_X'), APEX_UTIL.GET_SESSION_STATE.
        if (kind == "tainted" and self._apex_re is not None
                and self._apex_re.search(op)):
            self._taint_sources.add("apex")
        # PostgreSQL-Session-/GUC-Quelle (current_setting/set_config).
        if (kind == "tainted" and self._session_re is not None
                and self._session_re.search(op)):
            self._taint_sources.add("session")
        if kind != "tainted" or depth >= _MAX_TAINT_RESOLVE_DEPTH:
            return kind
        name = op.strip('"')
        if not _BARE_VAR_RE.match(name):
            return "tainted"        # Funktionsaufruf o.ä. - bleibt tainted
        assignments = self._variable_assignments(source, name)
        if not assignments:
            return "tainted"        # keine Zuweisung sichtbar (lokale Variable)
        resolved = set()
        for _pos, rhs_code, rhs_masked, wkind in assignments:
            if wkind == "parameter":
                # ungeprüfter Routine-Parameter -> 1st-order-Taint
                self._taint_sources.add("parameter")
                resolved.add("tainted")
                continue
            if wkind == "fetch_into":
                # Cursor-Wert -> konservativ 2nd-order-Taint
                self._taint_sources.add("table")
                resolved.add("tainted")
                continue
            if wkind in ("select_into", "returning_into"):
                # SELECT-/RETURNING-Quelle differenzieren:
                # Literal/Sanitizer/Tabelle.
                skind = self._select_into_source_kind(rhs_code)
                if skind == "literal":
                    resolved.add("literal")
                elif skind == "sanitized":
                    resolved.add("sanitized")
                else:
                    self._taint_sources.add("table")
                    resolved.add("tainted")
                continue
            if "||" in rhs_masked:
                sub = [self._operand_kind(source, p, depth + 1)
                       for p in _split_concat(rhs_code)]
                if "tainted" in sub:
                    resolved.add("tainted")
                elif "sanitized" in sub:
                    resolved.add("sanitized")
                else:
                    resolved.add("literal")
            else:
                resolved.add(self._operand_kind(source, rhs_code, depth + 1))
        if "tainted" in resolved:
            return "tainted"
        if "sanitized" in resolved:
            return "sanitized"
        return "literal"

    def _pick_source(self):
        """Schärfste an dieser Ausführungsstelle gesammelte Taint-Quelle.

        ``apex`` (benutzerkontrolliertes Page Item / Session State) ist die
        spezifischste und wird bevorzugt ausgewiesen.
        """
        if "apex" in self._taint_sources:
            return "apex"
        if "session" in self._taint_sources:
            return "session"
        if "parameter" in self._taint_sources:
            return "parameter"
        if "table" in self._taint_sources:
            return "table"
        return None

    def _classify_concat(self, source, expr_code, has_using):
        """Bewertet einen per ``||`` konkatenierten Ausdruck."""
        parts = _split_concat(expr_code)
        kinds = [self._operand_kind(source, p) for p in parts]
        has_sanitizer = "sanitized" in kinds
        if "tainted" in kinds:
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "die Konkatenation enthält ungeprüfte/unvalidierte Werte",
                has_concat=True, has_bind=has_using,
                has_sanitizer=has_sanitizer, source=self._pick_source())
        if has_sanitizer:
            return DynamicSqlAssessment(
                DynamicSqlRisk.SANITIZED_CONCAT,
                "alle variablen Anteile sind über Sanitizer "
                "(DBMS_ASSERT bzw. quote_ident/quote_literal) abgesichert",
                has_concat=True, has_bind=has_using, has_sanitizer=True)
        return DynamicSqlAssessment(
            DynamicSqlRisk.LITERAL_ONLY,
            "die Konkatenation besteht ausschließlich aus String-Literalen",
            has_concat=True, has_bind=has_using)

    def _classify_concat_call(self, source, expr_code, expr_masked, has_using):
        """Bewertet dynamisches SQL, das mit der Funktion ``concat()``
        zusammengesetzt wird (Alternative zur ``||``-Verkettung)."""
        operands = _concat_func_operands(expr_code)
        if not operands:
            return DynamicSqlAssessment(
                DynamicSqlRisk.UNKNOWN_DYNAMIC,
                "concat()-Aufruf ohne erkennbare Argumente",
                has_unknown_variable=True)
        kinds = [self._operand_kind(source, op) for op in operands]
        has_sanitizer = "sanitized" in kinds
        if "tainted" in kinds:
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "die concat()-Verkettung enthält ungeprüfte/unvalidierte "
                "Werte", has_concat=True, has_bind=has_using,
                has_sanitizer=has_sanitizer, source=self._pick_source())
        if has_sanitizer:
            return DynamicSqlAssessment(
                DynamicSqlRisk.SANITIZED_CONCAT,
                "concat()-Verkettung, alle variablen Anteile sind über "
                "Sanitizer abgesichert",
                has_concat=True, has_bind=has_using, has_sanitizer=True)
        return DynamicSqlAssessment(
            DynamicSqlRisk.LITERAL_ONLY,
            "concat()-Verkettung ausschließlich aus String-Literalen",
            has_concat=True, has_bind=has_using)

    def _classify_format(self, source, expr, has_using):
        """Bewertet einen PostgreSQL-``format()``-Aufruf.

        Nur ein **literaler** Formatstring darf anhand seiner
        Platzhalter bewertet werden (``%I``/``%L`` entschärfend, ``%s``
        riskant). Ist der Formatstring variabel - ein Routine-Parameter,
        eine Variable, ein Funktionsergebnis oder ein Tabellenwert -,
        bestimmt der Aufrufer bzw. die Datenlage die Platzhalter-Politik.
        Der Aufruf gilt dann **nicht** als harmlos, sondern wird wie
        dynamisches SQL unbekannter/getainteter Herkunft klassifiziert.
        """
        first = _format_first_arg(expr)
        if not first:
            return DynamicSqlAssessment(
                DynamicSqlRisk.UNKNOWN_DYNAMIC,
                "format() ohne erkennbares Format-Argument",
                has_unknown_variable=True)
        if len(_split_concat(first)) > 1:
            # Der Formatstring wird selbst per Konkatenation gebildet -
            # die Platzhalter-Politik ist damit nicht statisch fixiert.
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "format() mit nicht-literalem Formatstring - der "
                "Formatstring wird selbst per Konkatenation gebildet",
                has_concat=True)
        if not _is_string_literal(first):
            # Variabler Formatstring: den Formatstring selbst wie einen
            # dynamischen SQL-Ausdruck klassifizieren - Parameter ->
            # tainted (1st-order), SELECT/FETCH INTO -> 2nd-order,
            # Funktionsergebnis/unbekannt -> unknown dynamic SQL.
            inner = self._classify(source, first, first, has_using)
            return replace(
                inner,
                reason=("format() mit nicht-literalem (variablem) "
                        f"Formatstring - {inner.reason}"))
        placeholders = re.findall(r"%[A-Za-z%]", first)
        if any(p.lower() == "%s" for p in placeholders):
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "format() verwendet %s - der Wert wird ungeprüft eingesetzt "
                "(für Bezeichner %I, für Literale %L verwenden)")
        if any(p.lower() in ("%i", "%l") for p in placeholders):
            return DynamicSqlAssessment(
                DynamicSqlRisk.SANITIZED_CONCAT,
                "format() verwendet %I/%L - Bezeichner bzw. Literale werden "
                "automatisch escaped", has_sanitizer=True)
        return DynamicSqlAssessment(
            DynamicSqlRisk.LITERAL_ONLY,
            "format() (literaler Formatstring) ohne variable Platzhalter")

    def _classify_rhs(self, source, rhs_code, rhs_masked):
        """Bewertet die rechte Seite einer Variablenzuweisung."""
        rhs = rhs_code.strip()
        if not rhs:
            return DynamicSqlAssessment(
                DynamicSqlRisk.UNKNOWN_DYNAMIC, "leere Zuweisung",
                has_unknown_variable=True)
        if (self.dialect in ("postgres", "postgresql")
                and re.match(r"format\s*\(", rhs, re.I)):
            return self._classify_format(source, rhs, False)
        if "||" in rhs_masked:
            return self._classify_concat(source, rhs_code, False)
        if _is_string_literal(rhs):
            return DynamicSqlAssessment(
                DynamicSqlRisk.LITERAL_ONLY,
                "Zuweisung eines reinen String-Literals")
        # einzelner Operand: Sanitizer-Aufruf, andere Variable o.ä.
        kind = self._operand_kind(source, rhs)
        if kind == "literal":
            return DynamicSqlAssessment(
                DynamicSqlRisk.LITERAL_ONLY, "Zuweisung eines Literalwerts")
        if kind == "sanitized":
            return DynamicSqlAssessment(
                DynamicSqlRisk.SANITIZED_CONCAT,
                "Zuweisung eines über einen Sanitizer abgesicherten Werts",
                has_sanitizer=True)
        return DynamicSqlAssessment(
            DynamicSqlRisk.UNKNOWN_DYNAMIC,
            "Zuweisung aus einer statisch nicht nachvollziehbaren Quelle",
            has_unknown_variable=True)

    def _control_flow_between(self, start, end):
        """True, wenn zwischen ``start`` und ``end`` ein Kontrollfluss-
        Schlüsselwort (IF/LOOP/CASE/...) liegt.

        Nutzt die in run() einmal je Datei ermittelten, aufsteigend
        sortierten Positionen (``_cf_positions``) - so entfällt der
        wiederholte Volltext-Scan je Ausführungsstelle.
        """
        positions = self._cf_positions
        lo = bisect.bisect_left(positions, start)
        return lo < len(positions) and positions[lo] < end

    def _classify_select_source_node(self, node, depth=0):
        """Klassifiziert eine SELECT-Quell-Expression rekursiv über die
        Expression-IR.

        ``IRConcat`` wird über seine Teile aufgelöst (eine Konkatenation
        nur aus Literalen bleibt ``literal``); ein ``IRCall`` gilt als
        ``sanitized``, wenn er ein Sanitizer-Aufruf ist, sonst als
        ``tainted``. Bezeichner (Tabellenspalten), Bindevariablen und
        unbekannte Knoten gelten als ``tainted`` (2nd-order).
        """
        if depth > 6:
            return "tainted"
        if isinstance(node, IRConcat):
            kinds = {self._classify_select_source_node(p, depth + 1)
                     for p in node.parts}
            if "tainted" in kinds:
                return "tainted"
            if "sanitized" in kinds:
                return "sanitized"
            return "literal"
        if isinstance(node, IRCall):
            if _classify_operand(node.text, self.sanitizers) == "sanitized":
                return "sanitized"
            return "tainted"
        if node.kind == "literal":
            return "literal"
        return "tainted"

    def _select_into_source_kind(self, src):
        """Klassifiziert die Quell-Expression eines ``SELECT ... INTO``.

        Liefert ``literal`` (konstante Quelle - kein Risiko),
        ``sanitized`` (über einen Sanitizer abgesicherter Wert) oder
        ``tainted`` (Tabellenspalte bzw. statisch nicht nachvollziehbarer
        Wert - 2nd-order). Eine leere Quelle (z.B. ``FETCH``) gilt
        konservativ als ``tainted``. Zusammengesetzte Quellen werden über
        die Expression-IR aufgelöst (siehe :meth:`_classify_select_source_node`).
        """
        s = (src or "").strip()
        if not s:
            return "tainted"
        return self._classify_select_source_node(parse_expression(s))

    def _classify_write(self, source, rhs_code, rhs_masked, kind):
        """Bewertet einen einzelnen Schreibzugriff auf eine Variable.

        ``parameter`` ist eine 1st-order-Taint-Quelle. ``fetch_into`` gilt
        konservativ als 2nd-order (Cursor-Quelle nicht bestimmbar).
        ``select_into`` wird über die Quell-Expression differenziert
        (Literal/Sanitizer/Tabellenwert). Ein ``:=`` läuft über
        :meth:`_classify_rhs`.
        """
        if kind == "parameter":
            self._taint_sources.add("parameter")
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "der dynamische SQL-String ist ein ungeprüfter "
                "Routine-Parameter",
                source="parameter")
        if kind == "fetch_into":
            self._taint_sources.add("table")
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "der dynamische SQL-String stammt aus einem ungeprüft "
                "weiterverwendeten Cursor-Wert (FETCH ... INTO)",
                source="table")
        if kind in ("select_into", "returning_into"):
            label = ("SELECT ... INTO" if kind == "select_into"
                     else "RETURNING ... INTO")
            skind = self._select_into_source_kind(rhs_code)
            if skind == "literal":
                return DynamicSqlAssessment(
                    DynamicSqlRisk.LITERAL_ONLY,
                    f"der per {label} gelesene Wert ist ein "
                    "konstantes Literal")
            if skind == "sanitized":
                return DynamicSqlAssessment(
                    DynamicSqlRisk.SANITIZED_CONCAT,
                    f"der per {label} gelesene Wert ist über einen "
                    "Sanitizer abgesichert", has_sanitizer=True)
            self._taint_sources.add("table")
            return DynamicSqlAssessment(
                DynamicSqlRisk.TAINTED_CONCAT,
                "der dynamische SQL-String stammt aus einem ungeprüft "
                f"weiterverwendeten Tabellenwert ({label})",
                source="table")
        return self._classify_rhs(source, rhs_code, rhs_masked)

    def _classify_variable(self, source, var, has_using):
        """Verfolgt die Schreibzugriffe einer als dynamisches SQL genutzten
        Variable - positionssensitiv (nur Zugriffe vor der Ausführung,
        routine-lokal). Schreibzugriffe sind ``:=``-Zuweisungen,
        ``SELECT/FETCH INTO`` (2nd-order) sowie - implizit am Routinenkopf
        - die Eigenschaft, ein Routine-Parameter zu sein (1st-order).

        Grundsätzlich wird bei mehreren in Frage kommenden Schreibzugriffen
        konservativ der kritischste bewertet. Ausnahme - "dead-assignment
        elimination": Ist der Pfad zwischen dem ersten Schreibzugriff und
        der Ausführung kontrollfluss-frei (geradliniger Code ohne
        IF/LOOP/CASE/...) und überschreibt der textuell letzte Zugriff den
        Wert vollständig (seine rechte Seite liest die Variable nicht
        selbst), so ist nur dieser letzte Zugriff zur Ausführungszeit
        wirksam - frühere sind toter Code. Sobald Kontrollfluss im Spiel
        ist, bleibt es bei der konservativen Bewertung über alle Zugriffe.
        """
        assignments = self._variable_assignments(source, var)
        if not assignments:
            # Kein sichtbarer Schreibzugriff vor der Ausführung und kein
            # Parameter - Herkunft unklar.
            return DynamicSqlAssessment(
                DynamicSqlRisk.UNKNOWN_DYNAMIC,
                f"Variable '{var}' ohne nachvollziehbare Zuweisung vor "
                f"der Ausführung",
                has_unknown_variable=True)

        candidates = assignments
        if len(assignments) > 1 and self._exec_offset is not None:
            first_pos = assignments[0][0]
            _lp, _lc, last_masked, _lk = assignments[-1]
            straight_line = not self._control_flow_between(
                first_pos, self._exec_offset)
            # Volle Überschreibung nur, wenn die rechte Seite des letzten
            # Zugriffs die Variable nicht selbst liest (kein var := var
            # || ... bzw. var := f(var)) - sonst fließt der frühere Wert
            # weiter ein.
            overwrites = not re.search(
                r"\b" + re.escape(var) + r"\b", last_masked, re.I)
            if straight_line and overwrites:
                candidates = [assignments[-1]]

        best = None
        assign_line = None
        for pos, rhs_code, rhs_masked, kind in candidates:
            sub = self._classify_write(source, rhs_code, rhs_masked, kind)
            if best is None or _RISK_ORDER[sub.risk] > _RISK_ORDER[best.risk]:
                best = sub
                assign_line = source.line_col(pos)[0]
        best.assign_line = assign_line
        best.has_bind = best.has_bind or has_using
        # Alle beteiligten Schreibzugriffe als Taint-Quellen mitführen -
        # das Reporting zeigt sie als zusätzliche Fundstellen an.
        best.origins = [(pos, kind) for pos, _rc, _rm, kind in candidates]
        return best

    # -- Severity-/Message-Zuordnung -------------------------------------
    def _level_for(self, risk):
        return {
            DynamicSqlRisk.TAINTED_CONCAT: self.tainted_level,
            DynamicSqlRisk.UNKNOWN_DYNAMIC: self.unknown_level,
            DynamicSqlRisk.SANITIZED_CONCAT: self.sanitized_level,
            DynamicSqlRisk.LITERAL_ONLY: self.literal_level,
        }.get(risk)

    @staticmethod
    def _plsql_injection_message(label, a):
        """Eigene Meldung/Empfehlung fuer PL/SQL-Injection-Findings.

        Anders als bei klassischer SQL-Injection wird hier nicht nur ein
        einzelnes Statement injiziert, sondern ein vollstaendiger anonymer
        PL/SQL-Block (``BEGIN ... END;`` oder ``DECLARE ... BEGIN ... END;``).
        Damit lassen sich beliebige Folgen von DDL/DCL/PL/SQL-Aufrufen mit
        den Rechten des ausfuehrenden Schemas ausfuehren - typischer
        Vorbereitungsschritt fuer Rechteausweitung/Persistenz.
        """
        tag = {
            "apex":      "PL/SQL-Injection (APEX Page Item / Session State - "
                         "benutzerkontrolliert)",
            "parameter": "PL/SQL-Injection (1st-order, ungeprüfter "
                         "Routine-Parameter)",
            "table":     "PL/SQL-Injection (2nd-order, Wert aus "
                         "Tabelle/Cursor)",
        }.get(a.source, "PL/SQL-Injection")
        msg = (f"{tag}: {label} fuehrt einen anonymen PL/SQL-Block "
               f"(BEGIN/DECLARE ...) aus - {a.reason}. Anonyme Bloecke "
               f"erlauben mehrere Statements und DDL/DCL in einem "
               f"Schritt, die gesamte Block-Logik wird kompromittiert.")
        if a.assign_line is not None and a.source != "parameter":
            msg += f" Der SQL-String wird in Zeile {a.assign_line} gebildet."
        if a.has_bind:
            msg += (" Hinweis: Bindevariablen (USING) sind vorhanden, "
                    "die Konkatenation bleibt jedoch angreifbar.")
        rec = ("Keine PL/SQL-Bloecke aus konkatenierten Eingaben zusammen"
               "bauen. Stattdessen statische, vordefinierte Prozeduren mit "
               "Bindevariablen (USING) aufrufen; Eingaben mit DBMS_ASSERT "
               "(Oracle) bzw. quote_ident()/format() %I (PostgreSQL) "
               "absichern.")
        if a.source == "table":
            rec += (" 2nd-order: aus der Datenbank gelesene Werte vor "
                    "der Wiederverwendung in dynamischem SQL pruefen.")
        return msg, rec

    @staticmethod
    def _message_for(label, a):
        if a.risk == DynamicSqlRisk.TAINTED_CONCAT:
            tag = {
                "apex": "Mögliche SQL-Injection (APEX Page Item / Session "
                        "State - benutzerkontrolliert)",
                "session": "Mögliche SQL-Injection (Session-/GUC-Wert - "
                           "current_setting/set_config, potentiell "
                           "benutzerkontrolliert)",
                "parameter": "Mögliche SQL-Injection (1st-order, ungeprüfter "
                             "Routine-Parameter)",
                "table": "Mögliche SQL-Injection (2nd-order, Wert aus "
                         "Tabelle/Cursor)",
            }.get(a.source, "Mögliche SQL-Injection")
            msg = f"{tag}: {label} führt dynamisches SQL aus - {a.reason}."
            if a.assign_line is not None and a.source not in ("parameter",
                                                              "apex", "session"):
                msg += f" Der SQL-String wird in Zeile {a.assign_line} gebildet."
            if a.has_bind:
                msg += (" Hinweis: Bindevariablen (USING) sind vorhanden, "
                        "die Konkatenation bleibt jedoch angreifbar.")
            rec = ("Werte über Bindevariablen (USING) statt per "
                   "String-Konkatenation übergeben. Objektnamen mit "
                   "DBMS_ASSERT (Oracle) bzw. quote_ident()/format() %I "
                   "(PostgreSQL) absichern.")
            if a.source == "apex":
                rec += (" APEX: Page-Item-/Session-State-Werte als "
                        "Bindevariablen (:P1_x im SQL-Text) übergeben, nicht "
                        "konkatenieren.")
            if a.source == "table":
                rec += (" 2nd-order: aus der Datenbank gelesene Werte vor "
                        "der Wiederverwendung in dynamischem SQL prüfen.")
            return msg, rec
        if a.risk == DynamicSqlRisk.UNKNOWN_DYNAMIC:
            msg = (f"{label} führt dynamisches SQL aus, dessen Herkunft "
                   f"statisch nicht nachvollziehbar ist - {a.reason}.")
            if a.assign_line is not None:
                msg += f" Zuweisung in Zeile {a.assign_line}."
            rec = ("Herkunft des SQL-Strings prüfen und sicherstellen, dass "
                   "keine ungeprüften Eingaben einfließen. Nach Möglichkeit "
                   "statisches SQL oder Bindevariablen verwenden.")
            return msg, rec
        if a.risk == DynamicSqlRisk.SANITIZED_CONCAT:
            msg = (f"Dynamisches SQL ({label}) verwendet validierte/escapte "
                   f"Eingaben - {a.reason}. Verbleibendes Risiko gering.")
            rec = ("Sanitizer-Abdeckung prüfen: jeder variable Anteil muss "
                   "über DBMS_ASSERT, quote_ident()/quote_literal() oder "
                   "format() %I/%L abgesichert sein.")
            return msg, rec
        # LITERAL_ONLY
        msg = (f"Dynamisches SQL ({label}) wird ausschließlich aus String-"
               f"Literalen gebildet - {a.reason}. Aktuell kein "
               f"Injection-Risiko.")
        rec = ("Wenn möglich statisches SQL verwenden; bei späterer Aufnahme "
               "variabler Werte Bindevariablen einsetzen.")
        return msg, rec

    @staticmethod
    def _origin_locations(source, assessment):
        """Beschriftete Taint-Quellen-Fundstellen aus ``assessment.origins``
        (siehe :func:`_origin_related`)."""
        return _origin_related(source, assessment.origins)

    # -- Interprozedurale Taint (Call-Graph innerhalb der Datei) ----------
    @staticmethod
    def _simple_name(name):
        """Letzter Namensbestandteil (``pkg.proc`` -> ``proc``), gross."""
        if not name:
            return None
        return re.sub(r'\s+', '', name).rsplit(".", 1)[-1].strip('"').upper()

    def _expr_uses_bare_param(self, node, pname):
        """True, wenn ``pname`` als *ungeprüfter* (nicht sanitisierter)
        Operand in der Ausdrucks-IR eines dynamischen SQL steht.

        Konservativ: erkannt wird der klassische Konkatenationsfall
        (``'...' || p`` bzw. ``p`` als ganzer Ausdruck). Ein in einen
        Sanitizer-Aufruf gewickelter Parameter (``DBMS_ASSERT.ENQUOTE_NAME(p)``)
        zaehlt nicht als ungeprueft.
        """
        if node is None:
            return False
        target = pname.strip('"').upper()
        if isinstance(node, IRConcat):
            return any(self._expr_uses_bare_param(part, pname)
                       for part in node.parts)
        if isinstance(node, IRCall):
            # Sanitizer-Aufruf entschaerft den Parameter -> nicht ungeprueft.
            if _classify_operand(node.text, self.sanitizers) == "sanitized":
                return False
            return False
        ident = re.sub(r'\s+', '', node.text or '').strip('"').upper()
        return node.kind in ("identifier", "bind_variable") and ident == target

    def _build_sink_params(self, source, by_name):
        """Baut je Hilfsroutine die Menge ihrer Parameter, die *ungeprüft* in
        dynamisches SQL fliessen.

        ``by_name`` ist die ``{simple_name: IRRoutine}``-Abbildung der
        Routinen mit Parametern. Liefert
        ``{simple_name: [(param, index, sink_offset, sink_label)]}``.
        """
        sinks: dict = {}
        for dyn in source.ir.dynamic_sql:
            sname = self._simple_name(dyn.routine_name)
            r = by_name.get(sname) if sname else None
            if r is None:
                continue
            for idx, pname in enumerate(r.parameters):
                if self._expr_uses_bare_param(dyn.expression_ir, pname):
                    sinks.setdefault(sname, [])
                    key = (pname, idx)
                    if key not in [(p, i) for p, i, _o, _l in sinks[sname]]:
                        sinks[sname].append(
                            (pname, idx, dyn.trigger_start, dyn.label))
        return sinks

    def _arg_is_caller_tainted(self, arg, caller):
        """True, wenn das Aufrufargument im Kontext des aufrufenden Routine
        ``caller`` ungeprueft/benutzerkontrolliert ist.

        Konservativ: der Parameter des Aufrufers selbst (1st-order-Durch-
        reichung) oder eine typisierte Session-/APEX-Quelle. Alles andere
        (Literale, lokale Variablen, Funktionsergebnisse) wird nicht
        gemeldet - das haelt die interprozedurale Analyse falsch-positiv-arm.
        """
        a = arg.strip()
        if not a:
            return None
        if self._session_re is not None and self._session_re.search(a):
            return "session"
        if self._apex_re is not None and self._apex_re.search(a):
            return "apex"
        if _BARE_VAR_RE.match(a):
            up = a.strip('"').upper()
            if caller is not None and up in {p.upper()
                                             for p in caller.parameters}:
                return "parameter"
        return None

    def _interprocedural_findings(self, source):
        """Findet Aufrufstellen, an denen ein ungeprüfter Wert über die
        Aufrufgrenze in das dynamische SQL einer Hilfsroutine fliesst."""
        if not self.interprocedural:
            return []
        routines = source.ir.routines
        if len(routines) < 2:
            return []
        # {simple_name: IRRoutine} der Routinen mit Parametern - Grundlage
        # sowohl fuer die Sink-Ermittlung als auch fuer die Named-Argument-
        # Zuordnung an der Aufrufstelle.
        by_name: dict = {}
        for r in routines:
            sn = self._simple_name(r.name)
            if sn and r.parameters:
                by_name.setdefault(sn, r)
        sinks = self._build_sink_params(source, by_name)
        if not sinks:
            return []
        level = self.interprocedural_level
        masked = source.code_masked
        code = source.code_no_comments
        findings: list[Finding] = []
        seen: set = set()
        for sname, params in sinks.items():
            callee = by_name.get(sname)
            callee_params = [p.upper() for p in callee.parameters] \
                if callee else []
            call_re = re.compile(r'\b' + re.escape(sname) + r'\s*\(', re.I)
            for m in call_re.finditer(masked):
                # Definition (PROCEDURE/FUNCTION name(...)) ist kein Aufruf.
                if _prev_word_upper(masked, m.start()) in (
                        "PROCEDURE", "FUNCTION"):
                    continue
                caller = _routine_at(routines, m.start())
                # Aufruf muss aus einer *anderen* Routine kommen.
                if caller is None or self._simple_name(caller.name) == sname:
                    continue
                open_pos = m.end() - 1
                close = _paren_end_str(masked, open_pos)
                # Argumente positions- UND namensbasiert (Oracle
                # ``p_name => expr``) den Parameter-Indizes zuordnen.
                call_args = _parse_call_args(masked, code, open_pos + 1, close)
                bound = _bind_arguments(call_args, callee_params)
                for pname, idx, sink_off, sink_label in params:
                    arg = bound.get(idx)
                    if arg is None:
                        continue
                    src = self._arg_is_caller_tainted(arg, caller)
                    if not src:
                        continue
                    key = (m.start(), sname, idx)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._interproc_finding(
                        source, m.start(), level, sname, pname,
                        arg.strip(), src, sink_off, sink_label))
                    break
        return findings

    def _interproc_finding(self, source, offset, level, sname, pname,
                           arg, src, sink_off, sink_label):
        sink_line = source.line_col(sink_off)[0]
        srctag = {
            "parameter": "einen ungeprüften Parameter des aufrufenden "
                         "Unterprogramms",
            "session": "einen Session-/GUC-Wert (current_setting/set_config)",
            "apex": "ein benutzerkontrolliertes APEX Page Item / Session State",
        }.get(src, "einen ungeprüften Wert")
        msg = (f"Mögliche SQL-Injection (interprozedural): Der Aufruf von "
               f"'{sname}' übergibt {srctag} ('{arg}') an den Parameter "
               f"'{pname}', der in '{sname}' in dynamisches SQL "
               f"({sink_label}, Zeile {sink_line}) einfliesst. Die "
               f"Injection ist über diese Aufrufkette erreichbar.")
        rec = ("Den Wert bereits am Aufrufer absichern (Bindevariablen; "
               "DBMS_ASSERT bzw. quote_ident()/format() %I) oder die "
               "Hilfsroutine so umbauen, dass sie ausschliesslich "
               "Bindevariablen statt String-Konkatenation verwendet.")
        return self._finding(
            source, offset, level, msg, recommendation=rec,
            rule_ref="ACI-SQLI-IP",
            related=[("dynamisches SQL in der Hilfsroutine", sink_off)])

    def run(self, source):
        findings: list[Finding] = []
        # Kontrollfluss-Positionen einmal je Datei vorab ermitteln
        # (finditer liefert sie bereits aufsteigend sortiert).
        self._cf_positions = [
            m.start() for m in _CONTROL_FLOW_RE.finditer(source.code_masked)]
        # Die dynamischen SQL-Stellen kommen aus der IR-Schicht (Source baut
        # die IR immer auf).
        dyn_items = dynamic_sql_executions(source.ir)
        for dyn in dyn_items:
            # Variablenverfolgung auf Zuweisungen VOR dieser Stelle begrenzen.
            self._exec_offset = dyn.trigger_start
            self._operand_cache = {}        # Cache je Ausführungsstelle
            self._taint_sources = set()     # Quellen je Ausführungsstelle
            expr_code, expr_masked, has_using = self._extract_expr(
                source, dyn)
            if not expr_code:
                continue
            # Statische Cursor (OPEN c FOR SELECT ...) sind unkritisch.
            if dyn.kind == "open_for" and re.match(
                    r'^\s*(?:SELECT|WITH)\b', expr_code, re.I):
                continue
            assessment = self._classify(source, expr_code, expr_masked,
                                        has_using)
            level = self._level_for(assessment.risk)
            if level is None:           # NONE / BIND_SAFE -> kein Finding
                continue
            # PL/SQL-Injection: dynamisches SQL beginnt mit ``BEGIN`` oder
            # ``DECLARE`` (anonymer Block). Eskalation gegenueber regulaerer
            # SQL-Injection: eigene Regel-ID ``ACI-PLSQLI``, eigene Message,
            # eigener (konfigurierbarer) Schweregrad-Wert.
            is_plsql_injection = (
                assessment.risk in (DynamicSqlRisk.TAINTED_CONCAT,
                                    DynamicSqlRisk.UNKNOWN_DYNAMIC)
                and _starts_with_plsql_block(expr_code))
            if is_plsql_injection:
                level = self.plsql_injection_level
                msg, rec = self._plsql_injection_message(
                    dyn.label, assessment)
                rule_ref = "ACI-PLSQLI"
            else:
                msg, rec = self._message_for(dyn.label, assessment)
                rule_ref = dyn.label
            # Taint-Quellen (Zuweisungen/Routinenkopf) als zusätzliche
            # Fundstellen ausweisen - abschaltbar über die Option
            # ``taint_sources`` (aci.ini) bzw. ``--no-taint-sources``.
            # Liegt eine Quelle vor, wird der Kontext am Sink (EXECUTE …)
            # auf eine Zeile davor/danach reduziert - der eigentliche
            # Code steht dann in den Quell-Ausschnitten.
            related = (self._origin_locations(source, assessment)
                       if self.show_taint_sources else [])
            # Snippet/Kontext über die vollständige dynamische
            # SQL-Anweisung (Trigger bis zum abschließenden ;), damit
            # mehrzeilige Statements nicht abgeschnitten erscheinen.
            semi = source.code_masked.find(";", dyn.expr_end)
            span_end = semi + 1 if semi != -1 else dyn.expr_end
            # ``clip_to_statement=True`` + ``span_start=dyn.trigger_start``:
            # der Kontext umfasst genau die EXECUTE-IMMEDIATE/EXECUTE/OPEN-FOR-
            # Anweisung selbst (vom ``EXECUTE``-Trigger bis zum Statement-
            # Semikolon). Mehrere benachbarte dynamische SQL-Anweisungen
            # (z.B. drei aufeinanderfolgende EXECUTE IMMEDIATE auf
            # verschiedenen Zeilen) sind eigenstaendige Findings; keines
            # zieht die Nachbarn in seinen Kontext.
            findings.append(self._finding(
                source, dyn.trigger_start, level, msg,
                recommendation=rec, rule_ref=rule_ref,
                related=related, span_end=span_end,
                context_n=1 if related else None,
                clip_to_statement=True,
                span_start=dyn.trigger_start))
        # Interprozedurale Taint: ungeprüfter Wert fliesst über einen
        # Routinenaufruf in das dynamische SQL einer Hilfsroutine.
        findings.extend(self._interprocedural_findings(source))
        return findings

