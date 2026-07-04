"""Lightweight Parser/IR builder for ACI.

This module intentionally builds on :mod:`aci.lexer`. It does not implement a
complete SQL grammar. Instead, it converts lexer results into stable IR models
with source ranges, routine association and assignment/dynamic-SQL helpers.
"""

from __future__ import annotations

import bisect
import re

from .lexer import lex
from .ir import (
    line_starts,
    IRSource,
    IRStatement,
    IRRoutine,
    IRAssignment,
    IRDynamicSqlExecution,
    IRExpression,
    IRCall,
    IRConcat,
    IRControlBlock,
    IRParseError,
    SourceLocation,
    SourceRange,
)

_KIND_RE = re.compile(r"^\s*(SELECT|WITH|INSERT|UPDATE|DELETE|MERGE|CREATE|ALTER|DROP|GRANT|REVOKE|BEGIN|DECLARE|EXECUTE|OPEN)\b", re.I)
_ASSIGN_RE = re.compile(r"^\s*(?P<target>[A-Za-z_][\w$#]*(?:\s*\.\s*[A-Za-z_][\w$#]*)?)\s*:=", re.I)
_CONTROL_TOKEN_RE = re.compile(r"\b(IF|ELSIF|ELSE|LOOP|WHILE|FOR|EXCEPTION)\b", re.I)


def _location(starts: list[int], text_len: int, offset: int) -> SourceLocation:
    offset = max(0, min(offset, text_len))
    line_idx = bisect.bisect_right(starts, offset) - 1
    if line_idx < 0:
        line_idx = 0
    return SourceLocation(line_idx + 1, offset - starts[line_idx] + 1, offset)


def _range(starts: list[int], text_len: int, start: int, end: int) -> SourceRange:
    return SourceRange(_location(starts, text_len, start), _location(starts, text_len, end))


def _routine_for_offset(routines, offset: int, _starts_cache=None):
    """Findet die Routine, die ``offset`` enthaelt.

    Routinen sind im Lexer als *konsekutive*, nicht-ueberlappende Bereiche
    abgelegt (Routine i.end == Routine i+1.start), daher gehoert jedes
    Offset zu hoechstens einer Routine. Die Suche nutzt bisect ueber die
    Start-Positionen und ist damit O(log R) statt O(R). Optional kann ein
    vorberechnetes Starts-Array uebergeben werden, um auch das einmalige
    Listcomp bei wiederholten Aufrufen zu sparen.
    """
    if not routines:
        return None
    starts = _starts_cache if _starts_cache is not None else [
        r.start for r in routines]
    idx = bisect.bisect_right(starts, offset) - 1
    if idx < 0:
        return None
    r = routines[idx]
    return r if r.end > offset else None


# Kopf einer Package-internen PROCEDURE/FUNCTION (ohne fuehrendes CREATE).
_ROUTINE_HEAD_RE = re.compile(
    r'\b(?P<kw>PROCEDURE|FUNCTION)\s+(?P<name>"[^"\n]+"|[A-Za-z_][\w$#]*)', re.I)
# SELECT/FETCH/RETURNING ... INTO <ziele> : aus einer Tabelle/einem Cursor
# gelesener bzw. von einem DML zurueckgegebener Wert -> 2nd-order-Taint-
# Quelle. Auf ein Statement begrenzt ([^;]). ``src`` ist bei SELECT die
# Auswahlliste und bei RETURNING die zurueckgegebene Ausdrucksliste
# (Quell-Expressionen); bei FETCH (Cursor) bleibt die Quelle leer.
_INTO_RE = re.compile(
    r'\b(?P<kw>SELECT|FETCH|RETURNING)\b(?P<src>[^;]*?)\bINTO\b'
    r'(?P<targets>[^;]*?)(?:\bFROM\b|\bUSING\b|;)', re.I)
_BULK_RE = re.compile(r'\bBULK\b|\bCOLLECT\b', re.I)
_WORD_RE = re.compile(r'[A-Za-z_][\w$#]*')
# Woerter, nach denen ein PROCEDURE/FUNCTION-Kopf bereits vom Lexer als
# CREATE-Routine erfasst ist bzw. gar keine Definition einleitet.
# ``ON`` faengt ``COMMENT ON FUNCTION f() IS '...'`` sowie
# ``GRANT/REVOKE EXECUTE ON PROCEDURE p`` ab: dort folgt zwar ein
# PROCEDURE/FUNCTION-Kopf, aber es ist keine Definition. Ohne diesen
# Ausschluss entstuenden Phantom-Routinen (z.B. aus jedem pg_dump-
# ``COMMENT ON FUNCTION``), die nachfolgende Statements faelschlich einem
# Routinen-/Taint-Kontext zuordnen.
_HEAD_SKIP_LEAD = frozenset(
    {"CREATE", "REPLACE", "EDITIONABLE", "NONEDITIONABLE", "DROP", "ALTER",
     "ON"})


def _prev_word(text: str, idx: int) -> str:
    """Wort unmittelbar vor ``idx`` (Whitespace uebersprungen), gross."""
    j = idx - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    end = j + 1
    while j >= 0 and (text[j].isalnum() or text[j] in "_$#"):
        j -= 1
    return text[j + 1:end].upper()


def _header_params(masked: str, head_start: int) -> tuple:
    """Parameternamen (gross) aus dem Routinenkopf ab ``head_start``.

    Steht vor der oeffnenden Klammer bereits ``IS``/``AS``/``RETURN``, ist
    die Routine parameterlos.
    """
    op = masked.find('(', head_start)
    isat = re.search(r'\b(?:IS|AS|RETURN)\b',
                     masked[head_start:head_start + 240], re.I)
    if op == -1 or (isat and head_start + isat.start() < op):
        return ()
    depth, i, n, bs, parts = 0, op, len(masked), op + 1, []
    while i < n:
        c = masked[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                parts.append(masked[bs:i])
                break
        elif c == ',' and depth == 1:
            parts.append(masked[bs:i])
            bs = i + 1
        i += 1
    names = []
    for p in parts:
        w = _WORD_RE.search(p)
        if w:
            names.append(w.group(0).upper())
    return tuple(names)


def _inner_routines(masked: str, text_len: int) -> list:
    """Findet Package-interne PROCEDURE/FUNCTION-Definitionen (ohne CREATE).

    Liefert ``[(start, end, kind, name)]``. Das Ende einer Routine wird
    bevorzugt über ihr ``END <name>;`` bestimmt; so werden auch
    verschachtelte lokale Subprogramme korrekt umschlossen (der
    most-specific-Treffer in :func:`_routine_for_offset` ordnet inneren
    Code dann der inneren Routine zu). Fehlt ein benanntes ``END``
    (z.B. blankes ``END;``), wird sequenziell bis zur nächsten Routine
    abgegrenzt. Vorwärts-Deklarationen und CREATE-Routinen entfallen.
    """
    heads = []
    for m in _ROUTINE_HEAD_RE.finditer(masked):
        s = m.start()
        # Ein PROCEDURE/FUNCTION-Kopf, dem CREATE/REPLACE/EDITIONABLE
        # vorangeht, ist bereits eine vom Lexer erfasste CREATE-Routine.
        if _prev_word(masked, s) in _HEAD_SKIP_LEAD:
            continue
        # Definition vs. Vorwaerts-Deklaration: IS/AS muss vor dem
        # naechsten ``;`` stehen.
        nxt = re.search(r'\bIS\b|\bAS\b|;', masked[s:s + 4000], re.I)
        if not nxt or masked[s + nxt.start()] == ';':
            continue
        kind = "procedure" if m.group("kw").upper() == "PROCEDURE" else "function"
        heads.append((s, kind, m.group("name").strip('"')))
    out = []
    for i, (s, kind, name) in enumerate(heads):
        seq_end = heads[i + 1][0] if i + 1 < len(heads) else text_len
        # Obergrenze der ``END <name>;``-Suche: die nächste gleichnamige
        # Routine - so vereinnahmt eine überladene Routine nicht das END
        # einer späteren mit demselben Namen.
        cap = text_len
        for s2, _k2, n2 in heads[i + 1:]:
            if n2.upper() == name.upper():
                cap = s2
                break
        # pos/endpos statt masked[s:cap]: vermeidet je Kopf eine O(n)-
        # Slice-Kopie des maskierten Textes (bei grossen Package Bodies mit
        # vielen Prozeduren war das der Speicher-/Zeit-Hotspot).
        m_end = re.compile(
            r'\bEND\s+"?' + re.escape(name) + r'"?\s*;',
            re.IGNORECASE).search(masked, s, cap)
        end = m_end.end() if m_end else seq_end
        out.append((s, end, kind, name))
    return out


_INTO_KINDS = {
    "SELECT": "select_into",
    "FETCH": "fetch_into",
    "RETURNING": "returning_into",
}


def _into_writes(masked: str, code: str) -> list:
    """Findet SELECT/FETCH/RETURNING ... INTO-Schreibzugriffe.

    Liefert ``[(offset, target_name, kind, src_text, src_start, src_end)]``.
    ``kind`` ist ``select_into``, ``fetch_into`` oder ``returning_into``.
    Bei ``SELECT``/``RETURNING`` wird jedem Ziel die zugehörige
    Quell-Expression der Auswahl-/RETURNING-Liste positionell zugeordnet
    (gleiche Anzahl vorausgesetzt); ``src_text`` stammt aus dem Code mit
    sichtbaren String-Literalen. Bei ``FETCH`` (Quelle = Cursor) bleibt die
    Quelle leer - der Check bewertet das konservativ.
    """
    out = []
    for m in _INTO_RE.finditer(masked):
        kw = m.group("kw").upper()
        kind = _INTO_KINDS[kw]
        has_src = kw in ("SELECT", "RETURNING")
        targets = _split_top_level(m.group("targets"), ",")
        tgt_base = m.start("targets")
        src_items = []
        if has_src:
            src_base = m.start("src")
            for a, b in _split_top_level(m.group("src"), ","):
                if _BULK_RE.search(masked[src_base + a:src_base + b]):
                    continue            # 'BULK COLLECT' ist keine Quelle
                src_items.append((src_base + a, src_base + b))
        for idx, (ta, tb) in enumerate(targets):
            w = _WORD_RE.search(masked[tgt_base + ta:tgt_base + tb])
            if not w:
                continue
            if has_src and len(src_items) == len(targets):
                s_a, s_b = src_items[idx]
                src_text = code[s_a:s_b].strip()
            else:
                s_a = s_b = m.start()   # FETCH / Anzahl passt nicht
                src_text = ""
            out.append((m.start(), w.group(0), kind, src_text, s_a, s_b))
    return out


def _statement_kind(text: str, masked_text: str) -> str:
    masked = masked_text.strip()
    if not masked:
        return "unknown"
    if _ASSIGN_RE.match(masked):
        return "assignment"
    if re.search(r"\bEXECUTE\s+IMMEDIATE\b", masked, re.I):
        return "execute_immediate"
    if re.search(r"\bDBMS_SQL\s*\.\s*PARSE\b", masked, re.I):
        return "dbms_sql_parse"
    if re.search(r"\bDBMS_SYS_SQL\s*\.\s*PARSE", masked, re.I):
        return "dbms_sys_sql_parse"
    if re.search(r"\bOPEN\b.+\bFOR\b", masked, re.I | re.S):
        return "open_for"
    m = _KIND_RE.match(masked)
    if not m:
        return "unknown"
    word = m.group(1).lower()
    if word == "with":
        return "select"
    if word in ("begin", "declare"):
        return "block"
    if word == "execute":
        return "execute"
    return word


def _ir_dyn_kind(kind: str) -> str:
    return "execute" if kind == "pg_execute" else kind


_SPLIT_DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
_SPLIT_QQUOTE_OPEN_RE = re.compile(r"[nN]?[qQ]'")
_SPLIT_Q_CLOSE = {"[": "]", "{": "}", "(": ")", "<": ">"}


def _split_top_level(text: str, separator: str) -> list[tuple[int, int]]:
    """Return ranges split at a top-level separator outside strings/parens.

    Beruecksichtigt neben Standard-Strings ``'...'`` (mit ``''``-Escape) auch
    PostgreSQL-Dollar-Quotes (``$tag$...$tag$``) und Oracle-q-Quotes
    (``q'X...X'``, ``nq'``). Ein ``||`` bzw. ``,`` *innerhalb* eines solchen
    Literals ist KEIN Top-Level-Trenner - sonst wuerde z.B.
    ``'PRE ' || $tag$a || b$tag$`` faelschlich in drei Operanden zerlegt und
    der harmlose Literal-Teil als getainteter Wert (False Positive) gewertet.
    """
    parts: list[tuple[int, int]] = []
    depth = 0
    in_str = False
    start = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if in_str:
            if ch == "'":
                if i + 1 < n and text[i + 1] == "'":
                    i += 2
                    continue
                in_str = False
            i += 1
            continue
        # Oracle q-Quote: q'X...X' / nq'X...X'. Vor dem q/nq darf kein
        # Bezeichnerzeichen stehen (sonst ist es Teil eines Namens).
        qm = _SPLIT_QQUOTE_OPEN_RE.match(text, i)
        if qm and (i == 0 or not (text[i - 1].isalnum()
                                  or text[i - 1] in "_$#")):
            delim = text[qm.end()] if qm.end() < n else ""
            close = _SPLIT_Q_CLOSE.get(delim, delim)
            j = text.find(close + "'", qm.end() + 1) if close else -1
            i = (j + 2) if j != -1 else n
            continue
        # PostgreSQL-Dollar-Quote: $tag$...$tag$ (auch $$...$$).
        if ch == "$":
            dm = _SPLIT_DOLLAR_TAG_RE.match(text, i)
            if dm:
                tag = dm.group(0)
                j = text.find(tag, dm.end())
                i = (j + len(tag)) if j != -1 else n
                continue
        if ch == "'":
            in_str = True
            i += 1
            continue
        if ch == "(":
            depth += 1
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0 and text.startswith(separator, i):
            parts.append((start, i))
            i += len(separator)
            start = i
            continue
        i += 1
    parts.append((start, n))
    return parts


# Obergrenze der Ausdrucks-Rekursion. Tief verschachtelte Ausdruecke
# (z.B. ``f(f(f(...)))`` mit tausenden Ebenen, auch aus boesartig erzeugtem
# Code) wuerden sonst einen ``RecursionError`` ausloesen und - da parse_ir
# nur den Lexer absichert - den Scan der ganzen Datei/des Verzeichnisses
# abbrechen. Ab dieser Tiefe wird der Rest konservativ als ``unknown``
# behandelt (Checks bleiben damit vorsichtig).
_MAX_EXPR_DEPTH = 60


def parse_expression(expression_text: str, starts: list[int] | None = None,
                     text_len: int | None = None, base_offset: int = 0,
                     _depth: int = 0) -> IRExpression:
    """Parse a shallow expression IR node.

    This helper intentionally recognizes only high-value expression shapes:
    string/numeric literals, bind variables, identifiers, function calls and
    top-level ``||`` concatenations. Unknown/complex expressions are preserved
    as ``kind="unknown"`` so checks can remain conservative.
    """
    if starts is None:
        starts = line_starts(expression_text)
        base_offset = 0
    if text_len is None:
        text_len = max(len(expression_text), base_offset + len(expression_text))
    raw = expression_text
    stripped = raw.strip()
    leading = len(raw) - len(raw.lstrip())
    start = base_offset + leading
    end = start + len(stripped)
    rng = _range(starts, text_len, start, end)
    if not stripped:
        return IRExpression(stripped, rng, "unknown")
    if _depth >= _MAX_EXPR_DEPTH:
        return IRExpression(stripped, rng, "unknown")

    concat_ranges = _split_top_level(stripped, "||")
    if len(concat_ranges) > 1:
        parts = tuple(
            parse_expression(stripped[a:b], starts, text_len, start + a,
                             _depth + 1)
            for a, b in concat_ranges
            if stripped[a:b].strip()
        )
        return IRConcat(stripped, rng, "concat", parts)

    if re.match(r"^[nN]?[qQ]?'", stripped) or stripped.startswith("'"):
        return IRExpression(stripped, rng, "literal")
    if re.match(r"^\d+(?:\.\d+)?$", stripped):
        return IRExpression(stripped, rng, "literal")
    if re.match(r"^[:$][A-Za-z_][\w$#]*$", stripped):
        return IRExpression(stripped, rng, "bind_variable")

    call = re.match(
        r"^(?P<fn>[A-Za-z_][\w$#]*(?:\s*\.\s*[A-Za-z_][\w$#]*)*)\s*\((?P<args>.*)\)$",
        stripped, re.S)
    if call:
        args_text = call.group("args")
        args_base = start + call.start("args")
        arg_ranges = _split_top_level(args_text, ",") if args_text.strip() else []
        args = tuple(
            parse_expression(args_text[a:b], starts, text_len, args_base + a,
                             _depth + 1)
            for a, b in arg_ranges
            if args_text[a:b].strip()
        )
        fn = re.sub(r"\s+", "", call.group("fn"))
        kind = "format_call" if fn.lower() == "format" else "call"
        return IRCall(stripped, rng, kind, fn, args)

    if re.match(r'^"?[A-Za-z_][\w$#]*(?:"?\s*\.\s*"?[A-Za-z_][\w$#]*)?"?$', stripped):
        return IRExpression(stripped, rng, "identifier")
    return IRExpression(stripped, rng, "unknown")


def _control_blocks(masked_text: str, starts: list[int], text_len: int,
                    statements: list[IRStatement]) -> list[IRControlBlock]:
    blocks: list[IRControlBlock] = []
    # Statements sind konsekutiv und nicht ueberlappend; das enthaltende
    # Statement wird per bisect in O(log S) statt linear ueber alle
    # Statements gesucht (frueherer O(Tokens x Statements)-Hotspot).
    stmt_starts = [s.start for s in statements]
    for m in _CONTROL_TOKEN_RE.finditer(masked_text):
        word = m.group(1).lower()
        kind = "elsif" if word == "elsif" else word
        idx = bisect.bisect_right(stmt_starts, m.start()) - 1
        stmt_tuple: tuple = ()
        if idx >= 0 and statements[idx].start <= m.start() < statements[idx].end:
            stmt_tuple = (statements[idx],)
        blocks.append(IRControlBlock(kind, _range(starts, text_len, m.start(), m.end()), stmt_tuple))
    return blocks


def parse_ir(source_text: str, dialect: str = "oracle", lexed=None) -> IRSource:
    """Build the lightweight IR for ``source_text``.

    Parse errors are represented in ``IRSource.errors``. The current builder is
    lexer-backed and should therefore normally be recoverable for malformed SQL.

    ``lexed`` kann ein bereits vorhandenes :class:`~aci.lexer.LexResult`
    desselben Quelltexts/Dialekts sein. :class:`aci.source.Source` reicht so
    sein eigenes Lex-Ergebnis durch, damit dieselbe Datei nicht zweimal
    lexikalisch analysiert wird (vormals lexte Source einmal und parse_ir ein
    weiteres Mal - doppelte Tokenisierung pro Datei).
    """
    dialect = (dialect or "oracle").lower()
    starts = line_starts(source_text)
    text_len = len(source_text)
    errors: list[IRParseError] = []
    if lexed is None:
        try:
            lexed = lex(source_text, dialect)
        except Exception as exc:  # defensive fallback: caller can keep scanning
            errors.append(
                IRParseError(f"lexer failed: {type(exc).__name__}: {exc}"))
            return IRSource(dialect, source_text, (), (), (), (), tuple(errors))

    # Routinen: vom Lexer erkannte CREATE-Routinen plus Package-interne
    # PROCEDURE/FUNCTION-Definitionen (ohne CREATE). Beide tragen ihre
    # Parameterliste als Taint-Quelle.
    routines_base = [
        IRRoutine(
            dialect=r.dialect,
            kind=r.kind,
            name=r.name,
            range=_range(starts, text_len, r.start, r.end),
            statements=(),
            parameters=_header_params(lexed.code_masked, r.start),
        )
        for r in lexed.routines
    ]
    for s, e, kind, name in _inner_routines(lexed.code_masked, text_len):
        routines_base.append(IRRoutine(
            dialect=dialect,
            kind=kind,
            name=name,
            range=_range(starts, text_len, s, e),
            statements=(),
            parameters=_header_params(lexed.code_masked, s),
        ))

    # Routine-Starts einmal vorab cachen; alle nachfolgenden
    # ``_routine_for_offset``-Aufrufe verwenden das Cache und sind so
    # O(log R) statt O(R) pro Aufruf (Listcomp innerhalb der Funktion
    # waere sonst der versteckte Hotspot bei tausenden Aufrufen).
    routine_starts_base = [r.start for r in routines_base]
    statements: list[IRStatement] = []
    for stmt in lexed.statements:
        routine = _routine_for_offset(
            routines_base, stmt.start, routine_starts_base)
        raw = lexed.code_no_comments[stmt.start:stmt.end]
        masked = lexed.code_masked[stmt.start:stmt.end]
        statements.append(IRStatement(
            kind=_statement_kind(raw, masked),
            text=raw,
            range=_range(starts, text_len, stmt.start, stmt.end),
            routine_name=(routine.name if routine else None),
            routine_kind=(routine.kind if routine else None),
        ))

    # Statement-Starts vorab fuer bisect-Suche: pro Routine die Slice der
    # enthaltenen Statements ueber zwei bisect-Aufrufe holen statt linear
    # ueber alle Statements zu iterieren. Bei R Routinen und S Statements
    # ist die naive Variante O(R*S) - bei 300+ Funktionen und tausenden
    # Statements pro Datei der Hauptzeitfresser des Source-Aufbaus.
    stmt_starts_arr = [s.start for s in statements]
    routines: list[IRRoutine] = []
    for routine in routines_base:
        lo = bisect.bisect_left(stmt_starts_arr, routine.start)
        hi = bisect.bisect_left(stmt_starts_arr, routine.end)
        r_statements = tuple(statements[lo:hi])
        routines.append(IRRoutine(
            dialect=routine.dialect,
            kind=routine.kind,
            name=routine.name,
            range=routine.range,
            statements=r_statements,
            parameters=routine.parameters,
        ))

    # Auch fuer die IR-Routinen (mit den eingebetteten Statement-Tupeln)
    # vorab Starts-Cache anlegen - dasselbe Reason wie oben.
    routine_starts_ir = [r.start for r in routines]

    assignments: list[IRAssignment] = []
    expressions: list[IRExpression] = []
    for assignment in lexed.assignments:
        routine = _routine_for_offset(
            routines, assignment.target_start, routine_starts_ir)
        expression_ir = parse_expression(
            assignment.expression, starts, text_len, assignment.expr_start)
        expressions.append(expression_ir)
        assignments.append(IRAssignment(
            target=assignment.target,
            expression=assignment.expression,
            range=_range(starts, text_len, assignment.target_start, assignment.expr_end),
            routine_name=(routine.name if routine else None),
            expression_ir=expression_ir,
            target_start=assignment.target_start,
            expr_start=assignment.expr_start,
            expr_end=assignment.expr_end,
            kind="assignment",
        ))
    # SELECT/FETCH ... INTO als 2nd-order-Taint-Schreibzugriffe ergaenzen.
    # Bei SELECT wird die Quell-Expression mitgefuehrt, damit der Check
    # Literal/Sanitizer/Tabellenwert unterscheiden kann.
    for off, name, kind, src_text, s_a, s_b in _into_writes(
            lexed.code_masked, lexed.code_no_comments):
        routine = _routine_for_offset(routines, off, routine_starts_ir)
        src_ir = (parse_expression(src_text, starts, text_len, s_a)
                  if src_text else None)
        assignments.append(IRAssignment(
            target=name,
            expression=src_text,
            range=_range(starts, text_len, off, max(s_b, off)),
            routine_name=(routine.name if routine else None),
            expression_ir=src_ir,
            target_start=off,
            expr_start=s_a,
            expr_end=s_b,
            kind=kind,
        ))
    assignments.sort(key=lambda a: a.target_start)

    dynamic_sql: list[IRDynamicSqlExecution] = []
    for dyn in lexed.dynamic_sql:
        routine = _routine_for_offset(
            routines, dyn.trigger_start, routine_starts_ir)
        expr_text = lexed.code_no_comments[dyn.expr_start:dyn.expr_end].strip()
        expression_ir = parse_expression(expr_text, starts, text_len, dyn.expr_start)
        expressions.append(expression_ir)
        dynamic_sql.append(IRDynamicSqlExecution(
            dialect=dialect,
            kind=_ir_dyn_kind(dyn.kind),
            expression=expr_text,
            range=_range(starts, text_len, dyn.trigger_start, dyn.expr_end),
            routine_name=(routine.name if routine else None),
            expression_ir=expression_ir,
            label=dyn.label,
            trigger_start=dyn.trigger_start,
            trigger_end=dyn.trigger_end,
            expr_start=dyn.expr_start,
            expr_end=dyn.expr_end,
        ))

    return IRSource(
        dialect=dialect,
        text=source_text,
        statements=tuple(statements),
        routines=tuple(routines),
        assignments=tuple(assignments),
        dynamic_sql=tuple(dynamic_sql),
        errors=tuple(errors),
        expressions=tuple(expressions),
        control_blocks=tuple(_control_blocks(lexed.code_masked, starts, text_len, statements)),
    )
