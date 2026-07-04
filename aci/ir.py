"""Lightweight Intermediate Representation (IR) models for ACI.

The IR is intentionally small: it preserves source locations, routine
boundaries, statement order, assignments and dynamic SQL execution sites. It is
not a full Oracle PL/SQL or PostgreSQL PL/pgSQL compiler, but it gives checks a
single structured view instead of duplicating lexer/assignment logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def line_starts(text: str) -> list[int]:
    """Return the absolute start offset of every line in ``text``.

    ``line_starts(text)[n]`` is the offset at which line ``n`` (0-based)
    begins. It is the basis for the offset-to-(line, column) conversion
    used by both :mod:`aci.parser` and :class:`aci.source.Source` (each
    evaluates it via :func:`bisect.bisect_right`).
    """
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


@dataclass(frozen=True)
class SourceLocation:
    """A 1-based line/column pair plus the absolute character offset."""

    line: int
    column: int
    offset: int


@dataclass(frozen=True)
class SourceRange:
    """A half-open source range: ``start`` inclusive, ``end`` exclusive."""

    start: SourceLocation
    end: SourceLocation


@dataclass(frozen=True)
class IRStatement:
    """A coarse SQL/PLSQL/PLpgSQL statement."""

    kind: str
    text: str
    range: SourceRange
    routine_name: str | None = None
    routine_kind: str | None = None

    @property
    def start(self) -> int:
        return self.range.start.offset

    @property
    def end(self) -> int:
        return self.range.end.offset


@dataclass(frozen=True)
class IRRoutine:
    """A recognized routine/block boundary.

    ``parameters`` lists the routine's formal parameter names (upper-case).
    They are modelled as a taint source: a value that reaches dynamic SQL
    from a parameter is caller-controlled (1st-order) input.
    """

    dialect: str
    kind: str
    name: str | None
    range: SourceRange
    statements: tuple[IRStatement, ...] = ()
    parameters: tuple[str, ...] = ()

    @property
    def start(self) -> int:
        return self.range.start.offset

    @property
    def end(self) -> int:
        return self.range.end.offset




@dataclass(frozen=True)
class IRExpression:
    """A lightweight expression node used by dynamic-SQL analysis.

    The expression IR is deliberately shallow. It captures the common shapes
    ACI needs for security classification (literals, identifiers, function
    calls and top-level concatenations) without pretending to be a full SQL
    expression grammar.
    """

    text: str
    range: SourceRange
    kind: str


@dataclass(frozen=True)
class IRCall(IRExpression):
    """A function/procedure call expression."""

    function_name: str
    arguments: tuple[IRExpression, ...]


@dataclass(frozen=True)
class IRConcat(IRExpression):
    """A top-level ``||`` concatenation expression."""

    parts: tuple[IRExpression, ...]


@dataclass(frozen=True)
class IRAssignment:
    """A write to a variable used for dynamic-SQL taint tracking.

    ``kind`` distinguishes the write source:

    * ``assignment``     - a plain ``ziel := ausdruck`` assignment;
    * ``select_into``    - a ``SELECT ... INTO ziel`` (value read from a table);
    * ``fetch_into``     - a ``FETCH ... INTO ziel`` (value read from a cursor);
    * ``returning_into`` - a ``... RETURNING ... INTO ziel`` (value returned by
      an INSERT/UPDATE/DELETE).

    ``select_into``/``fetch_into``/``returning_into`` are 2nd-order taint
    sources: the value originates in the database and reaches the variable
    unverified.
    """

    target: str
    expression: str
    range: SourceRange
    routine_name: str | None = None
    expression_ir: IRExpression | None = None
    # Compatibility fields for existing checks. They intentionally mirror the
    # legacy lexer.Assignment attributes.
    target_start: int = 0
    expr_start: int = 0
    expr_end: int = 0
    kind: str = "assignment"


@dataclass(frozen=True)
class IRDynamicSqlExecution:
    """A dynamic SQL execution site."""

    dialect: str
    kind: str
    expression: str
    range: SourceRange
    routine_name: str | None = None
    expression_ir: IRExpression | None = None
    label: str = ""
    # Compatibility fields for existing checks. They intentionally mirror the
    # legacy lexer.DynamicSql attributes.
    trigger_start: int = 0
    trigger_end: int = 0
    expr_start: int = 0
    expr_end: int = 0




@dataclass(frozen=True)
class IRControlBlock:
    """A coarse control-flow block boundary.

    This is a preparation step for future conservative control-flow analysis.
    It currently records the location and kind of control constructs such as
    IF/ELSE/LOOP without changing existing finding semantics.
    """

    kind: str
    range: SourceRange
    statements: tuple[IRStatement, ...] = ()


@dataclass(frozen=True)
class IRParseError:
    """Recoverable parser/IR extraction diagnostic."""

    message: str
    range: SourceRange | None = None
    recoverable: bool = True


@dataclass(frozen=True)
class IRSource:
    """The lightweight IR for one source file."""

    dialect: str
    text: str
    statements: tuple[IRStatement, ...]
    routines: tuple[IRRoutine, ...]
    assignments: tuple[IRAssignment, ...]
    dynamic_sql: tuple[IRDynamicSqlExecution, ...]
    errors: tuple[IRParseError, ...] = ()
    expressions: tuple[IRExpression, ...] = ()
    control_blocks: tuple[IRControlBlock, ...] = ()


def routine_for_offset(ir: IRSource, offset: int) -> IRRoutine | None:
    """Return the innermost/most specific routine containing ``offset``."""
    matches = [r for r in ir.routines if r.start <= offset < r.end]
    if not matches:
        return None
    return min(matches, key=lambda r: r.end - r.start)


def assignments_before(
    ir: IRSource,
    variable_name: str,
    offset: int,
    routine_name: str | None = None,
) -> tuple[IRAssignment, ...]:
    """Return assignments to ``variable_name`` before ``offset``.

    If ``routine_name`` is provided, only assignments from that routine are
    returned. This is the central position/routine-sensitive lookup used by
    dynamic DDL and SQL-injection checks.
    """
    var = variable_name.upper()
    out = []
    for assignment in ir.assignments:
        if assignment.target.upper() != var:
            continue
        if assignment.target_start >= offset:
            continue
        if routine_name is not None and assignment.routine_name != routine_name:
            continue
        out.append(assignment)
    return tuple(out)


def nearest_assignment_before(
    ir: IRSource,
    variable_name: str,
    offset: int,
    routine_name: str | None = None,
) -> IRAssignment | None:
    """Return the nearest assignment before ``offset`` or ``None``."""
    assignments = assignments_before(ir, variable_name, offset, routine_name)
    return assignments[-1] if assignments else None


def dynamic_sql_executions(ir: IRSource) -> tuple[IRDynamicSqlExecution, ...]:
    """Return all dynamic SQL execution sites."""
    return ir.dynamic_sql


def _range_to_dict(rng: SourceRange | None) -> dict[str, Any] | None:
    if rng is None:
        return None
    return {
        "start": {
            "line": rng.start.line,
            "column": rng.start.column,
            "offset": rng.start.offset,
        },
        "end": {
            "line": rng.end.line,
            "column": rng.end.column,
            "offset": rng.end.offset,
        },
    }


def _expression_to_dict(expr: IRExpression | None, *, include_text: bool) -> dict[str, Any] | None:
    if expr is None:
        return None
    data: dict[str, Any] = {
        "kind": expr.kind,
        "range": _range_to_dict(expr.range),
    }
    if include_text:
        data["text"] = expr.text
    if isinstance(expr, IRCall):
        data["function_name"] = expr.function_name
        data["arguments"] = [
            _expression_to_dict(arg, include_text=include_text)
            for arg in expr.arguments
        ]
    if isinstance(expr, IRConcat):
        data["parts"] = [
            _expression_to_dict(part, include_text=include_text)
            for part in expr.parts
        ]
    return data


def ir_to_dict(ir: IRSource, *, include_text: bool = True) -> dict[str, Any]:
    """Serialize IR for tests/debugging and the optional ``--dump-ir`` CLI."""
    def statement_to_dict(stmt: IRStatement) -> dict[str, Any]:
        data = {
            "kind": stmt.kind,
            "range": _range_to_dict(stmt.range),
            "routine_name": stmt.routine_name,
            "routine_kind": stmt.routine_kind,
        }
        if include_text:
            data["text"] = stmt.text
        return data

    return {
        "dialect": ir.dialect,
        "statements": [statement_to_dict(s) for s in ir.statements],
        "routines": [
            {
                "kind": r.kind,
                "name": r.name,
                "range": _range_to_dict(r.range),
                "statements": [statement_to_dict(s) for s in r.statements],
            }
            for r in ir.routines
        ],
        "assignments": [
            {
                "target": a.target,
                "expression": a.expression if include_text else "",
                "expression_ir": _expression_to_dict(a.expression_ir, include_text=include_text),
                "range": _range_to_dict(a.range),
                "routine_name": a.routine_name,
                "target_start": a.target_start,
                "expr_start": a.expr_start,
                "expr_end": a.expr_end,
            }
            for a in ir.assignments
        ],
        "dynamic_sql": [
            {
                "kind": d.kind,
                "label": d.label,
                "expression": d.expression if include_text else "",
                "expression_ir": _expression_to_dict(d.expression_ir, include_text=include_text),
                "range": _range_to_dict(d.range),
                "routine_name": d.routine_name,
                "trigger_start": d.trigger_start,
                "trigger_end": d.trigger_end,
                "expr_start": d.expr_start,
                "expr_end": d.expr_end,
            }
            for d in ir.dynamic_sql
        ],
        "errors": [
            {
                "message": e.message,
                "range": _range_to_dict(e.range),
                "recoverable": e.recoverable,
            }
            for e in ir.errors
        ],
        "expressions": [
            _expression_to_dict(expr, include_text=include_text)
            for expr in ir.expressions
        ],
        "control_blocks": [
            {
                "kind": block.kind,
                "range": _range_to_dict(block.range),
                "statements": [statement_to_dict(s) for s in block.statements],
            }
            for block in ir.control_blocks
        ],
    }
