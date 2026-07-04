"""Kleiner, stabiler Lexer für Oracle PL/SQL und PostgreSQL PL/pgSQL.

Der Lexer ist die Parser-Grundlage von ACI. Er erkennt zuverlässig:

* **Kommentare** - ``-- Zeile`` und ``/* Block */`` (in PostgreSQL
  korrekt verschachtelbar, in Oracle nicht).
* **String-Literale** - Standard ``'...'`` mit ``''``-Escape, Oracle
  q-Quotes (``q'X...X'``, auch ``nq'``), PostgreSQL-Dollar-Quote-Strings.
* **Dollar-Quote-Code-Rümpfe** - der Körper von ``CREATE FUNCTION ...
  AS $$ ... $$`` bzw. ``DO $$ ... $$`` ist Code und wird normal zerlegt.
* **Statement-Grenzen** - lexikalisch: ein ``;`` (außerhalb von Strings
  und Kommentaren) bzw. eine ``/``-Zeile beendet ein Statement.
* **Dynamische SQL-Ausführungen** - EXECUTE IMMEDIATE, OPEN ... FOR,
  DBMS_SQL.PARSE, DBMS_SYS_SQL.PARSE[_AS_USER], PL/pgSQL-EXECUTE.
* **Routinen** - Funktionen, Prozeduren, Trigger, Packages, anonyme
  Blöcke und DO-Blöcke (Name, Typ, Dialekt, Bereich).
* **Zuweisungen** - einfache ``ziel := ausdruck``-Zuweisungen als
  Grundlage einer späteren Datenflussanalyse.

Bewusst **kein vollständiger Parser**: es gibt keine Grammatik- oder
Block-Analyse (BEGIN/END-Schachtelung). Der Lexer liefert eine
verlässliche Token-Schicht - genauer als reine Regex über Rohtext,
aber klein, deterministisch und wartbar. Die Heuristik-Checks setzen
unverändert darauf auf.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Tokentypen.
TOK_CODE = "code"
TOK_LINE_COMMENT = "line_comment"
TOK_BLOCK_COMMENT = "block_comment"
TOK_STRING = "string"
# Begrenzter (quotierter) Bezeichner ``"..."``. Als eigenes Token gefuehrt,
# damit seine Inhalte (z.B. ein ``;`` in ``"my;col"``) nicht als
# Statement-Trenner zaehlen; fuer die Muster-Checks bleibt er in
# ``code_masked`` unveraendert sichtbar (Routinennamen koennen quotiert sein).
TOK_QIDENT = "qident"

# Dollar-Quote-Begrenzer ($$ bzw. $tag$).
_DOLLAR_TAG_RE = re.compile(r"\$(?:[A-Za-z_]\w*)?\$")
# Schlüsselworte, nach denen ein Dollar-Quote einen Code-Rumpf einleitet.
_CODE_BODY_LEAD = frozenset({"AS", "IS", "DO"})
# Bezeichner (auch in Anführungszeichen).
_IDENT = r'(?:"[^"\n]+"|[A-Za-z_][\w$#]*)'
# Schließende Begrenzer für Oracle-q-Quotes.
_Q_CLOSE = {"[": "]", "{": "}", "(": ")", "<": ">"}

_PG_DIALECTS = ("postgres", "postgresql")

# Routine-Definitionen (Oracle und PostgreSQL).
_ROUTINE_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?"
    r"(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
    r"(?P<kind>PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TRIGGER)\s+"
    r"(?P<name>" + _IDENT + r"(?:\s*\.\s*" + _IDENT + r")?)",
    re.IGNORECASE)

# Zuweisung  "ziel := ..."  - gesucht wird auf der maskierten Variante,
# ein ":=" in einem String oder Kommentar löst daher nichts aus.
_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][\w$#]*(?:\s*\.\s*[A-Za-z_][\w$#]*)?)\s*:=")

# Typnamen zum Aussortieren von Deklarations-Defaults: bei
# "pi NUMBER := 3.14" steht vor dem := der Typ, nicht die Zielvariable.
_TYPE_WORDS = frozenset({
    "NUMBER", "NUMERIC", "DECIMAL", "DEC", "INTEGER", "INT", "SMALLINT",
    "BIGINT", "FLOAT", "REAL", "BINARY_FLOAT", "BINARY_DOUBLE",
    "BINARY_INTEGER", "PLS_INTEGER", "SIMPLE_INTEGER", "BOOLEAN", "BOOL",
    "VARCHAR2", "NVARCHAR2", "VARCHAR", "NCHAR", "CHAR", "CHARACTER",
    "CLOB", "NCLOB", "BLOB", "BFILE", "LONG", "RAW", "ROWID", "UROWID",
    "DATE", "TIMESTAMP", "TIMESTAMPTZ", "INTERVAL", "XMLTYPE", "JSON",
    "JSONB", "BYTEA", "TEXT", "UUID", "MONEY", "SERIAL", "BIGSERIAL",
    "SYS_REFCURSOR",
})


# ----------------------------------------------------------------------
# Datenmodell
# ----------------------------------------------------------------------

@dataclass
class Token:
    """Ein lexikalisches Token. ``start``/``end`` sind Zeichen-Offsets
    (``end`` exklusiv). Bei Strings markieren ``content_start`` und
    ``content_end`` den Inhalt ohne Begrenzer."""

    type: str
    start: int
    end: int
    content_start: int = -1
    content_end: int = -1


@dataclass
class StringSpan:
    """Position eines String-Literals im Quelltext."""

    start: int           # Offset des öffnenden Begrenzers
    end: int             # Offset hinter dem schließenden Begrenzer
    content_start: int   # Offset des ersten Inhaltszeichens
    content_end: int     # Offset hinter dem letzten Inhaltszeichen


@dataclass
class Statement:
    """Ein lexikalisches Statement (Bereich zwischen zwei Terminatoren)."""

    start: int
    end: int             # exklusiv; schließt den Terminator (; bzw. /) ein


@dataclass
class DynamicSql:
    """Eine Stelle, an der dynamisches SQL ausgeführt wird."""

    kind: str            # execute_immediate | open_for | dbms_sql_parse
    #                      | dbms_sys_sql_parse | pg_execute
    label: str           # lesbare Bezeichnung
    trigger_start: int   # Offset des auslösenden Schlüsselworts
    trigger_end: int     # Offset hinter dem Schlüsselwort
    expr_start: int      # Beginn des SQL-Ausdrucks
    expr_end: int        # Ende des Ausdrucks (vor dem nächsten ;)


@dataclass
class Routine:
    """Eine erkannte Programmeinheit.

    ``kind`` ist eine von: ``package``, ``package_body``, ``procedure``,
    ``function``, ``trigger``, ``do_block``, ``anonymous_block``.
    ``name`` ist ``None`` bei anonymen Blöcken und DO-Blöcken.
    ``start``/``end`` umschließen die Routine (``end`` reicht bis zur
    nächsten Routine bzw. zum Dateiende).
    """

    kind: str
    name: "str | None"
    dialect: str
    start: int
    end: int


@dataclass
class Assignment:
    """Eine Zuweisung ``ziel := ausdruck`` im Quelltext.

    ``expression`` ist der Ausdruckstext (ohne Kommentare, getrimmt).
    Die Liste der Zuweisungen behält die Quelltext-Reihenfolge.
    """

    target: str
    target_start: int
    expr_start: int
    expr_end: int
    expression: str


@dataclass
class LexResult:
    """Vollständiges Ergebnis der lexikalischen Analyse."""

    text: str
    dialect: str
    tokens: list = field(default_factory=list)
    code_no_comments: str = ""
    code_masked: str = ""
    string_spans: list = field(default_factory=list)
    statements: list = field(default_factory=list)
    dynamic_sql: list = field(default_factory=list)
    routines: list = field(default_factory=list)
    assignments: list = field(default_factory=list)


# ----------------------------------------------------------------------
# Hilfsfunktionen
# ----------------------------------------------------------------------

def _preceding_token(text: str, idx: int) -> str:
    """Liefert das Wort unmittelbar vor ``idx`` (Whitespace übersprungen)."""
    j = idx - 1
    while j >= 0 and text[j] in " \t\r\n":
        j -= 1
    end = j + 1
    while j >= 0 and (text[j].isalnum() or text[j] == "_"):
        j -= 1
    return text[j + 1:end]


def _opens_code_body(text: str, idx: int) -> bool:
    """Heuristik: Leitet der Dollar-Quote bei ``idx`` einen Code-Rumpf ein?

    Wahr, wenn unmittelbar davor ``AS``, ``IS`` oder ``DO`` steht.
    Verschachtelte Dollar-Quotes müssen - wie von PostgreSQL gefordert -
    unterschiedliche Tags verwenden ($func$ / $msg$).
    """
    return _preceding_token(text, idx).upper() in _CODE_BODY_LEAD


# ----------------------------------------------------------------------
# Tokenizer
# ----------------------------------------------------------------------

def _tokenize(text: str, dialect: str) -> list:
    """Zerlegt den Quelltext in eine lückenlose Tokenfolge."""
    n = len(text)
    is_pg = dialect in _PG_DIALECTS
    tokens: list = []
    dollar_close: set = set()      # Offsets schließender Code-Rumpf-Begrenzer
    code_start = 0                 # Beginn des laufenden CODE-Laufs
    i = 0

    def flush_code(upto: int) -> None:
        if upto > code_start:
            tokens.append(Token(TOK_CODE, code_start, upto))

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # -- Zeilenkommentar -----------------------------------------------
        if ch == "-" and nxt == "-":
            flush_code(i)
            j = i
            while j < n and text[j] != "\n":
                j += 1
            tokens.append(Token(TOK_LINE_COMMENT, i, j))
            code_start = j
            i = j
            continue

        # -- Blockkommentar (in PostgreSQL verschachtelbar) ----------------
        if ch == "/" and nxt == "*":
            flush_code(i)
            j = i + 2
            depth = 1
            while j < n:
                if text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                    if depth == 0:
                        break
                    continue
                if is_pg and text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                j += 1
            tokens.append(Token(TOK_BLOCK_COMMENT, i, min(j, n)))
            code_start = min(j, n)
            i = min(j, n)
            continue

        # -- Oracle q-Quote-Literal: q'X...X' (auch nq'/Nq') ---------------
        if dialect == "oracle" and ch in "qQ" and nxt == "'":
            prev = text[i - 1] if i > 0 else ""
            before = prev
            if prev in ("n", "N"):          # NCHAR-Präfix nq'/Nq'
                before = text[i - 2] if i > 1 else ""
            if not (before.isalnum() or before == "_"):
                flush_code(i)
                delim = text[i + 2] if i + 2 < n else ""
                close = _Q_CLOSE.get(delim, delim)
                content_start = i + 3
                j = content_start
                while j < n and not (text[j] == close
                                     and j + 1 < n and text[j + 1] == "'"):
                    j += 1
                end = min(j + 2, n)
                tokens.append(Token(TOK_STRING, i, end, content_start, j))
                code_start = end
                i = end
                continue

        # -- PostgreSQL-Dollar-Quoting -------------------------------------
        if is_pg and ch == "$":
            m = _DOLLAR_TAG_RE.match(text, i)
            if m:
                tag_end = m.end()
                if i in dollar_close:
                    # schließender Begrenzer eines Code-Rumpfes -> Code
                    i = tag_end
                    continue
                tag = m.group(0)
                close_at = text.find(tag, tag_end)
                if close_at == -1:
                    # unbalanciert -> Begrenzer als Code überspringen
                    i = tag_end
                    continue
                if _opens_code_body(text, i):
                    # Funktions-/Prozedurrumpf: Inhalt ist Code.
                    dollar_close.add(close_at)
                    i = tag_end
                    continue
                # sonstiger Dollar-Quote = String-Literal
                flush_code(i)
                end = close_at + len(tag)
                tokens.append(Token(TOK_STRING, i, end, tag_end, close_at))
                code_start = end
                i = end
                continue

        # -- Quoted Identifier: "..." (Oracle/PostgreSQL) ------------------
        # ``"..."`` ist ein begrenzter Bezeichner. Sein Inhalt darf
        # Zeichen wie ``'`` enthalten, ohne ein String-Literal zu starten
        # (typisches Beispiel: ``OPTIONALLY ENCLOSED BY "'"`` in Oracle-
        # External-Table-DDL). Wird der Bezeichner uebersprungen, gilt sein
        # Inhalt weiterhin als Code - das ist auch das Verhalten echter
        # Parser. Wuerde der ``'`` darin als String-Anfang interpretiert,
        # bliebe das nachfolgende Skript fuer den Lexer "in einem String"
        # haengen, und Statement-Grenzen (``;``) waeren unsichtbar.
        # ``""`` innerhalb des Bezeichners ist die Escape-Sequenz.
        if ch == '"':
            flush_code(i)
            j = i + 1
            while j < n:
                if text[j] == '"':
                    if j + 1 < n and text[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            end = min(j + 1, n)
            tokens.append(Token(TOK_QIDENT, i, end, i + 1, min(j, n)))
            code_start = end
            i = end
            continue

        # -- Standard-String-Literal: '...' (mit '' als Escape) ------------
        if ch == "'":
            flush_code(i)
            content_start = i + 1
            j = content_start
            while j < n:
                if text[j] == "'":
                    if j + 1 < n and text[j + 1] == "'":
                        j += 2
                        continue
                    break
                j += 1
            end = min(j + 1, n)
            tokens.append(Token(TOK_STRING, i, end, content_start, j))
            code_start = end
            i = end
            continue

        i += 1

    flush_code(n)
    return tokens


# ----------------------------------------------------------------------
# Ableitungen aus der Tokenfolge
# ----------------------------------------------------------------------

_SQLPLUS_DIRECTIVE_RE = re.compile(
    # Zeilenanfang (mit ``re.MULTILINE``), optionaler Whitespace, dann ein
    # SQL*Plus-Direktivenwort. Direktiven werden zeilenweise verarbeitet
    # und enden ohne ``;`` - kollidiert eine Direktive mit einer echten
    # SQL-Anweisung (``SET TRANSACTION ...``, ``ALTER SESSION SET ...``,
    # ``DEFINE`` als Schluesselwort in SQL gibt es nicht), wird ueber ein
    # ``;`` in derselben Zeile erkannt, dass es kein SQL*Plus ist.
    #
    # Direktiven ohne ``;`` (von SQL*Plus erwartet):
    #   PROMPT, REM, REMARK, SPOOL, SET, COLUMN, BREAK, COMPUTE, TTITLE,
    #   BTITLE, ACCEPT, DEFINE, UNDEFINE, SHOW, CLEAR, PAUSE, TIMING,
    #   START, @, @@ (Skript ausfuehren).
    #
    # Die negative Lookahead ``(?![^\n]*;)`` stellt sicher, dass eine
    # Zeile mit ``;`` (z.B. ``SET TRANSACTION READ ONLY;``) NICHT als
    # SQL*Plus-Direktive maskiert wird.
    r"^[ \t]*(?:"
    # Keyword-Direktiven (Wortgrenze erforderlich)
    r"(?:PROMPT|REMARK|REM|SPOOL|SET|COLUMN|BREAK|COMPUTE|TTITLE"
    r"|BTITLE|ACCEPT|DEFINE|UNDEFINE|SHOW|CLEAR|PAUSE|TIMING|START)\b"
    # ODER: ``@``/``@@`` als Sigil-Direktiven (Skript einbinden/ausfuehren)
    r"|@@?"
    r")(?![^\n]*;)[^\n]*",
    re.IGNORECASE | re.MULTILINE,
)


def _at_statement_start(masked: list, start: int) -> bool:
    """True, wenn ``start`` den Beginn einer neuen Anweisung markiert.

    Geprueft wird der letzte sichtbare Nicht-Whitespace-Code (in der bereits
    teilmaskierten ``masked``-Liste) vor ``start``: ein ``;`` oder ein ``/``
    (SQL*Plus-Terminatorzeile) - oder kein Code (Dateianfang) - bedeutet
    Anweisungsbeginn. Alles andere ist eine Fortsetzungszeile.
    """
    j = start - 1
    while j >= 0 and masked[j] in " \t\r\n":
        j -= 1
    if j < 0:
        return True
    return masked[j] in ";/"


def _mask_sqlplus_directive_lines(text: str, no_comments: list, masked: list,
                                  dialect: str = "oracle"):
    """Maskiert SQL*Plus-Direktivenzeilen in den beiden Code-Varianten.

    SQL*Plus-Direktiven wie ``PROMPT ...``, ``REM ...``, ``REMARK ...``,
    ``SPOOL ...``, ``SET LONG 99`` etc. sind keine SQL-Anweisungen, sondern
    Ausgaben/Einstellungen des SQL*Plus-Clients. Ihr Inhalt darf weder die
    Mustererkennung der Checks beeinflussen (z.B. ``CREATE USER`` im
    PROMPT-Text als False-Positive triggern), noch die Statement-Grenzen-
    Heuristik (kein Walk-Back-Anhalter). Daher werden sie analog zu
    Kommentaren mit Leerzeichen ueberschrieben.

    SQL*Plus existiert nur in der **Oracle-Welt**. PostgreSQL benutzt
    ``psql`` mit Backslash-Befehlen (``\\d``, ``\\dt`` etc.) und kennt
    ``SET search_path = ...`` als echte SQL-Klausel innerhalb von
    ``CREATE FUNCTION``. Deshalb wird die Maskierung nur fuer Oracle
    angewendet.
    """
    if dialect in _PG_DIALECTS:
        return
    for m in _SQLPLUS_DIRECTIVE_RE.finditer(text):
        # Nur echte SQL*Plus-Direktiven maskieren, keine Fortsetzungszeilen
        # einer laufenden SQL-Anweisung. Andernfalls wuerde z.B. bei
        # mehrzeiligem DML die ``SET``-Zeile eines ``UPDATE ... SET ...``
        # faelschlich als SQL*Plus-Direktive geloescht - der ganze
        # ``SET``-Ausdruck (inkl. Konkatenationen) waere fuer alle Checks
        # unsichtbar. Eine Direktive steht am Anfang einer Anweisung: der
        # letzte sichtbare Code davor ist ein Terminator (``;`` bzw. eine
        # ``/``-Zeile) oder es gibt keinen (Dateianfang). ``masked`` traegt
        # bereits ausmaskierte Kommentare/Strings und - bei aufeinander
        # folgenden Direktiven - die zuvor geleerten Direktivenzeilen.
        if not _at_statement_start(masked, m.start()):
            continue
        for k in range(m.start(), m.end()):
            if text[k] != "\n":
                no_comments[k] = " "
                masked[k] = " "


def _render(text: str, tokens: list, dialect: str = "oracle"):
    """Erzeugt aus der Tokenfolge die beiden maskierten Code-Varianten.

    * ``code_no_comments`` - Kommentare durch Leerzeichen ersetzt.
    * ``code_masked``      - zusätzlich der Inhalt von String-Literalen
      ersetzt (die Begrenzer bleiben stehen).

    Beide Varianten sind exakt so lang wie das Original; Zeilenumbrüche
    bleiben erhalten. Zusaetzlich werden SQL*Plus-Direktivenzeilen
    (PROMPT/REM/REMARK/SPOOL) maskiert - sie sind keine SQL-Anweisungen
    und sollen weder Pattern-Matches triggern noch in den Statement-
    Grenzen erscheinen.
    """
    no_comments = list(text)
    masked = list(text)
    spans: list = []
    for tok in tokens:
        if tok.type in (TOK_LINE_COMMENT, TOK_BLOCK_COMMENT):
            for k in range(tok.start, tok.end):
                if text[k] != "\n":
                    no_comments[k] = " "
                    masked[k] = " "
        elif tok.type == TOK_STRING:
            for k in range(tok.content_start, tok.content_end):
                if text[k] != "\n":
                    masked[k] = " "
            spans.append(StringSpan(tok.start, tok.end,
                                    tok.content_start, tok.content_end))
    _mask_sqlplus_directive_lines(text, no_comments, masked, dialect)
    return "".join(no_comments), "".join(masked), spans


_BODY_START_RE = re.compile(
    # CREATE-Konstrukte mit eingebettetem **fremdsprachigem** Koerper, der
    # bis zum naechsten ``/``-auf-eigener-Zeile reicht. Innere ``;`` sind
    # KEINE SQL-Statement-Trenner, sondern Java-Statement-Trenner und
    # gehoeren zum Koerper.  Beschraenkt auf Java-Definitionen
    # (JAVA SOURCE/CLASS/RESOURCE) - PL/SQL-Routinenkoerper
    # (PROCEDURE/FUNCTION/PACKAGE/TYPE BODY/TRIGGER) sind absichtlich NICHT
    # erfasst: dort sind die ``;`` echte PL/SQL-Statement-Trenner, die der
    # SQL-Injection-/Datenfluss-Analyse als eigenstaendige Anweisungen
    # zugaenglich bleiben muessen (Zuweisungen, EXECUTE IMMEDIATE u.ae.).
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?"
    r"(?:AND\s+(?:RESOLVE|COMPILE)\s+)?"
    r"(?:NOFORCE\s+)?"
    r"(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
    r"JAVA\s+(?:SOURCE|CLASS|RESOURCE)\b",
    re.IGNORECASE,
)

_SLASH_LINE_RE = re.compile(r"(?m)^[ \t]*/[ \t]*\r?(?:\n|$)")

# PL/pgSQL: ``EXECUTE`` gefolgt von IMMEDIATE/ON/PROCEDURE/FUNCTION ist kein
# dynamisches SQL-EXECUTE, sondern ``GRANT EXECUTE ON`` bzw. die Trigger-
# Syntax ``EXECUTE PROCEDURE/FUNCTION``. Beliebiger Whitespace zulaessig.
_PG_EXECUTE_SKIP_RE = re.compile(
    r"\s+(?:IMMEDIATE|ON|PROCEDURE|FUNCTION)\b", re.I)


def _body_regions(masked: str) -> list:
    """Liefert ``[(start, end), ...]`` der Code-Koerper-Bereiche.

    Innerhalb dieser Bereiche werden ``;`` nicht als Statement-Trenner
    gewertet - das gilt fuer PL/SQL-Bodies (PROCEDURE/FUNCTION/PACKAGE/
    TYPE BODY/TRIGGER) und Java-Definitionen (CREATE JAVA SOURCE/CLASS/
    RESOURCE), wenn diese mit ``/`` auf eigener Zeile abgeschlossen
    werden (Oracle-SQL*Plus-Konvention).

    PostgreSQL-Funktionen verwenden Dollar-Quoting (``$func$ ... $func$``)
    statt ``/`` und haben in der Regel kein ``/`` im File. Das Dollar-
    Quoting wird bereits im Tokenizer beruecksichtigt; ohne ``/`` wird
    hier KEIN Bereich markiert, damit die inneren ``;`` (z.B.
    Zuweisungen) als regulaere Statement-Trenner erkannt bleiben.
    """
    regions: list = []
    for m in _BODY_START_RE.finditer(masked):
        slash = _SLASH_LINE_RE.search(masked, m.end())
        if slash is None:
            continue
        regions.append((m.start(), slash.end()))
    return regions


def _find_statements(text: str, tokens: list, masked: str) -> list:
    """Ermittelt die lexikalischen Statement-Grenzen.

    Terminatoren sind ``;`` (außerhalb von Strings/Kommentaren) sowie
    eine Zeile, die nur aus ``/`` besteht (SQL*Plus-Terminator).

    Innerhalb von Koerpern (CREATE PROCEDURE/FUNCTION/PACKAGE/TYPE BODY/
    TRIGGER/JAVA SOURCE ... / ) zaehlen ``;`` *nicht* als
    Statement-Trenner - sie sind dort PL/SQL- bzw. Java-Statement-Trenner
    innerhalb des Koerpers, der erst bei ``/`` auf eigener Zeile endet.

    Die Koerper-Erkennung laeuft auf ``masked`` (Kommentare/Strings
    ausgeblendet), damit ein ``CREATE JAVA SOURCE`` in einem Kommentar oder
    String-Literal die ``;``-Statement-Grenzen nicht faelschlich unterdrueckt.
    ``;``/``/`` selbst werden weiter ueber die CODE-Token gezaehlt; quotierte
    Bezeichner (eigene Token) sind dabei ausgenommen.
    """
    n = len(text)
    body_regions = _body_regions(masked)

    def in_body(k: int) -> bool:
        for a, b in body_regions:
            if a <= k < b:
                # Das schliessende ``/`` selbst ist Terminator und darf
                # daher noch eingelesen werden; "in body" nur fuer
                # Positionen davor.
                return True
        return False

    boundaries: set = set()
    for tok in tokens:
        if tok.type != TOK_CODE:
            continue
        for k in range(tok.start, tok.end):
            c = text[k]
            if c == ";":
                if in_body(k):
                    continue
                boundaries.add(k + 1)
            elif c == "/":
                line_start = text.rfind("\n", 0, k) + 1
                line_end = text.find("\n", k)
                if line_end == -1:
                    line_end = n
                if text[line_start:line_end].strip() == "/":
                    boundaries.add(line_end)
    statements: list = []
    start = 0
    for b in sorted(boundaries):
        if text[start:b].strip():
            statements.append(Statement(start, b))
        start = b
    if text[start:].strip():
        statements.append(Statement(start, n))
    return statements


def _expr_end(statements: "list[Statement]", masked: str, pos: int) -> int:
    """Ende eines dynamischen SQL-Ausdrucks.

    Der Ausdruck reicht bis zum Terminator des umgebenden lexikalischen
    Statements; das abschließende ``;`` gehört nicht mehr dazu. Damit
    ersetzt die Statement-Struktur die frühere Heuristik "bis zum
    nächsten ``;``".

    Bisect-basierte O(log n)-Suche: die naive lineare Iteration ueber alle
    Statements war auf grossen Dateien (z.B. PL/pgSQL-Funktionsbodies mit
    tausenden Statements) der dominierende Hotspot beim Source-Aufbau und
    skalierte quadratisch ueber alle Aufrufer hinweg.
    """
    n = len(statements)
    if n == 0:
        return len(masked)
    # Statement-Starts sind monoton steigend (sortiert im Konstrukt) -
    # bisect_right liefert den ersten Index mit ``stmt.start > pos``;
    # der Kandidat fuer "enthaelt pos" ist eins davor.
    lo, hi = 0, n
    while lo < hi:
        mid = (lo + hi) // 2
        if statements[mid].start <= pos:
            lo = mid + 1
        else:
            hi = mid
    idx = lo - 1
    if idx >= 0:
        st = statements[idx]
        if st.start <= pos < st.end:
            if st.end > pos and masked[st.end - 1] == ";":
                return st.end - 1
            return st.end
    return len(masked)


def _paren_end(masked: str, open_pos: int) -> int:
    """Offset der zu ``masked[open_pos] == '('`` passenden ``)``.

    Arbeitet auf ``masked`` (String-Inhalte ausgeblendet), daher stoeren
    Klammern in String-Literalen nicht. Liefert das Textende, wenn keine
    schliessende Klammer gefunden wird (unbalanciert -> konservativ)."""
    depth = 0
    n = len(masked)
    i = open_pos
    while i < n:
        c = masked[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def _find_dynamic_sql(masked: str, dialect: str, statements: list) -> list:
    """Findet alle Stellen, an denen dynamisches SQL ausgeführt wird.

    Gearbeitet wird auf ``code_masked`` - Schlüsselworte in Strings oder
    Kommentaren lösen daher nichts aus. Die Ausdrucksgrenze ergibt sich
    aus den Statement-Grenzen (siehe :func:`_expr_end`).
    """
    found: list = []

    def add(kind, label, m):
        found.append(DynamicSql(kind, label, m.start(), m.end(), m.end(),
                                _expr_end(statements, masked, m.end())))

    for m in re.finditer(r"\bEXECUTE\s+IMMEDIATE\b", masked, re.I):
        add("execute_immediate", "EXECUTE IMMEDIATE", m)
    for m in re.finditer(r"\bOPEN\s+" + _IDENT + r"\s+FOR\b", masked, re.I):
        add("open_for", "OPEN ... FOR", m)
    for m in re.finditer(r"\bDBMS_SQL\s*\.\s*PARSE\b", masked, re.I):
        add("dbms_sql_parse", "DBMS_SQL.PARSE", m)
    for m in re.finditer(
            r"\bDBMS_SYS_SQL\s*\.\s*(?:PARSE_AS_USER|PARSE)\b", masked, re.I):
        add("dbms_sys_sql_parse", "DBMS_SYS_SQL.PARSE", m)
    if dialect == "oracle":
        # DBMS_XMLGEN.NEWCONTEXT(query) bzw. DBMS_XMLQUERY.NEWCONTEXT(query)
        # fuehren die uebergebene SQL-Abfrage aus - ein SQL-Injection-Sink,
        # der die EXECUTE-IMMEDIATE-Erkennung umgeht (klassischer Bypass bei
        # XML-generierendem PL/SQL). Der Ausdruck ist das Argument in den
        # Klammern (bis zur passenden schliessenden Klammer); die Taint-
        # Bewertung des Arguments laeuft ueber dieselbe Logik wie bei
        # EXECUTE IMMEDIATE.
        for m in re.finditer(
                r"\b(?:SYS\s*\.\s*)?DBMS_XML(?:GEN|QUERY)\s*\.\s*"
                r"NEWCONTEXT\s*\(", masked, re.I):
            open_pos = m.end() - 1
            found.append(DynamicSql(
                "dbms_xmlgen", "DBMS_XMLGEN.NEWCONTEXT",
                m.start(), m.end(), m.end(),
                _paren_end(masked, open_pos)))
    if dialect in _PG_DIALECTS:
        # PL/pgSQL-EXECUTE-Statement; "GRANT EXECUTE ON ..." und
        # "... EXECUTE PROCEDURE/FUNCTION" (Trigger-Syntax) ausnehmen.
        for m in re.finditer(r"\bEXECUTE\b", masked, re.I):
            # Direkt auf ``masked`` mit pos matchen statt auf einem festen
            # Zeichenfenster: bei formatierter DDL (``EXECUTE\n    PROCEDURE``)
            # steht das Schluesselwort sonst ausserhalb des Fensters und der
            # Ausschluss (Trigger-Syntax / GRANT EXECUTE ON) griffe nicht.
            if _PG_EXECUTE_SKIP_RE.match(masked, m.end()):
                continue
            if _preceding_token(masked, m.start()).upper() in (
                    "GRANT", "REVOKE"):
                continue
            add("pg_execute", "EXECUTE", m)
    found.sort(key=lambda d: d.trigger_start)
    return found


def _find_routines(text: str, masked: str, dialect: str) -> list:
    """Erkennt Programmeinheiten (Routinen).

    CREATE-Routinen und DO-Blöcke werden direkt erkannt. Anonyme Blöcke
    sind ``/``-getrennte Abschnitte, die ein ``BEGIN`` enthalten, aber
    keine CREATE-/DO-Routine. Der Bereich einer Routine reicht jeweils
    bis zum Beginn der nächsten Routine bzw. zum Dateiende - das genügt
    als Datenflussgrundlage und zerstückelt keine Statements.
    """
    starts: list = []           # (offset, kind, name)
    for m in _ROUTINE_RE.finditer(masked):
        kind = re.sub(r"\s+", "_", m.group("kind").lower())
        name = re.sub(r"\s*\.\s*", ".", m.group("name").strip())
        starts.append((m.start(), kind, name))
    if dialect in _PG_DIALECTS:
        for m in re.finditer(r"\bDO\s*\$", masked, re.I):
            starts.append((m.start(), "do_block", None))

    create_do = list(starts)    # Momentaufnahme vor den anonymen Blöcken
    bounds = [0]
    for m in re.finditer(r"(?m)^[ \t]*/[ \t]*\r?$", masked):
        bounds.append(m.end())
    bounds.append(len(text))
    for a, b in zip(bounds, bounds[1:]):
        if any(a <= off < b for off, _k, _n in create_do):
            continue
        seg = masked[a:b]
        if re.search(r"\bBEGIN\b", seg, re.I):
            off = a + len(seg) - len(seg.lstrip())
            starts.append((off, "anonymous_block", None))

    starts.sort(key=lambda s: s[0])
    routines: list = []
    for i, (off, kind, name) in enumerate(starts):
        naive_end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
        end = naive_end
        # PostgreSQL/EPAS: das naive "bis zur naechsten Routine bzw. zum
        # Dateiende" zieht Statements NACH einer Funktion faelschlich in den
        # Routinen-Rumpf (z.B. ein DBMS_SQL.PARSE-Block hinter der Funktion
        # wuerde als SECURITY-DEFINER-Dynamic-SQL gewertet). Fuer
        # CREATE FUNCTION/PROCEDURE wird das Routinen-Ende daher auf das Ende
        # der CREATE-Anweisung begrenzt.
        if dialect in _PG_DIALECTS and kind in ("function", "procedure"):
            end = _pg_routine_stmt_end(text, masked, off, naive_end)
        routines.append(Routine(kind, name, dialect, off, end))
    return routines


def _pg_routine_stmt_end(text: str, masked: str, start: int, limit: int) -> int:
    """Ende (exklusiv) der PostgreSQL-``CREATE FUNCTION/PROCEDURE``-Anweisung
    ab ``start`` (hoechstens bis ``limit``).

    Der dollar-quotierte Code-Rumpf wird uebersprungen, damit ein ``;`` im
    Rumpf (z.B. ``END;``) die Routine nicht vorzeitig beendet; anschliessend
    wird die Position hinter dem ersten Top-Level-``;`` geliefert (deckt
    ``$$ LANGUAGE plpgsql SECURITY DEFINER;`` mit ab). Einfach-quotierte
    Rumpfe brauchen keine Sonderbehandlung: in ``masked`` ist ihr Inhalt
    (inkl. ``;``) ausgeblendet. Liefert ``limit``, wenn kein Terminator
    gefunden wird (konservativ)."""
    scan = start
    m = _DOLLAR_TAG_RE.search(text, start, limit)
    while m is not None:
        if _opens_code_body(text, m.start()):
            tag = m.group(0)
            close = text.find(tag, m.end(), limit)
            if close == -1:
                return limit          # unbalanciert -> konservativ
            scan = close + len(tag)
            break
        m = _DOLLAR_TAG_RE.search(text, m.end(), limit)
    semi = masked.find(";", scan, limit)
    return semi + 1 if semi != -1 else limit


def _find_assignments(code: str, masked: str, statements: list,
                      dialect: str = "oracle") -> list:
    """Erkennt einfache Zuweisungen ``ziel := ausdruck``.

    Erfasst wird die Körper-Zuweisungsform. Deklarations-Defaults
    (``pi NUMBER := 3.14``) werden bewusst übersprungen, weil dort vor
    dem ``:=`` der Typ und nicht das Ziel steht (konservativ statt
    fehlklassifizierend).

    In PostgreSQL ist ``:=`` zudem die Named-Argument-Syntax in
    Funktionsaufrufen (``f(a := 1)``). Ein ``:=``, dem unmittelbar ein
    ``(`` oder ``,`` vorausgeht, ist daher ein benannter Aufrufparameter
    und keine Zuweisung - andernfalls wuerde die Taint-Historie der
    Zielvariable verfaelscht.
    """
    is_pg = dialect in _PG_DIALECTS
    out: list = []
    for m in _ASSIGN_RE.finditer(masked):
        if is_pg:
            j = m.start(1) - 1
            while j >= 0 and masked[j] in " \t\r\n":
                j -= 1
            if j >= 0 and masked[j] in "(,":
                continue
        target = re.sub(r"\s*\.\s*", ".", m.group(1).strip())
        if target.rsplit(".", 1)[-1].upper() in _TYPE_WORDS:
            continue
        expr_start = m.end()
        expr_end = _expr_end(statements, masked, expr_start)
        out.append(Assignment(target, m.start(1), expr_start, expr_end,
                              code[expr_start:expr_end].strip()))
    return out


# ----------------------------------------------------------------------
# Öffentliche Schnittstelle
# ----------------------------------------------------------------------

# PostgreSQL-COPY-Datenblock: ``COPY ... FROM STDIN ... ;`` und die
# anschliessenden Datenzeilen bis zur Terminatorzeile ``\.``.
_COPY_STDIN_RE = re.compile(r"\bCOPY\b[^;]*?\bFROM\s+STDIN\b[^;]*?;",
                            re.IGNORECASE)
_COPY_TERM_RE = re.compile(r"(?m)^\\\.[ \t]*\r?$")


def _blank_copy_data(text: str) -> str:
    """Ersetzt PostgreSQL-COPY-Datenblöcke durch Leerraum.

    Bei ``COPY ... FROM STDIN;`` folgen rohe Datenzeilen (kein SQL) bis
    zur Zeile ``\\.``. Diese Zeilen werden - unter Beibehaltung von Länge
    und Zeilenumbrüchen - ausmaskiert, damit Inhalte wie ein Name
    ``GRANT`` in den Daten keine Findings auslösen.
    """
    spans = []
    for m in _COPY_STDIN_RE.finditer(text):
        nl = text.find("\n", m.end())
        if nl == -1:
            continue
        data_start = nl + 1
        term = _COPY_TERM_RE.search(text, data_start)
        data_end = term.start() if term else len(text)
        if data_end > data_start:
            spans.append((data_start, data_end))
    if not spans:
        return text
    chars = list(text)
    for a, b in spans:
        for k in range(a, b):
            if chars[k] != "\n":
                chars[k] = " "
    return "".join(chars)


def lex(text: str, dialect: str = "oracle") -> LexResult:
    """Führt die vollständige lexikalische Analyse durch.

    ``text`` bleibt im Ergebnis unverändert; PostgreSQL-COPY-Datenblöcke
    werden für die lexikalische Analyse jedoch ausmaskiert (siehe
    :func:`_blank_copy_data`), da die Datenzeilen kein Code sind.
    """
    dialect = (dialect or "oracle").lower()
    scan = _blank_copy_data(text) if dialect in _PG_DIALECTS else text
    tokens = _tokenize(scan, dialect)
    code_no_comments, code_masked, string_spans = _render(scan, tokens, dialect)
    statements = _find_statements(scan, tokens, code_masked)
    dynamic_sql = _find_dynamic_sql(code_masked, dialect, statements)
    routines = _find_routines(scan, code_masked, dialect)
    assignments = _find_assignments(code_no_comments, code_masked, statements,
                                    dialect)
    return LexResult(
        text=text,
        dialect=dialect,
        tokens=tokens,
        code_no_comments=code_no_comments,
        code_masked=code_masked,
        string_spans=string_spans,
        statements=statements,
        dynamic_sql=dynamic_sql,
        routines=routines,
        assignments=assignments,
    )
