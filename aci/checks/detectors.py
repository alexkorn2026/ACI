"""Bibliothek der eingebauten Guideline-/MITRE-Detektoren.

Jeder Detektor ist über ``@_builtin(name)`` in :data:`_BUILTIN_DETECTORS`
registriert; :class:`~aci.checks.guidelines.GuidelineCheck` schlägt ihn
darüber per Namen nach.
"""

from __future__ import annotations

import re

from ..ir import dynamic_sql_executions
from ..lexer import TOK_LINE_COMMENT, TOK_BLOCK_COMMENT, TOK_STRING

from .base import (_DATATYPES, _norm_ws,
                    _assignments_before, _split_concat)
from .psql_meta import parse_psql_meta_line


# -- Registry der eingebauten Detektoren --------------------------------

_BUILTIN_DETECTORS: dict = {}


def _builtin(name):
    def deco(fn):
        _BUILTIN_DETECTORS[name] = fn
        return fn
    return deco


# Deklarations-Erkennung für die Namens-Detektoren.
_DECL_PREFIX_RE = re.compile(
    r"(?P<lead>[;(,]|\bDECLARE\b|\bIS\b|\bAS\b)\s*"
    r"(?P<id>[A-Za-z_][\w$#]*)\s+"
    r"(?P<const>CONSTANT\s+)?"
    r"(?:IN\s+OUT\s+NOCOPY|IN\s+OUT|IN|OUT|NOCOPY)?\s*"
    r"(?:(?:" + _DATATYPES + r")\b|[A-Za-z_][\w$#.]*\s*%\s*(?:TYPE|ROWTYPE))",
    re.IGNORECASE,
)

_PROGRAM_UNIT_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:EDITIONABLE\s+|NONEDITIONABLE\s+)?"
    r"(?P<kind>PACKAGE\s+BODY|PACKAGE|PROCEDURE|FUNCTION|TYPE\s+BODY|TRIGGER)\s+"
    r"(?P<name>(?:\"[^\"]+\"|[A-Za-z_][\w$#]*)"
    r"(?:\s*\.\s*(?:\"[^\"]+\"|[A-Za-z_][\w$#]*))?)",
    re.IGNORECASE,
)

_SUBPROG_PARAMS_RE = re.compile(
    r"\b(?:PROCEDURE|FUNCTION)\s+(?:\"[^\"]+\"|[A-Za-z_][\w$#]*)\s*"
    r"\(([^()]*(?:\([^()]*\)[^()]*)*)\)",
    re.IGNORECASE,
)


@_builtin("naming_prefix")
def _detect_naming_prefix(check, source):
    """Trivadis-Namenskonvention: Präfixe für Variablen, Konstanten,
    Parameter (z.B. l_, co_, in_/out_)."""
    params = check.detector.get("params", {})
    p_local = params.get("local", "l_")
    p_const = params.get("constant", "co_")
    p_params = tuple(params.get("parameter", ["in_", "out_", "io_", "p_"]))
    findings, seen = [], set()
    for m in _DECL_PREFIX_RE.finditer(source.code_masked):
        ident = m.group("id")
        low = ident.lower()
        lead = m.group("lead")
        if lead in ("(", ","):
            expected, kind = p_params, "Parameter"
        elif m.group("const"):
            expected, kind = (p_const,), "Konstante"
        else:
            expected, kind = (p_local,), "lokale Variable"
        if low.startswith(tuple(e.lower() for e in expected)):
            continue
        if m.start("id") in seen:
            continue
        seen.add(m.start("id"))
        exp_txt = " / ".join(f"'{e}'" for e in expected)
        findings.append(check._gf(
            source, m.start("id"),
            f"{kind} '{ident}' folgt nicht der Trivadis-Namenskonvention "
            f"(erwartetes Präfix: {exp_txt})."))
    return findings


@_builtin("short_identifier")
def _detect_short_identifier(check, source):
    """G-2185: zu kurze, wenig aussagekräftige Bezeichner."""
    min_len = int(check.detector.get("params", {}).get("min_length", 3))
    findings, seen = [], set()
    for m in _DECL_PREFIX_RE.finditer(source.code_masked):
        ident = m.group("id")
        if len(ident) >= min_len or m.start("id") in seen:
            continue
        seen.add(m.start("id"))
        findings.append(check._gf(
            source, m.start("id"),
            f"Bezeichner '{ident}' ist sehr kurz ({len(ident)} Zeichen) "
            f"und dadurch wenig aussagekräftig."))
    return findings


# snake_case: nur Kleinbuchstaben, Ziffern und Unterstriche.
_SNAKE_CASE_RE = re.compile(r"[a-z_][a-z0-9_]*$")


@_builtin("snake_case_identifier")
def _detect_snake_case_identifier(check, source):
    """Bezeichner sollen der snake_case-Konvention folgen.

    PostgreSQL faltet unquotete Bezeichner ohnehin auf Kleinschreibung
    (``myVar`` und ``myvar`` sind dieselbe Spalte/Variable); CamelCase oder
    Großbuchstaben erschweren daher nur die Lesbarkeit und täuschen eine
    Unterscheidung vor, die es nicht gibt. Gemeldet werden Deklarationen
    mit Großbuchstaben im (unquoteten) Bezeichner. Quotete Bezeichner
    (``"MyVar"``) werden vom Deklarations-Muster nicht erfasst und daher
    nicht beanstandet - dort ist die Schreibweise signifikant und gewollt.
    """
    findings, seen = [], set()
    for m in _DECL_PREFIX_RE.finditer(source.code_masked):
        ident = m.group("id")
        if m.start("id") in seen:
            continue
        if _SNAKE_CASE_RE.fullmatch(ident):
            continue
        seen.add(m.start("id"))
        findings.append(check._gf(
            source, m.start("id"),
            f"Bezeichner '{ident}' folgt nicht der snake_case-Konvention "
            f"(nur Kleinbuchstaben, Ziffern und Unterstriche)."))
    return findings


@_builtin("rownum_order_by")
def _detect_rownum_order_by(check, source):
    """G-3185: ROWNUM und ORDER BY auf derselben Abfrageebene."""
    findings, pos = [], 0
    for stmt in source.code_masked.split(";"):
        rn = re.search(r"\bROWNUM\b", stmt, re.I)
        ob = re.search(r"\bORDER\s+BY\b", stmt, re.I)
        if rn and ob:
            findings.append(check._gf(source, pos + rn.start()))
        pos += len(stmt) + 1
    return findings


@_builtin("commit_in_loop")
def _detect_commit_in_loop(check, source):
    """G-3310: COMMIT (oder ROLLBACK) innerhalb einer Schleife."""
    findings, depth = [], 0
    token = re.compile(r"\bEND\s+LOOP\b|\bLOOP\b|\bCOMMIT\b|\bROLLBACK\b", re.I)
    for m in token.finditer(source.code_masked):
        word = re.sub(r"\s+", " ", m.group(0).upper())
        if word == "END LOOP":
            depth = max(0, depth - 1)
        elif word == "LOOP":
            depth += 1
        elif depth > 0:
            findings.append(check._gf(source, m.start()))
    return findings


@_builtin("case_for_elsif")
def _detect_case_for_elsif(check, source):
    """G-4210: IF-Anweisung mit mehreren ELSIF-Zweigen."""
    findings, stack = [], []
    token = re.compile(r"\bEND\s+IF\b|\bELSIF\b|\bIF\b", re.I)
    for m in token.finditer(source.code_masked):
        word = re.sub(r"\s+", " ", m.group(0).upper())
        if word == "END IF":
            if stack:
                off, count = stack.pop()
                if count >= 2:
                    findings.append(check._gf(source, off))
        elif word == "ELSIF":
            if stack:
                stack[-1][1] += 1
        else:  # IF
            stack.append([m.start(), 0])
    return findings


@_builtin("error_backtrace")
def _detect_error_backtrace(check, source):
    """G-5080: SQLERRM/FORMAT_ERROR_STACK ohne FORMAT_ERROR_BACKTRACE."""
    code = source.code_no_comments
    if re.search(r"\bFORMAT_ERROR_BACKTRACE\b", code, re.I):
        return []
    m = re.search(r"\b(?:SQLERRM|FORMAT_ERROR_STACK)\b", code, re.I)
    return [check._gf(source, m.start())] if m else []


@_builtin("end_label")
def _detect_end_label(check, source):
    """G-7120: das abschließende END trägt nicht den Namen der Einheit."""
    masked = source.code_masked
    findings = []
    for m in _PROGRAM_UNIT_RE.finditer(masked):
        name = re.split(r"\s*\.\s*", m.group("name").strip())[-1].strip('"')
        if not name:
            continue
        if re.search(r"\bEND\s+" + re.escape(name) + r"\s*;", masked, re.I):
            continue
        findings.append(check._gf(
            source, m.start(),
            f"Programmeinheit '{name}': das abschließende END sollte den "
            f"Namen der Einheit tragen (END {name};)."))
    return findings


@_builtin("parameter_mode")
def _detect_parameter_mode(check, source):
    """G-7160: Parameter ohne expliziten Modus (IN/OUT/IN OUT)."""
    masked = source.code_masked
    findings, seen = [], set()
    for m in _SUBPROG_PARAMS_RE.finditer(masked):
        base = m.start(1)
        for pm in re.finditer(r"[^,]+", m.group(1)):
            decl = re.match(r"\s*([A-Za-z_][\w$#]*)\s+(IN\s+OUT|IN|OUT)?\b",
                            pm.group(0), re.I)
            if not decl or decl.group(2):
                continue
            off = base + pm.start() + decl.start(1)
            key = (source.line_col(off)[0], decl.group(1).lower())
            if key in seen:
                continue
            seen.add(key)
            findings.append(check._gf(
                source, off,
                f"Parameter '{decl.group(1)}' ist ohne expliziten Modus "
                f"(IN / OUT / IN OUT) deklariert."))
    return findings


@_builtin("nested_comments")
def _detect_nested_comments(check, source):
    """G-1070: verschachtelte Blockkommentare."""
    text = source.text
    n = len(text)
    findings = []
    i = 0
    while i < n - 1:
        if text[i] == "/" and text[i + 1] == "*":
            j = i + 2
            while j < n - 1 and not (text[j] == "*" and text[j + 1] == "/"):
                if text[j] == "/" and text[j + 1] == "*":
                    findings.append(check._gf(source, j))
                    break
                j += 1
            while j < n - 1 and not (text[j] == "*" and text[j + 1] == "/"):
                j += 1
            i = j + 2
        else:
            i += 1
    return findings


_SECURITY_DEFINER_SCAN_RE = re.compile(r"\bSECURITY\s+DEFINER\b", re.I)
_SET_SEARCH_PATH_RE = re.compile(r"\bSET\s+search_path\b", re.I)


def _security_definer_region(code, routines, off):
    """Region (Start/Ende) der Routine, die ``off`` enthaelt - sonst eine
    heuristische ``CREATE … ;``-Spanne als Rueckfall (z.B. wenn keine IR
    vorliegt)."""
    for r in routines:
        if r.start <= off < r.end:
            return r.start, r.end
    start = code.rfind("CREATE", 0, off)
    if start == -1:
        start = max(0, off - 400)
    end = code.find(";", off)
    if end == -1:
        end = min(len(code), off + 1200)
    return start, end


@_builtin("security_definer_search_path")
def _detect_security_definer_search_path(check, source):
    """PG-7010: SECURITY DEFINER ohne festgelegten search_path.

    Eine SECURITY-DEFINER-Funktion läuft mit den Rechten ihres
    Eigentümers. Fehlt ``SET search_path``, kann ein Angreifer über
    einen manipulierten search_path eigene Objekte unterschieben.

    Prüfung **pro Routine** (über die IR-/Routinengrenzen): gemeldet wird
    jede SECURITY-DEFINER-Routine, die in *ihrer eigenen* Spanne kein
    ``SET search_path`` setzt. Ein ``SET search_path`` in einer *anderen*
    Routine derselben Datei lässt eine ungesicherte Routine damit nicht
    mehr fälschlich sicher erscheinen.
    """
    code = source.code_no_comments
    ir = getattr(source, "ir", None)
    routines = list(ir.routines) if ir is not None else []
    findings, seen = [], set()
    for m in _SECURITY_DEFINER_SCAN_RE.finditer(code):
        off = m.start()
        r_start, r_end = _security_definer_region(code, routines, off)
        if _SET_SEARCH_PATH_RE.search(code[r_start:r_end]):
            continue
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


@_builtin("security_definer_unsafe_search_path")
def _detect_security_definer_unsafe_search_path(check, source):
    """SECURITY DEFINER with a risky search_path (public before pg_temp)."""
    code = source.code_no_comments
    findings, seen = [], set()
    for m in re.finditer(r"\bSECURITY\s+DEFINER\b", code, re.I):
        # Look around the containing CREATE FUNCTION statement. This stays
        # intentionally heuristic; it is a guardrail, not a full parser.
        stmt_start = code.rfind("CREATE", 0, m.start())
        stmt_end = code.find(";", m.end())
        if stmt_start == -1:
            stmt_start = max(0, m.start() - 400)
        if stmt_end == -1:
            stmt_end = min(len(code), m.end() + 1200)
        region = code[stmt_start:stmt_end]
        sp = re.search(r"\bSET\s+search_path\s*=\s*([^\n;]+)", region, re.I)
        if not sp:
            continue  # PG-7010 handles missing search_path.
        path = _norm_ws(sp.group(1)).replace('"', '')
        entries = [e.strip() for e in path.split(',') if e.strip()]
        if "PUBLIC" in entries or ("PG_TEMP" in entries and entries[-1] != "PG_TEMP"):
            key = source.line_col(stmt_start + sp.start())[0]
            if key not in seen:
                seen.add(key)
                findings.append(check._gf(source, stmt_start + sp.start()))
    return findings


@_builtin("security_definer_dynamic_execute")
def _detect_security_definer_dynamic_execute(check, source):
    """SECURITY DEFINER routine containing dynamic EXECUTE."""
    findings, seen = [], set()
    ir = getattr(source, "ir", None)
    if ir is None:
        return []
    code = source.code_masked
    for routine in ir.routines:
        region = code[routine.start:routine.end]
        if not re.search(r"\bSECURITY\s+DEFINER\b", region, re.I):
            continue
        for dyn in ir.dynamic_sql:
            if routine.start <= dyn.trigger_start < routine.end:
                line = source.line_col(dyn.trigger_start)[0]
                if line in seen:
                    continue
                seen.add(line)
                findings.append(check._gf(source, dyn.trigger_start))
    return findings


@_builtin("security_definer_unqualified_call")
def _detect_security_definer_unqualified_call(check, source):
    """SECURITY DEFINER routine with an unqualified function call.

    PostgreSQL resolves unqualified function names through search_path. In a
    SECURITY DEFINER function this can become a privilege-escalation primitive.
    The detector is intentionally conservative and focuses on PERFORM/SELECT
    call sites with simple unqualified names.
    """
    ir = getattr(source, "ir", None)
    if ir is None:
        return []
    code = source.code_masked
    findings, seen = [], set()
    safe = {"NULL", "RAISE", "COALESCE", "COUNT", "SUM", "MIN", "MAX", "AVG", "EXISTS"}
    call_re = re.compile(r"\b(?:PERFORM|SELECT)\s+([A-Za-z_][\w$#]*)\s*\(", re.I)
    for routine in ir.routines:
        region = code[routine.start:routine.end]
        if not re.search(r"\bSECURITY\s+DEFINER\b", region, re.I):
            continue
        for m in call_re.finditer(region):
            name = m.group(1).upper()
            if name in safe:
                continue
            off = routine.start + m.start(1)
            line = source.line_col(off)[0]
            if line in seen:
                continue
            seen.add(line)
            findings.append(check._gf(source, off))
    return findings


# -- EPAS/PostgreSQL Audit-Tampering / Audit-Bypass ---------------------

# Privilegierte/system-aendernde Operationen, die in einer SECURITY-DEFINER-
# Routine ein starkes Eskalations-/Audit-Bypass-Signal sind. Lauf auf
# code_no_comments (String-Literale bleiben erhalten), damit auch dynamisches
# ``EXECUTE 'ALTER ROLE ' || ...`` ueber das Literal-Fragment greift.
_SECDEF_PRIV_DDL_RE = re.compile(
    r"\b(?:CREATE|ALTER|DROP)\s+(?:USER|ROLE)\b"
    r"|\bGRANT\b[\s\S]{0,200}?\bTO\b"
    r"|\bREVOKE\b[\s\S]{0,200}?\bFROM\b"
    r"|\bALTER\s+DEFAULT\s+PRIVILEGES\b"
    r"|\bALTER\s+SYSTEM\b"
    r"|\bCREATE\s+EXTENSION\b"
    r"|\bCREATE\s+SERVER\b"
    r"|\bCREATE\s+USER\s+MAPPING\b"
    r"|\bCOPY\b[\s\S]{0,200}?\bPROGRAM\b",
    re.IGNORECASE)

_SECURITY_DEFINER_RE = re.compile(r"\bSECURITY\s+DEFINER\b", re.IGNORECASE)

# CREATE [OR REPLACE] FUNCTION|PROCEDURE [schema.]name ( ...
_PG_ROUTINE_NAME_RE = re.compile(
    r"\bCREATE\s+(?:OR\s+REPLACE\s+)?(?:FUNCTION|PROCEDURE)\s+"
    r"(?P<name>(?:\"[^\"]+\"|[A-Za-z_][\w$#]*)"
    r"(?:\s*\.\s*(?:\"[^\"]+\"|[A-Za-z_][\w$#]*))?)",
    re.IGNORECASE)


def _secdef_privileged_routines(source):
    """``[(routine, ddl_offset)]`` aller SECURITY-DEFINER-Routinen, deren
    Rumpf eine privilegierte/system-aendernde Operation enthaelt.

    Strikt auf den Routinen-Rumpf (``ir.routines``) begrenzt - es wird nicht
    ueber Funktionsgrenzen hinweg gematcht. ``ddl_offset`` ist die absolute
    Position des privilegierten DDL-Treffers.
    """
    ir = getattr(source, "ir", None)
    if ir is None:
        return []
    code = source.code_no_comments
    out = []
    for routine in ir.routines:
        region = code[routine.start:routine.end]
        if not _SECURITY_DEFINER_RE.search(region):
            continue
        m = _SECDEF_PRIV_DDL_RE.search(region)
        if m:
            out.append((routine, routine.start + m.start()))
    return out


@_builtin("security_definer_privileged_ddl")
def _detect_security_definer_privileged_ddl(check, source):
    """SECURITY-DEFINER-Routine mit privilegierter Account-/Rollen-/System-DDL.

    Erfasst statische DDL (z.B. ``CREATE USER ... SUPERUSER``) und
    dynamisches ``EXECUTE`` mit privilegiertem Literal-Fragment
    (``EXECUTE 'ALTER ROLE ' || p_user || ' SUPERUSER'``). Je Routine genau
    ein Finding. SECURITY INVOKER / fehlendes SECURITY DEFINER -> kein Treffer.
    """
    findings, seen = [], set()
    for _routine, off in _secdef_privileged_routines(source):
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


# Spaeterer Aufruf einer Routine: SELECT/PERFORM/CALL name( oder FROM name(
_PG_CALL_TMPL = (
    r"\b(?:SELECT|PERFORM|CALL|FROM)\b[\s\S]{{0,40}}?\b{name}\s*\(")


@_builtin("secdef_call_bypass_candidate")
def _detect_secdef_call_bypass_candidate(check, source):
    """Potenzielles EPAS-Audit-Bypass-Muster: eine SECURITY-DEFINER-Routine
    mit privilegierter DDL wird spaeter im selben Skript aufgerufen.

    Der Routinen-Name wird aus dem ``CREATE FUNCTION/PROCEDURE``-Kopf
    extrahiert (schemaqualifiziert unterstuetzt). Gemeldet wird an der
    *Aufrufstelle* ausserhalb des Routinen-Rumpfes. Ohne spaeteren Aufruf
    bzw. ohne privilegierte DDL kein Treffer.
    """
    code = source.code_no_comments
    findings, seen = [], set()
    for routine, _off in _secdef_privileged_routines(source):
        header = code[routine.start:min(routine.end, routine.start + 400)]
        nm = _PG_ROUTINE_NAME_RE.search(header)
        if not nm:
            continue
        # Nur den unqualifizierten Bezeichner als Aufrufnamen verwenden.
        raw = nm.group("name").split(".")[-1].strip().strip('"')
        if not raw:
            continue
        # Den Namen am Ort der CREATE-Definition selbst (Signatur) merken,
        # um ihn nicht als "Aufruf" zu zaehlen. Das Aufruf-Muster verlangt
        # ohnehin ein vorangestelltes SELECT/PERFORM/CALL/FROM, sodass der
        # CREATE-FUNCTION-Kopf nicht matcht; die IR-Routinengrenze
        # (``routine.end``) ist hier bewusst NICHT als Filter geeignet, da
        # sie bis zum Skriptende ueberlaufen kann.
        def_name_off = routine.start + nm.start("name")
        call_re = re.compile(_PG_CALL_TMPL.format(name=re.escape(raw)),
                             re.IGNORECASE)
        for m in call_re.finditer(code):
            off = m.start()
            if off <= def_name_off <= m.end():
                continue  # die Definition selbst, kein Aufruf
            line = source.line_col(off)[0]
            if line in seen:
                continue
            seen.add(line)
            findings.append(check._gf(source, off))
    return findings


# Audit-/sicherheitsrelevante Konfigurationsparameter (Kontext fuer Reload).
_SENSITIVE_CONFIG_RE = re.compile(
    r"\bALTER\s+SYSTEM\b"
    r"|\bedb_audit(?:_statement|_connect|_destination|_directory)?\b"
    r"|\blog_statement\b|\blogging_collector\b|\blog_destination\b"
    r"|\blog_min_duration_statement\b|\blog_connections\b"
    r"|\blog_disconnections\b|\brow_security\b"
    r"|\bshared_preload_libraries\b|\bsession_preload_libraries\b"
    r"|\blocal_preload_libraries\b|\bsession_replication_role\b"
    r"|\barchive_command\b|\brestore_command\b"
    r"|\bpostgresql\.auto\.conf\b|\bpg_hba\.conf\b",
    re.IGNORECASE)

_PG_RELOAD_RE = re.compile(r"\bpg_reload_conf\s*\(", re.IGNORECASE)


def _reload_offsets(source):
    """Offsets aller ``pg_reload_conf(``-Aufrufe (auf code_masked, daher ohne
    Kommentar-/String-Treffer)."""
    masked = source.code_masked
    return [m.start() for m in _PG_RELOAD_RE.finditer(masked)]


def _has_sensitive_config_change(source) -> bool:
    """True, wenn das Skript eine audit-/sicherheitsrelevante
    Konfigurationsaenderung enthaelt (ALTER SYSTEM, Audit-/Logging-Parameter,
    Config-Datei-Bezug). Kommentare werden ausgeschlossen (code_no_comments);
    der Datei-/Parameterbezug in psql ``\\!``-Zeilen lebt im rohen Text und
    wird zusaetzlich beruecksichtigt."""
    if _SENSITIVE_CONFIG_RE.search(source.code_no_comments):
        return True
    # psql-Direktiven sind in code_* ausmaskiert -> rohen Text (ohne
    # Kommentarzeilen) zusaetzlich pruefen.
    comments = _comment_spans(source)
    for m in _SENSITIVE_CONFIG_RE.finditer(source.text):
        if not any(a <= m.start() < b for a, b in comments):
            return True
    return False


@_builtin("pg_reload_conf_plain")
def _detect_pg_reload_conf_plain(check, source):
    """``pg_reload_conf()`` OHNE begleitende audit-/sicherheitsrelevante
    Konfigurationsaenderung im selben Skript (High-Signal, aber kein
    Kontext). Schliesst sich gegenseitig mit
    :func:`_detect_pg_reload_conf_after_sensitive` aus -> keine Doppelmeldung.
    """
    if _has_sensitive_config_change(source):
        return []
    findings, seen = [], set()
    for off in _reload_offsets(source):
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


@_builtin("pg_reload_conf_after_sensitive")
def _detect_pg_reload_conf_after_sensitive(check, source):
    """``pg_reload_conf()`` MIT begleitender audit-/sicherheitsrelevanter
    Konfigurationsaenderung im selben Skript (Critical-Kontext). Schliesst
    sich gegenseitig mit :func:`_detect_pg_reload_conf_plain` aus.
    """
    if not _has_sensitive_config_change(source):
        return []
    findings, seen = [], set()
    for off in _reload_offsets(source):
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


# Schreib-/Aenderungs-Verben fuer die Konfig-Datei-Manipulation. Reine
# Leseprogramme (cat/less/more/grep/head/tail/view) sind bewusst NICHT dabei.
_CONFIG_WRITE_VERB_RE = re.compile(
    r"\b(?:vi|vim|nano|emacs|ed|ex|sed|perl|awk|tee|cp|mv|install|dd"
    r"|chmod|chown|chgrp|truncate)\b", re.IGNORECASE)
_REDIRECT_RE = re.compile(r">>?")


@_builtin("config_file_tampering")
def _detect_config_file_tampering(check, source):
    """Manipulation einer PostgreSQL-/EPAS-Konfigurationsdatei aus einem
    Deployment-/psql-Skript (z.B. ``\\! sed -i ... postgresql.auto.conf`` oder
    ``echo ... >> postgresql.auto.conf``).

    ``params.files``: Liste der Zieldateinamen (Default
    ``["postgresql.auto.conf"]``). Eine Zeile gilt als Manipulation, wenn sie
    einen Zieldateinamen und entweder ein Schreib-/Aenderungs-Verb oder eine
    Umleitung (``>``/``>>``) enthaelt. Reiner Lesezugriff (z.B.
    ``\\! cat postgresql.auto.conf``) wird nicht gemeldet. Kommentar-Treffer
    werden ausgeschlossen. Je Zeile genau ein Finding.
    """
    params = check.detector.get("params", {}) or {}
    files = [f.lower() for f in (params.get("files")
                                 or ["postgresql.auto.conf"])]
    comments = _comment_spans(source)
    findings, seen = [], set()
    pos = 0
    for line in source.text.splitlines(keepends=True):
        start, pos = pos, pos + len(line)
        low = line.lower()
        hit = next((f for f in files if f in low), None)
        if hit is None:
            continue
        if not (_CONFIG_WRITE_VERB_RE.search(line) or _REDIRECT_RE.search(line)):
            continue
        off = start + low.index(hit)
        if any(a <= off < b for a, b in comments):
            continue
        lineno = source.line_col(off)[0]
        if lineno in seen:
            continue
        seen.add(lineno)
        findings.append(check._gf(source, off))
    return findings


# Bezeichner-Bestandteile, die auf ein Passwort/Geheimnis hindeuten.
_SECRET_NAME_RE = re.compile(r"passw|pwd|kennw|passphrase|secret",
                             re.IGNORECASE)
# Variablenzuweisung 'name [Typ] := '...''  (rechte Seite ist ein Literal).
_PASSWORD_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][\w$#]*)\b[^;:=\n]*?:=\s*('(?:[^'\n]|'')+')",
    re.IGNORECASE)


@_builtin("hardcoded_password")
def _detect_hardcoded_password(check, source):
    """Hartcodiertes Passwort/Geheimnis im Code.

    Erkennt eine passwortartig benannte Variable (enthält ``passw``,
    ``pwd``, ``kennw``, ``passphrase`` oder ``secret``), die mit einem
    nicht-leeren String-Literal belegt wird - ein klassischer Hinweis
    auf hartcodierte Zugangsdaten (CWE-798).
    """
    code = source.code_no_comments
    findings, seen = [], set()
    for m in _PASSWORD_ASSIGN_RE.finditer(code):
        name = m.group(1)
        if not _SECRET_NAME_RE.search(name):
            continue
        if m.group(2) in ("''", "'  '"):     # leeres Literal -> kein Geheimnis
            continue
        off = m.start(1)
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(
            source, off,
            f"Hartcodiertes Geheimnis: die Variable '{name}' wird mit "
            f"einem String-Literal belegt."))
    return findings


@_builtin("definer_dynamic_sql")
def _detect_definer_dynamic_sql(check, source):
    """AUTHID DEFINER + dynamisches SQL in derselben Routine.

    Eine mit ``AUTHID DEFINER`` (Definer-Rechten) laufende Routine, die
    dynamisches SQL ausfuehrt, ist ein klassischer Rechteausweitungs-Pfad:
    eingeschleustes SQL laeuft mit den Rechten des Eigentuemers, nicht des
    Aufrufers. Anders als die reine ``AUTHID DEFINER``-Regel (die nur die
    Deklaration markiert) wird hier je dynamischer SQL-Stelle in einer
    solchen Routine gemeldet - die Kombination ist das eigentliche Risiko.
    Das Pendant fuer PostgreSQL ist ``security_definer_dynamic_execute``.
    """
    ir = getattr(source, "ir", None)
    if ir is None:
        return []
    code = source.code_masked
    findings, seen = [], set()
    for routine in ir.routines:
        region = code[routine.start:routine.end]
        if not re.search(r"\bAUTHID\s+DEFINER\b", region, re.I):
            continue
        for dyn in ir.dynamic_sql:
            if routine.start <= dyn.trigger_start < routine.end:
                line = source.line_col(dyn.trigger_start)[0]
                if line in seen:
                    continue
                seen.add(line)
                findings.append(check._gf(source, dyn.trigger_start))
    return findings


@_builtin("tainted_concat_sink")
def _detect_tainted_concat_sink(check, source):
    """Aufruf eines gefaehrlichen Sinks mit ``||``-Konkatenation in
    derselben Anweisung - Hinweis auf eingeschleuste, ungepruefte Eingaben.

    Der Sink wird ueber das Regex ``params.pattern`` beschrieben (z.B.
    ``DBMS_LDAP.*`` fuer LDAP-Injection oder ``extractvalue``/``existsnode``/
    ``xmlquery``/``xmltable`` fuer XPath-/XQuery-Injection). Gemeldet wird
    nur, wenn die umgebende Anweisung (Statement-Grenzen des Lexers) eine
    ``||``-Konkatenation enthaelt. In ``code_masked`` sind String-Inhalte
    ausmaskiert, sodass ein ``||`` *innerhalb* eines Literals nicht
    faelschlich als Konkatenation zaehlt - ein rein literaler, statischer
    Ausdruck loest also nichts aus (konservativ, geringe Fehlalarmquote).
    """
    pat = (check.detector.get("params", {}) or {}).get("pattern")
    if not pat:
        return []
    sink_re = re.compile(pat, re.IGNORECASE)
    masked = source.code_masked
    findings, seen = [], set()
    for m in sink_re.finditer(masked):
        start = source.statement_start_before(m.start())
        end = source.statement_end_after(m.start())
        if start is None:
            start = masked.rfind(";", 0, m.start()) + 1
        if end is None:
            nxt = masked.find(";", m.start())
            end = nxt if nxt != -1 else len(masked)
        if "||" not in masked[start:end]:
            continue
        line = source.line_col(m.start())[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, m.start()))
    return findings




# SQL*Plus/edbplus-Substitutions-Zustand. SET DEFINE/SCAN steuert, OB und mit
# WELCHEM Zeichen Substitution stattfindet (Standard: aktiviert, Zeichen '&').
#   SET DEFINE OFF / SET SCAN OFF   -> deaktiviert
#   SET DEFINE ON  / SET SCAN ON    -> aktiviert (Zeichen unveraendert)
#   SET DEFINE ^   / SET DEFINE "#" -> aktiviert, Substitutionszeichen gewechselt
# SCAN ist das veraltete Synonym fuer DEFINE und kennt nur ON/OFF.
_SET_DEFINE_RE = re.compile(
    r"(?im)^[ \t]*SET[ \t]+(?:DEFINE|DEF)[ \t]+(OFF|ON|\"[^\"\n]\"|'[^'\n]'|\S)")
_SET_SCAN_RE = re.compile(r"(?im)^[ \t]*SET[ \t]+SCAN[ \t]+(OFF|ON)\b")
_SUBST_NAME = r"([A-Za-z_]\w*)"


def _substitution_segments(text: str) -> list:
    """Liefert ``[(start, end, marker)]`` ueber den gesamten Quelltext.

    ``marker`` ist das in diesem Segment aktive Substitutionszeichen (Standard
    ``&``) bzw. ``None``, wenn die Substitution dort per ``SET DEFINE/SCAN OFF``
    deaktiviert ist. Modelliert auch ``SET DEFINE <char>`` (Zeichenwechsel).
    """
    events = [(m.start(), "def", m.group(1)) for m in _SET_DEFINE_RE.finditer(text)]
    events += [(m.start(), "scan", m.group(1)) for m in _SET_SCAN_RE.finditer(text)]
    events.sort(key=lambda e: e[0])
    segments: list = []
    enabled, marker, seg_start = True, "&", 0
    for off, kind, value in events:
        segments.append((seg_start, off, marker if enabled else None))
        upper = value.upper()
        if upper == "OFF":
            enabled = False
        elif upper == "ON":
            enabled = True
        elif kind == "def":            # SET DEFINE <char>: aktiviert + Wechsel
            enabled = True
            marker = value.strip("\"'")[:1] or marker
        seg_start = off
    segments.append((seg_start, len(text), marker if enabled else None))
    return segments


def _active_substitution_uses(text: str) -> list:
    """``[(offset, varname)]`` aller *aktiven* Substitutionsverwendungen.

    Beruecksichtigt ``SET DEFINE/SCAN OFF`` (keine Substitution) und ein per
    ``SET DEFINE <char>`` gewechseltes Substitutionszeichen (z.B. ``^var``).
    """
    uses: list = []
    for start, end, marker in _substitution_segments(text):
        if marker is None:
            continue
        rx = re.compile(re.escape(marker) + re.escape(marker) + "?" + _SUBST_NAME)
        uses += [(m.start(), m.group(1)) for m in rx.finditer(text, start, end)]
    return uses


@_builtin("client_directive")
def _detect_client_directive(check, source):
    """Erkennt eine Client-/Skript-Direktive (SQL*Plus, edbplus, psql) im
    *rohen* Quelltext.

    Hintergrund: Der Lexer maskiert SQL*Plus-Direktivenzeilen (PROMPT, SET,
    SPOOL, @, ...) in ``code``/``code_masked`` aus, damit sie die regulaeren
    Checks nicht stoeren - dadurch sind sie aber fuer Regex-Detektoren mit
    Ziel ``code``/``masked`` unsichtbar. Dieser Detektor arbeitet daher auf
    ``source.text`` und schliesst Treffer in Kommentaren (immer) und - sofern
    ``params.skip_strings`` nicht auf ``false`` steht (Default ``true``) -
    auch in String-Literalen aus, um Fehlalarme zu vermeiden. Substitutions-
    variablen (``&var``) leben jedoch *innerhalb* von String-Literalen (der
    Client ersetzt sie vor dem Parsen) - die zugehoerige Regel setzt daher
    ``skip_strings: false``. Das Muster kommt aus ``params.pattern`` - so
    bleibt die Regel datengetrieben und je Dialekt (Oracle/EPAS-edbplus vs.
    PostgreSQL-psql) in den Regeldateien steuerbar.
    """
    params = check.detector.get("params", {}) or {}
    pat = params.get("pattern")
    if not pat:
        return []
    rx = re.compile(pat, re.IGNORECASE | re.MULTILINE)
    skip_types = [TOK_LINE_COMMENT, TOK_BLOCK_COMMENT]
    if params.get("skip_strings", True):
        skip_types.append(TOK_STRING)
    skip = [(t.start, t.end) for t in source.tokens if t.type in skip_types]
    findings, seen = [], set()
    for m in rx.finditer(source.text):
        off = m.start()
        if any(a <= off < b for a, b in skip):
            continue
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        # Client-/Skript-Direktiven sind zeilenorientiert: Snippet/Kontext
        # auf die betroffene Direktivenzeile begrenzen, damit aufeinander
        # folgende Direktiven nicht zu einem Snippet verschmelzen (F4).
        findings.append(check._gf(source, off, single_line=True))
    return findings


# ACCEPT/DEFINE-Variablendefinition (auch Abkuerzungen DEF/ACC).
_SQLPLUS_DEFINE_RE = re.compile(
    r"(?im)^[ \t]*(?:ACCEPT|ACC|DEFINE|DEF)[ \t]+([A-Za-z_]\w*)")
# Sicherheitsrelevanter Anweisungskontext fuer die generische Substitutionsregel.
_SQLPLUS_SEC_CTX_RE = re.compile(
    r"\b(?:CREATE|ALTER|DROP|GRANT|REVOKE|EXECUTE[ \t]+IMMEDIATE"
    r"|IDENTIFIED[ \t]+BY)\b", re.IGNORECASE)


def _comment_spans(source) -> list:
    return [(t.start, t.end) for t in source.tokens
            if t.type in (TOK_LINE_COMMENT, TOK_BLOCK_COMMENT)]


@_builtin("sqlplus_substitution")
def _detect_sqlplus_substitution(check, source):
    """Eingabe-gesteuerte SQL*Plus-/edbplus-Substitution: eine ueber
    ``ACCEPT``/``DEFINE`` (haeufig interaktive Eingabe) gesetzte Variable, die
    spaeter als Substitution (``&var`` bzw. dem aktiven SET-DEFINE-Zeichen)
    rein textuell eingesetzt wird - ohne Escaping ein klassischer
    Injection-Pfad in Deployment-/Installationsskripten.

    Hohe Signalstaerke (geringe FP): gemeldet wird nur, wenn der Name der
    Substitutionsvariable zuvor per ACCEPT/DEFINE definiert wurde - nicht jede
    beliebige Substitution. Je Variable genau ein Finding (Dedup). Beruecksichtigt
    SET DEFINE/SCAN OFF und ein gewechseltes Substitutionszeichen ueber
    :func:`_active_substitution_uses`; Kommentar-Treffer werden ausgeschlossen.
    """
    text = source.text
    defined = {m.group(1).upper() for m in _SQLPLUS_DEFINE_RE.finditer(text)}
    if not defined:
        return []
    comments = _comment_spans(source)
    findings, seen = [], set()
    for off, name in _active_substitution_uses(text):
        key = name.upper()
        if key not in defined or key in seen:
            continue
        if any(a <= off < b for a, b in comments):
            continue
        seen.add(key)
        findings.append(check._gf(source, off))
    return findings


@_builtin("psql_meta_command")
def _detect_psql_meta_command(check, source):
    """Erkennt psql-Meta-Kommandos ueber die normalisierte Sicht
    (:func:`aci.checks.psql_meta.parse_psql_meta_line`) statt per Roh-Regex.

    ``params``:
      * ``commands``: Liste der Kommandonamen (z.B. ``["o", "out", "g", "gx"]``;
        ``"!"`` fuer den Shell-Escape).
      * ``requires`` (optional): zusaetzliche Bedingung an die Zeile -
        ``program`` (\\copy ... PROGRAM), ``backtick`` (\\set ... `cmd`),
        ``pipe`` (Ausgabe an ein Programm), ``shell`` (\\!) oder
        ``file_target`` (Argument vorhanden und KEINE Pipe, z.B. \\o datei).

    Robust gegen Whitespace-/Tab-Varianten; Kommentar-Treffer werden
    ausgeschlossen. Je Zeile genau ein Finding.
    """
    params = check.detector.get("params", {}) or {}
    commands = {c.lower() for c in params.get("commands", []) or []}
    requires = params.get("requires")
    if not commands:
        return []
    comments = _comment_spans(source)
    findings, seen = [], set()
    pos = 0
    for line in source.text.splitlines(keepends=True):
        start, pos = pos, pos + len(line)
        mc = parse_psql_meta_line(line)
        if mc is None or mc.command not in commands:
            continue
        if requires == "program" and not mc.has_program:
            continue
        if requires == "backtick" and not mc.has_backtick:
            continue
        if requires == "pipe" and not mc.has_pipe_target:
            continue
        if requires == "shell" and not mc.has_shell_escape:
            continue
        if requires == "file_target" and (mc.has_pipe_target or not mc.args):
            continue
        off = start + line.index("\\")
        if any(a <= off < b for a, b in comments):
            continue
        lineno = source.line_col(off)[0]
        if lineno in seen:
            continue
        seen.add(lineno)
        findings.append(check._gf(source, off))
    return findings


@_builtin("sqlplus_security_substitution")
def _detect_sqlplus_security_substitution(check, source):
    """Substitutionsvariable in einer sicherheitsrelevanten Anweisung
    (CREATE/ALTER/DROP/GRANT/REVOKE/EXECUTE IMMEDIATE/IDENTIFIED BY).

    FP-arm: nur in solchen Zeilen, nicht bei jeder Substitution. Char-/OFF-
    bewusst (``SET DEFINE ^`` erkennt ``^var``, ``SET DEFINE OFF`` unterdrueckt).
    Je Zeile genau ein Finding; Kommentar-Treffer ausgeschlossen.
    """
    findings, seen = [], set()
    comments = _comment_spans(source)
    for off, _name in _active_substitution_uses(source.text):
        if any(a <= off < b for a, b in comments):
            continue
        line = source.line_col(off)[0]
        if line in seen:
            continue
        if not _SQLPLUS_SEC_CTX_RE.search(source.line_text(line)):
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


# -- APEX / ORDS Detektoren ---------------------------------------------

# Benutzerkontrollierte APEX-Quellen (Page Items / Session State / ORDS-
# Bind-Parameter). Bewusst heuristisch: Page-Item-Binds (:P1_NAME), App-/
# Global-Items (:APP_USER, :G_X), die Funktionen V()/NV() (mit Literal-Arg)
# und APEX_UTIL.GET_SESSION_STATE.
_APEX_ITEM_RE = re.compile(
    r":(?:P\d+_\w+|APP_\w+|G_\w+|REQUEST\b)"
    r"|\bN?V\s*\(\s*'"
    r"|\bAPEX_UTIL\s*\.\s*GET_SESSION_STATE\s*\(",
    re.IGNORECASE)

# Ein String-Literal-Operand, der wie SQL aussieht (Schluesselwort enthaelt).
_SQL_TEXT_RE = re.compile(
    r"\b(?:SELECT|WITH|FROM|WHERE|ORDER\s+BY|GROUP\s+BY|HAVING|UNION)\b",
    re.IGNORECASE)


def _looks_like_apex_sql_concat(expr_code: str) -> bool:
    """True, wenn ``expr_code`` eine ||-Konkatenation ist, die (a) eine
    APEX-Taint-Quelle und (b) einen SQL-artigen String-Literal-Operanden
    enthaelt. Das ist das Kernsignal fuer 'SQL aus Session State gebaut'
    (z.B. PL/SQL Function Body returning SQL, Region Source) - legitimer
    APEX-Code nutzt hier Bindevariablen *im* SQL-Text statt Konkatenation.
    """
    parts = _split_concat(expr_code)
    if len(parts) < 2:
        return False
    if not any(_APEX_ITEM_RE.search(p) for p in parts):
        return False
    for p in parts:
        s = p.strip()
        if (s.startswith("'") or re.match(r"^[nN]?[qQ]'", s)) \
                and _SQL_TEXT_RE.search(s):
            return True
    return False


_APEX_RETURN_RE = re.compile(
    r"\bRETURN\b([^;]*?)(?=;|\bIS\b|\bAS\b|\bBEGIN\b|$)", re.I)


def _apex_concat_offsets(source) -> list:
    """Offsets, an denen SQL per || aus APEX Session State gebaut und (ohne
    EXECUTE-Sink) per RETURN zurueckgegeben wird.

    Zwei Formen: ``RETURN '...'||V('P1_X')`` direkt sowie die Zuweisung an
    eine spaeter per RETURN zurueckgegebene Variable
    (``l_sql := '...'||:P1_X; ... RETURN l_sql;``). Reine Erkennung ohne
    Finding-Erzeugung, damit der APEX-Export-Extraktor dieselbe Logik auf
    extrahierten Code-Fragmenten wiederverwenden kann.
    """
    masked = source.code_masked
    code = source.code_no_comments
    # RETURN-Anweisung erkennen, aber NICHT die Funktions-Signatur
    # ``RETURN <typ> IS/AS`` (sonst verschluckt der gierige Lauf bis zum
    # naechsten ';' die eigentliche RETURN-Anweisung). Lauf auf ``masked``:
    # IS/AS/BEGIN in SQL-Literalen sind dort ausmaskiert und stoeren nicht.
    returned_vars, returns = set(), []
    for m in _APEX_RETURN_RE.finditer(masked):
        returns.append(m)
        w = re.match(r"\s*([A-Za-z_][\w$#]*)\s*$", m.group(1))
        if w:
            returned_vars.add(w.group(1).upper())

    offsets = []
    # (a) RETURN <konkatenierter SQL-Ausdruck>
    for m in returns:
        if "||" in m.group(1) and _looks_like_apex_sql_concat(
                code[m.start(1):m.end(1)].strip()):
            offsets.append(m.start())
    # (b) Zuweisung an eine spaeter zurueckgegebene Variable
    for a in source.ir.assignments:
        if getattr(a, "kind", "assignment") != "assignment":
            continue
        if a.target.upper() not in returned_vars:
            continue
        if "||" not in masked[a.expr_start:a.expr_end]:
            continue
        if _looks_like_apex_sql_concat(a.expression):
            offsets.append(a.expr_start)
    return offsets


@_builtin("apex_concat_sql")
def _detect_apex_concat_sql(check, source):
    """SQL-Text, der per || aus APEX Session State gebaut und (ohne
    EXECUTE-Sink) per RETURN zurueckgegeben wird - das zentrale Muster
    'PL/SQL Function Body returning SQL' / Region Source.

    Echte EXECUTE-/OPEN-FOR-Sinks bleiben dem SqlInjectionCheck ueberlassen
    (keine Doppel-Findings).
    """
    findings, seen = [], set()
    for off in _apex_concat_offsets(source):
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


# Code-tragende Argumente eines APEX-Exports (wwv_flow_api / wwv_flow_imp...).
# Der eigentliche PL/SQL-/SQL-Code steht als String-Literal hinter diesen
# Parametern - er ist fuer die regulaeren Checks unsichtbar (maskiert), weil
# er Literal-Inhalt ist. Bewusst eine kuratierte, FP-arme Auswahl.
_APEX_EXPORT_ARG_RE = re.compile(
    r"\bp_(?:plug_source|query|source|function_body|plsql_code|"
    r"process_sql_clob|plsql_function_body|region_source|plug_query_sql)"
    r"\s*=>\s*'((?:[^']|'')*)'",
    re.IGNORECASE)


@_builtin("apex_export_code_sql")
def _detect_apex_export_code_sql(check, source):
    """APEX-Export (Phase 3): SQL/PLSQL, das als String-Argument in einem
    ``wwv_flow_api``-Aufruf steht und per || aus Session State gebaut wird.

    Der Code lebt in Export-Dateien *innerhalb* von String-Literalen (z.B.
    ``p_plug_source => 'return ''select ...''||:P1_X;'``) und ist daher fuer
    die regulaeren Checks maskiert/unsichtbar. Dieser Detektor extrahiert den
    Literal-Inhalt code-tragender Argumente, hebt die ``''``-Escapes auf und
    wendet auf das Fragment dieselbe APEX-Heuristik an wie auf normalen Code
    (`_apex_concat_offsets` plus der reine Konkatenations-Fall). Gemeldet wird
    an der Position des Export-Arguments.

    Bewusste Grenzen (Phase 3, erste Ausbaustufe): nur einfache ``'...'``-
    Literale; ueber ``wwv_flow_string.join(...)`` oder ``||`` gesplitteter Code
    und q-Quote-Argumente werden noch nicht zusammengesetzt.
    """
    # Verzoegerter Import: vermeidet einen Importzyklus
    # (source -> checks -> detectors -> source).
    from ..source import Source

    findings, seen = [], set()
    for m in _APEX_EXPORT_ARG_RE.finditer(source.text):
        fragment = m.group(1).replace("''", "'").strip()
        if "||" not in fragment or not _APEX_ITEM_RE.search(fragment):
            continue
        risky = _looks_like_apex_sql_concat(fragment)
        if not risky:
            try:
                risky = bool(_apex_concat_offsets(
                    Source(fragment, source.filename, "oracle")))
            except Exception:       # defensiv: Fragment unparsebar -> skip
                risky = False
        if not risky:
            continue
        off = m.start(1)
        line = source.line_col(off)[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, off))
    return findings


@_builtin("apex_tainted_sink")
def _detect_apex_tainted_sink(check, source):
    """Aufruf eines gefaehrlichen Sinks (``params.pattern``), dessen
    umgebende Anweisung ein APEX Page Item / Session State per ||
    konkateniert.

    Zielt auf APEX-spezifische Injection in Nicht-SQL-Sinks: SSRF ueber
    ``APEX_WEB_SERVICE.MAKE_REST_REQUEST`` und XSS ueber ``HTP.P``/``HTP.PRN``.
    Die zusaetzliche APEX-Item-Bedingung haelt die Fehlalarmquote niedrig
    (rein literale Konkatenation wie ``htp.p('<tr>'||'<td>')`` loest nichts
    aus)."""
    pat = (check.detector.get("params", {}) or {}).get("pattern")
    if not pat:
        return []
    sink_re = re.compile(pat, re.IGNORECASE)
    masked = source.code_masked
    code = source.code_no_comments
    findings, seen = [], set()
    for m in sink_re.finditer(masked):
        start = source.statement_start_before(m.start())
        end = source.statement_end_after(m.start())
        if start is None:
            start = masked.rfind(";", 0, m.start()) + 1
        if end is None:
            nxt = masked.find(";", m.start())
            end = nxt if nxt != -1 else len(masked)
        if "||" not in masked[start:end]:
            continue
        if not _APEX_ITEM_RE.search(code[start:end]):
            continue
        line = source.line_col(m.start())[0]
        if line in seen:
            continue
        seen.add(line)
        findings.append(check._gf(source, m.start()))
    return findings


# -- PostgreSQL MITRE helper detectors ----------------------------------

def _compile_param_regex(check):
    """Compile the regex pattern supplied in a builtin detector params block."""
    params = check.detector.get("params", {}) or {}
    pattern = params.get("pattern", "")
    if not pattern:
        return None
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


def _dynamic_sql_regions_for_rule(source):
    """Return dynamic-SQL expression regions for MITRE/rule detectors.

    The normal masked source suppresses all string literals. That is correct
    for avoiding false positives, but it would also hide SQL built inside real
    dynamic SQL statements such as ``EXECUTE 'GRANT ...'``. This helper adds
    back only the expression of genuine dynamic SQL executions, including
    routine/position-sensitive variable assignments, mirroring the DDL check.
    """
    code = source.code_no_comments
    masked = source.code_masked
    regions = []
    seen_assign: set = set()
    dyn_items = dynamic_sql_executions(source.ir)
    for dyn in dyn_items:
        expr_start, expr_end = dyn.expr_start, dyn.expr_end
        regions.append((expr_start, code[expr_start:expr_end]))
        mvar = re.match(
            r'\s*"?([A-Za-z_][\w$#]*)"?\s*(?:INTO\b|USING\b|BULK\b|$)',
            masked[expr_start:expr_end], re.IGNORECASE)
        if not mvar:
            continue
        cut = dyn.trigger_start
        routine = source.routine_at(cut)
        for assignment in _assignments_before(source, mvar.group(1), cut, routine):
            if assignment.expr_start in seen_assign:
                continue
            seen_assign.add(assignment.expr_start)
            regions.append((assignment.expr_start,
                            code[assignment.expr_start:assignment.expr_end]))
    return regions


def _statement_regions(text: str, base: int = 0):
    """Yield ``(absolute_offset, statement_text)`` for each ``;``-delimited
    region of ``text``.

    Splitting the masked code at ``;`` keeps a detector regex
    *statement-local*: a pattern such as ``CREATE ROLE ... SUPERUSER``
    can no longer match across a statement boundary, where a privileged
    keyword in a *later* statement would otherwise attach to an earlier,
    harmless one (e.g. ``CREATE ROLE app LOGIN; ALTER ROLE x SUPERUSER;``).

    In ``code_masked`` string literals and comments are masked, so a
    ``;`` inside a literal or comment is not a real statement boundary
    and correctly does not split a region.
    """
    start = 0
    for index, char in enumerate(text):
        if char == ";":
            if index > start:
                yield base + start, text[start:index]
            start = index + 1
    if start < len(text):
        yield base + start, text[start:]


@_builtin("regex_static_and_dynamic")
def _detect_regex_static_and_dynamic(check, source):
    """Regex detector that scans code plus genuine dynamic SQL expressions.

    Static scanning uses ``code_masked`` so comments and ordinary string
    literals cannot trigger findings. Dynamic scanning uses only expressions of
    real dynamic SQL statements, so ``EXECUTE 'GRANT ...'`` remains visible
    while ``SELECT 'GRANT ...'`` stays ignored.

    The regex is applied **per ``;``-delimited statement**, not over the
    whole source: a pattern can never match across a statement boundary.
    This prevents false positives in multi-statement deployment scripts,
    where a privileged keyword in a later statement would otherwise be
    attributed to an earlier, harmless one.
    """
    compiled = _compile_param_regex(check)
    if compiled is None:
        return []
    findings, seen = [], set()
    for base, text in [(0, source.code_masked)] + _dynamic_sql_regions_for_rule(source):
        for stmt_base, stmt_text in _statement_regions(text, base):
            for m in compiled.finditer(stmt_text):
                off = stmt_base + m.start()
                key = (off, check.id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(check._gf(source, off))
    return findings






@_builtin("postgres_copy_server_file")
def _detect_postgres_copy_server_file(check, source):
    """Detect COPY TO/FROM server-side file paths while ignoring strings.

    File paths are SQL string literals and therefore masked. We identify real
    COPY statements via IR/masked statement boundaries and inspect only those
    unmasked statement regions for quoted absolute paths, excluding STDIN and
    STDOUT.
    """
    params = check.detector.get("params", {}) or {}
    direction = str(params.get("direction", "")).upper()
    if direction not in {"TO", "FROM"}:
        return []
    pattern = re.compile(r"\bCOPY\b[\s\S]*?\b" + direction + r"\s+'/[\s\S]*?'", re.I)
    findings, seen = [], set()
    regions = []
    for stmt in getattr(source.ir, "statements", ()):
        if re.search(r"\bCOPY\b", stmt.text, re.I):
            regions.append((stmt.start, source.code_no_comments[stmt.start:stmt.end]))
    regions.extend(_dynamic_sql_regions_for_rule(source))
    for base, text in regions:
        m = pattern.search(text)
        if not m:
            continue
        off = base + m.start()
        if off in seen:
            continue
        seen.add(off)
        findings.append(check._gf(source, off))
    return findings


@_builtin("postgres_subscription_credentials")
def _detect_postgres_subscription_credentials(check, source):
    """Detect CREATE SUBSCRIPTION statements containing credentials.

    Connection strings are ordinary SQL string literals, so they are masked in
    ``code_masked``. We first prove from the masked statement/dynamic region
    that it is a real CREATE SUBSCRIPTION statement, then inspect the matching
    unmasked code region for ``password=`` or URI-style ``user:pass@``.
    """
    findings, seen = [], set()
    regions = []
    for stmt in getattr(source.ir, "statements", ()):
        if re.search(r"\bCREATE\s+SUBSCRIPTION\b", stmt.text, re.I):
            regions.append((stmt.start, source.code_no_comments[stmt.start:stmt.end]))
    regions.extend(_dynamic_sql_regions_for_rule(source))
    for base, text in regions:
        if not re.search(r"\bCREATE\s+SUBSCRIPTION\b", text, re.I):
            continue
        if not re.search(r"\bpassword\s*=|postgres(?:ql)?://[^'\s;:@]+:[^'\s;@]+@", text, re.I):
            continue
        off = base + (re.search(r"\bCREATE\s+SUBSCRIPTION\b", text, re.I).start())
        if off in seen:
            continue
        seen.add(off)
        findings.append(check._gf(source, off))
    return findings

