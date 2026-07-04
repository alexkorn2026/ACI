"""Datenfluss-Check: DDL-Anweisungen im Code (GRANT, CREATE, ALTER, ...).

Erkennt DDL sowohl in dynamischem SQL als auch als eigenständige
Anweisung und folgt - wie der SQL-Injection-Check - der Taint-Quelle.
"""

from __future__ import annotations

import re

from ..finding import (Finding)
from ..ir import dynamic_sql_executions

from .base import (Check, _OBJECT_DEF_RE, _ddl_keyword,
                    _norm_ws, build_ddl_regex,
                    _normalize_ddl, _external_table_at, _ALTER_SESSION_NLS_RE,
                    _GRANT_END_RE, _assignments_before, _collect_var_writes,
                    _origin_related)


# ----------------------------------------------------------------------
# Check 5 - DDL im Code
# ----------------------------------------------------------------------

class DdlCheck(Check):
    """Erkennt DDL-Anweisungen (GRANT, CREATE, ALTER, DROP, ...) - sowohl
    in dynamischem SQL als auch als eigenständige Anweisungen.

    Dynamische DDL wird ausschließlich in den Ausdrücken echter
    dynamischer SQL-Statements (EXECUTE IMMEDIATE / EXECUTE / OPEN FOR /
    DBMS_SQL.PARSE) gesucht - DDL-Schlüsselworte in beliebigen anderen
    String-Literalen (z.B. ``DBMS_OUTPUT.PUT_LINE('DROP USER x')`` oder
    ``RAISE NOTICE 'DROP USER x'``) erzeugen damit kein Finding.
    """

    config_key = "ddl_in_code"

    def __init__(self, config, dialect):
        super().__init__(config, dialect)
        # DDL-Objektvokabular datengetrieben: optionale Regelkonfiguration
        # ``ddl_objects`` (create/alter/drop/truncate) überschreibt die
        # Defaults; fehlt sie, gilt das eingebaute Standardvokabular.
        self._ddl_re = build_ddl_regex(config.get("ddl_objects"))
        self.detect_dynamic = bool(config.get("detect_in_dynamic_sql", True))
        self.detect_standalone = bool(config.get("detect_standalone", True))
        self.skip_object_defs = bool(config.get("skip_object_definitions", True))
        self.keywords = {}
        for item in config.get("keywords", []) or []:
            kw = item.get("keyword", "").upper()
            if kw:
                self.keywords[kw] = item
        # Allowlist: eigenständige DDL-Anweisungen, die in CI/CD-Skripten
        # erlaubt sind und kein Finding erzeugen (z.B. CREATE/ALTER/DROP
        # TABLE). Greift nur für eigenständige DDL - dynamische DDL
        # bleibt grundsätzlich meldepflichtig. Externe Tabellen sind
        # ausgenommen (siehe external_table).
        allowed = config.get("allowed_statements") or []
        self.allowed_statements = (
            {_normalize_ddl(s) for s in allowed
             if isinstance(s, str) and s.strip()}
            if isinstance(allowed, list) else set())
        # Konfiguration für die Meldung externer Tabellen.
        self.external_table = config.get("external_table") or {}
        # Statements mit fest erhöhter Kritikalität (z.B. ALTER USER -
        # Benutzerverwaltung gehört nicht in CI/CD-Deployments).
        self.critical_statements = {}
        for item in config.get("critical_statements") or []:
            if isinstance(item, dict) and item.get("statement"):
                self.critical_statements[
                    _normalize_ddl(item["statement"])] = item
        # Zentrale, leicht erweiterbare Listen für die
        # GRANT/REVOKE-Analyse: Oracle-Systemprivilegien und
        # -Standardrollen. Privilegiennamen werden NICHT um
        # CREATE-Modifizierer bereinigt (z.B. CREATE PUBLIC DATABASE
        # LINK ist ein eigenständiger Privilegienname).
        self.system_privileges = {
            _norm_ws(s) for s in config.get("system_privileges") or []
            if isinstance(s, str) and s.strip()
        }
        self.standard_roles = {
            _norm_ws(r) for r in config.get("standard_roles") or []
            if isinstance(r, str) and r.strip()
        }
        # Meldungstexte/Schweregrad für GRANT/REVOKE von
        # Systemprivilegien bzw. Standardrollen.
        self.privilege_grant = config.get("privilege_grant") or {}
        # Objektprivilegien, die in CI/CD-Deployments gewollt sind: ein
        # eigenständiges GRANT, das ausschließlich diese Rechte auf ein
        # Objekt vergibt (z.B. GRANT SELECT ON t TO rolle), erzeugt kein
        # Finding. Dynamische und sonstige GRANTs bleiben meldepflichtig.
        self.harmless_object_privileges = {
            str(p).upper() for p in config.get(
                "harmless_object_privileges",
                ["SELECT", "READ", "INSERT", "UPDATE", "DELETE"])
            if isinstance(p, str) and p.strip()
        }

    def _keyword_cfg(self, keyword):
        return self.keywords.get(keyword, {})

    def _external_finding(self, source, offset, dynamic, span_end=None,
                          clip_to_statement=False, span_start=None):
        """Erzeugt ein Finding für eine externe Tabelle.

        ``span_start``/``span_end``/``clip_to_statement`` werden an
        :meth:`_finding` durchgereicht: der Snippet/Kontext umfasst dann
        das gesamte ``CREATE TABLE ... ORGANIZATION EXTERNAL ...``-
        Statement und nicht die Nachbar-DDL oder vorgelagerte SQL*Plus-
        Direktiven (``PROMPT`` etc.).
        """
        ext = self.external_table
        message = ext.get(
            "message",
            "Externe Tabelle (CREATE TABLE ... ORGANIZATION EXTERNAL) - "
            "liest Daten aus einer Datei im Dateisystem des "
            "Datenbankservers.")
        if dynamic:
            message = "In dynamischem SQL gebildet - " + message
        return self._finding(
            source, offset, ext.get("level", "High"), message,
            recommendation=ext.get(
                "recommendation",
                "Externe Tabellen greifen über ein DIRECTORY-Objekt auf "
                "das Dateisystem des Datenbankservers zu. Quelle, "
                "DIRECTORY-Rechte und Inhalt prüfen."),
            rule_ref="EXTERNAL TABLE",
            span_end=span_end,
            clip_to_statement=clip_to_statement,
            span_start=span_start)

    def _dynamic_sql_regions(self, source):
        """Liefert ``(Offset, Text)`` der Ausdrücke aller dynamischen
        SQL-Statements.

        Die dynamischen SQL-Stellen und ihre Ausdrucksgrenzen stammen
        aus dem Lexer (``source.dynamic_sql``). Der Text wird aus
        ``code_no_comments`` entnommen - String-Literale sind also
        sichtbar, sodass DDL *innerhalb* von dynamischem SQL erkannt
        wird. Ist der Ausdruck nur ein Bezeichner, werden zusätzlich
        dessen Zuweisungen einbezogen - positions- und routinesensitiv:
        nur Zuweisungen *vor* der Ausführung und in derselben Routine
        zählen (spätere oder routine-fremde Zuweisungen nicht).
        """
        code = source.code_no_comments
        masked = source.code_masked
        regions = []
        seen_assign: set = set()
        dyn_items = dynamic_sql_executions(source.ir)
        for dyn in dyn_items:
            cut = dyn.trigger_start
            expr_start, semi = dyn.expr_start, dyn.expr_end
            regions.append((expr_start, code[expr_start:semi], cut))
            mvar = re.match(
                r'\s*"?([A-Za-z_][\w$#]*)"?\s*(?:INTO\b|USING\b|BULK\b|$)',
                masked[expr_start:semi], re.IGNORECASE)
            if mvar:
                routine = source.routine_at(cut)
                for a in _assignments_before(source, mvar.group(1), cut,
                                             routine):
                    if a.expr_start in seen_assign:
                        continue
                    seen_assign.add(a.expr_start)
                    regions.append(
                        (a.expr_start, code[a.expr_start:a.expr_end], cut))
        return regions

    def _grant_kind(self, text, after):
        """Klassifiziert ein GRANT/REVOKE ab Position ``after`` (hinter
        dem Schlüsselwort).

        Liefert ``(kind, items)``: ``kind`` ist ``role`` (Standard-
        rolle), ``system`` (Systemprivileg) oder ``base`` (Objekt-
        privileg ``GRANT ... ON ...`` bzw. nicht klassifizierbar).
        Die Privilegien-/Rollenliste vor ``TO``/``FROM`` wird dabei -
        auch mehrzeilig - normalisiert und gegen die zentralen Listen
        geprüft.
        """
        semi = text.find(";", after)
        region = text[after:semi if semi != -1 else len(text)]
        end = _GRANT_END_RE.search(region)
        granted = region[:end.start()] if end else region
        if re.search(r"\bON\b", granted, re.IGNORECASE):
            return "base", []           # Objektprivileg: GRANT ... ON ...
        roles, systems = [], []
        for part in granted.split(","):
            norm = _norm_ws(part)
            if not norm:
                continue
            if norm in self.standard_roles:
                roles.append(norm)
            elif norm in self.system_privileges:
                systems.append(norm)
        if systems:
            return "system", systems
        if roles:
            return "role", roles
        return "base", []

    def _is_harmless_object_privilege(self, text, after):
        """True für ein GRANT/REVOKE ausschließlich harmloser Objekt-
        privilegien.

        Ein ``GRANT``/``REVOKE`` von ``SELECT/READ/INSERT/UPDATE/DELETE``
        auf ein Objekt (``... ON <Objekt> TO/FROM <Rolle/Benutzer>``) ist
        in CI/CD-Deployments eine gewollte Aktivität und erzeugt kein
        Finding. Sobald ein anderes Recht (z.B. ``ALTER``, ``EXECUTE``,
        ``ALL``, ``REFERENCES``) enthalten ist oder es kein
        Objektprivileg ist, greift die Ausnahme nicht.
        """
        if not self.harmless_object_privileges:
            return False
        semi = text.find(";", after)
        region = text[after:semi if semi != -1 else len(text)]
        end = _GRANT_END_RE.search(region)
        granted = region[:end.start()] if end else region
        on = re.search(r"\bON\b", granted, re.IGNORECASE)
        if not on:
            return False                # kein Objektprivileg (GRANT ... ON)
        # Privilegienliste vor ON; Spaltenlisten in Klammern entfernen.
        privs = re.sub(r"\([^)]*\)", " ", granted[:on.start()])
        words = set(re.findall(r"[A-Za-z]+", privs.upper()))
        return bool(words) and words <= self.harmless_object_privileges

    def _describe(self, kw, stmt, text, m, dynamic):
        """Liefert ``(level, message, recommendation, rule_ref)`` für
        einen DDL-Treffer - inklusive Sonderbehandlung für GRANT/REVOKE
        von Systemprivilegien/Standardrollen sowie kritische Statements
        (z.B. ALTER USER)."""
        cfg = self._keyword_cfg(kw)
        where = "in dynamischem SQL" if dynamic else "im Code"
        prefix = "DDL-Anweisung" if dynamic else "Eigenständige DDL-Anweisung"
        note = "In dynamischem SQL gebildet - " if dynamic else ""
        level = cfg.get("level", "High")
        message = f"{prefix} ({kw}) {where}. " + cfg.get("message", "")
        recommendation = cfg.get(
            "recommendation",
            "Prüfen, ob die DDL an dieser Stelle beabsichtigt und "
            "autorisiert ist.")
        rule_ref = kw

        if kw in ("GRANT", "REVOKE"):
            kind, items = self._grant_kind(text, m.end())
            if kind in ("system", "role"):
                pg = self.privilege_grant
                level = pg.get("level", "Critical")
                if kind == "role":
                    base_msg = pg.get(
                        "role_message",
                        "GRANT/REVOKE einer Oracle-Standardrolle.")
                    rule_ref = kw + " STANDARD ROLE"
                else:
                    base_msg = pg.get(
                        "system_message",
                        "GRANT/REVOKE eines Oracle-Systemprivilegs.")
                    rule_ref = kw + " SYSTEM PRIVILEGE"
                if items:
                    base_msg += " Erkannt: " + ", ".join(items) + "."
                message = note + base_msg
                recommendation = pg.get("recommendation", recommendation)
        elif stmt in self.critical_statements:
            citem = self.critical_statements[stmt]
            level = citem.get("level", "Critical")
            message = note + citem.get("message", message)
            recommendation = citem.get("recommendation", recommendation)
            rule_ref = stmt
        return level, message, recommendation, rule_ref

    @staticmethod
    def _dyn_taint_origins(source, base, text, cut):
        """Taint-Quellen der in dynamischem SQL verwendeten Variablen.

        Im maskierten Ausdruck sind die String-Inhalte ausgeblendet, es
        verbleiben nur die echten Code-Bezeichner (z.B. die per ``||``
        konkatenierten Variablen). Für jeden wird - sofern es eine
        routine-lokal nachvollziehbare Variable bzw. ein Parameter ist -
        die Zuweisung bzw. der Routinenkopf als zusätzliche Fundstelle
        ausgewiesen. Bezeichner ohne Schreibzugriff (Schlüsselworte,
        Funktionsnamen) liefern nichts und entfallen damit von selbst.
        """
        masked = source.code_masked[base:base + len(text)]
        seen, origins = set(), []
        for m in re.finditer(r"[A-Za-z_][\w$#]*", masked):
            var = m.group(0)
            if var.upper() in seen:
                continue
            seen.add(var.upper())
            for pos, _rc, _rm, kind in _collect_var_writes(source, var, cut):
                origins.append((pos, kind))
        return _origin_related(source, origins)

    def _scan_regions(self, source, regions, dynamic, findings, seen):
        """Durchsucht ``(base, text, cut)``-Regionen nach DDL-Anweisungen.

        Ein GRANT/REVOKE wird als ganzes Statement behandelt: die
        Privilegien-/Rollenliste darf keine eigenen DDL-Treffer
        erzeugen. Die Allowlist und das Überspringen von
        Objektdefinitionen greifen nur für eigenständige DDL. ``cut`` ist
        bei dynamischem SQL die Ausführungsstelle (für die Taint-Quellen-
        Verfolgung), sonst ``None``.
        """
        for base, text, cut in regions:
            skip_until = -1
            for m in self._ddl_re.finditer(text):
                if m.start() < skip_until:
                    continue            # innerhalb eines GRANT/REVOKE
                kw = _ddl_keyword(m.group(0))
                if self.keywords and kw not in self.keywords:
                    continue
                if kw in ("GRANT", "REVOKE"):
                    semi = text.find(";", m.end())
                    skip_until = semi if semi != -1 else len(text)
                # Eigenständiges GRANT/REVOKE ausschließlich harmloser
                # Objektprivilegien (z.B. GRANT/REVOKE SELECT ON obj
                # TO/FROM rolle): in CI/CD gewollt, daher kein Finding.
                if (kw in ("GRANT", "REVOKE") and not dynamic
                        and self._is_harmless_object_privilege(
                            text, m.end())):
                    continue
                # ALTER SESSION SET NLS_*: harmlose Sitzungseinstellung.
                if _ALTER_SESSION_NLS_RE.match(text, m.start()):
                    continue
                stmt = _normalize_ddl(m.group(0))
                external = (stmt == "CREATE TABLE"
                            and _external_table_at(text, m.start()))
                if not dynamic and not external:
                    if stmt in self.allowed_statements:
                        continue
                    if (self.skip_object_defs and kw == "CREATE"
                            and _OBJECT_DEF_RE.search(m.group(0))):
                        continue
                offset = base + m.start()
                # Dedup über die absolute Fundstelle (Offset): echte
                # Doppeltreffer werden unterdrückt, mehrere DDL-/GRANT-/
                # REVOKE-Anweisungen auf derselben Zeile aber nicht.
                key = ("dyn" if dynamic else "std", offset)
                if key in seen:
                    continue
                seen.add(key)
                # span_end fuer das gesamte Statement bestimmen:
                #  - dynamisch: die ganze dynamische Ausdrucksregion.
                #  - sonst: das Ende des Lexer-Statements, das den Fund
                #    enthaelt. Der Lexer behandelt sowohl ``;`` als auch
                #    ``/`` auf eigener Zeile als Statement-Terminator -
                #    das ist wichtig fuer ``ALTER PROFILE ... /``, wo das
                #    Statement OHNE ``;`` endet. Ein ``text.find(";")``-
                #    Fallback wuerde sonst das ``;`` der naechsten DDL
                #    einsammeln (z.B. ``DROP TABLE ...;`` darunter) und
                #    dessen Zeilen mit in den Kontext nehmen.
                if dynamic:
                    span_end = base + len(text)
                else:
                    span_end = source.statement_end_after(offset)
                if external:
                    # ``span_start=offset``: das ``CREATE`` ist der echte
                    # Anfang der externen Tabelle - kein Walk-Back ueber
                    # vorherige Zeilen (z.B. SQL*Plus PROMPT) noetig.
                    findings.append(self._external_finding(
                        source, offset, dynamic, span_end=span_end,
                        clip_to_statement=True, span_start=offset))
                    continue
                level, message, rec, ref = self._describe(
                    kw, stmt, text, m, dynamic)
                # Bei DDL in dynamischem SQL die Herkunft der dort
                # verwendeten Variablen als Taint-Quelle ausweisen -
                # abschaltbar über die Option ``taint_sources``
                # (aci.ini) bzw. ``--no-taint-sources``.
                related = []
                if dynamic and cut is not None and self.show_taint_sources:
                    related = self._dyn_taint_origins(
                        source, base, text, cut)
                # span_end wurde oben bereits berechnet und deckt Snippet/
                # Kontext bis zum Statement-Ende ab. ``clip_to_statement``
                # blendet zusaetzlich Padding mit Nachbar-Statements und
                # Pre-/Post-Kommentaren aus.
                #
                # ``span_start=offset`` fuer nicht-dynamische DDL: das DDL-
                # Keyword (CREATE/ALTER/DROP/GRANT/...) IST der Anfang des
                # Statements - kein Walk-Back zu vorgelagerten SQL*Plus-
                # Direktiven (``PROMPT``, ``SET``) oder Trennstrich-
                # Kommentaren. Bei dynamischer DDL bleibt Auto-Detect, da
                # der Match innerhalb einer ``EXECUTE IMMEDIATE``/``format``-
                # Ausdrucksregion liegt und der Statement-Anfang vom Lexer
                # (Region-Basis) bestimmt wird.
                stmt_start_pos = offset if not dynamic else None
                findings.append(self._finding(
                    source, offset, level, message,
                    recommendation=rec, rule_ref=ref,
                    related=related,
                    context_n=1 if related else None,
                    span_end=span_end,
                    clip_to_statement=True,
                    span_start=stmt_start_pos))

    def run(self, source):
        findings: list[Finding] = []
        seen: set = set()
        # (a) DDL in echten dynamischen SQL-Statements; (b) eigenständige
        #     DDL im maskierten Quelltext (Kommentare/Strings ausmaskiert).
        if self.detect_dynamic:
            self._scan_regions(source, self._dynamic_sql_regions(source),
                               True, findings, seen)
        if self.detect_standalone:
            self._scan_regions(source, [(0, source.code_masked, None)],
                               False, findings, seen)
        # Bei Ketten gleichartiger DDL-Anweisungen den Kontext jeweils auf
        # die betroffene Zeile beschränken (Nachbarn sind eigene Findings).
        Check.collapse_sibling_context(findings)
        return findings

