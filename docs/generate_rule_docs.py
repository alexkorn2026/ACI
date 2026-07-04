#!/usr/bin/env python3
"""Generiert die HTML-Regeldokumentation unter ``docs/rules/``.

Liest alle Regeldateien unter ``aci/rules/`` und erzeugt je Regelsatz
(Oracle/PostgreSQL x Sicherheit/Coding-Guidelines/MITRE) eine HTML-Seite,
die jeden Regelsatz und jede einzelne Regel detailliert beschreibt, sowie
eine Index-Seite.

Aufruf:  python3 docs/generate_rule_docs.py
"""

from __future__ import annotations

import glob
import html
import json
import os
from datetime import date

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RULES = os.path.join(ROOT, "aci", "rules")
OUT = os.path.join(HERE, "rules")
# PL/SQL- bzw. PL/pgSQL-Beispiele (verwundbar/sicher bzw. Verstoß/konform)
# je Regel. Reine Dokumentationsdaten - werden hier eingespielt, nicht von
# der ACI-Laufzeit gelesen. Struktur:
#   {"security":   {dialekt: {check-id: HTML-Block}},
#    "mitre":      {dialekt: {Regeltitel: HTML-Block}},
#    "guidelines": {dialekt: {Regeltitel: HTML-Block}}}
EXAMPLES_PATH = os.path.join(HERE, "rule_examples.json")

CSS = """
:root{--blocker:#7f1d1d;--critical:#b91c1c;--high:#c2410c;--major:#b45309;
--warning:#a16207;--minor:#0e7490;--info:#6b7280;--bg:#f4f5f7;--card:#fff;
--ink:#1f2933;--muted:#6b7280;--border:#e3e6ea;--accent:#2563eb;}
*{box-sizing:border-box;}html{scroll-behavior:smooth;}
body{margin:0;background:var(--bg);color:var(--ink);font-size:15px;
line-height:1.6;font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,
sans-serif;}
header{background:#111827;color:#fff;padding:30px 40px;}
header h1{margin:0 0 6px;font-size:23px;}
header .sub{color:#9ca3af;font-size:13.5px;}
header a{color:#9ca3af;}
.wrap{max-width:1100px;margin:0 auto;padding:28px 40px 80px;}
section{background:var(--card);border:1px solid var(--border);
border-radius:12px;padding:22px 28px;margin-bottom:20px;}
h2{font-size:19px;margin:2px 0 6px;padding-bottom:8px;
border-bottom:2px solid var(--border);}
h3{font-size:15px;margin:0;}
p{margin:7px 0;}
p.lead{color:var(--muted);}
code{background:#eef2f7;color:#b91c5b;padding:1px 5px;border-radius:4px;
font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12.5px;
word-break:break-word;}
table{width:100%;border-collapse:collapse;margin:10px 0;font-size:13.5px;}
th{text-align:left;background:#f9fafb;padding:8px 11px;
border-bottom:2px solid var(--border);font-size:11px;text-transform:uppercase;
letter-spacing:.04em;color:var(--muted);}
td{padding:8px 11px;border-bottom:1px solid var(--border);
vertical-align:top;}
.badge{display:inline-block;padding:2px 9px;border-radius:999px;color:#fff;
font-size:10.5px;font-weight:700;text-transform:uppercase;}
.badge.blocker{background:var(--blocker);}.badge.critical{background:var(--critical);}
.badge.high{background:var(--high);}.badge.major{background:var(--major);}
.badge.warning{background:var(--warning);}.badge.minor{background:var(--minor);}
.badge.info{background:var(--info);}
.rule{border:1px solid var(--border);border-radius:10px;padding:14px 18px;
margin:12px 0;}
.rule.off{opacity:.6;}
.rule-head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}
.rid{font-family:ui-monospace,Menlo,monospace;font-size:12px;font-weight:700;
background:#1f2933;color:#fff;padding:2px 8px;border-radius:5px;}
.tag{font-size:10.5px;border:1px solid var(--border);border-radius:999px;
padding:1px 8px;color:var(--muted);}
.rule .msg{margin:8px 0;}
.meta{font-size:13px;color:var(--muted);margin:4px 0;}
.meta b{color:var(--ink);}
.chips{display:flex;flex-wrap:wrap;gap:5px;margin:6px 0;}
.chip{background:#eef2f7;border-radius:5px;padding:2px 7px;font-size:12px;
font-family:ui-monospace,Menlo,monospace;}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));
gap:14px;}
.cards a{display:block;text-decoration:none;color:inherit;border:1px solid
var(--border);border-radius:10px;padding:16px 18px;background:#fff;}
.cards a:hover{border-color:var(--accent);}
.cards h3{color:var(--accent);margin-bottom:4px;}
.toc{font-size:13.5px;}
.toc a{color:var(--accent);text-decoration:none;margin-right:14px;}
.examples{margin-top:14px;}
.ex{border-top:1px dashed var(--border);margin-top:14px;padding-top:12px;}
.ex.first{border-top:none;margin-top:8px;}
.exname{font-weight:700;margin:0 0 2px;font-size:13.5px;}
.exname code{background:#1f2933;color:#fff;}
.exnote{color:var(--muted);font-size:12.5px;margin:2px 0 6px;}
.exlabel{font-size:10.5px;font-weight:700;text-transform:uppercase;
letter-spacing:.04em;margin:9px 0 3px;}
.exlabel.bad{color:var(--critical);}
.exlabel.bad::before{content:"\\2718  ";}
.exlabel.good{color:#15803d;}
.exlabel.good::before{content:"\\2714  ";}
pre.code{margin:0;padding:10px 13px;border-radius:7px;overflow-x:auto;
font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12px;
line-height:1.55;white-space:pre;}
pre.code.bad{background:#fef2f2;border:1px solid #fecaca;color:#7f1d1d;}
pre.code.good{background:#f0fdf4;border:1px solid #bbf7d0;color:#14532d;}
footer{max-width:1100px;margin:0 auto;padding:0 40px 50px;color:var(--muted);
font-size:12.5px;}
"""


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def badge(severity) -> str:
    sev = (severity or "").strip()
    if not sev:
        return ""
    return f'<span class="badge {esc(sev.lower())}">{esc(sev)}</span>'


def page(title: str, subtitle: str, body: str) -> str:
    """Baut ein vollständiges HTML-Dokument."""
    return (
        "<!doctype html>\n<html lang=\"de\">\n<head>\n"
        "<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
        f"<title>{esc(title)}</title>\n<style>{CSS}</style>\n</head>\n<body>\n"
        f"<header>\n<h1>{esc(title)}</h1>\n"
        f"<div class=\"sub\">{subtitle}</div>\n</header>\n"
        f"<div class=\"wrap\">\n{body}\n</div>\n"
        f"<footer>ACI &ndash; Automated Code Inspection &middot; "
        f"Regeldokumentation &middot; generiert am {date.today().isoformat()} "
        f"von <code>docs/generate_rule_docs.py</code></footer>\n"
        "</body>\n</html>\n"
    )


def _load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _kv_table(pairs) -> str:
    rows = "".join(
        f"<tr><td><b>{esc(k)}</b></td><td>{v}</td></tr>"
        for k, v in pairs if v not in (None, "", [], {}))
    return f"<table>{rows}</table>" if rows else ""


def _chips(values) -> str:
    if not values:
        return "<p class=\"meta\">(keine)</p>"
    return ('<div class="chips">'
            + "".join(f'<span class="chip">{esc(v)}</span>' for v in values)
            + "</div>")


def _detector(det) -> str:
    if not isinstance(det, dict):
        return esc(det)
    parts = [f"Typ <code>{esc(det.get('type', '?'))}</code>"]
    if det.get("name"):
        parts.append(f"Detektor <code>{esc(det['name'])}</code>")
    if det.get("pattern"):
        parts.append(f"Muster <code>{esc(det['pattern'])}</code>")
    if det.get("target"):
        parts.append(f"Ziel <code>{esc(det['target'])}</code>")
    return " &middot; ".join(parts)


# ----------------------------------------------------------------------
# Sicherheits-Regelsatz (oracle.json / postgresql.json)
# ----------------------------------------------------------------------

_SCALAR_LABELS = {
    "level": "Schweregrad", "max_identifier_length": "Max. Bezeichnerlänge",
    "flag_quoted_reserved": "Reservierte Worte in Quotes melden",
    "detect_wrapped": "Wrapped-Code erkennen", "wrapped_level": "Level Wrapped",
    "detect_chr_chain": "CHR-Ketten erkennen",
    "chr_chain_min": "Min. CHR-Kettenlänge", "chr_chain_level": "Level CHR-Kette",
    "tainted_level": "Level ungeprüfte Konkatenation",
    "literal_only_level": "Level reine Literale",
    "sanitized_level": "Level abgesichert",
    "unknown_dynamic_level": "Level unbekannte Herkunft",
    "detect_in_dynamic_sql": "DDL in dynamischem SQL erkennen",
    "detect_standalone": "Eigenständige DDL erkennen",
    "skip_object_definitions": "Objektdefinitionen überspringen",
}
_LIST_KEYS = {"items", "keywords", "patterns", "critical_statements",
              "reserved_words", "sanitizers", "system_privileges",
              "standard_roles", "allowed_statements",
              "harmless_object_privileges"}


def _obj_table(rows, columns) -> str:
    head = "".join(f"<th>{esc(c[1])}</th>" for c in columns)
    body = ""
    for row in rows:
        cells = ""
        for key, _label in columns:
            val = row.get(key) if isinstance(row, dict) else None
            if key in ("level", "severity"):
                cells += f"<td>{badge(val)}</td>"
            elif key in ("regex", "pattern", "keyword", "statement", "name",
                         "id"):
                cells += f"<td><code>{esc(val)}</code></td>" if val else "<td></td>"
            else:
                cells += f"<td>{esc(val)}</td>"
        body += f"<tr>{cells}</tr>"
    return f"<table><tr>{head}</tr>{body}</table>"


def render_security(data, dialect_label, examples=None) -> str:
    examples = examples or {}
    checks = data.get("checks", {})
    toc = " ".join(
        f'<a href="#{esc(c.get("id", k))}">{esc(c.get("name", k))}</a>'
        for k, c in checks.items())
    body = [
        f'<section><h2>Regelsatz &bdquo;Sicherheit&ldquo; &ndash; '
        f'{esc(dialect_label)}</h2>',
        f'<p class="lead">{esc(data.get("description", ""))}</p>',
        _kv_table([
            ("Dialekt", esc(data.get("dialect"))),
            ("Version", esc(data.get("version"))),
            ("Dateiendungen", _chips(data.get("file_extensions", []))),
            ("Checks", str(len(checks))),
        ]),
        f'<p class="toc">{toc}</p></section>',
    ]
    for key, cfg in checks.items():
        cid = cfg.get("id", key)
        scalars = [(_SCALAR_LABELS.get(k, k), esc(v))
                   for k, v in cfg.items()
                   if k not in _LIST_KEYS | {"id", "name", "enabled",
                                             "external_table",
                                             "privilege_grant"}]
        body.append(
            f'<section id="{esc(cid)}"><h2>{esc(cfg.get("name", key))} '
            f'<span class="rid">{esc(cid)}</span></h2>')
        body.append(
            f'<p class="meta">Konfigurationsschlüssel <code>{esc(key)}</code> '
            f'&middot; Status: '
            f'{"aktiv" if cfg.get("enabled") else "inaktiv"}</p>')
        if scalars:
            body.append(_kv_table(scalars))
        # Listen-/Objektfelder
        if cfg.get("items"):
            body.append("<h3>Unerwünschte Pakete/Objekte</h3>")
            body.append(_obj_table(cfg["items"], [
                ("name", "Name"), ("level", "Schweregrad"),
                ("message", "Beschreibung"), ("recommendation", "Empfehlung")]))
        if cfg.get("keywords"):
            body.append("<h3>DDL-Schlüsselworte</h3>")
            body.append(_obj_table(cfg["keywords"], [
                ("keyword", "Schlüsselwort"), ("level", "Schweregrad"),
                ("message", "Beschreibung"), ("recommendation", "Empfehlung")]))
        if cfg.get("critical_statements"):
            body.append("<h3>Kritische Statements</h3>")
            body.append(_obj_table(cfg["critical_statements"], [
                ("statement", "Statement"), ("level", "Schweregrad"),
                ("message", "Beschreibung"), ("recommendation", "Empfehlung")]))
        if cfg.get("patterns"):
            body.append("<h3>Muster</h3>")
            body.append(_obj_table(cfg["patterns"], [
                ("id", "ID"), ("level", "Schweregrad"), ("target", "Ziel"),
                ("regex", "Regex"), ("message", "Beschreibung"),
                ("recommendation", "Empfehlung")]))
        for lk, label in (("system_privileges", "Systemprivilegien"),
                          ("standard_roles", "Standardrollen"),
                          ("harmless_object_privileges",
                           "Harmlose Objektprivilegien (kein Finding)"),
                          ("sanitizers", "Sanitizer"),
                          ("allowed_statements", "Erlaubte Statements"),
                          ("reserved_words", "Reservierte Worte")):
            if cfg.get(lk):
                body.append(f"<h3>{label} ({len(cfg[lk])})</h3>")
                body.append(_chips(cfg[lk]))
        for dk, label in (("external_table", "Externe Tabellen"),
                          ("privilege_grant", "Privilegien-GRANT/REVOKE")):
            if isinstance(cfg.get(dk), dict) and cfg[dk]:
                body.append(f"<h3>{label}</h3>")
                body.append(_kv_table(
                    [(k, esc(v)) for k, v in cfg[dk].items()]))
        if examples.get(cid):
            body.append(examples[cid])
        body.append("</section>")
    return "\n".join(body)


# ----------------------------------------------------------------------
# Coding-Guidelines / MITRE (Liste von Regeln je Datei)
# ----------------------------------------------------------------------

def render_rule(rule, examples=None) -> str:
    examples = examples or {}
    rid = rule.get("id", "?")
    off = "" if rule.get("enabled", True) else " off"
    tags = "" if rule.get("enabled", True) else '<span class="tag">inaktiv</span>'
    meta = []
    if rule.get("technique"):
        meta.append(("MITRE-Technik", esc(rule["technique"])))
    if rule.get("characteristics"):
        meta.append(("Merkmal", esc(rule["characteristics"])))
    if rule.get("detector"):
        meta.append(("Detektor", _detector(rule["detector"])))
    if rule.get("recommendation"):
        meta.append(("Empfehlung", esc(rule["recommendation"])))
    if rule.get("url"):
        meta.append(("Quelle",
                     f'<a href="{esc(rule["url"])}">{esc(rule["url"])}</a>'))
    ex = examples.get(rule.get("title", ""), "")
    return (
        f'<div class="rule{off}" id="{esc(rid)}">'
        f'<div class="rule-head"><span class="rid">{esc(rid)}</span>'
        f'<h3>{esc(rule.get("title", ""))}</h3>'
        f'{badge(rule.get("severity"))}{tags}</div>'
        f'<p class="msg">{esc(rule.get("message", ""))}</p>'
        f'{_kv_table(meta)}{ex}</div>'
    )


def render_ruleset_list(files, heading, intro, group_key, group_id_key,
                        examples=None) -> str:
    examples = examples or {}
    body = [f'<section><h2>{esc(heading)}</h2><p class="lead">{esc(intro)}</p>']
    total = 0
    blocks = []
    for path in files:
        data = _load(path)
        rules = data.get("rules", [])
        total += len(rules)
        gid = data.get(group_id_key, "")
        name = data.get(group_key, os.path.basename(path))
        anchor = esc(os.path.splitext(os.path.basename(path))[0])
        blocks.append((anchor, name, gid, data.get("description", ""), rules))
    toc = " ".join(f'<a href="#{a}">{esc(n)}</a>' for a, n, _g, _d, _r in blocks)
    body.append(f'<p class="meta">{len(blocks)} Gruppen &middot; '
                f'{total} Regeln</p><p class="toc">{toc}</p></section>')
    for anchor, name, gid, desc, rules in blocks:
        gid_html = f' <span class="rid">{esc(gid)}</span>' if gid else ""
        body.append(f'<section id="{anchor}"><h2>{esc(name)}{gid_html}</h2>')
        if desc:
            body.append(f'<p class="lead">{esc(desc)}</p>')
        body.append(f'<p class="meta">{len(rules)} Regeln</p>')
        for rule in rules:
            body.append(render_rule(rule, examples))
        body.append("</section>")
    return "\n".join(body)


def _count_rules(files):
    return sum(len(_load(p).get("rules", [])) for p in files)


# ----------------------------------------------------------------------

def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    sub = ("Detaillierte Beschreibung der Prüfregeln &middot; "
           '<a href="index.html">Übersicht</a>')
    ex = _load(EXAMPLES_PATH)
    ex_sec = ex.get("security", {})
    ex_mit = ex.get("mitre", {})
    ex_gl = ex.get("guidelines", {})

    gl_o = sorted(glob.glob(os.path.join(RULES, "guidelines/oracle/*.json")))
    gl_p = sorted(glob.glob(os.path.join(RULES, "guidelines/postgresql/*.json")))
    mi_o = sorted(glob.glob(os.path.join(RULES, "mitre/oracle/*.json")))
    mi_p = sorted(glob.glob(os.path.join(RULES, "mitre/postgresql/*.json")))

    pages = {
        "oracle-security.html": page(
            "ACI-Regeln &ndash; Oracle Sicherheit", sub,
            render_security(_load(os.path.join(RULES, "oracle.json")),
                            "Oracle", ex_sec.get("oracle"))),
        "postgresql-security.html": page(
            "ACI-Regeln &ndash; PostgreSQL Sicherheit", sub,
            render_security(_load(os.path.join(RULES, "postgresql.json")),
                            "PostgreSQL", ex_sec.get("postgresql"))),
        "oracle-guidelines.html": page(
            "ACI-Regeln &ndash; Oracle Coding Guidelines", sub,
            render_ruleset_list(
                gl_o, "Coding Guidelines &ndash; Oracle",
                "PL/SQL- und SQL-Coding-Guidelines (Trivadis v4.4), nach "
                "Kategorien gegliedert.", "category", "category",
                ex_gl.get("oracle"))),
        "postgresql-guidelines.html": page(
            "ACI-Regeln &ndash; PostgreSQL Coding Guidelines", sub,
            render_ruleset_list(
                gl_p, "Coding Guidelines &ndash; PostgreSQL",
                "PL/pgSQL- und SQL-Coding-Guidelines für PostgreSQL.",
                "category", "category", ex_gl.get("postgresql"))),
        "oracle-mitre.html": page(
            "ACI-Regeln &ndash; Oracle MITRE ATT&CK", sub,
            render_ruleset_list(
                mi_o, "MITRE ATT&CK &ndash; Oracle",
                "Code-erkennbare Angriffsindikatoren, nach MITRE-ATT&CK-"
                "Taktiken gegliedert.", "tactic", "tactic_id",
                ex_mit.get("oracle"))),
        "postgresql-mitre.html": page(
            "ACI-Regeln &ndash; PostgreSQL MITRE ATT&CK", sub,
            render_ruleset_list(
                mi_p, "MITRE ATT&CK &ndash; PostgreSQL",
                "Code-erkennbare Angriffsindikatoren für PostgreSQL, nach "
                "MITRE-ATT&CK-Taktiken gegliedert.", "tactic", "tactic_id",
                ex_mit.get("postgresql"))),
    }

    # Index-Seite
    def card(href, title, desc):
        return (f'<a href="{href}"><h3>{title}</h3>'
                f'<p class="meta">{desc}</p></a>')

    cards = "".join([
        card("oracle-security.html", "Oracle &ndash; Sicherheit",
             "5 Sicherheits-Checks (Naming, Pakete, Obfuskation, "
             "SQL-Injection, DDL)."),
        card("oracle-guidelines.html", "Oracle &ndash; Coding Guidelines",
             f"{len(gl_o)} Kategorien, {_count_rules(gl_o)} Regeln (Trivadis)."),
        card("oracle-mitre.html", "Oracle &ndash; MITRE ATT&CK",
             f"{len(mi_o)} Taktiken, {_count_rules(mi_o)} Angriffsindikatoren."),
        card("postgresql-security.html", "PostgreSQL &ndash; Sicherheit",
             "5 Sicherheits-Checks für PL/pgSQL und SQL."),
        card("postgresql-guidelines.html",
             "PostgreSQL &ndash; Coding Guidelines",
             f"{len(gl_p)} Kategorie(n), {_count_rules(gl_p)} Regeln."),
        card("postgresql-mitre.html", "PostgreSQL &ndash; MITRE ATT&CK",
             f"{len(mi_p)} Taktiken, {_count_rules(mi_p)} Angriffsindikatoren."),
    ])
    index_body = (
        '<section><h2>ACI-Regeldokumentation</h2>'
        '<p class="lead">Diese Seiten beschreiben alle von ACI '
        '(Automated Code Inspection) ausgewerteten Regeln &ndash; je '
        'Regelsatz und je einzelner Regel. ACI prüft Oracle-PL/SQL- und '
        'PostgreSQL-PL/pgSQL-Code in drei Regelbereichen: Sicherheit, '
        'Coding Guidelines und MITRE-ATT&amp;CK-Angriffsindikatoren.</p>'
        '<p class="meta">Die Seiten werden aus den JSON-Regeldateien unter '
        '<code>aci/rules/</code> erzeugt und spiegeln den ausgelieferten '
        'Regelstand wider.</p></section>'
        f'<section><h2>Regelsätze</h2><div class="cards">{cards}</div>'
        '</section>')
    pages["index.html"] = page("ACI &ndash; Regeldokumentation",
                               "Übersicht aller Prüfregeln", index_body)

    for name, content in pages.items():
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"geschrieben: docs/rules/{name}")


if __name__ == "__main__":
    main()
