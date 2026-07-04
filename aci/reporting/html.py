"""HTML-Report - eigenständige, teilbare HTML-Seite."""

from __future__ import annotations

import html

from .._version import __version__
from ..finding import Severity, GROUP_SCALES, GROUP_GUIDELINES
from .report import ScanReport
from ._common import _thousands


def _sev_class(severity: Severity) -> str:
    return severity.name.lower()


def _cfg_val(value) -> str:
    """Bereitet einen Konfigurationswert für die Anzeige auf."""
    if isinstance(value, bool):
        return "ja" if value else "nein"
    text = str(value)
    return text if text != "" else "—"


def _ctx_pre(context, snippet, esc) -> str:
    """Rendert einen Codeausschnitt als ``<pre>``.

    Liegt ``context`` (Zeilen mit Nummern) vor, wird die Fundzeile
    hervorgehoben; sonst dient ``snippet`` als einzeilige Notlösung.
    """
    if not context:
        return (f'<pre class="snippet">{esc(snippet)}</pre>'
                if snippet else "")
    rows = []
    for lineno, text, is_find in context:
        cls = "ctxline finding-line" if is_find else "ctxline"
        rows.append(f'<span class="{cls}"><span class="ctxno">{lineno}'
                    f'</span>{esc(text) or "&nbsp;"}</span>')
    return '<pre class="snippet ctx">' + "".join(rows) + '</pre>'


def _context_html(finding, esc) -> str:
    """Codeausschnitt mit Kontext vor/nach der Fundstelle (dem Sink)."""
    return _ctx_pre(finding.context, finding.snippet, esc)


def _related_html(finding, esc) -> str:
    """Zusätzliche Fundstellen (Taint-Quellen) eines Findings.

    Jede Stelle erhält eine Beschriftung und einen eigenen
    Codeausschnitt - z.B. die Zuweisung(en), die einen dynamischen
    SQL-String aufbauen, bzw. der Prozedur-/Funktionskopf.
    """
    if not finding.related:
        return ""
    blocks = []
    for rel in finding.related:
        ctx = _ctx_pre(rel.context, rel.snippet, esc)
        blocks.append(
            f'<div class="related"><div class="rellabel">'
            f'{esc(rel.label)} &mdash; Zeile {rel.line}</div>{ctx}</div>')
    return "".join(blocks)


def _sections_by_file(report: ScanReport, group: str):
    """Findings einer Gruppe nach Datei gebündelt: ``[(pfad, [findings])]``.

    Dateien ohne Findings der Gruppe entfallen.
    """
    out = []
    for path, findings in sorted(report.results.items()):
        group_findings = [f for f in findings if f.group == group]
        if group_findings:
            out.append((path, group_findings))
    return out


def _sections_by_rule(report: ScanReport, group: str):
    """Findings einer Gruppe nach Regel gebündelt:
    ``[((check_id, check_name), [findings])]``.

    Die Abschnitte sind nach höchstem Schweregrad und dann nach Regel-ID
    sortiert; die Findings innerhalb einer Regel nach Datei und Zeile.
    """
    buckets: dict = {}
    for path, findings in sorted(report.results.items()):
        for f in findings:
            if f.group != group:
                continue
            buckets.setdefault((f.check_id, f.check_name), []).append(f)
    sections = []
    for key, findings in buckets.items():
        findings.sort(key=lambda f: (f.file, f.line, f.column))
        sections.append((key, findings))
    sections.sort(key=lambda kv: (
        -max(f.severity.weight for f in kv[1]), kv[0][0]))
    return sections


def _group_sections(report: ScanReport, group: str, group_by: str):
    """Liefert die Findings-Abschnitte gemäß der gewählten Gruppierung."""
    if group_by == "file":
        return _sections_by_file(report, group)
    return _sections_by_rule(report, group)


def _finding_row_html(f, esc, anchors, group_by: str) -> str:
    """Eine Tabellenzeile für ein Finding.

    Bei Gruppierung nach Regel zeigt die zweite Spalte den Dateipfad
    der Fundstelle, bei Gruppierung nach Datei die Regel. Gewaiverte
    Findings werden gekennzeichnet und gedämpft dargestellt.
    """
    cls = _sev_class(f.severity)
    snippet = _context_html(f, esc)
    related = _related_html(f, esc)
    rec = (f'<div class="rec"><strong>Empfehlung:</strong> '
           f'{esc(f.recommendation)}</div>' if f.recommendation else "")
    link = (f'<div class="lnk"><a href="{esc(f.url)}" '
            f'target="_blank" rel="noopener">{esc(f.url)}</a></div>'
            if f.url else "")
    # Gewaiverte Findings: Hinweisbox mit Ticket/Owner/Ablauf/Begründung.
    waiver_html = ""
    row_cls = f"row-{cls}"
    badge = f'<span class="badge {cls}">{esc(f.severity.label)}</span>'
    if f.waiver is not None:
        w = f.waiver
        row_cls += " waived"
        badge += ' <span class="wtag">waived</span>'
        waiver_html = (
            f'<div class="waiver"><span class="wbadge">Waived</span>'
            f'<strong>Ticket {esc(w.ticket)}</strong> &middot; '
            f'Owner {esc(w.owner)} &middot; gültig bis '
            f'{esc(w.expires_str)}'
            f'<div class="wreason">{esc(w.reason)}</div></div>')
    fp_html = (f'<div class="fp">Fingerprint: <code>{esc(f.fingerprint)}'
               f'</code></div>' if f.fingerprint else "")
    if group_by == "rule":
        second = f'<td class="file">{esc(f.file)}</td>'
    else:
        second = (f'<td class="check">{esc(f.check_id)}<br>'
                  f'<span class="checkname">{esc(f.check_name)}</span></td>')
    return (
        f'<tr id="{anchors.get(id(f), "")}" class="{row_cls}">'
        f'<td>{badge}</td>'
        f'{second}'
        f'<td class="loc">{f.line}:{f.column}</td>'
        f'<td class="desc">{esc(f.message)}{waiver_html}{snippet}'
        f'{related}{rec}{link}{fp_html}</td>'
        f'</tr>')


def _render_group_html(report: ScanReport, group: str, esc, anchors,
                       group_by: str) -> str:
    parts: list[str] = []
    counts = report.counts_for_group(group)
    scale = GROUP_SCALES[group]

    parts.append(f'<h2 class="group">{esc(group)}'
                 f'<span class="gtotal">{report.total_in_group(group)} '
                 f'Finding(s)</span></h2>')
    # Kennzahlen-Karten je Schweregrad der Gruppe
    parts.append('<div class="cards">')
    for sev in scale:
        cls = _sev_class(sev)
        parts.append(
            f'<div class="card {cls}"><div class="num">{counts.get(sev, 0)}'
            f'</div><div class="lbl">{esc(sev.label)}</div></div>')
    parts.append('</div>')

    sections = _group_sections(report, group, group_by)
    if not sections:
        parts.append('<p class="ok">Keine Findings in dieser Gruppe.</p>')
        return "\n".join(parts)

    for label, findings in sections:
        if group_by == "rule":
            cid, cname = label
            parts.append(
                f'<h3 class="rule">{esc(cid)} '
                f'<span class="checkname">{esc(cname)}</span>'
                f'<span class="filecount">{len(findings)} '
                f'Finding(s)</span></h3>')
            second_head = '<th class="file">Datei</th>'
        else:
            parts.append(f'<h3 class="file">{esc(label)} '
                         f'<span class="filecount">{len(findings)} '
                         f'Finding(s)</span></h3>')
            second_head = "<th>Regel</th>"
        parts.append('<table class="findings"><thead><tr><th>Schweregrad</th>'
                     f'{second_head}<th>Zeile</th><th>Beschreibung</th>'
                     '</tr></thead><tbody>')
        for f in findings:
            parts.append(_finding_row_html(f, esc, anchors, group_by))
        parts.append('</tbody></table>')
    return "\n".join(parts)


def _render_stats_table(report: ScanReport, group: str,
                        group_stats: dict, esc) -> str:
    """Eine Statistik-Tabelle fuer eine einzelne Pruefgruppe.

    Spalten: Schweregrad, Regel, Findings. Jede Zeile ist anklickbar
    (Sprung zum ersten Treffer der Regel) und zeigt per Mouse-Over einen
    Tooltip mit den Eckdaten.
    """
    parts = [
        '<section class="statistik">',
        f'<h2 class="group">Statistik &ndash; {esc(group)}'
        f'<span class="gtotal">{report.total_in_group(group)} '
        f'Finding(s)</span></h2>',
    ]
    if not group_stats:
        parts.append('<p class="ok">Keine Findings in dieser Gruppe.</p>'
                     '</section>')
        return "\n".join(parts)
    parts.append('<table class="findings"><thead><tr><th>Schweregrad</th>'
                 '<th>Regel</th><th>Findings</th></tr></thead><tbody>')
    rows = sorted(group_stats.items(),
                  key=lambda kv: (-kv[0][3].weight, -kv[1][0]))
    for (grp, cid, cname, sev), (count, anchor) in rows:
        cls = _sev_class(sev)
        tip = (f"Gruppe: {grp}  |  Regel: {cid} {cname}  |  "
               f"Schweregrad: {sev.label}  |  {count} Finding(s).  "
               f"Klicken, um zum ersten Treffer zu springen.")
        parts.append(
            f'<tr class="row-{cls} statrow" '
            f'onclick="location.hash=\'#{anchor}\'" title="{esc(tip)}">'
            f'<td><span class="badge {cls}">{esc(sev.label)}</span></td>'
            f'<td class="check">{esc(cid)} '
            f'<span class="checkname">{esc(cname)}</span></td>'
            f'<td class="statcount">{count}</td></tr>')
    parts.append('</tbody></table></section>')
    return "\n".join(parts)


def _render_stats_html(report: ScanReport, stats: dict, esc) -> str:
    """Je eine Statistik-Tabelle pro Pruefgruppe am Reportanfang.

    Es werden getrennte Statistiken erzeugt - eine fuer die Gruppe
    Sicherheit und eine fuer die Coding Guidelines.
    """
    blocks = []
    for group in report.groups():
        group_stats = {k: v for k, v in stats.items() if k[0] == group}
        blocks.append(_render_stats_table(report, group, group_stats, esc))
    return "\n".join(b for b in blocks if b)


def _render_integrity_html(report: ScanReport, esc) -> str:
    """Zeile zur Regelintegrität: Ruleset-Hash und Vertrauensstatus.

    Stammen alle Regeldateien aus dem ACI-Paket, ist die Zeile neutral;
    bei benutzerdefinierten Regelpfaden wird sie als Warnung
    hervorgehoben und nennt die betroffenen Dateien.
    """
    intg = report.integrity
    if intg is None:
        return ""
    if intg.trusted:
        status = ('<span class="trust-ok">vertrauenswürdig '
                  '(gebündelte Regeln)</span>')
        cls = "meta integrity"
    else:
        names = ", ".join(esc(f.name) for f in intg.untrusted_files)
        status = (f'<span class="trust-bad">{len(intg.untrusted_files)} '
                  f'Datei(en) aus benutzerdefiniertem Pfad (untrusted): '
                  f'{names}</span>')
        cls = "meta integrity untrusted"
    return (f'<div class="{cls}"><strong>Regelintegrität:</strong> '
            f'Ruleset-Hash <code>{esc(intg.ruleset_hash)}</code> '
            f'&nbsp;|&nbsp; {status}</div>')


def _render_waivers_html(report: ScanReport, esc) -> str:
    """Abschnitt für den Waiver-/Ausnahmeprozess.

    Liefert einen leeren String, wenn kein Waiver-Lauf stattfand (keine
    ``--waivers``-Datei). Sonst Kennzahlen-Karten und eine Tabelle aller
    Waiver mit ihrem Lebenszyklus-Status.
    """
    wr = report.waiver_report
    if wr is None or not wr.path:
        return ""
    parts = [
        '<section class="waivers">',
        '<h2 class="group">Waiver / Ausnahmen'
        f'<span class="gtotal">{wr.applied} Finding(s) gewaivert</span>'
        '</h2>',
        f'<p class="wmeta">Waiver-Datei: <code>{esc(wr.path)}</code> '
        '&ndash; gewaiverte Findings bleiben sichtbar, zählen aber nicht '
        'für <code>--fail-on</code>.</p>',
        '<div class="cards">',
    ]
    for num, lbl, kls in (
            (wr.applied, "Findings gewaivert", "info"),
            (len(wr.active), "Aktive Waiver", "info"),
            (len(wr.soon), "Läuft bald ab", "warning"),
            (len(wr.expired), "Abgelaufen", "high"),
            (len(wr.orphaned), "Verwaist", "minor"),
            (len(wr.errors), "Datei-Fehler", "critical")):
        parts.append(f'<div class="card {kls}"><div class="num">{num}</div>'
                     f'<div class="lbl">{esc(lbl)}</div></div>')
    parts.append('</div>')
    # soon ist eine Teilmenge von active - in der Tabelle nur einmal
    # zeigen (mit dem treffenderen Status "läuft bald ab").
    soon_ids = {id(w) for w in wr.soon}
    active_only = [w for w in wr.active if id(w) not in soon_ids]
    ordered = [("aktiv", active_only), ("läuft bald ab", wr.soon),
               ("abgelaufen", wr.expired), ("verwaist", wr.orphaned)]
    if any(lst for _s, lst in ordered):
        parts.append('<table class="findings"><thead><tr><th>Status</th>'
                     '<th>Ticket</th><th>Owner</th><th>Gültig bis</th>'
                     '<th>Treffer</th><th>Begründung</th></tr></thead>'
                     '<tbody>')
        for status, lst in ordered:
            for w in lst:
                scls = {"abgelaufen": "row-high",
                        "läuft bald ab": "row-major"}.get(status, "")
                parts.append(
                    f'<tr class="{scls}"><td>{esc(status)}</td>'
                    f'<td class="check">{esc(w.ticket)}</td>'
                    f'<td>{esc(w.owner)}</td>'
                    f'<td class="loc">{esc(w.expires_str)}</td>'
                    f'<td class="statcount">{w.match_count}</td>'
                    f'<td class="desc">{esc(w.reason)}'
                    f'<div class="fp">Fingerprint: <code>'
                    f'{esc(w.fingerprint)}</code></div></td></tr>')
        parts.append('</tbody></table>')
    if wr.errors:
        parts.append('<div class="werrors"><strong>Fehler in der '
                     'Waiver-Datei:</strong><ul>')
        for err in wr.errors:
            parts.append(f'<li>{esc(err)}</li>')
        parts.append('</ul></div>')
    parts.append('</section>')
    return "\n".join(parts)


# Stylesheet des HTML-Reports. Bewusst als eigenständige Konstante (kein
# f-string) gehalten: so entfällt die {{ }}-Maskierung jeder CSS-Klammer,
# und render_html bleibt auf die Seitenstruktur konzentriert.
_HTML_STYLE = """<style>
  :root {
    --blocker:#7f1d1d; --critical:#b91c1c; --high:#c2410c;
    --major:#b45309; --warning:#a16207; --minor:#0e7490; --info:#6b7280;
    --bg:#f4f5f7; --card:#ffffff; --ink:#1f2933; --muted:#6b7280;
    --border:#e3e6ea;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
    font-size:14px; line-height:1.5; }
  header { background:#111827; color:#fff; padding:28px 36px; }
  header h1 { margin:0 0 4px; font-size:22px; }
  header .sub { color:#9ca3af; font-size:13px; }
  main { max-width:1100px; margin:0 auto; padding:24px 36px 60px; }
  .meta { background:var(--card); border:1px solid var(--border);
    border-radius:10px; padding:14px 20px; margin-bottom:24px;
    color:var(--muted); font-size:13px; }
  .meta strong { color:var(--ink); }
  h2.group { font-size:17px; margin:30px 0 12px; padding:8px 14px;
    background:#111827; color:#fff; border-radius:8px; }
  h2.group .gtotal { float:right; font-weight:400; color:#9ca3af;
    font-size:13px; }
  h3.file { font-size:14px; margin:20px 0 8px; word-break:break-all; }
  h3.file .filecount { color:var(--muted); font-weight:400; font-size:12px; }
  .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:14px; }
  .card { background:var(--card); border:1px solid var(--border);
    border-radius:10px; padding:12px 18px; flex:1; min-width:110px; }
  .card .num { font-size:26px; font-weight:700; }
  .card .lbl { color:var(--muted); font-size:11px; text-transform:uppercase;
    letter-spacing:.05em; }
  .card.blocker .num { color:var(--blocker); }
  .card.critical .num { color:var(--critical); }
  .card.high .num { color:var(--high); }
  .card.major .num { color:var(--major); }
  .card.warning .num { color:var(--warning); }
  .card.minor .num { color:var(--minor); }
  .card.info .num { color:var(--info); }
  table.findings { width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--border); border-radius:10px; overflow:hidden; }
  table.findings th { text-align:left; background:#f9fafb; padding:9px 12px;
    font-size:11px; text-transform:uppercase; letter-spacing:.05em;
    color:var(--muted); border-bottom:1px solid var(--border); }
  table.findings td { padding:11px 12px; border-bottom:1px solid var(--border);
    vertical-align:top; }
  td.loc { font-family:ui-monospace,Menlo,monospace; white-space:nowrap;
    color:var(--muted); }
  td.check { white-space:nowrap; font-weight:600; }
  .checkname { font-weight:400; color:var(--muted); font-size:12px; }
  .badge { display:inline-block; padding:2px 9px; border-radius:999px;
    color:#fff; font-size:11px; font-weight:700; text-transform:uppercase; }
  .badge.blocker { background:var(--blocker); }
  .badge.critical { background:var(--critical); }
  .badge.high { background:var(--high); }
  .badge.major { background:var(--major); }
  .badge.warning { background:var(--warning); }
  .badge.minor { background:var(--minor); }
  .badge.info { background:var(--info); }
  .row-blocker,.row-critical { background:#fef2f2; }
  .row-high,.row-major { background:#fff7ed; }
  .statrow { cursor:pointer; }
  .statrow:hover { background:#eef2f7; }
  td.statcount { text-align:right; font-weight:700;
    font-family:ui-monospace,Menlo,monospace; }
  td.statgroup { white-space:nowrap; font-size:12px; color:var(--muted); }
  .scanparams { margin-top:-12px; }
  .scancmd { margin-top:-12px; }
  .scancmd code { background:#0f172a; color:#e5e7eb; padding:6px 10px;
    border-radius:6px; display:inline-block; max-width:100%;
    overflow-wrap:anywhere; font-size:12.5px; }
  .cfg-changed { color:var(--high); font-weight:600; }
  h3.rule { font-size:14px; margin:22px 0 8px; }
  h3.rule .filecount, h3.file .filecount { color:var(--muted);
    font-weight:400; font-size:12px; margin-left:8px; }
  /* Datei-Spalte: mindestens 32 Zeichen breit, damit lange Pfade nicht
     unnoetig umgebrochen werden. ``min-width: 32ch`` greift sowohl auf
     dem Kopf (th.file) als auch auf der Zelle (td.file); nur bei noch
     laengeren Pfaden bricht der Text ueberhaupt um (overflow-wrap:
     anywhere), und dann nicht mehr mitten im Wort. */
  th.file, td.file { min-width:32ch; }
  td.file { font-family:ui-monospace,Menlo,monospace; font-size:12px;
    color:var(--muted); overflow-wrap:anywhere; word-break:normal; }
  pre.snippet.ctx { padding:6px 0; }
  .ctxline { display:block; padding:1px 12px; }
  .ctxline.finding-line { background:#42342a;
    border-left:3px solid #f59e0b; padding-left:9px; }
  .ctxno { display:inline-block; min-width:3.4em; margin-right:14px;
    color:#7c8794; text-align:right; user-select:none; }
  table.findings tr:target { outline:3px solid #2563eb;
    outline-offset:-3px; }
  table.findings tr:target td { background:#eff6ff; }
  pre.snippet { background:#1f2933; color:#e5e7eb; padding:8px 10px;
    border-radius:6px; margin:8px 0 4px; overflow-x:auto; font-size:12px;
    font-family:ui-monospace,Menlo,monospace; }
  .related { margin:6px 0 2px; }
  .rellabel { font-size:11.5px; font-weight:700; color:#92400e;
    margin:8px 0 2px; }
  .rellabel::before { content:"\\21AA  "; }
  .rec { color:#374151; font-size:13px; margin-top:4px; }
  .lnk { font-size:12px; margin-top:4px; }
  .lnk a { color:#2563eb; }
  .ok { background:#ecfdf5; border:1px solid #a7f3d0; color:#065f46;
    padding:14px 18px; border-radius:10px; }
  footer { max-width:1100px; margin:0 auto; padding:0 36px 40px;
    color:var(--muted); font-size:12px; }
  .waiver { background:#eef2ff; border:1px solid #c7d2fe;
    border-radius:6px; padding:6px 10px; margin:8px 0 4px;
    font-size:12.5px; color:#3730a3; }
  .wbadge { display:inline-block; background:#4f46e5; color:#fff;
    border-radius:999px; padding:1px 8px; font-size:10px; font-weight:700;
    text-transform:uppercase; margin-right:6px; }
  .wreason { color:#4338ca; margin-top:3px; }
  .wtag { display:inline-block; background:#e0e7ff; color:#3730a3;
    border-radius:999px; padding:1px 7px; font-size:9px; font-weight:700;
    text-transform:uppercase; vertical-align:middle; }
  tr.waived { opacity:.7; }
  .fp { font-size:11px; color:var(--muted); margin-top:6px;
    font-family:ui-monospace,Menlo,monospace; }
  .fp code { background:#eef0f3; padding:1px 5px; border-radius:4px; }
  .wmeta { color:var(--muted); font-size:12.5px; margin:2px 0 14px; }
  .wmeta code { background:#eef0f3; padding:1px 5px; border-radius:4px;
    font-size:11.5px; }
  .werrors { background:#fef2f2; border:1px solid #fecaca; color:#991b1b;
    border-radius:8px; padding:10px 16px; margin-top:14px; font-size:13px; }
  .werrors ul { margin:6px 0 0; padding-left:20px; }
  .integrity { margin-top:-12px; }
  .integrity code { background:#eef0f3; padding:1px 5px; border-radius:4px;
    font-size:11px; word-break:break-all; }
  .integrity.untrusted { background:#fef2f2; border-color:#fecaca;
    color:#991b1b; }
  .integrity.untrusted strong { color:#991b1b; }
  .trust-ok { color:#15803d; font-weight:600; }
  .trust-bad { color:#b91c1c; font-weight:700; }
</style>"""


def _render_audit_html(report: ScanReport, esc) -> str:
    """Kompakte Gate-/Runtime-/Integritäts-Zeile (Audit/CI-Metadaten)."""
    gate, rv, rt = report.gate, report.ruleset_verification, report.runtime
    if not (gate or rv or rt):
        return ""
    parts = []
    if gate:
        passed = gate.get("passed")
        cls = "trust-ok" if passed else "trust-bad"
        parts.append(
            f'<strong>Gate:</strong> <span class="{cls}">'
            f'{"bestanden" if passed else "nicht bestanden"} '
            f'(Exit {esc(str(gate.get("exit_code")))})</span> '
            f'&middot; fail-on: {esc(str(gate.get("fail_on")))}'
            + (f' &middot; Profil: {esc(str(gate.get("profile")))}'
               if gate.get("profile") else ""))
    if rv and rv.get("expected_sha256"):
        ok = rv.get("verified")
        cls = "trust-ok" if ok else "trust-bad"
        parts.append(f'<span class="{cls}">Ruleset-Hash '
                     f'{"verifiziert" if ok else "NICHT verifiziert"}</span>')
    if rt:
        parts.append(f'ACI {esc(str(rt.get("aci_version")))} &middot; '
                     f'Python {esc(str(rt.get("python")))} &middot; '
                     f'{esc(str(rt.get("duration_ms")))} ms')
    return ('<div class="meta integrity"><strong>Audit:</strong> '
            + ' &nbsp;|&nbsp; '.join(parts) + '</div>')


def render_html(report: ScanReport) -> str:
    """Erzeugt den HTML-Report als eigenständige Seite."""
    esc = html.escape
    group_by = report.html_group_by
    # Anker je Finding vergeben und Statistik aufbauen - in derselben
    # Reihenfolge (Gruppierung), in der die Findings unten gerendert
    # werden.
    anchors: dict = {}
    stats: dict = {}
    counter = 0
    for g in report.groups():
        for _label, findings in _group_sections(report, g, group_by):
            for f in findings:
                counter += 1
                aid = f"f{counter}"
                anchors[id(f)] = aid
                key = (f.group, f.check_id, f.check_name, f.severity)
                if key not in stats:
                    stats[key] = [0, aid]
                stats[key][0] += 1
    stats_html = _render_stats_html(report, stats, esc)
    integrity_html = _render_integrity_html(report, esc)
    audit_html = _render_audit_html(report, esc)
    waivers_html = _render_waivers_html(report, esc)
    blocks = [_render_group_html(report, g, esc, anchors, group_by)
              for g in report.groups()]
    body = "\n".join(blocks)
    generated = report.created.strftime("%Y-%m-%d %H:%M:%S")
    cov = ""
    if GROUP_GUIDELINES in report.groups() and report.guideline_rules:
        active, documented = report.guideline_coverage()
        cov = (f' &nbsp;|&nbsp; <strong>Guidelines:</strong> {active} aktiv, '
               f'{documented} dokumentiert')

    # Scan-Parameter als Inline-Zeile (analog zu den Scan-Details). Je
    # Parameter Name und Wert; weicht der Wert vom Default ab, wird
    # dieser in Klammern ergänzt.
    params_html = ""
    if report.scanner_config:
        defaults = report.scanner_defaults or {}
        pieces = []
        for k, v in report.scanner_config.items():
            piece = f'<strong>{esc(str(k))}:</strong> {esc(_cfg_val(v))}'
            dv = defaults.get(k, "")
            if k in defaults and str(v) != str(dv):
                piece += (f' <span class="cfg-changed">(default: '
                          f'{esc(_cfg_val(dv))})</span>')
            pieces.append(piece)
        params_html = ('<div class="meta scanparams">'
                       '<strong>Scan-Parameter:</strong> '
                       + ' &nbsp;|&nbsp; '.join(pieces) + '</div>')

    # Scan-Aufruf: der originale Kommandozeilenaufruf (Programmname +
    # Argumente, shell-escaped). Dient der Audit-Reproduzierbarkeit -
    # "Womit wurde dieser Report erzeugt?". Wird nur angezeigt, wenn die
    # Kommandozeile bekannt ist (über die CLI gesetzt).
    cmdline_html = ""
    if report.command_line:
        cmdline_html = ('<div class="meta scancmd">'
                        '<strong>Scan-Aufruf:</strong> '
                        f'<code>{esc(report.command_line)}</code></div>')

    return f"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ACI Report - {esc(report.target)}</title>
{_HTML_STYLE}
</head>
<body>
<header>
  <h1>ACI &ndash; Automated Code Inspection</h1>
  <div class="sub">Sicherheits- und Coding-Guidelines-Analyse von
    {esc(report.ruleset.dialect.title())}-Code</div>
</header>
<main>
  <div class="meta">
    <strong>Scan-Details:</strong> &nbsp;
    <strong>Ziel:</strong> {esc(report.target)} &nbsp;|&nbsp;
    <strong>Dialekt:</strong> {esc(report.ruleset.dialect)} &nbsp;|&nbsp;
    <strong>Gruppen:</strong> {esc(', '.join(report.groups()))} &nbsp;|&nbsp;
    <strong>Dateien:</strong> {report.file_count()}
    ({report.files_with_findings()} mit Findings) &nbsp;|&nbsp;
    <strong>gescannte KB:</strong> {_thousands(report.scanned_kb())} KB
    &nbsp;|&nbsp;
    <strong>LOC:</strong> {_thousands(report.loc())} &nbsp;|&nbsp;
    <strong>Findings:</strong> {report.total()}{cov} &nbsp;|&nbsp;
    <strong>Erstellt:</strong> {generated} &nbsp;|&nbsp;
    <strong>Laufzeit:</strong> {esc(report.duration_str())} (mm:ss:hh)
  </div>
  {params_html}
  {cmdline_html}
  {integrity_html}
  {audit_html}
  {stats_html}
  {waivers_html}
  {body}
</main>
<footer>Erstellt mit ACI {esc(__version__)} &ndash; Automated Code Inspection.
Die Oracle-Coding-Guideline-Regeln basieren auf den Trivadis PL/SQL &amp; SQL
Coding Guidelines v4.4 (Apache-2.0); die PostgreSQL-Guidelines sind
ACI-eigene PL/pgSQL-Regeln.</footer>
</body>
</html>
"""
