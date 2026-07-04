# -*- coding: utf-8 -*-
"""Prototyp v2: SQLI-Bestimmung via positions-sensitivem Taint-Quellen-Modell.

Quellen, die ACI 2.6.0 noch nicht als Taint kennt:
  param  -> Routine-Parameter (extern kontrollierte Eingabe)
  table  -> SELECT/FETCH ... INTO (aus DB-Tabelle gelesen -> 2nd-order)
Positions-sensitiv: nur Schreibzugriffe VOR der Ausfuehrung zaehlen.
"""
import re, sys, glob
sys.path.insert(0, "/sessions/youthful-ecstatic-clarke/mnt/ACI")
from aci.lexer import lex
from aci.parser import parse_expression
from aci.ir import IRConcat, IRCall

CORPUS = "/sessions/youthful-ecstatic-clarke/mnt/26ai.unwrapped"
HDR = re.compile(r'\b(PROCEDURE|FUNCTION)\s+("?[A-Za-z_][\w$#]*"?)\s*(\(|\bIS\b|\bAS\b|\bRETURN\b)', re.I)
INTO = re.compile(r'\b(?:SELECT|FETCH)\b.*?\bINTO\b(?P<t>.*?)(?:\bFROM\b|\bUSING\b|;)', re.I | re.S)
SANI = re.compile(r'(dbms_assert|quote_ident|quote_literal)', re.I)
IDENT = re.compile(r'^"?[A-Za-z_][\w$#]*"?$')
RANK = {"literal": 0, "sanitized": 1, "unknown": 2, "table": 3, "param": 4}


def routine_spans(masked):
    hits = [(m.start(), m.group(2).strip('"').upper()) for m in HDR.finditer(masked)]
    return [(o, hits[i + 1][0] if i + 1 < len(hits) else len(masked), n)
            for i, (o, n) in enumerate(hits)]


def header_params(masked, hdr_start):
    op = masked.find('(', hdr_start)
    isat = re.search(r'\b(IS|AS|RETURN)\b', masked[hdr_start:hdr_start + 200], re.I)
    if op == -1 or (isat and hdr_start + isat.start() < op):
        return set()
    depth, i, n, bs, parts = 0, op, len(masked), op + 1, []
    while i < n:
        c = masked[i]
        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                parts.append(masked[bs:i]); break
        elif c == ',' and depth == 1:
            parts.append(masked[bs:i]); bs = i + 1
        i += 1
    out = set()
    for p in parts:
        m = re.match(r'\s*("?[A-Za-z_][\w$#]*"?)', p)
        if m:
            out.add(m.group(1).strip('"').upper())
    return out


def into_targets(masked, a, b):
    out = []
    for m in INTO.finditer(masked[a:b]):
        for tok in m.group('t').split(','):
            mm = re.search(r'([A-Za-z_][\w$#]*)', tok)
            if mm:
                out.append((a + m.start(), mm.group(1).upper()))
    return out


def leaves(node, acc):
    if isinstance(node, IRConcat):
        for p in node.parts:
            leaves(p, acc)
    elif isinstance(node, IRCall):
        fn = node.function_name
        if SANI.search(fn):
            acc.append(("sanitized", fn))
        elif fn.lower().split('.')[-1] == "concat":
            for arg in node.arguments:
                leaves(arg, acc)
        else:
            acc.append(("call", fn))          # opake Funktion
    else:
        acc.append((node.kind, node.text))


def classify(expr, params, into, assigns, exec_off, seen=None, depth=0):
    if seen is None:
        seen = set()
    if depth > 4:
        return "unknown"
    acc = []
    leaves(parse_expression(expr), acc)
    verdict = "literal"

    def worse(a, b):
        return a if RANK[a] >= RANK[b] else b

    for kind, text in acc:
        if kind == "literal":
            cand = "literal"
        elif kind == "sanitized":
            cand = "sanitized"
        elif kind == "identifier" and IDENT.match(text):
            cand = resolve(text.strip('"').upper(), params, into, assigns,
                           exec_off, seen, depth)
        else:
            cand = "unknown"
        verdict = worse(verdict, cand)
    return verdict


def resolve(name, params, into, assigns, exec_off, seen, depth):
    if name in seen:
        return "unknown"
    seen = seen | {name}
    writes = []
    if name in params:
        writes.append("param")
    for off, nm in into:
        if nm == name and off < exec_off:
            writes.append("table")
    rhs = [a for a in assigns
           if a.target.upper() == name and a.target_start < exec_off]
    if not writes and not rhs:
        return "unknown"
    best = "literal"
    for w in writes:
        if RANK[w] > RANK[best]:
            best = w
    for a in rhs:
        sub = classify(a.expression, params, into, assigns, exec_off,
                       seen, depth + 1)
        if RANK[sub] > RANK[best]:
            best = sub
    return best


def run():
    from collections import Counter
    tally = Counter()
    shape = Counter()          # (verdict, bare|concat)
    ex = {"param": [], "table": []}
    for path in sorted(glob.glob(CORPUS + "/*.plb")):
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        lr = lex(text, "oracle")
        masked, code = lr.code_masked, lr.code_no_comments
        spans = routine_spans(masked)
        for dyn in lr.dynamic_sql:
            rt = next(((s, e, n) for s, e, n in spans if s <= dyn.trigger_start < e), None)
            if not rt:
                tally["no-routine"] += 1
                continue
            s, e, nm = rt
            params = header_params(masked, s)
            into = into_targets(masked, s, e)
            assigns = [a for a in lr.assignments if s <= a.target_start < e]
            expr = code[dyn.expr_start:dyn.expr_end].strip()
            mc = re.search(r'\b(USING|INTO|BULK\s+COLLECT)\b', expr, re.I)
            if mc:
                expr = expr[:mc.start()].strip()
            if not expr:
                continue
            v = classify(expr, params, into, assigns, dyn.trigger_start)
            tally[v] += 1
            bare = bool(IDENT.match(expr))
            shape[(v, "bare" if bare else "concat")] += 1
            if v in ex and len(ex[v]) < 7:
                ln = text[:dyn.trigger_start].count("\n") + 1
                ex[v].append((path.split("/")[-1], ln, nm,
                              "bare" if bare else "concat", expr[:85]))
    print("=== Prototyp v2 - Taint-Quelle aller dynamischen SQL-Stellen ===")
    tot = sum(v for k, v in tally.items())
    for k, n in tally.most_common():
        print(f"  {k:11s} {n:6d}  ({100*n/tot:.1f}%)")
    print("\n=== param/table aufgeschluesselt nach Ausdrucksform ===")
    for (v, sh), n in sorted(shape.items()):
        if v in ("param", "table"):
            print(f"  {v:7s} {sh:6s} {n}")
    for cat in ("param", "table"):
        print(f"\n--- Beispiele '{cat}' ---")
        for fn, ln, nm, sh, e in ex[cat]:
            print(f"  {fn}:{ln} {nm}() [{sh}]  EXECUTE IMMEDIATE {e}")


run()
