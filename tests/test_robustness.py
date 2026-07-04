"""Robustheits-/Stresstests fuer den ACI-Lexer.

Die Testdaten werden im Test selbst erzeugt - es werden keine grossen
Dateien eingecheckt. Geprueft wird, dass der Scanner unguenstige, aber
realistische Eingaben korrekt und ohne Haenger verarbeitet.
"""

from aci.source import Source


def _src(code, dialect="oracle"):
    return Source(code, "stress.sql", dialect)


def test_many_comments():
    code = "\n".join(f"-- Kommentarzeile {i}" for i in range(5000))
    code += "\nSELECT 1 FROM dual;\n"
    s = _src(code)
    assert "Kommentarzeile" not in s.code_no_comments
    assert "SELECT 1" in s.code_no_comments


def test_many_string_literals():
    body = "\n".join(f"  v := 'literal {i}';" for i in range(5000))
    s = _src(f"BEGIN\n{body}\nEND;\n")
    assert len(s.string_spans) == 5000


def test_many_semicolons_inside_a_string():
    s = _src("v := '" + ";" * 20000 + "';\n")
    # Nur das abschliessende ; ausserhalb des Strings zaehlt.
    assert len(s.statements) == 1


def test_dollar_quote_with_many_semicolons():
    body = "  PERFORM 1;\n" * 3000
    s = _src(f"DO $$\nBEGIN\n{body}END;\n$$;\n", "postgresql")
    # Der DO-Block wird erkannt; der Funktionskoerper bleibt zusammen.
    assert any(r.kind == "do_block" for r in s.routines)


def test_long_line_with_many_suspicious_tokens():
    line = " || ".join("'x'" for _ in range(5000))
    s = _src(f"v := {line};\n")
    assert len(s.statements) == 1


def test_many_dynamic_sql_executions():
    body = "\n".join(
        f"  EXECUTE IMMEDIATE 'select {i}';" for i in range(2000))
    s = _src(f"BEGIN\n{body}\nEND;\n")
    assert len(s.dynamic_sql) == 2000


def test_deeply_concatenated_assignment():
    rhs = " || ".join(["'a'"] + [f"p{i}" for i in range(500)])
    s = _src(f"BEGIN\n  v := {rhs};\nEND;\n")
    assert s.assignments and s.assignments[0].target == "v"


def test_sql_injection_handles_many_chained_variables(oracle_rules):
    # Viele dynamische SQL-Stellen mit über mehrere Variablen
    # verketteten Werten - die Taint-Verfolgung muss das ohne Haenger
    # bewaeltigen (Memoisierung von _operand_kind/_split_concat sowie
    # der vorab indizierten Zuweisungen).
    from aci.checks import SqlInjectionCheck
    lines = ["DECLARE", "  p_in VARCHAR2(100);"]
    lines += [f"  l{i} VARCHAR2(4000);" for i in range(400)]
    lines.append("BEGIN")
    lines.append("  l0 := 'select * from t where c = ' || p_in;")
    for i in range(1, 400):
        lines.append(f"  l{i} := l{i - 1} || ' ' || l{i - 1};")
        lines.append(f"  EXECUTE IMMEDIATE l{i};")
    code = "\n".join(lines) + "\nEND;\n/\n"
    s = _src(code)
    findings = SqlInjectionCheck(
        oracle_rules.check("sql_injection"), "oracle").run(s)
    # Der ungeprüfte Input fliesst durch die Kette - wird als kritisch
    # erkannt, ohne dass die Analyse haengt.
    assert any(f.check_id == "ACI-SQLI" for f in findings)
