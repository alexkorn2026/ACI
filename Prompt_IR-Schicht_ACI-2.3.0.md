# Claude-Prompt: Parser-/IR-Schicht für ACI 2.3.0 einführen

> Verschärfte Fassung — Basis-Prompt plus fünf ergänzende Zusatz-Abschnitte am
> Ende, die eine Schein-Implementierung ausschließen und die produktive Nutzung
> der IR verbindlich machen.

Du bist ein Senior Python Engineer, Security Tooling Architect, Static Analysis
Expert und Datenbank-Security-Reviewer mit tiefem Wissen in Oracle PL/SQL,
PostgreSQL PL/pgSQL, SQL-Parser-Design, SAST-Tools, CI/CD und
False-Positive-/False-Negative-Reduktion.

Arbeite am Projekt:

```text
ACI – Automated Code Inspection
Version: aci-2.3.0
```

ACI ist ein Python-basiertes Security- und Coding-Guidelines-Tool für Oracle
PL/SQL und PostgreSQL PL/pgSQL. Es analysiert SQL-Dateien und erzeugt Findings
in Console-, JSON-, HTML- und SARIF-Reports.

ACI 2.3.0 ist aktuell stabil:

```bash
python -m pytest -q
# Erwartung: ca. 395 Tests grün

python -m compileall -q aci tests
# Erwartung: erfolgreich

python -m aci --version
# Erwartung: ACI 2.3.0
```

Die Version enthält bereits:

* CLI mit Console/JSON/HTML/SARIF
* externe JSON-Regeln
* Oracle- und PostgreSQL-Regeln
* Oracle-CI/CD-Policy-Regeln:
  * `ALTER USER` = Critical
  * `GRANT` von Systemprivilegien = Critical
  * `GRANT` von Standardrollen = Critical
  * `REVOKE` von Systemprivilegien = Critical
  * `REVOKE` von Standardrollen = Critical
* PostgreSQL-Regeln, u. a. `COPY PROGRAM`, `GRANT ... TO PUBLIC`, erste
  MITRE-Abdeckung
* `aci/lexer.py` mit Erkennung von:
  * Kommentaren
  * Oracle-String-Literalen
  * Oracle `q'[...]'`-Strings
  * PostgreSQL-Dollar-Quotes
  * Statement-Grenzen
  * dynamischem SQL
  * Routinen
  * einfachen Zuweisungen
* dynamische DDL-Analyse ist positions- und routinesensitiv verbessert
* Testsuite ist im Source-Archiv lauffähig

Der nächste größere Qualitätssprung ist die Einführung einer Parser-/IR-Schicht.

## Hauptziel

Führe eine saubere, kleine und stabile
Parser-/Intermediate-Representation-Schicht ein, die zwischen Lexer und Checks
liegt.

Ziel ist nicht, sofort einen vollständigen SQL-/PLSQL-/PLpgSQL-Compiler zu
bauen.

Ziel ist:

1. vorhandene Lexer-Ergebnisse strukturiert in eine IR überführen,
2. Routinen, Statements, Assignments und Dynamic-SQL-Executions explizit
   modellieren,
3. bestehende Checks schrittweise auf IR umstellen,
4. False Positives reduzieren,
5. False Negatives verringern,
6. Codequalität und Wartbarkeit verbessern,
7. bestehende CLI-/Report-Kompatibilität erhalten.

## Wichtigste Randbedingungen

### 1. Keine Big-Bang-Umschreibung

Bitte nicht den bestehenden Scanner komplett ersetzen.

Stattdessen:

```text
source -> lexer -> IR parser -> existing checks + IR-aware checks -> findings -> reports
```

Die bestehende Funktionalität muss erhalten bleiben.

### 2. Fallback muss bleiben

Wenn die Parser-/IR-Schicht unsicher ist oder Fehler sammelt:

* Scan darf nicht abbrechen.
* bestehende heuristische Checks sollen weiterlaufen.
* Parserfehler sollen in der IR gesammelt werden.
* Nur bei bestehendem `--strict-internal-errors` darf ein harter Fehler erwogen
  werden.

### 3. Keine schwere Runtime-Abhängigkeit

ACI hat aktuell den Vorteil geringer Runtime-Komplexität. Bitte keine
ANTLR-/Java-/große Parser-Abhängigkeit einführen.

Bevorzugt:

* eigene kleine IR-Schicht auf Basis von `aci/lexer.py`
* keine neuen Runtime-Abhängigkeiten
* keine großen externen Parser

### 4. Bestehende Tests müssen grün bleiben

Vor Änderung ausführen:

```bash
python -m pytest -q
python -m compileall -q aci tests
```

Nach jeder größeren Änderung erneut prüfen.

### 5. Keine Finding-ID-Änderungen ohne Grund

Bestehende Finding IDs und Severity-Einstufungen dürfen nicht unnötig geändert
werden.

## Zielarchitektur

### Neue Module

Bitte führe neue Module ein, z. B.:

```text
aci/
  ir.py
  parser.py
```

Optional, falls besser strukturiert:

```text
aci/
  parser/
    __init__.py
    models.py
    build.py
    helpers.py
```

Wähle die Variante, die am besten in das bestehende Projekt passt. Wichtig ist:
übersichtlich, klein, testbar.

### IR-Datenmodell

Ergänze stabile, einfache Datenklassen.

SourceLocation

```python
@dataclass(frozen=True)
class SourceLocation:
    line: int
    column: int
    offset: int
```

SourceRange

```python
@dataclass(frozen=True)
class SourceRange:
    start: SourceLocation
    end: SourceLocation
```

IRStatement

```python
@dataclass(frozen=True)
class IRStatement:
    kind: str
    text: str
    range: SourceRange
    routine_name: str | None = None
    routine_kind: str | None = None
```

Mögliche `kind`-Werte:

```text
unknown
select
insert
update
delete
merge
create
alter
drop
grant
revoke
execute_immediate
execute
dbms_sql_parse
dbms_sys_sql_parse
open_for
assignment
block
routine_definition
```

Nicht alle müssen sofort perfekt sein. Beginne konservativ.

IRRoutine

```python
@dataclass(frozen=True)
class IRRoutine:
    dialect: str
    kind: str
    name: str | None
    range: SourceRange
    statements: tuple[IRStatement, ...]
```

Mögliche `kind`-Werte:

Oracle:

```text
anonymous_block
procedure
function
trigger
package
package_body
```

PostgreSQL:

```text
function
procedure
trigger_function
do_block
```

IRAssignment

```python
@dataclass(frozen=True)
class IRAssignment:
    target: str
    expression: str
    range: SourceRange
    routine_name: str | None = None
```

IRDynamicSqlExecution

```python
@dataclass(frozen=True)
class IRDynamicSqlExecution:
    dialect: str
    kind: str
    expression: str
    range: SourceRange
    routine_name: str | None = None
```

Mögliche `kind`-Werte:

Oracle:

```text
execute_immediate
dbms_sql_parse
dbms_sys_sql_parse
open_for
```

PostgreSQL:

```text
execute
return_query_execute
```

IRParseError

```python
@dataclass(frozen=True)
class IRParseError:
    message: str
    range: SourceRange | None = None
    recoverable: bool = True
```

IRSource

```python
@dataclass(frozen=True)
class IRSource:
    dialect: str
    text: str
    statements: tuple[IRStatement, ...]
    routines: tuple[IRRoutine, ...]
    assignments: tuple[IRAssignment, ...]
    dynamic_sql: tuple[IRDynamicSqlExecution, ...]
    errors: tuple[IRParseError, ...]
```

Optional kann `IRSource` zusätzlich Referenzen auf Lexer-Ergebnisse enthalten,
falls nützlich.

### Parser-Funktion

Ergänze eine zentrale Funktion:

```python
def parse_ir(source_text: str, dialect: str) -> IRSource:
    ...
```

Oder, falls die bestehende `SourceFile`-Struktur verwendet wird:

```python
def parse_ir(source: SourceFile) -> IRSource:
    ...
```

Die Funktion soll:

1. `aci/lexer.py` verwenden,
2. Tokens/Regionen/Statements aus dem Lexer in IR-Objekte überführen,
3. Fehler sammeln statt werfen,
4. Zeilen-/Spalten-/Offset-Informationen korrekt bereitstellen,
5. keine Findings erzeugen.

## Integration in Scanner und Checks

### Scanner

Prüfe die aktuelle Scanner-Architektur, vermutlich in:

```text
aci/scanner.py
aci/checks.py
aci/source.py
```

Integriere IR so, dass Checks sie optional nutzen können.

Beispielhafte Zielstruktur:

```python
source = load_source(...)
ir = parse_ir(source.text, dialect)

for check in checks:
    findings.extend(check.run(source, ir=ir))
```

Falls bestehende `run()`-Signaturen nicht ohne Weiteres angepasst werden können,
wähle eine minimal-invasive Lösung.

Beispiele:

```python
check.run(source)
```

bleibt gültig, aber neue Checks können:

```python
check.run(source, ir)
```

nutzen.

Oder:

```python
ScanContext(source=source, ir=ir, config=config)
```

Nur einführen, wenn es nicht zu groß wird.

### Wichtig

Bestehende Checks dürfen nicht alle auf einmal umgebaut werden.

Zunächst IR in folgenden Bereichen nutzen:

1. Dynamic SQL
2. Assignments
3. Routine-Grenzen
4. DDL-Erkennung
5. SQL-Injection-Klassifikation

## Erste IR-Nutzung: Dynamic SQL und Assignments zentralisieren

### Problem

ACI hat inzwischen Logik für:

* Dynamic SQL
* Assignments
* positionssensitive DDL
* SQL-Injection-Klassifikation

Diese Logik sollte nicht mehrfach verstreut sein.

### Aufgabe

Zentralisiere mindestens folgende Hilfsfunktionen auf IR-Basis:

```python
def routine_for_offset(ir: IRSource, offset: int) -> IRRoutine | None:
    ...
```

```python
def assignments_before(
    ir: IRSource,
    variable_name: str,
    offset: int,
    routine_name: str | None = None,
) -> tuple[IRAssignment, ...]:
    ...
```

```python
def nearest_assignment_before(
    ir: IRSource,
    variable_name: str,
    offset: int,
    routine_name: str | None = None,
) -> IRAssignment | None:
    ...
```

```python
def dynamic_sql_executions(ir: IRSource) -> tuple[IRDynamicSqlExecution, ...]:
    ...
```

Nutze diese Helper anschließend mindestens in:

* SQL-Injection-Check
* DDL-Check für dynamisches SQL

Ziel: Eine einzige zentrale Wahrheit für Positions- und Routine-Sensitivität.

## Funktionale Mindestanforderungen

### 1. Kommentare und Strings bleiben sicher behandelt

Die IR darf keine Statements aus Kommentaren oder harmlosen String-Literalen
erzeugen.

Nicht als Statement erkennen:

```sql
-- ALTER USER app IDENTIFIED BY secret;
```

```sql
SELECT 'GRANT DBA TO app_user' FROM dual;
```

Aber dynamisches SQL soll weiterhin analysierbar sein:

```sql
EXECUTE IMMEDIATE 'ALTER USER app ACCOUNT UNLOCK';
```

### 2. Oracle q-Quote bleibt korrekt

```sql
BEGIN
  EXECUTE IMMEDIATE q'[select * from users where name = 'O''Reilly']';
END;
/
```

Erwartung:

* eine Dynamic-SQL-Execution
* keine falsche Statement-Segmentierung

### 3. PostgreSQL-Dollar-Quotes bleiben korrekt

```sql
CREATE OR REPLACE FUNCTION f(p_table text)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
  v_sql text;
BEGIN
  v_sql := 'select * from ' || p_table;
  EXECUTE v_sql;
END;
$$;
```

Erwartung:

* eine Routine `f`
* eine Assignment-IR für `v_sql`
* eine Dynamic-SQL-Execution für `EXECUTE v_sql`

### 4. Statement-Grenzen bleiben korrekt

Semikolons in Strings oder Dollar-Quotes dürfen Statements nicht trennen.

```sql
SELECT 'hello; world' FROM dual;
```

```sql
RAISE NOTICE 'hello; world';
```

### 5. Routine-Grenzen sind korrekt genug

Mindestens erkennen:

Oracle:

```sql
CREATE OR REPLACE PROCEDURE p AS
BEGIN
  NULL;
END;
/
```

```sql
CREATE OR REPLACE FUNCTION f RETURN NUMBER AS
BEGIN
  RETURN 1;
END;
/
```

PostgreSQL:

```sql
CREATE OR REPLACE FUNCTION f()
RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  NULL;
END;
$$;
```

## Tests

Bitte ergänze gezielte Tests für die IR.

Neue Testdateien z. B.:

```text
tests/test_ir_parser.py
tests/test_ir_integration.py
```

Test 1: Oracle Routine wird erkannt

```python
def test_ir_detects_oracle_procedure():
    sql = """
    CREATE OR REPLACE PROCEDURE p AS
    BEGIN
      NULL;
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    assert len(ir.routines) == 1
    assert ir.routines[0].name.upper() == "P"
    assert ir.routines[0].kind == "procedure"
```

Test 2: Oracle Dynamic SQL wird erkannt

```python
def test_ir_detects_oracle_execute_immediate():
    sql = """
    BEGIN
      EXECUTE IMMEDIATE 'DROP USER x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    assert len(ir.dynamic_sql) == 1
    assert ir.dynamic_sql[0].kind == "execute_immediate"
```

Test 3: PostgreSQL Function wird erkannt

```python
def test_ir_detects_postgresql_function():
    sql = """
    CREATE OR REPLACE FUNCTION f()
    RETURNS void
    LANGUAGE plpgsql
    AS $$
    BEGIN
      NULL;
    END;
    $$;
    """
    ir = parse_ir(sql, dialect="postgresql")
    assert len(ir.routines) == 1
    assert ir.routines[0].name == "f"
    assert ir.routines[0].kind == "function"
```

Test 4: PostgreSQL Assignment und EXECUTE

```python
def test_ir_detects_postgresql_assignment_and_execute():
    sql = """
    CREATE OR REPLACE FUNCTION f(p_table text)
    RETURNS void
    LANGUAGE plpgsql
    AS $$
    DECLARE
      v_sql text;
    BEGIN
      v_sql := 'select * from ' || p_table;
      EXECUTE v_sql;
    END;
    $$;
    """
    ir = parse_ir(sql, dialect="postgresql")
    assert any(a.target.lower() == "v_sql" for a in ir.assignments)
    assert any(d.kind == "execute" for d in ir.dynamic_sql)
```

Test 5: Kommentare erzeugen keine IR-Statements für Admin-DDL

```python
def test_ir_ignores_admin_ddl_in_comments():
    sql = """
    -- ALTER USER app ACCOUNT UNLOCK;
    SELECT 1 FROM dual;
    """
    ir = parse_ir(sql, dialect="oracle")
    assert not any("ALTER USER" in s.text.upper() for s in ir.statements)
```

Test 6: Strings erzeugen keine IR-Statements für Admin-DDL

```python
def test_ir_ignores_admin_ddl_in_string_literals():
    sql = "SELECT 'GRANT DBA TO app_user' FROM dual;"
    ir = parse_ir(sql, dialect="oracle")
    assert not any(s.kind == "grant" for s in ir.statements)
```

Test 7: assignments_before ist positionssensitiv

```python
def test_ir_assignments_before_ignores_later_assignment():
    sql = """
    CREATE OR REPLACE PROCEDURE p AS
      l_sql varchar2(4000);
    BEGIN
      l_sql := 'select * from safe_table';
      EXECUTE IMMEDIATE l_sql;
      l_sql := 'drop table x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    exec_ = ir.dynamic_sql[0]
    assigns = assignments_before(ir, "l_sql", exec_.range.start.offset, exec_.routine_name)
    assert len(assigns) == 1
    assert "safe_table" in assigns[0].expression
```

Test 8: Routine-Grenzen werden beachtet

```python
def test_ir_assignments_before_respects_routine_boundaries():
    sql = """
    CREATE OR REPLACE PROCEDURE a AS
      l_sql varchar2(1000);
    BEGIN
      l_sql := 'select * from safe_table';
      EXECUTE IMMEDIATE l_sql;
    END;
    /

    CREATE OR REPLACE PROCEDURE b AS
      l_sql varchar2(1000);
    BEGIN
      l_sql := 'drop user x';
    END;
    /
    """
    ir = parse_ir(sql, dialect="oracle")
    exec_ = ir.dynamic_sql[0]
    assigns = assignments_before(ir, "l_sql", exec_.range.start.offset, exec_.routine_name)
    assert all("drop user" not in a.expression.lower() for a in assigns)
```

Test 9: Bestehende DDL-Check-Regression bleibt grün

Nutze vorhandene Tests für:

* spätere Zuweisung ignorieren
* andere Routine ignorieren
* vorherige gefährliche Zuweisung erkennen
* mehrere DDLs pro Zeile

Passe sie so an, dass sie über IR laufen, ohne Verhalten zu ändern.

## Migration bestehender Checks

Bitte migriere nicht alle Checks auf einmal.

Phase 1: IR nur zusätzlich erzeugen

* `parse_ir()` wird im Scanner erzeugt.
* Bestehende Checks laufen weiter wie bisher.
* Tests für IR bestehen.

Phase 2: DDL-Check nutzt IR-Helper

* dynamische DDL-Regionen nutzen `ir.dynamic_sql` und `assignments_before`.
* bestehende False-Positive-Fixes bleiben erhalten.

Phase 3: SQL-Injection-Check nutzt IR-Helper

* variable Klassifikation nutzt `assignments_before`.
* keine Regression bei Sanitizer-Erkennung.

Phase 4: Optionale weitere Checks

Nur falls einfach:

* Admin-DDL-Erkennung kann `ir.statements` nutzen.
* PostgreSQL `COPY PROGRAM` kann `ir.statements` nutzen.

## Kompatibilität

### CLI

Keine Breaking Changes an CLI.

Folgende Optionen müssen weiter funktionieren:

```text
--format console|json|html|sarif
--safe-report
--no-context
--redact-secrets
--fail-on
--min-level
--strict-internal-errors
--list-checks
```

### Reports

Keine Breaking Changes an JSON-/HTML-/SARIF-Struktur.

Optional dürfen additive Felder ergänzt werden, aber nicht erforderlich.

Falls Parserfehler sichtbar gemacht werden sollen, dann nur additiv und nicht
als hartes Fehlverhalten.

## Performance

Die IR-Schicht darf Scans nicht massiv verlangsamen.

Ergänze optional einen kleinen Test, der große synthetische SQL-Dateien scannt,
falls bestehende Performance-Tests vorhanden sind.

## Dokumentation

Ergänze im README eine kurze Architektursektion:

```markdown
## Analysis architecture

ACI uses a layered static analysis pipeline:

1. Source loading and size/exclusion checks
2. Lexical analysis and masking of comments/string literals
3. Parser/IR extraction for routines, statements, assignments and dynamic SQL
4. Rule checks
5. Reporting in console, JSON, HTML or SARIF

The IR layer is intentionally lightweight. It is not a full SQL compiler, but it reduces common false positives by preserving statement boundaries, routine boundaries and assignment order.
```

Wichtig: Keine falschen Garantien.

Ergänze auch klar:

```markdown
ACI is still a heuristic static analysis tool. Complex control flow, generated SQL and database-specific runtime behavior may require manual review.
```

## Akzeptanzkriterien

Die Aufgabe ist abgeschlossen, wenn:

1. neue IR-Datenmodelle existieren,
2. `parse_ir()` existiert,
3. IR erkennt mindestens:
   * Statements
   * Routinen
   * Assignments
   * Dynamic-SQL-Executions
4. IR ignoriert Kommentare und normale String-Literale korrekt,
5. Oracle `q'[...]'` bleibt korrekt,
6. PostgreSQL-Dollar-Quotes bleiben korrekt,
7. `assignments_before()` ist positionssensitiv,
8. `assignments_before()` beachtet Routine-Grenzen,
9. DDL-Check nutzt IR oder gemeinsame IR-Helper für dynamische SQL-Zuweisungen,
10. SQL-Injection-Check nutzt IR oder gemeinsame IR-Helper für variable
    Klassifikation,
11. bestehende 395 Tests bleiben grün,
12. neue IR-Tests sind vorhanden,
13. `python -m compileall -q aci tests` läuft grün,
14. CLI und Reports bleiben kompatibel,
15. README beschreibt die neue Analysepipeline ehrlich.

## Validierung am Ende

Bitte ausführen:

```bash
python -m pytest -q
python -m compileall -q aci tests
python -m aci --version
```

Falls verfügbar:

```bash
python -m ruff check .
python -m mypy aci
python -m build --sdist
```

Falls `build` verfügbar ist, zusätzlich sdist-Test:

```bash
tmpdir="$(mktemp -d)"
tar -xzf dist/*.tar.gz -C "$tmpdir"
cd "$tmpdir"/aci-*
python -m pip install -e ".[dev]"
python -m pytest -q
python -m compileall -q aci tests
```

## Erwartete Ergebniszusammenfassung von Claude

Bitte liefere am Ende:

```markdown
## Summary

Implemented:
- Added lightweight Parser/IR layer.
- Added IR models for source, routines, statements, assignments and dynamic SQL.
- Added parse_ir().
- Added IR helper functions for routine lookup and assignment lookup.
- Migrated dynamic DDL analysis to IR helpers.
- Migrated SQL injection variable classification to IR helpers.
- Added IR parser tests.
- Updated README architecture documentation.

Changed files:
- ...

Tests added:
- ...

Validation:
- python -m pytest -q: ...
- python -m compileall -q aci tests: ...
- python -m aci --version: ...
- ruff/mypy/build/sdist: ...

Compatibility:
- CLI unchanged.
- Report formats unchanged except optional additive metadata, if any.
- Existing finding IDs unchanged.

Remaining limitations:
- IR is lightweight, not a full SQL compiler.
- Complex control flow and runtime-generated SQL still require manual review.
```

## Wichtige Hinweise für die Umsetzung

Bitte arbeite mit höchster Vorsicht:

* Kleine Commits / kleine logische Schritte.
* Erst Modelle und Tests.
* Dann Parser.
* Dann Integration.
* Dann Migration einzelner Checks.
* Keine kosmetische Massenänderung.
* Keine neue Runtime-Abhängigkeit.
* Keine komplette Neufassung von `aci/lexer.py`, wenn nicht nötig.
* Keine Entfernung bestehender Fallback-Logik.
* Bei Unsicherheit konservativ bleiben und dokumentieren.

Das Ziel ist eine stabile, testbare Parser-/IR-Zwischenschicht, nicht ein
perfekter SQL-Compiler.

---

## Zusatz: Keine Schein-Implementierung akzeptieren

Die Parser-/IR-Schicht darf nicht nur ein dünner Wrapper sein, der bestehende
Lexer-Ergebnisse unverändert weiterreicht, ohne dass Checks davon profitieren.

Die Aufgabe gilt nicht als erfüllt, wenn:

* `parse_ir()` existiert, aber von keinem produktiven Check genutzt wird,
* `IRSource` nur befüllt wird, aber `DdlCheck` und `SqlInjectionCheck` weiterhin
  eigene unabhängige Assignment-/Dynamic-SQL-Logik verwenden,
* Routine-Grenzen nur in Tests, aber nicht in der produktiven Analyse
  berücksichtigt werden,
* spätere Assignments wieder DDL-/SQLI-Findings beeinflussen,
* Assignments aus anderen Routinen wieder berücksichtigt werden,
* Kommentare/String-Literale durch die IR erneut False Positives erzeugen.

Mindestens diese produktiven Pfade müssen IR-basiert oder über gemeinsame
IR-Helper laufen:

```text
DdlCheck dynamic SQL analysis
SqlInjectionCheck variable assignment classification
routine_for_offset()
assignments_before()
nearest_assignment_before()
dynamic_sql_executions()
```

## Zusatz: Harte Regressionstests aus ACI 2.3.0 beibehalten

Diese Fälle müssen weiterhin grün bleiben:

Spätere gefährliche Zuweisung darf kein dynamisches DDL-Finding erzeugen

```sql
CREATE OR REPLACE PROCEDURE p(p_table varchar2) AS
  l_sql varchar2(4000);
BEGIN
  l_sql := 'select * from safe_table';
  EXECUTE IMMEDIATE l_sql;
  l_sql := 'drop table ' || p_table;
END;
/
```

Erwartung:

```text
Kein dynamisches DROP-Finding aus der späteren Zuweisung.
```

Zuweisung aus anderer Routine darf nicht verwendet werden

```sql
CREATE OR REPLACE PROCEDURE a AS
  l_sql varchar2(1000);
BEGIN
  l_sql := 'select * from safe_table';
  EXECUTE IMMEDIATE l_sql;
END;
/

CREATE OR REPLACE PROCEDURE b(p_user varchar2) AS
  l_sql varchar2(1000);
BEGIN
  l_sql := 'DROP USER ' || p_user;
END;
/
```

Erwartung:

```text
Kein DROP-Finding für Routine a.
Kein DROP-Finding für Routine b, weil dort kein EXECUTE stattfindet.
```

Mehrere kritische Statements pro Zeile dürfen nicht dedupliziert werden

```sql
GRANT CONNECT TO a; GRANT DBA TO b;
REVOKE CONNECT FROM a; REVOKE DBA FROM b;
CREATE USER a IDENTIFIED BY x; CREATE DIRECTORY d AS '/tmp';
```

Erwartung:

```text
Jedes relevante Statement erzeugt ein eigenes Finding.
```

## Zusatz: IR muss nachvollziehbar debugbar sein

Bitte ergänze interne Debug-/Testbarkeit, ohne die CLI zu verkomplizieren.

Mindestens sollen Tests direkt prüfen können:

```python
ir = parse_ir(sql, dialect="oracle")
assert ir.routines
assert ir.statements
assert ir.assignments
assert ir.dynamic_sql
assert not ir.errors
```

Optional kann später eine CLI-Option ergänzt werden:

```text
--dump-ir
```

Aber nur, wenn das einfach und sauber möglich ist. Für diesen Auftrag ist
`--dump-ir` optional und nicht erforderlich.

## Zusatz: Keine neuen False Positives durch IR

Die IR darf bestehende Masking-/Lexer-Sicherheit nicht umgehen.

Diese Beispiele müssen weiterhin keine Admin-/DDL-Findings erzeugen:

```sql
-- ALTER USER app ACCOUNT UNLOCK;
```

```sql
/*
GRANT DBA TO app_user;
REVOKE CONNECT FROM app_user;
*/
```

```sql
SELECT 'ALTER USER app ACCOUNT UNLOCK' FROM dual;
```

```sql
SELECT 'GRANT DBA TO app_user' FROM dual;
```

Aber diese Beispiele müssen weiterhin Findings erzeugen:

```sql
EXECUTE IMMEDIATE 'ALTER USER app ACCOUNT UNLOCK';
```

```sql
EXECUTE IMMEDIATE 'GRANT DBA TO app_user';
```

## Zusatz: Ergebnis muss messbar sein

Bitte liefere am Ende zusätzlich eine kurze Tabelle:

```markdown
| Area | Before | After |
|---|---|---|
| Dynamic SQL assignments | scattered logic | IR helper based |
| Routine boundaries | heuristic/local | central IR helper |
| DDL dynamic SQL | custom logic | IR-backed |
| SQLI variable classification | custom logic | IR-backed |
| Tests | existing 395 | existing + new IR tests |
```
