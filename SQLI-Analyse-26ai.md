# SQL-Injection-Erkennung — Analyse am Korpus `26ai.unwrapped`

Test: Wie lassen sich SQL-Injection-Findings genauer bestimmen, insbesondere
für (1) dynamisches SQL aus einem ungeprüften Routine-Parameter und
(2) 2nd-order-Injection aus einem ungeprüft weiterverwendeten Tabellenwert.

## Testkorpus

689 entwrappte Oracle-PL/SQL-Package-Bodies (interne Pakete von Oracle 26ai,
`DBMS_*`, `CTX_*`/`DR0*` u.a.), rund 39 MB. Darin **10.768 dynamische
SQL-Ausführungsstellen** (`EXECUTE IMMEDIATE`, `OPEN ... FOR`, `DBMS_SQL.PARSE`,
PL/pgSQL-`EXECUTE`). Getestet wurde gegen ACI 2.6.0.

## Befund 1 — ACI erkennt die inneren Package-Routinen nicht

Die Dateien beginnen mit `PACKAGE BODY <name> AS` — **ohne** `CREATE`. ACIs
Routinenerkennung (`_ROUTINE_RE` im Lexer) verlangt aber ein führendes
`CREATE`. Folge: In den 408 reinen Package-Bodies erkennt ACI **null**
Routinen; die **23.066** inneren `PROCEDURE`/`FUNCTION`-Definitionen sind für
das Routinenmodell unsichtbar.

Damit kollabiert die positions- und routinesensitive Analyse (`routine_at`,
`assignments_before`) auf **dateiweite** Betrachtung. Eine `:=`-Zuweisung an
eine Variable `STMT` in Prozedur A wird für ein `EXECUTE IMMEDIATE STMT` in
Prozedur B mitberücksichtigt — Cross-Routine-Leck. In diesem Korpus fällt das
kaum als Fehlalarm auf, weil ACI im Zweifel „tainted" annimmt und damit oft
zufällig auf *Critical* landet; auf normalem Anwendungscode erzeugt dasselbe
Leck aber sowohl falsch-positive als auch falsch-negative Findings.

## Befund 2 — ACI modelliert keine Taint-Quellen

ACI 2.6.0 verfolgt nur `ziel := ausdruck`-Zuweisungen. Es unterscheidet nicht:

* einen **Routine-Parameter** (extern, vom Aufrufer kontrolliert) von
* einer **lokalen Variable ohne sichtbare Zuweisung** und kennt
* `SELECT/FETCH ... INTO` (aus einer Tabelle gelesener Wert) **gar nicht** als
  Wertquelle.

Für eine Variable ohne `:=`-Zuweisung meldet ACI pauschal
`UNKNOWN_DYNAMIC` → **High** mit dem Text „Herkunft statisch nicht
nachvollziehbar". Genau diese beiden vom Auftrag gewünschten Muster fallen so
durch das Raster bzw. werden zu schwach eingestuft.

## Prototyp — positions-sensitives Taint-Quellen-Modell

Der Prototyp (`sqli_taint_prototype.py`) setzt auf ACIs Lexer- und
Expression-IR-Schicht auf und ergänzt genau das Fehlende:

* **Package-innere Routinen** werden über die `PROCEDURE`/`FUNCTION`-Köpfe
  erkannt (auch ohne `CREATE`), inklusive ihrer **Parameterlisten**.
* **`SELECT/FETCH ... INTO`-Ziele** werden je Routine als Taint-Quelle erfasst.
* Jede dynamische SQL-Stelle wird positions-sensitiv (nur Schreibzugriffe
  *vor* der Ausführung) auf ihre schärfste Quelle zurückverfolgt:
  `param` > `table` > `unknown` > `sanitized` > `literal`.

Ergebnis über alle 10.768 Stellen:

| Quelle (Prototyp) | Stellen | Anteil |
|---|---:|---:|
| `param` — leitet sich aus einem Routine-Parameter ab | 881 | 8,2 % |
| `table` — 2nd-order, leitet sich aus `SELECT/FETCH INTO` ab | 81 | 0,8 % |
| `sanitized` — variable Teile über `DBMS_ASSERT`/`quote_*` | 1.359 | 12,6 % |
| `literal` — nur String-Literale | 3.600 | 33,4 % |
| `unknown` — nicht zurückverfolgbar | 4.847 | 45,0 % |

Die `param`-Fälle zerfallen in 673 „bare" (`EXECUTE IMMEDIATE <Parameter>`
direkt) und 208 „concat"; die `table`-Fälle in 72 „bare" und 9 „concat".

## Gegenüberstellung ACI 2.6.0 ↔ Prototyp

Kreuztabelle über eine Stichprobe von **7.844** Stellen (ACI-Severity je
Stelle gegen die Prototyp-Quelle):

| Prototyp-Quelle | ACI Critical | ACI High | ACI Warning | ACI keine |
|---|---:|---:|---:|---:|
| `param` (651) | 587 | 41 | 23 | 0 |
| `table` (48) | 48 | 0 | 0 | 0 |
| `sanitized` (1.115) | 473 | 16 | 626 | 0 |
| `unknown` (3.563) | 2.789 | 540 | 131 | 103 |
| `literal` (2.467) | 639 | 3 | 1.561 | 264 |

Interpretation:

* ACI stuft die meisten `param`-/`table`-Stellen bereits *Critical* ein — aber
  überwiegend **aus dem falschen Grund**: durch das Cross-Routine-Leck greift
  es irgendeine `:=`-Zuweisung im selben File auf und über die Default-Annahme
  „unbekannt = tainted". Das Ergebnis stimmt hier zufällig, die Begründung
  nicht — und die Begründung im Report lautet generisch „ungeprüfte Werte"
  statt „stammt aus Parameter X" bzw. „2nd-order aus Tabelle".
* Die **41 `param`/`bare`-Stellen mit nur *High*** sind der saubere Treffer:
  ein Routine-Parameter wird unmittelbar als dynamisches SQL ausgeführt, und
  ACI sagt nur „Herkunft nicht nachvollziehbar". Fachlich ist das eine
  klassische, eindeutige Injection (*Critical*).
* `sanitized`: 473 über `DBMS_ASSERT` o.ä. abgesicherte Stellen meldet ACI als
  *Critical* — Kandidaten für **Fehlalarme**, ebenfalls eine Folge des
  Cross-Routine-Lecks.

## Verifizierte Beispiele

**Muster 1 — ungeprüfter Parameter** (`dbmssearch.plb`, Zeile 1862):

```sql
PROCEDURE GET_MESSAGE_LIST(SQL_STMT IN     VARCHAR2,
                           RID      IN     ROWID,
                           MSG_LIST    OUT MESSAGE_LIST)
IS
  PRAGMA AUTONOMOUS_TRANSACTION;
BEGIN
  EXECUTE IMMEDIATE SQL_STMT
    BULK COLLECT INTO MSG_LIST USING RID;
```

`SQL_STMT` ist ein `IN VARCHAR2`-Parameter und wird unverändert als
dynamisches SQL ausgeführt. ACI 2.6.0 meldet:

> **HIGH** — „EXECUTE IMMEDIATE führt dynamisches SQL aus, dessen Herkunft
> statisch nicht nachvollziehbar ist — Variable 'SQL_STMT' ohne
> nachvollziehbare Zuweisung."

Korrekt wäre **Critical** mit der Begründung „dynamisches SQL ist der
ungeprüfte Routine-Parameter `SQL_STMT`". Genau das liefert der Prototyp.

**Muster 2 — 2nd-order über einen Tabellenwert** (`owmcddlb.plb`,
`CREATESKELETONTABLE`):

```sql
SELECT NEXT_EXTENT INTO SQL_STRING
FROM   SYS.ALL_TABLES
WHERE  OWNER = TAB_OWNER AND TABLE_NAME = TAB_NAME || '_LT';
...
SQL_STRING := 'declare ... execute immediate ''alter table '
           || TAB_OWNER || '.' || TAB_NAME || SKELETON_TB_EXT
           || ' storage(next ' || SQL_STRING || ')'' ; ...';
EXECUTE IMMEDIATE SQL_STRING;
```

Der aus `SYS.ALL_TABLES` gelesene Wert (`NEXT_EXTENT`) fließt über `SQL_STRING`
in dynamisches SQL ein — ohne eigene Prüfung. ACI kennt `SELECT ... INTO`
nicht als Wertquelle und kann diese Stelle nicht als 2nd-order kennzeichnen;
der Prototyp markiert sie als `table`.

## Empfehlung — so lassen sich SQLI-Findings besser bestimmen

> **Status: umgesetzt.** Die Punkte A–C wurden in ACI implementiert
> (`aci/parser.py`, `aci/ir.py`, `aci/checks.py`; Tests in
> `tests/test_sqli_taint_sources.py`; siehe PROMPTS.MD Abschnitt 10).

In dieser Reihenfolge umsetzen:

**A. Package-innere Routinen erkennen.** Die Routinenerkennung muss
`PROCEDURE`/`FUNCTION` auch ohne `CREATE` innerhalb von `PACKAGE BODY` (und
`TYPE BODY`) erfassen, mit korrekten Grenzen. Das ist die Grundlage — ohne
echte Routinengrenzen bleibt jede positions-/routinesensitive Analyse auf
Package-Code unsolide.

**B. Taint-Quellen explizit modellieren.** Die IR-Schicht sollte je Routine
führen: die **Parameter** (`IN`/`IN OUT`) und die **`SELECT/FETCH INTO`-Ziele**.
Eine Variable ohne `:=`-Zuweisung ist dann nicht mehr pauschal „unknown":

* ist sie ein Parameter → 1st-order-Taint (vom Aufrufer kontrolliert),
* ist sie ein `SELECT/FETCH INTO`-Ziel → 2nd-order-Taint (aus der DB gelesen),
* sonst → weiterhin „unknown".

**C. Findings typisieren.** Statt nur `TAINTED_CONCAT`/`UNKNOWN_DYNAMIC` sollte
ein Finding ausweisen, *woher* der Taint stammt: „ungeprüfter Parameter
`X`" bzw. „2nd-order: Wert aus Tabelle". Das macht Findings priorisierbar und
erklärt sie nachvollziehbar.

Erwarteter Effekt: die 41 sauber verfehlten Parameter-Direktausführungen
werden korrekt *Critical*; die rund 590 bereits als *Critical* gemeldeten
Parameter-/Tabellen-Stellen erhalten eine **belastbare** Begründung statt
einer zufällig richtigen; das Cross-Routine-Leck (potenzielle Fehlalarme,
u.a. bei den 473 `sanitized`-aber-*Critical*-Stellen) entfällt; und 1st- vs.
2nd-order-Injection werden unterscheidbar — genau die zwei Kategorien aus dem
Auftrag.

## Grenzen

Der Prototyp ist heuristisch: Routinengrenzen werden sequenziell geschnitten
(verschachtelte lokale Routinen werden vereinfacht), „Validierung" eines
Parameters via `IF`-Prüfung wird nicht erkannt (nur `DBMS_ASSERT`-artige
Sanitizer), und die Taint-Verfolgung durch `:=`-Ketten ist tiefenbegrenzt.
Für die Größenordnung und die Richtung der Verbesserung sind die Zahlen
aussagekräftig; exakte Einzelbefunde gehören gegengeprüft.

Reproduktion: `python3 sqli_taint_prototype.py` (erwartet das Korpus unter
`../26ai.unwrapped`).
