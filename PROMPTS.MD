# PROMPTS.MD

Diese Datei dokumentiert alle Prompts und Anweisungen, die der Entwicklung
von **ACI (Automated Code Inspection)** zugrunde liegen. Sie dient der
Nachvollziehbarkeit der Anforderungen.

Projekt: **ACI** &mdash; Sitzungen ab 2026-05-22 (zuletzt aktualisiert 2026-05-24)

---

## 1. Projektanweisung

Dauerhaft für das Projekt "ACI" hinterlegte Anweisung:

> Es soll ein Programm erstellt werden, welches ein übergebenen Oracle
> oder PostgreSQL Code auf Sicherheitslücken überprüft.

---

## 2. Hauptanforderung

> ACI (Automated Code Inspection) soll übergebenen Oracle Code auf
> Sicherheitslücken überprüfen.
>
> Es soll verschiedene Finding Levels geben.
>
> - Warning
> - High
> - Critical
>
> Es sollen verschiedene Checks implementiert werden.
>
> 1. Verstoß Namenskonventionen (z.B. Verwendung reservierte Worte)
>    ==> Warnung
> 2. Verstoß gegen unerwünschte Packages (z.B. dbms_crypto,
>    dbms_obfuscation_toolkit, ...)
> 3. Verschlüsselter / Obfuscated Code (gewrappter Code, verschlüsselter
>    Code, obfuscated Code, verschleierter Code (base64))
> 4. SQL Injection (execute immediate mit Concatenation)
> 5. DDL im Code (z.B. grant, create, ...)
>
> Die Regeln sollen in externen Dateien gepflegt werden können.

---

## 3. Klärungsfragen und Antworten

Vor Umsetzungsbeginn wurden folgende Punkte abgestimmt:

| Frage | Antwort |
|-------|---------|
| In welcher Sprache soll ACI implementiert werden? | **Python** |
| In welchem Format sollen die externen Regeldateien gepflegt werden? | **JSON** |
| Wie soll das Ergebnis (Findings) ausgegeben werden? | **HTML-Report, JSON-Report, Konsole (Text)** |
| Welchen Umfang soll die erste Version abdecken? | **Oracle + PostgreSQL** |

---

## 4. Folgeanweisung

> Dokumentation von ACI bitte in HTML.
> Dokumentiere alle prompts in der PROMPTS.MD

Umsetzung:

- Die Dokumentation wurde als HTML-Datei erstellt:
  `docs/ACI_Dokumentation.html`.
- Alle Prompts werden in dieser Datei (`PROMPTS.MD`) dokumentiert.

---

## 5. Abgeleitete Umsetzung (Zusammenfassung)

Aus den obigen Prompts ergab sich folgender Funktionsumfang:

- **Sprache:** Python 3 (nur Standardbibliothek, keine Abhängigkeiten).
- **Finding-Levels:** Warning, High, Critical.
- **Fünf Checks:**
  1. `ACI-NAME` &mdash; Namenskonventionen / reservierte Worte (Warning).
  2. `ACI-PKG`  &mdash; unerwünschte Packages (Level je Eintrag).
  3. `ACI-OBF`  &mdash; verschlüsselter / obfuskierter Code
     (Wrapped, CHR-Ketten, Base64/Hex, Dekodieraufrufe).
  4. `ACI-SQLI` &mdash; SQL Injection (dynamisches SQL mit Konkatenation).
  5. `ACI-DDL`  &mdash; DDL im Code (GRANT, CREATE, ALTER, DROP, ...).
- **Dialekte:** Oracle und PostgreSQL, je eigene Regeldatei.
- **Externe Regeln:** JSON-Dateien unter `rules/`
  (`oracle.json`, `postgresql.json`).
- **Ausgabeformate:** Konsole (farbig), JSON, HTML.
- **Dokumentation:** `docs/ACI_Dokumentation.html`.

---

## 6. Folgeanweisung — echte Umlaute

> Verwende in den Reports richtige Umlaute ü,ö,ä,ß anstatt ue,oe,ae,ss

Umsetzung: Die ASCII-Umschrift wurde projektweit durch echte Umlaute
ersetzt — wortgenau, sodass korrekte ss-Wörter (muss, Klasse, …)
unverändert bleiben.

---

## 7. Folgeanweisung — Trivadis Coding Guidelines

> Wie würdest Du die plsql coding guidelines mit einbauen. Bitte noch
> nicht einbauen, erst mit mir besprechen. Z.b. in neuen Gruppen
>
> https://github.com/trivadis/plsql-and-sql-coding-guidelines

Nach Abstimmung wurden folgende Entscheidungen getroffen:

| Frage | Antwort |
|-------|---------|
| Schweregrade der Guidelines | **Eigene Skala je Gruppe** — Sicherheit: Warning/High/Critical; Coding Guidelines: Info/Minor/Major/Critical/Blocker |
| Organisation der Regeldateien | **Eine JSON-Datei je Trivadis-Kategorie** (`rules/guidelines/oracle/`) |
| Umfang der ersten Stufe | **Heuristik-taugliche Teilmenge** (~35 aktive Regeln; tiefe Regeln dokumentiert als `needs-parser`) |
| Gruppen-Granularität | **Eine Gruppe „Coding Guidelines"** neben „Sicherheit" |
| Vorgehen | **Komplett in einem Rutsch** umsetzen |

Umsetzung (ACI 2.0.0):

- Neues `Severity`-Modell mit zwei Skalen und gruppenübergreifendem Gewicht.
- Zwei Prüfgruppen: „Sicherheit" und „Coding Guidelines".
- `GuidelineCheck` mit regex- und builtin-Detektoren.
- Zehn Kategoriedateien unter `rules/guidelines/oracle/` (~35 aktive,
  ~82 dokumentierte Regeln), basierend auf den Trivadis PL/SQL & SQL
  Coding Guidelines v4.4 (Apache-2.0).
- CLI-Option `--group` (all/security/guidelines); `--fail-on`/`--min-level`
  auf die kombinierte Skala erweitert.
- Reporter (Konsole, JSON, HTML) stellen beide Gruppen getrennt dar.
- Coding Guidelines gelten nur für Oracle; PostgreSQL behält die Gruppe
  Sicherheit.

---

## 8. Folgeanweisung — MITRE-ATT&CK-Angriffserkennung

> Analysiere die Oracle MITRE Dokumente, ob und welche Analysen man für
> Angriffe in den Scanner einbauen könnte

Analyse: Die 15 Oracle-MITRE-ATT&CK-Dokumente sind überwiegend
laufzeit-/SOC-orientiert. Für einen statischen Scanner relevant ist die
Teilmenge der Techniken, die Spuren im übergebenen Quelltext hinterlässt.

Nach Abstimmung getroffene Entscheidungen:

| Frage | Antwort |
|-------|---------|
| Umsetzung | **Komplett umsetzen** |
| Einordnung | **In der Gruppe „Sicherheit"** (kein eigener dritter Bereich) |

Umsetzung:

- Neue Check-Klasse `MitreCheck` (auf Basis der bestehenden
  Detektor-Engine), Findings in der Gruppe „Sicherheit".
- 11 Taktik-Regeldateien unter `rules/mitre/oracle/` mit 34 code-erkennbaren
  Angriffsindikatoren, jeweils mit MITRE-Taktik/-Technik und Verweis auf
  attack.mitre.org.
- Abgedeckt: Execution, Persistence, Privilege Escalation, Defense
  Evasion, Credential Access, Lateral Movement, Exfiltration, Command &
  Control, Impact, Defense Impairment, Resource Development.
- Die Indikatoren ergänzen die fünf Checks gezielt (keine Doppel-Findings);
  laufzeitbezogene Techniken bleiben den SOC-Regeln des MITRE-Leitfadens
  vorbehalten.
- CLI-Option `--mitre-dir`; `--list-checks` zeigt die MITRE-Abdeckung.
- Beispieldatei `samples/mitre_oracle.sql`.

---

## 9. Folgeanweisung — Parser-/IR-Schicht (ACI 2.4.0–2.6.0)

> Zwischen Lexer und Checks soll eine leichtgewichtige Parser-/Intermediate-
> Representation-Schicht (IR) eingeführt werden. Ziel ist kein vollständiger
> SQL-Compiler, sondern eine stabile, strukturierte Sicht auf Routinen,
> Statements, Zuweisungen und dynamische SQL-Ausführungen, über die
> insbesondere `DdlCheck` und `SqlInjectionCheck` einheitlich auf
> Datenflussfragen zugreifen. Bestehende Funktionalität, CLI, Reportformate
> und Finding-IDs müssen erhalten bleiben.

Umsetzung (eingeführt mit ACI 2.4.0, erweitert bis 2.6.0):

- Neues Modul `aci/ir.py` mit unveränderlichen Datenklassen: `SourceLocation`,
  `SourceRange`, `IRStatement`, `IRRoutine`, `IRAssignment`,
  `IRDynamicSqlExecution`, `IRParseError` und `IRSource`.
- Neues Modul `aci/parser.py` mit `parse_ir()` — lexergestützt, baut die
  `IRSource` aus dem Lexer-Ergebnis auf und sammelt Fehler in
  `IRSource.errors`, statt einen Scan abzubrechen.
- Zentrale, positions-/routinesensitive Helfer (`routine_for_offset()`,
  `assignments_before()`, `nearest_assignment_before()`,
  `dynamic_sql_executions()`) — eine gemeinsame Wahrheit für Positions- und
  Routine-Sensitivität.
- `Source` stellt die IR als `source.ir` bereit; `parse_ir` und die
  IR-Modelle werden zusätzlich aus dem Paket `aci` exportiert.
- ACI 2.6.0 ergänzt eine flache **Ausdrucks-IR** (`IRExpression`, `IRCall`,
  `IRConcat` — Literale, Bindevariablen, Funktionsaufrufe inkl.
  PostgreSQL-`format()`, `||`-Konkatenation) sowie erste
  **Kontrollfluss-Blöcke** (`IRControlBlock` für IF/ELSE/LOOP/…) als
  Grundlage künftiger, konservativer Analysen.
- Neue CLI-Option `--dump-ir` gibt die IR (über `ir_to_dict()`) als JSON aus
  — interne Debug-/Testbarkeit ohne Einfluss auf das normale Reporting.
- Tests: `tests/test_ir_parser.py` deckt IR-Aufbau, Helfer, Ausdrucks-IR und
  `--dump-ir` ab.

ACI 2.6.0 enthält darüber hinaus zwei nicht-IR-Erweiterungen: PostgreSQL-
Rollen-/Systemrechte-Verwaltung (`GRANT`/`REVOKE`) in Deployment-Skripten
wird als kritisch gewertet, und für die PostgreSQL-MITRE-Regeln gibt es ein
Rule-Test-Harness (`tests/rules/postgresql/mitre/cases.json` mit
`tests/test_postgresql_mitre_rule_harness.py`).

---

## 10. Folgeanweisung — Taint-Quellen für die SQL-Injection-Erkennung

> Die SQL-Injection-Findings sollen genauer bestimmt werden. Ausgehend von
> der Analyse am Korpus `26ai.unwrapped` (siehe `SQLI-Analyse-26ai.md`)
> sollen drei Punkte umgesetzt werden: (A) die Routinenerkennung muss
> `PROCEDURE`/`FUNCTION` auch ohne `CREATE` innerhalb von Package-Bodys
> erfassen; (B) die IR soll Taint-Quellen modellieren - Routine-Parameter
> sowie `SELECT/FETCH ... INTO`-Ziele; (C) Findings sollen typisiert werden
> in 1st-order (ungeprüfter Parameter) und 2nd-order (Wert aus einer
> Tabelle/einem Cursor).

Umsetzung:

- **(A)** `parse_ir` erkennt zusätzlich Package-interne PROCEDURE/FUNCTION-
  Definitionen (ohne `CREATE`). `IRRoutine` führt die Parameterliste im
  neuen Feld `parameters`. Damit wird die routine-lokale Analyse auch in
  reinen Package-Bodys korrekt (kein Cross-Routine-Leck mehr).
- **(B)** `IRAssignment` erhält ein `kind`-Feld; `SELECT/FETCH ... INTO`
  wird als Schreibzugriff (`select_into`/`fetch_into`) in `ir.assignments`
  geführt. Routine-Parameter werden im `SqlInjectionCheck` als impliziter
  Schreibzugriff am Routinenkopf modelliert.
- **(C)** Der `SqlInjectionCheck` verfolgt Variablen positionssensitiv über
  diese Taint-Quellen. `DynamicSqlAssessment.source` typisiert das Finding
  als `parameter` (1st-order) bzw. `table` (2nd-order); die Meldung weist
  dies aus. Ein direkt ausgeführter ungeprüfter Parameter wird damit
  korrekt *Critical* (zuvor *High* „Herkunft nicht nachvollziehbar").
- Tests: `tests/test_sqli_taint_sources.py`.

---

## 11. Folgeanweisung — ACI 2.7.1 (Python-Mindestversion, SELECT…INTO)

> ACI 2.7.1: 1. Python-Mindestversion korrigieren. 2. SELECT…INTO genauer
> modellieren. 3. FETCH…INTO konservativ als 2nd-order behalten.
> 4. Versionshistorie-Dokumentation korrigieren. 5. Tests ergänzen.

Umsetzung (ACI 2.7.1):

- Python-Mindestversion auf **3.8** festgelegt und echte 3.8-/3.9-
  Kompatibilität mit realen Interpretern verifiziert (der Kunde betreibt
  Red Hat Enterprise Linux 8 mit Python 3.9). `pyproject.toml`,
  Klassifizierer und CI-Matrix entsprechend gesetzt.
- `SELECT … INTO` trägt seine Quellexpression in der IR; der
  `SqlInjectionCheck` unterscheidet ein Konstanten-Literal (kein Risiko),
  einen sanitizer-geschützten Wert (abgesichert) und eine Tabellenspalte
  (2nd-order, *Critical*).
- `FETCH … INTO` bleibt konservativ immer 2nd-order, da die Cursor-Quelle
  statisch nicht bestimmbar ist.
- Versionshistorie in `docs/ACI_Dokumentation.html` korrigiert.
- Tests ergänzt.

---

## 12. Folgeanweisung — ACI 2.8.0 (Routine-Grenzen, interprozedurale Politik)

> ACI 2.8.0: 1. Genauere PL/SQL-Routine-Grenzen über `END <name>;`.
> 2. SELECT-INTO-Expression-IR ausbauen. 3. Interprozedurale Grenzen
> bewusst definieren und dokumentieren. 4. Optional: py310-only Cleanup.
> 5. Optional: ruff/mypy/build verpflichtend in CI.

Umsetzung (ACI 2.8.0):

- Package-interne Routine-Grenzen werden über das abschließende
  `END <name>;` bestimmt; verschachtelte lokale Unterprogramme werden
  korrekt umschlossen, innerer Code dem innersten Programm zugeordnet.
- Die `SELECT … INTO`-Quellklassifikation nutzt die Ausdrucks-IR,
  inklusive konkatenierter Quellen (eine nur aus Literalen gebildete
  Konkatenation bleibt unkritisch).
- Die routine-lokale Datenflussanalyse ist als bewusste, **dokumentierte
  konservative Cross-Routine-Politik** festgeschrieben: ein Parameter gilt
  als aufrufergesteuert (1st-order), eine routine-intern nie geschriebene
  Variable als „unbekannte Herkunft", das Ergebnis eines Aufrufs anderer
  Routinen sowie anderswo geschriebene Package-Variablen als tainted.
  Punkt 4 wurde verworfen — die echte 3.8-Kompatibilität bleibt erhalten.
- `ruff`, `mypy` und der sdist-Build sind verpflichtende CI-Schritte
  (`mypy` mit `python_version = 3.9`, Laufzeit-Minimum weiterhin 3.8).

---

## 13. Folgeanweisungen — Lizenz, Regelpflege und False-Positive-Bereinigung

Mehrere Anweisungen zur laufenden Regelpflege (alle in 2.8.0 eingeflossen,
ohne Versionssprung):

- > Das ACI-Projekt läuft unter der MIT-Lizenz. Bitte hinzufügen.

  MIT-`LICENSE` ergänzt und in `pyproject.toml`/README referenziert.

- > Entferne `COMMENT ON COLUMN` und `COMMENT ON TABLE` von der Liste der
  > Findings.

  `COMMENT` aus den DDL-Schlüsselworten beider Dialekte entfernt.

- > Harmlose REVOKEs sollen auch stillgelegt werden.

  `harmless_object_privileges` (SELECT/READ/INSERT/UPDATE/DELETE auf
  Objekten) gilt jetzt auch für eigenständige `REVOKE`-Anweisungen.

- Kuratierte Listen harmloser Package-Member (`ignore_members`) wurden
  erweitert — u.a. für UTL_HTTP-, DBMS_LOB-, OWA_UTIL- und DBMS_SQL-Typen
  und -Hilfsroutinen, sodass reine Typ-/Close-/Free-Verwendungen kein
  Finding mehr erzeugen.

- **False Positive:** `GRANT` innerhalb von PostgreSQL-`COPY … FROM STDIN`-
  Datenblöcken. Der Lexer maskiert COPY-Datenzeilen; ein echter `GRANT`
  nach dem Datenblock wird weiterhin gemeldet.

- > Welche DDL wie `CREATE TABLE`/`CREATE VIEW` sind in PostgreSQL erlaubt;
  > füge `CREATE SCHEMA` hinzu.

  `CREATE SCHEMA` in die PostgreSQL-Allowlist `allowed_statements`
  aufgenommen.

- **False Positive:** `CREATE INDEX [CONCURRENTLY] ON tab (...)` — das
  Schlüsselwort `ON` (bzw. ein zurückgesetztes `CONCURRENTLY`) wird nicht
  mehr als reserviertes Wort im Objektnamen gemeldet; ein gequoteter
  `"on"`-Bezeichner bleibt ein Finding.

- **False Positive:** lange Hex-/Base64-Blöcke in `INSERT … VALUES`-
  Datenzeilen (z.B. PostGIS-WKB-Geometrie, serialisierte BLOBs) gelten als
  Daten, nicht als verschleierter Code, und erzeugen kein
  Obfuskations-Finding mehr (`skip_in_insert`).

---

## 14. Folgeanweisung — neue Regel „Dateisystem-Zugriff mit copy"

> Hier passiert mit dem copy Befehl ein Dateisystem-Zugriff. Dies sollte
> als Regel „Dateisystem-Zugriff mit copy" auftauchen.
>
> (… die `\copy`-Regel als **High** einstufen.)

Umsetzung:

- Neue PostgreSQL-MITRE-Regel `ACI-PG-COPY-CLIENT-FILE` „Dateisystem-
  Zugriff mit copy" (Taktik *TA0009 Collection*). Sie erkennt die
  psql-Meta-Anweisung `\copy`, die clientseitig auf das Dateisystem des
  psql-Aufrufers zugreift — als Ergänzung zu den serverseitigen
  `COPY … FROM/TO '/pfad'`-Regeln.
- Schweregrad **High**.
- Positiv-/Negativ-Fall im PostgreSQL-MITRE-Test-Harness ergänzt.

---

## 15. Folgeanweisung — Code-Beispiele in der Regeldokumentation

> Die ACI-Regeldokumentation soll verbessert werden. Zu jeder Regel soll es
> neben Name, Schweregrad, Beschreibung und Empfehlung nun auch
> Beispiel-Code (PL/SQL bzw. PL/pgSQL) geben — je ein die Regel auslösendes
> und ein sicheres/konformes Gegenbeispiel. Anschließend dauerhaft im
> Generator verankern.

Umsetzung:

- Zu jeder aktiven Regel der sechs Regelsätze (Oracle/PostgreSQL ×
  Sicherheit / MITRE / Coding Guidelines) wurde ein Beispielpaar ergänzt:
  ein die Regel auslösendes Beispiel („Verwundbar" bzw. bei Coding
  Guidelines „Verstoß") und ein sicheres/konformes Gegenbeispiel.
  Insgesamt 201 Beispielpaare.
- Die Beispiele liegen als reine Dokumentationsdaten in
  `docs/rule_examples.json` und werden vom Regeldokumentations-Generator
  `docs/generate_rule_docs.py` in die HTML-Seiten unter `docs/rules/`
  eingespielt — ein erneuter Lauf des Generators reproduziert sie.

---

## 16. Folgeanweisung — SQL-Injection-Ausgabe: Taint-Quelle anzeigen

> Optimierung der SQL-Injection-Ausgabe (Oracle): Wird ein zusammengebauter
> String per `EXECUTE IMMEDIATE` ausgeführt, sollen statt der Zeilen rund um
> das `EXECUTE` die Zuweisung(en) des Strings gezeigt werden. Stammt der
> String aus einem Prozedur-/Funktionsparameter, soll die Definition der
> Prozedur/Funktion gezeigt werden. Anschließend: die Anzeige als Option
> in `aci.ini` und auf der Kommandozeile, standardmäßig aktiviert.

Umsetzung:

- Neues Datenmodell `RelatedLocation`; ein Finding kann zusätzliche,
  beschriftete Fundstellen tragen. Der `SqlInjectionCheck` hängt bei
  Variablen-Ausführung alle aufbauenden Zuweisungen und bei einem
  ungeprüften Parameter den Routinenkopf als Taint-Quelle an; der Kontext
  am Sink (EXECUTE) wird dabei auf eine Zeile reduziert.
- Die Quellen erscheinen in allen Reportformaten (Konsole, HTML, JSON
  `related`, SARIF `relatedLocations`).
- Neue Option `taint_sources` (Standard `true`) in `aci.ini` sowie die
  CLI-Schalter `--taint-sources` / `--no-taint-sources`.

---

## 17. Folgeanweisung — DDL-Kontext bei Anweisungsketten

> Stehen mehrere gleichartige DDL-Anweisungen (z.B. eine Reihe `DROP TYPE`)
> untereinander, soll im Kontext jeweils nur die betroffene Zeile gezeigt
> werden — die anderen erscheinen ohnehin als eigene Findings.

Umsetzung: Der `DdlCheck` reduziert den Kontext eines Findings auf die
betroffene Zeile, sobald das Kontextfenster die Fundzeile eines anderen
DDL-Findings derselben Datei enthält; isolierte DDL-Anweisungen behalten
den vollen Kontext.

---

## 18. Folgeanweisung — CI/CD-Gate, Einschränkungen und Architekturbilder

> In die HTML-Dokumentation aufnehmen: einen empfohlenen CI/CD-Gate (mit
> `--fail-on high` als audit-relevanter Schwelle), die kritischen
> ACI-Einschränkungen am Anfang der Doku sowie zwei Architekturbilder
> (Aufbau ACI, Integration in eine CI/CD-Pipeline).

Umsetzung in `docs/ACI_Dokumentation.html`:

- Abschnitt 11 um einen empfohlenen CI/CD-Gate-Aufruf (PostgreSQL/Oracle)
  samt Schalter-Erläuterung und Audit-Hinweis zu `--fail-on high` ergänzt.
- Neuer hervorgehobener Abschnitt „Kritische Einschränkungen" ganz am
  Anfang der Dokumentation (heuristischer Scanner, False Positives/
  Negatives, Regeldateien als Trust Boundary u.a.).
- Zwei Inline-SVG-Architekturbilder: die Analyse-Pipeline (Abschnitt 3)
  und ACI als blockierender Gate in einer CI/CD-Pipeline (Abschnitt 11).

---

## 19. Folgeanweisung — ACI 2.9.0: erweiterte Regelabdeckung

> Eine Regel-Bewertung benannte rund zwei Dutzend fehlende Regeln. Alle
> davon umsetzen und die Version auf 2.9.0 anheben.

Umsetzung (ACI 2.9.0):

- **Oracle:** neue MITRE-Indikatoren für `ADMINISTER KEY MANAGEMENT`,
  `CREATE CREDENTIAL`, Erstellung von Datenbank-Links, `DBMS_CLOUD`-Export,
  `DBMS_XSLPROCESSOR.CLOB2FILE`, `NOLOGGING`, `TRUNCATE`/`DROP` von
  Audit-Tabellen und das Absenken sicherheitskritischer
  `ALTER SYSTEM`-Parameter; zusätzliche unerwünschte Pakete
  `DBMS_DATAPUMP`, `DBMS_CREDENTIAL`, `DBMS_RLS`, `DBMS_REDACT`, `DBMS_FGA`.
- **PostgreSQL:** `SECURITY DEFINER` ohne festen `search_path` bzw. mit
  dynamischem `EXECUTE` jetzt auch als Security-Findings; Abschalten von
  Row Level Security, RLS-Policy-Änderungen, Trigger-Deaktivierung,
  `GRANT ... WITH GRANT/ADMIN OPTION`, `LOAD` einer Shared Library,
  `ALTER SYSTEM RESET`, Objekte in Systemschemata. Predefined-Rollen- und
  Risky-Extension-Listen erweitert; EPAS-Oracle-Kompatibilitätspakete
  (`UTL_HTTP`, `UTL_FILE`, `DBMS_SCHEDULER`, `DBMS_CRYPTO` u.a.) ergänzt.
- 9 neue PostgreSQL-MITRE-Regeln mit Positiv-/Negativ-Fällen im
  Test-Harness; Version auf 2.9.0 angehoben.
