# ACI – Automated Code Inspection

ACI ist ein **heuristischer** statischer Sicherheits- und
Coding-Guidelines-Scanner für **Oracle PL/SQL** und **PostgreSQL
PL/pgSQL**. Er führt den Code nicht aus, sondern prüft ausschließlich
den übergebenen Quelltext.

ACI prüft in zwei Gruppen:

- **Sicherheit** – fünf Sicherheits-Checks (SQL-Injection, unerwünschte
  Packages, obfuskierter Code, DDL im Code, Namenskonventionen) sowie
  MITRE-ATT&CK-Angriffsindikatoren. Schweregrade: Warning, High, Critical.
- **Coding Guidelines** – für Oracle nach den *Trivadis PL/SQL & SQL
  Coding Guidelines*, für PostgreSQL ein eigener Satz an
  PL/pgSQL-Guidelines. Schweregrade: Info, Minor, Major, Critical,
  Blocker.

Die Regeln liegen in externen JSON-Dateien (`aci/rules/`) und sind ohne
Code-Änderung erweiterbar. ACI benötigt nur die Python-Standardbibliothek.

## Analysearchitektur

ACI verwendet eine geschichtete statische Analyse-Pipeline:

1. Quelltext laden, Größenprüfung und Ausschlussregeln
2. Lexikalische Analyse und Maskierung von Kommentaren/String-Literalen
3. Leichtgewichtige Parser-/IR-Extraktion für Routinen, Statements,
   Zuweisungen und dynamisches SQL
4. Regelprüfungen mit heuristischer und IR-gestützter Analyse
5. Reporting als Konsole, JSON, HTML oder SARIF

Die Parser-/IR-Schicht ist bewusst leichtgewichtig. Sie ist kein
vollständiger SQL-Compiler, reduziert aber typische False Positives,
indem sie Statement-Grenzen, Routine-Grenzen und die Reihenfolge von
Zuweisungen bewahrt.

### Parser-/IR-Schicht

Seit ACI 2.4.0 enthält ACI eine offiziell dokumentierte,
leichtgewichtige Parser-/IR-Schicht. ACI 2.6.0 erweitert diese IR um
flache Ausdrucksknoten und erste Kontrollblock-Markierungen.

Die IR modelliert:

- Quell-Positionen und -Bereiche
- Statements
- Routinen
- Zuweisungen
- Ausführungen dynamischen SQLs
- flache Ausdrücke (`IRExpression`, `IRCall`, `IRConcat`)
- grobe Kontrollblock-Markierungen
- behebbare Parse-Fehler

Die IR wird von ausgewählten Checks genutzt, etwa der Erkennung
dynamischer DDL und der SQL-Injection-Klassifikation. Sie erhöht die
Genauigkeit, indem sie die Quell-Reihenfolge und Routine-Grenzen
bewahrt. Die Ausdrucks-IR aus 2.6.0 hilft künftigen Checks beim Schließen
über Literale, Bezeichner, Funktionsaufrufe und Top-Level-Konkatenationen,
ohne eine vollständige SQL-Grammatik einzuführen.

Die IR ist bewusst leichtgewichtig und ersetzt keinen vollständigen
Oracle-PL/SQL- oder PostgreSQL-PL/pgSQL-Parser.

Zur Fehlersuche und Entwicklung lässt sich eine einzelne Datei in
IR-JSON umwandeln:

```sh
python -m aci pfad/zur/datei.sql --dump-ir
```

`--dump-ir` ist ein Werkzeug zur Entwicklung/Fehlersuche. Seine Ausgabe
kann Quelltext-Fragmente enthalten und sollte als internes Artefakt
behandelt werden.

### IR-gestützte Analyse

ACI nutzt die Parser-/IR-Schicht für ausgewählte, besonders wertvolle
Checks, insbesondere:

- Verfolgung der Zuweisungen an dynamisches SQL
- Erkennung dynamischer DDL
- Klassifikation von Variablen bei SQL-Injection
- routine-lokale Zuweisungssuche
- positionssensitive Zuweisungsanalyse

Das vermeidet typische False Positives wie das Verwenden von
Zuweisungen, die *nach* einem `EXECUTE IMMEDIATE` stehen, oder von
Zuweisungen aus einer anderen Prozedur/Funktion.

### Analyse-Erweiterungen in ACI 2.6.0

ACI 2.6.0 ergänzt ein kleines Ausdrucks- und Kontrollfluss-Fundament:

- `IRExpression` für Literale, Bezeichner, Bind-Variablen und unbekannte
  Ausdrücke
- `IRCall` für Funktionsaufrufe wie `DBMS_ASSERT.SQL_OBJECT_NAME(...)`,
  `quote_ident(...)` oder PostgreSQL `format(...)`
- `IRConcat` für Top-Level-`||`-Konkatenationen
- `IRControlBlock`-Markierungen für Konstrukte wie `IF`, `ELSE`, `LOOP`
  und `EXCEPTION`

Diese Modelle sind bewusst flach. Sie bereiten eine präzisere künftige
Analyse vor, aber ACI 2.6.0 gibt weiterhin nicht vor, ein vollständiger
SQL-Parser oder eine vollständige Kontrollfluss-Engine zu sein.

Die PostgreSQL-Sicherheitsabdeckung wurde zudem für riskante Muster wie
`ALTER SYSTEM`, riskante `CREATE EXTENSION`-Anweisungen,
Server-Datei-Funktionen, Large-Object-Datei-Import/-Export,
`ALTER DEFAULT PRIVILEGES ... TO PUBLIC` und zusätzliche
`SECURITY DEFINER`-Prüfsignale erweitert.

### SQL-Injection-Taint-Quellen in ACI 2.7.0

ACI 2.7.0 erweitert die SQL-Injection-Analyse um eine explizite
Modellierung der Taint-Quellen:

- Die Parser-/IR-Schicht erkennt nun auch package-interne
  `PROCEDURE`/`FUNCTION`-Definitionen (ohne führendes `CREATE`) und
  erfasst deren Parameter (`IRRoutine.parameters`)
- `SELECT`/`FETCH ... INTO`-Schreibzugriffe werden als IR-Zuweisungen
  modelliert (`IRAssignment.kind` = `select_into` / `fetch_into`)
- Der SQL-Injection-Check klassifiziert Findings als **1st-order**
  (dynamisches SQL aus einem ungeprüften Routine-Parameter) oder
  **2nd-order** (aus einem Wert, der aus Tabelle oder Cursor gelesen wurde)

Dynamisches SQL, das direkt ein ungeprüfter Routine-Parameter ist, wird
nun als Critical gemeldet statt nur als „Herkunft nicht nachvollziehbar".
Das Erkennen package-interner Routine-Grenzen macht außerdem die
positionssensitive Zuweisungsanalyse innerhalb von Package-Bodies korrekt
(keine routine-übergreifende Vermischung).

### SELECT-...-INTO-Quellmodellierung in ACI 2.7.1

ACI 2.7.1 verfeinert die 2nd-order-Analyse. Ein `SELECT ... INTO`-
Schreibzugriff trägt nun seinen Quellausdruck mit, und der
SQL-Injection-Check unterscheidet:

- eine **konstante Literal**-Quelle (`SELECT 'text' INTO v`) – kein
  Injection-Risiko
- eine **sanitizer-geschützte** Quelle (`SELECT DBMS_ASSERT.…(…) INTO v`)
  – bereinigt
- eine **Tabellenspalten**-Quelle (`SELECT col INTO v FROM t`) –
  2nd-order, Critical

`FETCH ... INTO` bleibt konservativ: Die Cursor-Quelle lässt sich
statisch nicht bestimmen, daher gilt sie stets als 2nd-order-Taint-Quelle.

### Interprozedurale Analyse (Routine-Grenzen)

ACIs Datenflussanalyse – Zuweisungsverfolgung, Parameter-Taint und
`SELECT`/`FETCH ... INTO`-Modellierung – ist **routine-lokal**. Sie löst
Werte nur innerhalb der Grenzen einer einzelnen Routine auf: einer
Prozedur, Funktion, eines anonymen Blocks oder einer package-internen
Routine (erkannt über `CREATE`-Köpfe und – innerhalb von Package-Bodies
– über `PROCEDURE`/`FUNCTION`-Definitionen, abgegrenzt durch ihr
`END <name>;`). ACI führt bewusst **keine** vollständige
inter-prozedurale Analyse durch – es verfolgt Taint nicht über einen
Aufruf von einer Routine in eine andere.

Wo ein Wert eine Routine-Grenze überschreitet, wendet ACI eine bewusst
**konservative** Politik an (es bevorzugt einen False Positive vor einem
False Negative):

- ein Routine-**Parameter** gilt als vom Aufrufer kontrollierte Eingabe
  (1st-order-Taint), denn der Aufrufer liegt außerhalb der analysierten
  Routine;
- eine Variable in dynamischem SQL, die **keinen Schreibzugriff
  innerhalb ihrer Routine** hat und kein Parameter ist, wird als
  *unbekannte Herkunft* gemeldet (Schweregrad High) – nie als sicher
  angenommen;
- das **Ergebnis eines Aufrufs in eine andere Routine oder Funktion**
  ist undurchsichtig und gilt als getaintet/unbekannt;
- eine **Package-Variable**, die in einer anderen Routine geschrieben
  wird, wird nicht verfolgt; ihre Verwendung gilt konservativ als
  unbekannte Herkunft.

Das hält die Analyse an Routine-Grenzen tendenziell sicher, ohne den
Aufwand und die Fragilität einer programmweiten Datenflussanalyse.
Findings, deren Bewertung von routine-übergreifendem Verhalten abhinge,
sollten durch manuelles Review bestätigt werden.

**Ergänzung in ACI 2.22.0 – gezielte interprozedurale Taint.** Zusätzlich
zur konservativen Routine-lokalen Politik erkennt ACI seit 2.22.0 einen
klar umrissenen routine-übergreifenden Fall innerhalb *einer Datei*: Baut
eine Hilfsroutine dynamisches SQL aus einem ihrer Parameter und übergibt
eine andere Routine dabei einen ungeprüften Wert – ihren eigenen
Parameter bzw. eine Session-/APEX-Quelle – an genau diesen Parameter, so
wird die Aufrufstelle als **interprozedurale SQL-Injection** gemeldet
(Regel-Ref `ACI-SQLI-IP`). Das schließt die häufige, über zwei Prozeduren
verteilte 1st-order-Injection. Der Pass ist bewusst konservativ (nur klare
Durchreichungen von Literalen/Sanitizern lösen nichts aus) und lässt sich
je Regeldatei über `"interprocedural": false` im `sql_injection`-Check
abschalten.

### SQL-Injection-Taint-Quellen-Fundstellen in ACI 2.8.0

SQL-Injection-Findings zeigen auf die *Taint-Quelle*, nicht nur auf den
Sink. Ein Finding bleibt am `EXECUTE IMMEDIATE`-Statement verankert,
trägt aber zusätzlich beschriftete **Related Locations**: Ist der
ausgeführte String eine Variable, wird jede aufbauende Zuweisung
gezeigt; ist der String ein ungeprüfter Routine-Parameter, wird
stattdessen der Prozedur-/Funktionskopf gezeigt. Die Related Locations
erscheinen in allen Reportformaten – Konsole, HTML, JSON (`related`) und
SARIF (`relatedLocations`).

Die Anzeige ist standardmäßig aktiv und lässt sich mit
`--no-taint-sources` (oder `taint_sources = false` in `aci.ini`)
abschalten; das Finding selbst, sein Schweregrad und die Zählungen
bleiben unberührt.

### PostgreSQL-Verfeinerungen in ACI 2.8.0

ACI 2.8.0 ergänzt die PostgreSQL-Sicherheitsregel
`ACI-PG-COPY-CLIENT-FILE` („Dateisystem-Zugriff mit copy"): Das
psql-Meta-Kommando `\copy` führt einen clientseitigen Dateisystem-Zugriff
durch – es liest oder schreibt eine Datei auf der Maschine, auf der psql
läuft – und wird als Collection-Indikator (Schweregrad High) gemeldet,
ergänzend zu den bestehenden serverseitigen
`COPY ... FROM/TO '/pfad'`-Regeln.

Mehrere False Positives wurden ebenfalls beseitigt:

- ein unbenannter Index `CREATE INDEX [CONCURRENTLY] ON tab (...)` meldet
  das Schlüsselwort `ON` (bzw. ein zurückgesetztes `CONCURRENTLY`) nicht
  mehr als Objektnamen mit reserviertem Wort; ein gequoteter
  `"on"`-Bezeichner wird weiterhin gemeldet;
- lange Hex- oder Base64-Blöcke in `INSERT ... VALUES`-Datenzeilen (etwa
  PostGIS-WKB-Geometrie oder serialisierte BLOBs) gelten nicht mehr als
  obfuskierter Inhalt – INSERT-Daten sind Daten, kein Code;
- `CREATE SCHEMA` ist Teil der PostgreSQL-Allowlist eigenständiger
  DDL-Anweisungen.

### Regeldokumentation mit Beispielen

Die HTML-Regelreferenz unter `docs/rules/` dokumentiert jeden Regelsatz
(Oracle/PostgreSQL × Sicherheit / MITRE / Coding Guidelines), eine Seite
je Satz plus Index. Neben Name, Schweregrad, Beschreibung und Empfehlung
trägt jede aktive Regel ein **Code-Beispielpaar** in PL/SQL bzw.
PL/pgSQL – einen Ausschnitt, der die Regel auslöst, und ein
konformes/sicheres Gegenstück.

Die Seiten werden von `docs/generate_rule_docs.py` aus den
JSON-Regeldateien plus `docs/rule_examples.json` (den Beispieldaten)
erzeugt. Ein Lauf des Generators reproduziert die Seiten:

```sh
python3 docs/generate_rule_docs.py
```

### Erweiterte Regelabdeckung in ACI 2.9.0

ACI 2.9.0 ergänzt rund zwei Dutzend Sicherheitsregeln rund um
Cloud-/Datenbewegung, Policy- und Audit-Manipulation, Row Level Security
und vordefinierte Datenbankrollen.

Für **Oracle**: TDE-/Wallet-Schlüsselverwaltung
(`ADMINISTER KEY MANAGEMENT`), Anlegen von Zugangsdaten
(`CREATE CREDENTIAL`), Erstellung von Datenbank-Links, Cloud-Datenexport
über `DBMS_CLOUD`, serverseitiges Datei-Schreiben
(`DBMS_XSLPROCESSOR.CLOB2FILE`), `NOLOGGING`, `TRUNCATE`/`DROP` von
Audit-Tabellen sowie das Absenken sicherheitskritischer
`ALTER SYSTEM`-Parameter; dazu die Pakete `DBMS_DATAPUMP`,
`DBMS_CREDENTIAL`, `DBMS_RLS`, `DBMS_REDACT` und `DBMS_FGA`.

Für **PostgreSQL**: `SECURITY DEFINER`-Funktionen ohne festen
`search_path` oder mit dynamischem `EXECUTE` sind nun ebenfalls Findings
der Gruppe Sicherheit; Abschalten von Row Level Security, Änderungen an
RLS-Policies, Deaktivieren von Triggern,
`GRANT ... WITH GRANT/ADMIN OPTION`, `LOAD` einer Shared Library,
`ALTER SYSTEM RESET` und das Anlegen von Objekten in Systemschemata. Die
Liste der vordefinierten Rollen und die Liste riskanter Extensions wurden
erweitert, und die Oracle-kompatiblen Pakete des EnterpriseDB Postgres
Advanced Server (EPAS) (`UTL_HTTP`, `UTL_FILE`, `DBMS_SCHEDULER`,
`DBMS_CRYPTO`, …) werden nun erfasst.

### Waiver-Prozess, Regelintegrität und feineres SARIF in ACI 2.10.0

ACI 2.10.0 ergänzt einen kontrollierten Ausnahmeprozess (Waiver) für den
CI/CD-Einsatz. Jedes Finding trägt nun einen inhaltsgebundenen
**Fingerabdruck** (SHA-256 über Check-ID, Regelreferenz, Dateiname und
den normalisierten beanstandeten Code – ohne Zeilennummer). Eine
versionierte JSON-Waiver-Datei (`--waivers`) kann einzelne Findings als
akzeptiert markieren: Ein gültiger Waiver hält das Finding im Report
sichtbar – mit Ticket, Owner, Ablaufdatum und Begründung –, nimmt es
aber aus dem `--fail-on`-Gate heraus und erzeugt einen
SARIF-`suppressions`-Eintrag. Abgelaufene Waiver unterdrücken nicht
mehr; ACI warnt über abgelaufene, bald ablaufende und verwaiste Waiver.
Eine fehlerhafte Waiver-Datei warnt standardmäßig nur und endet mit
`--strict-waivers` mit Exit-Code 2. Siehe Abschnitt
*Ausnahmeprozess / Waiver* weiter unten.

ACI 2.10.0 ergänzt außerdem einen **Regelintegritäts**-Kontrollpunkt.
Jeder Report zeigt einen **Ruleset-Hash** – einen SHA-256 über den
Inhalt aller geladenen Regeldateien – sowie je Datei einen
Vertrauensstatus (gebündelte Paketregeln vs. benutzerdefinierte Pfade).
`--require-trusted-rules` lässt den Lauf scheitern (Exit-Code 2), sobald
eine Regeldatei aus einem nicht-gebündelten Pfad geladen würde, sodass
eine manipulierte Regel den Gate nicht still schwächen kann. Siehe
*Regelintegrität (Ruleset-Hash)*.

Schließlich wird der **SARIF**-Regelkatalog nun je `check_id:rule_ref`
geführt statt nur je `check_id`, sodass GitHub-/GitLab-Security-
Dashboards einzelne Regeln getrennt verfolgen (z.B. jedes unerwünschte
Paket unter `ACI-PKG`).

### Statement-lokale PostgreSQL-Regeln und Strukturbereinigung in ACI 2.11.0

ACI 2.11.0 behebt eine False-Positive-Klasse: Der Detektor
`regex_static_and_dynamic` wertet sein Muster nun **je
`;`-begrenztem Statement** aus, sodass ein privilegiertes Schlüsselwort
in einem späteren Statement (etwa `ALTER ROLE x SUPERUSER`) nicht mehr
einem früheren, harmlosen Statement (`CREATE ROLE app LOGIN`) zugeordnet
werden kann. Die Python-Mindestversion ist nun ein ehrliches,
verifiziertes `>=3.9`, das Release-Archiv ist reproduzierbar frei von
`__pycache__`/`.pyc`/Cache-Verzeichnissen, und die beiden größten Module
wurden in Pakete aufgeteilt – `aci/checks/` (base, lexical, sqli, ddl,
detectors, guidelines) und `aci/reporting/` (Datenmodell plus je ein
Modul pro Reportformat) – ohne Verhaltens- oder API-Änderung.

### CI/CD-Profile und deutschsprachige Vereinheitlichung in ACI 2.12.0

ACI 2.12.0 ergänzt vordefinierte **CI/CD-Profile** (`--profile`), sodass
man in der Pipeline keine lange Schalter-Kette mehr zusammenstellen muss
(siehe Abschnitt *CI/CD-Profile*). Dieses README ist vollständig auf
Deutsch vereinheitlicht, und die mitgelieferte `aci.ini` ist als
selbsterklärende, durchgehend deutsch kommentierte Vorlage aufbereitet.

### ACI 2.12.1 kritische CI/CD-Fixes

ACI 2.12.1 ist ein kleines Patch-Release mit drei sicherheitsrelevanten
Korrekturen, ohne Änderung an Findings-IDs, Schweregraden, Reportformaten
oder CLI-Verhalten:

- **Waiver-Fingerabdruck mit repo-relativem Pfad.** Der Fingerabdruck
  enthält nun einen repository-relativen Dateipfad (plus den
  SQL-Dialekt) statt nur des Dateinamens. Gleichnamige Dateien in
  verschiedenen Verzeichnissen sind dadurch unterscheidbar – ein Waiver
  deckt keine fremde Datei mehr versehentlich mit ab. Absolute lokale
  oder CI-/Runner-Pfade fließen bewusst nicht ein.
- **PostgreSQL `format()`.** Für dynamisches PostgreSQL-SQL gilt
  `format()` nur dann als sicherer, wenn der Formatstring selbst ein
  String-Literal ist. Variable Formatstrings wie `format(p_fmt, ...)`
  werden als unsicher bzw. als dynamisches SQL unbekannter Herkunft
  behandelt, weil die Platzhalter-Politik dann vom Aufrufer oder von
  Daten gesteuert wird.
- **Release-Hygiene.** Das Quellarchiv enthält keine `__pycache__`-,
  `.pyc`-, `.pytest_cache`- oder generierten `aci_report_*`-Dateien.

### SQL-Injection-Korrekturen und RETURNING-Erkennung in ACI 2.13.0

ACI 2.13.0 behebt zwei Fehlklassifikationen im SQL-Injection-Check und
erweitert die Taint-Quellen. Findings-IDs und Reportformate bleiben
unverändert; in den beiden Fehlerfällen ändert sich der Schweregrad
(siehe `CHANGELOG.md`):

- **`format()` in Konkatenation (vormals übersehene Injection).** Ein
  `format()`-Aufruf als Operand einer `||`-Verkettung wurde unabhängig
  vom Platzhalter pauschal als Sanitizer (*Warning*) gewertet. Da `%s`
  nicht escaped, blieb `'... ' || format('%s', x)` eine übersehene
  Injection. Der Operand wird nun wie ein Top-Level-`format()` bewertet
  (`%I`/`%L` entschärfend, `%s` kritisch).
- **Dollar-/q-Quote-Literale (vormals Fehlalarm).** Ein `||` *innerhalb*
  eines PostgreSQL-Dollar-Quotes (`$tag$…$tag$`) oder Oracle-q-Quotes
  wurde fälschlich als Konkatenations-Operator gewertet, das Literal
  zerteilt und als getaintet (*Critical*) gemeldet. Solche Literale
  bleiben jetzt unzerteilt und gelten als konstant.
- **`RETURNING … INTO`** wird als eigene 2nd-order-Taint-Quelle erkannt
  (Wert aus einem DML-`RETURNING` in eine Variable), analog zu
  `SELECT/FETCH … INTO`.
- **Performance/Aufräumen.** Jede Datei wird nur noch einmal lexikalisch
  analysiert (zuvor doppelt); tote Lexer-Fallback-Pfade wurden entfernt.

### Erweiterte Erkennungsabdeckung in ACI 2.14.0

ACI 2.14.0 bündelt die 2.13.0-Korrekturen mit deutlich breiterer
Erkennung (Details in `CHANGELOG.md`):

- **EPAS-Paketkonsistenz.** Der `ACI-PKG`-Check für PostgreSQL/EPAS wurde
  am Funktionsumfang von EDB Postgres Advanced Server ausgerichtet
  (`DBMS_LOB`, `UTL_MAIL`, `UTL_URL`, `UTL_ENCODE` ergänzt; nicht
  existentes `UTL_TCP` entfernt).
- **PostgreSQL-Namenskonventionen** (`PG-NC-1010` snake_case,
  `PG-NC-1020` zu kurze Bezeichner) und **aus Oracle portierte
  PL/pgSQL-Guidelines** (`PG-1080`, `PG-3110`, `PG-3190`, `PG-4270`,
  `PG-7125`).
- **Zusätzliche Security-Regeln (Oracle):** AUTHID DEFINER + dynamisches
  SQL, `DBMS_SESSION.SET_ROLE`, LDAP- und XPath-/XQuery-Injection;
  PostgreSQL: hartcodierte Geheimnisse in Variablen.
- **Client-/Deployment-Skript-Direktiven** für SQL\*Plus, **edbplus** und
  **psql** (`@`/`@@`/`SPOOL`/`&`-Substitution/`ACCEPT`,
  `\!`/`\i`/`\o`/Pipe). **Remote-Skriptaufrufe** (`@`/`@@`/`START` bzw. die
  Oracle-Kurzform `STA` mit `http://`/`https://`/`ftp://` oder UNC-Pfad)
  werden als `ACI-ORA-SQLPLUS-REMOTE-SCRIPT` (Critical, T1105) gesondert und
  höher bewertet als lokale (Warning) bzw. variable (`&`, High) Skriptpfade.
  Oracle SQL\*Plus unterstützt `@`/`@@`/`START` mit HTTP/FTP-URLs (HTTPS
  laut Doku nicht, wird aber als verdächtig gemeldet). Snippets von
  Skript-Direktiven sind auf die jeweilige Direktivenzeile begrenzt.
- **APEX & ORDS (Oracle, heuristisch).** Page Items / Session State
  (`:P1_x`, `V('…')`, `APEX_UTIL.GET_SESSION_STATE`) gelten als
  benutzerkontrollierte Taint-Quellen. Erkannt werden u.a.
  „PL/SQL Function Body returning SQL" (auch in **APEX-Export-Dateien**),
  SSRF über `APEX_WEB_SERVICE`, XSS über `HTP.*`, AutoREST-Exposition.
  Neues CI/CD-Profil **`--profile apex`**.

### Verbesserte Client-/Deployment-Skript-Erkennung in ACI 2.15.0

ACI 2.15.0 schärft die Erkennung in ausgeführten SQL-Skripten (Details in
`CHANGELOG.md`):

- **Variable Skriptpfade** (`@&var`, `START &var`) als High-Befund;
  literale `@skript.sql`-Aufrufe bleiben Warning.
- **psql** `\copy … PROGRAM`, `\gexec`, `\set` mit Backquote-Kommando
  (`\set v `cmd``) und `\setenv`/`\getenv`.
- **`HOST`/`!`** läuft jetzt über denselben `client_directive`-Mechanismus
  (konsistent, string-/kommentarsicher).
- **`&`-Substitution** deutlich FP-ärmer: nur noch in sicherheitsrelevantem
  Kontext (`CREATE`/`ALTER`/`DROP`/`GRANT`/`REVOKE`/`EXECUTE IMMEDIATE`/
  `IDENTIFIED BY`); die gefährliche Kombination **ACCEPT/DEFINE → `&var`**
  wird gezielt als High gemeldet.
- **`SET DEFINE OFF`/`SET SCAN OFF`** wird berücksichtigt — `&` in solchen
  Regionen ist kein Substitutions-Trigger und löst keine Findings aus.
- **`WHENEVER SQLERROR/OSERROR CONTINUE`** (Fehler werden ignoriert) als
  Warning.

### Gehärtete CI/CD-Integration in ACI 2.16.0

ACI 2.16.0 fokussiert auf belastbare CI/CD-Gates und Audit-Nachweise
(Details in `CHANGELOG.md`):

- **Ruleset-Lock:** `--expected-ruleset-sha256 <64-hex>` bzw.
  `--ruleset-lock <pfad>` prüfen den tatsächlichen Regelsatz-Hash gegen
  einen Sollwert; bei Abweichung Abbruch mit Exit-Code 2 (fail-closed).
- **Explizite Config-Steuerung:** `--config <pfad>`, `--no-config`,
  `--print-effective-config` — kein versehentliches Laden einer lokalen
  `aci.ini` mehr im CI.
- **Audit-Metadaten** im Report: `runtime`, `gate` (fail_on, strikte Flags,
  `passed`, `exit_code`), `ruleset_integrity`, `config` — in JSON, SARIF
  (`run.properties`) und HTML. Unter `--safe-report` werden cwd/executable
  maskiert.
- **Boolesche Gegenschalter:** `--no-strict-waivers`,
  `--no-require-trusted-rules`, `--unsafe-report`, `--context`,
  `--no-redact-secrets`, `--no-follow-symlinks`, … (Präzedenz:
  Defaults < Config < Profil < CLI).
- **`SET DEFINE <char>`** wird modelliert (`SET DEFINE ^` erkennt `^var`),
  und psql-Meta-Kommandos laufen über eine Normalisierungsschicht
  (`aci/checks/psql_meta.py`) — robuster gegen Whitespace-Varianten.

### Erweiterte PostgreSQL-/EPAS-Sicherheitsregeln in ACI 2.17.0

ACI 2.17.0 erweitert den PostgreSQL-/EPAS-Regelsatz minimal-invasiv um
elf neue MITRE-Regeln. Die **EPAS Oracle-kompatiblen Paketregeln** greifen
sowohl in dollar-quoted PL/pgSQL-Bodies als auch in Oracle-Stil-Bodies, da
der Body-Inhalt nicht als String maskiert wird:

- `ACI-EPAS-SCHEDULER-EXECUTABLE` (Critical) — `DBMS_SCHEDULER`-Job mit
  `job_type => 'EXECUTABLE'` (OS-Befehl auf dem Server).
- `ACI-EPAS-DBMS-SQL` (High) — dynamisches SQL über `DBMS_SQL.PARSE/EXECUTE`.
- `ACI-EPAS-SCHEDULER-CREATE-JOB` (High) — `DBMS_SCHEDULER.CREATE_JOB` /
  `DBMS_JOB.SUBMIT` (Persistenz über geplante Jobs).
- `ACI-EPAS-UTL-FILE` (High) — serverseitiger Dateizugriff über `UTL_FILE`.
- `ACI-EPAS-UTL-HTTP` (High) — ausgehender Web-Request über `UTL_HTTP`.
- `ACI-EPAS-UTL-TCP` (High) — rohe TCP-Verbindung über `UTL_TCP`.
- `ACI-EPAS-UTL-SMTP` (High) — E-Mail-Versand über `UTL_SMTP`.

Hinzu kommen **PostgreSQL-native** Regeln:

- `ACI-PG-SESSION-REPLICATION-ROLE` (High) — `SET session_replication_role`
  (deaktiviert Trigger inkl. Fremdschlüssel-/Audit-Durchsetzung).
- `ACI-PG-SET-ROW-SECURITY-OFF` (High) — `SET row_security = off/false`
  (umgeht Row-Level-Security für die Sitzung).
- `ACI-PG-REASSIGN-OWNED` (High) — `REASSIGN OWNED BY` (Eigentumsübertragung).
- `ACI-PG-READ-PG-AUTHID` (High) — Lesen von `pg_authid` / `pg_shadow`
  (gespeicherte Passwort-Hashes).

Jede neue aktive Regel hat einen positiven und negativen Harness-Case.
Bereits durch bestehende Regeln abgedeckte Fälle (z. B. Grants auf
vordefinierte Rollen, `BYPASSRLS`, RLS-Abschaltung, `ALTER SYSTEM`
Preload/Archive) wurden bewusst **nicht** dupliziert; stark
falsch-positiv-anfällige Muster (generisches `ALTER ... OWNER TO`,
`DROP CONSTRAINT`, `NOT VALID`) wurden bewusst zurückgestellt.

### EPAS Audit Tampering / Audit Bypass in ACI 2.18.0

ACI 2.18.0 ergänzt eine Regelgruppe für Audit-Tampering, Audit-Bypass und
forensisch verdächtige Konfigurationsänderungen in PostgreSQL/EPAS:

1. **Audit/Logging-Abschaltung via `ALTER SYSTEM`** —
   `ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM` (Critical) und
   `ACI-PG-AUDIT-LOGGING-DISABLE-ALTER-SYSTEM` (Critical) erkennen
   `edb_audit*='none'/'off'` bzw. `log_statement='none'`,
   `logging_collector=off` usw.; `ACI-EPAS-AUDIT-WEAKEN-ALTER-SYSTEM` (High)
   und `ACI-PG-AUDIT-LOGGING-WEAKEN-SET` (High) erfassen Abschwächungen
   (`edb_audit_statement='ddl'/'mod'`, `SET log_statement='none'`,
   `set_config('log_statement','none',...)`).
2. **`postgresql.auto.conf`-Manipulation via psql-Shell-Escape** —
   `ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING` (Critical) erkennt
   Schreibzugriffe (`\! sed -i ... postgresql.auto.conf`,
   `echo ... >> postgresql.auto.conf`, Editoren, `tee`, `cp/mv`, `chmod` …);
   reiner Lesezugriff wird nicht gemeldet. `ACI-PG-CONFIG-FILE-TAMPERING`
   (High) deckt `postgresql.conf`/`pg_hba.conf`/`pg_ident.conf` ab.
3. **`pg_reload_conf()` nach audit-sensitiver Änderung** —
   `ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE` (Critical) feuert, wenn im
   selben Skript eine Audit-/Logging-/Sicherheitsänderung vorkommt;
   `ACI-EPAS-AUDIT-CONFIG-RELOAD` (High) für einen isolierten Reload (beide
   schließen sich gegenseitig aus).
4. **SECURITY-DEFINER-Funktion, die privilegierte Account-Erstellung
   versteckt** — `ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION` (Critical)
   erkennt privilegierte DDL (CREATE/ALTER/DROP ROLE|USER, GRANT/REVOKE,
   ALTER SYSTEM, CREATE EXTENSION/SERVER/USER MAPPING, COPY … PROGRAM) im
   Routinen-Rumpf — statisch und dynamisch (`EXECUTE '…'`).
   `ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE` (High) meldet den
   späteren Aufruf einer solchen Funktion (`SELECT fn_acc(…)`).

#### Runtime forensic checks outside ACI static analysis

ACI ist statische Analyse und erkennt **keine** Manipulation, die außerhalb
gescannter Skripte passiert. Insbesondere bleibt unerkannt: eine direkte
OS-seitige Editierung von `postgresql.auto.conf` (ohne gescanntes Skript),
Zeitstempel-/`mtime`-Anomalien der Konfigurationsdateien und die fehlende
Korrelation zwischen `ALTER SYSTEM`-Audit-Events und tatsächlichem
Datei-Inhalt. Empfohlene ergänzende Laufzeit-/Forensik-Kontrollen:

- `mtime` von `postgresql.auto.conf` prüfen und gegen das letzte
  `ALTER SYSTEM`-Audit-Event korrelieren,
- File Integrity Monitoring auf `postgresql.auto.conf`, `postgresql.conf`,
  `pg_hba.conf`,
- SIEM-Regeln für `pg_reload_conf()` und für Änderungen an `edb_audit*`-
  Parametern,
- OS-Audit für Schreibzugriffe auf die Konfigurationsdateien.

Da PostgreSQL-Scans standardmäßig nur SQL-/PL/pgSQL-Endungen umfassen
(`.sql`, `.pgsql`, `.plpgsql`, `.psql`, `.ddl`, `.func`, `.pck`), werden
Audit-Parameter *innerhalb* von `.conf`-Dateien nur erkannt, wenn die Datei
ausdrücklich als Scan-Eingabe mit passender Endung übergeben wird (nicht der
Standardfall).

### SQL\*Plus-Remote-Skripterkennung in ACI 2.19.0

ACI 2.19.0 erkennt das Ausführen von **Remote-Skripten** über SQL\*Plus/
edbplus gesondert: `@`/`@@`/`START` sowie die Oracle-Kurzform `STA` mit
`http://`/`https://`/`ftp://` oder UNC-Pfad werden als
`ACI-ORA-SQLPLUS-REMOTE-SCRIPT` (Critical, T1105) gemeldet — höher als der
lokale (Warning) bzw. der variable `&`-Pfad (High). Jeder Skriptaufruf erhält
genau eine Klassifizierung (Remote vor variabel vor lokal); es gibt keine
Doppelmeldung.

### Review-Findings, Routine-Grenzen und Pfadmaskierung in ACI 2.20.0

ACI 2.20.0 behebt sieben Review-Findings (Details in `CHANGELOG.md`):

1. **PostgreSQL-/EPAS-Passwörter** (`PASSWORD '…'`, inkl.
   `ENCRYPTED`/`UNENCRYPTED`, FDW-`OPTIONS (password '…')`) werden unter
   `--redact-secrets` zuverlässig maskiert; `PASSWORD NULL` bleibt unberührt.
2. **PostgreSQL-/EPAS-Routine-Grenzen**: eine Funktion endet am
   Statement-Terminator, nicht am Dateiende — Statements nach einer Funktion
   zählen nicht mehr zur SECURITY-DEFINER-Routine.
3. SQL\*Plus-Kurzform `STA` für Remote-Skripte (siehe 2.19.0).
4. Client-Directive-Snippets sind auf die betroffene Zeile begrenzt.
5. **`--redact-paths`** (von `--safe-report` impliziert) anonymisiert absolute
   Pfade in allen Report-Feldern (Verzeichnis → `<PATH>`, Dateiname bleibt).
6. `pg_reload_conf()`-Findings werden dedupliziert, wenn eine spezifischere
   EPAS-Audit-Reload-Regel dieselbe Zeile meldet.
7. Eine harte, formatübergreifende Report-Leakage-Test-Suite (JSON/SARIF/
   HTML/Console) sichert die Redaction ab.

### Härtung aus umfassendem Code-Review in ACI 2.21.0

ACI 2.21.0 behebt mehrere im Review gefundene False-Negative-/False-
Positive-Quellen und Robustheitslücken (Details in `CHANGELOG.md`), u.a.:
mehrzeilige `UPDATE … SET`-Zeilen werden nicht mehr fälschlich als
SQL\*Plus-Direktive weggeblendet; `DBMS_ASSERT.NOOP` gilt nicht mehr als
Sanitizer (echte Injection bleibt *Critical*); UTF-16/BOM-Dateien werden
korrekt dekodiert statt unbemerkt „sauber" durchzulaufen; der
Integritäts-Hash bildet „hash what you load" (TOCTOU geschlossen); die
Secret-Redaction greift bei den üblichen PL/SQL-Namen (`v_password`,
`l_pwd`) und bei `IDENTIFIED BY VALUES '<hash>'`; nicht lesbare Dateien/
Verzeichnisse werden gemeldet statt still übersprungen.

### Erweiterte Analyse und CI-Ergonomie in ACI 2.22.0

- **Interprozedurale Taint** (siehe *Interprozedurale Analyse* oben):
  ungeprüfter Wert, der über einen Routinenaufruf in das dynamische SQL
  einer Hilfsroutine fließt, wird an der Aufrufstelle gemeldet
  (`ACI-SQLI-IP`).
- **Oracle-SQLi über XML-Generierung:** `DBMS_XMLGEN.NEWCONTEXT(query)` und
  `DBMS_XMLQUERY.NEWCONTEXT(query)` führen die übergebene SQL-Abfrage aus
  und werden als dynamische SQL-Sinks mit voller Taint-Bewertung erkannt
  (Bypass der `EXECUTE IMMEDIATE`-Erkennung).
- **PostgreSQL-Session-/GUC-Taint-Quelle:** `current_setting(…)` und
  `set_config(…)` werden als benutzerkontrollierbare Quelle typisiert und
  in der Meldung ausgewiesen.
- **Inline-Suppression** direkt am Code: `-- aci:ignore` bzw.
  `-- aci:ignore-next-line`, optional auf Regeln beschränkt
  (`-- aci:ignore[ACI-SQLI] Ticket …`). Unterdrückte Findings zählen nicht
  fürs Gate; die Anzahl wird als Hinweis gemeldet. Werkzeugfehler
  (`ACI-INTERNAL`) sind nicht unterdrückbar.
- **Baseline-/Diff-Modus** für Legacy-Code: `--write-baseline DATEI`
  schreibt den akzeptierten Ausgangsstand (über die inhaltsgebundenen
  Fingerabdrücke) und beendet ohne Gate; `--baseline DATEI` unterdrückt bei
  Folgeläufen die bekannten Findings, sodass nur **neu hinzugekommene**
  gemeldet werden und fürs Gate zählen.

### Härtung der Gate-Verlässlichkeit in ACI 2.23.0

Schwerpunkt aus einem umfassenden externen Review: nicht einzelne Regeln,
sondern die **Verlässlichkeit des Scans als Security-Gate**. Behoben wurden
sechs Muss- und die Soll-Findings (M1–M6, S1–S15).

- **Symlink-Zykluserkennung (M1):** `--follow-symlinks` erkennt bereits
  besuchte reale Verzeichnisse über `(st_dev, st_ino)` und kappt Zyklen
  (`loop/loop/…`) – ein präpariertes Repository kann den Scanner nicht mehr
  in Endlosrekursion/Timeout treiben.
- **Scan-Vollständigkeit als Gate (M2):** `--scan-completeness advisory|strict`
  sowie `--fail-on-access-error` / `--fail-on-skipped-file`. Ein CI-Lauf
  „besteht" nicht mehr stumm mit Exit 0, wenn Dateien nicht gelesen,
  übersprungen oder nicht dekodiert wurden. Der Report enthält einen Block
  `scan_completeness` (JSON) bzw. `aci_scan_completeness` (SARIF). Das
  `strict`-Profil setzt `strict`; das `ci`-Profil setzt `--fail-on-access-error`.
- **Vollständiger Safe-Report (M3):** Die Redaction erfasst nun auch
  `message`/`recommendation` und Zusatzstellen-Labels; interne Fehler-Findings
  werden im Safe-Modus auf `Interner Fehler im Check <ID>: <ExceptionTyp>`
  standardisiert (kein Pfad-/Input-Leak, voller Text nur mit `--debug`);
  `platform` wird auf die grobe OS-Familie reduziert. `--safe-console` wendet
  die Pfadmaskierung zusätzlich auf die stderr-Hinweise an (CI-Logs).
- **Schutzgrenzen für Einzeldateien (M4):** Größenlimit, benutzerdefinierte
  `--exclude`-Muster und der Symlink-Schutz gelten jetzt auch für eine explizit
  übergebene Einzeldatei. Bewusste Ausnahme: `--force-file`. (Die
  Default-Excludes wie `dist`/`build` gelten weiterhin nur beim
  Verzeichnis-Scan – eine ausdrücklich benannte Datei wird nicht durch sie
  abgelehnt.)
- **Atomares Schreiben aller Reports (M5):** JSON/HTML/SARIF/CodeClimate werden
  – wie die Baseline – über `aci._io.atomic_write_text` geschrieben
  (Temp-Datei + `fsync` + `os.replace`). Kein halb geschriebenes Artefakt für
  SARIF-Upload, `jq` oder GitLab-Code-Quality.
- **Verpflichtende Regelsatz-Bindung (M6):** `--require-ruleset-pin` (vom
  `strict`-Profil gesetzt) verlangt einen erwarteten Hash
  (`--expected-ruleset-sha256`/`--ruleset-lock`). „Gebündelt" (`--require-
  trusted-rules`) bedeutet nur „aus dem Paketpfad", nicht „unverändert".
- **Reproduzierbarer Report (S3):** `--reproducible-report` lässt Zeitstempel,
  Dauer, Plattform und absolute Pfade weg – der Report bleibt byte-identisch.
- **Encoding (S8):** `--encoding` erzwingt eine Kodierung, `--encoding-errors
  replace|strict` steuert nicht dekodierbare Bytes; im `strict`-Modus gilt eine
  solche Datei als ungeprüft und zählt für die Scan-Vollständigkeit.
- **TOCTOU-feste Größenprüfung (S9):** Datei wird einmal geöffnet, `fstat` auf
  demselben Deskriptor, und höchstens `Limit+1` Byte gelesen.
- **Suppression-Governance (S13):** `--strict-suppressions` verlangt für
  `-- aci:ignore` die Metadaten `ticket=` und `reason=` und lehnt abgelaufene
  (`expires=YYYY-MM-DD`) oder ungültige Direktiven ab; eine **abgelaufene**
  Direktive unterdrückt nicht mehr, der Befund wird wieder sichtbar.
- **Routine-bewusster Fingerabdruck (S14):** Der inhaltsgebundene
  Fingerabdruck bezieht jetzt den Namen der umgebenden Routine ein. **Achtung:
  bestehende Baselines/Waiver müssen mit `--write-baseline` neu erzeugt bzw.
  neu gebunden werden.**
- **Weiteres:** zentrale Dialekt-Normalisierung `postgres`/`pg → postgresql`
  (S5), aufgeschlüsselte `--print-effective-config` (`resolution`-Block, S4),
  `--report-name` gegen Namenskollisionen (S10), leere `--format`-Liste ist ein
  Fehler (K3), IEC-Einheiten `KiB/MiB/GiB` (K4), SemVer-Release-Workflow (S1).

## Grenzen & Hinweise

ACI ist ein **heuristischer** statischer Review-Assistent – **kein**
SQL-Compiler, **kein** formaler Sicherheitsbeweis und **kein** Ersatz
für manuelles Review oder Datenbank-Härtung.

### Bekannte Grenzen der Parser-/IR-Schicht

Die Parser-/IR-Schicht ist kein vollständiger Oracle-PL/SQL- oder
PostgreSQL-PL/pgSQL-Compiler.

Bekannte Grenzen:

- keine vollständige Kontrollflussanalyse
- keine vollständige Datenflussanalyse über Funktionsaufrufe hinweg
- keine semantische Validierung gegen eine laufende Datenbank
- begrenztes Verständnis komplex generierter SQL-Fragmente
- konservative Behandlung unbekannter Hilfsfunktionen
- False Positives und False Negatives bleiben möglich

Findings zu dynamischem SQL und administrativer DDL sollten weiterhin
manuell geprüft werden. ACI garantiert nicht, dass alle SQL-Injections
oder Datenbank-Sicherheitsprobleme erkannt werden.

### False Negatives bei generiertem und dynamischem SQL

ACI ist eine **statische** Analyse des *übergebenen* Quelltextes. Sie
ist stark bei Code, der ihr vollständig vorliegt – aber sie sieht
grundsätzlich **nicht**, was erst zur Build- oder Laufzeit entsteht.
Dadurch können Befunde unentdeckt bleiben (False Negatives),
insbesondere bei:

- **dynamischem SQL über mehrere Dateien hinweg** – ein SQL-String wird
  in einer Datei/Routine zusammengesetzt und in einer anderen
  ausgeführt; ACIs Datenflussanalyse ist routine-lokal und folgt
  Aufrufen nicht (siehe *Interprozedurale Analyse*);
- **Build-Templates und Code-Generatoren** – wird der eigentliche
  SQL-Code erst durch ein Template-/Makro-System, einen Präprozessor
  oder einen Generator erzeugt, prüft ACI nur die *Vorlage*, nicht das
  erzeugte Ergebnis;
- **Migrations-Generatoren** – Migrationswerkzeuge (ORM-Migrationen,
  Schema-Diff-Tools), die SQL erst zur Laufzeit aus einem Modell
  ableiten, liefern ACI keinen statisch prüfbaren Quelltext;
- **Konfigurations- und Datengetriebenem SQL** – SQL-Fragmente, die aus
  Konfigurationsdateien, Datenbankinhalten oder externen Eingaben
  stammen und erst zur Laufzeit zu einer Anweisung zusammengesetzt
  werden, liegen außerhalb des analysierten Textes.

Wo SQL erst nach dem von ACI geprüften Stand entsteht, sollte das
**erzeugte** SQL zusätzlich geprüft werden – etwa indem der Generator-
oder Migrations-Output selbst durch ACI läuft – und durch manuelles
Review ergänzt werden. ACI ist ein Review-Assistent und CI-Signal, kein
vollständiger Nachweis der Abwesenheit von SQL-Injection.

Weitere Grenzen:

- Findings müssen **manuell geprüft** werden. False Positives und False
  Negatives sind möglich.
- ACI ist als **Review-Assistent und CI-Signal** gedacht, nicht als
  alleinige Grundlage für eine Sicherheitsfreigabe.
- Die PostgreSQL-Regelabdeckung ist trotz eigener PL/pgSQL-Guidelines
  weiterhin geringer als die für Oracle; die MITRE-ATT&CK-Abdeckung für
  PostgreSQL ist kleiner als für Oracle.
- Reports können Quelltext-Ausschnitte enthalten und sind als
  **vertrauliche Artefakte** zu behandeln (siehe `--no-context`,
  `--redact-secrets` und Abschnitt *Reportpfade und Vertraulichkeit*).
- Verschachtelte PostgreSQL-Dollar-Quotes müssen – wie von PostgreSQL
  ohnehin gefordert – unterschiedliche Tags verwenden (`$func$` / `$msg$`).

## Sicherheitsmodell / Vertrauensgrenze

- ACI analysiert **lokale Dateien** und führt **keinen** SQL-Code aus.
- ACI sollte **nicht** als Webservice mit ungeprüften Parametern
  betrieben werden.
- Regeldateien (`aci/rules/`, `--rules` / `--rules-dir`) gelten als
  **vertrauenswürdige Eingabe** und werden beim Laden hart validiert.
  ACI weist im Report einen **Ruleset-Hash** und den Vertrauensstatus
  jeder Regeldatei aus; `--require-trusted-rules` erzwingt, dass nur die
  gebündelten Regeln verwendet werden (siehe *Regelintegrität*).
- Reports können sensible Informationen (Quelltext, ggf. Geheimnisse,
  absolute Pfade mit Benutzer-/Kunden-/Projektnamen) enthalten und sollten
  entsprechend geschützt oder mit `--no-context`, `--redact-secrets` bzw.
  `--redact-paths` erzeugt werden. `--safe-report` bündelt alle drei.
- ACI ist **statische Analyse**: manuelle OS-seitige Änderungen außerhalb
  gescannter Skripte (z. B. direktes Editieren von `postgresql.auto.conf`),
  Live-`mtime`-/Timestamp-Anomalien und Auditlog-Korrelation liegen
  außerhalb des Erkennungsbereichs und erfordern Laufzeit-/Forensik-Tooling
  (FIM, SIEM).

## Installation

Voraussetzung: Python 3.9 oder neuer.

```sh
pip install .
```

Danach steht das Kommando `aci` zur Verfügung. Alternativ lässt sich ACI
ohne Installation direkt aus dem Quellverzeichnis starten:

```sh
python -m aci tests/samples/oracle_vulnerable.sql
python3 aci.py samples/vulnerable_oracle.sql
```

### Docker

Für CI-Runner ohne kontrollierte Python-Umgebung liegt ein
Multi-Stage-`Dockerfile` bei (Basis `python:3.12-slim`, läuft als
unprivilegierter Benutzer, `ENTRYPOINT aci`):

```sh
docker build -t aci:latest .

# Repo als /code mounten, Reports nach /code/reports
docker run --rm -v "$PWD:/code" aci:latest \
    --profile ci -f sarif,codeclimate -o /code/reports /code/sql
```

Die Exit-Codes des Containers entsprechen denen des Kommandos
(`0` = Gate bestanden, `1` = Gate verletzt, `2` = Fehler) und können in
der Pipeline direkt ausgewertet werden.

## Verwendung

```sh
aci <Datei-oder-Verzeichnis> [Optionen]
```

Beispiele:

```sh
aci samples/vulnerable_oracle.sql
aci ./src --dialect oracle --format console,html --output-dir reports/
aci code.sql --group security
aci ./src --profile ci                       # CI/CD-Gate (siehe unten)
aci ./src --exclude generated --max-file-size 5MB
aci ./src --no-context                       # Reports ohne Quelltext
aci --list-checks                            # aktive Checks/Regeln anzeigen
```

> **Hinweis:** Für PostgreSQL-Code muss `--dialect postgresql` gesetzt
> werden – ACI verwendet sonst den Oracle-Regelsatz.

Wichtigste Optionen:

| Option | Beschreibung |
|--------|--------------|
| `-d, --dialect` | `oracle` oder `postgresql` (Alias `postgres` wird ebenfalls akzeptiert) |
| `-g, --group` | `all`, `security` oder `guidelines` |
| `--profile` | CI/CD-Voreinstellung: `advisory`, `ci`, `strict`, `audit`, `apex` (siehe *CI/CD-Profile*) |
| `-f, --format` | `console`, `json`, `html`, `sarif`, `codeclimate` (kommagetrennt) |
| `-o, --output-dir` | Zielverzeichnis für JSON-/HTML-/SARIF-/CodeClimate-Reports |
| `--html-group-by` | HTML-Findings nach `rule` oder `file` gruppieren |
| `--min-level` | nur Findings ab einem Schweregrad ausgeben |
| `--fail-on` | Exit-Code 1, wenn Findings ≥ Schweregrad (CI/CD) |
| `--strict-internal-errors` | Exit-Code 2, wenn ein Check intern fehlschlägt |
| `--waivers DATEI` | JSON-Datei mit kontrollierten Ausnahmen (Waiver); gewaiverte Findings bleiben sichtbar, zählen aber nicht für `--fail-on` |
| `--strict-waivers` | Exit-Code 2, wenn die Waiver-Datei fehlerhaft ist (Default: nur warnen) |
| `--baseline DATEI` | bekannte (in der Baseline enthaltene) Findings unterdrücken – es werden nur **neue** Findings gemeldet und gezählt (Adoption auf Legacy-Code) |
| `--write-baseline DATEI` | aktuellen Stand als Baseline schreiben und ohne Gate beenden (Exit 0) |
| `--require-trusted-rules` | Exit-Code 2, wenn eine Regeldatei aus einem benutzerdefinierten (nicht gebündelten) Pfad geladen würde |
| `--require-ruleset-pin` | verlangt einen erwarteten Regelsatz-Hash (`--expected-ruleset-sha256`/`--ruleset-lock`); fehlt er, Exit-Code 2 (vom `strict`-Profil gesetzt) |
| `--scan-completeness advisory\|strict` | `strict`: Exit-Code 2, wenn nicht jede Zieldatei geprüft wurde |
| `--fail-on-access-error` / `--fail-on-skipped-file` | Exit-Code 2 bei nicht lesbaren bzw. wegen Limit/Exclude übersprungenen Dateien |
| `--strict-suppressions` | Inline-`aci:ignore` müssen `ticket=`/`reason=` tragen und dürfen nicht abgelaufen sein; sonst Exit-Code 2 |
| `--encoding` / `--encoding-errors replace\|strict` | Quelltext-Kodierung erzwingen; `strict` = nicht dekodierbare Datei gilt als ungeprüft |
| `--reproducible-report` | byte-identischer Report (ohne Zeitstempel/Dauer/Plattform/absolute Pfade) |
| `--report-name NAME` | fester Basisname der Report-Dateien (verhindert Namenskollisionen) |
| `--context-lines N` | Zeilen Quelltext-Kontext pro Finding |
| `--no-context` | keinen Quelltext-Kontext in den Report aufnehmen |
| `--no-color` | Konsolenausgabe ohne ANSI-Farbcodes |
| `--redact-secrets` | einfache Geheimnis-Muster im Kontext maskieren (inkl. PostgreSQL/EPAS `PASSWORD '…'`) |
| `--redact-paths` | absolute Pfade im Report anonymisieren (Verzeichnis → `<PATH>`, Dateiname bleibt); Unix-/Windows-/UNC-Pfade. Relative Pfade bleiben unverändert |
| `--safe-report` | `--no-context`, `--redact-secrets` und `--redact-paths` gemeinsam aktivieren |
| `--safe-console` | Pfadmaskierung auch auf die stderr-Hinweise anwenden (CI-Logs) |
| `--taint-sources` / `--no-taint-sources` | Taint-Quelle bei SQL-Injection- und dynamischen DDL-Findings als zusätzliche Fundstelle zeigen (Standard: an) |
| `--exclude MUSTER` | Datei-/Verzeichnismuster ausschließen (mehrfach); gilt auch für explizit benannte Einzeldateien |
| `--max-file-size GRÖSSE` | Dateien über dieser Größe überspringen (`5MB`, `500KB`, `1GiB`; binär); gilt auch für Einzeldateien |
| `--force-file` | Größenlimit/Exclude/Symlink-Schutz **nicht** auf eine explizit benannte Einzeldatei anwenden |
| `--follow-symlinks` | symbolischen Verknüpfungen folgen (mit Zykluserkennung) |
| `--rules` / `--rules-dir` | eigene Regeldateien verwenden |
| `--debug` | bei unerwarteten Fehlern den vollen Traceback zeigen |

Die Vorgabewerte der meisten Optionen stammen aus `aci.ini` (siehe
Abschnitt *Konfiguration*); ein gesetzter Schalter überschreibt sie.

Beim rekursiven Verzeichnis-Scan werden Versionsverwaltung, Build-
Artefakte und Tool-Caches standardmäßig übersprungen: `.git`, `.hg`,
`.svn`, `target`, `dist`, `build`, `node_modules`, `.venv`, `venv`,
`__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox`,
`.idea`, `.eggs`. Symlinks werden ohne `--follow-symlinks` nicht verfolgt.

**Dateiauswahl:** Beim Scan eines **Verzeichnisses** werden nur Dateien
mit unterstützter SQL-Dateiendung berücksichtigt (`.sql`, `.pks`,
`.pkb`, … – je Dialekt in der Regeldatei festgelegt). Eine **explizit
angegebene Einzeldatei** wird dagegen unabhängig von ihrer Dateiendung
analysiert.

Eine ausführliche Beschreibung aller Checks, Regeln und Reportformate
enthält `docs/ACI_Dokumentation.html`.

## Konfiguration

Die Standardwerte der Optionen liegen in der INI-Datei `aci.ini` und
können dort dauerhaft angepasst werden. ACI sucht die Datei im
aktuellen Arbeitsverzeichnis und im Projektverzeichnis; fehlt sie,
gelten die werkseitigen Vorgaben. Ein auf der Kommandozeile gesetzter
Schalter hat stets Vorrang vor der Datei.

Die mitgelieferte `aci.ini` ist eine **selbsterklärende Vorlage**: Jeder
Parameter ist mit seinem werkseitigen Default eingetragen und auf
Deutsch kommentiert. Die Datei verwendet einen Abschnitt `[defaults]`:

```ini
[defaults]
dialect = oracle
group = all
min_level = info
context_lines = 3
taint_sources = true
html_group_by = rule
```

Der HTML-Report zeigt die verwendeten Werte als Zeile *Scan-Parameter*;
weicht ein Wert vom Default ab, wird der Default in Klammern ergänzt
(z.B. `min_level: warning (default: info)`).

Über `html_group_by` lässt sich das Layout des HTML-Reports steuern:
`rule` (Standard) gruppiert die Findings nach Regel und nennt je
Fundstelle den Dateipfad; `file` gruppiert wie bisher nach Datei.

Der DDL-Check besitzt in der Regeldatei (`ddl_in_code`) eine Allowlist
`allowed_statements`: dort aufgeführte eigenständige DDL-Anweisungen
(z.B. `CREATE TABLE`, `ALTER TABLE`, `DROP INDEX`) gelten als reguläre
Deployment-DDL und erzeugen kein Finding. Dynamisch zusammengesetzte
DDL bleibt davon unberührt, und externe Tabellen (`ORGANIZATION
EXTERNAL`) werden trotz erlaubtem `CREATE TABLE` weiterhin gemeldet.

### Administrative Oracle-Anweisungen in CI/CD

Bestimmte administrative Oracle-Aktionen gehören nicht in normale
Deployment-Pipelines, sondern in kontrollierte DBA-, IAM- oder
Security-Prozesse. ACI bewertet sie daher als **Critical**:

- `ALTER USER` (Benutzerverwaltung),
- `GRANT`/`REVOKE` von Oracle-Systemprivilegien (z.B. `CREATE SESSION`,
  `CREATE PROCEDURE`, `ALTER USER`),
- `GRANT`/`REVOKE` von Oracle-Standardrollen (`CONNECT`, `RESOURCE`,
  `DBA`, `SELECT_CATALOG_ROLE`, …).

Die maßgeblichen Listen `system_privileges` und `standard_roles` liegen
in `aci/rules/oracle.json` (`ddl_in_code`) und lassen sich dort zentral
erweitern. Mehrzeilige `GRANT`/`REVOKE`-Anweisungen werden erkannt;
Treffer in Kommentaren und String-Literalen erzeugen kein Finding.

### PostgreSQL-Verwaltungsanweisungen in CI/CD

Seit ACI 2.6.0 behandelt ACI PostgreSQL-Rollenverwaltung sowie
`GRANT`/`REVOKE` vordefinierter bzw. System-Rollen als kritische
Findings, wenn sie in normalen Deployment-Skripten auftreten. Solche
Operationen gehören in kontrollierte DBA-, IAM- oder
Security-Freigabeprozesse, nicht in Anwendungs-Migrationen.

Beispiele:

```sql
CREATE ROLE app_admin SUPERUSER LOGIN;
ALTER ROLE app_user BYPASSRLS;
GRANT pg_execute_server_program TO app_user;
REVOKE pg_read_server_files FROM app_user;
```

ACI meldet außerdem ausgewählte PostgreSQL-Operationen rund um FDW, User
Mapping, logische Replikation, Event Trigger und Server-Dateien, weil
sie Zugangsdaten, entfernte Konnektivität, Lateral-Movement-Pfade,
Persistenz oder Datenexfiltrations-Kanäle einführen können:

```sql
CREATE SERVER remote_pg FOREIGN DATA WRAPPER postgres_fdw;
CREATE USER MAPPING FOR app_user SERVER remote_pg OPTIONS (password 'secret');
CREATE SUBSCRIPTION sub1 CONNECTION 'host=remote user=repl password=secret' PUBLICATION pub1;
CREATE EVENT TRIGGER ddl_backdoor ON ddl_command_end EXECUTE FUNCTION backdoor_func();
COPY sensitive_table TO '/tmp/dump.csv';
```

`COPY ... TO STDOUT` und `COPY ... FROM STDIN` werden von diesen Regeln
nicht als Server-Datei-Findings behandelt.

## CI/CD-Einsatz

ACI eignet sich als Gate in einer CI/CD-Pipeline.

### CI/CD-Profile

Damit man in der Pipeline keine lange Schalter-Kette zusammenstellen
muss, kennt ACI vordefinierte **Profile**. Ein Profil ist ein benanntes
Bündel sinnvoller Voreinstellungen; es legt eine Vorgabe-Schicht
zwischen `aci.ini` und die expliziten Kommandozeilen-Schalter. Ein
ausdrücklich gesetzter Schalter hat also weiterhin Vorrang vor dem
Profil.

| Profil | Zweck | gesetzte Vorgaben |
|--------|-------|-------------------|
| `advisory` | beratend – scannt und berichtet, blockiert nie | `--group security --fail-on none --format console,json,sarif --safe-report` |
| `ci` | empfohlener harter Gate – blockiert ab High | `--group security --fail-on high --format console,json,sarif --safe-report --strict-internal-errors --fail-on-access-error --safe-console` |
| `strict` | strengster Gate – `ci` plus strenge Waiver-/Regel-/Vollständigkeitsprüfung | wie `ci`, zusätzlich `--strict-waivers --require-trusted-rules --require-ruleset-pin --scan-completeness strict --fail-on-skipped-file` |
| `audit` | vollständige Prüfung für manuelles Review (mit Kontext, ohne Blockade) | `--group all --fail-on none --format console,html --taint-sources` |
| `apex` | APEX-/ORDS-Review (Oracle) – Sicherheitsgruppe inkl. APEX/ORDS-Regeln, mit Kontext, ohne Blockade | `--group security --fail-on none --format console,html --taint-sources` |

```sh
aci src/sql --profile ci                       # empfohlener Gate
aci src/sql --profile ci --waivers aci-waivers.json
aci src/sql --profile advisory                  # nur berichten
# strengster Gate: verlangt eine feste Regelsatz-Bindung (Pin/Lock)
aci src/sql --profile strict --ruleset-lock ruleset.lock.json
```

> **Hinweis:** `--profile strict` setzt `--require-ruleset-pin` und
> `--scan-completeness strict`. Ohne `--expected-ruleset-sha256` bzw.
> `--ruleset-lock` bricht der Lauf daher mit Exit-Code 2 ab; ebenso, wenn
> nicht jede Zieldatei geprüft werden konnte. Das ist beabsichtigt: ein
> „fail-closed"-Gate soll nicht ohne nachweisbaren Regelstand und nicht über
> ungeprüften Code hinweg bestehen.

Einzelne Vorgaben eines Profils lassen sich überschreiben, indem man den
betreffenden Schalter zusätzlich angibt:

```sh
aci src/sql --profile ci --fail-on critical      # Schwelle hochsetzen
```

Wer keinen Profil-Schalter verwenden möchte, kann die Optionen auch
einzeln setzen:

```sh
aci src/sql --fail-on high
aci src/sql --format json --output-dir reports
aci src/sql --exclude .git --exclude target --max-file-size 5MB
```

**Empfohlene Gate-Schwelle: mindestens `--fail-on high`.** Viele
CI-relevante administrative Befunde sind bewusst mit **High** bewertet,
nicht mit **Critical** — etwa `ALTER SYSTEM SET …` oder ein riskantes
`CREATE EXTENSION dblink`. Ein Gate mit `--fail-on critical` lässt
genau diese Anweisungen unbemerkt durch. Für ein Deployment-Gate sollte
daher `--fail-on high` (oder strenger) gelten; `--fail-on critical` ist
für ein verlässliches Sicherheits-Gate zu schwach. Die Profile `ci` und
`strict` setzen `--fail-on high` bereits.

**Sichere Report-Artefakte:** JSON-/HTML-Reports können Quelltext-
Ausschnitte enthalten. Für CI-Artefakte daher Reports ohne Kontext
bevorzugen:

```sh
aci src/sql --format json --no-context
```

Wird Kontext benötigt, die Redaction einfacher Geheimnis-Muster
aktivieren – oder beides mit `--safe-report` bündeln:

```sh
aci src/sql --format json --redact-secrets
aci src/sql --format json --safe-report
```

Hinweis: Die Redaction ist heuristisch und entfernt nicht zwingend
*alle* Geheimnisse – sie reduziert lediglich das Risiko. Die Profile
`advisory`, `ci` und `strict` aktivieren `--safe-report` bereits.

### Ausnahmeprozess / Waiver

Reale Pipelines brauchen einen **kontrollierten** Weg, einzelne
Befunde zu akzeptieren – ohne `--fail-on` global abzuschwächen oder
Regeln zu deaktivieren. Dafür kennt ACI **Waiver**: eine versionierte
JSON-Datei mit einem Eintrag je akzeptierter Ausnahme.

Ein Waiver bindet sich über den **Fingerabdruck** eines Findings: einen
inhaltsgebundenen SHA-256-Hash aus Check-ID, Regelreferenz, SQL-Dialekt,
einem **repo-relativen Dateipfad** und dem (auf Leerzeichen
normalisierten) beanstandeten Code – **ohne** Zeilennummer und **ohne**
absolute lokale oder CI-/Runner-Pfade. Der repo-relative Pfad (statt nur
des Dateinamens) sorgt dafür, dass gleichnamige Dateien in
verschiedenen Verzeichnissen – etwa `db/admin/install.sql` und
`db/app/install.sql` – unterscheidbar bleiben: ein Waiver für die eine
Datei deckt **nicht** versehentlich ein Finding in der anderen mit ab.
So überlebt ein Waiver harmlose Code-Verschiebungen, verfällt aber
automatisch, sobald sich der beanstandete Code selbst ändert. Der
Fingerabdruck steht in jedem Report (Konsole, JSON, HTML, SARIF) und
kann direkt übernommen werden.

Waiver-Datei `aci-waivers.json` (Pflichtfelder: `fingerprint`,
`ticket`, `owner`, `expires`, `reason`):

```json
[
  {
    "fingerprint": "39e7c9525757badd",
    "ticket": "SEC-1423",
    "owner": "ak@red-database-security.com",
    "expires": "2026-09-30",
    "reason": "Dynamisches SQL nur über validierte Whitelist-Konstante; Refactor in SEC-1423 geplant.",
    "created": "2026-05-24",
    "risk_accepted": true
  }
]
```

In der Pipeline:

```sh
aci src/sql --profile ci --waivers aci-waivers.json
```

Verhalten:

- Ein **gültiger** Waiver (Ablaufdatum ≥ heute, Fingerabdruck trifft
  ein Finding) markiert das Finding als *Waived*. Es bleibt im Report
  sichtbar – mit Ticket, Owner, Ablaufdatum und Begründung – zählt aber
  **nicht** für `--fail-on`. In SARIF erscheint es als `suppressions`.
- Ein **abgelaufener** Waiver greift nicht mehr; das Finding zählt
  wieder voll. ACI warnt über abgelaufene und über bald (≤ 14 Tage)
  ablaufende Waiver.
- Ein **verwaister** Waiver (Fingerabdruck trifft kein Finding) wird im
  Report gemeldet – Hinweis, dass er entfernt werden kann.
- Eine **fehlerhafte** Waiver-Datei (ungültiges JSON, fehlende
  Pflichtfelder, kaputtes Datum) führt standardmäßig nur zu einer
  Warnung; mit `--strict-waivers` zu Exit-Code 2.

Die Waiver-Datei gehört unter Versionskontrolle; Änderungen laufen
über den normalen Pull-Request-Review – das ist die eigentliche
Freigabe-Kontrolle. Das Ablaufdatum erzwingt eine Wiedervorlage.

### Inline-Suppression (`-- aci:ignore`)

Ergänzend zur zentralen Waiver-Datei lassen sich einzelne Fundstellen mit
einem Kommentar **direkt am Code** stummschalten – ergonomisch und im Diff
sichtbar. Zwei Formen:

- `-- aci:ignore` unterdrückt Findings der zugehörigen Codezeile: steht der
  Kommentar am Ende einer Codezeile, ist es diese Zeile; steht er allein auf
  einer reinen Kommentarzeile, die **nächste tatsächliche Codezeile**;
- `-- aci:ignore-next-line` unterdrückt Findings der nächsten tatsächlichen
  Codezeile. Leerzeilen sowie reine Zeilen- und Blockkommentarzeilen werden
  dabei übersprungen; eine Zeile mit Code **und** Kommentar gilt als
  Codezeile.

Optional lässt sich die Unterdrückung in eckigen Klammern auf bestimmte
Regeln (Regelreferenz oder Check-ID, kommagetrennt) beschränken; ohne
Klammer gilt sie für alle Findings der Zielzeile. Sowohl `--`-Zeilen- als
auch `/* … */`-Blockkommentare werden als Träger akzeptiert.

> **Nur echte Kommentare (ab ACI 2.22.1):** Direktiven werden ausschließlich
> innerhalb lexikalisch gültiger Kommentare erkannt. Eine identische
> Zeichenfolge in einem String-Literal (einfaches Literal, Oracle-q-Quote,
> PostgreSQL-Dollar-Quote, quoted identifier, dynamisches SQL,
> `RAISE NOTICE`-Text) löst **keine** Suppression aus.

```sql
v_sql := 'select * from t where c = ''' || p_name || '''';
-- aci:ignore[ACI-SQLI] SEC-42: Wert stammt aus geprüfter Whitelist
EXECUTE IMMEDIATE v_sql;
```

Unterdrückte Findings zählen **nicht** für `--fail-on`; ihre Anzahl wird
als Hinweis auf stderr gemeldet. Werkzeugfehler (`ACI-INTERNAL`) sind
bewusst **nicht** per Kommentar unterdrückbar – ein Werkzeugfehler soll
nicht stillschweigend verschwinden.

**Governance mit `--strict-suppressions` (ab ACI 2.23.0).** Eine reine
Direktive ohne Begründung kann dauerhaft unbemerkt im Code verbleiben. Mit
`--strict-suppressions` verlangt ACI daher Governance-Metadaten und meldet
Verstöße mit Exit-Code 2. Unterstützte Schlüssel hinter der Direktive:
`ticket=`, `reason=`, `owner=` und `expires=YYYY-MM-DD` (Werte optional
gequotet):

```sql
v_sql := 'select * from t where c = ''' || p_name || '''';
-- aci:ignore[ACI-SQLI] ticket=SEC-42 reason="Whitelist-geprüft" expires=2026-12-31
EXECUTE IMMEDIATE v_sql;
```

Ohne `ticket=`/`reason=`, mit ungültigem oder **abgelaufenem** `expires=`
schlägt der Lauf unter `--strict-suppressions` fehl. Eine **abgelaufene**
Direktive unterdrückt zudem generell nicht mehr – der Befund wird wieder
sichtbar, sodass eine Inline-Suppression nicht unbegrenzt lange still ein
Finding deckt.

### Baseline-/Diff-Modus (Legacy-Adoption)

Auf gewachsenem Code liefert der erste Scan oft zu viele Findings, um
sofort ein hartes Gate zu schalten. Der Baseline-Modus löst das: Er
schreibt den aktuellen Stand als akzeptierten Ausgangspunkt fest und
meldet fortan nur noch **neu hinzugekommene** Findings.

```sh
# Einmalig: aktuellen Stand als Baseline festschreiben (beendet mit Exit 0)
aci src/sql --write-baseline aci-baseline.json

# In der Pipeline: nur neue Findings zählen fürs Gate
aci src/sql --profile ci --baseline aci-baseline.json
```

Die Bindung erfolgt über denselben inhaltsgebundenen **Fingerabdruck** wie
bei den Waivern – unabhängig von absolutem Pfad und Report-Kontext. Eine
Baseline bleibt damit über CI-Läufe stabil, solange sich der beanstandete
Code nicht ändert; sobald eine neue riskante Stelle hinzukommt, wird nur
diese gemeldet. Bekannte (in der Baseline enthaltene) Findings werden
unterdrückt; ihre Anzahl erscheint als Hinweis. `ACI-INTERNAL`
(Werkzeugfehler) wird nie über die Baseline unterdrückt. Eine fehlende
oder fehlerhafte Baseline-Datei führt fail-closed zu Exit-Code 2.

**Multiset-Semantik (ab ACI 2.22.1):** Da der Fingerabdruck bewusst keine
Zeilennummer enthält, können zwei identische Befunde in einer Datei denselben
Fingerabdruck haben. Die Baseline führt daher je Fingerabdruck eine **Anzahl**
(Format Version 2). Sind *k* Vorkommen bekannt und treten aktuell *m* auf,
gelten `min(k, m)` als bekannt; die übrigen bleiben als neue Findings
sichtbar. Wird verwundbarer Code an eine zweite Stelle kopiert, meldet ACI
die neue Instanz. Geschrieben wird:

```json
{
  "baseline_version": 2,
  "generated_by": "ACI 2.22.1",
  "findings": { "39e7c9525757badd": 1, "a1b2c3d4e5f60718": 3 }
}
```

Baselines im Format aus ACI 2.22.0 (`{"fingerprints": [...]}` oder eine blanke
JSON-Liste) bleiben lesbar; dort zählt jedes Vorkommen als eins. Die Datei
wird atomar geschrieben – ein Abbruch hinterlässt keine beschädigte Baseline.

Baseline und Waiver ergänzen sich: die **Baseline** akzeptiert pauschal den
Ist-Stand (schneller Einstieg), der **Waiver** dokumentiert einzelne
Ausnahmen mit Ticket/Owner/Ablauf (kontrollierte Einzelfreigabe).

### Regelintegrität (Ruleset-Hash)

Die Regeldateien bestimmen, *was* ACI prüft. Über `--rules`,
`--rules-dir`, `--guidelines-dir` und `--mitre-dir` lassen sie sich
austauschen – in einer Pipeline auch ein Manipulationsrisiko: Wer die
Regeln verändert, kann den Gate schwächen. ACI macht den verwendeten
Regelstand daher überprüfbar.

Jeder Report enthält einen **Ruleset-Hash** – einen SHA-256 über den
Inhalt *aller* tatsächlich geladenen Regeldateien (Sicherheits-Regelsatz,
Coding-Guidelines, MITRE-Indikatoren). Der Hash ist stabil und
reproduzierbar; ein Team kann ihn in der Pipeline gegen einen erwarteten
Wert prüfen. Zusätzlich weist ACI je Datei aus, ob sie
**vertrauenswürdig** ist – also Teil der mit ACI ausgelieferten,
gebündelten Regeln (innerhalb des installierten `aci`-Pakets) – oder aus
einem benutzerdefinierten Pfad stammt (*untrusted*). Untrusted
Regeldateien werden im Report sichtbar markiert und auf stderr gewarnt.

`--require-trusted-rules` macht daraus einen harten Kontrollpunkt: ACI
bricht mit Exit-Code 2 ab, sobald eine Regeldatei von außerhalb des
Pakets geladen würde. Für ein abgesichertes CI-Gate:

```sh
aci src/sql --fail-on high --require-trusted-rules
```

Der Ruleset-Hash erscheint in allen Reportformaten: Konsole (Zeile
`Regeln`), JSON (`ruleset.integrity`), HTML (Zeile *Regelintegrität*)
und SARIF (`runs[].properties.aci_ruleset_hash`).

### Reportpfade und Vertraulichkeit

ACI-Reports können Dateipfade und Scan-Ziel-Metadaten enthalten. Je
nachdem, wie ACI ausgeführt wird, können das absolute Pfade sein, die
interne Workspace- oder CI-Runner-Informationen verraten – etwa
Benutzernamen, Projektnamen, Repository-Pfade oder
Build-Agent-Verzeichnisstrukturen.

JSON-, HTML- und SARIF-Reports sind als interne Artefakte zu behandeln,
solange sie nicht geprüft oder bereinigt wurden. Für die externe
Weitergabe sollten Reports ohne Quelltext-Kontext bevorzugt werden:

```sh
python -m aci pfad/zur/sql --format json --no-context
```

Wird Quelltext-Kontext benötigt, sollte die Redaction aktiviert werden:

```sh
python -m aci pfad/zur/sql --format json --redact-secrets
```

Die Redaction ist heuristisch und garantiert nicht, dass jedes
Geheimnis oder jeder sensible Pfad entfernt wird.

**SARIF-Ausgabe:** Mit `--format sarif` erzeugt ACI einen
SARIF-2.1.0-Report (`aci_report_<name>.sarif`). Das Format wird u.a.
von GitHub Code Scanning eingelesen, sodass die Findings direkt im
Pull Request erscheinen:

```sh
aci src/sql --format sarif --output-dir reports --safe-report
```

Der SARIF-Regelkatalog wird je **konkreter Regelreferenz** geführt –
die `ruleId` ist `check_id:rule_ref` (z.B. `ACI-PKG:utl_http`,
`ACI-OBF:CHR-CHAIN`), nicht nur `check_id`. So verfolgen GitHub-/GitLab-
Security-Dashboards einzelne Regeln getrennt; die `check_id` und
`rule_ref` stehen zusätzlich in den `properties` jedes Regeleintrags.
Fehlt eine Regelreferenz oder gleicht sie der `check_id`, bleibt es bei
der reinen `check_id`. Gewaiverte Findings erscheinen als
`suppressions`, jeder Befund trägt seinen Fingerabdruck als
`partialFingerprints`.

**CodeClimate-Ausgabe (GitLab Code Quality):** Mit `--format codeclimate`
erzeugt ACI einen Report im CodeClimate-Subset-Format
(`aci_report_<name>.codeclimate.json`), den GitLab als
`codequality`-Artefakt einliest – die Findings erscheinen direkt im
Merge-Request-Widget und im Diff. Die Schweregrade werden über das
ACI-Gewicht abgebildet (Info→`info`, Minor/Warning→`minor`,
Major/High→`major`, Critical→`critical`, Blocker→`blocker`); jeder
Befund trägt seinen inhaltsgebundenen Fingerabdruck (bei Mehrfach-
Vorkommen deterministisch eindeutig gemacht, damit GitLab nichts
dedupliziert). Beispiel `.gitlab-ci.yml`:

```yaml
aci-scan:
  image: python:3.12-slim
  script:
    - pip install --quiet aci-2.22.1-py3-none-any.whl
    - aci src/sql --profile ci -f codeclimate,sarif -o reports
      # Exit 1 bricht den Job – das MR-Widget zeigt die Findings
  artifacts:
    when: always
    reports:
      codequality: reports/aci_report_sql.codeclimate.json
    paths:
      - reports/
```

Exit-Codes:

| Code | Bedeutung |
|------|-----------|
| `0` | Lauf erfolgreich, `--fail-on`-Schwelle nicht erreicht |
| `1` | `--fail-on`-Schwelle erreicht oder überschritten |
| `2` | Werkzeug-/Eingabefehler (ungültige Regeldatei, Pfad nicht gefunden, ungültige Option) oder – mit `--strict-internal-errors` bzw. `--strict-waivers` / `--require-trusted-rules` – ein interner Check-Fehler, eine fehlerhafte Waiver-Datei bzw. eine untrusted Regeldatei |

## Tests

ACI bringt eine pytest-basierte Testsuite mit (`tests/`). Die empfohlene,
gepinnte Entwickler-Toolchain (pytest, ruff, mypy) wird über das
`dev`-Extra installiert:

```sh
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy aci
```

> Hinweis: ACI bleibt zur Laufzeit auf Python 3.9 kompatibel; der
> mypy-Prüf-Target ist auf 3.10 gesetzt (siehe `pyproject.toml`), da aktuelle
> mypy-Versionen `python_version = "3.9"` nicht mehr unterstützen.

**Release-Artefakt prüfen:** Das Source-Archiv (sdist) muss vollständig
und eigenständig testbar sein. Dazu Archiv bauen, entpacken und darin
erneut testen (entspricht dem CI-Job `sdist-test`):

```sh
python -m build --sdist
mkdir -p /tmp/aci-sdist && tar -xzf dist/*.tar.gz -C /tmp/aci-sdist
cd /tmp/aci-sdist/* && pip install -e ".[dev]"
python -m pytest -q
python -m compileall -q aci tests
```

**PostgreSQL-MITRE-Regel-Testharness:** Seit ACI 2.6.0 gibt es einen
Regel-Testharness für die PostgreSQL-MITRE-Regeln. Zu jeder aktiven
PostgreSQL-MITRE-Regel wird mindestens ein positives und ein negatives
SQL-Beispiel unter `tests/rules/postgresql/mitre/cases.json` erwartet.
Der generische pytest-Harness prüft, dass positive Beispiele die
erwartete Regel-ID auslösen und negative nicht. Das hält die
MITRE-Regeldateien überprüfbar und senkt das Risiko stiller Regressionen,
wenn Regeln zwischen Taktiken verschoben werden.

## Aufbau

```
aci/            Python-Paket (Scanner-Engine, Checks, Reporter, CLI)
aci/lexer.py    Lexer - Parser-Grundlage (Tokens, Statements, dyn. SQL)
aci/parser.py   leichtgewichtige Parser-/IR-Schicht (mit aci/ir.py)
aci/source.py   Vorverarbeitung je Datei (Lexer + IR)
aci/scanner.py  Scan-Engine (Dateien/Verzeichnisse)
aci/cli.py      Kommandozeilen-Schnittstelle (orchestriert den Lauf)
aci/config.py   Laden der Standardparameter aus aci.ini
aci/waivers.py  Waiver-/Ausnahmeprozess
aci/integrity.py Regelintegritaet (Ruleset-Hash, Trust-Status)
aci/_version.py zentrale Versionsangabe
aci/checks/     Pruef-Checks (Paket): base, lexical, sqli, ddl, detectors, guidelines
aci/reporting/  Reportformate (Paket): report, console, json_report, sarif, html, codeclimate
aci/rules/      ausgelieferte Regeldateien (Sicherheit, Guidelines, MITRE)
aci.ini         Standardparameter (Default-Werte, anpassbar)
aci.py          Starter fuer den Aufruf ohne Installation
samples/        Beispiel-SQL-Dateien
tests/          pytest-Testsuite samt eigener Beispieldateien
docs/                       HTML-Dokumentation
docs/ACI_Dokumentation.html Gesamtdokumentation
docs/rules/                 HTML-Regelreferenz je Regelsatz (mit Code-Beispielen)
docs/generate_rule_docs.py  Generator der Regelreferenz
docs/rule_examples.json     Code-Beispiele je Regel (Eingabe des Generators)
```

## Lizenz

ACI ist ein Projekt mit **gemischter Lizenzierung**:

- Der **eigene Code von ACI** – das Paket `aci/`, die CLI sowie die
  PL/pgSQL-Guidelines unter `aci/rules/guidelines/postgresql/` – steht
  unter der **MIT-Lizenz** (siehe `LICENSE`).
- Die **Oracle-Coding-Guideline-Regeldateien** unter
  `aci/rules/guidelines/oracle/` sind aus den *Trivadis PL/SQL & SQL
  Coding Guidelines* v4.4 abgeleitet und stehen daher unter der
  **Apache-Lizenz, Version 2.0** (siehe `licenses/Apache-2.0.txt`).
  Sie wurden für ACI angepasst – als JSON-Regeldateien neu
  strukturiert, mit Detector-Konfiguration und Schweregrad-Zuordnung
  versehen. Die Datei `NOTICE` enthält die vollständige Attribution und
  den Änderungshinweis nach Apache-Lizenz Abschnitt 4(b).

Die MIT-Lizenz von ACI bleibt davon unberührt; Apache-2.0 und MIT sind
permissive, miteinander vereinbare Lizenzen. Die MITRE-ATT&CK-Zuordnungen
verweisen auf das MITRE-ATT&CK-Framework.
