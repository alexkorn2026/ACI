# Changelog

Alle nennenswerten Änderungen an ACI werden in dieser Datei dokumentiert.

Das Format orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
die Versionierung folgt [Semantic Versioning](https://semver.org/lang/de/).

## [Unveröffentlicht]

### Hinzugefügt
- **CodeClimate-Report (GitLab Code Quality).** Neues Ausgabeformat
  `--format codeclimate` erzeugt `aci_report_<name>.codeclimate.json` im
  CodeClimate-Subset-Format, das GitLab als `codequality`-Artefakt einliest –
  Findings erscheinen im Merge-Request-Widget und im Diff. Schweregrade
  werden über das ACI-Gewicht abgebildet (Info→info, Minor/Warning→minor,
  Major/High→major, Critical→critical, Blocker→blocker). Jeder Befund trägt
  seinen inhaltsgebundenen Fingerabdruck; Mehrfach-Vorkommen erhalten einen
  deterministischen Zähler-Suffix, damit GitLab keine Findings dedupliziert.
  Gewaiverte Findings bleiben sichtbar (Beschreibung nennt das Ticket),
  zählen aber wie überall nicht für das Gate.
- **Dockerfile + .dockerignore.** Multi-Stage-Build auf `python:3.12-slim`:
  Stage 1 baut das Wheel, Stage 2 installiert nur das Wheel und läuft als
  unprivilegierter Benutzer (`USER aci`, `ENTRYPOINT aci`). Exit-Codes des
  Containers entsprechen dem Kommando. README-Abschnitte *Docker* und
  *CodeClimate-Ausgabe* mit `.gitlab-ci.yml`-Beispiel ergänzt.

## [2.22.1] - 2026-07-03

Korrektur-Release aus dem Review von 2.22.0. Behebt zwei Muss- und vier
Soll-Findings der neuen Inline-Suppression- und Baseline-Funktionen sowie der
interprozeduralen Analyse. Rückwärtskompatibel; bestehende Regeln, Severities
und Reportformate unverändert.

### Behoben
- **Inline-Suppressions nur noch in echten Kommentaren.** Direktiven
  (`aci:ignore`, `aci:ignore-next-line`) werden ausschließlich innerhalb der
  vom Lexer gelieferten Kommentarbereiche erkannt. Eine identische
  Zeichenfolge in einem String-Literal (einfaches Literal, Oracle-q-Quote,
  PostgreSQL-Dollar-Quote, quoted identifier, dynamisches SQL, `RAISE NOTICE`)
  löst **keine** Suppression mehr aus.
- **Baselines berücksichtigen die Anzahl identischer Findings (Multiset).**
  Da der Fingerabdruck keine Zeilennummer enthält, können identische Befunde
  denselben Hash haben. Die Baseline führt jetzt je Fingerabdruck einen
  Zähler; bei *k* bekannten und *m* aktuellen Vorkommen gelten `min(k, m)` als
  bekannt, die übrigen bleiben als neue Findings sichtbar. Kopierter
  verwundbarer Code wird dadurch gemeldet.
- **`ignore-next-line` bezieht sich auf die nächste tatsächliche Codezeile.**
  Leerzeilen sowie reine Zeilen- und Blockkommentarzeilen werden übersprungen;
  eine Zeile mit Code *und* Kommentar gilt als Codezeile. `aci:ignore` auf
  einer reinen Kommentarzeile wirkt ebenfalls auf die nächste Codezeile, am
  Ende einer Codezeile auf diese Zeile.
- **Oracle Named Arguments in der interprozeduralen Analyse.**
  `sink(p_sql => p_input)` und gemischte Aufrufe werden über den
  normalisierten Parameternamen dem korrekten Parameter zugeordnet;
  Positionsargumente füllen der Reihe nach. Unbekannte Parameternamen werden
  konservativ ignoriert (keine Zuordnung allein per Index).
- **Baseline-Dateien werden streng validiert.** Wurzeltyp, Version,
  Fingerabdruck-Format (16 Hex-Zeichen), positive Ganzzahl-Counts (keine
  Booleans), Obergrenzen. Fehler führen fail-closed zu einer klaren Meldung
  (Exit-Code 2); eine defekte Baseline wird nicht still wie eine leere
  behandelt. Unbekannte zukünftige `baseline_version` werden abgelehnt.
- **Baselines werden atomar geschrieben** (Temporärdatei im Zielverzeichnis,
  `flush`/`fsync`, `os.replace`; Aufräumen der Temporärdatei bei Fehlern).
  Eine bestehende Baseline bleibt bei einem Schreibfehler unbeschädigt.

### Kompatibilität
- Legacy-Baselines aus 2.22.0 (`{"fingerprints": [...]}` bzw. blanke JSON-
  Liste) bleiben lesbar; jedes Vorkommen zählt als eins.
- Das neue Baseline-Format wird als **Version 2** geschrieben
  (`{"baseline_version": 2, "generated_by": ..., "findings": {fp: count}}`).

## [2.22.0] - 2026-07-03

Feature-Release: erweiterte Analyse-Präzision und CI-Ergonomie. Additiv und
rückwärtskompatibel; bestehende Findings unverändert.

### Neu – Analyse
- **Interprozedurale Taint (Call-Graph innerhalb der Datei).** Erkennt, wenn
  eine Hilfsroutine dynamisches SQL aus einem ihrer Parameter baut und eine
  andere Routine dabei einen ungeprüften Wert (ihren eigenen Parameter bzw.
  eine Session-/APEX-Quelle) an genau diesen Parameter übergibt — die
  „über zwei Prozeduren verteilte" 1st-order-Injection, die zuvor
  unentdeckt blieb. Befund an der Aufrufstelle, Regel-Ref `ACI-SQLI-IP`.
  Konservativ (nur klare Durchreichungen) und über `interprocedural: false`
  je Regeldatei abschaltbar.
- **Oracle-SQLi über XML-Generierung.** `DBMS_XMLGEN.NEWCONTEXT(query)` und
  `DBMS_XMLQUERY.NEWCONTEXT(query)` führen die übergebene SQL-Abfrage aus und
  werden nun als dynamische SQL-Sinks mit voller Taint-Bewertung erkannt
  (Bypass der `EXECUTE IMMEDIATE`-Erkennung).
- **PostgreSQL-Session-/GUC-Taint-Quelle.** `current_setting(...)` und
  `set_config(...)` werden als benutzerkontrollierbare Quelle typisiert; die
  Meldung weist die GUC-Herkunft explizit aus (`session_taint_patterns` in
  `postgresql.json`).

### Neu – Ergonomie & CI
- **Inline-Suppression** direkt am Code: `-- aci:ignore` bzw.
  `-- aci:ignore-next-line`, optional auf Regeln beschränkt
  (`-- aci:ignore[ACI-SQLI] Ticket …`). Unterdrückte Findings zählen nicht
  fürs Gate; die Anzahl wird als Hinweis gemeldet. Werkzeugfehler
  (`ACI-INTERNAL`) sind bewusst nicht unterdrückbar.
- **Baseline-/Diff-Modus** für die Adoption auf Legacy-Code:
  `--write-baseline DATEI` schreibt den akzeptierten Ausgangsstand (über die
  inhaltsgebundenen Fingerabdrücke) und beendet ohne Gate; `--baseline DATEI`
  unterdrückt bei Folgeläufen die bekannten Findings, sodass nur **neu
  hinzugekommene** gemeldet werden und fürs Gate zählen.

## [2.21.0] - 2026-07-03

Härtungs-Release aus einem umfassenden Code-Review (Kern-Engine,
Erkennungslogik, CLI/Reporting). Behebt mehrere False-Negative-/False-
Positive-Quellen sowie Robustheits- und Report-Sicherheitslücken. Keine
geänderten Regel-IDs; Report-Formate rückwärtskompatibel.

### Behoben – Kern-Engine (Lexer/Parser/Scanner)
- **`UPDATE … SET`-Zeilen nicht mehr weggeblendet.** Die SQL*Plus-
  Direktiven-Maskierung löschte jede mit `SET` beginnende Zeile ohne `;` —
  bei mehrzeiligem DML also die `SET`-Zeile eines `UPDATE`. Deren Inhalt
  (inkl. Konkatenationen) war damit für **alle** Checks unsichtbar
  (False Negative). Direktiven werden jetzt nur noch am Anweisungsanfang
  maskiert, nicht in Fortsetzungszeilen (`lexer.py`).
- **Statement-Grenzen robuster.** Die Körper-Erkennung (`CREATE JAVA
  SOURCE …/`) lief auf dem Rohtext; ein solches Konstrukt in einem
  Kommentar/String konnte `;`-Grenzen unterdrücken und Statements
  verschmelzen. Läuft nun auf `code_masked` (`lexer.py`).
- **`;` in quotierten Bezeichnern** (`"a;b"`) wird nicht mehr als
  Statement-Trenner gewertet (eigener Token-Typ `TOK_QIDENT`).
- **Kein Scan-Abbruch mehr bei pathologischem Input.** Tief verschachtelte
  Ausdrücke lösten einen `RecursionError` aus, der – da nur der Lexer
  abgesichert war – den Scan der ganzen Datei/des Verzeichnisses abbrach.
  Ausdrucks-Rekursion ist jetzt tiefenbegrenzt, und der Source-/IR-Aufbau
  ist im Scanner abgesichert (internes Finding statt Abbruch).
- **`COMMENT ON FUNCTION` / `GRANT EXECUTE ON …` erzeugen keine Phantom-
  Routinen mehr** (führendes `ON` ausgeschlossen), die nachfolgende
  Statements fälschlich einem Routinen-/Taint-Kontext zuordneten
  (`parser.py`).
- **UTF-16/BOM-Dateien** werden erkannt und korrekt dekodiert (`utf-8-sig`,
  UTF-16/-32 per BOM) statt als Ersetzungszeichen-Brei „sauber"
  durchzulaufen — schließt eine Scanner-Blend-Lücke (`scanner.py`).
- **PL/pgSQL:** Der `EXECUTE`-Ausschluss (`GRANT EXECUTE ON`, Trigger-
  Syntax `EXECUTE PROCEDURE/FUNCTION`) greift jetzt bei beliebigem
  Whitespace; `f(a := 1)` (Named-Argument) wird nicht mehr als Zuweisung
  fehlinterpretiert (`lexer.py`).
- **Performance:** `_control_blocks` und `_inner_routines` von O(n²) auf
  bisect- bzw. pos/endpos-basierte Suche umgestellt (`parser.py`).

### Behoben – Erkennungslogik
- **`DBMS_ASSERT.NOOP` gilt nicht mehr als Sanitizer.** NOOP führt keine
  Prüfung durch; eine damit „abgesicherte" Injection wurde auf *Warning*
  heruntergestuft. Sie wird jetzt korrekt als *Critical* gemeldet
  (`checks/base.py`).
- **Literal-Ketten-Fehlalarm behoben.** Reine Literale über mehr als zwei
  Zwischenvariablen (`v1:='x'; v2:=v1; v3:=v2; …`) wurden am zu niedrigen
  Tiefenlimit (2) konservativ als *Critical* gemeldet. Das Limit der
  Taint-Verfolgung wurde erhöht (`checks/sqli.py`).

### Behoben – Regelintegrität, CLI & Reporting
- **Integritäts-Hash „hash what you load".** Der Ruleset-Hash wird über die
  beim Laden gelesenen Bytes gebildet statt die Dateien für den Hash erneut
  zu lesen — schließt ein TOCTOU-Fenster. Nicht lesbare Regeldateien gelten
  nicht mehr als vertrauenswürdig (`rules.py`, `integrity.py`).
- **Secret-Redaction greift bei üblichen PL/SQL-Namen.** `v_password := …`,
  `l_pwd := …`, `the_token := …` (führendes `_`) und die Deklarationsform
  mit Typ (`v_password VARCHAR2(30) := …`) werden jetzt maskiert; auch
  `IDENTIFIED BY VALUES '<hash>'` (der Hash blieb zuvor im Klartext).
- **`--redact-paths` maskiert auch den Regeldatei-Pfad** (`ruleset.path`),
  der zuvor trotz Anonymisierung im Report stand.
- **`aci.ini` mit `%` im Wert** führt nicht mehr zu einem rohen
  Interpolations-Traceback (Exit 1), sondern zu einem sauberen Fehler
  (`interpolation=None`, `config.py`).
- **Zugriffsfehler klar behandelt.** Eine nicht lesbare Einzeldatei liefert
  „Zugriff verweigert" (Exit 2) statt „unerwarteter Fehler"; nicht lesbare
  Dateien/Verzeichnisse im Verzeichnis-Scan werden als **Warnung** gemeldet
  (statt still übersprungen), damit ein CI-Gate nicht unbemerkt über
  ungeprüften Code hinweggeht (`cli.py`, `scanner.py`).

## [2.20.2] - 2026-05-29

### Behoben
- **Oracle-Bezeichnerlänge korrigiert (30 → 128).** Die
  `naming_conventions`-Prüfung meldete Oracle-Bezeichner > 30 Zeichen als
  „zu lang". Das ist das Legacy-Limit (Oracle ≤ 12.1); seit **Oracle 12.2**
  sind Bezeichner bis **128 Byte** zulässig. `max_identifier_length` für
  Oracle steht jetzt auf 128 — Namen bis 128 Zeichen erzeugen kein
  Längen-Finding mehr (PostgreSQL bleibt bei 63). Rein datengetriebene
  Änderung in `aci/rules/oracle.json`; Regel-ID und Meldungsformat
  unverändert.

## [2.20.1] - 2026-05-29

Schließt fünf Audit-Lücken aus dem 2.20-Review (minimal-invasiv, rückwärts-
kompatibel; keine geänderten Regel-IDs oder Report-Formate).

### Behoben
- **PG-7010 jetzt routine-scoped:** Die SECURITY-DEFINER-`search_path`-Prüfung
  arbeitet pro Routine (über die IR-/Routinengrenzen) statt dateibasiert. Ein
  `SET search_path` in einer *anderen* Funktion derselben Datei lässt eine
  ungesicherte SECURITY-DEFINER-Routine nicht mehr fälschlich sicher
  erscheinen; jede ungesicherte Routine wird einzeln gemeldet.
- **`--print-effective-config` zeigt effektive Werte:** Bei aktivem
  `safe_report` (u.a. `--profile ci`/`strict`) werden `no_context`,
  `redact_secrets` und `redact_paths` als *effektive* `true`-Werte
  ausgegeben (zuvor teils rohe argparse-Defaults). `--context-lines 0`
  impliziert `no_context`; `--unsafe-report` hebt das Bündel auf.
- **CLI-Hilfe/Doku-Konsistenz:** `--safe-report` nennt nun überall (CLI-Hilfe,
  HTML-Doku) alle drei gebündelten Schalter (`--no-context`,
  `--redact-secrets`, `--redact-paths`); `--profile` listet `apex` mit; die
  Optionentabelle führt `--redact-paths`/`--no-redact-paths`.

### Hinzugefügt
- **Tiefe Regelvalidierung** für `ddl_in_code`: `critical_statements`
  (Pflichtfeld `statement`, gültiges `level`, optionale String-Felder),
  `external_table`, `privilege_grant`, `standard_roles`,
  `system_privileges`, `harmless_object_privileges` und `ddl_objects` werden
  hart geprüft; defekte Regeldateien brechen fail-closed mit `RuleError` ab.
- **Datengetriebenes DDL-Objektvokabular:** Die DDL-Objektarten je Schlüsselwort
  liegen als Default in `aci/checks/base.py` und sind je Dialekt über
  `ddl_in_code.ddl_objects` (create/alter/drop/truncate) in der Regeldatei
  überschreib-/erweiterbar - ein neuer Objekttyp (z.B. `CREATE PUBLICATION`)
  wird ohne Codeänderung erkannt. Fehlt die Struktur, gelten die Defaults
  (bestehendes Verhalten unverändert); FP-Schutz (Wortgrenzen) bleibt.
- **Doku-/CLI-Konsistenztest** (`tests/test_doc_cli_consistency.py`): prüft
  zentrale Optionen und Profile aus `aci --help` gegen die HTML-Doku.

## [2.20.0] - 2026-05-29

Behebt die sieben Review-Findings aus dem Audit von ACI 2.19.0
(Redaction-Leak, Routine-Grenzen, STA-Kurzform, Snippet-Verschmelzung,
Pfadmaskierung, pg_reload_conf-Duplikate, Report-Leakage-Tests).

### Behoben
- **Finding 1 - PostgreSQL-/EPAS-Passwörter wurden trotz `--redact-secrets`
  geleakt** (bereits in 2.19.1): die DDL-Form `PASSWORD '<wert>'` ohne
  Zuweisungsoperator wird nun maskiert (inkl. `ENCRYPTED`/`UNENCRYPTED`,
  FDW-`OPTIONS (password '…')`, dynamischem `PASSWORD ' || '…'`); `PASSWORD
  NULL` bleibt unangetastet. In 2.20.0 durch eine harte, formatübergreifende
  Leakage-Test-Suite abgesichert (Finding 7).
- **Finding 2 - PostgreSQL-/EPAS-Routine-Grenzen.** Eine
  `CREATE FUNCTION/PROCEDURE`-Routine endet jetzt am Statement-Terminator
  (`;` nach dem dollar-quotierten Rumpf bzw. nach `LANGUAGE`/Optionen), nicht
  mehr am Datei-/nächsten-Routinen-Anfang. Statements *nach* einer Funktion
  (z. B. ein nachfolgender `DBMS_SQL.PARSE`-Block) werden nicht mehr
  fälschlich als Teil der SECURITY-DEFINER-Routine gewertet. Tagged Dollar
  Quotes (`$func$`), `SECURITY DEFINER` vor/nach `LANGUAGE` und
  `CREATE OR REPLACE` werden berücksichtigt.
- **Finding 3 - SQL*Plus-Kurzform `STA`.** `ACI-ORA-SQLPLUS-REMOTE-SCRIPT`
  (und die generische `RUN-SCRIPT`-/`RUN-SCRIPT-VAR`-Regel) erkennen jetzt
  `STA[RT]` (Oracle-Abkürzung), z. B. `STA http://…`, `STA ftp://…`,
  `STA https://…` - ohne `STATISTICS`/`STAT…` falsch zu treffen.
- **Finding 4 - Client-Directive-Snippets.** Findings für zeilenorientierte
  Direktiven (`@`/`@@`/`START`/psql-`\\`-Meta) zeigen nur noch die betroffene
  Zeile; aufeinanderfolgende Direktiven verschmelzen nicht mehr zu einem
  Snippet. Normale (mehrzeilige) SQL-Statements behalten ihren Kontext.
- **Finding 6 - `pg_reload_conf()`-Duplikate.** Die generische
  `ACI-PKG`-Warnung auf der Reload-Zeile wird entfernt, wenn dort bereits
  eine spezifischere EPAS-Reload-Regel (`ACI-EPAS-AUDIT-CONFIG-RELOAD` /
  `ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE`) greift. Andere
  `ACI-PKG`-Funktionsmeldungen bleiben unverändert.

### Hinzugefügt
- **Finding 5 - `--redact-paths`** (Gegenschalter `--no-redact-paths`):
  anonymisiert absolute Pfade in Report-Ausgaben (Verzeichnis → `<PATH>`,
  Dateiname bleibt erhalten; Unix-, Windows- und UNC-Pfade). Erfasst
  `target`, `finding.file`, `config.file`, `config.effective.*`-Pfade,
  `runtime.cwd`/`executable` und die rekonstruierte `command_line`. Relative
  Pfade bleiben unverändert. `--safe-report` impliziert `--redact-paths`.
  Neuer `aci.ini`-Schlüssel `redact_paths` (Default `false`).
- **Finding 7 - Report-Leakage-Tests** (`tests/test_report_leakage.py`):
  prüfen formatübergreifend (JSON, SARIF, HTML, Console) und über alle
  Redaction-Flag-Kombinationen, dass kein Testsecret im Report erscheint,
  der Redaction-Marker vorhanden ist (wenn Kontext aktiv), Findings und
  Rule-IDs sichtbar bleiben und unter `--safe-report` keine absoluten Pfade
  auftauchen.

### Geändert
- `--safe-report` maskiert jetzt zusätzlich absolute Pfade (über
  `--redact-paths`).

## [2.19.1] - 2026-05-29

### Behoben
- **`--redact-secrets` maskierte PostgreSQL-/EPAS-Passwörter nicht.** Die
  Redaction-Regel für `password` verlangte einen Zuweisungsoperator
  (`:=`/`=>`/`=`); die SQL-DDL-Form `PASSWORD '<wert>'` (Schlüsselwort +
  Whitespace, ohne Operator) blieb daher im Report im Klartext. Neue,
  dedizierte Regel maskiert `PASSWORD '<wert>'` inkl. der Varianten
  `ENCRYPTED PASSWORD '…'` / `UNENCRYPTED PASSWORD '…'`, FDW-Optionen
  (`OPTIONS (password '…')`) und des dynamischen Falls
  (`PASSWORD ' || 'geheim'`). Bewusst auf **quotierte Literale** beschränkt,
  damit z. B. `SELECT password FROM t` nicht fälschlich maskiert wird.

## [2.19.0] - 2026-05-29

Spezifische Erkennung von **Remote-Skriptaufrufen** über SQL*Plus/edbplus
(`@`, `@@`, `START` mit URL bzw. UNC-Netzwerkpfad).

### Hinzugefügt
- **`ACI-ORA-SQLPLUS-REMOTE-SCRIPT`** (Critical, TA0002 / T1105 Ingress Tool
  Transfer, CWE-829): erkennt `@`/`@@`/`START` mit `http://`, `https://`,
  `ftp://` oder UNC-Pfad (`//server…`, `\\server…`). Der Skriptpfad ist
  vollständig fremdbestimmt und wird über einen nicht authentifizierten
  Klartext-Transport geladen — höher bewertet als der variable lokale Pfad
  (`-VAR`, High). Whitespace-Varianten (`@ http://…`, `@@  ftp://…`) und
  `START` ohne Whitespace-Pflicht werden abgedeckt; `https://` wird als
  verdächtig gemeldet, obwohl Oracle es nicht ausführt. Reuse des bestehenden
  `client_directive`-Detektors (überspringt Kommentare und String-Literale).

### Geändert
- **`ACI-ORA-SQLPLUS-RUN-SCRIPT`** (Warning): Pattern schließt Remote-Fälle
  (URL/UNC) nun explizit aus, sodass jeder Skriptaufruf genau eine
  Klassifizierung erhält — REMOTE (Critical) bzw. VAR (High) vor
  generisch-lokal (Warning), keine Doppelmeldung. Zusätzlich `@@`-robuste
  Alternation (`@@|@(?!@)`), damit `@@http://…` nicht fälschlich als
  lokales Skript erkannt wird.

## [2.18.0] - 2026-05-29

Neue Regelgruppe **EPAS Audit Tampering / Audit Bypass**: spezifische
PostgreSQL-/EPAS-Regeln fuer das Abschalten/Schwaechen von Auditierung und
Logging, das Neuladen der Serverkonfiguration im audit-sensitiven Kontext,
die Manipulation von Konfigurationsdateien aus Skripten sowie das Verstecken
privilegierter Operationen hinter SECURITY-DEFINER-Funktionen. Minimal-invasiv;
bestehende Regel-IDs/Reporting-Formate unveraendert. Jede neue aktive Regel
hat einen positiven und negativen Harness-Case.

### Hinzugefuegt
- **EPAS-Audit ueber ALTER SYSTEM**: `ACI-EPAS-AUDIT-DISABLE-ALTER-SYSTEM`
  (Critical, CWE-778) fuer `edb_audit`/`edb_audit_statement = 'none'/'off'`;
  `ACI-EPAS-AUDIT-WEAKEN-ALTER-SYSTEM` (High) fuer `edb_audit_statement =
  'ddl'/'mod'` (schliesst `none` aus -> keine Doppelmeldung mit der
  Critical-Regel).
- **Logging ueber ALTER SYSTEM / SET**:
  `ACI-PG-AUDIT-LOGGING-DISABLE-ALTER-SYSTEM` (Critical, CWE-778) fuer
  `log_statement='none'`, `logging_collector=off`, `log_destination=''`,
  `log_min_duration_statement=-1`, `log_connections/disconnections=off`;
  `ACI-PG-AUDIT-LOGGING-WEAKEN-SET` (High) fuer `SET log_statement='none'`
  und `set_config('log_statement','none',...)`.
- **pg_reload_conf()-Kontext**: `ACI-EPAS-AUDIT-CONFIG-RELOAD` (High) fuer
  einen Reload ohne begleitende sensible Aenderung;
  `ACI-EPAS-AUDIT-RELOAD-AFTER-AUDIT-CHANGE` (Critical, CWE-778), wenn im
  selben Skript eine audit-/sicherheitsrelevante Aenderung vorkommt. Die
  beiden Regeln schliessen sich gegenseitig aus.
- **Konfig-Datei-Manipulation aus Skripten**:
  `ACI-EPAS-AUDIT-CONFIG-FILE-TAMPERING` (Critical, CWE-284) fuer
  Schreib-/Aenderungszugriffe (Editor, `sed -i`, Umleitung, `tee`, `cp/mv`,
  `chmod/chown` ...) auf `postgresql.auto.conf`;
  `ACI-PG-CONFIG-FILE-TAMPERING` (High) fuer `postgresql.conf`/`pg_hba.conf`/
  `pg_ident.conf` (disjunkte Dateimengen -> keine Doppelmeldung). Reiner
  Lesezugriff (`cat`/`less`/`grep` ...) wird nicht gemeldet.
- **SECURITY DEFINER mit privilegierter DDL**:
  `ACI-EPAS-SECURITY-DEFINER-ROLE-CREATION` (Critical, CWE-269) erkennt
  CREATE/ALTER/DROP ROLE|USER, GRANT/REVOKE, ALTER DEFAULT PRIVILEGES,
  ALTER SYSTEM, CREATE EXTENSION/SERVER/USER MAPPING, COPY ... PROGRAM im
  Rumpf einer SECURITY-DEFINER-Routine - statisch und dynamisch
  (`EXECUTE '...'`). Strikt auf den Routinen-Rumpf begrenzt.
- **Audit-Bypass-Kandidat**:
  `ACI-EPAS-FUNCTION-CALL-AUDIT-BYPASS-CANDIDATE` (High, CWE-269) meldet den
  spaeteren Aufruf einer solchen privilegierten SECURITY-DEFINER-Routine
  (schemaqualifizierte Namen unterstuetzt).
- Dedizierte Tests in `tests/test_epas_audit_tampering.py` (31 Faelle) sowie
  je ein positiver/negativer Harness-Case pro neuer Regel.

### Geaendert
- Verbesserte PostgreSQL-/EPAS-Audit-Bypass-Abdeckung; `pg_reload_conf()`
  wird im audit-sensitiven Kontext mit hoeherer Severity gemeldet (bestehende
  generische Warning-Erkennung bleibt erhalten).

### Hinweise / Grenzen
- ACI scannt SQL-/PL/pgSQL-Skripte (`.sql`, `.pgsql`, ... - **keine**
  `.conf`-Dateien). Audit-Parameter direkt in `postgresql.auto.conf` werden
  daher nur erkannt, wenn die Aenderung *aus einem gescannten Skript heraus*
  erfolgt (z. B. `\! sed -i ... postgresql.auto.conf`). Reine OS-seitige
  Editierung der Datei ausserhalb gescannter Skripte ist statisch nicht
  erkennbar - siehe Abschnitt "Runtime forensic checks outside ACI static
  analysis" in der README.
- Kein neues `ACI-EPAS-CREATE-SUPERUSER-ACCOUNT`: Superuser-Erstellung ist
  bereits durch `ACI-PG-ADMIN-CREATE-ROLE-PRIVILEGED` /
  `ACI-PG-ADMIN-ALTER-ROLE-PRIVILEGED` abgedeckt (nur Testabdeckung ergaenzt).

## [2.17.0] - 2026-05-28

Deutliche, minimal-invasive Erweiterung der PostgreSQL-/EPAS-Sicherheitsregeln:
EPAS Oracle-kompatible Pakete (UTL_*/DBMS_*) sowie zusätzliche PostgreSQL-
native Defense-Evasion-, Privilege-Escalation- und Credential-Access-Regeln.
Keine bestehenden Regel-IDs oder Reporting-Formate geändert; jede neue aktive
Regel hat einen positiven und negativen Harness-Case.

### Hinzugefügt
- **EPAS Oracle-kompatible Paketregeln** (greifen sowohl in dollar-quoted
  PL/pgSQL-Bodies als auch in Oracle-Stil-Bodies, da der Body-Inhalt nicht als
  String maskiert wird):
  - `ACI-EPAS-SCHEDULER-EXECUTABLE` (Critical, TA0002/T1059, CWE-78) –
    `DBMS_SCHEDULER`-Job mit `job_type => 'EXECUTABLE'` (OS-Befehl).
  - `ACI-EPAS-DBMS-SQL` (High, TA0002/T1059, CWE-89) – dynamisches SQL über
    `DBMS_SQL.PARSE/EXECUTE`.
  - `ACI-EPAS-SCHEDULER-CREATE-JOB` (High, TA0003/T1053, CWE-250) –
    `DBMS_SCHEDULER.CREATE_JOB` / `DBMS_JOB.SUBMIT` (Persistenz).
  - `ACI-EPAS-UTL-FILE` (High, TA0009/T1005, CWE-73) – Server-Dateizugriff.
  - `ACI-EPAS-UTL-HTTP` (High, TA0010/T1071, CWE-918) – ausgehender Web-Request.
  - `ACI-EPAS-UTL-TCP` (High, TA0010/T1095, CWE-918) – rohe TCP-Verbindung.
  - `ACI-EPAS-UTL-SMTP` (High, TA0010/T1048, CWE-200) – E-Mail-Versand.
- **PostgreSQL-native Regeln**:
  - `ACI-PG-SESSION-REPLICATION-ROLE` (High, TA0005, CWE-693) –
    `SET session_replication_role` (deaktiviert Trigger/FK-/Audit-Durchsetzung).
  - `ACI-PG-SET-ROW-SECURITY-OFF` (High, TA0005, CWE-693) –
    `SET row_security = off/false` (umgeht RLS für die Sitzung).
  - `ACI-PG-REASSIGN-OWNED` (High, TA0004/T1098, CWE-269) – `REASSIGN OWNED BY`.
  - `ACI-PG-READ-PG-AUTHID` (High, TA0006/T1003, CWE-522) – Lesen von
    `pg_authid` / `pg_shadow` (gespeicherte Passwort-Hashes).
- Pro neuer Regel ein positiver und negativer Eintrag in
  `tests/rules/postgresql/mitre/cases.json` sowie dedizierte Tests in
  `tests/test_new_security_rules.py` (inkl. Masking-/FP-Abgrenzung).

### Hinweise
- Bewusst **nicht** dupliziert (bereits abgedeckt): Grants auf
  vordefinierte Rollen wie `pg_read_all_data`/`pg_monitor` etc.
  (`ACI-PG-ADMIN-GRANT-SYSTEM-ROLE`), `BYPASSRLS` in CREATE/ALTER ROLE
  (`ACI-PG-ADMIN-CREATE/ALTER-ROLE-PRIVILEGED`), RLS-Abschaltung/Policy-Änderung
  (`ACI-PG-RLS-DISABLE`/`ACI-PG-RLS-POLICY-CHANGE`), `ALTER SYSTEM`
  Preload/Archive (`ACI-PG-CONFIG-CRITICAL-PRELOAD-OR-ARCHIVE`),
  `GRANT ... TO PUBLIC` (`T1098`).
- Bewusst **zurückgestellt** (zu hohe Falsch-Positiv-Rate in Migrationsskripten):
  generisches `ALTER ... OWNER TO`, `DROP CONSTRAINT`, `ADD CONSTRAINT ... NOT
  VALID`. Diese erfordern Kontext (Zielrolle/Tabelle) für ein sinnvolles Signal.

## [2.16.0] - 2026-05-28

Härtung der CI/CD-Integration (Ruleset-Lock, explizite Config-Steuerung,
Audit-Metadaten, boolesche Gegenschalter), genaueres SQL*Plus-Substitutions-
Modell und eine psql-Meta-Command-Normalisierung; gepinnte Dev-Toolchain und
korrigierte Lizenz-Metadaten.

### Hinzugefügt
- **Expected-Ruleset-SHA256-Verifikation** für harte CI/CD-Gates:
  `--expected-ruleset-sha256 <64-hex>` und `--ruleset-lock <pfad>` (JSON mit
  `ruleset_sha256`). Bei Abweichung/ungültigem Hash/Konflikt fail-closed mit
  Exit-Code 2 (erwarteter + tatsächlicher Hash und beteiligte Regeldateien in
  der Meldung). Vergleich case-insensitiv. Report-Block `ruleset_integrity`
  (`actual_sha256`/`expected_sha256`/`verified`/`source`).
- **Explizite Config-Steuerung**: `--config <pfad>` (lädt ausschließlich diese
  Datei; fehlend/ungültig → Exit 2), `--no-config` (keine aci.ini laden),
  `--print-effective-config` (effektive Konfiguration als JSON, ohne Secrets,
  und beenden). `--config` + `--no-config` zusammen → Exit 2. Report-Block
  `config` (`mode`/`file`/`effective`).
- **Runtime-, Gate- und Config-Metadaten** in JSON/SARIF/HTML: `runtime`
  (Version, Python, Plattform, executable, cwd, Startzeit, Dauer), `gate`
  (Profil, fail_on, strikte Flags, erwarteter/tatsächlicher Ruleset-Hash,
  `passed`, `exit_code`). Unter `--safe-report`/`--redact-secrets` werden
  cwd/executable maskiert.
- **Boolesche Gegenschalter** für alle sicherheitsrelevanten Flags:
  `--no-strict-internal-errors`, `--no-strict-waivers`,
  `--no-require-trusted-rules`, `--no-redact-secrets`, `--no-follow-symlinks`
  (via `argparse.BooleanOptionalAction`, Python-3.9-kompatibel) sowie
  `--unsafe-report` (zu `--safe-report`) und `--context` (zu `--no-context`).
  Präzedenz: Defaults < Config < Profil < explizite CLI-Option.
- **SQL*Plus `SET DEFINE <char>`-Modellierung**: Substitutions-State-Machine
  mit `define_enabled` + aktivem Zeichen. `SET DEFINE ^` erkennt `^var` (und
  nicht mehr `&var`), `SET DEFINE &`/`ON` stellen `&` wieder her, `SET SCAN
  OFF/ON` wirkt analog. Mehrere Wechsel pro Datei werden abschnittsweise
  berücksichtigt.
- **psql-Meta-Command-Normalisierung** (`aci/checks/psql_meta.py`,
  `parse_psql_meta_line` + `PsqlMetaCommand`): die psql-Regeln (`\!`, `\copy …
  PROGRAM`, `\o`/`\g`-Pipe, `\o`-Datei, `\set`-Backquote, `\setenv`/`\getenv`,
  `\i`/`\ir`/`\include`) laufen jetzt über das normalisierte Modell statt über
  Roh-Regex - robust gegen Whitespace-/Tab-Varianten.
- **Corpus-/Snapshot-Tests** (`tests/corpus/`, `tests/test_corpus.py`):
  realistische Oracle-/PostgreSQL-/Liquibase-/Flyway-Dateien mit erwarteten
  Findings; kaputtes SQL darf den Scanner nicht crashen.

### Geändert
- **Reproduzierbare Dev-Toolchain**: `pytest>=7,<10`, `ruff>=0.8,<0.16`,
  `mypy>=1.10,<2.2` in `[project.optional-dependencies].dev`; mypy-`python_version`
  auf `3.10` (Code bleibt 3.9-kompatibel).
- **Lizenz-Metadaten** korrigiert: `license = "MIT AND Apache-2.0"` (zuvor nur
  MIT) plus Apache-Classifier - konsistent mit NOTICE/README (eigener Code MIT,
  abgeleitete Trivadis-Oracle-Guidelines Apache-2.0).

### Behoben
- Weniger False Negatives rund um den SQL*Plus-Substitutionszeichen-Wechsel
  (`SET DEFINE ^`).
- Robusteres Erkennen von psql-Client-Kommandos bei Whitespace-/Tab-Varianten.

## [2.15.0] - 2026-05-28

Verbesserte Client-/Deployment-Skript-Erkennung (SQL*Plus, edbplus, psql):
variable Skriptpfade, `\copy … PROGRAM`/`\gexec`, `HOST`-Migration, schärfere
`&`-Substitution mit ACCEPT-Korrelation, `SET DEFINE OFF`-Bewusstsein,
psql `\set`-Backtick/`\setenv` und `WHENEVER … CONTINUE`.

### Hinzugefügt / Geändert (Client-/Deployment-Skript-Erkennung, Phase 1)
- **Variable Skriptpfade (Oracle):** neue Regel `ACI-ORA-SQLPLUS-RUN-SCRIPT-VAR`
  (High) für `@&var` / `@@&var` / `START &var` - der ausgeführte Skriptpfad
  stammt aus einer Substitutionsvariable und ist damit zur Laufzeit steuerbar.
  Die generische `ACI-ORA-SQLPLUS-RUN-SCRIPT`-Regel (Warning) schließt den
  `&`-Fall jetzt aus (keine Doppel-Findings).
- **psql `\copy … PROGRAM` (High):** neue Regel `ACI-PG-PSQL-COPY-PROGRAM` -
  clientseitige Programm-Pipe = OS-Befehl. Die generische `\copy`-Regel
  (`ACI-PG-COPY-CLIENT-FILE`) klammert den PROGRAM-Fall jetzt aus.
- **psql `\gexec` (High):** neue Regel `ACI-PG-PSQL-GEXEC` - führt
  generiertes SQL ungeprüft aus (dynamische SQL-Ausführung auf Client-Ebene).
- **`HOST`/`!` migriert:** die Regel `T1059` (SQL*Plus HOST) nutzt jetzt den
  `client_directive`-Detektor statt einer separaten Regex - konsistent mit den
  übrigen Client-Direktiven und nun auch string-/kommentarsicher.
  (`aci/rules/mitre/oracle/ta0002_execution.json`,
  `aci/rules/mitre/postgresql/ta0002_execution.json`,
  `aci/rules/mitre/postgresql/ta0009_collection.json`)

### Hinzugefügt / Geändert (Client-Skript-Erkennung, Phase 1 - Schritt 2)
- **`&`-Substitution FP-Reduktion (Oracle):** `ACI-ORA-SQLPLUS-SUBSTITUTION`
  greift jetzt nur noch, wenn die Zeile einen sicherheitsrelevanten Kontext
  hat (`CREATE`/`ALTER`/`DROP`/`GRANT`/`REVOKE`/`EXECUTE IMMEDIATE`/
  `IDENTIFIED BY`) - statt jeder beliebigen `&var`-Verwendung. Deutlich
  weniger Rauschen in realen Skripten (reine Wert-Substitution in `SELECT`
  wird bewusst nicht mehr gemeldet).
- **ACCEPT/DEFINE → `&var`-Kombination (Oracle, High):** neuer Builtin
  `sqlplus_substitution` + Regel `ACI-ORA-SQLPLUS-ACCEPT-SUBSTITUTION`. Meldet
  gezielt Variablen, die per `ACCEPT`/`DEFINE` (oft interaktive Eingabe) gesetzt
  und später als `&var` textuell in SQL eingesetzt werden - der eigentlich
  gefährliche Injection-Pfad. Hohe Signalstärke (nur ACCEPT/DEFINE-Namen),
  Dedup pro Variable, kommentarsicher.
  (`aci/checks/detectors.py`, `aci/rules/mitre/oracle/ta0002_execution.json`)

### Hinzugefügt / Geändert (Client-Skript-Erkennung, Phase 2)
- **`SET DEFINE OFF`/`SET SCAN OFF`-Bewusstsein:** In Regionen, in denen die
  Substitution deaktiviert ist, ist `&` ein normales Zeichen - `&`-Treffer
  dort werden jetzt unterdrückt (kein FP). Greift für die generische
  Substitutionsregel (`client_directive`, neuer opt-in `respect_set_define`)
  und für `sqlplus_substitution`. (`aci/checks/detectors.py`,
  `aci/rules/mitre/oracle/ta0002_execution.json`)
- **psql `\set` mit Backquote (High):** `ACI-PG-PSQL-SET-BACKTICK` -
  `\set v `cmd`` führt einen Shell-Befehl aus (OS-Command-Vektor).
- **psql `\setenv`/`\getenv` (Warning):** `ACI-PG-PSQL-ENV` - Umgebungs-
  variablen-Manipulation/-Lesen (env-Werte können in Subprozesse oder per
  `:var` in SQL einfließen).
- **`WHENEVER SQLERROR/OSERROR CONTINUE` (Warning):**
  `ACI-ORA-SQLPLUS-WHENEVER-CONTINUE` - das Skript läuft nach Fehlern weiter;
  fehlgeschlagene sicherheitsrelevante Schritte (REVOKE/Grants) können
  unbemerkt übergangen werden. (`aci/rules/mitre/postgresql/ta0002_execution.json`,
  `aci/rules/mitre/oracle/ta0002_execution.json`)

## [2.14.0] - 2026-05-28

Sammelrelease: die urspruenglichen 2.13.0-Bugfixes (format()/Dollar-Quote/
Redaction/RETURNING) plus umfangreiche neue Erkennungsabdeckung (EPAS-Pakete,
PostgreSQL-Namenskonventionen, aus Oracle portierte PG-Guidelines, zusaetzliche
Security-Regeln, Client-/Deployment-Skript-Direktiven und APEX/ORDS Phase 1-3).

### Behoben (Sicherheit)
- **SQL-Injection – False Negative bei `format()` in Konkatenation**: Ein
  `format()`-Aufruf als Operand einer `||`-Verkettung wurde pauschal als
  Sanitizer (Severity *Warning*) gewertet, unabhängig vom Platzhalter. Da
  `%s` *nicht* escaped, blieb z.B. `'... ' || format('%s', x)` eine
  übersehene Injection. Der Operand wird nun über dieselbe Platzhalter-Logik
  wie ein Top-Level-`format()` bewertet (`%I`/`%L` entschärfend, `%s`
  kritisch). (`aci/checks/sqli.py`)
- **SQL-Injection – False Positive bei Dollar-/q-Quote-Literalen**: Ein `||`
  *innerhalb* eines PostgreSQL-Dollar-Quote-Literals (`$tag$…$tag$`) oder
  eines Oracle-q-Quotes wurde fälschlich als Top-Level-Konkatenations-
  Operator behandelt; das Literal wurde zerteilt und die Fragmente als
  getaintet gemeldet (Severity *Critical* auf harmlosem Code). `_split_top_level`
  überspringt diese Literale jetzt, und Dollar-Quotes werden in der Operanden-
  Klassifikation als `literal` erkannt. (`aci/parser.py`, `aci/checks/base.py`)
- **Redaction deckte Taint-Quellen nicht ab**: `--redact-secrets`/`--safe-report`
  maskierte nur Fundort-Snippet/-Kontext, nicht die zusätzlichen Fundstellen
  (`related` – z.B. die Taint-Quellen des SQL-Injection-Checks). Ein Geheimnis
  in einer Taint-Quell-Zeile konnte so trotz Redaction in JSON/HTML/SARIF
  gelangen. `_redact_results` redigiert jetzt auch `related`-Snippet/-Kontext.
  (`aci/cli.py`)
- **Redaction-Muster für dynamisches SQL erweitert**: Geheimnisse, die per
  `||` an ein Schlüsselwort angehängt sind (`… IDENTIFIED BY ' || 'geheim'`)
  oder mit SQL-`''`-Escapes in dynamischem SQL stehen (`password => ''geheim''`),
  wurden von der Heuristik nicht erfasst. Die Muster decken diese Fälle nun ab.
  (`aci/cli.py`)

### Hinzugefügt
- **APEX / ORDS Security (Phase 1, Oracle, heuristisch)**: erste Abdeckung der
  bislang fehlenden APEX-/ORDS-Angriffsflaeche. APEX Page Items / Session State
  (`:P1_x`, `V('P1_x')`, `APEX_UTIL.GET_SESSION_STATE`) gelten als
  benutzerkontrollierte Taint-Quellen. Neue Regeln in
  `aci/rules/mitre/oracle/apex_ords.json` + zwei Builtins
  (`aci/checks/detectors.py`):
  - `ACI-APEX-DYNSQL-SESSION-STATE` (Builtin `apex_concat_sql`): SQL, das per
    `||` aus Session State gebaut und per RETURN zurueckgegeben wird -
    erkennt das zentrale Muster "PL/SQL Function Body returning SQL" /
    Region Source **ohne** EXECUTE-Sink (das war die eigentliche Luecke; echte
    EXECUTE-/OPEN-FOR-Sinks deckt weiterhin der SqlInjectionCheck ab).
  - `ACI-APEX-SSRF-REST` / `ACI-APEX-XSS-HTP` (Builtin `apex_tainted_sink`):
    SSRF ueber `APEX_WEB_SERVICE.MAKE_REST_REQUEST` bzw. XSS ueber
    `HTP.P`/`HTP.PRN`/`OWA_UTIL.CELLSPRINT`, jeweils nur bei `||`-Konkatenation
    eines APEX Items (rein literale Konkatenation loest nichts aus).
  - `ACI-ORDS-AUTOREST-ENABLE` (Regex): `ORDS.ENABLE_OBJECT`/`ENABLE_SCHEMA`.
  - `ACI-APEX-WEAK-AUTHZ` (Regex, `enabled:false`): Autorisierung allein ueber
    `APP_USER`/`G_USER` - bewusst deaktiviert (heuristisch, FP-anfaellig).

  Grenze (bewusst, Phase 1): handgeschriebener PL/SQL-Code. APEX-Export-Dateien
  (Code in `wwv_flow_api`-String-Argumenten) erfordern einen Region-Extractor
  (Phase 3) und werden noch nicht entmaskiert gescannt.
- **APEX / ORDS Security (Phase 2)**:
  - *APEX-bewusste SQL-Injection-Kennzeichnung (Kern-Check):* der
    `SqlInjectionCheck` erkennt APEX Page Items / Session State
    (`:P1_x`, `V('…')`, `APEX_UTIL.GET_SESSION_STATE`) jetzt als eigene,
    benannte Taint-Quelle (`source="apex"`, 1st-order). Bereits zuvor erkannte
    Treffer in echten Sinks (EXECUTE IMMEDIATE / OPEN FOR / dyn. Cursor)
    werden damit praezise als „APEX Page Item / Session State
    (benutzerkontrolliert)" gemeldet statt generisch. Rein konfigurations-
    getrieben (`sql_injection.apex_taint_patterns` in `oracle.json`) - ohne
    diese Liste unveraendertes Verhalten. (`aci/checks/sqli.py`, `oracle.json`)
  - *Breite:* `ACI-APEX-MAIL-EXFIL` (APEX_MAIL mit Item-Konkatenation),
    XSS-Sink-Muster um `HTP.PRINTS`/`HTP.PS` erweitert.
  - *CI/CD-Profil `apex`* (`--profile apex`): Sicherheitsgruppe mit Kontext &
    Taint-Quellen, ohne Build-Blockade - fuers gezielte APEX-/ORDS-Review.
    (`aci/cli.py`)
  - ORDS-Handler-Binds (`:param`) in dynamischem SQL sind bereits durch die
    generische SQL-Injection-Erkennung abgedeckt; eine *praezise* ORDS-Quellen-
    Kennzeichnung ist ohne Handler-Metadaten nicht zuverlaessig moeglich
    (bewusst offen, vgl. Phase 3).
- **APEX / ORDS Security (Phase 3 - Export-Dateien)**: `ACI-APEX-EXPORT-DYNSQL`
  (Builtin `apex_export_code_sql`) erkennt SQL, das per `||` aus Session State
  in einem code-tragenden `wwv_flow_api`-Export-Argument gebaut wird
  (`p_plug_source`, `p_query`, `p_function_body`, `p_plsql_code`, ...). Der
  Code lebt in Export-Dateien *innerhalb* von String-Literalen und ist daher
  fuer die regulaeren Checks maskiert; der Detektor extrahiert den Literal-
  Inhalt, hebt `''`-Escapes auf und wendet dieselbe APEX-Heuristik auf das
  Fragment an. Damit werden erstmals *exportierte* APEX-Apps abgedeckt. Grenze
  (erste Ausbaustufe): nur einfache `'...'`-Literale; ueber
  `wwv_flow_string.join(...)`/`||` gesplitteter Code und q-Quote-Argumente
  werden noch nicht zusammengesetzt.
  (`aci/checks/detectors.py`, `aci/rules/mitre/oracle/apex_ords.json`)
- **Client-/Deployment-Skript-Direktiven (SQL\*Plus, edbplus, psql)**: neuer
  kommentar-/string-sicherer Builtin `client_directive`, der auf dem *rohen*
  Quelltext arbeitet (die SQL\*Plus-Direktiven werden vom Lexer maskiert und
  waren daher fuer Regex-Checks unsichtbar). Neue MITRE-Regeln:
  - *Oracle/EPAS (edbplus)*: `ACI-ORA-SQLPLUS-RUN-SCRIPT` (`@`/`@@`/`START`),
    `ACI-ORA-SQLPLUS-SPOOL`, `ACI-ORA-SQLPLUS-SUBSTITUTION` (`&`/`&&`,
    erkennt auch innerhalb von String-Literalen), `ACI-ORA-SQLPLUS-ACCEPT`
    (ACCEPT/DEFINE). `HOST`/`!` waren bereits via T1059 abgedeckt.
  - *PostgreSQL (psql)*: `ACI-PG-PSQL-SHELL` (`\!`), `ACI-PG-PSQL-PIPE`
    (`\o`/`\g` Pipe an Programm), `ACI-PG-PSQL-INCLUDE` (`\i`/`\ir`/`\include`),
    `ACI-PG-PSQL-OUTPUT-FILE` (`\o`/`\out` in Datei). `\copy` war bereits
    abgedeckt.
  (`aci/checks/detectors.py`, `aci/rules/mitre/oracle/ta0002,ta0010`,
  `aci/rules/mitre/postgresql/ta0002,ta0009`)
- **Aus Oracle portierte PostgreSQL-Coding-Guidelines**: dialektneutrale
  Ideen aus dem Oracle-/Trivadis-Regelsatz auf PL/pgSQL übertragen. Neu aktiv:
  `PG-1080` (gleicher Ausdruck beidseits eines Vergleichs), `PG-3110` (INSERT
  ohne Spaltenliste), `PG-3190` (NATURAL JOIN), `PG-4270` (Boolean-Vergleich
  mit TRUE/FALSE), `PG-7125` (CREATE ohne OR REPLACE). Zusätzlich als
  dokumentiert/`enabled:false` (turnkey aktivierbar): `PG-2210`
  (numeric/decimal ohne Präzision), `PG-2310` (char(n) statt text), `PG-2330`
  (Oracle-Migrationsfalle: `'' IS NOT NULL` in PostgreSQL). Aktive
  PG-Guidelines damit 16 → 21. (`aci/rules/guidelines/postgresql/g_postgresql.json`)
- **Erweiterte Security-Abdeckung (regelbasiert, MITRE)**: neue Detektoren und
  Regeln schließen Lücken bei Credentials, AuthZ und weiteren Injektionsarten.
  - *Hardcoded Secrets (PostgreSQL)*: `T1552-VAR` verdrahtet den
    dialektneutralen `hardcoded_password`-Detektor jetzt auch für PL/pgSQL
    (passwortartig benannte Variable := String-Literal). Oracle war bereits
    abgedeckt.
  - *AuthZ (Oracle)*: `T1548-DYNAMIC-SQL` (neuer Builtin `definer_dynamic_sql`)
    meldet die kritische Kombination AUTHID DEFINER + dynamisches SQL je
    Ausführungsstelle (höheres Signal als die bloße AUTHID-DEFINER-Regel);
    `T1548-SET-ROLE` meldet `DBMS_SESSION.SET_ROLE`. Das PostgreSQL-Pendant
    (`SECURITY DEFINER` + dyn. SQL, `SET ROLE`) existierte bereits.
  - *Injektionen (Oracle)*: `ACI-ORA-LDAP-INJECTION` (DBMS_LDAP) und
    `ACI-ORA-XPATH-INJECTION` (EXTRACTVALUE/EXISTSNODE/XMLQUERY/XMLTABLE) über
    den neuen, konservativen Builtin `tainted_concat_sink` – meldet nur bei
    `||`-Konkatenation in derselben Anweisung (rein literale Ausdrücke lösen
    nichts aus). OS-Command-Injection (HOST/`!`, Java, DBMS_MLE, EXECUTABLE-
    Jobs, EXTPROC; PostgreSQL: COPY PROGRAM/LOAD/LANGUAGE C) war bereits
    abgedeckt.
  (`aci/checks/detectors.py`, `aci/rules/mitre/oracle/*`,
  `aci/rules/mitre/postgresql/ta0006_credential_access.json`)
- **`ACI-PKG` PostgreSQL/EPAS-Konsistenz**: `DBMS_LOB` (Warning) ergänzt – wird
  von EPAS bereitgestellt und war in der Oracle-Liste, fehlte aber in der
  PostgreSQL-Liste. Zusätzlich die EPAS-Pakete `UTL_MAIL` (High), `UTL_URL`
  (Warning) und `UTL_ENCODE` (Warning) aufgenommen. `UTL_TCP` entfernt: EPAS
  implementiert kein UTL_TCP, der Eintrag konnte nie greifen.
  (`aci/rules/postgresql.json`)
- **PostgreSQL-Namenskonventionen** (`PG-NC-1010`, `PG-NC-1020`): Bislang gab
  es Namens-/Bezeichner-Regeln nur für Oracle (Trivadis-Präfixe `G-NC-1010`,
  Kurz-Bezeichner `G-2185`). Für PostgreSQL prüft ACI jetzt dialektgerecht
  `snake_case` (neuer Builtin-Detektor `snake_case_identifier`, meldet
  CamelCase/Großbuchstaben in unquoteten Deklarationen) sowie zu kurze
  Bezeichner (`short_identifier`, min. 3 Zeichen). (`aci/checks/detectors.py`,
  `aci/rules/guidelines/postgresql/g_postgresql.json`)
- **`RETURNING … INTO` als 2nd-order-Taint-Quelle**: Aus DML zurückgegebene
  Werte (`INSERT/UPDATE/DELETE … RETURNING … INTO ziel`) werden nun als
  eigener Schreibzugriff (`returning_into`) erkannt und korrekt als 2nd-order
  (Wert aus Tabelle/Cursor) typisiert. (`aci/parser.py`, `aci/checks/sqli.py`,
  `aci/checks/base.py`, `aci/ir.py`)

### Geändert / Performance
- **Doppelte lexikalische Analyse beseitigt**: `Source` lexte eine Datei und
  `parse_ir` ein weiteres Mal. `parse_ir` übernimmt jetzt optional das
  vorhandene Lex-Ergebnis – nur noch ein Lex-Durchlauf pro Datei.
  (`aci/parser.py`, `aci/source.py`)

### Aufgeräumt
- Tote Lexer-Fallback-Pfade entfernt: Da `Source` die IR immer aufbaut, waren
  die dualen IR-/Lexer-Codepfade in `_assignments_before`/`_collect_var_writes`
  sowie die `else source.dynamic_sql`-Zweige (in `sqli`, `lexical`, `ddl`,
  `detectors`) unerreichbar. (`aci/checks/`)

### Dokumentation
- HTML-Gesamtdokumentation auf 2.14.0 gehoben; Inkonsistenzen korrigiert
  („vier" statt „drei" Ausgabeformate, Regelzahl). Die redundante Wurzel-Kopie
  `ACI_Dokumentation.html` entfernt – einzige Quelle ist nun `docs/`.
- Docstring `_load_mitre` korrigiert (MITRE gilt für Oracle **und** PostgreSQL).
- `ACI_BESCHREIBUNG.md`: Guideline-Anzahl und MITRE-Taktik-Aufzählung
  präzisiert. README: `--no-color` und der `--dialect postgres`-Alias
  dokumentiert. `find_ruleset`-Fehlermeldung nennt alle akzeptierten Aliase.
- `pyproject.toml`: Hinweis ergänzt, dass `[tool.mypy] python_version = "3.9"`
  ein älteres mypy (< 1.18) voraussetzt.

### Tests
- 16 neue Regressionstests: `format('%s')`/`%I` in Konkatenation,
  Dollar-/q-Quote-Split-Verhalten, `RETURNING … INTO`-2nd-order-Taint,
  Redaction von Taint-Quellen und von Geheimnissen in dynamischem SQL sowie
  die neuen PostgreSQL-Namenskonventionen (`PG-NC-1010`/`PG-NC-1020`) sowie
  die EPAS-Paketabdeckung (`DBMS_LOB`/`UTL_MAIL`/`UTL_URL`/`UTL_ENCODE`,
  entferntes `UTL_TCP`), die neuen Security-Regeln (AUTHID DEFINER +
  dyn. SQL, SET_ROLE, LDAP-/XPath-Injection, PG-Hardcoded-Secret) sowie die
  aus Oracle portierten PG-Guidelines (`PG-1080`/`3110`/`3190`/`4270`/`7125`)
  sowie die Client-/Skript-Direktiven (SQL\*Plus/edbplus & psql) und die
  APEX-/ORDS-Regeln (Phase 1-3).
  Gesamtzahl: 783 Tests (zuvor 707).
