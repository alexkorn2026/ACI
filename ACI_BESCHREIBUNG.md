# ACI – Automated Code Inspection

## Was ist ACI?

ACI ist ein statischer Sicherheits- und Coding-Guidelines-Scanner für Datenbank-Code — Oracle PL/SQL und PostgreSQL PL/pgSQL. ACI führt den Quelltext nicht aus, sondern analysiert ihn lexikalisch und liefert in Sekunden eine konkrete Audit-Sicht: SQL-Injection-Risiken, riskante DDL, verschleierter Code, MITRE-ATT&CK-Angriffsindikatoren und Wartbarkeits-Findings — alles mit Datei, Zeile, Statement-Snippet und Handlungsempfehlung.

## Was wird geprüft?

Zwei klar getrennte Prüfgruppen, jede mit eigener Schweregrad-Skala. Die Gruppe **Sicherheit** deckt SQL-Injection (mit Taint-Quellen-Tracking, 1st-/2nd-Order-Klassifikation und eigener Eskalation für PL/SQL-Block-Injection), DDL im Code (GRANT/CREATE/ALTER/DROP, inklusive externer Tabellen), unerwünschte Pakete (DBMS_CRYPTO, UTL_HTTP, UTL_FILE, DBMS_SQL, …), Obfuskation (Base64/Hex/CHR-Ketten, Oracle-WRAP) sowie ein MITRE-ATT&CK-Indikatoren-Set über die relevanten Taktiken (u.a. Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Lateral Movement, Exfiltration, Impact sowie – für Oracle – Resource Development und Defense Impairment) ab. Hinzu kommen heuristische Regeln für **Client-/Deployment-Skripte** (SQL\*Plus, edbplus, psql: `HOST`/`!`, `@`/`@@`, `SPOOL`, `&`-Substitution, `\!`/`\i`/`\o`-Pipes) und für **Oracle APEX & ORDS** (APEX Page Items / Session State als benutzerkontrollierte Taint-Quelle, „PL/SQL Function Body returning SQL" – auch in APEX-Export-Dateien –, SSRF über `APEX_WEB_SERVICE`, XSS über `HTP.*`, ORDS-AutoREST-Exposition). Die Gruppe **Coding Guidelines** wertet Oracle-Code gegen die Trivadis PL/SQL & SQL Coding Guidelines (über 30 aktive Regeln) und PostgreSQL-Code gegen ACI-eigene PL/pgSQL-Regeln (Namenskonventionen, aus Oracle portierte Muster) aus.

## Wie funktioniert es?

ACI ist bewusst kein vollständiger SQL-Compiler, sondern ein heuristischer Scanner aus klar getrennten Schichten: Lexer (Strings, Kommentare, Dollar-Quoting, Statement-Grenzen, SQL\*Plus-Direktiven), leichte Intermediate Representation (Routinen, Zuweisungen, dynamische SQL-Ausdrücke), Check-Klassen je Sicherheitsdomäne und externe JSON-Regeldateien für Mustererkennung, MITRE-Mappings und Ausnahmelisten. Regeln sind Daten — neue Pattern, Schweregrade und Whitelisten werden ohne Code-Änderung gepflegt. Findings haben einen stabilen, inhaltsgebundenen Fingerprint (Waiver-fähig), Snippet und Kontext klemmen exakt auf das beanstandete Statement, und SQL\*Plus-Direktiven, Java-Bodies und Kommentare bleiben außerhalb des Findings.

## Wie nutzt man es?

ACI benötigt nur die Python-Standardbibliothek — keine externen Abhängigkeiten, installierbar via `pip install` oder direkt als `python -m aci`. Vier Report-Formate (Console, JSON, HTML, SARIF), CI/CD-Integration über Exit-Codes mit `--fail-on`-Schwelle, vorkonfigurierte Profile (`--profile ci`) für Audit-Läufe und Waiver-Dateien für genehmigte Ausnahmen. Der eigene ACI-Code und die PostgreSQL-Guideline-Regeln stehen unter der MIT-Lizenz, die Oracle-Guideline-Regeln basieren auf den Trivadis-Guidelines v4.4 (Apache 2.0) — eindeutig auseinandergehalten und unbedenklich für den kommerziellen Einsatz.
