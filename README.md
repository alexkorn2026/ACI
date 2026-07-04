# ACI – Automated Code Inspection

[![License: MIT AND Apache-2.0](https://img.shields.io/badge/license-MIT%20AND%20Apache--2.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-2.23.0-green.svg)](CHANGELOG.md)
[![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](pyproject.toml)

**ACI** ist ein heuristischer, statischer Sicherheits- und Coding-Guidelines-Scanner
für **Oracle PL/SQL** und **PostgreSQL PL/pgSQL**. ACI führt den Code nicht aus,
sondern analysiert ausschließlich den übergebenen Quelltext – ohne Datenbankverbindung
und ohne externe Abhängigkeiten (nur Python-Standardbibliothek).

## Features

- **Sicherheits-Checks** – SQL-Injection (mit Taint-Analyse), unerwünschte Packages,
  obfuskierter Code, DDL im Code und Namenskonventionen, ergänzt um
  **MITRE-ATT&CK**-Angriffsindikatoren. Schweregrade: Warning, High, Critical.
- **Coding Guidelines** – für Oracle nach den *Trivadis PL/SQL & SQL Coding Guidelines*,
  für PostgreSQL ein eigener PL/pgSQL-Regelsatz. Schweregrade: Info, Minor, Major,
  Critical, Blocker.
- **Leichtgewichtige Parser-/IR-Schicht** – bewahrt Statement- und Routine-Grenzen sowie
  die Reihenfolge von Zuweisungen und reduziert so typische False Positives.
- **Externe JSON-Regeln** unter `aci/rules/` – ohne Code-Änderung erweiterbar.
- **Reportformate** – Konsole, JSON, HTML, SARIF und CodeClimate.
- **CI/CD-fähig** – fertige Profile, Exit-Code-Gates, Waiver- und Baseline-Prozess,
  Regelintegritäts-Prüfung und Docker-Image.

## Installation

Voraussetzung: **Python 3.9 oder neuer** (keine weiteren Abhängigkeiten).

```sh
pip install .
```

Danach steht das Kommando `aci` zur Verfügung. Ohne Installation direkt aus dem
Quellverzeichnis:

```sh
python -m aci samples/vulnerable_oracle.sql
```

### Docker

```sh
docker build -t aci:latest .
docker run --rm -v "$PWD:/code" aci:latest --profile ci -f sarif -o /code/reports /code/sql
```

## Verwendung

```sh
aci <Datei-oder-Verzeichnis> [Optionen]
```

Beispiele:

```sh
aci samples/vulnerable_oracle.sql
aci ./src --dialect oracle --format console,html --output-dir reports/
aci ./src --dialect postgresql --group security
aci ./src --profile ci                 # CI/CD-Gate mit Exit-Code
aci --list-checks                      # aktive Checks/Regeln anzeigen
```

> **Hinweis:** Für PostgreSQL-Code muss `--dialect postgresql` gesetzt werden –
> ACI verwendet sonst den Oracle-Regelsatz.

Wichtigste Optionen:

| Option | Beschreibung |
|--------|--------------|
| `-d, --dialect` | `oracle` oder `postgresql` |
| `-g, --group` | `all`, `security` oder `guidelines` |
| `--profile` | CI/CD-Voreinstellung: `advisory`, `ci`, `strict`, `audit`, `apex` |
| `-f, --format` | `console`, `json`, `html`, `sarif`, `codeclimate` (kommagetrennt) |
| `-o, --output-dir` | Zielverzeichnis für Reports |
| `--min-level` | nur Findings ab einem Schweregrad ausgeben |
| `--fail-on` | Exit-Code 1, wenn Findings ≥ Schweregrad (CI/CD) |
| `--waivers` / `--baseline` | kontrollierte Ausnahmen bzw. Adoption auf Legacy-Code |
| `--safe-report` / `--safe-console` | Report bzw. Konsole ohne Quelltext, mit maskierten Secrets/Pfaden |
| `--scan-completeness strict` | Exit-Code 2, wenn nicht jede Zieldatei geprüft wurde (mit `--fail-on-access-error`) |
| `--require-ruleset-pin` | verlangt festen Regelsatz-Hash (`--expected-ruleset-sha256`/`--ruleset-lock`) |
| `--strict-suppressions` | Inline-`aci:ignore` müssen `ticket=`/`reason=` tragen und dürfen nicht abgelaufen sein |
| `--reproducible-report` | byte-identische Reports (ohne Zeitstempel/Plattform/Pfade) |
| `--exclude` / `--max-file-size` | Dateien ausschließen bzw. Größenlimit (auch für Einzeldateien; `--force-file` hebt es auf) |

Vollständige Optionsliste: `aci --help` oder [`docs/MANUAL.md`](docs/MANUAL.md).

## Konfiguration

Standardwerte liegen in `aci.ini` (Abschnitt `[defaults]`) und werden von
Kommandozeilen-Schaltern überschrieben. Die mitgelieferte `aci.ini` ist eine
selbsterklärende Vorlage – jeder Parameter ist mit seinem Default kommentiert.

```ini
[defaults]
dialect = oracle
group = all
min_level = info
format = console
```

## Tests

```sh
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check .
python -m mypy aci
```

## Projektstruktur

```
aci/            Paket: CLI, Checks, Reporter, IR-Schicht
aci/rules/      Externe JSON-Regeln (Guidelines + MITRE, je Dialekt)
docs/           Dokumentation (MANUAL.md, HTML-Doku, Präsentation)
samples/        Beispiel-SQL für Demos
tests/          pytest-Testsuite inkl. Regel-Testharness
```

Ausführliche Dokumentation aller Checks, Regeln und Reportformate:
[`docs/MANUAL.md`](docs/MANUAL.md) und `docs/ACI_Dokumentation.html`.
Versionshistorie: [`CHANGELOG.md`](CHANGELOG.md).

## Sicherheitsmodell & Grenzen

ACI ist ein **heuristischer** Scanner, kein vollständiger SQL-Compiler. Für den
Einsatz als CI/CD-Security-Gate ist wichtig, die Grenzen zu kennen:

- **Kein Soundness-Versprechen.** ACI besitzt keinen vollständigen
  PL/SQL-/PL/pgSQL-Parser und keinen Kontrollflussgraphen. **False Negatives
  sind möglich**, insbesondere bei dynamisch generiertem SQL, Makros/Präprozessor,
  ungewöhnlichen Body-Quotings, bedingter Kompilierung oder Editioning.
- **Statische Analyse des übergebenen Quelltexts.** ACI führt Code nicht aus und
  ersetzt weder eine Laufzeit- noch eine Datenbankrechte-Analyse.
- **Scan-Vollständigkeit ist Teil des Gates.** Übersprungene, nicht lesbare oder
  nicht dekodierbare Dateien können einen Lauf unvollständig machen. Für ein
  belastbares Gate `--profile strict` bzw. `--scan-completeness strict`
  zusammen mit `--fail-on-access-error` verwenden, damit ein unvollständiger
  Scan **nicht** als „bestanden" gilt.
- **Regelintegrität.** Regeln liegen als externe JSON-Dateien vor. Für ein
  reproduzierbares Gate den Regelsatz binden (`--require-ruleset-pin` mit
  `--expected-ruleset-sha256`/`--ruleset-lock`); „gebündelt" bedeutet nicht
  automatisch „unverändert".
- **Safe-Reports.** `--safe-report`/`--safe-console` reduzieren die Preisgabe
  sensibler Daten (Secrets, Pfade, Exception-Details), sind aber heuristisch und
  keine Garantie – Reports vor Veröffentlichung prüfen.

Empfehlung: ACI eignet sich als **unterstützender** Security- und
Audit-Scanner. Als alleinige, fail-closed Sicherheitskontrolle sollte es nur mit
`--profile strict` (Vollständigkeits- und Integritätsprüfung aktiv) betrieben
werden.

## Lizenz

ACI ist **gemischt lizenziert**:

- Der eigene Code (`aci/`, CLI, PL/pgSQL-Guidelines) steht unter der
  **MIT-Lizenz** (siehe [`LICENSE`](LICENSE)).
- Die Oracle-Coding-Guideline-Regeln unter `aci/rules/guidelines/oracle/` sind aus den
  *Trivadis PL/SQL & SQL Coding Guidelines* v4.4 abgeleitet und stehen unter der
  **Apache-Lizenz 2.0** (siehe [`licenses/Apache-2.0.txt`](licenses/Apache-2.0.txt) und
  [`NOTICE`](NOTICE)).

MIT und Apache-2.0 sind permissive, miteinander vereinbare Lizenzen. Die
MITRE-ATT&CK-Zuordnungen verweisen auf das MITRE-ATT&CK-Framework.
