# REVIEW_FIXES_2.22.1

Korrektur der Muss- und Soll-Findings aus dem Review von ACI **2.22.0**.
Alle Änderungen sind additiv, rückwärtskompatibel und vollständig getestet;
bestehende Regeln, Severities und Reportformate bleiben unverändert.

## 1. Zusammenfassung aller Änderungen

| # | Typ | Finding | Status |
|---|-----|---------|--------|
| M1 | Muss | Inline-Suppressions nur in echten Kommentaren | behoben |
| M2 | Muss | Baseline berücksichtigt Anzahl identischer Findings (Multiset) | behoben |
| S1 | Soll | `ignore-next-line` = nächste tatsächliche Codezeile | behoben |
| S2 | Soll | Oracle Named Arguments in interprozeduraler Analyse | behoben |
| S3 | Soll | Baseline-Dateien streng validieren | behoben |
| S4 | Soll | Baseline atomar schreiben | behoben |

## 2. Geänderte Dateien

**Produktivcode**

- `aci/suppressions.py` – Neuschreibung: Direktiven nur noch aus echten
  Lexer-Kommentarbereichen; `ignore-next-line`/`ignore` auf nächste
  tatsächliche Codezeile.
- `aci/baseline.py` – Neuschreibung: Multiset-/Counter-Semantik, Format
  Version 2, strenge Validierung, atomares Schreiben, Legacy-Kompatibilität.
- `aci/checks/sqli.py` – interprozedurale Analyse: `CallArgument`,
  `_parse_call_args`, `_bind_arguments`; Named-Argument-Zuordnung.
- `aci/scanner.py` – `apply_suppressions(findings, source)` (statt Rohtext).
- `aci/cli.py` – sauberer Fehlerpfad für `--write-baseline`, angepasste
  Meldung (Format v2).
- `aci/_version.py` – Version `2.22.1`.

**Dokumentation**

- `CHANGELOG.md`, `README.md`, `docs/ACI_Dokumentation.html`,
  `REVIEW_FIXES_2.22.1.md` (diese Datei).

**Tests** – siehe Abschnitt 5.

## 3. Technische Ursache je Finding

- **M1:** `parse_suppressions` scannte den *unveränderten* Quelltext per
  Regex. Dadurch konnte `-- aci:ignore` innerhalb eines String-Literals
  (dynamisches SQL, `RAISE NOTICE`, q-/Dollar-Quote …) als Direktive gelten.
- **M2:** Die Baseline war eine `set`-Menge von Fingerabdrücken. Da der
  Fingerabdruck keine Zeilennummer enthält, konnte ein einzelnes
  Baseline-Vorkommen beliebig viele aktuelle identische Findings
  unterdrücken – kopierter verwundbarer Code blieb unsichtbar.
- **S1:** `ignore-next-line` verwendete `aktuelle Zeile + 1` und griff daher
  nicht über Leer- oder reine Kommentarzeilen hinweg.
- **S2:** Die Aufrufargumente wurden rein positionsbasiert per Listenindex
  zugeordnet; Oracle-Named-Argument-Syntax (`p_sql => x`) wurde nicht dem
  richtigen Parameter zugeordnet.
- **S3:** `load_baseline` akzeptierte beliebige JSON-Werte per pauschaler
  `str()`-Konvertierung; fehlerhafte Dateien wurden faktisch tolerant
  behandelt.
- **S4:** Die Baseline wurde direkt in die Zieldatei geschrieben; ein Abbruch
  konnte eine beschädigte Baseline hinterlassen.

## 4. Gewählte Lösung

- **M1:** `Source` liefert bereits die Lexer-Token. `parse_suppressions`
  arbeitet jetzt ausschließlich auf den Kommentar-Token-Bereichen
  (`TOK_LINE_COMMENT`, `TOK_BLOCK_COMMENT`); der Direktiven-Regex enthält
  keinen eigenen Kommentar-Leader mehr. Keine zweite String-/Kommentar-Logik.
- **M2:** Interne Umstellung auf `collections.Counter`. Beim Anwenden wird je
  Fingerabdruck der verbleibende Zähler dekrementiert; ist er 0, gilt das
  Finding als neu. Deterministisch über nach Pfad sortierte Verarbeitung.
  Neues Format Version 2 (`findings: {fp: count}` bzw. Liste von
  `{fingerprint, count}`).
- **S1:** Auflösung der Zielzeile über `code_no_comments`: die nächste Zeile,
  deren Inhalt (Kommentare ausgeblendet) nicht leer ist. `aci:ignore` am Ende
  einer Codezeile wirkt auf diese Zeile, auf einer reinen Kommentarzeile auf
  die nächste Codezeile.
- **S2:** `CallArgument(name, expression)`; `_parse_call_args` erkennt
  `name =>` auf der maskierten Variante (kein `=>` aus Strings);
  `_bind_arguments` ordnet Named Arguments über den normalisierten (großen)
  Parameternamen zu und füllt Positionsargumente der Reihe nach. Unbekannte
  Namen werden ignoriert (keine Zuordnung per Index).
- **S3:** Strikte Validierung in `load_baseline` – Wurzeltyp, unterstützte
  `baseline_version` (1/2, Zukunft abgelehnt), Fingerabdruck (16 Hex-Zeichen),
  `count` als positive Ganzzahl (keine Booleans), Obergrenzen. Fehler ⇒
  `BaselineError` ⇒ Exit 2 (fail-closed).
- **S4:** `_atomic_write_text` – `tempfile.mkstemp` im Zielverzeichnis,
  `write`/`flush`/`os.fsync`, Übernahme bestehender Dateirechte, `os.replace`;
  bei Fehlern wird die Temporärdatei entfernt.

## 5. Neue und geänderte Tests

Neue Module:

- `tests/test_suppression_lexical_context.py` (M1)
- `tests/test_suppression_next_code_line.py` (S1)
- `tests/test_baseline_multiset.py` (M2)
- `tests/test_baseline_validation.py` (S3 + Legacy)
- `tests/test_baseline_atomic_write.py` (S4)
- `tests/test_interprocedural_named_arguments.py` (S2)

Geändert:

- `tests/test_suppressions_baseline.py` – jetzt CLI-End-to-End (Suppression
  im String vs. Kommentar, Baseline v2 schreiben/lesen, Legacy-Baseline,
  kopiertes identisches Finding bleibt sichtbar, Named-Argument-Finding,
  ungültige Baseline ⇒ Exit 2).

Abgedeckte Kernfälle u.a.: Suppression in Literal/q-Quote/Dollar-Quote/
`RAISE NOTICE`/dynamischem SQL (kein Effekt), `ignore-next-line` über Leer-/
Kommentarzeilen, Multiset 1/2/2/2/2/3, Legacy-Liste als Counter,
Zeilenverschiebung baseline-stabil, `ACI-INTERNAL` nie unterdrückt,
Named/positional/gemischte Aufrufe, simulierter `os.replace`-/Schreibfehler
ohne Beschädigung.

## 6. Testergebnisse

- `python -m pytest` – **1145 passed** (vorher 1078).
- `python -m compileall aci/` – ok.
- `ruff check aci/ tests/` – All checks passed.
- `mypy aci/` – keine Fehler.

## 7. Rückwärtskompatibilität

- Bestehende CLI-Optionen und Ausgabeformate unverändert.
- Legacy-Baselines aus 2.22.0 (`{"fingerprints": [...]}` und blanke Liste)
  bleiben lesbar; jedes Vorkommen zählt als eins.
- Neues Baseline-Format wird als Version 2 geschrieben.
- `ACI-INTERNAL` bleibt weder durch Inline-Suppression noch durch Baseline
  unterdrückbar.

## 8. Verbleibende bekannte Einschränkungen

- Die interprozedurale Analyse bleibt bewusst dateilokal und konservativ
  (keine globale Call-Graph-/Alias-/SSA-Analyse – außerhalb des Scopes). Sie
  erkennt die Durchreichung eines Aufrufer-Parameters bzw. einer Session-/
  APEX-Quelle an einen Sink-Parameter; komplexe Umschreibungen des Arguments
  vor dem Aufruf werden nicht verfolgt.
- Named-Argument-Auflösung nutzt die statisch sichtbare Parameterliste der
  gleichnamigen Routine in derselben Datei; Überladungen mit identischem
  einfachem Namen werden über den ersten Treffer aufgelöst.

## 9. Migrationshinweise für Baseline-Dateien

- Keine Aktion nötig: vorhandene 2.22.0-Baselines werden weiter gelesen.
- Empfehlung: Baseline mit `--write-baseline` einmalig neu schreiben, um auf
  Format Version 2 (mit Multiset-Zählung) zu wechseln – erst dann wird
  kopierter identischer Code korrekt als neu erkannt.

---

```text
Version:                        2.22.1
Geänderte Produktivdateien:     aci/suppressions.py, aci/baseline.py,
                                aci/checks/sqli.py, aci/scanner.py,
                                aci/cli.py, aci/_version.py
Neue/geänderte Testdateien:     6 neue Module + test_suppressions_baseline.py
Anzahl Tests vorher:            1078
Anzahl Tests nachher:           1145
Testergebnis:                   1145 passed
Lint-Ergebnis:                  ruff: All checks passed
Typing-Ergebnis:                mypy: keine Fehler
Verbleibende bekannte Einschränkungen:
                                dateilokale, konservative interprozedurale
                                Analyse; Überladungen per erstem Namenstreffer
```
