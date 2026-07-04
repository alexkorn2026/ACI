"""Tests fuer ``Check.collapse_sibling_context``.

Stehen mehrere Findings derselben Regel direkt untereinander (etwa eine
Reihe von ``GRANT ... TO PUBLIC``), zeigt das Kontextfenster eines
Findings sonst die Nachbar-Fundstellen mit - die wiederum eigene
Findings sind. Der Collapse-Mechanismus reduziert den Kontext jedes
solchen Findings auf die eigene Fundzeile; isolierte Findings behalten
ihren vollen Kontext.
"""

from aci.source import Source
from aci.checks import build_mitre_checks
from aci.rules import load_mitre_rules, find_mitre_dir


def _pg_mitre_findings(code, mitre_base, rule_id):
    rules = load_mitre_rules(find_mitre_dir("postgresql", mitre_base),
                             "postgresql")
    checks = build_mitre_checks(rules, "postgresql")
    source = Source(code, "t.sql", "postgresql")
    findings = []
    for check in checks:
        findings.extend(check.run(source))
    return [f for f in findings if f.rule_ref == rule_id]


def test_mitre_grant_to_public_chain_collapses_context(mitre_base):
    # Vier aufeinanderfolgende ``GRANT ... TO PUBLIC`` (MITRE T1098):
    # jeder Fund soll nur seine eigene Zeile als Kontext zeigen.
    lines = ["SELECT %d;" % i for i in range(1, 11)]
    lines += [
        "grant select on table app.queue to public;",
        "grant select on table app.subscription to public;",
        "grant select on table app.event_template to public;",
        "grant select on table app.retry_queue to public;",
    ]
    code = "\n".join(lines) + "\n"
    findings = _pg_mitre_findings(code, mitre_base, "T1098")
    assert len(findings) == 4
    for f in findings:
        assert len(f.context) == 1
        assert f.context[0][0] == f.line


def test_mitre_isolated_grant_to_public_clips_to_statement_line(mitre_base):
    # Ein einzelner ``GRANT ... TO PUBLIC`` ist ein einzeiliges Statement.
    # MITRE-Findings setzen ``clip_to_statement=True``: nicht-statement-Zeilen
    # (umliegende SELECTs, Kommentare) fallen aus dem Kontext.
    code = (
        "SELECT 1;\n"
        "SELECT 2;\n"
        "SELECT 3;\n"
        "grant select on table app.x to public;\n"
        "SELECT 4;\n"
        "SELECT 5;\n"
        "SELECT 6;\n"
    )
    findings = _pg_mitre_findings(code, mitre_base, "T1098")
    assert len(findings) == 1
    f = findings[0]
    # Genau die Statement-Zeile - kein Padding der Nachbar-SELECTs.
    assert [ln for ln, _, _ in f.context] == [f.line]


# -- Obfuscation: Reihen von Base64-/Hex-Bloecken (z.B. PostGIS-Testdaten) --


_HEX200 = (
    "0102000020E610000028000000A84F0FE6B3EE4FC0A58B86253F5E4C40"
    "CDE58612CBEE4FC0076A685F255E4C40206D718DCFEE4FC0F89971ABBE"
    "CDABF09898E612CBEE4FC0076A685F255E4C40206D718DCFEE4FC0F899"
    "76FCAA0903400540403040"
)[:200]


def _pg_obfuscation_findings(code, pg_rules):
    from aci.checks import ObfuscationCheck
    s = Source(code, "t.sql", "postgresql")
    return ObfuscationCheck(
        pg_rules.check("obfuscation"), "postgresql").run(s)


def test_obfuscation_hex_blob_chain_collapses_context(pg_rules):
    # Mehrere benachbarte Zeilen mit langen Hex-Bloecken (typisch in
    # PostGIS-Tests/-Migrationen mit kodierten Geometrien): jeder Fund
    # zeigt nur seine eigene Zeile, nicht ueberlappende Fenster.
    lines = ["SELECT 1;", "SELECT 2;"]
    for i in range(4):
        lines.append(f"select '#{i}', ST_Subdivide('{_HEX200}');")
    lines += ["SELECT 99;"]
    code = "\n".join(lines) + "\n"
    hex_findings = [f for f in _pg_obfuscation_findings(code, pg_rules)
                    if f.rule_ref == "hex-blob"]
    assert len(hex_findings) == 4
    for f in hex_findings:
        assert len(f.context) == 1
        assert f.context[0][0] == f.line


def test_multiline_ddl_keeps_statement_lines_despite_sibling(oracle_rules):
    # Eine mehrzeilige DDL-Anweisung (z.B. ``CREATE DATABASE LINK ... USING
    # '...'`` ueber mehrere Zeilen) darf nicht vom Cluster-Kollaps verkuerzt
    # werden, nur weil ein anderes DDL-Finding (hier: DROP) in ihrer
    # Padding-Region liegt. Die Statement-Zeilen (4..16) bleiben sichtbar;
    # der Padding-Bereich davor (z.B. Zeile 2 mit dem DROP) wird gefaltet.
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "\n"
        "drop database link site_link;\n"
        "\n"
        "create database link site_link\n"
        "connect to system identified by \"x\"\n"
        "using '(DESCRIPTION =\n"
        "       (ADDRESS_LIST =\n"
        "         (ADDRESS = (PROTOCOL = TCP)\n"
        "           (HOST = 192.168.128.101)\n"
        "           (PORT = 1521))\n"
        "       )\n"
        "       (CONNECT_DATA =\n"
        "         (SID = XE)\n"
        "       )\n"
        "     )'\n"
        ";\n"
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    create = next(f for f in findings if f.rule_ref == "CREATE")
    # Statement spannt Zeile 4..16; alle Zeilen muessen im Kontext stehen.
    ctx_lines = [ln for ln, _, _ in create.context]
    for ln in range(4, 17):
        assert ln in ctx_lines, f"Zeile {ln} fehlt im Kontext: {ctx_lines}"
    # DROP-Finding selbst bleibt einzeilig (eigenes Statement, eine Zeile).
    drop = next(f for f in findings if f.rule_ref == "DROP")
    assert len(drop.context) == 1 and drop.context[0][0] == drop.line


def test_mitre_multiline_dbms_network_acl_admin_shows_full_statement(mitre_base):
    # MITRE T1562 (Aufruf von DBMS_NETWORK_ACL_ADMIN.CREATE_ACL mit
    # benannten Argumenten ueber mehrere Zeilen): vom Aufruf bis zum
    # schliessenden ``;`` muss alles im Kontext sichtbar sein.
    code = (
        "BEGIN\n"                                           # line 1
        "  IF lv_acl_exists = 0 THEN\n"                     # line 2
        "    BEGIN\n"                                       # line 3
        "      DBMS_NETWORK_ACL_ADMIN.CREATE_ACL(\n"        # line 4
        "        acl         => 'api_acl.xml',\n"           # line 5
        "        description => 'ACL for API',\n"           # line 6
        "        principal   => UPPER('SCOTT'),\n"          # line 7
        "        is_grant    => TRUE,\n"                    # line 8
        "        privilege   => 'connect'\n"                # line 9
        "      );\n"                                        # line 10
        "    END;\n"                                        # line 11
        "  END IF;\n"                                       # line 12
        "END;\n"                                            # line 13
    )
    from aci.source import Source
    from aci.rules import load_mitre_rules, find_mitre_dir
    from aci.checks import build_mitre_checks
    rules = load_mitre_rules(find_mitre_dir("oracle", mitre_base), "oracle")
    checks = build_mitre_checks(rules, "oracle")
    source = Source(code, "t.sql", "oracle")
    findings = []
    for check in checks:
        findings.extend(check.run(source))
    acl = [f for f in findings if "NETWORK_ACL_ADMIN" in f.message.upper()]
    assert len(acl) >= 1
    f = acl[0]
    ctx_lines = [ln for ln, _, _ in f.context]
    # Statement spannt Zeilen 4..10 - alle muessen sichtbar sein.
    for ln in range(4, 11):
        assert ln in ctx_lines, f"Zeile {ln} fehlt: {ctx_lines}"


def test_mitre_multiline_identified_by_shows_full_statement(mitre_base):
    # MITRE T1098 (IDENTIFIED BY) auf einer mehrzeiligen DDL: Snippet und
    # Kontext muessen das gesamte Statement abdecken, nicht nur die
    # Fundzeile mit dem Schluesselwort.
    code = (
        "drop database link site_link;\n"
        "\n"
        "create database link site_link\n"
        "connect to system identified by \"x\"\n"
        "using '(DESCRIPTION =\n"
        "       (ADDRESS_LIST =\n"
        "         (ADDRESS = (PROTOCOL = TCP)\n"
        "           (HOST = 192.168.128.101)\n"
        "           (PORT = 1521))\n"
        "       )\n"
        "       (CONNECT_DATA =\n"
        "         (SID = XE)\n"
        "       )\n"
        "     )'\n"
        ";\n"
    )
    from aci.source import Source
    from aci.rules import load_mitre_rules, find_mitre_dir
    from aci.checks import build_mitre_checks
    rules = load_mitre_rules(find_mitre_dir("oracle", mitre_base), "oracle")
    checks = build_mitre_checks(rules, "oracle")
    source = Source(code, "t.sql", "oracle")
    findings = []
    for check in checks:
        findings.extend(check.run(source))
    t1098 = [f for f in findings if f.rule_ref == "T1098"]
    # Genau ein T1098-IDENTIFIED-BY-Finding fuer dieses Statement.
    by_pwd = [f for f in t1098 if "IDENTIFIED BY" in f.message.upper()]
    assert len(by_pwd) >= 1
    f = by_pwd[0]
    # Statement endet auf Zeile 15 (Semikolon-Zeile in der Aufstellung).
    assert f.statement_end_line >= 14
    # Snippet enthaelt mehr als nur die Fundzeile.
    assert "using" in f.snippet.lower()
    # Kontext umfasst die Statement-Zeilen 3..15.
    ctx_lines = [ln for ln, _, _ in f.context]
    for ln in range(3, 16):
        assert ln in ctx_lines, f"Zeile {ln} fehlt im Kontext: {ctx_lines}"


# -- DDL: Kontext klemmt sich an die Statement-Zeilen --------------------


def test_ddl_single_line_grant_omits_unrelated_neighbors(oracle_rules):
    # Einzeiliges GRANT mit benachbarten anderen DDL-Statements: nur die
    # eigene Zeile darf im Kontext stehen, nicht die DROP/CREATE-Nachbarn.
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "GRANT EXECUTE ON DBMS_CRYPTO TO video_store;\n"
        "DROP TABLE contact CASCADE CONSTRAINTS PURGE;\n"
        "DROP TABLE system_user CASCADE CONSTRAINTS PURGE;\n"
        "CREATE TABLE contact (id NUMBER);\n"
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    grant = [f for f in findings if f.rule_ref == "GRANT"]
    assert len(grant) == 1
    assert [ln for ln, _, _ in grant[0].context] == [1]


def test_ddl_external_table_shows_only_table_statement(oracle_rules):
    # Externe Tabelle: Kontext umfasst exakt die Zeilen der externen
    # Tabellendefinition, nicht das vorangehende DROP TABLE.
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "DROP TABLE PASSWORD_DICTIONARY_STAGE;\n"
        "CREATE TABLE PASSWORD_DICTIONARY_STAGE\n"
        "(\n"
        "  password  VARCHAR2(50),\n"
        "  frequency VARCHAR2(50)\n"
        ")\n"
        "ORGANIZATION EXTERNAL (\n"
        "  TYPE oracle_loader\n"
        "  DEFAULT DIRECTORY sec\n"
        "  ACCESS PARAMETERS (FIELDS TERMINATED BY ',')\n"
        "  LOCATION ('dict.csv')\n"
        ");\n"
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    ext = [f for f in findings if f.rule_ref == "EXTERNAL TABLE"]
    assert len(ext) == 1
    f = ext[0]
    ctx = [ln for ln, _, _ in f.context]
    # Statement spannt Zeilen 2..12 - das DROP auf Zeile 1 darf nicht im
    # Kontext stehen.
    assert ctx == list(range(2, 13))
    assert 1 not in ctx


def test_ddl_create_user_after_sqlplus_prompt_clips_correctly(oracle_rules):
    # Vor einem ``CREATE USER`` steht haeufig eine SQL*Plus-Praeambel
    # (PROMPT, Trennstrich-Kommentare). Diese ist nicht Teil des
    # Statements und darf nicht in den Kontext rutschen - auch nicht
    # ueber das Walk-Back nach dem vorhergehenden ``;``.
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "PROMPT Creating user &&ps_app_owner...\n"                           # 1
        "\n"                                                                  # 2
        "------------                       CREATE USER                  ----\n"  # 3
        "CREATE USER &&ps_app_owner\n"                                       # 4
        "  IDENTIFIED BY pwd\n"                                              # 5
        "  DEFAULT TABLESPACE users\n"                                       # 6
        "  TEMPORARY TABLESPACE temp\n"                                      # 7
        "  ACCOUNT UNLOCK;\n"                                                # 8
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    create = [f for f in findings if f.rule_ref == "CREATE"]
    assert len(create) == 1
    assert [ln for ln, _, _ in create[0].context] == [4, 5, 6, 7, 8]


def test_sqlplus_prompt_text_does_not_trigger_ddl_finding(oracle_rules):
    # Text innerhalb eines PROMPT-Kommandos darf keine Pattern-Treffer
    # erzeugen (kein false positive ``CREATE USER section below``).
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "PROMPT will own the framework packages\n"
        "PROMPT according to the required privs listed under CREATE USER section below.\n"
        "PROMPT\n"
        "SET VERIFY OFF\n"
        "SELECT 1 FROM DUAL;\n"
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    assert findings == []


def test_mitre_t1059_skips_label_style_bang_comments(mitre_base):
    # ``! Note: ...``, ``! TODO: ...`` und aehnliche Label-Kommentare
    # sind keine echten SQL*Plus-HOST-Aufrufe und sollen kein Finding
    # erzeugen. Echte Aufrufe wie ``! ls`` bleiben Findings.
    from aci.source import Source
    from aci.rules import load_mitre_rules, find_mitre_dir
    from aci.checks import build_mitre_checks
    rules = load_mitre_rules(find_mitre_dir("oracle", mitre_base), "oracle")
    checks = build_mitre_checks(rules, "oracle")
    code = (
        "! Note: This is a sample application.\n"  # line 1 - label, NO finding
        "! TODO: refactor later\n"                  # line 2 - label, NO finding
        "! ls -la /etc/passwd\n"                    # line 3 - real, EXPECT finding
        "HOST whoami\n"                             # line 4 - real, EXPECT finding
    )
    s = Source(code, "t.sql", "oracle")
    findings = []
    for c in checks:
        findings.extend(c.run(s))
    host_findings = [f for f in findings
                     if "HOST" in f.message and "!" in f.message]
    lines = sorted(f.line for f in host_findings)
    assert lines == [3, 4]


def test_ddl_strips_pre_and_post_comments_from_context(oracle_rules):
    # GRANT umgeben von reinen Kommentarzeilen: weder die Kommentare davor
    # noch die Kommentare/Trennlinien danach gehoeren zum Statement und
    # duerfen nicht im Kontext erscheinen.
    from aci.source import Source
    from aci.checks import DdlCheck
    code = (
        "-- you need to grant execute on the function to public\n"
        "-- with their profile\n"
        "--------------------------------------------------------\n"
        "GRANT EXECUTE ON ora12c_verify_function TO PUBLIC;\n"
        "--------------------------------------------------------\n"
        "-- Insert new passwords ...\n"
        "--------------------------------------------------------\n"
    )
    s = Source(code, "t.sql", "oracle")
    findings = DdlCheck(oracle_rules.check("ddl_in_code"), "oracle").run(s)
    grant = [f for f in findings if f.rule_ref == "GRANT"]
    assert len(grant) == 1
    assert [ln for ln, _, _ in grant[0].context] == [4]


def test_obfuscation_isolated_blob_keeps_full_context(pg_rules):
    # Ein einzelner langer Hex-Block (kein Nachbar derselben Regel):
    # der volle Kontext (mehrere Zeilen vor/nach) bleibt erhalten.
    code = (
        "SELECT 1;\n"
        "SELECT 2;\n"
        "SELECT 3;\n"
        f"select '#single', '{_HEX200}';\n"
        "SELECT 4;\n"
        "SELECT 5;\n"
        "SELECT 6;\n"
    )
    hex_findings = [f for f in _pg_obfuscation_findings(code, pg_rules)
                    if f.rule_ref == "hex-blob"]
    assert len(hex_findings) == 1
    assert len(hex_findings[0].context) > 1
