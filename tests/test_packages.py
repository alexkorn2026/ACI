"""Tests fuer die Erkennung unerwuenschter Packages (PackagesCheck).

Schwerpunkt: ein Paketname in einem Ausgabe-/Meldungstext oder
Kommentar ist kein Paketaufruf und darf kein Finding erzeugen -
echte Aufrufe und Pakete in dynamischem SQL hingegen schon.
"""

from aci.source import Source
from aci.checks import PackagesCheck


def pkg(code, rules, dialect="oracle"):
    s = Source(code, "t.sql", dialect)
    return PackagesCheck(rules.check("undesired_packages"), dialect).run(s)


def refs(findings):
    return sorted(f.rule_ref.lower() for f in findings)


def test_real_package_call_is_flagged(oracle_rules):
    code = "BEGIN\n  DBMS_LOB.FILEOPEN(f, 0);\nEND;\n"
    assert "dbms_lob" in refs(pkg(code, oracle_rules))


def test_package_name_inside_output_string_is_not_flagged(oracle_rules):
    # Regression: DBMS_LOB nur als Text in einer DBMS_OUTPUT-Ausgabe.
    code = ("BEGIN\n"
            "  DBMS_OUTPUT.PUT_LINE('Inhalt via DBMS_LOB und UTL_HTTP');\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


def test_package_name_in_plain_string_is_not_flagged(oracle_rules):
    code = "BEGIN\n  l_msg := 'siehe UTL_FILE-Dokumentation';\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_package_name_in_comment_is_not_flagged(oracle_rules):
    code = "-- verwendet DBMS_JAVA\nBEGIN\n  NULL;\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_real_call_flagged_despite_string_mention_same_package(oracle_rules):
    # Bloße Erwaehnung in Zeile 2, echter Aufruf in Zeile 3.
    code = ("BEGIN\n"
            "  DBMS_OUTPUT.PUT_LINE('nutzt DBMS_LOB');\n"
            "  DBMS_LOB.READ(x, l_amt, l_off, l_buf);\n"
            "END;\n")
    findings = [x for x in pkg(code, oracle_rules)
                if x.rule_ref.lower() == "dbms_lob"]
    assert findings
    assert all(x.line == 3 for x in findings)


def test_package_inside_dynamic_sql_string_is_flagged(oracle_rules):
    # Paket im dynamischen SQL-String -> wird zur Laufzeit ausgefuehrt.
    code = ("BEGIN\n"
            "  EXECUTE IMMEDIATE 'BEGIN UTL_HTTP.REQUEST(x); END;';\n"
            "END;\n")
    assert "utl_http" in refs(pkg(code, oracle_rules))


def test_dbms_advisor_create_file_is_flagged(oracle_rules):
    # DBMS_ADVISOR.CREATE_FILE schreibt eine Datei ins Server-Dateisystem.
    code = ("BEGIN\n"
            "  DBMS_ADVISOR.CREATE_FILE(l_buf, 'DATA_DIR', 'out.sql');\n"
            "END;\n")
    assert "dbms_advisor.create_file" in refs(pkg(code, oracle_rules))


def test_dbms_advisor_without_create_file_is_not_flagged(oracle_rules):
    # Nur DBMS_ADVISOR.CREATE_FILE ist gelistet - die uebrige
    # (gutartige) Advisor-Nutzung darf kein Finding erzeugen.
    code = ("BEGIN\n"
            "  DBMS_ADVISOR.QUICK_TUNE(l_task, 'name', 'SELECT 1 FROM dual');\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


# -- Gutartige Paket-Member (ignore_members) erzeugen kein Finding -------

def test_dbms_lob_instr_is_not_flagged(oracle_rules):
    # DBMS_LOB.INSTR ist nur eine Suche in einem LOB - kein Finding.
    code = "BEGIN\n  l_pos := DBMS_LOB.INSTR(l_lob, 'x');\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_dbms_lob_substr_is_not_flagged(oracle_rules):
    # DBMS_LOB.SUBSTR schneidet nur einen Teil aus einem LOB aus.
    code = "BEGIN\n  l_part := DBMS_LOB.SUBSTR(l_lob, 10, 1);\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_dbms_lob_default_csid_is_not_flagged(oracle_rules):
    code = "BEGIN\n  l_csid := DBMS_LOB.DEFAULT_CSID;\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_dbms_lob_default_lang_ctx_is_not_flagged(oracle_rules):
    code = "BEGIN\n  l_ctx := DBMS_LOB.DEFAULT_LANG_CTX;\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_dbms_lob_real_call_still_flagged(oracle_rules):
    # Echte LOB-/Datei-Operationen bleiben weiterhin meldepflichtig.
    code = "BEGIN\n  DBMS_LOB.READ(l_lob, l_amt, l_off, l_buf);\nEND;\n"
    assert "dbms_lob" in refs(pkg(code, oracle_rules))


def test_dbms_lob_temporary_lob_ops_are_not_flagged(oracle_rules):
    # Temp-LOB-Lebenszyklus (kein Datei-/BFILE-Zugriff) ist kein Finding.
    code = ("BEGIN\n"
            "  DBMS_LOB.CREATETEMPORARY(l_lob, TRUE);\n"
            "  IF DBMS_LOB.ISTEMPORARY(l_lob) = 1 THEN\n"
            "    DBMS_LOB.FREETEMPORARY(l_lob);\n"
            "  END IF;\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


def test_utl_file_file_type_is_not_flagged(oracle_rules):
    # UTL_FILE.FILE_TYPE ist nur die Typdeklaration eines Datei-Handles.
    code = ("DECLARE\n  l_file UTL_FILE.FILE_TYPE;\n"
            "BEGIN\n  NULL;\nEND;\n")
    assert pkg(code, oracle_rules) == []


def test_utl_file_real_call_still_flagged(oracle_rules):
    code = "BEGIN\n  l_file := UTL_FILE.FOPEN('D', 'f.txt', 'w');\nEND;\n"
    assert "utl_file" in refs(pkg(code, oracle_rules))


def test_utl_http_type_references_are_not_flagged(oracle_rules):
    # UTL_HTTP.REQ/RESP sind Record-Typen - eine Typdeklaration ist
    # selbst noch kein HTTP-Zugriff.
    code = ("DECLARE\n"
            "  l_req  UTL_HTTP.REQ;\n"
            "  l_resp UTL_HTTP.RESP;\n"
            "BEGIN\n  NULL;\nEND;\n")
    assert pkg(code, oracle_rules) == []


def test_utl_http_real_call_still_flagged(oracle_rules):
    # Echte HTTP-Aufrufe (auch UTL_HTTP.REQUEST) bleiben meldepflichtig.
    code = ("BEGIN\n"
            "  l_resp := UTL_HTTP.GET_RESPONSE(l_req);\n"
            "  l_page := UTL_HTTP.REQUEST('http://x');\n"
            "END;\n")
    assert "utl_http" in refs(pkg(code, oracle_rules))


def test_utl_http_utility_members_are_not_flagged(oracle_rules):
    # Konfiguration, Statusabfragen, Aufraeumen, Ausnahmen und Typen von
    # UTL_HTTP sind selbst kein ausgehender HTTP-Zugriff.
    code = ("DECLARE\n"
            "  l_cookies UTL_HTTP.COOKIE_TABLE;\n"
            "  l_conn    UTL_HTTP.CONNECTION;\n"
            "BEGIN\n"
            "  UTL_HTTP.SET_TRANSFER_TIMEOUT(gv_timeout);\n"
            "  UTL_HTTP.SET_HEADER(l_req, 'X', 'y');\n"
            "  IF UTL_HTTP.END_OF_BODY(l_resp) THEN NULL; END IF;\n"
            "  UTL_HTTP.END_RESPONSE(l_resp);\n"
            "EXCEPTION\n"
            "  WHEN UTL_HTTP.TOO_MANY_REQUESTS THEN NULL;\n"
            "  WHEN UTL_HTTP.REQUEST_FAILED THEN NULL;\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


# -- Aus der PL/SQL-Source-Analyse abgeleitete Regeln --------------------

def test_bfilename_is_flagged(oracle_rules):
    # BFILENAME oeffnet eine Datei im Server-Dateisystem (Pfad-Traversal).
    code = "BEGIN\n  f := BFILENAME('MY_DIR', p_file);\nEND;\n"
    assert "bfilename" in refs(pkg(code, oracle_rules))


def test_dbms_assert_noop_is_flagged(oracle_rules):
    # DBMS_ASSERT.NOOP deaktiviert die Eingabepruefung explizit.
    code = "BEGIN\n  l_sql := DBMS_ASSERT.NOOP(p_in);\nEND;\n"
    assert "dbms_assert.noop" in refs(pkg(code, oracle_rules))


def test_dbms_assert_real_check_is_not_flagged(oracle_rules):
    # Echte DBMS_ASSERT-Pruefungen sind kein Finding (nur NOOP).
    code = "BEGIN\n  l := DBMS_ASSERT.SIMPLE_SQL_NAME(p_in);\nEND;\n"
    assert pkg(code, oracle_rules) == []


def test_harmless_cleanup_members_are_not_flagged(oracle_rules):
    # Aufraeum-Operationen (Close/Free) auf UTL_FILE/DBMS_LOB sind
    # harmlos und duerfen kein Finding erzeugen.
    code = ("BEGIN\n"
            "  UTL_FILE.FCLOSE(l_file);\n"
            "  DBMS_LOB.FILECLOSE(l_bfile);\n"
            "  DBMS_LOB.FREETEMPORARY(l_clob_data);\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


def test_real_file_access_members_are_still_flagged(oracle_rules):
    # Echte Datei-/LOB-Zugriffe bleiben meldepflichtig.
    code = ("BEGIN\n"
            "  l_file := UTL_FILE.FOPEN(l_dir, l_name, 'r');\n"
            "  DBMS_LOB.LOADFROMFILE(l_dest, l_bfile, l_len);\n"
            "END;\n")
    assert "utl_file" in refs(pkg(code, oracle_rules))
    assert "dbms_lob" in refs(pkg(code, oracle_rules))


def test_dbms_lob_lob_helper_ops_are_not_flagged(oracle_rules):
    # Reine LOB-Operationen ohne Datei-/BFILE-Zugriff sind kein Finding.
    code = ("BEGIN\n"
            "  l_len  := DBMS_LOB.GETLENGTH(l_lob);\n"
            "  l_csz  := DBMS_LOB.GETCHUNKSIZE(l_lob);\n"
            "  DBMS_LOB.APPEND(l_dst, l_src);\n"
            "  DBMS_LOB.COPY(l_dst, l_src, l_len);\n"
            "  DBMS_LOB.WRITEAPPEND(l_lob, l_amt, l_buf);\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


def test_owa_util_header_members_are_not_flagged(oracle_rules):
    # HTTP-Header-Plumbing von OWA_UTIL ist kein Finding.
    code = ("BEGIN\n"
            "  OWA_UTIL.MIME_HEADER('text/html', FALSE);\n"
            "  OWA_UTIL.HTTP_HEADER_CLOSE;\n"
            "END;\n")
    assert pkg(code, oracle_rules) == []


def test_dbms_sql_bind_array_types_are_not_flagged(oracle_rules):
    # DBMS_SQL-Sammeltypen sind reine Typdeklarationen.
    code = ("DECLARE\n"
            "  l_nums DBMS_SQL.NUMBER_TABLE;\n"
            "  l_strs DBMS_SQL.VARCHAR2_TABLE;\n"
            "  l_desc DBMS_SQL.DESC_TAB;\n"
            "BEGIN\n  NULL;\nEND;\n")
    assert pkg(code, oracle_rules) == []


def test_dbms_sql_real_call_still_flagged(oracle_rules):
    # Echte DBMS_SQL-Operationen bleiben meldepflichtig.
    code = "BEGIN\n  c := DBMS_SQL.OPEN_CURSOR;\nEND;\n"
    assert "dbms_sql" in refs(pkg(code, oracle_rules))


def test_utl_http_read_raw_is_not_flagged(oracle_rules):
    code = "BEGIN\n  UTL_HTTP.READ_RAW(l_resp, l_data, 256);\nEND;\n"
    assert pkg(code, oracle_rules) == []


# -- ACI 2.9.0: zusaetzliche unerwuenschte Pakete ------------------------

def test_oracle_dbms_datapump_is_flagged(oracle_rules):
    code = "BEGIN\n  l_h := DBMS_DATAPUMP.OPEN('EXPORT', 'FULL');\nEND;\n"
    assert "dbms_datapump" in refs(pkg(code, oracle_rules))


def test_oracle_dbms_fga_is_flagged(oracle_rules):
    code = "BEGIN\n  DBMS_FGA.DROP_POLICY('s', 't', 'p');\nEND;\n"
    assert "dbms_fga" in refs(pkg(code, oracle_rules))


def test_postgres_epas_utl_file_is_flagged(pg_rules):
    code = "BEGIN\n  l_fh := UTL_FILE.FOPEN('DIR', 'f.txt', 'r');\nEND;\n"
    assert "utl_file" in refs(pkg(code, pg_rules, "postgresql"))


# -- per-Item Kontext-Override -------------------------------------------
# Einige Eintraege in ``undesired_packages`` setzen ``"context_lines"``,
# um bei punktuellen Befehlen (z.B. set_config) keine ueberlappenden
# Kontextbloecke zu erzeugen. Der Check muss diesen Wert anwenden, andere
# Eintraege behalten die globale Kontextgroesse.


def test_set_config_uses_only_the_affected_line(pg_rules):
    # Drei aufeinanderfolgende set_config-Aufrufe: jeder Fund zeigt nur
    # seine eigene Zeile, nicht ueberlappende Kontextfenster.
    code = (
        "begin;\n"
        "\n"
        "\\o /dev/null\n"
        "select set_config('app.username', 'u', true);\n"
        "select set_config('app.is_superuser', 'f', true);\n"
        "select set_config('app.login', 't', true);\n"
        "\\o\n"
    )
    findings = [f for f in pkg(code, pg_rules, "postgresql")
                if f.rule_ref.lower() == "set_config"]
    assert len(findings) == 3
    for f in findings:
        # Pro Fund nur die betroffene Zeile, sonst nichts.
        assert len(f.context) == 1
        assert f.context[0][0] == f.line


def test_single_line_package_call_shows_only_statement_line(pg_rules):
    # ``pg_reload_conf`` ist ein einzeiliger Aufruf. Mit
    # ``clip_to_statement=True`` zeigt der Kontext genau die Statement-
    # Zeile - benachbarte (nicht zugehoerige) Statements werden nicht in
    # den Kontext einbezogen.
    code = (
        "BEGIN;\n"
        "SELECT 1;\n"
        "SELECT pg_reload_conf();\n"
        "SELECT 2;\n"
        "END;\n"
    )
    findings = [f for f in pkg(code, pg_rules, "postgresql")
                if f.rule_ref.lower() == "pg_reload_conf"]
    assert len(findings) == 1
    f = findings[0]
    assert [ln for ln, _, _ in f.context] == [f.line]


def test_multiline_dbms_sql_parse_shows_full_statement(oracle_rules):
    # Mehrzeiliger DBMS_SQL.parse-Aufruf (typisch in PL/SQL): vom Aufruf
    # bis zum Semikolon muss alles im Kontext sichtbar sein.
    code = (
        "PROCEDURE foo IS\n"                              # line 1
        "  v_cur INTEGER := DBMS_SQL.open_cursor;\n"      # line 2
        "BEGIN\n"                                         # line 3
        "  DBMS_SQL.parse(v_cur\n"                        # line 4
        "                , l_sql\n"                       # line 5
        "                , 1\n"                           # line 6
        "                , v_upperbound\n"                # line 7
        "                , FALSE\n"                       # line 8
        "                , DBMS_SQL.native);\n"           # line 9
        "END;\n"                                          # line 10
    )
    findings = [f for f in pkg(code, oracle_rules, "oracle")
                if f.rule_ref.lower() == "dbms_sql" and f.line == 4]
    assert len(findings) == 1
    f = findings[0]
    ctx_lines = [ln for ln, _, _ in f.context]
    # Statement spannt Zeilen 4..9 - alle muessen sichtbar sein.
    for ln in range(4, 10):
        assert ln in ctx_lines, f"Zeile {ln} fehlt: {ctx_lines}"
