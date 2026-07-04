-- ---------------------------------------------------------------------
-- Beispieldatei für ACI - bewusst unsichere PostgreSQL-Funktion.
-- Diese Datei dient ausschließlich Demonstrations- und Testzwecken.
-- Sie löst alle fünf ACI-Checks aus.
-- ---------------------------------------------------------------------

CREATE OR REPLACE FUNCTION get_user_data(p_user_name text, "select" integer)
RETURNS text AS $$
DECLARE
    l_sql      text;
    l_result   text;
    "user"     text;          -- Check 1: gequoteter reservierter Bezeichner
BEGIN
    -- Check 4: SQL Injection - dynamisches SQL per Konkatenation gebildet
    l_sql := 'SELECT data FROM accounts WHERE name = ''' || p_user_name || '''';
    EXECUTE l_sql INTO l_result;

    -- Check 4: SQL Injection - direkte Konkatenation einer Variablen
    EXECUTE 'SELECT col FROM t WHERE id = ' || p_user_name INTO l_result;

    -- Check 5: DDL im Code - dynamisches GRANT (Rechteausweitung)
    EXECUTE 'GRANT ALL ON accounts TO ' || p_user_name;

    -- Check 2: unerwünschte Funktionen / Erweiterungen
    l_result := pg_read_file('/etc/passwd');
    PERFORM dblink('host=angreifer.example.com', 'SELECT 1');

    -- Check 3: Base64-kodierter Block + Dekodierfunktion
    l_result := convert_from(
        decode('TG9yZW1JcHN1bURvbG9yU2l0QW1ldENvbnNlY3RldHVyQWRpcGlzY2luZ0VsaXQ=',
               'base64'), 'UTF8');

    RETURN l_result;
END;
$$ LANGUAGE plpython3u;          -- Check 2: nicht vertrauenswürdige Sprache

-- Check 5: eigenständige DDL-Anweisung (GRANT an PUBLIC)
GRANT EXECUTE ON FUNCTION get_user_data(text, integer) TO PUBLIC;
