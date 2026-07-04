-- ---------------------------------------------------------------------
-- Beispieldatei für ACI - sicher umgesetzte Oracle-Prozedur.
-- Diese Datei sollte keine Findings erzeugen und dient als
-- Gegenbeispiel zu vulnerable_oracle.sql.
-- ---------------------------------------------------------------------

CREATE OR REPLACE PROCEDURE get_account (
    p_account_id  IN  NUMBER,
    p_owner       OUT VARCHAR2
) AS
    l_sql     VARCHAR2(4000);
    l_owner   VARCHAR2(128);
BEGIN
    -- Sicheres dynamisches SQL: Werte ausschließlich über Bindevariablen.
    l_sql := 'SELECT owner FROM accounts WHERE id = :id';
    EXECUTE IMMEDIATE l_sql INTO l_owner USING p_account_id;
    p_owner := l_owner;
EXCEPTION
    WHEN NO_DATA_FOUND THEN
        p_owner := NULL;
END;
/
