-- postgres_dollar_quote_safe.sql
-- Der Funktionsrumpf ($func$...$func$) ist Code; die inneren
-- Dollar-Quotes ($msg$...$msg$) sind String-Literale und duerfen kein
-- Finding erzeugen - auch wenn ihr Inhalt wie DDL aussieht.
-- Verschachtelte Dollar-Quotes verwenden - wie von PostgreSQL gefordert -
-- unterschiedliche Tags.

CREATE OR REPLACE FUNCTION log_demo ()
   RETURNS void
   LANGUAGE plpgsql
AS $func$
BEGIN
   RAISE NOTICE $msg$EXECUTE IMMEDIATE 'DROP USER X'$msg$;
   RAISE NOTICE $msg$DROP TABLE employees$msg$;
END;
$func$;
