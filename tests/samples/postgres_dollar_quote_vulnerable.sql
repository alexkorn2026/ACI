-- postgres_dollar_quote_vulnerable.sql
-- Der Funktionsrumpf ($func$...$func$) wird als Code analysiert: die
-- unsichere dynamische SQL-Konkatenation im EXECUTE wird erkannt.

CREATE OR REPLACE FUNCTION drop_table_unsafe (p_table text)
   RETURNS void
   LANGUAGE plpgsql
AS $func$
BEGIN
   -- dynamische DDL aus ungeprueftem Bezeichner
   EXECUTE 'DROP TABLE ' || p_table;
END;
$func$;
