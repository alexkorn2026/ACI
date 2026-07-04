-- postgres_vulnerable.sql
-- Absichtlich unsicheres PostgreSQL-/PL-pgSQL fuer die ACI-Testsuite.
-- Loest SQL-Injection, dynamische DDL und einen gefaehrlichen
-- Dateizugriff aus.

CREATE OR REPLACE FUNCTION find_user (p_name text)
   RETURNS void
   LANGUAGE plpgsql
AS $func$
DECLARE
   l_sql text;
BEGIN
   -- SQL-Injection durch String-Konkatenation
   l_sql := 'SELECT * FROM users WHERE name = ' || p_name;
   EXECUTE l_sql;

   -- Dynamische DDL: Rechteausweitung
   EXECUTE 'GRANT ALL ON users TO ' || p_name;

   -- Lesen beliebiger Serverdateien
   RAISE NOTICE '%', pg_read_file('/etc/passwd');
END;
$func$;
