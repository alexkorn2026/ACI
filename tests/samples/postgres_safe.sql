-- postgres_safe.sql
-- Sicheres PostgreSQL-/PL-pgSQL-Beispiel fuer die ACI-Testsuite.
-- Ziel: keine Sicherheits-Findings. Statisches SQL, kein EXECUTE,
-- keine gefaehrlichen Funktionen.

CREATE OR REPLACE FUNCTION get_employee_salary (in_employee_id integer)
   RETURNS numeric
   LANGUAGE plpgsql
AS $func$
DECLARE
   l_salary numeric;
BEGIN
   SELECT e.salary
     INTO l_salary
     FROM employees e
    WHERE e.employee_id = in_employee_id;
   RETURN l_salary;
END;
$func$;
