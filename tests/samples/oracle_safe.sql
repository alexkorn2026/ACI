-- oracle_safe.sql
-- Sicheres Oracle-PL/SQL-Beispiel fuer die ACI-Testsuite.
-- Ziel: keine Sicherheits-Findings und keine kritischen
-- Coding-Guideline-Verstoesse. Es wird ausschliesslich statisches SQL
-- mit Bindevariablen verwendet, keine gefaehrlichen Pakete, keine DDL.

CREATE OR REPLACE PACKAGE BODY employee_api AS

   FUNCTION get_salary (in_employee_id IN employees.employee_id%TYPE)
      RETURN employees.salary%TYPE IS
      l_salary employees.salary%TYPE;
   BEGIN
      SELECT e.salary
        INTO l_salary
        FROM employees e
       WHERE e.employee_id = in_employee_id;
      RETURN l_salary;
   END get_salary;

   PROCEDURE raise_salary (in_employee_id IN employees.employee_id%TYPE,
                           in_amount      IN NUMBER) IS
   BEGIN
      UPDATE employees e
         SET e.salary = e.salary + in_amount
       WHERE e.employee_id = in_employee_id;
   END raise_salary;

END employee_api;
/
