SET DEFINE OFF
PROMPT Installing &APP_NAME ...
GRANT dba TO &admin;
SET DEFINE ON
GRANT dba TO &admin;
@&deploy_step
WHENEVER SQLERROR CONTINUE
HOST echo done
