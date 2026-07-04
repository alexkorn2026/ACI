\set v `whoami`
\copy users TO PROGRAM 'gzip > u.gz'
\copy depts FROM 'depts.csv'
SELECT 'x' FROM t;
\gexec
\! rm -rf /tmp/x
