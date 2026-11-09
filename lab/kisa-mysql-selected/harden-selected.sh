#!/bin/bash
set -eu
bash /opt/lab/harden-mysql.sh
mysql --defaults-extra-file=/run/lab/client.cnf --batch >/dev/null 2>&1 <<'SQL'
DROP USER IF EXISTS 'lab_unused'@'localhost';
REVOKE SUPER ON *.* FROM 'lab_reader'@'%';
RENAME USER 'lab_probe'@'%' TO 'lab_probe'@'172.30.96.20';
SET DEFAULT ROLE ALL TO 'lab_probe'@'172.30.96.20';
SQL
printf 'Selected MySQL changes applied; retest required\n'
