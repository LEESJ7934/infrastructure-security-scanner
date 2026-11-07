#!/bin/bash
set -eu
# User-invoked mutation of only this disposable LAB; collector never calls it.
if ! mysql --defaults-extra-file=/run/lab/client.cnf --batch --connect-timeout=5 >/dev/null 2>&1 <<'SQL'
DROP USER IF EXISTS ''@'localhost';
DROP USER IF EXISTS 'root'@'%';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'lab_app'@'localhost';
GRANT SELECT ON lab_data.items TO 'lab_app'@'localhost';
SET GLOBAL local_infile=OFF;
SET GLOBAL require_secure_transport=ON;
SQL
then
    printf 'LAB hardening failed; collect actual state before retry\n' >&2
    exit 2
fi
printf 'LAB changes applied; read-only retest required\n'
