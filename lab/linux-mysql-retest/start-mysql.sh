#!/bin/bash
set -eu
umask 077
mkdir -p /run/lab
if [ -d /var/lib/mysql/mysql ]; then
    printf 'Unexpected persistent datadir; refusing secret replacement\n' >&2
    exit 2
fi
openssl rand -hex 32 > /run/lab/root-secret
{
    printf '[client]\nuser=root\npassword='
    cat /run/lab/root-secret
    printf 'protocol=SOCKET\nsocket=/var/run/mysqld/mysqld.sock\n'
} > /run/lab/client.cnf
chown -R mysql:mysql /run/lab
chmod 700 /run/lab
chmod 600 /run/lab/root-secret /run/lab/client.cnf
export MYSQL_ROOT_PASSWORD_FILE=/run/lab/root-secret
export MYSQL_ROOT_HOST=localhost
export MYSQL_INITDB_SKIP_TZINFO=1
exec /usr/local/bin/docker-entrypoint.sh "$@"
