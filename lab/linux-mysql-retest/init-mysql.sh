# Sourced by the official MySQL entrypoint, never executed independently.
# No secret literals, hashes, SQL transcripts or account output are printed.
lab_secret="$(openssl rand -hex 32)"
if ! docker_process_sql >/dev/null 2>&1 <<EOSQL
CREATE DATABASE lab_data;
CREATE TABLE lab_data.items (id INT PRIMARY KEY);
CREATE USER ''@'localhost' IDENTIFIED BY '$lab_secret';
CREATE USER 'root'@'%' IDENTIFIED BY '$lab_secret';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
CREATE USER 'lab_app'@'localhost' IDENTIFIED BY '$lab_secret';
GRANT ALL PRIVILEGES ON *.* TO 'lab_app'@'localhost';
EOSQL
then
    printf 'LAB initialization failed\n' >&2
    exit 2
fi
unset lab_secret
