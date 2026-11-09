# Sourced by the official entrypoint inside the disposable selected LAB only.
probe_secret="$(openssl rand -hex 32)"
if ! docker_process_sql >/dev/null 2>&1 <<EOSQL
CREATE USER 'lab_unused'@'localhost' IDENTIFIED BY '$probe_secret';
CREATE USER 'lab_probe'@'%' IDENTIFIED BY '$probe_secret';
CREATE ROLE 'lab_reader'@'%';
GRANT SELECT ON lab_data.items TO 'lab_reader'@'%';
GRANT SUPER ON *.* TO 'lab_reader'@'%';
GRANT 'lab_reader'@'%' TO 'lab_probe'@'%';
SET DEFAULT ROLE ALL TO 'lab_probe'@'%';
EOSQL
then
    printf 'Selected LAB initialization failed\n' >&2
    exit 2
fi
{
    printf '[client]\nuser=lab_probe\npassword=%s\nhost=172.30.96.10\nprotocol=TCP\nconnect-timeout=3\n' "$probe_secret"
} > /run/lab/probe.cnf
chmod 600 /run/lab/probe.cnf
unset probe_secret
