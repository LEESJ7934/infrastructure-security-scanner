"""Fixed read-only MySQL query and parser for its single tab-separated row."""

import re

from ..models import Observation

MYSQL_KEYS = ("version", "local_infile", "require_secure_transport", "skip_name_resolve", "general_log")
MYSQL_COMMAND = (
    "/bin/sh", "-c",
    """test -n "$MYSQL_ROOT_PASSWORD" || exit 42
export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
exec mysql --no-defaults --protocol=SOCKET --socket=/var/run/mysqld/mysqld.sock \
    --user=root --batch --raw --skip-column-names --connect-timeout=5 \
    --execute='SELECT VERSION(), @@GLOBAL.local_infile, @@GLOBAL.require_secure_transport, @@GLOBAL.skip_name_resolve, @@GLOBAL.general_log'""",
)


def parse_mysql_settings(output: str) -> dict[str, Observation]:
    rows = output.splitlines()
    values = rows[0].split("\t") if len(rows) == 1 else []
    if len(values) != len(MYSQL_KEYS):
        return dict.fromkeys(MYSQL_KEYS, Observation(collection_error=True))

    settings = {}
    for key, value in zip(MYSQL_KEYS, values, strict=True):
        if value in {"", "NULL"}:
            settings[key] = Observation()
        elif key == "version" and re.fullmatch(r"[0-9]{1,3}(?:\.[0-9]{1,3}){2}(?:-log)?", value):
            settings[key] = Observation(value)
        elif key != "version" and value in {"0", "1"}:
            settings[key] = Observation(int(value))
        else:
            settings[key] = Observation(collection_error=True)
    return settings
