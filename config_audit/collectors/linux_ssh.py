"""Parse the selected settings from an effective OpenSSH configuration."""

from ..models import Observation

SSH_COMMAND = ("/usr/sbin/sshd", "-T")
SSH_VALUES = {
    "maxauthtries": None,
    "permitrootlogin": frozenset({"yes", "no", "without-password", "prohibit-password", "forced-commands-only"}),
    "passwordauthentication": frozenset({"yes", "no"}),
    "x11forwarding": frozenset({"yes", "no"}),
    "permitemptypasswords": frozenset({"yes", "no"}),
}


def parse_ssh_settings(output: str) -> dict[str, Observation]:
    settings = dict.fromkeys(SSH_VALUES, Observation())
    seen = set()
    for line in output.splitlines():
        fields = line.strip().lower().split()
        if not fields or fields[0] not in SSH_VALUES:
            continue
        key = fields[0]
        if key in seen or len(fields) != 2:
            settings[key] = Observation(collection_error=True)
        elif key == "maxauthtries":
            value = fields[1]
            if value.isascii() and value.isdecimal() and len(value) <= 10:
                settings[key] = Observation(int(value))
            else:
                settings[key] = Observation(collection_error=True)
        else:
            value = fields[1]
            settings[key] = Observation(value if value in SSH_VALUES[key] else "unrecognized")
        seen.add(key)
    return settings
