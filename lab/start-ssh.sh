#!/bin/sh
set -eu
mkdir -p /run/sshd /home/lab/.ssh
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key; fi
if ! id lab >/dev/null 2>&1; then useradd -m -s /bin/sh lab; fi
if [ "${LAB_VULNERABLE:-0}" = "1" ]; then
  if [ -z "${LAB_SSH_PASSWORD:-}" ]; then echo "LAB_SSH_PASSWORD is required" >&2; exit 1; fi
  printf 'lab:%s\n' "$LAB_SSH_PASSWORD" | chpasswd
  password_auth=yes
else
  passwd -l lab
  password_auth=no
fi
if [ -n "${LAB_SSH_PUBKEY:-}" ]; then
  printf '%s\n' "$LAB_SSH_PUBKEY" > /home/lab/.ssh/authorized_keys
  chown -R lab:lab /home/lab/.ssh
  chmod 700 /home/lab/.ssh
  chmod 600 /home/lab/.ssh/authorized_keys
fi
exec /usr/sbin/sshd -D -e -p 2222 -o "PasswordAuthentication=$password_auth" \
  -o "PubkeyAuthentication=yes" -o "PermitRootLogin=no" \
  -o "KbdInteractiveAuthentication=no" -o "UsePAM=no"
