#!/bin/sh
set -eu
sha256sum /etc/nginx/nginx.conf > /tmp/startup-config.sha256
exec "$@"
