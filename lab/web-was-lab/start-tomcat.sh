#!/bin/sh
set -eu
sha256sum /usr/local/tomcat/conf/server.xml > /tmp/startup-config.sha256
exec "$@"
