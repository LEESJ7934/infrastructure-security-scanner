#!/bin/sh
# Run once on the existing OPNsense VM console. Read only, no policy reload.
set -eu
umask 077
[ "$(uname -s)" = FreeBSD ] || { printf 'OPNsense FreeBSD required\n' >&2; exit 2; }
command -v opnsense-version >/dev/null || exit 2
[ "$(id -u)" = 0 ] || { printf 'Console root needed for active PF/config metadata\n' >&2; exit 2; }
[ "$#" = 1 ] || { printf 'Usage: sh collect_opnsense_selected.sh NEW_OUTPUT_DIRECTORY\n' >&2; exit 2; }
[ ! -e "$1" ] || { printf 'New output directory required\n' >&2; exit 2; }
mkdir "$1"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$1/collection-started-at.txt"
opnsense-version > "$1/product-version.txt"
pfctl -sr > "$1/active-rules.txt"
pfctl -vvsr > "$1/active-rules-detail.txt"
sockstat -46l > "$1/listening-sockets.txt"
ifconfig -a > "$1/interfaces.txt"
sha256 -q /conf/config.xml > "$1/config-xml.sha256"
# Project only management fields. Never copy config.xml, credentials or keys.
php -r '
$x=simplexml_load_file("/conf/config.xml");
if ($x===false) exit(2);
$out=["webgui"=>[],"ssh"=>[]];
foreach (["protocol","port","interfaces","ssl-certref"] as $k) {
    if (isset($x->system->webgui->$k)) $out["webgui"][$k]=(string)$x->system->webgui->$k;
}
foreach (["enabled","port","interfaces","permitrootlogin","passwordauth"] as $k) {
    if (isset($x->system->ssh->$k)) $out["ssh"][$k]=(string)$x->system->ssh->$k;
}
$out["limitations"]=["Missing XML fields require product-version interpretation; they are not assumed secure."];
echo json_encode($out,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),"\n";
' > "$1/management-settings.json"
date -u '+%Y-%m-%dT%H:%M:%SZ' > "$1/collection-completed-at.txt"
(cd "$1" && sha256 ./*.txt ./*.json) > "$1/artifacts.sha256"
printf 'Actual console evidence saved. No full-item PASS assigned.\n'
