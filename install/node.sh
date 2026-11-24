#!/usr/bin/env bash
set -euo pipefail
umask 077
die(){ echo "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || die 'Run as root or with sudo'
for tool in curl openssl python3 systemctl sha256sum; do command -v "$tool" >/dev/null || die "Missing: $tool"; done
test -d /run/systemd/system || die 'Requires Linux with systemd'
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die 'Unsupported architecture';; esac
release=https://github.com/Toby1GO/stest-relay/releases/download/v1.0.0
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
fetch_binary(){
 local name="$1-linux-$arch"
 curl -fsSL --retry 3 "$release/$name" -o "$tmp/$name"
 curl -fsSL --retry 3 "$release/SHA256SUMS" -o "$tmp/sums"
 (cd "$tmp"; awk -v n="$name" '$2==n {print; found++} END{if(found!=1)exit 1}' sums > check; sha256sum -c check)
}

[[ $# == 5 ]] || die 'Copy the complete node command from your center'
role=$1;url=$2;pin=$3;id=$4;ticket=$5
case $role in server) unit=stest-exit.service;mode=server;; client) unit=stest-agent.service;mode='client -config proxy.properties forward';; *)die 'Invalid role';;esac
[[ $url == https://* && $pin == sha256//* && $ticket =~ ^[0-9a-f]{48}$ && $id =~ ^[a-zA-Z0-9_-]{1,64}$ ]] || die 'Invalid installation parameters'
dir=/opt/stest-$role
[[ ! -e "$dir" && ! -e /root/stest/proxy.properties ]] && ! systemctl cat "$unit" >/dev/null 2>&1 || die 'Existing installation found; stopped without replacing files'
fetch_binary socks5-go
printf '{"id":"%s","role":"%s"}' "$id" "$role" > "$tmp/request"
# The admin-issued SPKI pin authenticates even a self-signed center on first contact.
curl -fsS -k --pinnedpubkey "$pin" --max-time 15 -H "Authorization: Bearer $ticket" -H 'Content-Type: application/json' --data-binary @"$tmp/request" "$url/install/redeem" -o "$tmp/response" || die 'Enrollment failed. Install server first; check the ticket and center address.'
cd "$tmp"
python3 - "$role" <<'PY'
import json,sys,pathlib,ipaddress
r=json.loads(pathlib.Path('response').read_text())
for name,key in [('proxy.properties','config'),('management-center.crt','center'),('host','ip'),('auth','nodeToken')]:
 pathlib.Path(name).write_text(r[key])
ipaddress.IPv4Address(r['ip'])
if sys.argv[1]=='client':pathlib.Path('server.crt').write_text(r['certificate'])
PY
if [[ $role == server ]];then
 ip=$(cat host)
 openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 -subj "/CN=$ip" -addext "subjectAltName=IP:$ip" -keyout server.key -out server.crt 2>cert.log
 python3 - "$id" <<'PY'
import json,pathlib,sys
pathlib.Path('cert-request').write_text(json.dumps(dict(ID=sys.argv[1],certificate=pathlib.Path('server.crt').read_text())))
PY
fi
# Keep a recoverable installation if service start or certificate registration fails.
mkdir -m700 "$dir"
install -m755 "$tmp/socks5-go-linux-$arch" "$dir/socks5-go"
install -m600 proxy.properties server.crt management-center.crt "$dir/"
if [[ $role == server ]];then install -m600 server.key "$dir/";fi
cat >"/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=STest $role
After=network-online.target
[Service]
WorkingDirectory=$dir
Environment=SSL_CERT_FILE=$dir/management-center.crt
ExecStart=$dir/socks5-go $mode
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload;systemctl enable --now "$unit"
sleep 1;systemctl is-active --quiet "$unit" || die "Start failed: journalctl -u $unit"
if [[ $role == server ]];then
 curl -fsS --retry 3 --cacert management-center.crt --pinnedpubkey "$pin" -H "Authorization: Bearer $(cat auth)" -H 'Content-Type: application/json' --data-binary @cert-request "$url/install/certificate" >/dev/null
fi
echo "$role ($id) installed. Check the node heartbeat in your center."
