#!/usr/bin/env bash
set -euo pipefail
umask 077
die(){ echo "$*" >&2; exit 1; }
[[ $(id -u) == 0 ]] || die 'Run as root or with sudo'
for tool in curl openssl python3 systemctl sha256sum; do command -v "$tool" >/dev/null || die "Missing: $tool"; done
test -d /run/systemd/system || die 'Requires Linux with systemd'
case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die 'Unsupported architecture';; esac
release=https://github.com/Toby1GO/stest-relay/releases/download/v1.2.1
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
fetch_binary(){
 local name="$1-linux-$arch"
 if [[ -n ${STEST_PACKAGE_DIR:-} ]]; then
  cp -- "$STEST_PACKAGE_DIR/$name" "$tmp/$name"
  cp -- "$STEST_PACKAGE_DIR/SHA256SUMS" "$tmp/sums"
 else
  curl -fsSL --retry 3 "$release/$name" -o "$tmp/$name"
  curl -fsSL --retry 3 "$release/SHA256SUMS" -o "$tmp/sums"
 fi
 (cd "$tmp"; awk -v n="$name" '$2==n {print; found++} END{if(found!=1)exit 1}' sums > check; sha256sum -c check)
}

dir=/opt/stest-center
unit=stest-center.service
[[ ! -e "$dir" && ! -e /root/stest/center-managed ]] && ! systemctl cat "$unit" >/dev/null 2>&1 || die 'Existing center found; first-install script will not overwrite it'
ip=${1:-}
if [[ -z "$ip" ]]; then ip=$(curl -4fsS --max-time 6 https://api.ipify.org || true); fi
if [[ -z "$ip" ]]; then read -rp 'Center public IPv4: ' ip </dev/tty; fi
python3 -c 'import ipaddress,sys;ipaddress.IPv4Address(sys.argv[1])' "$ip"
fetch_binary stest-center
mkdir -m700 "$dir"
rollback(){ systemctl disable --now "$unit" >/dev/null 2>&1 || :; rm -f "/etc/systemd/system/$unit"; systemctl daemon-reload; mv "$dir" "$dir.failed.$(date +%s)"; }
trap rollback ERR
cd "$dir";install -m755 "$tmp/stest-center-linux-$arch" stest-center
openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 825 -subj "/CN=$ip" -addext "subjectAltName=IP:$ip" -keyout center.key -out center.crt 2>"$tmp/cert.log"
printf 'STEST_PUBLIC_URL=https://%s:8443\n' "$ip" > admin.env
cat >"/etc/systemd/system/$unit" <<UNIT
[Unit]
Description=STest center
After=network-online.target
[Service]
WorkingDirectory=$dir
EnvironmentFile=$dir/admin.env
ExecStart=$dir/stest-center -listen :8443 -cert center.crt -key center.key -state center-state.json
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload;systemctl enable --now "$unit"
ready=0
for i in {1..10}; do
 if [[ $(curl --noproxy '*' --connect-to "$ip:8443:127.0.0.1:8443" --cacert center.crt -s -o /dev/null -w '%{http_code}' "https://$ip:8443/") == 303 ]] && systemctl is-active --quiet "$unit"; then ready=1;break;fi
 sleep 1
done
[[ $ready == 1 ]]
trap - ERR
echo "Panel: https://$ip:8443/    Username: admin"
echo 'Initial password: admin (first login requires changing BOTH username and password)'
openssl x509 -in center.crt -noout -fingerprint -sha256
