#!/usr/bin/env bash
# Run on the existing center from a directory with the architecture-specific binary.
set -euo pipefail
umask 077
[[ $(id -u) == 0 ]]
pkg=$(cd "$(dirname "$0")" && pwd)
case $(uname -m) in x86_64) arch=amd64;; arm64|aarch64) arch=arm64;; *) exit 1;; esac
name=stest-center-linux-$arch
cd "$pkg"
awk -v name="$name" '$2==name {print; n++} END{if(n!=1) exit 1}' SHA256SUMS | sha256sum -c -
unit=stest-center.service
systemctl is-active --quiet "$unit"
dir=$(systemctl show -p WorkingDirectory --value "$unit")
case "$dir" in /root/stest/center-managed|/opt/stest-center) ;; *) echo "Unknown center directory: $dir" >&2; exit 1;; esac
cd "$dir"
pid=$(systemctl show -p MainPID --value "$unit")
[[ $(readlink "/proc/$pid/exe") == "$dir/stest-center" ]]
origin=$(sed -n 's/^STEST_PUBLIC_URL=//p' admin.env)
[[ $origin =~ ^https://([0-9.]+):([0-9]+)$ ]]
host=${BASH_REMATCH[1]}; port=${BASH_REMATCH[2]}
get(){ curl --noproxy '*' --cacert center.crt --connect-to "$host:$port:127.0.0.1:$port" --max-time 30 -fsS "$origin/$1"; }
backup=$(mktemp -d /root/stest-center-backup.XXXXXXXX)
echo "Backup: $backup"
cp -p stest-center "$backup/"
install -m755 "$pkg/$name" ./stest-center.next
rollback(){
  trap - ERR
  install -m755 "$backup/stest-center" ./stest-center.next
  mv -f ./stest-center.next ./stest-center
  systemctl restart "$unit"
  echo "Restored previous center binary" >&2
  exit 1
}
trap rollback ERR
systemctl stop "$unit"
cp -p admin.env center.crt center.key "$backup/"
for f in center-state.json*; do [[ ! -f $f ]] || cp -p "$f" "$backup/"; done
mv -f ./stest-center.next ./stest-center
systemctl start "$unit"
ready=0
for i in {1..15}; do
  if get install/files/node.sh >"$backup/node.sh"; then ready=1; break; fi
  sleep 1
done
[[ $ready == 1 ]]
bash -n "$backup/node.sh"
get install/files/SHA256SUMS >"$backup/node-sums"
for a in amd64 arm64; do
  bin=socks5-go-linux-$a
  expected=$(awk -v n="$bin" '$2==n {print $1; count++} END{if(count!=1)exit 1}' "$backup/node-sums")
  actual=$(get "install/files/$bin" | sha256sum)
  [[ ${actual%% *} == "$expected" ]]
done
systemctl is-active --quiet "$unit"
trap - ERR
echo "Updated center; verified both node downloads. Backup: $backup"
