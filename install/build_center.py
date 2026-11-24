"""Build self-contained Linux centers for both supported architectures."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import io
import json
import re
import shutil
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--signing-key", required=True, type=Path,
                    help="release RSA private key outside the source tree (never distributed)")
parser.add_argument("--openssl", default="openssl")
parser.add_argument("--passphrase-env", help="read the key passphrase from this environment variable")
args = parser.parse_args()

root = Path(__file__).resolve().parents[1]
payload = root / "install" / "payload"
output = root / "dist" / "bundled"
output.mkdir(parents=True, exist_ok=True)
tag = (root / "install/VERSION").read_text().strip()
assert re.fullmatch(r"v\d+\.\d+\.\d+", tag)
if root in args.signing_key.resolve().parents:
    parser.error("keep the release signing key outside the repository")
sign_env = os.environ.copy()
passin = []
if args.passphrase_env:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.passphrase_env) or not os.environ.get(args.passphrase_env):
        parser.error("missing signing passphrase environment variable")
    del os.environ[args.passphrase_env]
    passin = ["-passin", "env:" + args.passphrase_env]
public = subprocess.check_output([args.openssl, "rsa", *passin, "-in", str(args.signing_key),
                                  "-pubout"], stderr=subprocess.DEVNULL, env=sign_env).decode().strip().replace("\r\n", "\n")
cli = (root / "install/stest.py").read_text(encoding="utf8")
(payload / "stest").write_bytes(cli.replace("@RELEASE_PUBLIC_KEY@", public)
                                .replace("@RELEASE_VERSION@", tag).encode())
shutil.copyfile(payload / "stest", output / "stest")


def manifest(directory, scope, names):
    hashes = {n: hashlib.sha256((directory/n).read_bytes()).hexdigest() for n in names}
    data = directory / "manifest.json"
    data.write_bytes(json.dumps(dict(format=1, scope=scope, version=tag, sha256=hashes),
                                sort_keys=True).encode())
    subprocess.run([args.openssl, "dgst", "-sha256", *passin, "-sign", str(args.signing_key),
                    "-out", str(directory / "manifest.sig"), str(data)], check=True, env=sign_env)


def build(target, arch, pkg):
    subprocess.run(["go", "build", "-buildvcs=false", "-trimpath", "-o", str(target), pkg],
                   cwd=root, check=True,
                   env=dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0"))


checks = []
for arch in ("amd64", "arm64"):
    name = "socks5-go-linux-" + arch
    build(payload / name, arch, ".")
    checks.append(hashlib.sha256((payload / name).read_bytes()).hexdigest() + "  " + name)
(payload / "SHA256SUMS").write_bytes(("\n".join(checks) + "\n").encode())
manifest(payload, "node", ["stest", "socks5-go-linux-amd64", "socks5-go-linux-arm64"])
for arch in ("amd64", "arm64"):
    build(output / ("stest-center-linux-" + arch), arch, "./cmd/stest-center")
    name = "stest-center-linux-" + arch
    with tarfile.open(output / ("stest-center-kit-" + arch + ".tar.gz"), "w:gz") as kit:
        kit.add(output / name, arcname=name)
        kit.add(output / "stest", arcname="stest")
        sums = hashlib.sha256((output / name).read_bytes()).hexdigest() + "  " + name + "\n"
        sums += hashlib.sha256((output / "stest").read_bytes()).hexdigest() + "  stest\n"
        for filename, content in [
            ("SHA256SUMS", sums.encode()),
            *((script, (root / "install" / script).read_bytes().replace(b"\r\n", b"\n"))
              for script in ("center.sh", "upgrade-center.sh")),
        ]:
            info = tarfile.TarInfo(filename)
            info.size = len(content)
            info.mode = 0o755 if filename.endswith(".sh") else 0o644
            kit.addfile(info, io.BytesIO(content))

assets = sorted(output / ("stest-center-" + kind + arch + suffix)
                for arch in ("amd64", "arm64")
                for kind, suffix in (("linux-", ""), ("kit-", ".tar.gz")))
manifest(output, "center", ["stest", "stest-center-linux-amd64", "stest-center-linux-arm64"])
assets.extend(output / n for n in ("stest", "manifest.json", "manifest.sig"))
(output / "SHA256SUMS").write_bytes("".join(
    hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
    for p in assets
).encode())
