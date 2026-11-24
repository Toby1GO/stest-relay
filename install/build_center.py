"""Build self-contained Linux centers for both supported architectures."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import io

root = Path(__file__).resolve().parents[1]
payload = root / "install" / "payload"
output = root / "dist" / "bundled"
output.mkdir(parents=True, exist_ok=True)


def build(target, arch, pkg):
    subprocess.run(["go", "build", "-trimpath", "-o", str(target), pkg],
                   cwd=root, check=True,
                   env=dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0"))


checks = []
for arch in ("amd64", "arm64"):
    name = "socks5-go-linux-" + arch
    build(payload / name, arch, ".")
    checks.append(hashlib.sha256((payload / name).read_bytes()).hexdigest() + "  " + name)
(payload / "SHA256SUMS").write_bytes(("\n".join(checks) + "\n").encode())
for arch in ("amd64", "arm64"):
    build(output / ("stest-center-linux-" + arch), arch, "./cmd/stest-center")
    name = "stest-center-linux-" + arch
    with tarfile.open(output / ("stest-center-kit-" + arch + ".tar.gz"), "w:gz") as kit:
        kit.add(output / name, arcname=name)
        sums = hashlib.sha256((output / name).read_bytes()).hexdigest() + "  " + name + "\n"
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
(output / "SHA256SUMS").write_bytes("".join(
    hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
    for p in assets
).encode())
