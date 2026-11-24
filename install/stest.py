#!/usr/bin/env python3
"""STest Linux service updater. Installed from an authenticated release or center."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

PUBLIC_KEY = """@RELEASE_PUBLIC_KEY@"""
BASE_VERSION = "@RELEASE_VERSION@"
REPO = "https://github.com/Toby1GO/stest-relay"
CLI = Path("/usr/local/bin/stest")
# Marker used to avoid replacing unrelated software with the same name.
MARKER = b"STest Linux service updater."
SERVICES = {
    "center": ("stest-center.service", "stest-center", {"/opt/stest-center", "/root/stest/center-managed"}),
    "client": ("stest-agent.service", "socks5-go", {"/opt/stest-client"}),
    "server": ("stest-exit.service", "socks5-go", {"/opt/stest-server"}),
}


def fail(message):
    raise ValueError(message)


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def version(s):
    if not isinstance(s, str) or not re.fullmatch(r"v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", s):
        fail("不是正式版本号：" + str(s))
    return tuple(map(int, s[1:].split(".")))


def settings(path, key):
    values = [line.split("=", 1)[1].strip() for line in path.read_text().splitlines()
              if line.startswith(key + "=")]
    if len(values) != 1:
        fail("配置中缺少唯一的 " + key)
    origin = values[0]
    parsed = urlsplit(origin)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.path or parsed.query or parsed.fragment:
        fail("配置的中心地址无效")
    return origin


def download(url, dest, ca=None, limit=128*1024*1024, extra=()):
    cmd = ["curl", "--proto", "=https", "--proto-redir", "=https", "--fail", "--silent",
           "--show-error", "--retry", "2", "--connect-timeout", "10", "--max-time", "180",
           "--max-filesize", str(limit)]
    # A node never follows redirects away from its enrolled center.
    cmd += ["--cacert", str(ca)] if ca else ["--location"]
    status = run(*cmd, *extra, "--output", dest, "--write-out", "%{http_code}", "--", url)
    if status != "200" or dest.stat().st_size > limit:
        fail("下载失败：" + url)


def verify_manifest(tmp, scope, get):
    data, sig, pub = (tmp / n for n in ("manifest.json", "manifest.sig", "pub.pem"))
    get("manifest.json", data, 16384)
    get("manifest.sig", sig, 1024)
    pub.write_text(PUBLIC_KEY)
    run("openssl", "dgst", "-sha256", "-verify", pub, "-signature", sig, data)
    doc = json.loads(data.read_bytes())
    if doc["scope"] != scope or doc["format"] != 1:
        fail("签名清单类型不符")
    version(doc["version"])
    return doc


def detect(requested):
    found = []
    for role, (unit, name, dirs) in SERVICES.items():
        if requested and requested != role:
            continue
        state = subprocess.run(["systemctl", "show", "-p", "LoadState", "--value", unit],
                               stdout=subprocess.PIPE, text=True)
        if state.stdout.strip() == "not-found":
            continue
        state.check_returncode()
        if state.stdout.strip() != "loaded":
            continue
        directory = run("systemctl", "show", "-p", "WorkingDirectory", "--value", unit)
        if directory not in dirs:
            fail("不支持的服务目录：" + unit)
        found.append((role, unit, Path(directory), name))
    if len(found) != 1:
        fail("没有找到唯一的受管服务；同机多角色请加 --role center|client|server")
    return found[0]


def process_id(unit, executable):
    if run("systemctl", "is-active", unit) != "active":
        fail(unit + " 未运行")
    pid = int(run("systemctl", "show", "-p", "MainPID", "--value", unit))
    if pid < 1 or not os.path.samefile("/proc/%d/exe" % pid, executable):
        fail("运行程序与安装目录不一致")
    return pid


def healthy(unit, executable, probe):
    last = None
    stable = 0
    for _ in range(15):
        time.sleep(1)
        try:
            pid = process_id(unit, executable)
            stable = stable + 1 if last == pid else 1
            last = pid
            if stable >= 3:
                if probe:
                    probe()
                return
        except (OSError, ValueError, subprocess.CalledProcessError):
            stable = 0
    fail(unit + " 更新后未通过健康检查")


def replace_file(src, dst, mode):
    with tempfile.NamedTemporaryFile(dir=dst.parent, delete=False) as f:
        stage = Path(f.name)
    try:
        shutil.copyfile(src, stage)
        stage.chmod(mode)
        os.replace(stage, dst)
    finally:
        if stage.exists():
            stage.unlink()


def guard_cli():
    if CLI.is_symlink() or (CLI.exists() and (not CLI.is_file() or MARKER not in CLI.read_bytes()[:200])):
        fail("已有其他程序占用 " + str(CLI))


def update(args, tmp):
    role, unit, directory, executable = detect(args.role)
    binary = directory / executable
    arch = {"x86_64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(platform.machine())
    if not arch:
        fail("不支持的架构")
    name = executable + "-linux-" + arch
    tag = None
    if role == "center":
        info = tmp / "latest"
        download("https://api.github.com/repos/Toby1GO/stest-relay/releases/latest", info, limit=1024*1024)
        release = json.loads(info.read_bytes())
        if release["draft"] or release["prerelease"]:
            fail("不是正式发布")
        tag = release["tag_name"]
        version(tag)
        base, ca = REPO + "/releases/download/" + tag, None
    else:
        base = settings(directory / "proxy.properties", "center.url") + "/install/files"
        ca = directory / "management-center.crt"
    def get(file, dest, limit):
        download(base + "/" + file, dest, ca, limit)
    doc = verify_manifest(tmp, "center" if role=="center" else "node", get)
    target = doc["version"]
    stamp = directory / ".stest-release"
    floor = max(version(BASE_VERSION), version(stamp.read_text().strip()) if stamp.exists() else (0,0,0))
    if version(target) < floor or (tag and target != tag):
        fail("版本不符或低于已接受版本；未更新")
    guard_cli()
    changes = []
    for file, dest in [(name, binary), ("stest", CLI)]:
        expected = doc["sha256"][file]
        if not re.fullmatch("[0-9a-f]{64}", expected):
            fail("校验值无效")
        if not dest.exists() or digest(dest) != expected:
            changes.append((file, dest, expected))
    if not changes:
        print(role, target, "已是最新，无需重启。")
    else:
        print(role, target, "可更新：" + ", ".join(c[0] for c in changes), flush=True)
    if args.check:
        return
    for file, _, expected in changes:
        get(file, tmp/file, 128*1024*1024)
        if digest(tmp/file) != expected:
            fail(file + " SHA-256 不符；未替换")
    restarted = any(dest == binary for _, dest, _ in changes)
    if restarted:
        process_id(unit, binary)
    probe = None
    if restarted and role == "center":
        origin = settings(directory / "admin.env", "STEST_PUBLIC_URL")
        addr = urlsplit(origin)
        port = addr.port or 443
        def probe():
            dest = tmp / "probe"
            download(origin+"/install/files/manifest.json", dest, directory/"center.crt", 16384,
                     ("--noproxy","*","--connect-to",f"{addr.hostname}:{port}:127.0.0.1:{port}"))
            if json.loads(dest.read_bytes())["version"] != target:
                fail("中心未加载新节点清单")
    backups = []
    try:
        for file, dest, _ in changes:
            backup = tmp / ("old-" + file) if dest.exists() else None
            if backup:
                shutil.copy2(dest, backup)
            replace_file(tmp/file, dest, 0o755)
            backups.append((dest, backup))
        if restarted:
            run("systemctl", "restart", unit)
            healthy(unit, binary, probe)
        if not stamp.exists() or stamp.read_text().strip() != target:
            (tmp/"version").write_text(target+"\n")
            replace_file(tmp/"version", stamp, 0o600)
    except (Exception, KeyboardInterrupt):
        for dest, backup in reversed(backups):
            if backup:
                replace_file(backup, dest, backup.stat().st_mode & 0o777)
            else:
                dest.unlink()
        if any(dest == binary for dest, _ in backups):
            run("systemctl", "restart", unit)
            healthy(unit, binary, None)
            print("已恢复旧程序并重启。", file=sys.stderr)
        raise
    if changes:
        print("更新完成。" if restarted else "更新工具已更新，服务没有重启。")


def main():
    import fcntl
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["update", "install-cli"])
    p.add_argument("--check", action="store_true")
    p.add_argument("--role", choices=list(SERVICES))
    args = p.parse_args()
    if os.geteuid() != 0:
        fail("请以 root 运行")
    os.umask(0o077)
    with open("/run/stest-update.lock", "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == "install-cli":
            guard_cli()
            if not CLI.parent.is_dir():
                CLI.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                CLI.parent.chmod(0o755)
            replace_file(Path(__file__), CLI, 0o755)
        else:
            with tempfile.TemporaryDirectory(prefix="stest-update-") as d:
                update(args, Path(d))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as e:
        sys.exit("STest: " + str(e))
