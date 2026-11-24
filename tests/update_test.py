"""Exercise the updater transaction against a signed, disposable node release."""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("updater", ROOT / "install/stest.py")
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
SSL = os.environ.get("TEST_OPENSSL", "openssl")


class UpdateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.work.cleanup)
        cls.key = Path(cls.work.name) / "test-only.pem"
        subprocess.run([SSL, "genrsa", "-out", cls.key, "2048"], check=True, capture_output=True)
        cls.pub = subprocess.check_output([SSL, "rsa", "-in", cls.key, "-pubout"], stderr=subprocess.DEVNULL).decode()

    def setUp(self):
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        self.node, self.feed, self.tmp = [root/k for k in ("node", "feed", "tmp")]
        for p in (self.node, self.feed, self.tmp):
            p.mkdir()
        self.cli = self.node/"stest"
        self.cli.write_bytes(b"# STest Linux service updater.")
        self.exe = self.node/"socks5-go"
        self.exe.write_bytes(b"old")
        self.conf = self.node/"proxy.properties"
        self.conf.write_text("center.url=https://center.example:8443\nprivate=preserve\n")
        self.name = "socks5-go-linux-amd64"
        self.services, self.downloads = [], []
        def get(url, dest, ca=None, limit=None):
            self.assertTrue(url.startswith("https://center.example:8443/install/files/"))
            self.assertEqual(ca, self.node/"management-center.crt")
            name = url.rsplit("/", 1)[1]
            self.downloads.append(name)
            shutil.copyfile(self.feed/name, dest)
        original = u.run
        def run(*args):
            if args[0] == "openssl":
                return original(SSL, *args[1:])
            self.services.append(args)
        for obj, key, value in [(u,"PUBLIC_KEY",self.pub),(u,"BASE_VERSION","v1.3.0"),
                (u,"CLI",self.cli),(u.platform,"machine",lambda:"x86_64"),(u,"download",get),
                (u,"run",run),(u,"detect",lambda role: (role or "client","node.service",self.node,"socks5-go")),
                (u,"process_id",lambda *args: 10),(u,"healthy",lambda *args: None)]:
            stack.enter_context(patch.object(obj,key,value))

    def release(self, data=b"new", tag="v1.4.0"):
        doc = dict(format=1, scope="node", version=tag, sha256={self.name:hashlib.sha256(data).hexdigest(),
                   "stest":u.digest(self.cli)})
        (self.feed/self.name).write_bytes(data)
        f = self.feed/"manifest.json"
        f.write_text(json.dumps(doc))
        subprocess.run([SSL,"dgst","-sha256","-sign",self.key,"-out",self.feed/"manifest.sig",f],check=True)

    def invoke(self, check=False, role="client"):
        u.update(argparse.Namespace(check=check,role=role),self.tmp)

    def test_check_and_unchanged(self):
        self.release()
        self.invoke(check=True)
        self.assertEqual(self.downloads,["manifest.json","manifest.sig"])
        self.assertFalse((self.node/".stest-release").exists())
        self.release(b"old")
        self.invoke()
        self.assertNotIn(self.name,self.downloads)
        self.assertFalse(self.services)

    def test_update_both_node_roles(self):
        for role in ("client","server"):
            self.services.clear()
            self.exe.write_bytes(b"old")
            self.release()
            self.invoke(role=role)
            self.assertEqual(self.exe.read_bytes(),b"new")
            self.assertEqual(self.services,[("systemctl","restart","node.service")])
            self.assertIn("private=preserve",self.conf.read_text())

    def test_untrusted_artifacts(self):
        self.release()
        (self.feed/"manifest.json").write_text("{}")
        with self.assertRaises(subprocess.CalledProcessError):
            self.invoke()
        self.release()
        (self.feed/self.name).write_bytes(b"bad")
        with self.assertRaises(ValueError):
            self.invoke()
        self.release(tag="v1.2.9")
        with self.assertRaises(ValueError):
            self.invoke()
        self.assertEqual(self.exe.read_bytes(),b"old")
        self.assertFalse(self.services)

    def test_restart_failure_restores_previous_binary(self):
        self.release()
        with patch.object(u,"healthy",side_effect=[ValueError("unhealthy"),None]):
            with self.assertRaisesRegex(ValueError,"unhealthy"):
                self.invoke()
        self.assertEqual(self.exe.read_bytes(),b"old")
        self.assertEqual(len(self.services),2)
        self.assertFalse((self.node/".stest-release").exists())

    def test_center_resolves_stable_release_before_fetching_binary(self):
        self.name = "stest-center-linux-amd64"
        center = self.node / "stest-center"
        center.write_bytes(b"old")
        self.release()
        f = self.feed / "manifest.json"
        doc = json.loads(f.read_bytes())
        doc["scope"] = "center"
        f.write_text(json.dumps(doc))
        subprocess.run([SSL,"dgst","-sha256","-sign",self.key,"-out",self.feed/"manifest.sig",f],check=True)
        urls = []
        def github(url, dest, ca=None, limit=None):
            urls.append(url)
            self.assertIsNone(ca)
            if url == "https://api.github.com/repos/Toby1GO/stest-relay/releases/latest":
                dest.write_text(json.dumps(dict(tag_name="v1.4.0",draft=False,prerelease=False)))
            else:
                self.assertTrue(url.startswith(u.REPO + "/releases/download/v1.4.0/"))
                shutil.copyfile(self.feed/url.rsplit("/",1)[1],dest)
        (self.node/"admin.env").write_text("STEST_PUBLIC_URL=https://center.example:8443\n")
        with patch.object(u,"download",github), patch.object(u,"detect",return_value=(
                "center","stest-center.service",self.node,"stest-center")):
            self.invoke(check=True)
            self.assertEqual(len(urls),3)
            self.invoke()
        self.assertEqual(center.read_bytes(),b"new")
        self.assertEqual(self.services,[("systemctl","restart","stest-center.service")])

if __name__=="__main__":
    unittest.main()
