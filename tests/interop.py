"""Loopback integration test; optional upstream jars add both mixed Java/Go pairs."""
import argparse
import concurrent.futures
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--go-bin", required=True, type=lambda p: str(Path(p).resolve()))
parser.add_argument("--java", default="java")
parser.add_argument("--java-client", type=lambda p: str(Path(p).resolve()))
parser.add_argument("--java-server", type=lambda p: str(Path(p).resolve()))
parser.add_argument("--scratch", help="new directory for retaining test diagnostics")
parser.add_argument("--testcert", type=lambda p: str(Path(p).resolve()))
parser.add_argument("--openssl", default="openssl")
args = parser.parse_args()
class Origin(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass

def freeports(n):
    with contextlib.ExitStack() as s:
        socks = [s.enter_context(socket.socket()) for _ in range(n)]
        for sock in socks: sock.bind(("127.0.0.1", 0))
        return [v.getsockname()[1] for v in socks]

def exact(sock, n):
    data = bytearray()
    while len(data) < n:
        part = sock.recv(n-len(data))
        if not part: raise EOFError("unexpected end of stream")
        data.extend(part)
    return bytes(data)

def wait(proc, port):
    for _ in range(150):
        if proc.poll() is not None: raise RuntimeError(f"startup exit {proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), .1): return
        except OSError: time.sleep(.1)
    raise RuntimeError("startup timed out")

@contextlib.contextmanager
def process(cmd, cwd, label):
    with (cwd / (label+".log")).open("wb") as log:
        p = subprocess.Popen(cmd, cwd=cwd, stdout=log, stderr=subprocess.STDOUT)
        try: yield p
        except BaseException:
            log.flush()
            print((cwd / (label+".log")).read_text(errors="replace")[-2500:])
            raise
        finally:
            p.terminate()
            try: p.wait(3)
            except subprocess.TimeoutExpired: p.kill(); p.wait()

def working_set(proc):
    # Windows working set after the same requests; not peak or private bytes.
    import ctypes
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
            (n, ctypes.c_size_t) for n in ("peak", "current", "pp", "p", "np", "n", "page", "peakpage")]
    c = Counters()
    c.cb = ctypes.sizeof(c)
    if not ctypes.windll.psapi.GetProcessMemoryInfo(wintypes.HANDLE(proc._handle), ctypes.byref(c), c.cb):
        raise ctypes.WinError()
    return c.current / (1024 * 1024)

def exercise(directory, origin, java_client, java_server):
    b,s,h,c,m = freeports(5)
    cfg = f"""server.host=127.0.0.1
server.port={b}
server.monitor.port={m}
client.socks5.port={s}
client.http.port={h}
client.https.port={c}
client.http.enabled=true
client.https.enabled=true
client.socks5.password.auth.enabled=true
client.socks5.username=test
client.socks5.password=pass
client.auth.token=test-token
server.auth.token.list=test-token
"""
    (directory/"proxy.properties").write_text(cfg)
    def cmd(role, jar):
        return [args.java,"-XX:ActiveProcessorCount=2","-jar",jar] if jar else [args.go_bin,role]
    payload = os.urandom(180_000)
    target = f"127.0.0.1:{origin}"
    def request(mode):
        port = {"socks":s, "http":h, "connect":c}[mode]
        with socket.create_connection(("127.0.0.1", port), 6) as sock:
            if mode == "socks":
                sock.sendall(b"\5\1\2"); assert exact(sock,2)==b"\5\2"
                sock.sendall(b"\1\4test\4pass"); assert exact(sock,2)==b"\1\0"
                sock.sendall(b"\5\1\0\1\x7f\0\0\1"+origin.to_bytes(2,"big"))
                assert exact(sock,10)[:2]==b"\5\0"
            if mode == "connect":
                sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
                hdr = bytearray()
                while not hdr.endswith(b"\r\n\r\n"): hdr.extend(exact(sock,1))
                assert b" 200 " in hdr
            uri = f"http://{target}/echo?x=1" if mode=="http" else "/echo?x=1"
            sock.sendall(f"POST {uri} HTTP/1.1\r\nHost: {target}\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()+payload)
            with sock.makefile("rb") as f: response = f.read()
            head, body = response.split(b"\r\n\r\n",1)
            assert b" 200 " in head and body==payload,(mode,len(body))
    with process(cmd("server",java_server),directory,"server") as server:
        wait(server,b)
        with process(cmd("client",java_client),directory,"client") as client:
            wait(client,s)
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(request,["socks","http","connect","socks"]))
            with urllib.request.urlopen(f"http://127.0.0.1:{m}/") as resp:
                detail=json.load(resp); assert detail["global"]["inboundBytes"]!="0 kb"
            if os.name=="nt": print(f"working set (MiB): client={working_set(client):.1f} server={working_set(server):.1f}", flush=True)
    print(("Java" if java_client else "Go")+" client -> "+("Java" if java_server else "Go")+" server: PASS")

def fixed_ports(root, origin, java_server):
    # Two isolated test landings: negotiate SOCKS5, accept only their own login,
    # and only permit a CONNECT to the loopback test origin.
    class Landing(socketserver.BaseRequestHandler):
        def handle(self):
            s = self.request
            s.settimeout(5)
            try:
                assert exact(s,3)==b"\5\1\2"
            except EOFError:  # readiness probe
                return
            s.sendall(b"\5\2")
            assert exact(s,1)==b"\1"
            user=exact(s,exact(s,1)[0])
            password=exact(s,exact(s,1)[0])
            if (user,password)!=self.server.login:
                s.sendall(b"\1\1"); return
            s.sendall(b"\1\0")
            assert exact(s,10)==b"\5\1\0\1\x7f\0\0\1"+origin.to_bytes(2,"big")
            with socket.create_connection(("127.0.0.1",origin),5) as dest:
                s.sendall(b"\5\0\0\1"+bytes(6))
                body=exact(s,32)
                dest.sendall(b"POST / HTTP/1.0\r\nContent-Length: 32\r\n\r\n"+body)
                with dest.makefile("rb") as resp: result=resp.read()
                s.sendall(user+b":"+result.split(b"\r\n\r\n",1)[1])
    with contextlib.ExitStack() as stack:
        b,m,x,y=freeports(4)
        cfg=f"server.port={b}\nserver.monitor.port={m}\nclient.auth.token=test\nserver.auth.token.list=test\n"
        for port,label in [(x,b"tw"),(y,b"other")]:
            srv=stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1",0),Landing))
            srv.login=(label,label+b"-pass")
            threading.Thread(target=srv.serve_forever,daemon=True).start()
            stack.callback(srv.shutdown)
            cfg+=f"client.forward.{port}=127.0.0.1:{srv.server_address[1]}\n"
        (root/"proxy.properties").write_text(cfg)
        (root/"direct-allow.conf").write_text("127.0.0.1\n")  # fixed ports must still use B
        cmd=[args.java,"-XX:ActiveProcessorCount=2","-jar",java_server] if java_server else [args.go_bin,"server"]
        server=stack.enter_context(process(cmd,root,"fixed-server"));wait(server,b)
        client=stack.enter_context(process([args.go_bin,"client","forward"],root,"fixed-client"));wait(client,x)
        def probe(port,user,ok):
            with socket.create_connection(("127.0.0.1",port),5) as s:
                s.sendall(b"\5\1\2");assert exact(s,2)==b"\5\2"
                pwd=user+b"-pass";s.sendall(b"\1"+bytes([len(user)])+user+bytes([len(pwd)])+pwd)
                assert exact(s,2)==(b"\1\0" if ok else b"\1\1")
                if ok:
                    s.sendall(b"\5\1\0\1\x7f\0\0\1"+origin.to_bytes(2,"big"))
                    assert exact(s,10)[:2]==b"\5\0"
                    body=os.urandom(32);s.sendall(body);assert exact(s,len(user)+33)==user+b":"+body
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            jobs=[pool.submit(probe,*a) for a in [(x,b"tw",True),(y,b"other",True),(x,b"other",False),(y,b"tw",False)]]
            for j in jobs: j.result()
        with urllib.request.urlopen(f"http://127.0.0.1:{m}/") as resp:
            assert "test" in [r["token"] for r in json.load(resp)["tokens"]]
        server.terminate();server.wait(5)
        with socket.create_connection(("127.0.0.1",x),5) as s:
            try: s.sendall(b"\5\1\2"); assert not s.recv(2)
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError): pass
        print("Fixed ports via "+("Java" if java_server else "Go")+" B: correct/wrong logins, origin echo and no direct fallback: PASS")

if args.scratch: Path(args.scratch).mkdir(exist_ok=False)
with (contextlib.nullcontext(args.scratch) if args.scratch else tempfile.TemporaryDirectory()) as tmp, http.server.ThreadingHTTPServer(("127.0.0.1",0),Origin) as origin:
    root=Path(tmp).resolve()
    subprocess.run([args.testcert] if args.testcert else [args.openssl,"req","-x509","-newkey","rsa:2048","-nodes","-keyout","server.key","-out","server.crt","-days","1","-subj","/CN=MyTunnelServer"],cwd=root,check=True,stderr=subprocess.DEVNULL)
    threading.Thread(target=origin.serve_forever,daemon=True).start()
    for jc,js in [(None,None)]+([(args.java_client,None)] if args.java_client else [])+([(None,args.java_server)] if args.java_server else []):
        exercise(root,origin.server_port,jc,js)
    fixed_ports(root,origin.server_port,None)
    if args.java_server: fixed_ports(root,origin.server_port,args.java_server)
    origin.shutdown()
