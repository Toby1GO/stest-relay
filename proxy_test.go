package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFrames(t *testing.T) {
	var b bytes.Buffer
	if e := send(&b, connect, []byte("x:80")); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(b.Bytes(), []byte{0, 0, 0, 5, 2, 'x', ':', '8', '0'}) {
		t.Fatal(b.Bytes())
	}
	for _, length := range []uint32{0, 128 << 20, 0xffffffff} {
		var h [5]byte
		binary.BigEndian.PutUint32(h[:], length)
		if _, _, e := header(bytes.NewReader(h[:])); e == nil {
			t.Fatal(length)
		}
	}
}
func TestTokenRejected(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { defer b.Close(); serveTunnel(b, []string{"ok"}, &monitor{}) }()
	a.SetDeadline(time.Now().Add(time.Second))
	if e := send(a, auth, []byte("bad")); e != nil {
		t.Fatal(e)
	}
	typ, _, e := control(a)
	if e != nil || typ != failure {
		t.Fatal(typ, e)
	}
}
func TestRuleReload(t *testing.T) {
	p := t.TempDir()
	block, allow := filepath.Join(p, "block"), filepath.Join(p, "allow")
	for path, text := range map[string]string{block: "address=/example.org/0.0.0.0\n", allow: "*.example.org\nhome*\n*abc*\nrouter\n"} {
		if e := os.WriteFile(path, []byte(text), 0600); e != nil {
			t.Fatal(e)
		}
	}
	var r rules
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.watch(ctx, config{"client.block.path": block, "client.direct.allow.path": allow})
	for h, want := range map[string]string{"sub.Example.org": "block", "HOME1": "direct", "xabcx": "direct", "router": "direct", "notexample.org": "tunnel"} {
		if got := r.route(h); got != want {
			t.Fatal(h, got)
		}
	}
	if e := os.Remove(block); e != nil {
		t.Fatal(e)
	}
	end := time.Now().Add(4 * time.Second)
	for r.route("sub.example.org") != "direct" {
		if time.Now().After(end) {
			t.Fatal("delete did not hot reload")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
func TestMonitorRestore(t *testing.T) {
	f := filepath.Join(t.TempDir(), "stats.json")
	m := &monitor{}
	if e := m.load(f); e != nil {
		t.Fatal(e)
	}
	m.add("a", true, 2048)
	m.add("a", false, 1024)
	if e := m.save(f); e != nil {
		t.Fatal(e)
	}
	n := &monitor{}
	if e := n.load(f); e != nil {
		t.Fatal(e)
	}
	_, g := n.snapshot()
	if g.Read != 2048 || g.Write != 1024 {
		t.Fatal(g)
	}
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	r.RemoteAddr = "198.51.100.1:55"
	n.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
	w = httptest.NewRecorder()
	r.RemoteAddr = "127.0.0.1:55"
	n.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "2 kb") {
		t.Fatal(w.Body.String())
	}
}
func TestExplicitProxyRejections(t *testing.T) {
	c := client{cfg: config{"client.socks5.password.auth.enabled": "true", "client.socks5.username": "u", "client.socks5.password": "p"}}
	a, b := net.Pipe()
	defer a.Close()
	a.SetDeadline(time.Now().Add(time.Second))
	go func() { defer b.Close(); c.socks(b) }()
	a.Write([]byte{5, 1, 2})
	var buf [2]byte
	io.ReadFull(a, buf[:])
	a.Write([]byte{1, 1, 'u', 1, 'x'})
	if _, e := io.ReadFull(a, buf[:]); e != nil || buf != [2]byte{1, 1} {
		t.Fatal(buf, e)
	}
	w := httptest.NewRecorder()
	c.httpProxy(true)(w, httptest.NewRequest("GET", "http://example.test/", nil))
	if w.Code != 405 {
		t.Fatal(w.Code)
	}
}
func TestProperties(t *testing.T) {
	p := filepath.Join(t.TempDir(), "proxy.properties")
	if e := os.WriteFile(p, []byte("client.auth.token : t\\u0031\nserver.auth.token.list=t\\\n  1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := loadConfig(p)
	if e != nil || c.v("client.auth.token", "") != "t1" || c.tokens()[0] != "t1" {
		t.Fatal(c, e)
	}
}
