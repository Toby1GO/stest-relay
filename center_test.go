package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"socks5-go/internal/center"
	"strings"
	"testing"
	"time"
)

func TestCenterLifecycle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "center.json")
	const password = "management-secret"
	h, e := center.New(path, password)
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	request := func(path string, data any, admin bool, want int) []byte {
		body, _ := json.Marshal(data)
		method := "POST"
		if data == nil {
			method = "GET"
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if admin {
			r.SetBasicAuth("admin", password)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Center-Request", "1")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %d: %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	request("/api/nodes", nil, false, 401)
	request("/agent/sync", map[string]any{}, false, 401)
	auth := request("/api/nodes", map[string]string{"id": "a1", "region": "广州"}, true, 200)
	var reg struct{ Token string }
	if e := json.Unmarshal(auth, &reg); e != nil || reg.Token == "" {
		t.Fatal(e)
	}
	busy, e := net.Listen("tcp", ":0")
	if e != nil {
		t.Fatal(e)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	cfg := config{"center.url": server.URL, "center.node-id": "a1", "center.node-token": reg.Token, "center.cache": filepath.Join(dir, "cache.json")}
	f := &liveForwards{g: &group{active: map[*tracked]bool{}}, base: &client{cfg: cfg}}
	defer f.close()
	p := plan{IP: "203.0.113.4", Ports: "20000-20127"}
	a, e := newAgent(cfg, f, p)
	if e != nil {
		t.Fatal(e)
	}
	poll := func() {
		if e := a.poll(context.Background()); e != nil {
			t.Fatal(e)
		}
	}
	poll()
	base := a.current.Version
	if base == "" || a.h.Applied != base || a.current.Plan.IP != p.IP {
		t.Fatal("bootstrap/receipt failed")
	}
	p.Rules = []mapping{{Port: port, Target: "127.0.0.1:1080", UDP: true}}
	pub := map[string]any{"id": "a1", "base": base, "plan": p}
	request("/api/publish", pub, true, 200)
	request("/api/publish", pub, true, 409)
	poll()
	if a.h.Error == "" || a.h.Applied != base || len(f.active) != 0 {
		t.Fatal("failed publish replaced working config")
	}
	busy.Close()
	poll()
	if a.h.Error != "" || a.current.Version == base || len(f.active) != 1 {
		t.Fatal("retry did not apply")
	}
	list := request("/api/nodes", nil, true, http.StatusOK)
	if bytes.Contains(list, []byte(reg.Token)) || bytes.Contains(list, []byte(`"secret":`)) {
		t.Fatal("credentials in listing")
	}
	server.Close()
	f.close()
	restored, e := newAgent(cfg, f, plan{})
	if e != nil || restored.current.Version != a.current.Version {
		t.Fatal("offline cache", e)
	}
	if e = f.apply(restored.current.Plan, nil); e != nil || len(f.active) != 1 {
		t.Fatal("offline restore", e)
	}
	// An isolated A enforces the cached deadline without polling the center.
	expiry := time.Now().Add(90 * time.Millisecond)
	p.Rules[0].ExpiresAt = &expiry
	if e = f.apply(p, nil); e != nil {
		t.Fatal(e)
	}
	old, peer := net.Pipe()
	defer peer.Close()
	f.mu.Lock()
	f.sessions = map[int]map[net.Conn]bool{port: {old: true}}
	f.mu.Unlock()
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	if _, err := peer.Read(one[:]); err != io.EOF {
		t.Fatalf("expired session: %v", err)
	}
	f.mu.Lock()
	stillOpen := f.active[port] != nil
	f.mu.Unlock()
	if stillOpen {
		t.Fatal("expired listener remained open")
	}
	p.Rules[0].ExpiresAt = nil
	if e = f.apply(p, nil); e != nil || len(f.active) != 1 {
		t.Fatal("renewal", e)
	}
	p.Rules[0].Disabled = true
	if e = f.apply(p, nil); e != nil || len(f.active) != 0 {
		t.Fatal("disable", e)
	}
	b, e := os.ReadFile(path)
	if e != nil || !strings.Contains(string(b), "应用失败") || !strings.Contains(string(b), "已生效") {
		t.Fatal("missing persisted history", e)
	}
	var rows []struct {
		Generation string
		Desired    revision
	}
	if e = json.Unmarshal(list, &rows); e != nil || len(rows) != 1 {
		t.Fatal(e)
	}
	del := map[string]string{"id": "a1", "base": rows[0].Desired.Version, "generation": "stale"}
	request("/api/nodes/delete", del, true, 409)
	del["generation"] = rows[0].Generation
	request("/api/nodes/delete", del, true, 200)
	if got := string(request("/api/nodes", nil, true, 200)); strings.TrimSpace(got) != "[]" {
		t.Fatal(got)
	}

}
