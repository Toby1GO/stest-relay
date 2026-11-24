package center

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"socks5-go/install"
	"strings"
	"testing"
	"time"
)

func TestCenterDeliversVerifiedNodePackages(t *testing.T) {
	if !install.Ready() {
		t.Skip("run python install/build_center.py to test bundled payloads")
	}
	c := new(center)
	get := func(name string, want int) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		c.ServeHTTP(w, httptest.NewRequest("GET", "/install/files/"+name, nil))
		if w.Code != want {
			t.Fatalf("%s: HTTP %d", name, w.Code)
		}
		return w.Body.Bytes()
	}
	script := string(get("node.sh", 200))
	if !strings.Contains(script, "$url/install/files/") || strings.Contains(script, "github.com") || strings.Contains(script, "\r") {
		t.Fatal("unexpected bootstrap script")
	}
	sums := string(get("SHA256SUMS", 200))
	for _, arch := range []string{"amd64", "arm64"} {
		name := "socks5-go-linux-" + arch
		b := get(name, 200)
		if !strings.HasPrefix(string(b[:4]), "\x7fELF") || !strings.Contains(sums, fmt.Sprintf("%x  %s\n", sha256.Sum256(b), name)) {
			t.Fatal("invalid release asset: " + name)
		}
	}
	get("center-state.json", 404)
}

func TestRenewPendingClientAfterServerFinished(t *testing.T) {
	if !install.Ready() {
		t.Skip("requires bundled center")
	}
	c := &center{path: filepath.Join(t.TempDir(), "state"), bootstrapURL: "https://center.example", pin: "sha256//pin", nodes: map[string]managedNode{
		"a": {ID: "a", Role: "A", Secret: digest("node"), Install: &enrollment{Peer: "b", TicketHash: digest("old"), Until: time.Now().Add(-time.Hour), NodeKey: "node", Tunnel: "pair"}},
		"b": {ID: "b", Role: "B", Install: &enrollment{Peer: "a", Certificate: "public-cert"}},
	}}
	renew := func(id string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		c.renewInstall(w, httptest.NewRequest("POST", "/", strings.NewReader(fmt.Sprintf(`{"id":%q,"generation":%q}`, id, digest(c.nodes[id].Secret)))))
		return w
	}
	w := renew("a")
	var cmd map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &cmd) != nil || !strings.Contains(cmd["client"], "/install/files/node.sh") {
		t.Fatal("no center-hosted command")
	}
	fields := strings.Fields(cmd["client"])
	key := strings.Trim(fields[len(fields)-1], "'")
	for _, test := range []struct {
		key  string
		code int
	}{{"old", 403}, {key, 200}} {
		r := httptest.NewRequest("POST", "/install/redeem", strings.NewReader(`{"id":"a","role":"client"}`))
		r.Header.Set("Authorization", "Bearer "+test.key)
		w := httptest.NewRecorder()
		c.bootstrap(w, r)
		if w.Code != test.code {
			t.Fatalf("redeem: got %d, want %d", w.Code, test.code)
		}
	}
	if renew("b").Code != 409 || c.nodes["b"].Install.Certificate != "public-cert" {
		t.Fatal("completed server enrollment changed")
	}
}
