package center

import (
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestPairInstallation(t *testing.T) {
	h, e := New(filepath.Join(t.TempDir(), "state"), "admin-secret")
	if e != nil {
		t.Fatal(e)
	}
	c := h.(*center)
	c.bootstrapURL = "https://192.0.2.1:8443"
	c.centerPEM = "center-public"
	c.pin = "test-pin"
	call := func(path, key string, data any, admin bool, want int) []byte {
		raw, _ := json.Marshal(data)
		r := httptest.NewRequest("POST", path, strings.NewReader(string(raw)))
		w := httptest.NewRecorder()
		if admin {
			r.SetBasicAuth("admin", "admin-secret")
			r.Header.Set("X-Center-Request", "1")
			r.Header.Set("Content-Type", "application/json")
		} else {
			r.Header.Set("Authorization", "Bearer "+key)
		}
		c.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	var commands map[string]string
	if e = json.Unmarshal(call("/api/pair", "", map[string]string{"Client": "a01", "Server": "b01", "ClientIP": "192.0.2.2", "ServerIP": "127.0.0.1"}, true, 200), &commands); e != nil {
		t.Fatal(e)
	}
	ticket := func(role string) string {
		args := strings.Fields(commands[role])
		return strings.Trim(args[len(args)-1], "'")
	}
	get := func(id, role string, code int) map[string]string {
		res := call("/install/redeem", ticket(role), map[string]string{"ID": id, "role": role}, false, code)
		if code != 200 {
			return nil
		}
		var v map[string]string
		json.Unmarshal(res, &v)
		return v
	}
	get("a01", "client", 409)
	b := get("b01", "server", 200)
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	call("/install/certificate", b["nodeToken"], map[string]string{"id": "b01", "certificate": cert}, false, 200)
	if e = c.finishInstall(c.nodes["b01"]); e != nil {
		t.Fatal(e)
	}
	get("b01", "server", 403)
	a := get("a01", "client", 200)
	if a["certificate"] != cert || a["center"] != c.centerPEM || !strings.Contains(b["config"], "server.meter.owner.a01="+c.nodes["a01"].Install.Tunnel) || !strings.Contains(a["config"], "server.host=127.0.0.1") {
		t.Fatal("automatic pairing failed")
	}
}
