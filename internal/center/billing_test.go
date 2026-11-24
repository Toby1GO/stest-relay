package center

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"socks5-go/internal/control"
	"strings"
	"testing"
	"time"
)

func TestBillingReplayAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	h, _ := New(path, "admin-password")
	c := h.(*center)
	if e := c.commit(managedNode{ID: "b", Role: "B", Secret: digest("secret")}, "init"); e != nil {
		t.Fatal(e)
	}
	key := control.Month(time.Now()) + "/alpha/11001"
	call := func(path, method, body string, server bool) string {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.RemoteAddr = "127.0.0.1:1234"
		if server {
			r.Header.Set("Authorization", "Bearer secret")
			r.Header.Set("X-Node-ID", "b")
		} else {
			r.SetBasicAuth("admin", "admin-password")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-Center-Request", "1")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	payload := `{"port":8001,"usage":{"` + key + `":{"up":536870912,"down":536870912}}}`
	call("/agent/exit", "POST", payload, true)
	call("/agent/exit", "POST", payload, true)
	call("/api/rate", "POST", `{"key":"`+key+`","cents":125}`, false)
	var e error
	h, e = New(path, "admin-password")
	if e != nil {
		t.Fatal(e)
	}
	var bill struct{ Rows []billLine }
	if e = json.Unmarshal([]byte(call("/api/billing", "GET", "", false)), &bill); e != nil || len(bill.Rows) != 1 || bill.Rows[0].Fee != "1.25" {
		t.Fatal(bill, e)
	}
}
