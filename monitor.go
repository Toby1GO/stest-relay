package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type totals struct {
	Read  int64  `json:"readBytes"`
	Write int64  `json:"writeBytes"`
	Token string `json:"token"`
}
type monitor struct {
	meter  *exitMeter
	mu     sync.Mutex
	global totals
	tokens map[string]totals
}

func (m *monitor) load(path string) error {
	m.global.Token = "global"
	m.tokens = map[string]totals{}
	p, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(p)) == "" {
		return nil
	}
	var rows []totals
	if e = json.Unmarshal(p, &rows); e != nil {
		return e
	}
	for _, r := range rows {
		if r.Token == "global" {
			m.global = r
		} else {
			m.tokens[r.Token] = r
		}
	}
	return nil
}
func (m *monitor) add(token string, in bool, n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.tokens[token]
	r.Token = token
	if in {
		r.Read += int64(n)
		m.global.Read += int64(n)
	} else {
		r.Write += int64(n)
		m.global.Write += int64(n)
	}
	m.tokens[token] = r
}
func (m *monitor) snapshot() ([]totals, totals) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := make([]totals, 0, len(m.tokens))
	for _, r := range m.tokens {
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Token < rows[j].Token })
	return rows, m.global
}
func (m *monitor) save(path string) error {
	rows, g := m.snapshot()
	p, e := json.MarshalIndent(append(rows, g), "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".stats-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	_, e = f.Write(p)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}
func pretty(n int64) string {
	var s []string
	for i, u := range []string{"tb", "gb", "mb", "kb"} {
		shift := uint(10 * (4 - i))
		if q := n >> shift; q > 0 {
			s = append(s, fmt.Sprintf("%d %s", q, u))
			n -= q << shift
		}
	}
	if len(s) == 0 {
		return "0 kb"
	}
	return strings.Join(s, " ")
}
func (m *monitor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		http.Error(w, "Forbidden", 403)
		return
	}
	if r.Method != "GET" || r.RequestURI != "/" {
		http.NotFound(w, r)
		return
	}
	view := func(r totals, g bool) map[string]string {
		v := map[string]string{"token": r.Token}
		if g || r.Read != 0 {
			v["inboundBytes"] = pretty(r.Read)
		}
		if g || r.Write != 0 {
			v["outboundBytes"] = pretty(r.Write)
		}
		return v
	}
	rows, g := m.snapshot()
	ts := make([]map[string]string, 0, len(rows))
	for _, r := range rows {
		ts = append(ts, view(r, false))
	}
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	json.NewEncoder(w).Encode(map[string]any{"global": view(g, true), "tokens": ts})
}
