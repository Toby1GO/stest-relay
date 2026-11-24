package center

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net"
	"net/http"
	"os"
	"socks5-go/internal/control"
	"sort"
	"strconv"
	"strings"
	"time"
)

type book struct {
	Counters map[string]control.Bytes `json:"counters"` // exit/month/A/port
	Rates    map[string]int64         `json:"rates"`    // month/A/port, cents per GiB
}

func loadBook(path string) (book, error) {
	b := book{map[string]control.Bytes{}, map[string]int64{}}
	raw, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return b, nil
	}
	if e == nil {
		e = json.Unmarshal(raw, &b)
	}
	if b.Counters == nil || b.Rates == nil {
		return b, fmt.Errorf("invalid ledger")
	}
	return b, e
}

type probe struct {
	Address string    `json:"address"`
	At      time.Time `json:"at"`
	MS      float64   `json:"ms"`
	OK      bool      `json:"ok"`
}

func (c *center) scheduleProbe(n managedNode, r *http.Request, port int) {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if e != nil || ip == nil || ip.IsLoopback() || ip.IsUnspecified() || port < 1 || port > 65535 {
		return
	}
	prev := c.probes[n.ID]
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	if time.Since(prev.At) < 15*time.Second && addr == prev.Address {
		return
	}
	now := time.Now().UTC()
	if addr != prev.Address {
		prev = probe{Address: addr}
	}
	prev.At = now
	c.probes[n.ID] = prev
	go func() {
		before := time.Now()
		conn, e := net.DialTimeout("tcp", addr, 3*time.Second)
		ms := float64(time.Since(before).Microseconds()) / 1000
		if conn != nil {
			conn.Close()
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.probes[n.ID].At == now {
			c.probes[n.ID] = probe{addr, now, ms, e == nil}
		}
	}()
}
func (c *center) exitReport(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[r.Header.Get("X-Node-ID")]
	key, has := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || n.Role != "B" || !has || subtle.ConstantTimeCompare([]byte(n.Secret), []byte(digest(key))) != 1 {
		http.Error(w, "invalid exit credential", 401)
		return
	}
	var report control.ExitReport
	if e := readBody(w, r, &report); e != nil || report.Port < 1 || report.Port > 65535 {
		http.Error(w, "invalid report", 400)
		return
	}
	counters := maps.Clone(c.book.Counters)
	changed := false
	for k, b := range report.Usage {
		if !validBucket(k) || b.Up < 0 || b.Down < 0 {
			http.Error(w, "invalid counter", 400)
			return
		}
		id := n.ID + "/" + k
		old := counters[id]
		next := control.Bytes{Up: max(old.Up, b.Up), Down: max(old.Down, b.Down)}
		if old != next {
			changed = true
			counters[id] = next
		}
	}
	if changed {
		next := c.book
		next.Counters = counters
		if e := control.SaveJSON(c.path+".billing", next); e != nil {
			http.Error(w, "ledger save failed", 500)
			return
		}
		c.book = next
	}
	if n.Install != nil && n.Install.Certificate != "" {
		if e := c.finishInstall(n); e != nil {
			http.Error(w, "save failed", 500)
			return
		}
	}
	c.live[n.ID] = observed{Seen: time.Now().UTC()}
	c.scheduleProbe(n, r, report.Port)
	jsonOut(w, struct{}{})
}
func validBucket(k string) bool {
	parts := strings.Split(k, "/")
	if len(parts) != 3 {
		return false
	}
	_, e := time.Parse("2006-01", parts[0])
	p, pe := strconv.Atoi(parts[2])
	return e == nil && control.NodeID.MatchString(parts[1]) && pe == nil && p > 0 && p <= 65535 && strconv.Itoa(p) == parts[2]
}

type billLine struct {
	Key string `json:"key"`
	control.Bytes
	Rate *int64 `json:"rate"`
	Fee  string `json:"fee"`
}

func (c *center) billing(w http.ResponseWriter, r *http.Request) {
	month := r.URL.Query().Get("month")
	if month == "" {
		month = control.Month(time.Now())
	}
	if _, e := time.Parse("2006-01", month); e != nil {
		http.Error(w, "invalid month", 400)
		return
	}
	lines := map[string]control.Bytes{}
	if month == control.Month(time.Now()) {
		for _, n := range c.nodes {
			if n.Desired != nil {
				for _, m := range n.Desired.Plan.Rules {
					lines[fmt.Sprintf("%s/%s/%d", month, n.ID, m.Port)] = control.Bytes{}
				}
			}
		}
	}
	for id, b := range c.book.Counters {
		_, k, _ := strings.Cut(id, "/")
		if strings.HasPrefix(k, month+"/") {
			v := lines[k]
			v.Up += b.Up
			v.Down += b.Down
			lines[k] = v
		}
	}
	rows := []billLine{}
	for k, b := range lines {
		line := billLine{Key: k, Bytes: b}
		if rate, ok := c.book.Rates[k]; ok {
			line.Rate = &rate
			sum := new(big.Int).Add(big.NewInt(b.Up), big.NewInt(b.Down))
			charge := new(big.Rat).SetFrac(sum.Mul(sum, big.NewInt(rate)), big.NewInt(100*(1<<30)))
			line.Fee = charge.FloatString(2)
		}
		rows = append(rows, line)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	jsonOut(w, map[string]any{"month": month, "current": control.Month(time.Now()), "rows": rows})
}
func (c *center) setRate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Key   string
		Cents *int64
	}
	if readBody(w, r, &in) != nil || !validBucket(in.Key) || !strings.HasPrefix(in.Key, control.Month(time.Now())+"/") || in.Cents == nil || *in.Cents < 0 || *in.Cents > 100000000 {
		http.Error(w, "仅可设置本月费率（分/GiB）", 400)
		return
	}
	next := c.book
	next.Rates = maps.Clone(next.Rates)
	next.Rates[in.Key] = *in.Cents
	if e := control.SaveJSON(c.path+".billing", next); e != nil {
		http.Error(w, "费率保存失败", 500)
		return
	}
	c.book = next
	jsonOut(w, struct{}{})
}
