package center

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"socks5-go/internal/control"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web/vue.global.prod.js
var vueJS []byte

//go:embed web/console.css
var consoleCSS []byte

//go:embed web/index.html
var centerPage []byte

type revision = control.Revision
type plan = control.Plan
type entry struct {
	At   time.Time `json:"at"`
	Text string    `json:"text"`
}
type managedNode struct {
	Install *enrollment `json:"enrollment,omitempty"`
	Role    string      `json:"role,omitempty"`
	ID      string      `json:"id"`
	Region  string      `json:"region"`
	Secret  string      `json:"secret,omitempty"` // only the hash is stored
	Desired *revision   `json:"desired"`
	History []entry     `json:"history"`
}
type heartbeat = control.Heartbeat
type observed struct {
	heartbeat
	Seen       time.Time `json:"seen"`
	PortPolicy bool      `json:"portPolicy"`
}
type center struct {
	bootstrapURL, pin, centerPEM string
	book                         book
	probes                       map[string]probe
	mu                           sync.Mutex
	nodes                        map[string]managedNode
	live                         map[string]observed
	path, password               string
}

func nonce() (string, error) {
	var b [24]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func readBody(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if e := dec.Decode(v); e != nil {
		return e
	}
	if e := dec.Decode(&struct{}{}); e != io.EOF {
		return errors.New("无效的 JSON")
	}
	return nil
}
func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func (c *center) commit(n managedNode, msg string) error {
	h := append([]entry{{time.Now().UTC(), msg}}, n.History...)
	n.History = h[:min(40, len(h))]
	old, ok := c.nodes[n.ID]
	c.nodes[n.ID] = n
	if e := control.SaveJSON(c.path, c.nodes); e != nil {
		if ok {
			c.nodes[n.ID] = old
		} else {
			delete(c.nodes, n.ID)
		}
		return e
	}
	return nil
}
func (c *center) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	if (r.URL.Path == "/install/redeem" || r.URL.Path == "/install/certificate") && r.Method == "POST" {
		c.bootstrap(w, r)
		return
	}
	if r.URL.Path == "/agent/exit" && r.Method == "POST" {
		c.exitReport(w, r)
		return
	}
	if r.URL.Path == "/agent/sync" && r.Method == "POST" {
		c.sync(w, r)
		return
	}
	u, p, ok := r.BasicAuth()
	if !ok || u != "admin" || subtle.ConstantTimeCompare([]byte(digest(p)), []byte(digest(c.password))) != 1 {
		w.Header().Set("WWW-Authenticate", `Basic realm="Node Center", charset="UTF-8"`)
		http.Error(w, "请使用管理员账号登录", 401)
		return
	}
	if r.URL.Path == "/console.css" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Write(consoleCSS)
		return
	}
	if r.URL.Path == "/vue.js" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write(vueJS)
		return
	}
	if r.URL.Path == "/" && r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(centerPage)
		return
	}
	if r.Method == "POST" && (r.Header.Get("X-Center-Request") != "1" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json")) {
		http.Error(w, "需要管理页面请求", 403)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case r.URL.Path == "/api/pair" && r.Method == "POST":
		c.pair(w, r)
	case r.URL.Path == "/api/billing" && r.Method == "GET":
		c.billing(w, r)
	case r.URL.Path == "/api/rate" && r.Method == "POST":
		c.setRate(w, r)
	case r.URL.Path == "/api/nodes" && r.Method == "GET":
		type row struct {
			Probe probe `json:"probe"`
			managedNode
			Generation string   `json:"generation"`
			Status     observed `json:"status"`
			Online     bool     `json:"online"`
		}
		rows := []row{}
		for _, n := range c.nodes {
			generation := digest(n.Secret)
			n.Secret = ""
			n.Install = nil
			s := c.live[n.ID]
			rows = append(rows, row{c.probes[n.ID], n, generation, s, time.Since(s.Seen) < 50*time.Second})
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
		jsonOut(w, rows)
	case r.URL.Path == "/api/nodes" && r.Method == "POST":
		var in struct{ ID, Region, Role string }
		if readBody(w, r, &in) != nil || !control.NodeID.MatchString(in.ID) || (in.Role != "" && in.Role != "A" && in.Role != "B") || len(in.Region) > 200 {
			http.Error(w, "节点标识须为 1–64 位字母、数字、下划线或短横线", 400)
			return
		}
		if _, ok := c.nodes[in.ID]; ok {
			http.Error(w, "节点标识已存在", 409)
			return
		}
		key, e := nonce()
		if e != nil {
			http.Error(w, "随机密钥生成失败", 500)
			return
		}
		if e = c.commit(managedNode{Role: in.Role, ID: in.ID, Region: in.Region, Secret: digest(key)}, "已创建，等待 A 首次连接"); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		jsonOut(w, map[string]string{"token": key})
	case r.URL.Path == "/api/nodes/delete" && r.Method == "POST":
		var in struct{ ID, Generation, Base string }
		if e := readBody(w, r, &in); e != nil {
			http.Error(w, "请求格式错误", 400)
			return
		}
		n, ok := c.nodes[in.ID]
		if !ok {
			http.NotFound(w, r)
			return
		}
		base := ""
		if n.Desired != nil {
			base = n.Desired.Version
		}
		if digest(n.Secret) != in.Generation || base != in.Base {
			http.Error(w, "节点已变更，请刷新后重试", 409)
			return
		}
		delete(c.nodes, in.ID)
		if e := control.SaveJSON(c.path, c.nodes); e != nil {
			c.nodes[in.ID] = n
			http.Error(w, e.Error(), 500)
			return
		}
		delete(c.live, in.ID)
		delete(c.probes, in.ID)
		jsonOut(w, struct{}{})
	case r.URL.Path == "/api/publish" && r.Method == "POST":
		var in struct {
			ID, Base string
			Plan     plan
		}
		if e := readBody(w, r, &in); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		n, ok := c.nodes[in.ID]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if n.Desired == nil || n.Desired.Version != in.Base {
			http.Error(w, "配置已变更或 A 尚未接入，请重新载入", 409)
			return
		}
		if e := in.Plan.Validate(); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		if !c.live[n.ID].PortPolicy && needsPolicy(in.Plan) {
			http.Error(w, "请等待支持端口策略的 A 上报后再发布", 409)
			return
		}
		v, e := nonce()
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		n.Desired = &revision{Version: v, Plan: in.Plan}
		if e = c.commit(n, "已发布 "+v[:8]+"，等待 A 应用"); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		jsonOut(w, n.Desired)
	default:
		http.NotFound(w, r)
	}
}
func (c *center) sync(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, ok := c.nodes[r.Header.Get("X-Node-ID")]
	token, has := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || n.Role == "B" || !has || subtle.ConstantTimeCompare([]byte(n.Secret), []byte(digest(token))) != 1 {
		http.Error(w, "无效的节点凭据", 401)
		return
	}
	var h heartbeat
	if e := readBody(w, r, &h); e != nil {
		http.Error(w, e.Error(), 400)
		return
	}
	if len(h.Error) > 2048 || len(h.B) > 512 {
		http.Error(w, "状态过长", 400)
		return
	}
	if n.Desired == nil {
		if h.Initial == nil {
			jsonOut(w, map[string]bool{"bootstrap": true})
			return
		}
		if e := h.Initial.Validate(); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		v, e := nonce()
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		n.Desired = &revision{Version: v, Plan: *h.Initial}
		if e = c.commit(n, "已导入 A 现有映射 "+v[:8]); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
	}
	for _, rule := range n.Desired.Plan.Rules {
		if !rule.Restricted(time.Now()) {
			c.scheduleProbe(n, r, rule.Port)
			break
		}
	}
	if e := c.finishInstall(c.nodes[n.ID]); e != nil {
		http.Error(w, "save failed", 500)
		return
	}
	n = c.nodes[n.ID]
	h.Initial = nil
	prev := c.live[n.ID]
	if h.Tried == n.Desired.Version && (prev.Tried != h.Tried || prev.Error != h.Error) {
		msg := "已生效 " + h.Tried[:8]
		if h.Error != "" {
			msg = "应用失败 " + h.Tried[:8] + "：" + h.Error
		}
		if e := c.commit(c.nodes[n.ID], msg); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
	}
	c.live[n.ID] = observed{h, time.Now().UTC(), r.Header.Get("X-Port-Policy") == "1"}
	if needsPolicy(n.Desired.Plan) && !c.live[n.ID].PortPolicy {
		// Old agents ignore policy fields. Send only unrestricted rules, and
		// withhold scheduled rules until this agent supports local expiry.
		safe := *n.Desired
		safe.Version = "compat-" + safe.Version
		safe.Plan.Rules = nil
		for _, rule := range n.Desired.Plan.Rules {
			if !rule.Disabled && rule.ExpiresAt == nil {
				safe.Plan.Rules = append(safe.Plan.Rules, rule)
			}
		}
		if safe.Version != h.Applied {
			jsonOut(w, map[string]any{"desired": safe})
		} else {
			jsonOut(w, struct{}{})
		}
		return
	}
	if n.Desired.Version != h.Applied {
		jsonOut(w, map[string]any{"desired": n.Desired})
		return
	}
	jsonOut(w, struct{}{})
}
func needsPolicy(p plan) bool {
	for _, rule := range p.Rules {
		if rule.Disabled || rule.ExpiresAt != nil {
			return true
		}
	}
	return false
}

func New(path, password string) (http.Handler, error) {
	ledger, err := loadBook(path + ".billing")
	if err != nil {
		return nil, err
	}
	c := &center{book: ledger, probes: map[string]probe{}, path: path, password: password, nodes: map[string]managedNode{}, live: map[string]observed{}}
	b, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(b, &c.nodes); e != nil {
			return nil, e
		}
		if c.nodes == nil {
			return nil, fmt.Errorf("invalid state file")
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return c, nil
}
func Run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("center", flag.ContinueOnError)
	addr := fs.String("listen", "127.0.0.1:8088", "HTTP(S) listen address")
	path := fs.String("state", "center-state.json", "state file")
	cert := fs.String("cert", "", "HTTPS certificate")
	key := fs.String("key", "", "HTTPS private key")
	if e := fs.Parse(args); e != nil {
		return e
	}
	pw := os.Getenv("SOCKS_CENTER_PASSWORD")
	if len(pw) < 12 {
		return errors.New("请设置至少 12 字节的 SOCKS_CENTER_PASSWORD")
	}
	host, _, e := net.SplitHostPort(*addr)
	if e != nil {
		return e
	}
	if (*key == "") != (*cert == "") {
		return errors.New("必须同时指定 -cert 和 -key")
	}
	if *cert == "" && !net.ParseIP(host).IsLoopback() {
		return errors.New("非回环监听需要 HTTPS 证书")
	}
	c, e := New(*path, pw)
	if e != nil {
		return e
	}
	if e = c.(*center).setupInstall(os.Getenv("STEST_PUBLIC_URL"), *cert); e != nil {
		return e
	}
	s := &http.Server{Addr: *addr, Handler: c, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
	go func() { <-ctx.Done(); s.Close() }()
	log.Printf("center listening on %s", *addr)
	if *cert != "" {
		e = s.ListenAndServeTLS(*cert, *key)
	} else {
		e = s.ListenAndServe()
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
