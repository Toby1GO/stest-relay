package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	mgmt "socks5-go/internal/control"
	"strings"
	"time"
)

type agentCache struct {
	ID, Center string
	Revision   revision
}
type nodeAgent struct {
	id, endpoint, token, path string
	http                      *http.Client
	current                   revision
	h                         heartbeat
	f                         *liveForwards
}

func newAgent(cfg config, f *liveForwards, initial plan) (*nodeAgent, error) {
	endpoint := strings.TrimRight(cfg.v("center.url", ""), "/")
	u, e := url.Parse(endpoint)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
		return nil, errors.New("center.url 需要 HTTPS（本机回环地址可使用 HTTP）")
	}
	id, key := cfg.v("center.node-id", ""), cfg.v("center.node-token", "")
	if !mgmt.NodeID.MatchString(id) || key == "" {
		return nil, errors.New("需要有效的 center.node-id 和 center.node-token")
	}
	a := &nodeAgent{id: id, token: key, endpoint: endpoint, path: cfg.v("center.cache", "center-"+id+"-applied.json"), f: f, current: revision{Plan: initial},
		http: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		h:    heartbeat{B: net.JoinHostPort(cfg.v("server.host", "127.0.0.1"), cfg.port("server.port"))}}
	b, e := os.ReadFile(a.path)
	if e == nil {
		var cache agentCache
		if e = json.Unmarshal(b, &cache); e != nil {
			return nil, e
		}
		if cache.ID != id || cache.Center != endpoint {
			return nil, errors.New("节点缓存不属于当前中心或节点，请为新节点指定独立 center.cache")
		}
		a.current = cache.Revision
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	a.h.Applied = a.current.Version
	a.h.Tried = a.current.Version
	return a, nil
}
func (a *nodeAgent) poll(ctx context.Context) error {
	// At most three exchanges: heartbeat, first-time import, immediate receipt.
	for i := 0; i < 3; i++ {
		b, e := json.Marshal(a.h)
		if e != nil {
			return e
		}
		req, e := http.NewRequestWithContext(ctx, "POST", a.endpoint+"/agent/sync", bytes.NewReader(b))
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+a.token)
		req.Header.Set("X-Node-ID", a.id)
		req.Header.Set("X-Port-Policy", "1")
		req.Header.Set("Content-Type", "application/json")
		res, e := a.http.Do(req)
		if e != nil {
			return e
		}
		body, e := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		res.Body.Close()
		if e != nil {
			return e
		}
		if res.StatusCode != 200 {
			if res.StatusCode == http.StatusUnauthorized && a.current.Version != "revoked" {
				restricted := a.current
				restricted.Version = "revoked"
				restricted.Plan.Rules = nil
				a.f.revoke()
				if err := mgmt.SaveJSON(a.path, agentCache{a.id, a.endpoint, restricted}); err != nil {
					return err
				}
				a.current = restricted
				a.h.Applied = restricted.Version
			}
			return fmt.Errorf("中心 HTTP %d: %.200s", res.StatusCode, body)
		}
		var reply struct {
			Bootstrap bool
			Desired   *revision
		}
		if e = json.Unmarshal(body, &reply); e != nil {
			return e
		}
		a.h.Initial = nil
		if reply.Bootstrap {
			a.h.Initial = &a.current.Plan
			continue
		}
		v := reply.Desired
		if v == nil {
			return nil
		}
		if i > 0 && a.h.Tried == v.Version && a.h.Error != "" {
			return nil
		}
		a.h.Tried = v.Version
		e = a.f.apply(v.Plan, func() error { return mgmt.SaveJSON(a.path, agentCache{a.id, a.endpoint, *v}) })
		if e != nil {
			a.h.Error = e.Error()
			log.Printf("center apply: %v", e)
		} else {
			a.current = *v
			a.h.Applied = v.Version
			a.h.Error = ""
		}
	}
	return nil
}
func (a *nodeAgent) run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	defer a.http.CloseIdleConnections()
	for {
		if e := a.poll(ctx); e != nil && ctx.Err() == nil {
			log.Printf("center sync: %v", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
