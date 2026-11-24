package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	mgmt "socks5-go/internal/control"
	"strconv"
	"strings"
	"sync"
	"time"
)

type exitMeter struct {
	mu     sync.Mutex
	owners map[string]string
	usage  map[string]mgmt.Bytes
	path   string
	dirty  bool
}

func loadMeter(c config) (*exitMeter, error) {
	m := &exitMeter{owners: map[string]string{}, usage: map[string]mgmt.Bytes{}, path: c.v("server.meter.path", "meter-monthly.json")}
	for k, token := range c {
		owner, ok := strings.CutPrefix(k, "server.meter.owner.")
		if !ok {
			continue
		}
		if !mgmt.NodeID.MatchString(owner) || m.owners[token] != "" {
			return nil, errors.New("invalid or duplicate metering identity")
		}
		allowed := false
		for _, t := range c.tokens() {
			if t == token {
				allowed = true
			}
		}
		if !allowed {
			return nil, fmt.Errorf("meter owner %s requires an allowed token", owner)
		}
		m.owners[token] = owner
	}
	b, e := os.ReadFile(m.path)
	if e == nil {
		e = json.Unmarshal(b, &m.usage)
		if m.usage == nil {
			return nil, errors.New("empty meter database")
		}
	} else if os.IsNotExist(e) {
		e = nil
	}
	return m, e
}
func (m *exitMeter) add(owner string, port int, in bool, n int) {
	key := mgmt.UsageKey(owner, port, time.Now())
	m.mu.Lock()
	defer m.mu.Unlock()
	b := m.usage[key]
	if in {
		b.Up += int64(n)
	} else {
		b.Down += int64(n)
	}
	m.usage[key] = b
	m.dirty = true
}
func (m *exitMeter) snapshot() (map[string]mgmt.Bytes, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dirty {
		if e := mgmt.SaveJSON(m.path, m.usage); e != nil {
			return nil, e
		}
		m.dirty = false
	}
	return maps.Clone(m.usage), nil
}
func (m *exitMeter) report(ctx context.Context, c config, httpClient *http.Client) error {
	usage, e := m.snapshot()
	if e != nil {
		return e
	}
	endpoint := strings.TrimRight(c.v("center.url", ""), "/")
	if endpoint == "" {
		return nil
	}
	u, e := url.Parse(endpoint)
	if e != nil || u.User != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && net.ParseIP(u.Hostname()).IsLoopback())) {
		return errors.New("invalid center endpoint")
	}
	port, _ := strconv.Atoi(c.port("server.port"))
	data, e := json.Marshal(mgmt.ExitReport{Port: port, Usage: usage})
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint+"/agent/exit", bytes.NewReader(data))
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", "Bearer "+c.v("center.node-token", ""))
	req.Header.Set("X-Node-ID", c.v("center.node-id", ""))
	req.Header.Set("Content-Type", "application/json")
	res, e := httpClient.Do(req)
	if e != nil {
		return e
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode != 200 {
		return fmt.Errorf("exit report HTTP %d", res.StatusCode)
	}
	return nil
}
func (m *exitMeter) run(ctx context.Context, c config) {
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		if e := m.report(ctx, c, client); e != nil && ctx.Err() == nil {
			log.Printf("meter: %v", e)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
