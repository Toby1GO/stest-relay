package main

import (
	"fmt"
	"maps"
	"net"
	mgmt "socks5-go/internal/control"

	"strconv"
	"strings"
	"sync"
	"time"
)

// Only these fields may be changed remotely. Credentials and B stay local.
type mapping = mgmt.Mapping
type plan = mgmt.Plan
type revision = mgmt.Revision
type heartbeat = mgmt.Heartbeat

func fromProperties(c config) (plan, error) {
	ms, e := forwardMappings(c)
	p := plan{Rules: []mapping{}, IP: c.v("client.udp.advertise-ip", ""), Ports: c.v("client.udp.ports", "20000-20127")}
	for _, m := range ms {
		n, _ := strconv.Atoi(m.port)
		p.Rules = append(p.Rules, mapping{Port: n, Target: m.addr, UDP: c.yes("client.forward-udp."+m.port, false)})
	}
	return p, e
}
func planConfig(p plan, base config) (config, error) {
	if e := p.Validate(); e != nil {
		return nil, e
	}
	c := maps.Clone(base)
	if c == nil {
		c = config{}
	}
	for k := range c {
		if strings.HasPrefix(k, "client.forward.") || strings.HasPrefix(k, "client.forward-udp.") {
			delete(c, k)
		}
	}
	c["client.udp.ports"] = p.Ports
	c["client.udp.advertise-ip"] = p.IP
	for _, m := range p.Rules {
		k := strconv.Itoa(m.Port)
		c["client.forward."+k] = m.Target
		c["client.forward-udp."+k] = strconv.FormatBool(m.UDP)
	}
	return c, nil
}

type binding struct {
	net.Listener
	handle   func(net.Conn)
	expiry   *time.Timer
	deadline *time.Time
}
type liveForwards struct {
	mu        sync.Mutex
	active    map[int]*binding
	sessions  map[int]map[net.Conn]bool
	acceptors sync.WaitGroup
	g         *group
	base      *client
	onError   func(error)
}

// apply is serialized with Close by the caller. Reserve every new port and
// persist the candidate before publishing anything. Sessions own their handler.
func (f *liveForwards) apply(p plan, persist func() error) error {
	cfg, e := planConfig(p, f.base.cfg)
	if e != nil {
		return e
	}
	next := &client{cfg: cfg, tls: f.base.tls}
	f.mu.Lock()
	defer f.mu.Unlock()
	added := map[int]*binding{}
	defer func() {
		for _, b := range added {
			b.Close()
		}
	}()
	wanted := map[int]bool{}
	for _, r := range p.Rules {
		if r.Restricted(time.Now()) {
			continue
		}
		wanted[r.Port] = true
		if f.active[r.Port] == nil {
			l, e := net.Listen("tcp", ":"+strconv.Itoa(r.Port))
			if e != nil {
				return fmt.Errorf("端口 %d: %w", r.Port, e)
			}
			added[r.Port] = &binding{Listener: listener{l, f.g}}
		}
	}
	if persist != nil {
		if e := persist(); e != nil {
			return e
		}
	}
	if f.active == nil {
		f.active = map[int]*binding{}
	}
	for _, r := range p.Rules {
		if !wanted[r.Port] {
			f.stopPort(r.Port, true)
			continue
		}
		b := f.active[r.Port]
		if b == nil {
			b = added[r.Port]
			delete(added, r.Port)
			f.active[r.Port] = b
			f.acceptors.Add(1)
			go f.accept(r.Port, b)
		}
		m := fixedTarget{strconv.Itoa(r.Port), strings.TrimSpace(r.Target)}
		b.handle = func(c net.Conn) { next.forward(c, m) }
		if b.expiry != nil {
			b.expiry.Stop()
		}
		b.deadline = r.ExpiresAt
		if deadline := r.ExpiresAt; deadline != nil {
			b.expiry = time.AfterFunc(time.Until(*deadline), func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				if f.active[r.Port] == b && b.deadline == deadline {
					f.stopPort(r.Port, true)
				}
			})
		}
	}
	for port := range f.active {
		if !wanted[port] {
			f.stopPort(port, false)
		}
	}
	return nil
}

// Called with mu held. Normal mapping removal drains existing sessions.
func (f *liveForwards) stopPort(port int, disconnect bool) {
	if b := f.active[port]; b != nil {
		delete(f.active, port)
		if b.expiry != nil {
			b.expiry.Stop()
		}
		b.Close()
	}
	if disconnect {
		for c := range f.sessions[port] {
			c.Close()
		}
	}
}
func (f *liveForwards) accept(port int, b *binding) {
	defer f.acceptors.Done()
	for {
		c, e := b.Accept()
		f.mu.Lock()
		active := f.active[port] == b
		h := b.handle
		expired := b.deadline != nil && !time.Now().Before(*b.deadline)
		if active && !expired && e == nil {
			if f.sessions == nil {
				f.sessions = map[int]map[net.Conn]bool{}
			}
			if f.sessions[port] == nil {
				f.sessions[port] = map[net.Conn]bool{}
			}
			f.sessions[port][c] = true
		}
		f.mu.Unlock()
		if e != nil {
			if active && f.onError != nil {
				f.onError(e)
			}
			return
		}
		if !active {
			c.Close()
			return
		}
		if expired {
			c.Close()
			continue
		}
		f.g.Add(1)
		go func() {
			defer f.g.Done()
			defer func() {
				c.Close()
				f.mu.Lock()
				delete(f.sessions[port], c)
				if len(f.sessions[port]) == 0 {
					delete(f.sessions, port)
				}
				f.mu.Unlock()
			}()
			h(c)
		}()
	}
}
func (f *liveForwards) close() {
	f.mu.Lock()
	for p := range f.active {
		f.stopPort(p, false)
	}
	f.mu.Unlock()
	f.acceptors.Wait()
}
func (f *liveForwards) revoke() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for port := range f.active {
		f.stopPort(port, true)
	}
	for port := range f.sessions {
		f.stopPort(port, true)
	}
}
