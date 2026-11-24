package main

import (
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var errBlocked = errors.New("destination blocked")

func validTarget(addr string) bool {
	h, p, e := net.SplitHostPort(addr)
	n, e2 := strconv.Atoi(p)
	return e == nil && h != "" && e2 == nil && n > 0 && n <= 65535
}

type client struct {
	cfg   config
	tls   *tls.Config
	rules rules
}

func (c *client) dial(addr string) (net.Conn, error) {
	if !validTarget(addr) {
		return nil, errors.New("invalid destination")
	}
	h, _, _ := net.SplitHostPort(addr)
	switch c.rules.route(h) {
	case "block":
		return nil, errBlocked
	case "direct":
		return net.DialTimeout("tcp", addr, setupTimeout)
	}
	return c.dialTunnel(addr)
}

// dialTunnel always reaches the target from B; fixed forwards must never fall back to A.
func (c *client) dialTunnel(addr string) (net.Conn, error) {
	raw, e := c.openTunnel(connect, addr)
	if e != nil {
		return nil, e
	}
	return &stream{Conn: raw}, nil
}
func (c *client) openTunnel(kind byte, addr string) (net.Conn, error) {
	raw, e := tls.DialWithDialer(&net.Dialer{Timeout: setupTimeout}, "tcp", net.JoinHostPort(c.cfg.v("server.host", "127.0.0.1"), c.cfg.port("server.port")), c.tls)
	if e != nil {
		return nil, e
	}
	raw.SetDeadline(time.Now().Add(setupTimeout))
	if e = send(raw, auth, []byte(c.cfg.v("client.auth.token", ""))); e == nil {
		e = send(raw, kind, []byte(addr))
	}
	if e == nil {
		var t byte
		var reason string
		t, reason, e = control(raw)
		if e == nil && t != success {
			e = fmt.Errorf("tunnel refused: %s", reason)
		}
	}
	if e != nil {
		raw.Close()
		return nil, e
	}
	raw.SetDeadline(time.Time{})
	return raw, nil
}
func serveTunnel(raw net.Conn, tokens []string, m *monitor) {
	raw.SetDeadline(time.Now().Add(setupTimeout))
	t, token, e := control(raw)
	if e != nil || t != auth {
		return
	}
	ok := 0
	for _, s := range tokens {
		ok |= subtle.ConstantTimeCompare([]byte(s), []byte(token))
	}
	if ok != 1 {
		send(raw, failure, []byte("token验证失败"))
		return
	}
	t, addr, e := control(raw)
	count := func(in bool, n int) { m.add(token, in, n) }
	if t == meteredConnect || t == meteredSocks {
		var owner string
		if m.meter != nil {
			owner = m.meter.owners[token]
		}
		portText, target, found := strings.Cut(addr, " ")
		port, pe := strconv.Atoi(portText)
		if owner == "" || !found || pe != nil || port < 1 || port > 65535 {
			send(raw, failure, []byte("meter identity rejected"))
			return
		}
		count = func(in bool, n int) { m.add(token, in, n); m.meter.add(owner, port, in, n) }
		addr = target
		if t == meteredConnect {
			t = connect
		} else {
			t = socksForward
		}
	}
	if e != nil || (t != connect && t != socksForward) || !validTarget(addr) {
		send(raw, failure, []byte("invalid destination"))
		return
	}
	peer, e := net.DialTimeout("tcp", addr, setupTimeout)
	if e != nil {
		send(raw, failure, []byte("connection failed"))
		return
	}
	defer peer.Close()
	if send(raw, success, nil) != nil {
		return
	}
	raw.SetDeadline(time.Time{})
	if t == socksForward {
		socksBridge(raw, peer, nil, count)
		return
	}
	s := &stream{Conn: raw, count: count}
	relay(peer, peer, s)
}
