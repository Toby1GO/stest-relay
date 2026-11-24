package main

import (
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
)

type fixedTarget struct{ port, addr string }

func forwardMappings(c config) ([]fixedTarget, error) {
	const prefix = "client.forward."
	var out []fixedTarget
	for k, v := range c {
		p, ok := strings.CutPrefix(k, prefix)
		if !ok {
			continue
		}
		n, e := strconv.Atoi(p)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p {
			return nil, fmt.Errorf("invalid listener port in %s", k)
		}
		target := strings.TrimSpace(v)
		if !validTarget(target) || strings.ContainsAny(target, "/@?#\\ \r\n\t") {
			return nil, fmt.Errorf("%s requires a destination host:port (without credentials)", k)
		}
		if c.yes("client.forward-udp."+p, false) {
			if _, _, e := udpPorts(c); e != nil {
				return nil, e
			}
			if ip := c.v("client.udp.advertise-ip", ""); ip != "" && (net.ParseIP(ip) == nil || net.ParseIP(ip).IsUnspecified()) {
				return nil, fmt.Errorf("client.udp.advertise-ip requires a reachable IP address")
			}
		}
		out = append(out, fixedTarget{p, target})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	return out, nil
}

func (c *client) forward(local net.Conn, m fixedTarget) {
	addr := m.addr
	kind, rawKind := socksForward, connect
	if c.cfg.yes("client.meter.enabled", false) {
		addr = m.port + " " + addr
		kind, rawKind = meteredSocks, meteredConnect
	}
	if c.cfg.yes("client.forward-udp."+m.port, false) {
		peer, e := c.openTunnel(kind, addr)
		if e != nil {
			log.Printf("fixed SOCKS5 port %s: %v", m.port, e)
			return
		}
		defer peer.Close()
		socksBridge(local, peer, c, nil)
		return
	}
	peer, e := c.openTunnel(rawKind, addr)
	if e != nil {
		log.Printf("fixed TCP port %s: %v", m.port, e)
		return
	}
	relay(local, local, &stream{Conn: peer})
}
