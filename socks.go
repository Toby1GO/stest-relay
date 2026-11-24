package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"time"
)

func take(r io.Reader, n int) ([]byte, error) {
	p := make([]byte, n)
	_, e := io.ReadFull(r, p)
	return p, e
}
func sized(r io.Reader) ([]byte, error) {
	b, e := take(r, 1)
	if e != nil {
		return nil, e
	}
	return take(r, int(b[0]))
}
func (c *client) socks(local net.Conn) {
	local.SetDeadline(time.Now().Add(setupTimeout))
	h, e := take(local, 2)
	if e != nil || h[0] != 5 {
		return
	}
	methods, e := take(local, int(h[1]))
	if e != nil {
		return
	}
	var method byte
	if c.cfg.yes("client.socks5.password.auth.enabled", false) {
		method = 2
	}
	if !bytes.Contains(methods, []byte{method}) {
		local.Write([]byte{5, 255})
		return
	}
	if _, e = local.Write([]byte{5, method}); e != nil {
		return
	}
	if method == 2 {
		v, e := take(local, 1)
		if e != nil || v[0] != 1 {
			return
		}
		u, e := sized(local)
		if e != nil {
			return
		}
		p, e := sized(local)
		if e != nil {
			return
		}
		if subtle.ConstantTimeCompare(u, []byte(c.cfg.v("client.socks5.username", "")))&subtle.ConstantTimeCompare(p, []byte(c.cfg.v("client.socks5.password", ""))) != 1 {
			local.Write([]byte{1, 1})
			return
		}
		local.Write([]byte{1, 0})
	}
	h, e = take(local, 4)
	if e != nil || h[0] != 5 || h[2] != 0 {
		return
	}
	bad := func(code byte) { local.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
	if h[1] != 1 {
		bad(7)
		return
	}
	var raw []byte
	var host string
	switch h[3] {
	case 1, 4:
		n := 4
		if h[3] == 4 {
			n = 16
		}
		raw, e = take(local, n)
		host = net.IP(raw).String()
	case 3:
		raw, e = sized(local)
		host = string(raw)
		raw = append([]byte{byte(len(raw))}, raw...)
	default:
		bad(8)
		return
	}
	if e != nil {
		return
	}
	p, e := take(local, 2)
	if e != nil {
		return
	}
	r, e := c.dial(net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(p)))))
	if e != nil {
		if e == errBlocked {
			bad(2)
		} else {
			bad(1)
		}
		return
	}
	defer r.Close()
	if _, e = local.Write(append(append([]byte{5, 0, 0, h[3]}, raw...), p...)); e != nil {
		return
	}
	local.SetDeadline(time.Time{})
	relay(local, local, r)
}
