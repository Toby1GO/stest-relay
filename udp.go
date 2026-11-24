package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Preserve the landing node's authentication exchange. Only methods whose
// post-authentication framing we understand are offered on UDP-enabled ports.
func negotiateSOCKS(pc, node net.Conn) bool {
	h, e := take(pc, 2)
	if e != nil || h[0] != 5 {
		return false
	}
	methods, e := take(pc, int(h[1]))
	if e != nil {
		return false
	}
	var allowed []byte
	for _, m := range methods {
		if m == 0 || m == 2 {
			allowed = append(allowed, m)
		}
	}
	if len(allowed) == 0 {
		pc.Write([]byte{5, 255})
		return false
	}
	if _, e = node.Write(append([]byte{5, byte(len(allowed))}, allowed...)); e != nil {
		return false
	}
	h, e = take(node, 2)
	if e != nil || h[0] != 5 {
		return false
	}
	if !bytes.Contains(allowed, h[1:]) {
		pc.Write([]byte{5, 255})
		return false
	}
	if _, e = pc.Write(h); e != nil {
		return false
	}
	if h[1] == 0 {
		return true
	}
	v, e := take(pc, 1)
	if e != nil || v[0] != 1 {
		return false
	}
	u, e := sized(pc)
	if e != nil {
		return false
	}
	p, e := sized(pc)
	if e != nil {
		return false
	}
	msg := append([]byte{1, byte(len(u))}, u...)
	msg = append(msg, byte(len(p)))
	msg = append(msg, p...)
	if _, e = node.Write(msg); e != nil {
		return false
	}
	h, e = take(node, 2)
	if e != nil || h[0] != 1 {
		return false
	}
	_, e = pc.Write(h)
	return e == nil && h[1] == 0
}

func socksMessage(r io.Reader) (msg []byte, host string, port int, err error) {
	h, e := take(r, 4)
	if e != nil {
		return nil, "", 0, e
	}
	if h[0] != 5 || h[2] != 0 {
		return nil, "", 0, errors.New("invalid SOCKS header")
	}
	n := 4
	switch h[3] {
	case 1:
	case 4:
		n = 16
	case 3:
		b, e := take(r, 1)
		if e != nil {
			return nil, "", 0, e
		}
		n = int(b[0])
		h = append(h, b...)
		if n == 0 {
			return nil, "", 0, errors.New("empty SOCKS hostname")
		}
	default:
		return nil, "", 0, errors.New("invalid SOCKS address type")
	}
	b, e := take(r, n+2)
	if e != nil {
		return nil, "", 0, e
	}
	host = string(b[:n])
	if h[3] != 3 {
		host = net.IP(b[:n]).String()
	}
	return append(h, b...), host, int(binary.BigEndian.Uint16(b[n:])), nil
}

func socksEndpoint(code byte, ip net.IP, port int) []byte {
	h := []byte{5, code, 0, 1}
	if v := ip.To4(); v != nil {
		ip = v
	} else {
		h[3] = 4
		ip = ip.To16()
	}
	return binary.BigEndian.AppendUint16(append(h, ip...), uint16(port))
}

func udpPorts(cfg config) (int, int, error) {
	s := cfg.v("client.udp.ports", "20000-20127")
	a, b, _ := strings.Cut(s, "-")
	lo, e := strconv.Atoi(a)
	hi, f := strconv.Atoi(b)
	if e != nil || f != nil || lo < 1 || hi < lo || hi > 65535 {
		return 0, 0, errors.New("client.udp.ports requires first-last (1..65535)")
	}
	return lo, hi, nil
}

type trafficConn struct {
	net.Conn
	count func(bool, int)
}

func (c trafficConn) Read(b []byte) (int, error) {
	n, e := c.Conn.Read(b)
	if n > 0 {
		c.count(true, n)
	}
	return n, e
}
func (c trafficConn) Write(b []byte) (int, error) {
	n, e := c.Conn.Write(b)
	if n > 0 {
		c.count(false, n)
	}
	return n, e
}

// On A, pc is the real client and node is the extension tunnel. On B, pc
// is that tunnel and node is the real landing server.
func socksBridge(pc, node net.Conn, front *client, count func(bool, int)) {
	deadline := time.Now().Add(setupTimeout)
	pc.SetDeadline(deadline)
	node.SetDeadline(deadline)
	if !negotiateSOCKS(pc, node) {
		return
	}
	req, _, sourcePort, e := socksMessage(pc)
	if e != nil {
		return
	}
	fail := func(code byte) { pc.Write(socksEndpoint(code, net.IPv4zero, 0)) }
	if req[1] == 1 {
		if _, e = node.Write(req); e != nil {
			return
		}
		pc.SetDeadline(time.Time{})
		node.SetDeadline(time.Time{})
		if count != nil {
			pc = trafficConn{pc, count}
		}
		relay(pc, pc, node)
		return
	}
	if req[1] != 3 {
		fail(7)
		return
	}
	var bind *net.TCPAddr
	lo, hi := 0, 0
	if front != nil {
		bind = pc.LocalAddr().(*net.TCPAddr)
		lo, hi, e = udpPorts(front.cfg)
		if e != nil {
			fail(1)
			return
		}
	} else {
		bind = node.LocalAddr().(*net.TCPAddr)
	}
	var sock *net.UDPConn
	for p := lo; p <= hi; p++ {
		sock, e = net.ListenUDP("udp", &net.UDPAddr{IP: bind.IP, Zone: bind.Zone, Port: p})
		if e == nil {
			break
		}
	}
	if e != nil {
		fail(1)
		return
	}
	defer sock.Close()
	local := sock.LocalAddr().(*net.UDPAddr)
	// B supplies its actual source port so a node can distinguish concurrent
	// associations even if it returns a shared relay port.
	if _, e = node.Write(socksEndpoint(3, local.IP, local.Port)); e != nil {
		fail(1)
		return
	}
	reply, host, port, e := socksMessage(node)
	if e != nil {
		fail(1)
		return
	}
	if reply[1] != 0 {
		pc.Write(reply)
		return
	}
	var dest *net.UDPAddr
	var expected net.IP
	ctrl, tun := node, pc
	ip := local.IP
	if front != nil {
		ctrl, tun = pc, node
		expected = pc.RemoteAddr().(*net.TCPAddr).IP
		if s := front.cfg.v("client.udp.advertise-ip", ""); s != "" {
			ip = net.ParseIP(s)
			if ip == nil {
				fail(1)
				return
			}
		}
	} else {
		if v := net.ParseIP(host); v != nil && v.IsUnspecified() {
			host = node.RemoteAddr().(*net.TCPAddr).IP.String()
		}
		if port == 0 {
			fail(1)
			return
		}
		dest, e = net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
		if e != nil {
			fail(1)
			return
		}
	}
	if _, e = pc.Write(socksEndpoint(0, ip, local.Port)); e != nil {
		return
	}
	pc.SetDeadline(time.Time{})
	node.SetDeadline(time.Time{})
	pumpAssociation(ctrl, tun, sock, dest, expected, sourcePort, count)
}

func validPacket(p []byte) bool {
	if len(p) < 4 || p[0] != 0 || p[1] != 0 || p[2] != 0 {
		return false
	}
	switch p[3] {
	case 1:
		return len(p) >= 10
	case 4:
		return len(p) >= 22
	case 3:
		return len(p) >= 5 && p[4] != 0 && len(p) >= 7+int(p[4])
	}
	return false
}

// Each TCP association owns its own UDP socket on both A and B. The first
// valid datagram pins the client's source port if it wasn't specified.
func pumpAssociation(ctrl, tun net.Conn, sock *net.UDPConn, dest *net.UDPAddr, expected net.IP, sourcePort int, count func(bool, int)) {
	var mu sync.Mutex
	var workers sync.WaitGroup
	done := make(chan struct{}, 3)
	start := func(f func()) { workers.Add(1); go func() { defer workers.Done(); f(); done <- struct{}{} }() }
	start(func() { var b [1]byte; ctrl.Read(b[:]) })
	start(func() {
		buf := make([]byte, 65535)
		for {
			n, src, e := sock.ReadFromUDP(buf)
			if e != nil {
				return
			}
			if !validPacket(buf[:n]) {
				continue
			}
			mu.Lock()
			if dest == nil && expected.Equal(src.IP) && (sourcePort == 0 || sourcePort == src.Port) {
				dest = src
			}
			ok := dest != nil && dest.Port == src.Port && dest.IP.Equal(src.IP) && dest.Zone == src.Zone
			mu.Unlock()
			if !ok {
				continue
			}
			if send(tun, data, buf[:n]) != nil {
				return
			}
			if count != nil {
				count(false, n)
			}
		}
	})
	start(func() {
		buf := make([]byte, 65535)
		for {
			kind, n, e := header(tun)
			if e != nil || kind != data || n > len(buf) {
				return
			}
			if _, e = io.ReadFull(tun, buf[:n]); e != nil {
				return
			}
			if !validPacket(buf[:n]) {
				continue
			}
			mu.Lock()
			target := dest
			mu.Unlock()
			if target != nil {
				if _, e = sock.WriteToUDP(buf[:n], target); e != nil {
					return
				}
				if count != nil {
					count(true, n)
				}
			}
		}
	})
	<-done
	ctrl.Close()
	tun.Close()
	sock.Close()
	workers.Wait()
}
