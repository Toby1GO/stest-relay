package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http/httptest"
	mgmt "socks5-go/internal/control"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Stand-in for a landing node: password authentication and one shared UDP
// address. Both PC sessions stay active until both replies have been checked.
func TestTwoPCsViaSameFixedPort(t *testing.T) {
	loop := net.IPv4(127, 0, 0, 1)
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: loop})
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	accepted := make(chan string, 2)
	tcp := func() net.Listener {
		l, e := net.Listen("tcp4", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		return l
	}
	var wg sync.WaitGroup
	serveTest := func(l net.Listener, h func(net.Conn)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, e := l.Accept()
				if e != nil {
					return
				}
				wg.Add(1)
				go func() { defer wg.Done(); defer c.Close(); h(c) }()
			}
		}()
	}
	node := tcp()
	defer node.Close()
	serveTest(node, func(c net.Conn) {
		if b, _ := take(c, 3); !bytes.Equal(b, []byte{5, 1, 2}) {
			return
		}
		c.Write([]byte{5, 2})
		if b, _ := take(c, 5); !bytes.Equal(b, []byte{1, 1, 'a', 1, 'b'}) {
			return
		}
		c.Write([]byte{1, 0})
		req, host, p, e := socksMessage(c)
		if e != nil {
			return
		}
		if req[1] == 1 {
			c.Write(socksEndpoint(0, loop, 42))
			io.Copy(c, c)
			return
		}
		if req[1] != 3 {
			return
		}
		accepted <- net.JoinHostPort(host, strconv.Itoa(p))
		c.Write(socksEndpoint(0, net.IPv4zero, udp.LocalAddr().(*net.UDPAddr).Port))
		io.Copy(io.Discard, c)
	})
	fixture := httptest.NewTLSServer(nil)
	defer fixture.Close()
	b := tls.NewListener(tcp(), fixture.TLS)
	defer b.Close()
	stats := &monitor{tokens: make(map[string]totals), meter: &exitMeter{owners: map[string]string{"secret": "test-a"}, usage: map[string]mgmt.Bytes{}}}
	serveTest(b, func(c net.Conn) { serveTunnel(c, []string{"secret"}, stats) })
	pool := x509.NewCertPool()
	pool.AddCert(fixture.Certificate())
	a := tcp()
	address := a.Addr().String()
	portNum := a.Addr().(*net.TCPAddr).Port
	a.Close()
	port := strconv.Itoa(portNum)
	cl := client{cfg: config{"client.meter.enabled": "true", "client.forward-udp." + port: "true", "server.port": strconv.Itoa(b.Addr().(*net.TCPAddr).Port), "client.auth.token": "secret"}, tls: &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"}}
	live := &liveForwards{g: &group{active: map[*tracked]bool{}}, base: &cl}
	defer live.close()
	p := plan{Rules: []mapping{{Port: portNum, Target: node.Addr().String(), UDP: true}}, Ports: "20000-20127"}
	if e := live.apply(p, nil); e != nil {
		t.Fatal(e)
	}
	control := func() net.Conn {
		c, e := net.Dial("tcp", address)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{5, 1, 2})
		if b, e := take(c, 2); e != nil || !bytes.Equal(b, []byte{5, 2}) {
			t.Fatal("method", b, e)
		}
		c.Write([]byte{1, 1, 'a', 1, 'b'})
		if b, e := take(c, 2); e != nil || !bytes.Equal(b, []byte{1, 0}) {
			t.Fatal("auth", b, e)
		}
		return c
	}
	c := control()
	c.Write(socksEndpoint(1, loop, 42))
	if b, _, _, e := socksMessage(c); e != nil || b[1] != 0 {
		t.Fatal("CONNECT", e)
	}
	c.Write([]byte("tcp"))
	if b, e := take(c, 3); e != nil || string(b) != "tcp" {
		t.Fatal(b, e)
	}
	var ctl []net.Conn
	var pcs []*net.UDPConn
	var want [][]byte
	nodeSources := map[string]bool{}
	for i := 0; i < 2; i++ {
		c := control()
		ctl = append(ctl, c)
		c.Write(socksEndpoint(3, net.IPv4zero, 0))
		rep, host, p, e := socksMessage(c)
		if e != nil || rep[1] != 0 {
			t.Fatal("ASSOCIATE", rep, e)
		}
		nodeSources[<-accepted] = true
		pc, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(host), Port: p})
		if e != nil {
			t.Fatal(e)
		}
		defer pc.Close()
		pc.SetDeadline(time.Now().Add(5 * time.Second))
		pkt := append([]byte{0, 0, 0, 3, 1, 'x', 0, 53}, bytes.Repeat([]byte{byte('A' + i)}, 40000+i)...)
		if _, e = pc.Write(pkt); e != nil {
			t.Fatal(e)
		}
		pcs = append(pcs, pc)
		want = append(want, pkt)
	}
	if len(nodeSources) != 2 {
		t.Fatal("B reused a source endpoint")
	}
	// Repoint the original port at a raw echo service, add a second port,
	// then remove both while a TCP session and two UDP associations are live.
	raw := tcp()
	defer raw.Close()
	serveTest(raw, func(c net.Conn) { c.Write([]byte("new")); io.Copy(io.Discard, c) })
	spare := tcp()
	extra := spare.Addr().(*net.TCPAddr).Port
	extraAddr := spare.Addr().String()
	spare.Close()
	p.Rules = []mapping{{Port: portNum, Target: raw.Addr().String()}, {Port: extra, Target: raw.Addr().String()}}
	if e := live.apply(p, nil); e != nil {
		t.Fatal(e)
	}
	for _, addr := range []string{address, extraAddr} {
		nc, e := net.DialTimeout("tcp", addr, time.Second)
		if e != nil {
			t.Fatal(e)
		}
		nc.SetDeadline(time.Now().Add(3 * time.Second))
		msg, e := take(nc, 3)
		nc.Close()
		if e != nil || string(msg) != "new" {
			t.Fatal("new mapping", msg, e)
		}
	}
	p.Rules = nil
	if e := live.apply(p, nil); e != nil {
		t.Fatal(e)
	}
	if nc, e := net.DialTimeout("tcp", address, time.Second); e == nil {
		nc.Close()
		t.Fatal("removed port accepted a new connection")
	}
	c.Write([]byte("old"))
	if msg, e := take(c, 3); e != nil || string(msg) != "old" {
		t.Fatal("existing TCP session", msg, e)
	}
	c.Close()
	buf := make([]byte, 65535)
	udp.SetDeadline(time.Now().Add(5 * time.Second))
	for range pcs {
		n, src, e := udp.ReadFromUDP(buf)
		if e != nil || !nodeSources[src.String()] {
			t.Fatal("unexpected source", src, e)
		}
		if _, e = udp.WriteToUDP(buf[:n], src); e != nil {
			t.Fatal(e)
		}
	}
	for i, pc := range pcs {
		n, e := pc.Read(buf)
		if e != nil || !bytes.Equal(buf[:n], want[i]) {
			t.Fatal("incorrect datagram for PC", i, n, e)
		}
		ctl[i].Close()
	}
	raw.Close()
	b.Close()
	node.Close()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
		stats.meter.mu.Lock()
		defer stats.meter.mu.Unlock()
		u := stats.meter.usage[mgmt.UsageKey("test-a", portNum, time.Now())]
		if u.Up < 80000 || u.Down < 80000 {
			t.Fatalf("metered UDP round trips missing: %+v", u)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("control close leaked an association")
	}
}
