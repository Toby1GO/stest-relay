package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// group tracks both accepted and hijacked sockets so graceful shutdown can finish active relays.
type group struct {
	sync.WaitGroup
	mu     sync.Mutex
	closed bool
	active map[*tracked]bool
}
type tracked struct {
	net.Conn
	g    *group
	once sync.Once
}

func (t *tracked) Close() error {
	e := t.Conn.Close()
	t.once.Do(func() { t.g.mu.Lock(); delete(t.g.active, t); t.g.mu.Unlock() })
	return e
}

type listener struct {
	net.Listener
	g *group
}

func (l listener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	t := &tracked{Conn: c, g: l.g}
	l.g.mu.Lock()
	defer l.g.mu.Unlock()
	if l.g.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	l.g.active[t] = true
	return t, nil
}
func serve(l net.Listener, g *group, h func(net.Conn)) error {
	for {
		c, e := l.Accept()
		if e != nil {
			return e
		}
		g.Add(1)
		go func() { defer g.Done(); defer c.Close(); h(c) }()
	}
}
func run(ctx context.Context, role string, c config, mode string) (err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var flush func() error
	var listeners []net.Listener
	g := &group{active: map[*tracked]bool{}}
	var servers sync.WaitGroup
	errs := make(chan error, 1)
	defer func() {
		for _, l := range listeners {
			l.Close()
		}
		g.mu.Lock()
		g.closed = true
		var sockets []*tracked
		for t := range g.active {
			sockets = append(sockets, t)
		}
		g.mu.Unlock()
		for _, t := range sockets {
			t.Close()
		}
		servers.Wait()
		g.Wait()
		if flush != nil {
			if e := flush(); e != nil && err == nil {
				err = e
			}
		}
	}()
	start := func(name, addr string, h func(net.Listener) error) error {
		l, e := net.Listen("tcp", addr)
		if e != nil {
			return e
		}
		listeners = append(listeners, l)
		log.Printf("%s listening on %s", name, l.Addr())
		servers.Add(1)
		go func() {
			defer servers.Done()
			err := h(listener{l, g})
			select {
			case errs <- err:
			default:
			} // Only the first listener failure matters.
		}()
		return nil
	}
	httpServe := func(l net.Listener, h http.Handler) error {
		srv := &http.Server{Handler: h, ReadHeaderTimeout: setupTimeout, ReadTimeout: 60 * time.Second, MaxHeaderBytes: 8192}
		return srv.Serve(l)
	}
	if role == "server" {
		cert, e := tls.LoadX509KeyPair(c.v("server.cert.path", "server.crt"), c.v("server.key.path", "server.key"))
		if e != nil {
			return e
		}
		tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		m := &monitor{}
		path := c.v("server.stats.path", "./stats.json")
		if e = m.load(path); e != nil {
			return e
		}
		// Flush only after relay goroutines have stopped.
		m.meter, e = loadMeter(c)
		if e != nil {
			return e
		}
		meterCtx, stopMeter := context.WithCancel(ctx)
		meterDone := make(chan struct{})
		go func() { defer close(meterDone); m.meter.run(meterCtx, c) }()
		defer func() { stopMeter(); <-meterDone }()
		flush = func() error { _, me := m.meter.snapshot(); return errors.Join(me, m.save(path)) }
		tokens := c.tokens()
		if e = start("monitor", net.JoinHostPort(c.v("server.monitor.host", "127.0.0.1"), c.port("server.monitor.port")), func(l net.Listener) error { return httpServe(l, m) }); e != nil {
			return e
		}
		if e = start("tunnel", ":"+c.port("server.port"), func(l net.Listener) error {
			return serve(tls.NewListener(l, tc), g, func(conn net.Conn) { serveTunnel(conn, tokens, m) })
		}); e != nil {
			return e
		}
		select {
		case <-ctx.Done():
		case err = <-errs:
		}
		return err
	}
	cl := &client{cfg: c}
	cl.tls, err = clientTLS(c.v("server.host", "127.0.0.1"), c.v("server.cert.path", "server.crt"))
	if err != nil {
		return err
	}
	var fixedEnabled bool
	if mode == "" || mode == "forward" {
		initial, e := fromProperties(c)
		if e != nil {
			return e
		}
		managed := c.v("center.url", "") != ""
		if mode == "forward" && len(initial.Rules) == 0 && !managed {
			return errors.New("forward mode needs client.forward.<port>=host:port")
		}
		fixedEnabled = managed || len(initial.Rules) > 0
		f := &liveForwards{g: g, base: cl, onError: func(e error) {
			select {
			case errs <- e:
			default:
			}
		}}
		defer f.close()
		var a *nodeAgent
		if managed {
			a, e = newAgent(c, f, initial)
			if e != nil {
				return e
			}
			initial = a.current.Plan
		}
		if e = f.apply(initial, nil); e != nil {
			return e
		}
		if a != nil {
			done := make(chan struct{})
			go func() { defer close(done); a.run(ctx) }()
			defer func() { cancel(); <-done }()
		}
	}
	if mode != "forward" {
		cl.rules.watch(ctx, c)
	}
	for _, k := range []string{"socks5", "http", "https"} {
		if mode != "" && k != mode || mode == "" && !c.yes("client."+k+".enabled", k == "socks5") {
			continue
		}
		if err = start(k, ":"+c.port("client."+k+".port"), func(l net.Listener) error {
			if k == "socks5" {
				return serve(l, g, cl.socks)
			}
			return httpServe(l, cl.httpProxy(k == "https"))
		}); err != nil {
			return err
		}
	}
	if len(listeners) == 0 && !fixedEnabled {
		return errors.New("no enabled proxy listeners")
	}
	select {
	case <-ctx.Done():
		return nil
	case e := <-errs:
		return e
	}
}
func main() {
	if len(os.Args) < 2 || (os.Args[1] != "client" && os.Args[1] != "server") {
		fmt.Fprintln(os.Stderr, "usage: socks5-go client|server [-config proxy.properties] [socks5|http|https|forward]")
		os.Exit(2)
	}
	role := os.Args[1]
	flags := flag.NewFlagSet(role, flag.ExitOnError)
	path := flags.String("config", "proxy.properties", "Java-compatible configuration file")
	flags.Parse(os.Args[2:])
	mode := flags.Arg(0)
	if flags.NArg() > 1 || mode != "" && (role != "client" || mode != "socks5" && mode != "http" && mode != "https" && mode != "forward") {
		log.Fatal("invalid listener mode")
	}
	c, e := loadConfig(*path)
	if e != nil {
		log.Fatal(e)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e = run(ctx, role, c, mode); e != nil {
		log.Fatal(e)
	}
}
