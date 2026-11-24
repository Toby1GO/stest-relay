package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const (
	auth byte = 1 + iota
	connect
	data
	disconnect
	success
	failure
	socksForward // Go extension: SOCKS negotiation, then TCP bytes or framed UDP
	meteredConnect
	meteredSocks
)
const maxFrame = (128 << 20) - 4 // Netty maximum includes the outer length field.
const chunk = 32 << 10
const setupTimeout = 15 * time.Second

func header(r io.Reader) (byte, int, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, 0, err
	}
	n := binary.BigEndian.Uint32(h[:4])
	if n < 1 || n > maxFrame {
		return 0, 0, errors.New("invalid tunnel frame length")
	}
	return h[4], int(n - 1), nil
}
func control(r io.Reader) (byte, string, error) {
	t, n, e := header(r)
	if e != nil {
		return 0, "", e
	}
	if n > 65535 {
		return 0, "", errors.New("control frame too large")
	}
	p := make([]byte, n)
	_, e = io.ReadFull(r, p)
	return t, string(p), e
}
func send(w io.Writer, t byte, p []byte) error {
	var h [5]byte
	binary.BigEndian.PutUint32(h[:4], uint32(len(p)+1))
	h[4] = t
	if _, e := w.Write(h[:]); e != nil {
		return e
	}
	if len(p) > 0 {
		_, e := w.Write(p)
		return e
	}
	return nil
}

// stream exposes framed TYPE_DATA as a byte stream. Read large peer frames incrementally.
type stream struct {
	net.Conn
	remaining int
	packet    []byte
	mu        sync.Mutex
	count     func(bool, int)
}

func (s *stream) Read(p []byte) (int, error) {
	for s.remaining == 0 {
		t, n, e := header(s.Conn)
		if e != nil {
			return 0, e
		}
		if t == disconnect {
			return 0, io.EOF
		}
		if t != data {
			return 0, errors.New("unexpected tunnel frame")
		}
		s.remaining = n
	}
	n, e := s.Conn.Read(p[:min(len(p), s.remaining)])
	s.remaining -= n
	if s.count != nil && n > 0 {
		s.count(true, n)
	}
	return n, e
}
func (s *stream) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.packet == nil {
		s.packet = make([]byte, chunk+5)
		s.packet[4] = data
	}
	total := 0
	for len(p) > 0 {
		n := min(len(p), chunk)
		binary.BigEndian.PutUint32(s.packet[:4], uint32(n+1))
		copy(s.packet[5:], p[:n])
		if _, e := s.Conn.Write(s.packet[:5+n]); e != nil {
			return total, e
		}
		if s.count != nil {
			s.count(false, n)
		}
		total += n
		p = p[n:]
	}
	return total, nil
}
func (s *stream) Close() error {
	s.Conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	s.mu.Lock()
	_ = send(s.Conn, disconnect, nil)
	s.mu.Unlock()
	return s.Conn.Close()
}

// The upstream protocol signals full close, not a TCP half-close.
func relay(local net.Conn, reader io.Reader, remote net.Conn) {
	done := make(chan struct{})
	go func() { io.Copy(remote, reader); remote.Close(); local.Close(); close(done) }()
	io.Copy(local, remote)
	local.Close()
	remote.Close()
	<-done
}
