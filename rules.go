package main

import (
	"context"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type ruleSet struct {
	block map[string]bool
	allow []string
}
type rules struct{ current atomic.Pointer[ruleSet] }

type ruleFile struct {
	path  string
	info  os.FileInfo
	lines []string
}

func (f *ruleFile) refresh() bool {
	info, e := os.Stat(f.path)
	if os.IsNotExist(e) {
		changed := f.info != nil
		f.info, f.lines = nil, nil
		return changed
	}
	if e != nil {
		log.Print(e)
		return false
	}
	if f.info != nil && info.Size() == f.info.Size() && info.ModTime().Equal(f.info.ModTime()) && os.SameFile(info, f.info) {
		return false
	}
	p, e := os.ReadFile(f.path)
	if e != nil {
		log.Print(e)
		return false
	}
	var out []string
	for _, line := range strings.Split(string(p), "\n") {
		s := strings.ToLower(strings.TrimSpace(line))
		if s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, s)
		}
	}
	f.info, f.lines = info, out
	return true
}
func (r *rules) watch(ctx context.Context, c config) {
	block := ruleFile{path: c.v("client.block.path", "./block.conf")}
	allow := ruleFile{path: c.v("client.direct.allow.path", "./direct-allow.conf")}
	reload := func() {
		b, a := block.refresh(), allow.refresh()
		if !b && !a && r.current.Load() != nil {
			return
		}
		s := &ruleSet{map[string]bool{}, allow.lines}
		for _, b := range block.lines {
			if i := strings.LastIndexByte(b, '/'); strings.HasPrefix(b, "address=/") && i > 9 {
				b = strings.TrimSpace(b[9:i])
			}
			s.block[b] = true
		}
		r.current.Store(s)
	}
	reload()
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				reload()
			}
		}
	}()
}
func (r *rules) route(host string) string {
	s := r.current.Load()
	if s == nil {
		return "tunnel"
	}
	h := strings.ToLower(strings.TrimSpace(host))
	for v := h; v != ""; {
		if s.block[v] {
			return "block"
		}
		_, tail, found := strings.Cut(v, ".")
		if !found {
			break
		}
		v = tail
	}
	for _, v := range s.allow {
		l := len(v)
		switch {
		case l > 2 && v[0] == '*' && v[l-1] == '*':
			if strings.Contains(h, v[1:l-1]) {
				return "direct"
			}
		case l > 1 && v[0] == '*':
			if strings.HasSuffix(h, v[1:]) {
				return "direct"
			}
		case l > 1 && v[l-1] == '*':
			if strings.HasPrefix(h, v[:l-1]) {
				return "direct"
			}
		default:
			if h == v {
				return "direct"
			}
		}
	}
	return "tunnel"
}
