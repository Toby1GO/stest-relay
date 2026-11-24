package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

func (c *client) httpProxy(onlyConnect bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tunnel := r.Method == "CONNECT"
		if onlyConnect && !tunnel {
			http.Error(w, "HTTPS 代理仅支持 CONNECT 方法", 405)
			return
		}
		addr := r.Host
		if tunnel {
			addr = r.RequestURI
		} else if r.URL.Host != "" {
			addr = r.URL.Host
		}
		if !tunnel {
			if _, _, e := net.SplitHostPort(addr); e != nil {
				addr = net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]"), "80")
			}
		}
		if !validTarget(addr) {
			http.Error(w, "invalid destination", 400)
			return
		}
		if !tunnel {
			body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<20))
			r.Body.Close()
			if e != nil {
				if _, ok := e.(*http.MaxBytesError); ok {
					http.Error(w, "request too large", 413)
				} else {
					http.Error(w, "invalid request body", 400)
				}
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.TransferEncoding = nil
			r.Trailer = nil
			r.RequestURI = ""
			r.URL.Scheme = ""
			r.URL.Host = ""
			r.Header.Del("Proxy-Connection")
			r.Header.Del("Proxy-Authorization")
			r.Close = true
		}
		peer, e := c.dial(addr)
		if e != nil {
			if e == errBlocked {
				http.Error(w, e.Error(), 403)
			} else {
				http.Error(w, "connection failed", 502)
			}
			return
		}
		defer peer.Close()
		if !tunnel {
			if e = r.Write(peer); e != nil {
				http.Error(w, "forward failed", 502)
				return
			}
		}
		local, rw, e := w.(http.Hijacker).Hijack()
		if e != nil {
			return
		}
		defer local.Close()
		local.SetDeadline(time.Time{})
		if tunnel {
			if _, e = local.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); e == nil {
				relay(local, rw.Reader, peer)
			}
		} else {
			io.Copy(local, peer)
		}
	}
}
