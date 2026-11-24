package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf16"
)

type config map[string]string

func (c config) v(k, d string) string {
	if s, ok := c[k]; ok {
		return strings.TrimSpace(s)
	}
	return d
}
func (c config) yes(k string, d bool) bool {
	return strings.EqualFold(c.v(k, strconv.FormatBool(d)), "true")
}

var ports = map[string]string{"server.port": "58001", "client.socks5.port": "58080", "client.http.port": "58081", "client.https.port": "58082", "server.monitor.port": "18080"}

func (c config) port(k string) string { return c.v(k, ports[k]) }
func (c config) tokens() []string {
	var out []string
	for _, s := range strings.Split(c.v("server.auth.token.list", ""), ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// java.util.Properties.load(InputStream): Latin-1, logical lines and Unicode escapes.
func unescape(s string) (string, error) {
	var units []uint16
	for i := 0; i < len(s); i++ {
		b := s[i]
		if b == '\\' && i+1 < len(s) {
			i++
			b = s[i]
			switch b {
			case 'u':
				if i+4 >= len(s) {
					return "", errors.New("short unicode escape")
				}
				n, e := strconv.ParseUint(s[i+1:i+5], 16, 16)
				if e != nil {
					return "", e
				}
				units = append(units, uint16(n))
				i += 4
				continue
			case 't':
				b = '\t'
			case 'r':
				b = '\r'
			case 'n':
				b = '\n'
			case 'f':
				b = '\f'
			}
		}
		units = append(units, uint16(b))
	}
	return string(utf16.Decode(units)), nil
}
func loadConfig(path string) (config, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	c := config{}
	for sc.Scan() {
		s := strings.TrimLeft(sc.Text(), " \t\f")
		if s == "" || s[0] == '#' || s[0] == '!' {
			continue
		}
		for (len(s)-len(strings.TrimRight(s, "\\")))%2 == 1 {
			s = s[:len(s)-1]
			if !sc.Scan() {
				break
			}
			s += strings.TrimLeft(sc.Text(), " \t\f")
		}
		i := 0
		for i < len(s) {
			if strings.ContainsRune("=:\t \f", rune(s[i])) {
				break
			}
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			i++
		}
		key, e := unescape(s[:i])
		if e != nil {
			return nil, e
		}
		v := strings.TrimLeft(s[i:], " \t\f")
		if len(v) > 0 && (v[0] == ':' || v[0] == '=') {
			v = v[1:]
		}
		v, e = unescape(strings.TrimLeft(v, " \t\f"))
		if e != nil {
			return nil, e
		}
		c[key] = v
	}
	if e := sc.Err(); e != nil {
		return nil, e
	}
	for k := range ports {
		n, e := strconv.Atoi(c.port(k))
		if e != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %s", k)
		}
	}
	if c.v("client.auth.token", "") == "" || len(c.tokens()) == 0 {
		return nil, errors.New("client.auth.token and server.auth.token.list required")
	}
	if c.yes("client.socks5.password.auth.enabled", false) && (c.v("client.socks5.username", "") == "" || c.v("client.socks5.password", "") == "") {
		return nil, errors.New("missing SOCKS credentials")
	}
	return c, nil
}
