package center

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"socks5-go/internal/control"
	"strings"
	"sync"
	"time"
)

//go:embed web/login.html
var loginPage []byte

type credential struct {
	Username   string
	Salt, Hash []byte
	Initial    bool
}
type sessions struct {
	mu       sync.Mutex
	cred     credential
	path     string
	tokens   map[string]time.Time
	attempts map[string]attempt
}
type attempt struct {
	N     int
	Until time.Time
}

func makeCredential(user, pw string, initial bool) (credential, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return credential{}, e
	}
	hash, e := pbkdf2.Key(sha256.New, pw, salt, 600000, 32)
	return credential{user, salt, hash, initial}, e
}
func openSessions(path, legacy string) (*sessions, error) {
	s := &sessions{path: path, tokens: map[string]time.Time{}, attempts: map[string]attempt{}}
	raw, e := os.ReadFile(path)
	if e == nil {
		if e = json.Unmarshal(raw, &s.cred); e != nil {
			return nil, e
		}
		if s.cred.Username == "" || len(s.cred.Salt) != 16 || len(s.cred.Hash) != 32 {
			return nil, errors.New("invalid administrator credential file")
		}
		return s, nil
	}
	if !os.IsNotExist(e) {
		return nil, e
	}
	if legacy == "" {
		legacy = "admin"
	}
	s.cred, e = makeCredential("admin", legacy, true)
	if e == nil {
		e = control.SaveJSON(path, s.cred)
	}
	return s, e
}
func matches(c credential, pw string) bool {
	h, e := pbkdf2.Key(sha256.New, pw, c.Salt, 600000, 32)
	return e == nil && subtle.ConstantTimeCompare(h, c.Hash) == 1
}

const sessionName = "stest_session"

func sessionID(r *http.Request) string {
	c, e := r.Cookie(sessionName)
	if e != nil {
		return ""
	}
	return digest(c.Value)
}
func cookie(w http.ResponseWriter, r *http.Request, value string, seconds int) {
	http.SetCookie(w, &http.Cookie{Name: sessionName, Value: value, Path: "/", MaxAge: seconds, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
}
func (s *sessions) gate(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	id := sessionID(r)
	active := now.Before(s.tokens[id])
	path := r.URL.Path
	if path == "/login" && r.Method == "GET" {
		if active && !s.cred.Initial {
			http.Redirect(w, r, "/", 303)
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(loginPage)
		}
		return false
	}
	if strings.HasPrefix(path, "/auth/") {
		if path == "/auth/status" && r.Method == "GET" {
			jsonOut(w, map[string]bool{"change": active && s.cred.Initial})
			return false
		}
		if r.Method != "POST" || r.Header.Get("X-Center-Request") != "1" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "无效请求", 403)
			return false
		}
		switch path {
		case "/auth/logout":
			delete(s.tokens, id)
			cookie(w, r, "", -1)
			jsonOut(w, struct{}{})
		case "/auth/login", "/auth/change":
			var in struct{ Username, Password string }
			if path == "/auth/change" && (!active || !s.cred.Initial) {
				http.Error(w, "请重新登录", 401)
				return false
			}
			r.Body = http.MaxBytesReader(w, r.Body, 8192)
			if readBody(w, r, &in) != nil || len(in.Password) > 512 {
				http.Error(w, "输入无效", 400)
				return false
			}
			in.Username = strings.TrimSpace(in.Username)
			if path == "/auth/change" {
				if !control.NodeID.MatchString(in.Username) || len(in.Username) < 3 || strings.EqualFold(in.Username, "admin") || len([]rune(in.Password)) < 12 || strings.EqualFold(in.Password, in.Username) || matches(s.cred, in.Password) {
					http.Error(w, "请更换账号及密码：账号 3–64 位字母、数字、下划线或短横线；新密码至少 12 个字符。", 400)
					return false
				}
				next, e := makeCredential(in.Username, in.Password, false)
				if e != nil || control.SaveJSON(s.path, next) != nil {
					http.Error(w, "保存失败", 500)
					return false
				}
				s.cred = next
				clear(s.tokens)
				clear(s.attempts)
				cookie(w, r, "", -1)
				jsonOut(w, struct{}{})
				return false
			}
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			for k, v := range s.attempts {
				if !now.Before(v.Until) {
					delete(s.attempts, k)
				}
			}
			a := s.attempts[ip]
			if a.N >= 8 || len(s.attempts) >= 4096 {
				http.Error(w, "尝试过多，请稍后再试", 429)
				return false
			}
			if in.Username != s.cred.Username || !matches(s.cred, in.Password) {
				if a.N == 0 {
					a.Until = now.Add(5 * time.Minute)
				}
				a.N++
				s.attempts[ip] = a
				http.Error(w, "账号或密码错误", 401)
				return false
			}
			delete(s.attempts, ip)
			for k, v := range s.tokens {
				if !now.Before(v) {
					delete(s.tokens, k)
				}
			}
			key, e := nonce()
			if e != nil {
				http.Error(w, "无法登录", 500)
				return false
			}
			ttl := 8 * time.Hour
			if s.cred.Initial {
				ttl = 10 * time.Minute
			}
			delete(s.tokens, id)
			s.tokens[digest(key)] = now.Add(ttl)
			cookie(w, r, key, int(ttl.Seconds()))
			jsonOut(w, map[string]bool{"change": s.cred.Initial})
		default:
			http.NotFound(w, r)
		}
		return false
	}
	if !active || s.cred.Initial {
		if path == "/" && r.Method == "GET" {
			http.Redirect(w, r, "/login", 303)
		} else if active {
			http.Error(w, "须先更换管理员账号和密码", 403)
		} else {
			http.Error(w, "请登录", 401)
		}
		return false
	}
	return true
}
