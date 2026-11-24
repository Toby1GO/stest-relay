package center

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"socks5-go/internal/control"
	"strings"
	"time"
)

const installerURL = "https://raw.githubusercontent.com/Toby1GO/stest-relay/v1.1.0/install/node.sh"

type enrollment struct {
	Peer, Host, TicketHash, Tunnel, NodeKey, Certificate string
	Until                                                time.Time
}

func (c *center) pair(w http.ResponseWriter, r *http.Request) {
	var p struct{ Client, Server, ClientIP, ServerIP string }
	if readBody(w, r, &p) != nil || !control.NodeID.MatchString(p.Client) || !control.NodeID.MatchString(p.Server) || p.Client == p.Server || !ipv4(p.ClientIP) || !ipv4(p.ServerIP) || p.ClientIP == p.ServerIP {
		http.Error(w, "需要不同的节点标识和 IPv4 地址", 400)
		return
	}
	if c.nodes[p.Client].ID != "" || c.nodes[p.Server].ID != "" {
		http.Error(w, "节点标识已使用", 409)
		return
	}
	if c.bootstrapURL == "" {
		http.Error(w, "中心未配置安装入口（STEST_PUBLIC_URL）", 409)
		return
	}
	values := [5]string{}
	for i := range values {
		k, e := nonce()
		if e != nil {
			http.Error(w, "生成安装密钥失败", 500)
			return
		}
		values[i] = k
	}
	cmds := map[string]string{}
	until := time.Now().UTC().Add(2 * time.Hour)
	for i, role := range []string{"server", "client"} {
		id, peer, address, typ := p.Server, p.Client, p.ServerIP, "B"
		if i == 1 {
			id, peer, address, typ = p.Client, p.Server, p.ClientIP, "A"
		}
		key := values[i]
		n := managedNode{ID: id, Role: typ, Secret: digest(values[3+i]), Install: &enrollment{Peer: peer, Host: address, TicketHash: digest(key), NodeKey: values[3+i], Until: until, Tunnel: values[2]}, History: []entry{{time.Now().UTC(), "已登记，等待安装"}}}
		c.nodes[id] = n
		cmds[role] = fmt.Sprintf("curl -fsSL %s | bash -s -- %s '%s' '%s' '%s' '%s'", installerURL, role, c.bootstrapURL, c.pin, id, key)
	}
	if e := control.SaveJSON(c.path, c.nodes); e != nil {
		delete(c.nodes, p.Client)
		delete(c.nodes, p.Server)
		http.Error(w, "保存失败", 500)
		return
	}
	jsonOut(w, cmds)
}
func ipv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil && ip.String() == s && !ip.IsUnspecified() && !ip.IsMulticast()
}
func (c *center) bootstrap(w http.ResponseWriter, r *http.Request) {
	var in struct{ ID, Role, Certificate string }
	if readBody(w, r, &in) != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.nodes[in.ID]
	key, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || n.Install == nil || key == "" || c.bootstrapURL == "" {
		http.Error(w, "invalid enrollment", 403)
		return
	}
	en := *n.Install
	if r.URL.Path == "/install/certificate" {
		if n.Role != "B" || subtle.ConstantTimeCompare([]byte(n.Secret), []byte(digest(key))) != 1 {
			http.Error(w, "forbidden", 403)
			return
		}
		block, rest := pem.Decode([]byte(strings.TrimSpace(in.Certificate)))
		if !strings.HasPrefix(strings.TrimSpace(in.Certificate), "-----BEGIN CERTIFICATE-----") || block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
			http.Error(w, "invalid certificate", 400)
			return
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || cert.VerifyHostname(en.Host) != nil || time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			http.Error(w, "certificate address or validity mismatch", 400)
			return
		}
		if en.Certificate != "" && en.Certificate != string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})) {
			http.Error(w, "certificate already registered", 409)
			return
		}
		if en.Certificate == "" {
			en.Certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
			n.Install = &en
			if c.commit(n, "B 已提交隧道公钥证书") != nil {
				http.Error(w, "save failed", 500)
				return
			}
		}
		jsonOut(w, struct{}{})
		return
	}
	if en.TicketHash == "" || time.Now().After(en.Until) || subtle.ConstantTimeCompare([]byte(en.TicketHash), []byte(digest(key))) != 1 {
		http.Error(w, "安装凭据无效、已完成或已过期", 403)
		return
	}
	server := n
	role := "server"
	if n.Role == "A" {
		role = "client"
		server = c.nodes[en.Peer]
	}
	if role != in.Role {
		http.Error(w, "wrong role", 400)
		return
	}
	if server.Install == nil || (role == "client" && (server.Install.Peer != n.ID || server.Install.Certificate == "")) {
		http.Error(w, "请先安装配对的 server", 409)
		return
	}
	token := en.NodeKey
	cfg := fmt.Sprintf("client.auth.token=%s\nserver.auth.token.list=%s\nserver.port=8001\nserver.cert.path=server.crt\ncenter.url=%s\ncenter.node-id=%s\ncenter.node-token=%s\n", en.Tunnel, en.Tunnel, c.bootstrapURL, n.ID, token)
	if role == "server" {
		cfg += fmt.Sprintf("server.key.path=server.key\nserver.meter.owner.%s=%s\nserver.monitor.host=127.0.0.1\n", en.Peer, en.Tunnel)
	} else {
		cfg += fmt.Sprintf("server.host=%s\nclient.meter.enabled=true\nclient.udp.advertise-ip=%s\nclient.udp.ports=20000-20127\n", server.Install.Host, en.Host)
	}
	jsonOut(w, map[string]string{"config": cfg, "certificate": server.Install.Certificate, "center": c.centerPEM, "ip": en.Host, "nodeToken": token})
}
func (c *center) finishInstall(n managedNode) error {
	if n.Install == nil || n.Install.TicketHash == "" {
		return nil
	}
	en := *n.Install
	en.TicketHash = ""
	en.Tunnel = ""
	en.NodeKey = ""
	n.Install = &en
	return c.commit(n, "安装完成，安装凭据已失效")
}
func (c *center) setupInstall(origin, certpath string) error {
	if origin == "" {
		return nil
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil || !regexp.MustCompile(`^[a-zA-Z0-9.:-]+$`).MatchString(u.Host) {
		return fmt.Errorf("invalid STEST_PUBLIC_URL")
	}
	b, e := os.ReadFile(certpath)
	if e != nil {
		return e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return fmt.Errorf("invalid center certificate")
	}
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return e
	}
	if e = cert.VerifyHostname(u.Hostname()); e != nil {
		return e
	}
	hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	c.pin = "sha256//" + base64.StdEncoding.EncodeToString(hash[:])
	c.bootstrapURL = origin
	c.centerPEM = string(b)
	return nil
}
