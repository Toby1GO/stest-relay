package control

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

func (p Plan) Validate() error {
	if len(p.Rules) > 2048 {
		return fmt.Errorf("最多支持 2048 条映射")
	}
	if ip := net.ParseIP(p.IP); p.IP != "" && (ip == nil || ip.IsUnspecified()) {
		return fmt.Errorf("无效的 UDP 通告 IP")
	}
	a, b, _ := strings.Cut(p.Ports, "-")
	lo, e1 := strconv.Atoi(a)
	hi, e2 := strconv.Atoi(b)
	if e1 != nil || e2 != nil || lo < 1 || hi < lo || hi > 65535 {
		return fmt.Errorf("UDP 端口范围无效")
	}
	seen := map[int]bool{}
	for _, r := range p.Rules {
		if r.Port < 1 || r.Port > 65535 || seen[r.Port] {
			return fmt.Errorf("入口端口无效或重复：%d", r.Port)
		}
		seen[r.Port] = true
		if utf8.RuneCountInString(r.Customer) > 100 || utf8.RuneCountInString(r.Remark) > 500 {
			return fmt.Errorf("端口 %d 的客户名称最多 100 字，备注最多 500 字", r.Port)
		}
		dest := strings.TrimSpace(r.Target)
		host, port, e := net.SplitHostPort(dest)
		n, pe := strconv.Atoi(port)
		if e != nil || host == "" || pe != nil || n < 1 || n > 65535 || strings.ContainsAny(dest, "/@?#\\ \r\n\t") {
			return fmt.Errorf("端口 %d 的目标应为 host:port", r.Port)
		}
	}
	return nil
}
