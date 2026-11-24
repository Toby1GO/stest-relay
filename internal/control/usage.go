package control

import (
	"fmt"
	"time"
)

var billingZone = time.FixedZone("UTC+8", 8*3600)

func Month(t time.Time) string { return t.In(billingZone).Format("2006-01") }

type Bytes struct {
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

func UsageKey(owner string, port int, t time.Time) string {
	return fmt.Sprintf("%s/%s/%d", Month(t), owner, port)
}

type ExitReport struct {
	Port  int              `json:"port"`
	Usage map[string]Bytes `json:"usage"`
}
