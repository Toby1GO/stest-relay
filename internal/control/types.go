package control

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

type Mapping struct {
	Customer  string     `json:"customer,omitempty"`
	Remark    string     `json:"remark,omitempty"`
	Port      int        `json:"port"`
	Target    string     `json:"target"`
	UDP       bool       `json:"udp"`
	Disabled  bool       `json:"disabled,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

func (m Mapping) Restricted(now time.Time) bool {
	return m.Disabled || (m.ExpiresAt != nil && !now.Before(*m.ExpiresAt))
}

type Plan struct {
	Rules []Mapping `json:"rules"`
	IP    string    `json:"ip"`
	Ports string    `json:"ports"`
}

type Revision struct {
	Version string `json:"version"`
	Plan    Plan   `json:"plan"`
}
type Heartbeat struct {
	Applied string `json:"applied"`
	Tried   string `json:"tried"`
	Error   string `json:"error"`
	B       string `json:"b"`
	Initial *Plan  `json:"initial,omitempty"`
}

var NodeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func SaveJSON(path string, v any) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".socks-state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	e = json.NewEncoder(f).Encode(v)
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	return os.Rename(f.Name(), path)
}
