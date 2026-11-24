// Package install provides the public node installation files served by the center.
package install

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
	"time"
)

//go:embed node.sh payload/*
var files embed.FS

func Ready() bool {
	for _, name := range []string{"SHA256SUMS", "socks5-go-linux-amd64", "socks5-go-linux-arm64", "manifest.json", "manifest.sig", "stest"} {
		if _, err := fs.Stat(files, "payload/"+name); err != nil {
			return false
		}
	}
	return true
}

func Serve(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/install/files/")
	switch name {
	case "node.sh":
	case "SHA256SUMS", "socks5-go-linux-amd64", "socks5-go-linux-arm64", "manifest.json", "manifest.sig", "stest":
		name = "payload/" + name
	default:
		http.NotFound(w, r)
		return
	}
	f, err := files.Open(name)
	if err != nil {
		http.Error(w, "Node packages missing from center build", 503)
		return
	}
	defer f.Close()
	// The center's short API write timeout is unsuitable for slow node downloads.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Minute))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, time.Time{}, f.(io.ReadSeeker))
}
