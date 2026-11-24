package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

func clientTLS(host, path string) (*tls.Config, error) {
	certs, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certs) {
		return nil, errors.New("invalid server certificate PEM")
	}
	pins := map[[32]byte]bool{}
	for rest := certs; len(rest) > 0; {
		block, tail := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			pins[sha256.Sum256(block.Bytes)] = true
		}
		rest = tail
	}
	// Upstream examples use self-signed certificates without SANs. Accept the exact
	// configured leaf after chain/time/EKU validation. CA-issued leaves also need hostname validation.
	return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true, VerifyConnection: func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("no peer certificate")
		}
		leaf := cs.PeerCertificates[0]
		opts := x509.VerifyOptions{DNSName: host, Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: time.Now()}
		if pins[sha256.Sum256(leaf.Raw)] {
			opts.DNSName = ""
		}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		_, err := leaf.Verify(opts)
		return err
	}}, nil
}
