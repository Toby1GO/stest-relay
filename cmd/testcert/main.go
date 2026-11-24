// Generate a short-lived, self-signed certificate for local compatibility tests.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		log.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		log.Fatal(e)
	}
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "MyTunnelServer"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if e != nil {
		log.Fatal(e)
	}
	pk, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		log.Fatal(e)
	}
	for _, f := range []struct {
		path, t string
		b       []byte
	}{{"server.key", "PRIVATE KEY", pk}, {"server.crt", "CERTIFICATE", der}} {
		h, e := os.OpenFile(f.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			log.Fatal(e)
		}
		if e = pem.Encode(h, &pem.Block{Type: f.t, Bytes: f.b}); e != nil {
			log.Fatal(e)
		}
		if e = h.Close(); e != nil {
			log.Fatal(e)
		}
	}
}
