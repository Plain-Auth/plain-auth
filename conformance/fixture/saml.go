package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/Stonewrit/stonewrit-auth/plugins/sso"
)

func serveSAMLFixture(listener net.Listener, handler http.Handler, baseURL, dbPath string) error {
	server := &httptest.Server{Listener: listener, Config: &http.Server{Handler: handler}}
	server.StartTLS()
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(filepath.Join(filepath.Dir(dbPath), "saml-test-ca.pem"), certificate, 0600); err != nil {
		return err
	}
	fmt.Println(baseURL)
	select {}
}

func fixtureSAMLEncryption(dir string) (*sso.SAMLEncryption, error) {
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "sp-cert.pem"), filepath.Join(dir, "sp-key.pem"))
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	key, ok := pair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("local fixture requires an RSA encryption key")
	}
	return &sso.SAMLEncryption{PrivateKey: key, Certificate: cert}, nil
}
