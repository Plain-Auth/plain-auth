package main

import (
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
