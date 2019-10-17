package util

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/openshift/library-go/pkg/crypto"
)

// TestRotateSigningCA validates that service certs signed by pre- and
// post-rotation CAs can be validated by both the new and old bundles.
func TestRotateSigningCA(t *testing.T) {
	hosts := sets.NewString("127.0.0.1")

	// Create the pre-rotation CA
	oldCAConfig, err := crypto.MakeSelfSignedCAConfig("foo", SigningCertificateLifetimeInDays)
	if err != nil {
		t.Fatalf("Failed to generate a new cert")
	}
	oldCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          oldCAConfig,
	}
	oldBundle := []*x509.Certificate{oldCAConfig.Certs[0]}

	// Generate a service cert with the pre-rotation CA
	oldServingCert, err := oldCA.MakeServerCert(
		hosts,
		crypto.DefaultCertificateLifetimeInDays,
	)
	if err != nil {
		t.Fatalf("Error generating server old service cert: %v", err)
	}

	// Rotate the CA
	newSigningCA, err := RotateSigningCA(oldCAConfig.Certs[0], oldCAConfig.Key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatalf("Error rotating signing ca: %v", err)
	}
	newCA := &crypto.CA{
		SerialGenerator: &crypto.RandomSerialGenerator{},
		Config:          newSigningCA.Config,
	}
	newBundle := newSigningCA.Bundle

	// Generate a service cert with the post-rotation CA
	newServingCert, err := newCA.MakeServerCert(
		hosts,
		crypto.DefaultCertificateLifetimeInDays,
	)
	if err != nil {
		t.Fatalf("Error generating new service cert: %v", err)
	}
	// Append the intermediate cert to ensure that clients with the
	// old bundle will be able to validate the service cert signed by
	// the new ca.
	newServingCert.Certs = append(newServingCert.Certs, newSigningCA.IntermediateCA)

	testCases := map[string]struct {
		servingCert *crypto.TLSCertificateConfig
		bundle      []*x509.Certificate
	}{
		"Pre-rotation": {
			servingCert: oldServingCert,
			bundle:      oldBundle,
		},
		"Server rotated": {
			servingCert: newServingCert,
			bundle:      oldBundle,
		},
		"Client refreshed": {
			servingCert: oldServingCert,
			bundle:      newBundle,
		},
		"Server rotated and client refreshed": {
			servingCert: newServingCert,
			bundle:      newBundle,
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			checkClientTrust(t, tc.servingCert, tc.bundle)
		})
	}
}

func checkClientTrust(t *testing.T, servingCert *crypto.TLSCertificateConfig, bundleCerts []*x509.Certificate) {
	// Configure a server with the serving cert
	rawCAs := [][]byte{}
	for _, caCert := range servingCert.Certs {
		rawCAs = append(rawCAs, caCert.Raw)
	}
	srv := http.Server{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{
				{
					Certificate: rawCAs,
					PrivateKey:  servingCert.Key,
				},
			},
		},
	}

	// Create a listener on a random port
	listenerAddress := "127.0.0.1:0"
	ln, err := net.Listen("tcp", listenerAddress)
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	serverAddress := ln.Addr().String()
	defer ln.Close()

	// Start a server configured with the cert
	go func() {
		if err := srv.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			t.Fatalf("ServeTLS failed: %v", err)
		}
	}()
	defer func() {
		err = srv.Close()
		if err != nil {
			t.Fatalf("tls server close failed: %v", err)
		}
	}()

	// Make a client connection configured with the provided bundle
	roots := x509.NewCertPool()
	for _, bundleCert := range bundleCerts {
		roots.AddCert(bundleCert)
	}
	tlsConf := &tls.Config{RootCAs: roots}
	tr := &http.Transport{TLSClientConfig: tlsConf}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	clientAddress := fmt.Sprintf("https://%s", serverAddress)
	_, err = client.Get(clientAddress)
	if err != nil {
		t.Fatalf("Failed to receive output: %v", err)
	}
	// No error indicates that validation was successful
}

func TestCertHalfwayExpired(t *testing.T) {
	now := time.Now()
	tests := map[string]struct {
		testCert *x509.Certificate
		expected bool
	}{
		"expired now": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now,
			},
			expected: true,
		},
		"time left": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -1),
				NotAfter:  now.AddDate(0, 0, 2),
			},
			expected: false,
		},
		"time up": {
			testCert: &x509.Certificate{
				NotBefore: now.AddDate(0, 0, -2),
				NotAfter:  now.AddDate(0, 0, 1),
			},
			expected: true,
		},
	}
	for name, tc := range tests {
		if CertHalfwayExpired(tc.testCert) != tc.expected {
			t.Errorf("%s: unexpected result, expected %v, got %v", name, tc.expected, !tc.expected)
		}
	}
}
