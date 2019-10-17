package util

import (
	"crypto/rsa"
	"crypto/x509"
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
			roots := x509.NewCertPool()
			for _, bundleCert := range tc.bundle {
				roots.AddCert(bundleCert)
			}

			var intermediates *x509.CertPool
			if len(tc.servingCert.Certs) > 1 {
				intermediates = x509.NewCertPool()
				for i := 1; i < len(tc.servingCert.Certs); i++ {
					intermediates.AddCert(tc.servingCert.Certs[i])
				}
			}

			opts := x509.VerifyOptions{
				DNSName:       "",
				Intermediates: intermediates,
				Roots:         roots,
			}

			_, err = tc.servingCert.Certs[0].Verify(opts)
			if err != nil {
				t.Fatalf("%s: error verifying client trust: %v", testName, err)
			}
		})
	}
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
