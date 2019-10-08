package util

import (
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"time"

	"github.com/openshift/library-go/pkg/crypto"
)

const SigningCertificateLifetimeInDays = 365 // 1 year

type SigningCA struct {
	Config         *crypto.TLSCertificateConfig
	Bundle         []*x509.Certificate
	IntermediateCA *x509.Certificate
}

// GetPEMBytes returns PEM-encodings of the CA cert, key, bundle and intermediate CA cert.
func (ca *SigningCA) GetPEMBytes() ([]byte, []byte, []byte, []byte, error) {
	caPEM, keyPEM, err := ca.Config.GetPEMBytes()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	bundlePEM, err := crypto.EncodeCertificates(ca.Bundle...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	intermediatePEM, err := crypto.EncodeCertificates(ca.IntermediateCA)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return caPEM, keyPEM, bundlePEM, intermediatePEM, nil
}

// RotateSigningCA creates a new signing CA along with an intermediate CA to allow for graceful rollover.
func RotateSigningCA(currentCA *x509.Certificate, currentKey *rsa.PrivateKey) (*SigningCA, error) {
	// TODO(marun) Set AuthorityKeyID and SubjectKeyID on all certs

	// Generate a new signing cert
	newCAConfig, err := crypto.MakeSelfSignedCAConfigForSubject(currentCA.Subject, SigningCertificateLifetimeInDays)
	if err != nil {
		return nil, err
	}
	newCA := newCAConfig.Certs[0]

	bundle := []*x509.Certificate{
		newCA,
		currentCA,
	}

	// This intermediate CA comprises the new CA's public key, private key, and subject. It's self-issued but not
	// self-signed as it's signed by the current CA key. This creates a trust bridge between the unrefreshed clients and
	// refreshed servers as long as refreshed servers serve with a bundle containing this CA and the serving cert.
	rawIntermediateCA, err := x509.CreateCertificate(crand.Reader, newCA, newCA, newCA.PublicKey, currentKey)
	if err != nil {
		return nil, err
	}
	parsedCerts, err := x509.ParseCertificates(rawIntermediateCA)
	if err != nil {
		return nil, err
	}
	intermediateCA := parsedCerts[0]

	return &SigningCA{
		Config:         newCAConfig,
		Bundle:         bundle,
		IntermediateCA: intermediateCA,
	}, nil
}

// CertHalfwayExpired indicates whether half of the cert validity period has elapsed.
func CertHalfwayExpired(cert *x509.Certificate) bool {
	halfValidPeriod := cert.NotAfter.Sub(cert.NotBefore).Nanoseconds() / 2
	halfExpiration := cert.NotBefore.Add(time.Duration(halfValidPeriod) * time.Nanosecond)
	return time.Now().After(halfExpiration)
}
