package selftls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// SelfSignedCertKey generate selfsigned certificate with RSA 2048 RSA private key
func SelfSignedCertKey(DNSNames []string, IPAddresses []net.IP) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)

	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		BasicConstraintsValid: true,
		DNSNames:              DNSNames,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IPAddresses: IPAddresses,
		IsCA:        true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		NotAfter:     notAfter,
		NotBefore:    notBefore,
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Etoron Tech Inc"},
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	var certOut, keyOut bytes.Buffer

	pem.Encode(&certOut, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	pem.Encode(&keyOut, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	return certOut.Bytes(), keyOut.Bytes(), nil
}
