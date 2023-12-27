/*
   Copyright 2023 Loophole Labs

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package testpki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

type TestPKI struct {
	CaCert       []byte
	ClientCert   []byte
	ClientKey    []byte
	ClientConfig *tls.Config
	ServerCert   []byte
	ServerKey    []byte
	ServerConfig *tls.Config
}

func New() (*TestPKI, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate CA key: %w", err)
	}

	caParams := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"TestPKI Server Acceptor"},
			CommonName:   "TestPKI CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		MaxPathLen:            1,
		BasicConstraintsValid: true,
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caParams, caParams, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	caPEM, err := EncodeX509Certificate(caBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CA certificate: %w", err)
	}

	caCert, err := DecodeX509Certificate(caPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CA certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate server key: %w", err)
	}

	serverCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server CSR: %w", err)
	}

	serverCSR, err := DecodeX509CSR(serverCSRBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode server CSR: %w", err)
	}

	serverParams := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Signature:          serverCSR.Signature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          serverCSR.PublicKey,
		Subject: pkix.Name{
			CommonName: "TestPKI Server",
		},
		DNSNames:    []string{"localhost"},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	serverBytes, err := x509.CreateCertificate(rand.Reader, serverParams, caCert, serverCSR.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create server certificate: %w", err)
	}

	serverPEM, err := EncodeX509Certificate(serverBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode server certificate: %w", err)
	}

	clientKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate client key: %w", err)
	}

	clientCSRBytes, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, clientKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client CSR: %w", err)
	}

	clientCSR, err := DecodeX509CSR(clientCSRBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client CSR: %w", err)
	}

	clientParams := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		PublicKey:          clientCSR.PublicKey,
		Subject: pkix.Name{
			CommonName: "TestPKI Client",
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	clientBytes, err := x509.CreateCertificate(rand.Reader, clientParams, caCert, clientCSR.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	clientPEM, err := EncodeX509Certificate(clientBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to encode client certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	return &TestPKI{
		CaCert:     caPEM,
		ClientCert: clientPEM,
		ClientKey:  EncodeECDSAPrivateKey(clientKey),
		ClientConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{clientBytes}, PrivateKey: clientKey}},
			ServerName:   "localhost",
			RootCAs:      caPool,
		},
		ServerCert: serverPEM,
		ServerKey:  EncodeECDSAPrivateKey(serverKey),
		ServerConfig: &tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverBytes}, PrivateKey: serverKey}},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		},
	}, nil
}

func EncodeECDSAPrivateKey(privateKey *ecdsa.PrivateKey) []byte {
	marshalled, _ := x509.MarshalPKCS8PrivateKey(privateKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalled})
}

func DecodeECDSAPrivateKey(encoded []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(encoded)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if privateKey, ok := key.(*ecdsa.PrivateKey); ok {
		return privateKey, nil
	}
	return nil, fmt.Errorf("failed to decode private key")
}

func EncodeX509Certificate(caBytes []byte) ([]byte, error) {
	caPEMBuffer := new(bytes.Buffer)
	err := pem.Encode(caPEMBuffer, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, err
	}

	return caPEMBuffer.Bytes(), nil
}

func DecodeX509Certificate(encoded []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(encoded)
	return x509.ParseCertificate(block.Bytes)
}

func DecodeX509CSR(encoded []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(encoded)
	if block == nil {
		return x509.ParseCertificateRequest(encoded)
	} else {
		return x509.ParseCertificateRequest(block.Bytes)
	}
}
