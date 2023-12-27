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

package std

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

type Server struct {
	config *tls.Config
}

type Client struct {
	config *tls.Config
}

func NewServer(certificate []byte, key []byte, clientCACert []byte) (*Server, error) {
	cert, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, err
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if len(clientCACert) > 0 {
		config.ClientCAs = x509.NewCertPool()
		config.ClientCAs.AppendCertsFromPEM(clientCACert)
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return &Server{
		config: config,
	}, nil
}

func NewClient(caCert []byte, clientAuthCert []byte, clientAuthKey []byte, serverName string) (*Client, error) {
	config := &tls.Config{
		ServerName: serverName,
	}

	if len(caCert) > 0 {
		config.RootCAs = x509.NewCertPool()
		config.RootCAs.AppendCertsFromPEM(caCert)
	}

	if len(clientAuthCert) > 0 && len(clientAuthKey) > 0 {
		cert, err := tls.X509KeyPair(clientAuthCert, clientAuthKey)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return &Client{
		config: config,
	}, nil
}

func (s *Server) Connection(conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Server(conn, s.config)
	return tlsConn, tlsConn.Handshake()
}

func (c *Client) Connection(conn net.Conn) (net.Conn, error) {
	tlsConn := tls.Client(conn, c.config)
	return tlsConn, tlsConn.Handshake()
}
