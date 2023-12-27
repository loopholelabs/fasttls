//go:build linux && rustls

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

package fasttls

import (
	"github.com/loopholelabs/fasttls/pkg/client"
	"github.com/loopholelabs/fasttls/pkg/connection"
	"github.com/loopholelabs/fasttls/pkg/server"
	"net"
)

type Server struct {
	server *server.Server
}

type Client struct {
	client     *client.Client
	serverName string
}

func NewServer(certificate []byte, key []byte, clientCACert []byte) (*Server, error) {
	s, err := server.New(certificate, key, clientCACert)
	if err != nil {
		return nil, err
	}

	return &Server{
		server: s,
	}, nil
}

func NewClient(caCert []byte, clientAuthCert []byte, clientAuthKey []byte, serverName string) (*Client, error) {
	c, err := client.New(caCert, clientAuthCert, clientAuthKey)
	if err != nil {
		return nil, err
	}

	return &Client{
		client:     c,
		serverName: serverName,
	}, nil
}

func (s *Server) Connection(conn net.Conn) (net.Conn, error) {
	sess, err := s.server.Session()
	if err != nil {
		return nil, err
	}

	err = sess.Handshake(conn)
	if err != nil {
		return nil, err
	}

	return connection.New(conn, sess)
}

func (c *Client) Connection(conn net.Conn) (net.Conn, error) {
	sess, err := c.client.Session(c.serverName)
	if err != nil {
		return nil, err
	}

	err = sess.Handshake(conn)
	if err != nil {
		return nil, err
	}

	return connection.New(conn, sess)
}
