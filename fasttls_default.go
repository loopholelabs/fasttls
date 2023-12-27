//go:build !linux && !rustls

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
	"github.com/loopholelabs/fasttls/pkg/std"
	"net"
)

type Server struct {
	server *std.Server
}

type Client struct {
	client *std.Client
}

func NewServer(certificate []byte, key []byte, clientCACert []byte) (*Server, error) {
	server, err := std.NewServer(certificate, key, clientCACert)
	if err != nil {
		return nil, err
	}
	return &Server{
		server: server,
	}, nil
}

func NewClient(caCert []byte, clientAuthCert []byte, clientAuthKey []byte, serverName string) (*Client, error) {
	client, err := std.NewClient(caCert, clientAuthCert, clientAuthKey, serverName)
	if err != nil {
		return nil, err
	}
	return &Client{
		client: client,
	}, nil
}

func (s *Server) Connection(conn net.Conn) (net.Conn, error) {
	return s.server.Connection(conn)
}

func (c *Client) Connection(conn net.Conn) (net.Conn, error) {
	return c.client.Connection(conn)
}
