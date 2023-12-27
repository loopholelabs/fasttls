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

package ktls

import "C"
import (
	"errors"
	"fmt"
	"github.com/loopholelabs/fasttls/pkg/client"
	"github.com/loopholelabs/fasttls/pkg/server"
	"net"
	"unsafe"
)

const (
	TCP_ULP = 31
	SOL_TLS = 282
	TLS_TX  = 1
	TLS_RX  = 2
)

var (
	ErrInvalidConnType = errors.New("kTLS is only supported for Connections of type *net.TCPConn")
)

type Server struct {
	status C.fasttls_status_t
	server *server.Server
}

type Client struct {
	status     C.fasttls_status_t
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
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, ErrInvalidConnType
	}

	sess, err := s.server.Session()
	if err != nil {
		return nil, err
	}

	err = sess.Handshake(tcpConn)
	if err != nil {
		return nil, err
	}

	overflow, err := sess.ReadPlaintext(nil)
	if err != nil {
		return nil, err
	}

	secrets, err := sess.UnsafeSecrets()
	if err != nil {
		return nil, err
	}

	rawServerSocket, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var setupError error
	err = rawServerSocket.Control(func(fd uintptr) {
		C.fasttls_setup_ulp((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), *(*C.int32_t)(unsafe.Pointer(&fd)))
		if uint8(s.status) != 0 {
			setupError = fmt.Errorf("failed to get setup ULP: %d", uint8(s.status))
			return
		}

		C.fasttls_setup_ktls((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), *(*C.int32_t)(unsafe.Pointer(&fd)), secrets)
		if uint8(s.status) != 0 {
			setupError = fmt.Errorf("failed to get setup kTLS: %d", uint8(s.status))
		}
	})
	if err != nil {
		return nil, err
	}
	if setupError != nil {
		return nil, setupError
	}

	return newConnection(tcpConn, overflow)
}

func (c *Client) Connection(conn net.Conn) (net.Conn, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, ErrInvalidConnType
	}

	sess, err := c.client.Session(c.serverName)
	if err != nil {
		return nil, err
	}

	err = sess.Handshake(tcpConn)
	if err != nil {
		return nil, err
	}

	overflow, err := sess.ReadPlaintext(nil)
	if err != nil {
		return nil, err
	}

	secrets, err := sess.UnsafeSecrets()
	if err != nil {
		return nil, err
	}

	rawServerSocket, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var setupError error
	err = rawServerSocket.Control(func(fd uintptr) {
		C.fasttls_setup_ulp((*C.fasttls_status_t)(unsafe.Pointer(&c.status)), *(*C.int32_t)(unsafe.Pointer(&fd)))
		if uint8(c.status) != 0 {
			setupError = fmt.Errorf("failed to get setup ULP: %d", uint8(c.status))
			return
		}

		C.fasttls_setup_ktls((*C.fasttls_status_t)(unsafe.Pointer(&c.status)), *(*C.int32_t)(unsafe.Pointer(&fd)), secrets)
		if uint8(c.status) != 0 {
			setupError = fmt.Errorf("failed to get setup kTLS: %d", uint8(c.status))
		}
	})
	if err != nil {
		return nil, err
	}
	if setupError != nil {
		return nil, setupError
	}

	return newConnection(tcpConn, overflow)
}
