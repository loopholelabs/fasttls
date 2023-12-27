//go:build linux && !rustls

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

/*
#cgo LDFLAGS: ./target/release/libfasttls.a -ldl
#include "./fasttls.h"
*/
import "C"
import (
	"bufio"
	"github.com/hashicorp/go-version"
	"github.com/loopholelabs/fasttls/pkg/ktls"
	"github.com/loopholelabs/fasttls/pkg/std"
	"net"
	"os"
	"strings"
)

var (
	kTLSSupported = false
)

func init() {
	file, err := os.Open("/proc/version")
	if err != nil {
		kTLSSupported = false
		return
	}

	scanner := bufio.NewScanner(file)
	if scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) > 2 {
			v, err := version.NewVersion(parts[2])
			if err != nil {
				kTLSSupported = false
				return
			}
			if v.LessThan(version.Must(version.NewVersion("4.13"))) {
				kTLSSupported = false
				return
			}
		}
	}

	if _, err := os.Stat("sys/kernel/debug/tls"); os.IsNotExist(err) {
		kTLSSupported = false
	} else {
		kTLSSupported = true
	}
}

type Server struct {
	ktlsServer *ktls.Server
	stdServer  *std.Server
}

type Client struct {
	ktlsClient *ktls.Client
	stdClient  *std.Client
}

func NewServer(certificate []byte, key []byte, clientCACert []byte) (*Server, error) {
	if kTLSSupported {
		s, err := ktls.NewServer(certificate, key, clientCACert)
		if err != nil {
			return nil, err
		}

		return &Server{
			ktlsServer: s,
		}, nil
	}

	s, err := std.NewServer(certificate, key, clientCACert)
	if err != nil {
		return nil, err
	}

	return &Server{
		stdServer: s,
	}, nil
}

func NewClient(caCert []byte, clientAuthCert []byte, clientAuthKey []byte, serverName string) (*Client, error) {
	if kTLSSupported {
		c, err := ktls.NewClient(caCert, clientAuthCert, clientAuthKey, serverName)
		if err != nil {
			return nil, err
		}

		return &Client{
			ktlsClient: c,
		}, nil
	}

	c, err := std.NewClient(caCert, clientAuthCert, clientAuthKey, serverName)
	if err != nil {
		return nil, err
	}

	return &Client{
		stdClient: c,
	}, nil
}

func (s *Server) Connection(conn net.Conn) (net.Conn, error) {
	if kTLSSupported {
		return s.ktlsServer.Connection(conn)
	}

	return s.stdServer.Connection(conn)
}

func (c *Client) Connection(conn net.Conn) (net.Conn, error) {
	if kTLSSupported {
		return c.ktlsClient.Connection(conn)
	}

	return c.stdClient.Connection(conn)
}
