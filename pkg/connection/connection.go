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

package connection

import (
	"fmt"
	"github.com/loopholelabs/fasttls/pkg/session"
	"net"
	"time"
)

var _ net.Conn = (*Connection)(nil)

type Connection struct {
	conn    net.Conn
	session *session.Session
}

func New(conn net.Conn, session *session.Session) (*Connection, error) {
	if !session.HandshakeComplete() {
		return nil, fmt.Errorf("handshake is not complete")
	}
	return &Connection{
		conn:    conn,
		session: session,
	}, nil
}

func (c *Connection) Read(b []byte) (int, error) {
READ:
	readBytes, err := c.conn.Read(b)
	if err != nil {
		return 0, err
	}
	err = c.session.ReadTLS(b[:readBytes])
	if err != nil {
		return 0, nil
	}

	readBytes, err = c.session.ReadPlaintextSize(b)
	if err != nil {
		return 0, err
	}
	if readBytes == 0 {
		goto READ
	}

	return readBytes, nil
}

func (c *Connection) Write(b []byte) (int, error) {
	encrypted, err := c.session.Encrypt(b)
	if err != nil {
		return 0, err
	}

	return c.conn.Write(encrypted)
}

func (c *Connection) Close() error {
	err := c.session.SendCloseNotify()
	if err != nil {
		return err
	}
	encrypted, err := c.session.WriteTLS(nil)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(encrypted)
	if err != nil {
		return err
	}
	return c.conn.Close()
}

func (c *Connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Connection) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}
