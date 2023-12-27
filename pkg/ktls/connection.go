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

import (
	"net"
	"time"
)

var _ net.Conn = (*Connection)(nil)

type Connection struct {
	conn     *net.TCPConn
	overflow []byte
}

func newConnection(conn *net.TCPConn, overflow []byte) (*Connection, error) {
	return &Connection{
		conn: conn,
	}, nil
}

func (c *Connection) Read(b []byte) (int, error) {
	if len(c.overflow) > 0 {
		if len(c.overflow) > len(b) {
			written := copy(b, c.overflow)
			c.overflow = c.overflow[written:]
			return written, nil
		}
		written := copy(b, c.overflow)
		c.overflow = nil
		secondWrite, err := c.conn.Read(b[written:])
		return written + secondWrite, err
	}

	return c.conn.Read(b)
}

func (c *Connection) Write(b []byte) (int, error) {
	return c.conn.Write(b)
}

func (c *Connection) Close() error {
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
