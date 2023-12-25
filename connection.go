//go:build !linux

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
	"fmt"
	"net"
	"time"
)

var _ net.Conn = (*TCPConn)(nil)

type TCPConn struct {
	conn net.Conn
	//buffer  *bytes.Buffer
	session *Session
}

func NewConn(conn net.Conn, session *Session) (*TCPConn, error) {
	if !session.HandshakeComplete() {
		return nil, fmt.Errorf("handshake is not complete")
	}
	return &TCPConn{
		conn: conn,
		//buffer:  bytes.NewBuffer(nil),
		session: session,
	}, nil
}

//func (c *TCPConn) Read(b []byte) (int, error) {
//READ:
//	readBytes, err := c.conn.Read(b)
//	if err != nil {
//		return 0, err
//	}
//	var decrypted []byte
//	decrypted, err = c.session.Decrypt(b[:readBytes])
//	if err != nil {
//		return 0, err
//	}
//	if len(decrypted) == 0 {
//		goto READ
//	}
//	_, err = c.buffer.Write(decrypted)
//	if err != nil {
//		return 0, err
//	}
//	return c.buffer.Read(b)
//}

func (c *TCPConn) Read(b []byte) (int, error) {
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

func (c *TCPConn) Write(b []byte) (int, error) {
	encrypted, err := c.session.Encrypt(b)
	if err != nil {
		return 0, err
	}

	return c.conn.Write(encrypted)
}

func (c *TCPConn) Close() error {
	//TODO implement me
	panic("implement me")
}

func (c *TCPConn) LocalAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (c *TCPConn) RemoteAddr() net.Addr {
	//TODO implement me
	panic("implement me")
}

func (c *TCPConn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (c *TCPConn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}

func (c *TCPConn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("implement me")
}
