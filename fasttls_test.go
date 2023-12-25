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
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"github.com/loopholelabs/fasttls/internal/testpki"
	"github.com/loopholelabs/fasttls/pkg/client"
	"github.com/loopholelabs/fasttls/pkg/connection"
	"github.com/loopholelabs/fasttls/pkg/server"
	"github.com/loopholelabs/testing/conn/pair"
	"github.com/stretchr/testify/require"
	"net"
	"sync"
	"testing"
)

func TestSession(t *testing.T) {
	const testSize = 100000
	testPKI, err := testpki.New()
	require.NoError(t, err)

	s, err := server.New(testPKI.ServerCert, testPKI.ServerKey, testPKI.CaCert)
	require.NoError(t, err)

	c, err := client.New(testPKI.CaCert, testPKI.ClientCert, testPKI.ClientKey)
	require.NoError(t, err)

	serverSession, err := s.Session()
	require.NoError(t, err)

	clientSession, err := c.Session("localhost")
	require.NoError(t, err)

	serverSocket, clientSocket, err := pair.New()
	require.NoError(t, err)

	clientLastMessage := "no client message"
	serverLastMessage := "no server message"

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		t.Log("client initiating handshake")
		err := clientSession.Handshake(clientSocket)
		require.NoError(t, err)
		t.Log("client handshake complete")

		var i = 0
		for i < testSize {
			message := []byte(fmt.Sprintf("message #%d", i))
			t.Logf("client sending: %s (i = %d)", message, i)
			encryptedMessage, err := clientSession.Encrypt(message)
			require.NoError(t, err)

			_, err = clientSocket.Write(encryptedMessage)
			require.NoError(t, err)

			buffer := make([]byte, 1024)
			for {
				n, err := clientSocket.Read(buffer)
				require.NoError(t, err)

				decryptedMessage, err := clientSession.Decrypt(buffer[:n])
				require.NoError(t, err)
				if len(decryptedMessage) == 0 {
					continue
				}

				clientLastMessage = string(decryptedMessage)
				break
			}

			t.Logf("client received: %s (i = %d)", clientLastMessage, i)
			i++
		}

		t.Log("client closing connection")
		err = clientSession.SendCloseNotify()
		encrypted, err := clientSession.WriteTLS(nil)
		require.NoError(t, err)
		_, err = clientSocket.Write(encrypted)
		require.NoError(t, err)
		err = clientSocket.Close()
		require.NoError(t, err)

		wg.Done()
	}()

	t.Log("server initiating handshake")
	err = serverSession.Handshake(serverSocket)
	require.NoError(t, err)
	t.Log("server handshake complete")

	var i = 0
	for i < testSize {
		buffer := make([]byte, 1024)
		n, err := serverSocket.Read(buffer)
		require.NoError(t, err)

		decryptedMessage, err := serverSession.Decrypt(buffer[:n])
		require.NoError(t, err)

		if len(decryptedMessage) == 0 {
			continue
		}

		if string(decryptedMessage) == serverLastMessage {
			panic("server received duplicate message")
		}

		serverLastMessage = string(decryptedMessage)
		t.Logf("server received: %s (i = %d)", serverLastMessage, i)
		encryptedMessage, err := serverSession.Encrypt(decryptedMessage)
		require.NoError(t, err)

		_, err = serverSocket.Write(encryptedMessage)
		require.NoError(t, err)
		i++
	}

	wg.Wait()

	require.Equal(t, clientLastMessage, serverLastMessage)

	clientSession.Free()
	serverSession.Free()
	s.Free()
	c.Free()
}

func BenchmarkRaw(b *testing.B) {
	const testSize = 100

	reader, writer := createPair(b)

	b.Run("32 Bytes", throughputRunner(testSize, 32, reader, writer))
	b.Run("512 Bytes", throughputRunner(testSize, 512, reader, writer))
	b.Run("1024 Bytes", throughputRunner(testSize, 1024, reader, writer))
	b.Run("2048 Bytes", throughputRunner(testSize, 2048, reader, writer))
	b.Run("4096 Bytes", throughputRunner(testSize, 4096, reader, writer))

	_ = reader.Close()
	_ = writer.Close()
}

func BenchmarkNativeTLS(b *testing.B) {
	const testSize = 100

	reader, writer := createPair(b)

	testpki, err := testpki.New()
	require.NoError(b, err)

	var wg sync.WaitGroup
	tlsReader := tls.Server(reader, testpki.ServerConfig)
	wg.Add(1)
	go func() {
		err = tlsReader.Handshake()
		wg.Done()
		require.NoError(b, err)
	}()

	tlsWriter := tls.Client(writer, testpki.ClientConfig)
	wg.Add(1)
	go func() {
		err = tlsWriter.Handshake()
		wg.Done()
		require.NoError(b, err)
	}()

	wg.Wait()

	b.Run("32 Bytes", throughputRunner(testSize, 32, tlsReader, tlsWriter))
	b.Run("512 Bytes", throughputRunner(testSize, 512, tlsReader, tlsWriter))
	b.Run("1024 Bytes", throughputRunner(testSize, 1024, tlsReader, tlsWriter))
	b.Run("2048 Bytes", throughputRunner(testSize, 2048, tlsReader, tlsWriter))
	b.Run("4096 Bytes", throughputRunner(testSize, 4096, tlsReader, tlsWriter))

	_ = tlsReader.Close()
	_ = tlsWriter.Close()
}

func BenchmarkRustTLS(b *testing.B) {
	const testSize = 100

	reader, writer := createPair(b)

	testPKI, err := testpki.New()
	require.NoError(b, err)

	s, err := server.New(testPKI.ServerCert, testPKI.ServerKey, testPKI.CaCert)
	require.NoError(b, err)

	c, err := client.New(testPKI.CaCert, testPKI.ClientCert, testPKI.ClientKey)
	require.NoError(b, err)

	var wg sync.WaitGroup

	clientSession, err := c.Session("localhost")
	require.NoError(b, err)
	wg.Add(1)
	go func() {
		err := clientSession.Handshake(writer)
		wg.Done()
		require.NoError(b, err)
	}()

	serverSession, err := s.Session()
	require.NoError(b, err)
	wg.Add(1)
	go func() {
		err := serverSession.Handshake(reader)
		wg.Done()
		require.NoError(b, err)
	}()

	wg.Wait()

	tlsReader, err := connection.New(reader, serverSession)
	require.NoError(b, err)

	tlsWriter, err := connection.New(writer, clientSession)
	require.NoError(b, err)

	b.Run("32 Bytes", throughputRunner(testSize, 32, tlsReader, tlsWriter))
	b.Run("512 Bytes", throughputRunner(testSize, 512, tlsReader, tlsWriter))
	b.Run("1024 Bytes", throughputRunner(testSize, 1024, tlsReader, tlsWriter))
	b.Run("2048 Bytes", throughputRunner(testSize, 2048, tlsReader, tlsWriter))
	b.Run("4096 Bytes", throughputRunner(testSize, 4096, tlsReader, tlsWriter))

	_ = reader.Close()
	_ = writer.Close()
}

func createPair(t require.TestingT) (net.Conn, net.Conn) {
	reader, writer, err := pair.New()
	require.NoError(t, err)
	return reader, writer
}

func throughputRunner(testSize, packetSize uint32, readerConn, writerConn net.Conn) func(b *testing.B) {
	return func(b *testing.B) {
		b.SetBytes(int64(testSize * packetSize))
		b.ReportAllocs()

		randomData := make([]byte, packetSize)
		_, err := rand.Read(randomData)
		require.NoError(b, err)

		readData := make([]byte, packetSize)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				for x := uint32(0); x < testSize; x++ {
					_, err := readerConn.Read(readData)
					require.NoError(b, err)
				}
				wg.Done()
			}()
			for x := uint32(0); x < testSize; x++ {
				_, err := writerConn.Write(randomData)
				require.NoError(b, err)
			}
			wg.Wait()
		}
		b.StopTimer()
	}
}
