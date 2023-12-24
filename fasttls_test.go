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
	"github.com/loopholelabs/fasttls/internal/testpki"
	"github.com/loopholelabs/testing/conn/pair"
	"github.com/stretchr/testify/require"
	"net"
	"sync"
	"testing"
)

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
			done := make(chan struct{}, 1)
			errCh := make(chan error, 1)
			go func() {
				for i := uint32(0); i < testSize; i++ {
					_, err := readerConn.Read(readData)
					if err != nil {
						errCh <- err
						return
					}
				}
				done <- struct{}{}
			}()
			for i := uint32(0); i < testSize; i++ {
				select {
				case err = <-errCh:
					b.Fatal(err)
				default:
					_, err = writerConn.Write(randomData)
					if err != nil {
						b.Fatal(err)
					}
				}
			}
			select {
			case <-done:
				continue
			case err = <-errCh:
				b.Fatal(err)
			}
		}
		b.StopTimer()
	}
}

func BenchmarkRaw(b *testing.B) {
	const testSize = 100

	reader, writer, err := pair.New()
	require.NoError(b, err)

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

	reader, writer, err := pair.New()
	require.NoError(b, err)

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

	reader, writer, err := pair.New()
	require.NoError(b, err)

	testpki, err := testpki.New()
	require.NoError(b, err)

	server, err := NewServer(testpki.ServerCert, testpki.ServerKey, testpki.CaCert)
	require.NoError(b, err)

	client, err := NewClient(testpki.CaCert, testpki.ClientCert, testpki.ClientKey)
	require.NoError(b, err)

	var wg sync.WaitGroup

	clientSession, err := client.Session("localhost")
	require.NoError(b, err)
	wg.Add(1)
	go func() {
		err := clientSession.Handshake(writer)
		wg.Done()
		require.NoError(b, err)
	}()

	serverSession, err := server.Session()
	require.NoError(b, err)
	wg.Add(1)
	go func() {
		err := serverSession.Handshake(reader)
		wg.Done()
		require.NoError(b, err)
	}()

	wg.Wait()

	b.Run("32 Bytes", throughputRunner(testSize, 32, reader, writer))
	b.Run("512 Bytes", throughputRunner(testSize, 512, reader, writer))
	b.Run("1024 Bytes", throughputRunner(testSize, 1024, reader, writer))
	b.Run("2048 Bytes", throughputRunner(testSize, 2048, reader, writer))
	b.Run("4096 Bytes", throughputRunner(testSize, 4096, reader, writer))

	_ = reader.Close()
	_ = writer.Close()
}
