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
	"github.com/loopholelabs/fasttls/internal/testpki"
	"github.com/loopholelabs/testing/conn/pair"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestSession(t *testing.T) {
	testPKI, err := testpki.New()
	require.NoError(t, err)

	server, err := NewServer(testPKI.ServerCert, testPKI.ServerKey, testPKI.CaCert)
	require.NoError(t, err)

	client, err := NewClient(testPKI.CaCert, testPKI.ClientCert, testPKI.ClientKey)
	require.NoError(t, err)

	clientSession, err := client.Session("localhost")
	require.NoError(t, err)

	serverSession, err := server.Session()
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

		for i := 0; i < 1000; i++ {
			message := []byte(fmt.Sprintf("message #%d", i))
			t.Logf("client sending: %s", message)
			encryptedMessage, err := clientSession.Encrypt(message)
			require.NoError(t, err)

			_, err = clientSocket.Write(encryptedMessage)
			require.NoError(t, err)

			buffer := make([]byte, bufferSize)
			n, err := clientSocket.Read(buffer)
			require.NoError(t, err)

			decryptedMessage, err := clientSession.Decrypt(buffer[:n])
			require.NoError(t, err)
			if len(decryptedMessage) == 0 {
				i--
				continue
			}

			clientLastMessage = string(decryptedMessage)
			t.Logf("client received: %s", clientLastMessage)
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

	for i := 0; i < 1000; i++ {
		buffer := make([]byte, bufferSize)
		n, err := serverSocket.Read(buffer)
		require.NoError(t, err)

		decryptedMessage, err := serverSession.Decrypt(buffer[:n])
		require.NoError(t, err)

		if len(decryptedMessage) == 0 {
			i--
			continue
		}

		serverLastMessage = string(decryptedMessage)
		t.Logf("server received: %s", serverLastMessage)
		encryptedMessage, err := serverSession.Encrypt(decryptedMessage)
		require.NoError(t, err)

		_, err = serverSocket.Write(encryptedMessage)
		require.NoError(t, err)
	}

	wg.Wait()

	require.Equal(t, clientLastMessage, serverLastMessage)

	clientSession.Free()
	serverSession.Free()
	server.Free()
}
