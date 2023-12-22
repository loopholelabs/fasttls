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
	"github.com/loopholelabs/fasttls/internal/testpki"
	"github.com/loopholelabs/testing/conn/pair"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestSession(t *testing.T) {
	testPKI, err := testpki.New()
	if err != nil {
		panic(err)
	}

	server, err := NewServer(testPKI.ServerCert, testPKI.ServerKey, testPKI.CaCert)
	require.NoError(t, err)

	client, err := NewClient(testPKI.CaCert, testPKI.ClientCert, testPKI.ClientKey)
	require.NoError(t, err)

	clientSession, err := client.Session("localhost")
	require.NoError(t, err)

	serverSession, err := server.Session()
	require.NoError(t, err)

	serverSocket, clientSocket, err := pair.New()
	if err != nil {
		panic(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		t.Log("client initiating handshake")
		err := clientSession.Handshake(clientSocket)
		require.NoError(t, err)
		t.Log("client handshake complete")
		wg.Done()
	}()

	t.Log("server initiating handshake")
	err = serverSession.Handshake(serverSocket)
	require.NoError(t, err)
	t.Log("server handshake complete")

	wg.Wait()
	//
	//let client_handle = thread::spawn(move || {
	//	println!("client initiating connection");
	//	let mut client_socket = TcpStream::connect(listen_address.clone()).unwrap();
	//	client_socket.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
	//	client_socket.set_write_timeout(Some(Duration::from_millis(50))).unwrap();
	//
	//	println!("client initiating handshake");
	//	do_client_handshake(&mut client_socket, &mut client_session);
	//	println!("client handshake complete");
	//
	//	for i in 0..10 {
	//		let message = format!("message #{}", i);
	//		println!("client sending: {}", message);
	//		client_session.write_plaintext(message.as_bytes()).unwrap();
	//
	//		loop {
	//			match client_session.write_tls_to_writer(&mut client_socket) {
	//			Ok(_) => {
	//			break;
	//		}
	//			Err(err) => {
	//			if err.to_string().contains("Resource temporarily unavailable") {
	//			continue;
	//		}
	//			panic!("error writing data to client: {}", err);
	//		}
	//		}
	//		}
	//		match client_socket.flush() {
	//			Ok(_) => {}
	//			Err(err) => {
	//				panic!("error flushing bytes to client: {}", err);
	//			}
	//		};
	//
	//		loop {
	//			match client_session.read_tls_from_reader(&mut client_socket) {
	//			Ok(()) => break,
	//			Err(err) => {
	//			if err.to_string().contains("Resource temporarily unavailable") {
	//			continue;
	//		}
	//			panic!("error reading data from client: {}", err);
	//		}
	//		}
	//		}
	//
	//		let message = client_session.read_plaintext().unwrap();
	//		println!("client received: {}", std::str::from_utf8(&message).unwrap());
	//	}
	//
	//	println!("client closing connection");
	//	client_session.send_close_notify();
	//	_ = client_session.write_tls_to_writer(&mut client_socket);
	//	_ = client_socket.flush();
	//	_ = client_socket.shutdown(std::net::Shutdown::Both);
	//});

	clientSession.Free()
	serverSession.Free()
	server.Free()
}
