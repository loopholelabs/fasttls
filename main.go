//go:build unix

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

package main

/*
#cgo LDFLAGS: ./target/release/libfasttls.a -ldl
#include "./fasttls.h"
*/
import "C"
import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/loopholelabs/fasttls/internal/testpki"
	"github.com/loopholelabs/testing/conn/pair"
	"sync"
	"unsafe"
)

func main() {
	testPKI, err := testpki.New()
	if err != nil {
		panic(err)
	}

	serverSocket, clientSocket, err := pair.New()
	if err != nil {
		panic(err)
	}

	caCert, err := testpki.DecodeX509Certificate(testPKI.CaCert)
	if err != nil {
		panic(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	clientCert, err := testpki.DecodeX509Certificate(testPKI.ClientCert)
	if err != nil {
		panic(err)
	}

	clientKey, err := testpki.DecodeECDSAPrivateKey(testPKI.ClientKey)
	if err != nil {
		panic(err)
	}

	clientConfig := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{clientCert.Raw}, PrivateKey: clientKey}},
		ServerName:   "localhost",
		RootCAs:      caPool,
	}

	client := tls.Client(clientSocket, clientConfig)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			message := fmt.Sprintf("message #%d", i)
			fmt.Printf("Client sending: %s\n", message)
			_, err := client.Write([]byte(message))
			if err != nil {
				panic(err)
			}
			plaintext := make([]byte, 1024)
			readBytes, err := client.Read(plaintext)
			if err != nil {
				panic(err)
			}
			fmt.Printf("Client received: %s\n", plaintext[:readBytes])
		}
	}()

	fmt.Printf("Doing FFI\n")

	var status C.fasttls_status_t = C.FASTTLS_STATUS_NULL_PTR

	serverConfig := C.fasttls_server_config((*C.fasttls_status_t)(unsafe.Pointer(&status)), (*C.uint8_t)(unsafe.Pointer(&testPKI.ServerCert[0])), C.uint32_t(len(testPKI.ServerCert)), (*C.uint8_t)(unsafe.Pointer(&testPKI.ServerKey[0])), C.uint32_t(len(testPKI.ServerKey)), (*C.uint8_t)(unsafe.Pointer(&testPKI.CaCert[0])), C.uint32_t(len(testPKI.CaCert)))
	fmt.Printf("Config Status: %d\n", uint8(status))

	serverSession := C.fasttls_server_session((*C.fasttls_status_t)(unsafe.Pointer(&status)), serverConfig)
	fmt.Printf("Session Status: %d\n", uint8(status))

	for {
		readData := make([]byte, 1024)
		bytesRead, err := serverSocket.Read(readData)
		if err != nil {
			panic(err)
		}

		handshake := C.fasttls_server_handshake((*C.fasttls_status_t)(unsafe.Pointer(&status)), serverSession, (*C.uint8_t)(unsafe.Pointer(&readData[0])), C.uint32_t(bytesRead))
		fmt.Printf("Handshake Status: %d\n", uint8(status))
		fmt.Printf("Handshake State: %d\n", uint8(handshake.state))

		switch handshake.state {
		case C.FASTTLS_HANDSHAKE_STATE_NEED_READ:
		case C.FASTTLS_HANDSHAKE_STATE_NEED_WRITE, C.FASTTLS_HANDSHAKE_STATE_COMPLETE:
			if handshake.output_data_ptr != nil && handshake.output_data_len > 0 {
				output := unsafe.Slice((*byte)(unsafe.Pointer(handshake.output_data_ptr)), int(handshake.output_data_len))
				_, err = serverSocket.Write(output)
				if err != nil {
					panic(err)
				}
			}
			if handshake.state == C.FASTTLS_HANDSHAKE_STATE_COMPLETE {
				C.fasttls_free_handshake(handshake)
				goto HandshakeComplete
			}
		default:
			panic(fmt.Errorf("unexpected handshake state: %d", uint8(handshake.state)))
		}

		C.fasttls_free_handshake(handshake)
	}
HandshakeComplete:
	fmt.Printf("Handshake Complete\n")

	// This function takes ownership of the serverSession
	// it will be freed automatically when the handshake secrets are freed
	handshakeSecrets := C.fasttls_server_handshake_secrets((*C.fasttls_status_t)(unsafe.Pointer(&status)), serverSession)
	fmt.Printf("Handshake Secrets Status: %d\n", uint8(status))
	if handshakeSecrets == nil {
		panic(fmt.Errorf("handshake secrets is nil"))
	}

	fmt.Printf("Handshake Secrets RX (%d): %+v\n", uint32(handshakeSecrets.rx_size), handshakeSecrets.rx)
	fmt.Printf("Handshake Secrets TX (%d): %+v\n", uint32(handshakeSecrets.tx_size), handshakeSecrets.tx)

	fmt.Printf("Closing 1\n")
	C.fasttls_free_handshake_secrets(handshakeSecrets)

	fmt.Printf("Closing 2\n")
	C.fasttls_free_server_config(serverConfig)

	fmt.Printf("Done FFI\n")
}
