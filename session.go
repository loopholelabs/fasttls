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
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"
)

var (
	bufferSize = 1024
)

type kind uint8

const (
	kindServer kind = iota
	kindClient
)

type Session struct {
	free    atomic.Bool
	kind    kind
	status  C.fasttls_status_t
	session *C.fasttls_session_t
}

func newSession(session *C.fasttls_session_t, kind kind) (*Session, error) {
	if session == nil {
		return nil, fmt.Errorf("session is nil")
	}
	return &Session{
		session: session,
		kind:    kind,
	}, nil
}

func (s *Session) Handshake(connection io.ReadWriter) error {
	switch s.kind {
	case kindClient:
		fmt.Println("Client doing initial handshake")
		handshake := C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, nil, 0)
		if uint8(s.status) != 0 {
			return fmt.Errorf("failed to initiate client handshake: %d", uint8(s.status))
		}
		encryptedData := make([]byte, bufferSize)
		for {
			fmt.Printf("Client handshake state: %d\n", uint8(handshake.state))
			switch handshake.state {
			case C.FASTTLS_HANDSHAKE_STATE_NEED_READ:
			case C.FASTTLS_HANDSHAKE_STATE_NEED_WRITE, C.FASTTLS_HANDSHAKE_STATE_COMPLETE:
				if handshake.output_data_ptr != nil && handshake.output_data_len > 0 {
					fmt.Println("Client doing write")
					output := unsafe.Slice((*byte)(unsafe.Pointer(handshake.output_data_ptr)), int(handshake.output_data_len))
					_, err := connection.Write(output)
					if err != nil {
						C.fasttls_free_handshake(handshake)
						return fmt.Errorf("failed to write client handshake data: %w", err)
					}
				}
				if handshake.state == C.FASTTLS_HANDSHAKE_STATE_COMPLETE {
					C.fasttls_free_handshake(handshake)
					goto HANDSHAKE_COMPLETE
				}
			default:
				C.fasttls_free_handshake(handshake)
				return fmt.Errorf("unknown client handshake state: %d", uint8(handshake.state))
			}
			C.fasttls_free_handshake(handshake)
			fmt.Println("Client doing read")
			encryptedBytes, err := connection.Read(encryptedData)
			if err != nil {
				return fmt.Errorf("failed to read client handshake data: %w", err)
			}
			handshake = C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&encryptedData[0])), C.uint32_t(encryptedBytes))
			if uint8(s.status) != 0 {
				C.fasttls_free_handshake(handshake)
				return fmt.Errorf("failed to complete client handshake: %d", uint8(s.status))
			}
		}
	case kindServer:
		encryptedData := make([]byte, bufferSize)
		for {
			fmt.Println("Server doing read")
			encryptedBytes, err := connection.Read(encryptedData)
			if err != nil {
				return fmt.Errorf("failed to read server handshake data: %w", err)
			}
			handshake := C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&encryptedData[0])), C.uint32_t(encryptedBytes))
			if uint8(s.status) != 0 {
				return fmt.Errorf("failed to complete server handshake: %d", uint8(s.status))
			}
			fmt.Printf("Server handshake state: %d\n", uint8(handshake.state))
			switch handshake.state {
			case C.FASTTLS_HANDSHAKE_STATE_NEED_READ:
			case C.FASTTLS_HANDSHAKE_STATE_NEED_WRITE, C.FASTTLS_HANDSHAKE_STATE_COMPLETE:
				if handshake.output_data_ptr != nil && handshake.output_data_len > 0 {
					fmt.Println("Server doing write")
					output := unsafe.Slice((*byte)(unsafe.Pointer(handshake.output_data_ptr)), int(handshake.output_data_len))
					_, err = connection.Write(output)
					if err != nil {
						C.fasttls_free_handshake(handshake)
						return fmt.Errorf("failed to write server handshake data: %w", err)
					}
				}
				if handshake.state == C.FASTTLS_HANDSHAKE_STATE_COMPLETE {
					C.fasttls_free_handshake(handshake)
					goto HANDSHAKE_COMPLETE
				}
			default:
				C.fasttls_free_handshake(handshake)
				return fmt.Errorf("unknown server handshake state: %d", uint8(handshake.state))
			}
			C.fasttls_free_handshake(handshake)
		}
	default:
		return fmt.Errorf("unknown session kind: %d", s.kind)
	}
HANDSHAKE_COMPLETE:
	return nil
}

func (s *Session) Free() {
	if s.free.CompareAndSwap(false, true) {
		C.fasttls_free_session(s.session)
	}
}
