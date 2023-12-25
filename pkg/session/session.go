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

package session

/*
#cgo LDFLAGS: ./target/release/libfasttls.a -ldl
#include "../../fasttls.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"
)

var (
	ErrSessionNil          = errors.New("session is nil")
	ErrClosed              = errors.New("session is closed")
	ErrHandshakeInProgress = errors.New("handshake already in progress")
)

type kind uint8

const (
	KindServer kind = iota
	KindClient
)

const (
	handshakeStateNotComplete = iota
	handshakeStateInProgress
	handshakeStateComplete
)

type Session struct {
	free           atomic.Bool
	handshakeState atomic.Uint32
	kind           kind
	status         C.fasttls_status_t
	session        *C.fasttls_session_t
}

func New(session unsafe.Pointer, kind kind) (*Session, error) {
	if session == nil {
		return nil, ErrSessionNil
	}
	return &Session{
		session: (*C.fasttls_session_t)(session),
		kind:    kind,
	}, nil
}

func (s *Session) Handshake(connection io.ReadWriter) error {
	if s.handshakeState.CompareAndSwap(handshakeStateNotComplete, handshakeStateInProgress) {
		switch s.kind {
		case KindClient:
			return s.clientHandshake(connection)
		case KindServer:
			return s.serverHandshake(connection)
		default:
			return fmt.Errorf("unknown session kind: %d", s.kind)
		}
	}

	if s.handshakeState.Load() == handshakeStateInProgress {
		return ErrHandshakeInProgress
	}

	return nil
}

func (s *Session) HandshakeComplete() bool {
	return s.handshakeState.Load() == handshakeStateComplete
}

func (s *Session) WritePlaintext(plaintext []byte) error {
	if plaintext == nil {
		C.fasttls_write_plaintext((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, nil, 0)
	} else {
		C.fasttls_write_plaintext((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&plaintext[0])), C.uint32_t(len(plaintext)))
	}
	if uint8(s.status) != 0 {
		return fmt.Errorf("failed to write plaintext data: %d", uint8(s.status))
	}
	return nil
}

func (s *Session) WriteTLS(encrypted []byte) ([]byte, error) {
	buffer := C.fasttls_write_tls((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session)
	if uint8(s.status) != 0 {
		return nil, fmt.Errorf("failed to write tls data: %d", uint8(s.status))
	}
	if buffer.data_ptr == nil || buffer.data_len == 0 {
		return encrypted[:0], nil
	}
	if int(buffer.data_len) > len(encrypted) {
		encrypted = make([]byte, int(buffer.data_len))
	}
	encrypted = encrypted[:copy(encrypted, unsafe.Slice((*byte)(unsafe.Pointer(buffer.data_ptr)), int(buffer.data_len)))]
	C.fasttls_free_buffer(buffer)
	return encrypted, nil
}

func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	err := s.WritePlaintext(plaintext)
	if err != nil {
		return nil, err
	}
	return s.WriteTLS(nil)
}

func (s *Session) ReadTLS(encrypted []byte) error {
	if encrypted == nil {
		return nil
	} else {
		C.fasttls_read_tls((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&encrypted[0])), C.uint32_t(len(encrypted)))
	}
	if uint8(s.status) != 0 {
		return fmt.Errorf("failed to read tls data: %d", uint8(s.status))
	}
	return nil
}

func (s *Session) ReadPlaintext(plaintext []byte) ([]byte, error) {
	buffer := C.fasttls_read_plaintext((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session)
	if uint8(s.status) != 0 {
		closed := C.fasttls_is_closed((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session)
		if uint8(s.status) != 0 {
			return nil, fmt.Errorf("failed to read plaintext data: %d", uint8(s.status))
		}
		if bool(closed) {
			return nil, ErrClosed
		}
		return nil, fmt.Errorf("failed to read plaintext data: %d", uint8(s.status))
	}
	if buffer.data_ptr == nil || buffer.data_len == 0 {
		return plaintext[:0], nil
	}
	if int(buffer.data_len) > len(plaintext) {
		plaintext = make([]byte, int(buffer.data_len))
	}
	plaintext = plaintext[:copy(plaintext, unsafe.Slice((*byte)(unsafe.Pointer(buffer.data_ptr)), int(buffer.data_len)))]
	C.fasttls_free_buffer(buffer)
	return plaintext, nil
}

func (s *Session) ReadPlaintextSize(plaintext []byte) (int, error) {
	buffer := C.fasttls_read_plaintext_size((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, C.uint32_t(len(plaintext)))
	if uint8(s.status) != 0 {
		closed := C.fasttls_is_closed((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session)
		if uint8(s.status) != 0 {
			return 0, fmt.Errorf("failed to read plaintext data: %d", uint8(s.status))
		}
		if bool(closed) {
			return 0, ErrClosed
		}
		return 0, fmt.Errorf("failed to read plaintext data: %d", uint8(s.status))
	}
	if buffer.data_ptr == nil || buffer.data_len == 0 {
		return 0, nil
	}
	bufferLen := int(buffer.data_len)
	copy(plaintext, unsafe.Slice((*byte)(unsafe.Pointer(buffer.data_ptr)), bufferLen))
	C.fasttls_free_buffer(buffer)
	return bufferLen, nil
}

func (s *Session) Decrypt(encrypted []byte) ([]byte, error) {
	err := s.ReadTLS(encrypted)
	if err != nil {
		return nil, err
	}
	return s.ReadPlaintext(nil)
}

func (s *Session) SendCloseNotify() error {
	C.fasttls_send_close_notify((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session)
	if uint8(s.status) != 0 {
		return fmt.Errorf("failed to send close notify: %d", uint8(s.status))
	}
	return nil
}

func (s *Session) Free() {
	if s.free.CompareAndSwap(false, true) {
		C.fasttls_free_session(s.session)
	}
}

func (s *Session) clientHandshake(connection io.ReadWriter) error {
	handshake := C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, nil, 0)
	if uint8(s.status) != 0 {
		return fmt.Errorf("failed to initiate client handshake: %d", uint8(s.status))
	}
	encryptedData := make([]byte, 1024)
HANDSHAKE:
	for {
		switch handshake.state {
		case C.FASTTLS_HANDSHAKE_STATE_NEED_READ:
		case C.FASTTLS_HANDSHAKE_STATE_NEED_WRITE, C.FASTTLS_HANDSHAKE_STATE_COMPLETE:
			if handshake.output_data_ptr != nil && handshake.output_data_len > 0 {
				output := unsafe.Slice((*byte)(unsafe.Pointer(handshake.output_data_ptr)), int(handshake.output_data_len))
				_, err := connection.Write(output)
				if err != nil {
					C.fasttls_free_handshake(handshake)
					return fmt.Errorf("failed to write client handshake data: %w", err)
				}
			}
			if handshake.state == C.FASTTLS_HANDSHAKE_STATE_COMPLETE {
				C.fasttls_free_handshake(handshake)
				break HANDSHAKE
			}
		default:
			C.fasttls_free_handshake(handshake)
			return fmt.Errorf("unknown client handshake state: %d", uint8(handshake.state))
		}
		C.fasttls_free_handshake(handshake)
		encryptedBytes, err := connection.Read(encryptedData)
		if err != nil {
			return fmt.Errorf("failed to read client handshake data: %w", err)
		}
		handshake = C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&encryptedData[0])), C.uint32_t(encryptedBytes))
		if uint8(s.status) != 0 {
			return fmt.Errorf("failed to complete client handshake: %d", uint8(s.status))
		}
	}
	s.handshakeState.Store(handshakeStateComplete)
	return nil
}

func (s *Session) serverHandshake(connection io.ReadWriter) error {
	encryptedData := make([]byte, 1024)
HANDSHAKE:
	for {
		encryptedBytes, err := connection.Read(encryptedData)
		if err != nil {
			return fmt.Errorf("failed to read server handshake data: %w", err)
		}
		handshake := C.fasttls_handshake((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.session, (*C.uint8_t)(unsafe.Pointer(&encryptedData[0])), C.uint32_t(encryptedBytes))
		if uint8(s.status) != 0 {
			return fmt.Errorf("failed to complete server handshake: %d", uint8(s.status))
		}
		switch handshake.state {
		case C.FASTTLS_HANDSHAKE_STATE_NEED_READ:
		case C.FASTTLS_HANDSHAKE_STATE_NEED_WRITE, C.FASTTLS_HANDSHAKE_STATE_COMPLETE:
			if handshake.output_data_ptr != nil && handshake.output_data_len > 0 {
				output := unsafe.Slice((*byte)(unsafe.Pointer(handshake.output_data_ptr)), int(handshake.output_data_len))
				_, err = connection.Write(output)
				if err != nil {
					C.fasttls_free_handshake(handshake)
					return fmt.Errorf("failed to write server handshake data: %w", err)
				}
			}
			if handshake.state == C.FASTTLS_HANDSHAKE_STATE_COMPLETE {
				C.fasttls_free_handshake(handshake)
				break HANDSHAKE
			}
		default:
			C.fasttls_free_handshake(handshake)
			return fmt.Errorf("unknown server handshake state: %d", uint8(handshake.state))
		}
		C.fasttls_free_handshake(handshake)
	}
	s.handshakeState.Store(handshakeStateComplete)
	return nil
}
