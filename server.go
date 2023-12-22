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
	"errors"
	"fmt"
	"sync/atomic"
	"unsafe"
)

var (
	ErrServerFreed = errors.New("server has been freed")
)

type Server struct {
	free   atomic.Bool
	status C.fasttls_status_t
	server *C.fasttls_server_t
}

func NewServer(cert []byte, key []byte, clientCaCert []byte) (*Server, error) {
	server := new(Server)

	var clientCaCertPtr *C.uint8_t = nil
	var clientCaCertLen C.uint32_t = 0

	if clientCaCert != nil {
		clientCaCertPtr = (*C.uint8_t)(unsafe.Pointer(&clientCaCert[0]))
		clientCaCertLen = C.uint32_t(len(clientCaCert))
	}

	server.server = C.fasttls_server((*C.fasttls_status_t)(unsafe.Pointer(&server.status)), (*C.uint8_t)(unsafe.Pointer(&cert[0])), C.uint32_t(len(cert)), (*C.uint8_t)(unsafe.Pointer(&key[0])), C.uint32_t(len(key)), clientCaCertPtr, clientCaCertLen)

	if uint8(server.status) != 0 {
		return nil, fmt.Errorf("failed to create server: %d", uint8(server.status))
	}

	return server, nil
}

func (s *Server) Session() (*Session, error) {
	if s.free.Load() {
		return nil, ErrServerFreed
	}
	return newSession(C.fasttls_server_session((*C.fasttls_status_t)(unsafe.Pointer(&s.status)), s.server), kindServer)
}

func (s *Server) Free() {
	if s.free.CompareAndSwap(false, true) {
		C.fasttls_free_server(s.server)
	}
}
