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

package client

/*
#cgo LDFLAGS: ./target/release/libfasttls.a -ldl
#include "../../fasttls.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"github.com/loopholelabs/fasttls/pkg/session"
	"sync/atomic"
	"unsafe"
)

var (
	ErrFreed = errors.New("client has been freed")
)

type Client struct {
	free   atomic.Bool
	status C.fasttls_status_t
	client *C.fasttls_client_t
}

func New(caCert []byte, clientAuthCert []byte, clientAuthKey []byte) (*Client, error) {
	client := new(Client)

	var caDataPtr *C.uint8_t = nil
	var caDataLen C.uint32_t = 0

	if caCert != nil {
		caDataPtr = (*C.uint8_t)(unsafe.Pointer(&caCert[0]))
		caDataLen = C.uint32_t(len(caCert))
	}

	var clientAuthCertDataPtr *C.uint8_t = nil
	var clientAuthCertDataLen C.uint32_t = 0

	var clientAuthKeyDataPtr *C.uint8_t = nil
	var clientAuthKeyDataLen C.uint32_t = 0

	if clientAuthCert != nil && clientAuthKey != nil {
		clientAuthCertDataPtr = (*C.uint8_t)(unsafe.Pointer(&clientAuthCert[0]))
		clientAuthCertDataLen = C.uint32_t(len(clientAuthCert))

		clientAuthKeyDataPtr = (*C.uint8_t)(unsafe.Pointer(&clientAuthKey[0]))
		clientAuthKeyDataLen = C.uint32_t(len(clientAuthKey))
	}

	client.client = C.fasttls_client((*C.fasttls_status_t)(unsafe.Pointer(&client.status)), caDataPtr, caDataLen, clientAuthCertDataPtr, clientAuthCertDataLen, clientAuthKeyDataPtr, clientAuthKeyDataLen)

	if uint8(client.status) != 0 {
		return nil, fmt.Errorf("failed to create client: %d", uint8(client.status))
	}

	return client, nil
}

func (c *Client) Session(serverName string) (*session.Session, error) {
	if c.free.Load() {
		return nil, ErrFreed
	}
	s := C.CString(serverName)
	sess := C.fasttls_client_session((*C.fasttls_status_t)(unsafe.Pointer(&c.status)), c.client, (*C.int8_t)(unsafe.Pointer(s)))
	if uint8(c.status) != 0 {
		return nil, fmt.Errorf("failed to create client session: %d", uint8(c.status))
	}
	return session.New(unsafe.Pointer(sess), session.KindClient)
}

func (c *Client) Free() {
	if c.free.CompareAndSwap(false, true) {
		C.fasttls_free_client(c.client)
	}
}
