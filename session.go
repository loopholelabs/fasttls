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
import "sync/atomic"

type kind uint8

const (
	kindServer kind = iota
	kindClient
)

type Session struct {
	free    atomic.Bool
	kind    kind
	session *C.fasttls_session_t
}

func newSession(session *C.fasttls_session_t, kind kind) (*Session, error) {
	return &Session{
		session: session,
		kind:    kind,
	}, nil
}

func (s *Session) Free() {
	if s.free.CompareAndSwap(false, true) {
		C.fasttls_free_session(s.session)
	}
}
