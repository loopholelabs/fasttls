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

#![allow(clippy::not_unsafe_ptr_arg_deref)]

use std::ffi::CStr;
use crate::{Client, config, constants, handshake, Server, session, utils};

#[repr(u8)]
#[derive(Debug, Clone)]
pub enum Status {
    Pass,
    Fail,
    NullPointer,
}
impl Status {
    pub fn check_not_null(status: *mut Status) {
        if status.is_null() {
            panic!("status pointer is null");
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HandshakeResult {
    pub state: handshake::State,
    pub output_data_ptr: *mut u8,
    pub output_data_len: u32,
}
impl HandshakeResult {
    pub fn boxed_raw(state: handshake::State, output_data_ptr: *mut u8, output_data_len: u32) -> *mut Self {
        Box::into_raw(Box::new(HandshakeResult {
            state,
            output_data_ptr,
            output_data_len,
        }))
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Buffer {
    pub data_ptr: *mut u8,
    pub data_len: u32,
}
impl Buffer {
    pub fn boxed_raw(data_ptr: *mut u8, data_len: u32) -> *mut Self {
        Box::into_raw(Box::new(Buffer {
            data_ptr,
            data_len,
        }))
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server(status: *mut Status, cert_data_ptr: *mut u8, cert_data_len: u32, key_data_ptr: *mut u8, key_data_len: u32, client_auth_ca_data_ptr: *mut u8, client_auth_ca_data_len: u32) -> *mut Server {
    Status::check_not_null(status);

    if cert_data_ptr.is_null() || cert_data_len == 0 {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    if key_data_ptr.is_null() || key_data_len == 0 {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let cert_data = Vec::from(unsafe {
        std::slice::from_raw_parts(cert_data_ptr, cert_data_len as usize)
    });

    let key_data = Vec::from(unsafe {
        std::slice::from_raw_parts(key_data_ptr, key_data_len as usize)
    });

    let client_auth_ca_data = utils::convert_ptr_to_vec(client_auth_ca_data_ptr, client_auth_ca_data_len);

    match config::get_server_config(&cert_data, &key_data, client_auth_ca_data.as_ref()) {
        Ok(server_config) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(Server::new(server_config)))
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_server(server: *mut Server) {
    if !server.is_null() {
        unsafe {
            drop(Box::from_raw(server));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_client(status: *mut Status, ca_data_ptr: *mut u8, ca_data_len: u32, client_auth_cert_data_ptr: *mut u8, client_auth_cert_data_len: u32, client_auth_key_data_ptr: *mut u8, client_auth_key_data_len: u32) -> *mut Client {
    Status::check_not_null(status);

    let ca_data = utils::convert_ptr_to_vec(ca_data_ptr, ca_data_len);

    let client_auth_data = if client_auth_cert_data_ptr.is_null() || client_auth_cert_data_len == 0 || client_auth_key_data_ptr.is_null() || client_auth_key_data_len == 0 {
        None
    } else {
        let cert_data = unsafe {
            Vec::from(std::slice::from_raw_parts(client_auth_cert_data_ptr, client_auth_cert_data_len as usize))
        };
        let key_data = unsafe {
            Vec::from(std::slice::from_raw_parts(client_auth_key_data_ptr, client_auth_key_data_len as usize))
        };
        Some((cert_data, key_data))
    };

    match config::get_client_config(ca_data.as_ref(), client_auth_data.as_ref()) {
        Ok(client_config) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(Client::new(client_config)))
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_client(client: *mut Client) {
    if !client.is_null() {
        unsafe {
            drop(Box::from_raw(client));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server_session(status: *mut Status, server: *mut Server) -> *mut session::Session {
    Status::check_not_null(status);

    if server.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    match unsafe { (&*server).session() } {
        Ok(server_session) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(server_session))
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_client_session(status: *mut Status, client: *mut Client, server_name: *const i8) -> *mut session::Session {
    Status::check_not_null(status);

    if client.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    if server_name.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let server_name = match unsafe { CStr::from_ptr(server_name) }.to_str() {
        Ok(server_name) => server_name,
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            return std::ptr::null_mut();
        }
    };

    match unsafe { (&*client).session(server_name) } {
        Ok(client_session) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(client_session))
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_session(session: *mut session::Session) {
    if !session.is_null() {
        unsafe {
            drop(Box::from_raw(session));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_is_handshaking(status: *mut Status, session: *mut session::Session) -> bool {
    Status::check_not_null(status);
    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return false;
    }
    unsafe {
        *status = Status::Pass;
        (&mut *session).is_handshaking()
    }
}

#[no_mangle]
pub extern "C" fn fasttls_is_closed(status: *mut Status, session: *mut session::Session) -> bool {
    Status::check_not_null(status);
    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return false;
    }
    unsafe {
        *status = Status::Pass;
        (&mut *session).is_closed()
    }
}

#[no_mangle]
pub extern "C" fn fasttls_wants_read(status: *mut Status, session: *mut session::Session) -> bool {
    Status::check_not_null(status);
    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return false;
    }
    unsafe {
        *status = Status::Pass;
        (&mut *session).wants_read()
    }
}

#[no_mangle]
pub extern "C" fn fasttls_wants_write(status: *mut Status, session: *mut session::Session) -> bool {
    Status::check_not_null(status);
    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return false;
    }
    unsafe {
        *status = Status::Pass;
        (&mut *session).wants_write()
    }
}

#[no_mangle]
pub extern "C" fn fasttls_handshake(status: *mut Status, session: *mut session::Session, input_data_ptr: *mut u8, input_data_len: u32) -> *mut HandshakeResult {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let input_data = utils::convert_ptr_to_slice(input_data_ptr, input_data_len);

    match unsafe { (&mut *session).handshake(input_data) } {
        Ok(handshake_result) => {
            unsafe {
                *status = Status::Pass
            };
            match handshake_result.output {
                Some(output) => {
                    let mut boxed_output = output.into_boxed_slice();
                    let handshake_result = HandshakeResult::boxed_raw(handshake_result.state, boxed_output.as_mut_ptr(), boxed_output.len() as u32);
                    std::mem::forget(boxed_output);
                    handshake_result
                }
                None => {
                    HandshakeResult::boxed_raw(handshake_result.state, std::ptr::null_mut(), 0)
                }
            }
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_handshake(handshake: *mut HandshakeResult) {
    if !handshake.is_null() {
        unsafe {
            if !(*handshake).output_data_ptr.is_null() && (*handshake).output_data_len > 0 {
                let boxed_output = std::slice::from_raw_parts_mut((*handshake).output_data_ptr, (*handshake).output_data_len as usize) ;
                let value = boxed_output.as_mut_ptr();
                drop(Box::from_raw(value));
            }
            drop(Box::from_raw(handshake));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_secrets(status: *mut Status, session: *mut session::Session) -> *mut handshake::Secrets {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let session = unsafe { Box::from_raw(session) };

    match session.secrets() {
        Ok(handshake_secrets) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(handshake_secrets))
        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_secrets(handshake_secrets: *mut handshake::Secrets) {
    if !handshake_secrets.is_null() {
        unsafe {
            drop(Box::from_raw(handshake_secrets));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_read_tls(status: *mut Status, session: *mut session::Session, data_ptr: *mut u8, data_len: u32) {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return;
    }

    if data_ptr.is_null() || data_len == 0 {
        unsafe {
            *status = Status::NullPointer;
        }
        return;
    }

    let data = unsafe {
        std::slice::from_raw_parts(data_ptr, data_len as usize)
    };

    match unsafe { (&mut *session).read_tls(data) } {
        Ok(_) => {
            unsafe {
                *status = Status::Pass
            };

        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_write_plaintext(status: *mut Status, session: *mut session::Session, data_ptr: *mut u8, data_len: u32) {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return;
    }

    if data_ptr.is_null() || data_len == 0 {
        unsafe {
            *status = Status::NullPointer;
        }
        return;
    }

    let data = unsafe {
        std::slice::from_raw_parts(data_ptr, data_len as usize)
    };

    match unsafe { (&mut *session).write_plaintext(data) } {
        Ok(_) => {
            unsafe {
                *status = Status::Pass
            };

        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_read_plaintext(status: *mut Status, session: *mut session::Session) -> *mut Buffer {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    match unsafe { (&mut *session).read_plaintext() } {
        Ok(data) => {
            unsafe {
                *status = Status::Pass
            };
            if data.len() > 0 {
                let mut boxed_data = Box::new(data);
                let buffer = Buffer::boxed_raw(boxed_data.as_mut_ptr(), boxed_data.len() as u32);
                std::mem::forget(boxed_data);
                return buffer;
            }
            Buffer::boxed_raw(std::ptr::null_mut(), 0)

        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_write_tls(status: *mut Status, session: *mut session::Session) -> *mut Buffer {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    match unsafe { (&mut *session).write_tls() } {
        Ok(mut data) => {
            unsafe {
                *status = Status::Pass
            };
            if data.len() > 0 {
                let buffer = Buffer::boxed_raw(data.as_mut_ptr(), data.len() as u32);
                std::mem::forget(data);
                return buffer;
            }
            Buffer::boxed_raw(std::ptr::null_mut(), 0)

        }
        Err(_) => {
            unsafe {
                *status = Status::Fail;
            }
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_free_buffer(buffer: *mut Buffer) {
    if !buffer.is_null() {
        unsafe {
            if !(*buffer).data_ptr.is_null() && (*buffer).data_len > 0 {
                let boxed_output = std::slice::from_raw_parts_mut((*buffer).data_ptr, (*buffer).data_len as usize) ;
                let value = boxed_output.as_mut_ptr();
                drop(Box::from_raw(value));
            }
            drop(Box::from_raw(buffer));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_send_close_notify(status: *mut Status, session: *mut session::Session) {
    Status::check_not_null(status);

    if session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return;
    }

    unsafe {
        *status = Status::Pass;
        (&mut *session).send_close_notify();
    }
}

#[no_mangle]
pub extern "C" fn fasttls_setup_ulp(status: *mut Status, fd: i32) {
    Status::check_not_null(status);
    unsafe {
        if libc::setsockopt(fd, constants::SOL_TCP, constants::TCP_ULP, "tls".as_ptr() as *const libc::c_void, 3) < 0 {
            *status = Status::Fail;
        } else {
            *status = Status::Pass;
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_setup_ktls(status: *mut Status, fd: i32, handshake_secrets: *mut handshake::Secrets) {
    Status::check_not_null(status);

    let boxed_handshake_secrets = unsafe { Box::from_raw(handshake_secrets) };
    let mut ret = unsafe { libc::setsockopt(fd, constants::SOL_TLS, constants::TLS_TX, boxed_handshake_secrets.tx.as_ptr(), boxed_handshake_secrets.tx.size() as _) };
    if ret < 0 {
        unsafe {
            *status = Status::Fail;
        }
        return
    }

    ret = unsafe { libc::setsockopt(fd, constants::SOL_TLS, constants::TLS_RX, boxed_handshake_secrets.rx.as_ptr(), boxed_handshake_secrets.rx.size() as _) };
    if ret < 0 {
        unsafe {
            *status = Status::Fail;
        }
    } else {
        unsafe {
            *status = Status::Pass;
        }
    }

    drop(boxed_handshake_secrets);
}