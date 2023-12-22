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

use crate::{config, constants, crypto, handshake, Server, session, utils};
use rustls::{internal::msgs::{enums::AlertLevel, message::Message}, AlertDescription};

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

// #[no_mangle]
// pub extern "C" fn fasttls_client(status: *mut Status, cert_data_ptr: *mut u8, cert_data_len: u32, key_data_ptr: *mut u8, key_data_len: u32, client_auth_ca_data_ptr: *mut u8, client_auth_ca_data_len: u32) -> *mut Client {
//     Status::check_not_null(status);
//
//     if cert_data_ptr.is_null() || cert_data_len == 0 {
//         unsafe {
//             *status = Status::NullPointer;
//         }
//         return std::ptr::null_mut();
//     }
//
//     if key_data_ptr.is_null() || key_data_len == 0 {
//         unsafe {
//             *status = Status::NullPointer;
//         }
//         return std::ptr::null_mut();
//     }
//
//     let cert_data = Vec::from(unsafe {
//         std::slice::from_raw_parts(cert_data_ptr, cert_data_len as usize)
//     });
//
//     let key_data = Vec::from(unsafe {
//         std::slice::from_raw_parts(key_data_ptr, key_data_len as usize)
//     });
//
//     let client_auth_ca_data = utils::convert_ptr_to_vec(client_auth_ca_data_ptr, client_auth_ca_data_len);
//
//     match config::get_server_config(&cert_data, &key_data, client_auth_ca_data.as_ref()) {
//         Ok(server_config) => {
//             unsafe {
//                 *status = Status::Pass
//             };
//             Box::into_raw(Box::new(Server::new(server_config)))
//         }
//         Err(_) => {
//             unsafe {
//                 *status = Status::Fail;
//             }
//             std::ptr::null_mut()
//         }
//     }
// }

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
pub extern "C" fn fasttls_free_server_session(server_session: *mut session::Session) {
    if !server_session.is_null() {
        unsafe {
            drop(Box::from_raw(server_session));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server_handshake(status: *mut Status, server_session: *mut session::Session, input_data_ptr: *mut u8, input_data_len: u32) -> *mut HandshakeResult {
    Status::check_not_null(status);

    if server_session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let input_data = utils::convert_ptr_to_slice(input_data_ptr, input_data_len);

    match unsafe { (&mut *server_session).handshake(input_data) } {
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
pub extern "C" fn fasttls_server_secrets(status: *mut Status, server_session: *mut session::Session) -> *mut handshake::Secrets {
    Status::check_not_null(status);

    if server_session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let server_session = unsafe { Box::from_raw(server_session) };

    match server_session.secrets() {
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
pub extern "C" fn fasttls_server_read_plaintext(status: *mut Status, server_session: *mut session::Session) -> *mut Buffer {
    Status::check_not_null(status);

    if server_session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    match unsafe { (&mut *server_session).read_plaintext() } {
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

#[no_mangle]
pub extern "C" fn fasttls_send_close_notify(status: *mut Status, fd: i32) {
    let mut data = vec![];
    Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify)
        .payload
        .encode(&mut data);

    let mut cmsg = crypto::Cmsg::new(constants::SOL_TLS, constants::TLS_SET_RECORD_TYPE as i32, [constants::TLS_RECORD_ALERT]);

    let msg = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: &mut libc::iovec {
            iov_base: data.as_mut_ptr() as _,
            iov_len: data.len(),
        },
        msg_iovlen: 1,
        msg_control: &mut cmsg as *mut _ as *mut _,
        msg_controllen: cmsg.hdr.cmsg_len,
        msg_flags: 0,
    };

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret < 0 {
        unsafe {
            *status = Status::Fail;
        }
    } else {
        unsafe {
            *status = Status::Pass;
        }
    }
}