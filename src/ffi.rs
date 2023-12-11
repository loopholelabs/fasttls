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

use rustls::{ServerConfig, ServerConnection};
use crate::{config, HandshakeState};

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
    pub state: HandshakeState,
    pub output_data_ptr: *mut u8,
    pub output_data_len: u32,
}

impl HandshakeResult {
    pub fn boxed_raw(state: HandshakeState, output_data_ptr: *mut u8, output_data_size: u32) -> *mut Self {
        Box::into_raw(Box::new(HandshakeResult {
            state,
            output_data_ptr,
            output_data_len: output_data_size,
        }))
    }
}

fn convert_ptr_to_vec(ptr: *mut u8, size: u32) -> Option<Vec<u8>> {
    if ptr.is_null() || size == 0 {
        None
    } else {
        Some(unsafe {
            Vec::from(std::slice::from_raw_parts(ptr, size as usize))
        })
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server_config(status: *mut Status, cert_data_ptr: *mut u8, cert_data_len: u32, key_data_ptr: *mut u8, key_data_len: u32, client_auth_ca_data_ptr: *mut u8, client_auth_ca_data_len: u32) -> *mut ServerConfig {
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

    let client_auth_ca_data = convert_ptr_to_vec(client_auth_ca_data_ptr, client_auth_ca_data_len);

    match config::get_server_config(&cert_data, &key_data, client_auth_ca_data.as_ref()) {
        Ok(server_config) => {
            unsafe {
                *status = Status::Pass
            };
            Box::into_raw(Box::new(server_config))
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
pub extern "C" fn fasttls_free_server_config(server_config: *mut ServerConfig) {
    if !server_config.is_null() {
        unsafe {
            drop(Box::from_raw(server_config));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server_session(status: *mut Status, server_config: *mut ServerConfig) -> *mut ServerConnection {
    Status::check_not_null(status);

    if server_config.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    match unsafe { crate::server_session(&*server_config) } {
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
pub extern "C" fn fasttls_free_server_session(server_session: *mut ServerConnection) {
    if !server_session.is_null() {
        unsafe {
            drop(Box::from_raw(server_session));
        }
    }
}

#[no_mangle]
pub extern "C" fn fasttls_server_handshake(status: *mut Status, server_session: *mut ServerConnection, input_data_ptr: *mut u8, input_data_len: u32) -> *mut HandshakeResult {
    Status::check_not_null(status);

    if server_session.is_null() {
        unsafe {
            *status = Status::NullPointer;
        }
        return std::ptr::null_mut();
    }

    let input_data = convert_ptr_to_vec(input_data_ptr, input_data_len);

    match unsafe { crate::server_handshake(&mut *server_session, input_data) } {
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
            let boxed_output = std::slice::from_raw_parts_mut((*handshake).output_data_ptr, (*handshake).output_data_len as usize) ;
            let value = boxed_output.as_mut_ptr();
            drop(Box::from_raw(value));
            drop(Box::from_raw(handshake));
        }
    }
}