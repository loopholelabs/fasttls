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

use crate::constants;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Info {
    pub version: u16,
    pub cipher_type: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct SM4_GCM {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_SM4_GCM_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_SM4_GCM_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_SM4_GCM_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct SM4_CCM {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_SM4_CCM_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_SM4_CCM_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_SM4_CCM_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct AES_GCM_128 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_GCM_128_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_GCM_128_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_GCM_128_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct AES_GCM_256 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_GCM_256_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_GCM_256_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_GCM_256_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct AES_CCM_128 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_CCM_128_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_CCM_128_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_CCM_128_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
#[allow(non_camel_case_types)]
pub struct Chacha20_Poly1305 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE as usize],
}