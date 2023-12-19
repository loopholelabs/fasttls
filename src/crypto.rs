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

use std::error::Error;
use std::mem::size_of;
use rustls::ConnectionTrafficSecrets;
use crate::constants;

#[cfg_attr(target_pointer_width = "32", repr(C, align(4)))]
#[cfg_attr(target_pointer_width = "64", repr(C, align(8)))]
pub(crate) struct Cmsg<const N: usize> {
    pub(crate) hdr: libc::cmsghdr,
    data: [u8; N],
}
impl<const N: usize> Cmsg<N> {
    pub(crate) fn new(level: i32, typ: i32, data: [u8; N]) -> Self {
        Self {
            hdr: libc::cmsghdr {
                #[allow(clippy::unnecessary_cast)]
                cmsg_len: (memoffset::offset_of!(Self, data) + N) as _,
                cmsg_level: level,
                cmsg_type: typ,
            },
            data,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Info {
    pub version: u16,
    pub cipher_type: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12SM4GCM {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_SM4_GCM_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_SM4_GCM_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_SM4_GCM_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12SM4CCM {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_SM4_CCM_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_SM4_CCM_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_SM4_CCM_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESGCM128 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_GCM_128_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_GCM_128_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_GCM_128_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESGCM256 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_GCM_256_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_GCM_256_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_GCM_256_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESCCM128 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_AES_CCM_128_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_AES_CCM_128_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_AES_CCM_128_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12Chacha20Poly1305 {
    pub info: Info,
    pub iv: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE as usize],
    pub key: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE as usize],
    pub salt: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE as usize],
    pub rec_seq: [u8; constants::TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE as usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub enum Secret {
    AESGCM128(TLS12AESGCM128),
    AESGCM256(TLS12AESGCM256),
    AESCCM128(TLS12AESCCM128),
    Chacha20Poly1305(TLS12Chacha20Poly1305),
    SM4GCM(TLS12SM4GCM),
    SM4CCM(TLS12SM4CCM),
}

impl Secret {
    pub(crate) fn as_ptr(&self) -> *const libc::c_void {
        match self {
            Secret::AESGCM128(info) => info as *const _ as *const libc::c_void,
            Secret::AESGCM256(info) => info as *const _ as *const libc::c_void,
            Secret::AESCCM128(info) => info as *const _ as *const libc::c_void,
            Secret::Chacha20Poly1305(info) => info as *const _ as *const libc::c_void,
            Secret::SM4GCM(info) => info as *const _ as *const libc::c_void,
            Secret::SM4CCM(info) => info as *const _ as *const libc::c_void,
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Secret::AESGCM128(_) => size_of::<TLS12AESGCM128>(),
            Secret::AESGCM256(_) => size_of::<TLS12AESGCM256>(),
            Secret::AESCCM128(_) => size_of::<TLS12AESCCM128>(),
            Secret::Chacha20Poly1305(_) => size_of::<TLS12Chacha20Poly1305>(),
            Secret::SM4GCM(_) => size_of::<TLS12SM4GCM>(),
            Secret::SM4CCM(_) => size_of::<TLS12SM4CCM>(),
        }
    }
}

pub(crate) fn convert_to_secret(tls_version: u16, seq: u64, secrets: ConnectionTrafficSecrets) -> Result<Secret, Box<dyn Error>> {
    Ok(match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let mut corrected_iv = [0u8; 8usize];
            for i in 0..8 {
                corrected_iv[i] = iv.as_ref()[i+4];
            }
            let salt = (&iv.as_ref()[..4]).try_into().map_err(|_| "invalid iv length for AES128GCM Salt")?;
            let mut corrected_key = [0u8; 16usize];
            for i in 0..16 {
                corrected_key[i] = key.as_ref()[i];
            }
            Secret::AESGCM128(TLS12AESGCM128 {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_128 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            })
        },
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let mut corrected_iv = [0u8; 8usize];
            for i in 0..8 {
                corrected_iv[i] = iv.as_ref()[i+4];
            }
            let salt = (&iv.as_ref()[..4]).try_into().map_err(|_| "invalid iv length for AES256GCM Salt")?;
            let corrected_key = (&key.as_ref()[..32]).try_into().map_err(|_| "invalid key length for AES256GCM Key")?;
            Secret::AESGCM256(TLS12AESGCM256 {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_256 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            })
        },
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let corrected_iv = (&iv.as_ref()[..12]).try_into().map_err(|_| "invalid iv length for Chacha20Poly1305 IV")?;
            let corrected_key = (&key.as_ref()[..32]).try_into().map_err(|_| "invalid key length for Chacha20Poly1305 Key")?;
            Secret::Chacha20Poly1305(TLS12Chacha20Poly1305 {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: corrected_iv,
                salt: [0; 0],
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            })
        },
        _ => {
            return Err("unsupported cipher suite".into());
        }
    })
}
