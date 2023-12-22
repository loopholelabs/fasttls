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
use crate::{cipher, constants};

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
pub enum Secret {
    #[allow(non_camel_case_types)]
    AES_GCM_128(cipher::AES_GCM_128),
    #[allow(non_camel_case_types)]
    AES_GCM_256(cipher::AES_GCM_256),
    #[allow(non_camel_case_types)]
    Chacha20_Poly1305(cipher::Chacha20_Poly1305),
}

impl Secret {
    pub(crate) fn as_ptr(&self) -> *const libc::c_void {
        match self {
            Secret::AES_GCM_128(info) => info as *const _ as *const libc::c_void,
            Secret::AES_GCM_256(info) => info as *const _ as *const libc::c_void,
            Secret::Chacha20_Poly1305(info) => info as *const _ as *const libc::c_void,
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Secret::AES_GCM_128(_) => size_of::<cipher::AES_GCM_128>(),
            Secret::AES_GCM_256(_) => size_of::<cipher::AES_GCM_256>(),
            Secret::Chacha20_Poly1305(_) => size_of::<cipher::Chacha20_Poly1305>(),
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
            Secret::AES_GCM_128(cipher::AES_GCM_128 {
                info: cipher::Info {
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
            Secret::AES_GCM_256(cipher::AES_GCM_256 {
                info: cipher::Info {
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
            Secret::Chacha20_Poly1305(cipher::Chacha20_Poly1305 {
                info: cipher::Info {
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
