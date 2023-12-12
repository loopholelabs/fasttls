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
use std::marker::PhantomData;
use std::mem::size_of;
use rustls::ConnectionTrafficSecrets;
use crate::constants;

#[repr(C)]
#[derive(Default, Clone)]
pub struct __IncompleteArrayField<T>(PhantomData<T>, [T; 0]);
impl<T> __IncompleteArrayField<T> {
    #[inline]
    pub const fn new() -> Self {
        __IncompleteArrayField(PhantomData, [])
    }
    #[inline]
    pub fn as_ptr(&self) -> *const T {
        self as *const _ as *const T
    }
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut T {
        self as *mut _ as *mut T
    }
    #[inline]
    pub unsafe fn as_slice(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }
    #[inline]
    pub unsafe fn as_mut_slice(&mut self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }
}
impl<T> std::fmt::Debug for __IncompleteArrayField<T> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.write_str("__IncompleteArrayField")
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
    pub iv: [u8; 8usize],
    pub key: [u8; 16usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12SM4CCM {
    pub info: Info,
    pub iv: [u8; 8usize],
    pub key: [u8; 16usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESGCM128 {
    pub info: Info,
    pub iv: [u8; 8usize],
    pub key: [u8; 16usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESGCM256 {
    pub info: Info,
    pub iv: [u8; 8usize],
    pub key: [u8; 32usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12AESCCM128 {
    pub info: Info,
    pub iv: [u8; 8usize],
    pub key: [u8; 16usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12Chacha20Poly1305 {
    pub info: Info,
    pub iv: [u8; 12usize],
    pub key: [u8; 32usize],
    pub salt: __IncompleteArrayField<u8>,
    pub rec_seq: [u8; 8usize],
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
            for i in 0..12 {
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
            let salt = __IncompleteArrayField::new();
            let corrected_key = (&key.as_ref()[..32]).try_into().map_err(|_| "invalid key length for Chacha20Poly1305 Key")?;
            Secret::Chacha20Poly1305(TLS12Chacha20Poly1305 {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            })
        },
        _ => {
            return Err("unsupported cipher suite".into());
        }
    })
}
