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

use std::mem::size_of;
use std::error::Error;
use std::marker::PhantomData;
use std::os::raw::c_uchar;
use std::os::raw::c_ushort;
use rustls::ConnectionTrafficSecrets;
use crate::{constants, utils};

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
pub struct TLSCryptoInfo {
    pub version: c_ushort,
    pub cipher_type: c_ushort,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoSM4GCM {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 8usize],
    pub key: [c_uchar; 16usize],
    pub salt: [c_uchar; 4usize],
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoSM4CCM {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 8usize],
    pub key: [c_uchar; 16usize],
    pub salt: [c_uchar; 4usize],
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoAESGCM128 {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 8usize],
    pub key: [c_uchar; 16usize],
    pub salt: [c_uchar; 4usize],
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoAESGCM256 {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 8usize],
    pub key: [c_uchar; 32usize],
    pub salt: [c_uchar; 4usize],
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoAESCCM128 {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 8usize],
    pub key: [c_uchar; 16usize],
    pub salt: [c_uchar; 4usize],
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct TLS12CryptoInfoChacha20Poly1305 {
    pub info: TLSCryptoInfo,
    pub iv: [c_uchar; 12usize],
    pub key: [c_uchar; 32usize],
    pub salt: __IncompleteArrayField<c_uchar>,
    pub rec_seq: [c_uchar; 8usize],
}

#[repr(C)]
#[derive(Debug, Clone)]
pub enum Info {
    AESGCM128(TLS12CryptoInfoAESGCM128),
    AESGCM256(TLS12CryptoInfoAESGCM256),
    AESCCM128(TLS12CryptoInfoAESCCM128),
    Chacha20Poly1305(TLS12CryptoInfoChacha20Poly1305),
    SM4GCM(TLS12CryptoInfoSM4GCM),
    SM4CCM(TLS12CryptoInfoSM4CCM),
}

impl Info {
    pub(crate) fn as_ptr(&self) -> *const libc::c_void {
        match self {
            Info::AESGCM128(info) => info as *const _ as *const libc::c_void,
            Info::AESGCM256(info) => info as *const _ as *const libc::c_void,
            Info::AESCCM128(info) => info as *const _ as *const libc::c_void,
            Info::Chacha20Poly1305(info) => info as *const _ as *const libc::c_void,
            Info::SM4GCM(info) => info as *const _ as *const libc::c_void,
            Info::SM4CCM(info) => info as *const _ as *const libc::c_void,
        }
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Info::AESGCM128(_) => size_of::<TLS12CryptoInfoAESGCM128>(),
            Info::AESGCM256(_) => size_of::<TLS12CryptoInfoAESGCM256>(),
            Info::AESCCM128(_) => size_of::<TLS12CryptoInfoAESCCM128>(),
            Info::Chacha20Poly1305(_) => size_of::<TLS12CryptoInfoChacha20Poly1305>(),
            Info::SM4GCM(_) => size_of::<TLS12CryptoInfoSM4GCM>(),
            Info::SM4CCM(_) => size_of::<TLS12CryptoInfoSM4CCM>(),
        }
    }
}

pub(crate) fn convert_to_info(tls_version: u16, seq: u64, secrets: ConnectionTrafficSecrets) -> Result<Info, Box<dyn Error>> {
    let info = match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            Info::AESGCM128(TLS12CryptoInfoAESGCM128 {
                info: TLSCryptoInfo {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_128 as _,
                },
                iv: utils::convert_to_8_bytes(&iv.as_ref()[4..])?,
                key: utils::convert_to_16_bytes(&key.as_ref()[..16])?,
                salt: utils::convert_to_4_bytes(&iv.as_ref()[..4])?,
                rec_seq: seq.to_be_bytes(),
            })
        },
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            Info::AESGCM256(TLS12CryptoInfoAESGCM256 {
                info: TLSCryptoInfo {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_256 as _,
                },
                iv: utils::convert_to_8_bytes(&iv.as_ref()[4..])?,
                key: utils::convert_to_32_bytes(&key.as_ref()[..32])?,
                salt: utils::convert_to_4_bytes(&iv.as_ref()[..4])?,
                rec_seq: seq.to_be_bytes(),
            })
        },
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            Info::Chacha20Poly1305(TLS12CryptoInfoChacha20Poly1305 {
                info: TLSCryptoInfo {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: utils::convert_to_12_bytes(&iv.as_ref()[..12])?,
                key: utils::convert_to_32_bytes(&key.as_ref()[..32])?,
                salt: __IncompleteArrayField::new(),
                rec_seq: seq.to_be_bytes(),
            })
        },
        _ => {
            return Err("unsupported cipher suite".into());
        }
    };

    Ok(info)
}
