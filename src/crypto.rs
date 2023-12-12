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

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Info {
    pub version: u16,
    pub cipher_type: u16,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Secret {
    pub info: Info,
    pub iv: [u8; 12usize],
    pub key: [u8; 32usize],
    pub salt: [u8; 4usize],
    pub rec_seq: [u8; 8usize],
}

impl Secret {
    pub fn as_ptr(&self) -> *const libc::c_void{
        self as *const _ as *const libc::c_void
    }
    pub fn size(&self) -> u32 {
        size_of::<Secret>() as u32
    }
}

fn offset_iv_12(iv: &rustls::crypto::cipher::Iv) -> [u8; 12usize] {
    [iv.as_ref()[4], iv.as_ref()[5], iv.as_ref()[6], iv.as_ref()[7], iv.as_ref()[8], iv.as_ref()[9], iv.as_ref()[10], iv.as_ref()[11], 0, 0, 0, 0]
}

fn offset_iv_32(key: &rustls::crypto::cipher::AeadKey) -> [u8; 32usize] {
    [key.as_ref()[0], key.as_ref()[1], key.as_ref()[2], key.as_ref()[3], key.as_ref()[4], key.as_ref()[5], key.as_ref()[6], key.as_ref()[7], key.as_ref()[8], key.as_ref()[9], key.as_ref()[10], key.as_ref()[11], key.as_ref()[12], key.as_ref()[13], key.as_ref()[14], key.as_ref()[15], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

pub(crate) fn convert_to_secret(tls_version: u16, seq: u64, secrets: ConnectionTrafficSecrets) -> Result<Secret, Box<dyn Error>> {
    Ok(match secrets {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let mut corrected_iv = [0u8; 12usize];
            for i in 0..8 {
                corrected_iv[i] = iv.as_ref()[i+4];
            }
            let salt = (&iv.as_ref()[..4]).try_into().map_err(|_| "invalid iv length for AES128GCM Salt")?;
            let mut corrected_key = [0u8; 32usize];
            for i in 0..16 {
                corrected_key[i] = key.as_ref()[i];
            }
            Secret {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_128 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            }
        },
        ConnectionTrafficSecrets::Aes256Gcm { key, iv } => {
            let mut corrected_iv = [0u8; 12usize];
            for i in 0..12 {
                corrected_iv[i] = iv.as_ref()[i+4];
            }
            let salt = (&iv.as_ref()[..4]).try_into().map_err(|_| "invalid iv length for AES256GCM Salt")?;
            let corrected_key = (&key.as_ref()[..32]).try_into().map_err(|_| "invalid key length for AES256GCM Key")?;
            Secret {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_AES_GCM_256 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            }
        },
        ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => {
            let corrected_iv = (&iv.as_ref()[..12]).try_into().map_err(|_| "invalid iv length for Chacha20Poly1305 IV")?;
            let salt = [0u8; 4];
            let corrected_key = (&key.as_ref()[..32]).try_into().map_err(|_| "invalid key length for Chacha20Poly1305 Key")?;
            Secret {
                info: Info {
                    version: tls_version,
                    cipher_type: constants::TLS_CIPHER_CHACHA20_POLY1305 as _,
                },
                iv: corrected_iv,
                salt,
                key: corrected_key,
                rec_seq: seq.to_be_bytes(),
            }
        },
        _ => {
            return Err("unsupported cipher suite".into());
        }
    })
}
