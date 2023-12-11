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
pub const TLS_TX: libc::c_int = 1;
pub const TLX_RX: libc::c_int = 2;

// pub const TLS_TX_ZEROCOPY_RO: u32 = 3;
// pub const TLS_RX_EXPECT_NO_PAD: u32 = 4;
pub const TLS_1_2_VERSION_MAJOR: u32 = 3;
pub const TLS_1_2_VERSION_MINOR: u32 = 3;
pub const TLS_1_2_VERSION_NUMBER: u16 = (((TLS_1_2_VERSION_MAJOR & 0xFF) as u16) << 8) | ((TLS_1_2_VERSION_MINOR & 0xFF) as u16);
pub const TLS_1_3_VERSION_MAJOR: u32 = 3;
pub const TLS_1_3_VERSION_MINOR: u32 = 4;
pub const TLS_1_3_VERSION_NUMBER: u16 = (((TLS_1_3_VERSION_MAJOR & 0xFF) as u16) << 8) | ((TLS_1_3_VERSION_MINOR & 0xFF) as u16);
pub const TLS_CIPHER_AES_GCM_128: u32 = 51;
// pub const TLS_CIPHER_AES_GCM_128_IV_SIZE: u32 = 8;
// pub const TLS_CIPHER_AES_GCM_128_KEY_SIZE: u32 = 16;
// pub const TLS_CIPHER_AES_GCM_128_SALT_SIZE: u32 = 4;
// pub const TLS_CIPHER_AES_GCM_128_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE: u32 = 8;
pub const TLS_CIPHER_AES_GCM_256: u32 = 52;
// pub const TLS_CIPHER_AES_GCM_256_IV_SIZE: u32 = 8;
// pub const TLS_CIPHER_AES_GCM_256_KEY_SIZE: u32 = 32;
// pub const TLS_CIPHER_AES_GCM_256_SALT_SIZE: u32 = 4;
// pub const TLS_CIPHER_AES_GCM_256_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE: u32 = 8;
// pub const TLS_CIPHER_AES_CCM_128: u32 = 53;
// pub const TLS_CIPHER_AES_CCM_128_IV_SIZE: u32 = 8;
// pub const TLS_CIPHER_AES_CCM_128_KEY_SIZE: u32 = 16;
// pub const TLS_CIPHER_AES_CCM_128_SALT_SIZE: u32 = 4;
// pub const TLS_CIPHER_AES_CCM_128_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_AES_CCM_128_REC_SEQ_SIZE: u32 = 8;
pub const TLS_CIPHER_CHACHA20_POLY1305: u32 = 54;
// pub const TLS_CIPHER_CHACHA20_POLY1305_IV_SIZE: u32 = 12;
// pub const TLS_CIPHER_CHACHA20_POLY1305_KEY_SIZE: u32 = 32;
// pub const TLS_CIPHER_CHACHA20_POLY1305_SALT_SIZE: u32 = 0;
// pub const TLS_CIPHER_CHACHA20_POLY1305_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_CHACHA20_POLY1305_REC_SEQ_SIZE: u32 = 8;
// pub const TLS_CIPHER_SM4_GCM: u32 = 55;
// pub const TLS_CIPHER_SM4_GCM_IV_SIZE: u32 = 8;
// pub const TLS_CIPHER_SM4_GCM_KEY_SIZE: u32 = 16;
// pub const TLS_CIPHER_SM4_GCM_SALT_SIZE: u32 = 4;
// pub const TLS_CIPHER_SM4_GCM_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_SM4_GCM_REC_SEQ_SIZE: u32 = 8;
// pub const TLS_CIPHER_SM4_CCM: u32 = 56;
// pub const TLS_CIPHER_SM4_CCM_IV_SIZE: u32 = 8;
// pub const TLS_CIPHER_SM4_CCM_KEY_SIZE: u32 = 16;
// pub const TLS_CIPHER_SM4_CCM_SALT_SIZE: u32 = 4;
// pub const TLS_CIPHER_SM4_CCM_TAG_SIZE: u32 = 16;
// pub const TLS_CIPHER_SM4_CCM_REC_SEQ_SIZE: u32 = 8;
// pub const TLS_SET_RECORD_TYPE: u32 = 1;
// pub const TLS_GET_RECORD_TYPE: u32 = 2;
// pub const TLS_CONF_BASE: u32 = 1;
// pub const TLS_CONF_SW: u32 = 2;
// pub const TLS_CONF_HW: u32 = 3;
// pub const TLS_CONF_HW_RECORD: u32 = 4;
pub const SOL_TCP: libc::c_int = 6;
pub const TCP_ULP: libc::c_int = 31;
pub const SOL_TLS: libc::c_int = 282;
