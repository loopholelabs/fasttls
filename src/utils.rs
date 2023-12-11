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
use std::os::raw::c_uchar;

pub(crate) fn convert_to_4_bytes(slice: &[u8]) -> Result<[c_uchar; 4], Box<dyn Error>> {
    if slice.len() == 4 {
        let array: [u8; 4] = slice.try_into().map_err(|_| -> Box<dyn Error> { "slice has the incorrect length".into() })?;
        return Ok(array.map(|x| x as c_uchar))
    }
    Err("slice is not 4 bytes long".into())
}

pub(crate) fn convert_to_8_bytes(slice: &[u8]) -> Result<[c_uchar; 8], Box<dyn Error>> {
    if slice.len() == 8 {
        let array: [u8; 8] = slice.try_into().map_err(|_| -> Box<dyn Error> { "slice has the incorrect length".into() })?;
        return Ok(array.map(|x| x as c_uchar))
    }
    Err("slice is not 8 bytes long".into())
}

pub(crate) fn convert_to_12_bytes(slice: &[u8]) -> Result<[c_uchar; 12], Box<dyn Error>> {
    if slice.len() == 12 {
        let array: [u8; 12] = slice.try_into().map_err(|_| -> Box<dyn Error> { "slice has the incorrect length".into() })?;
        return Ok(array.map(|x| x as c_uchar))
    }
    Err("slice is not 8 bytes long".into())
}

pub(crate) fn convert_to_16_bytes(slice: &[u8]) -> Result<[c_uchar; 16], Box<dyn Error>> {
    if slice.len() == 16 {
        let array: [u8; 16] = slice.try_into().map_err(|_| -> Box<dyn Error> { "slice has the incorrect length".into() })?;
        return Ok(array.map(|x| x as c_uchar))
    }
    Err("slice is not 16 bytes long".into())
}

pub(crate) fn convert_to_32_bytes(slice: &[u8]) -> Result<[c_uchar; 32], Box<dyn Error>> {
    if slice.len() == 32 {
        let array: [u8; 32] = slice.try_into().map_err(|_| -> Box<dyn Error> { "slice has the incorrect length".into() })?;
        return Ok(array.map(|x| x as c_uchar))
    }
    Err("slice is not 32 bytes long".into())
}