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

pub(crate) fn convert_ptr_to_vec(ptr: *mut u8, size: u32) -> Option<Vec<u8>> {
    if ptr.is_null() || size == 0 {
        None
    } else {
        Some(unsafe {
            Vec::from(std::slice::from_raw_parts(ptr, size as usize))
        })
    }
}

pub(crate) fn convert_ptr_to_slice<'a>(ptr: *mut u8, size: u32) -> Option<&'a[u8]> {
    if ptr.is_null() || size == 0 {
        None
    } else {
        Some(unsafe {
            std::slice::from_raw_parts(ptr, size as usize)
        })
    }
}