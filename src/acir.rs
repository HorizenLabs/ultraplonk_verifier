// Copyright 2024, The Horizen Foundation
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{ffi::c_void, ffi::CStr, ptr};

// This matches bindgen::Builder output
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

type AcirComposerPtr = *mut c_void;

#[derive(Debug, thiserror::Error)]
pub enum AcirBackendError {
    #[error("Binding call error")]
    BindingCallError(String),
    #[error("Binding call output pointer error")]
    BindingCallPointerError(String),
}

/// Represents an ACIR composer with a pointer to the underlying C structure.
pub struct AcirComposer {
    composer_ptr: AcirComposerPtr,
}

impl AcirComposer {
    pub fn new(size_hint: &u32) -> Result<Self, AcirBackendError> {
        let mut out_ptr = ptr::null_mut();
        unsafe { acir_new_acir_composer(size_hint, &mut out_ptr) };
        if out_ptr.is_null() {
            return Err(AcirBackendError::BindingCallPointerError(
                "Failed to create a new ACIR composer.".to_string(),
            ));
        }

        Ok(Self {
            composer_ptr: out_ptr,
        })
    }

    pub fn load_verification_key(&self, vk: &[u8]) -> Result<(), AcirBackendError> {
        unsafe { acir_load_verification_key(&self.composer_ptr, vk.as_ptr()) };
        Ok(())
    }

    pub fn verify_proof(&self, proof: &[u8]) -> Result<bool, AcirBackendError> {
        let mut result = false;
        // unsafe {
        //     acir_verify_proof(
        //         acir_composer,
        //         serialize_slice(proof).as_slice().as_ptr(),
        //         &mut result,
        //     )
        // };

        let error_msg_ptr = unsafe {
            rust_acir_verify_proof(
                &self.composer_ptr,
                serialize_slice(proof).as_slice().as_ptr(),
                &mut result,
            )
        };
        if !error_msg_ptr.is_null() {
            let error_cstr = unsafe { CStr::from_ptr(error_msg_ptr) };
            let error_str = error_cstr.to_str().expect("Invalid UTF-8 string");
            return Err(AcirBackendError::BindingCallError(format!(
                "C++ error: {}",
                error_str
            )));
        }
        Ok(result)
    }
}

/// Implements the Drop trait for `AcirComposer` to ensure proper resource cleanup.
impl Drop for AcirComposer {
    fn drop(&mut self) {
        unsafe { acir_delete_acir_composer(&self.composer_ptr) };
    }
}

pub fn srs_init(
    points_buf: &[u8],
    num_points: u32,
    g2_point_buf: &[u8],
) -> Result<(), AcirBackendError> {
    unsafe { srs_init_srs(points_buf.as_ptr(), &num_points, g2_point_buf.as_ptr()) };
    Ok(())
}

fn serialize_slice(data: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buffer.extend_from_slice(data);
    buffer
}
