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

use crate::{
    acir_delete_acir_composer, acir_load_verification_key, acir_new_acir_composer,
    /*acir_verify_proof,*/ rust_acir_verify_proof, serialize_slice, srs_init_srs,
    BackendError,
};

pub type AcirComposerPtr = *mut c_void;

/// Creates a new ACIR composer.
///
/// This function initializes a new ACIR composer with a hint for its size.
/// The size hint is used to optimize internal allocations.
///
/// # Arguments
///
/// * `size_hint` - A hint for the size of the composer.
///
/// # Returns
///
/// A result containing the pointer to the newly created ACIR composer if successful,
/// or a `BackendError` if an error occurs during creation.
///
/// # Errors
///
/// Returns `BackendError::BindingCallPointerError` if the ACIR composer could not be created.
pub fn new_acir_composer(size_hint: &u32) -> Result<AcirComposerPtr, BackendError> {
    let mut out_ptr = ptr::null_mut();
    unsafe { acir_new_acir_composer(size_hint, &mut out_ptr) };
    if out_ptr.is_null() {
        return Err(BackendError::BindingCallPointerError(
            "Failed to create a new ACIR composer.".to_string(),
        ));
    }
    Ok(out_ptr)
}

/// Initializes the SRS (Structured Reference String) for the ACIR system.
///
/// This function sets up the SRS needed for the ACIR system by providing the necessary points.
///
/// # Arguments
///
/// * `points_buf` - A byte slice containing the points for the SRS.
/// * `num_points` - The number of points in `points_buf`.
/// * `g2_point_buf` - A byte slice containing the G2 point for the SRS.
///
/// # Returns
///
/// A result indicating success if the SRS was successfully initialized, or a `BackendError` otherwise.
pub fn srs_init(
    points_buf: &[u8],
    num_points: u32,
    g2_point_buf: &[u8],
) -> Result<(), BackendError> {
    unsafe { srs_init_srs(points_buf.as_ptr(), &num_points, g2_point_buf.as_ptr()) };
    Ok(())
}

/// Loads the verification key into the ACIR composer.
///
/// This function is used to load a verification key into an existing ACIR composer.
///
/// # Arguments
///
/// * `acir_composer` - A pointer to the ACIR composer.
/// * `verification_key` - A byte slice containing the verification key to be loaded.
///
/// # Returns
///
/// A result indicating success if the verification key was successfully loaded, or a `BackendError` otherwise.
pub fn load_verification_key(
    acir_composer: &AcirComposerPtr,
    verification_key: &[u8],
) -> Result<(), BackendError> {
    unsafe { acir_load_verification_key(acir_composer, verification_key.as_ptr()) };
    Ok(())
}

/// Verifies a proof using the ACIR composer.
///
/// This function takes a proof and uses the ACIR composer to verify it.
///
/// # Arguments
///
/// * `acir_composer` - A pointer to the ACIR composer.
/// * `proof` - A byte slice containing the proof to be verified.
///
/// # Returns
///
/// A result containing a boolean indicating the outcome of the verification (`true` if the proof is valid, `false` otherwise),
/// or a `BackendError` if an error occurs during verification.
pub fn verify_proof(acir_composer: &AcirComposerPtr, proof: &[u8]) -> Result<bool, BackendError> {
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
            acir_composer,
            serialize_slice(proof).as_slice().as_ptr(),
            &mut result,
        )
    };
    if !error_msg_ptr.is_null() {
        let error_cstr = unsafe { CStr::from_ptr(error_msg_ptr) };
        let error_str = error_cstr.to_str().expect("Invalid UTF-8 string");
        return Err(BackendError::BindingCallError(format!(
            "C++ error: {}",
            error_str
        )));
    }

    Ok(result)
}

/// Deletes the ACIR composer.
///
/// This function safely deletes the ACIR composer and frees up the resources it was using.
///
/// # Arguments
///
/// * `acir_composer` - The ACIR composer to be deleted.
///
/// # Returns
///
/// A result indicating success if the ACIR composer was successfully deleted, or a `BackendError` otherwise.
pub fn delete(acir_composer: AcirComposerPtr) -> Result<(), BackendError> {
    unsafe { acir_delete_acir_composer(&acir_composer) };
    Ok(())
}
