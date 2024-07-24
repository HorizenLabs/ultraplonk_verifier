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

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up paths
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let lib_path = manifest_dir.join("barretenberg/cpp");
    let assets_path = manifest_dir.join("resources/code");
    let acir_proofs_path = lib_path.join("src/barretenberg/dsl/acir_proofs");

    // Ensure barretenberg submodule is available
    if !lib_path.exists() {
        Command::new("git")
            .args(&["submodule", "update", "--init", "--recursive"])
            .status()?;
    }

    // Copy files from assets/code to barretenberg/cpp/src/barretenberg/dsl/acir_proofs
    for entry in fs::read_dir(&assets_path)? {
        let entry = entry?;
        let path = entry.path();
        let dest_path = acir_proofs_path.join(path.file_name().unwrap());

        if !dest_path.exists() {
            fs::copy(&path, &dest_path)?;
        }
        println!("cargo:rerun-if-changed={}", path.display());
    }

    // Notify Cargo to rerun if any C++ source files change.
    for entry in fs::read_dir(&lib_path)? {
        let entry = entry?;
        let path = entry.path();
        if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
            if ext == "cpp" || ext == "hpp" {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    // Rerun build script if VERBOSE environment variable changes
    println!("cargo:rerun-if-env-changed=VERBOSE");
    if env::var("VERBOSE").is_ok() {
        std::env::set_var("CARGO_BUILD_RUSTFLAGS", "-vv");
    }

    // Determine the Cargo build type
    let build_type = match env::var("PROFILE").as_deref() {
        Ok("production") | Ok("release") => "RelWithAssert",
        _ => "RelWithDebInfo",
    };

    // Check if we need to rebuild using CMake
    let cmake_build_dir = lib_path.join("build");

    // Ensure the build directory exists and is not empty
    let rebuild_needed = !cmake_build_dir.exists()
        || fs::read_dir(&cmake_build_dir)?.next().is_none()
        || !PathBuf::from(env::var("OUT_DIR")?)
            .join("bindings.rs")
            .exists();

    if rebuild_needed {
        // Build using the cmake crate
        let dst = cmake::Config::new(&lib_path)
            .configure_arg(format!("-DCMAKE_BUILD_TYPE={}", build_type))
            .configure_arg("-DMULTITHREADING=OFF")
            .build_target("bb")
            .very_verbose(true)
            .build();

        // Link the C++ standard library and custom libraries
        println!("cargo:rustc-link-search=native={}/build/lib", dst.display());
        println!("cargo:rustc-link-lib=static=barretenberg");
        println!("cargo:rustc-link-lib=static=env");
        if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
            println!("cargo:rustc-link-lib=c++");
        } else {
            println!("cargo:rustc-link-lib=stdc++");
        }

        // Generate Rust bindings for the C++ headers
        generate_bindings(&lib_path.join("src"))?;
    }

    Ok(())
}

fn generate_bindings(include_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Begin setting up bindgen to generate Rust bindings for C++ code.
    let bindings = bindgen::Builder::default()
        // Provide Clang arguments for C++20 and specify we are working with C++.
        .clang_args(&["-std=c++20", "-xc++"])
        // Add the include path for headers.
        .clang_args([format!("-I{}", include_path.display())])
        // Specify the headers to generate bindings from.
        .header_contents(
            "wrapper.hpp",
            r#"
                #include <barretenberg/dsl/acir_proofs/c_bind.hpp>
                #include <barretenberg/srs/c_bind.hpp>
                #include <barretenberg/dsl/acir_proofs/rust_bind.hpp>
            "#,
        )
        .allowlist_function("acir_new_acir_composer")
        .allowlist_function("acir_delete_acir_composer")
        .allowlist_function("acir_load_verification_key")
        .allowlist_function("acir_verify_proof")
        .allowlist_function("rust_acir_verify_proof")
        .allowlist_function("srs_init_srs")
        // Generate the bindings.
        .generate()
        .expect("Couldn't generate bindings!");

    // Determine the output path for the bindings using the OUT_DIR environment variable.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    // Write the generated bindings to a file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    Ok(())
}
