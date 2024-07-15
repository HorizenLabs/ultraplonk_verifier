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
use std::process::Command;
use std::path::{PathBuf, Path};

fn main() {
    // Notify Cargo to rerun this build script if `build.rs` changes.
    println!("cargo:rerun-if-changed=build.rs");

    let lib_path = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("barretenberg/cpp");

    // Notify Cargo to rerun if any C++ source files change.
    for entry in fs::read_dir(&lib_path).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("cpp")
            || path.extension().and_then(|s| s.to_str()) == Some("hpp")
        {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    println!("cargo:rerun-if-env-changed=VERBOSE");
    if env::var("VERBOSE").is_ok() {
        std::env::set_var("CARGO_BUILD_RUSTFLAGS", "-vv");
    }

    // Determine the Cargo build type
    let build_type = match env::var("PROFILE").as_deref() {
        Ok("release") => "Release",
        _ => "Debug",
    };

    // Build using the cmake crate. native-lib is the name of the CMake project.
    let dst = cmake::Config::new(&lib_path)
        .define("CMAKE_BUILD_TYPE", build_type)
        .define("CMAKE_BUILD_PARALLEL_LEVEL", num_cpus::get().to_string())
        .build_target("bb")
        .very_verbose(true)
        .build();

    println!("cargo:rustc-link-search=native={}/build/lib", dst.display());
    println!("cargo:rustc-link-lib=static=barretenberg");
    println!("cargo:rustc-link-lib=static=env");

    // Link the C++ standard library.
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") {
        println!("cargo:rustc-link-lib=c++");
    } else {
        println!("cargo:rustc-link-lib=stdc++");
    }

    // Generate Rust bindings for the C++ headers
    generate_bindings(&lib_path.join("src"));
}

fn generate_bindings(include_path: &PathBuf) {
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
            "#,
        )
        .allowlist_function("acir_new_acir_composer")
        .allowlist_function("acir_delete_acir_composer")
        .allowlist_function("acir_load_verification_key")
        .allowlist_function("acir_verify_proof")
        .allowlist_function("srs_init_srs")
        // Generate the bindings.
        .generate()
        .expect("Couldn't generate bindings!");

    // Determine the output path for the bindings using the OUT_DIR environment variable.
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // Write the generated bindings to a file.
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
