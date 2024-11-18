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
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use regex::Regex;

const BASE_ENV_CACHE: &str = "BARRETENBERG_LIB_DIR";
/// Enable logging.
pub const ENABLE_LOGS: bool = false;

#[macro_export]
macro_rules! log {
    ($($tokens: tt)*) => {
        if $crate::ENABLE_LOGS {
            println!("cargo:warning={}", format!($($tokens)*))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum BuildInfo {
    Debug,
    Release,
    Unknown,
}

impl BuildInfo {
    pub fn from_env_var() -> Self {
        match env::var("PROFILE").as_deref() {
            Ok("release") => BuildInfo::Release,
            Ok("debug") => BuildInfo::Debug,
            _ => BuildInfo::Unknown,
        }
    }

    pub fn cpp_build_type(&self) -> &'static str {
        match self {
            BuildInfo::Release => "RelWithAssert",
            BuildInfo::Debug | BuildInfo::Unknown => "RelWithDebInfo",
        }
    }

    pub fn env_cache_suffix(&self) -> &'static [&'static str] {
        match self {
            BuildInfo::Release => &["_RELEASE"],
            BuildInfo::Debug => &["_DEBUG", ""],
            BuildInfo::Unknown => &[""],
        }
    }
}

fn patch_cmd_base(repo_path: &Path) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_path).arg("apply").args([
        "-q",
        "--ignore-space-change",
        "--ignore-whitespace",
        "--whitespace=nowarn",
    ]);
    cmd
}

fn check_patch(repo_path: &Path, patch: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    patch_cmd_base(repo_path)
        .arg("--check")
        .arg(patch)
        .status()
        .map(|s| s.success())
        .map_err(Into::into)
}

fn apply_patch(repo_path: &Path, patch: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    patch_cmd_base(repo_path)
        .arg(patch)
        .status()
        .map(|s| s.success())
        .map_err(Into::into)
}

fn check_and_apply_patches(
    manifest_dir: &Path,
    repo_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=patches");
    let re = Regex::new(&format!(r"{repo_name}_([0-9]+)\.patch"))?;
    let repo_path = manifest_dir.join(repo_name);
    let mut patches = fs::read_dir(manifest_dir.join("patches"))?
        .inspect(|p| log!("Analyze {p:?}"))
        .filter_map(|p| p.ok())
        .filter_map(|p| match p.file_type() {
            Ok(f) if f.is_file() => Some(p.path()),
            _ => None,
        })
        .filter(|p| re.is_match(p.file_name().and_then(OsStr::to_str).unwrap()))
        .inspect(|p| log!("Selected {}", p.display()))
        .collect::<Vec<_>>();
    patches.sort();
    for patch in patches {
        log!("Check and apply patch: {}", patch.display());
        if check_patch(&repo_path, &patch)? {
            log!("Applying patch: {}", patch.display());
            if !apply_patch(&repo_path, &patch)? {
                log!("Applying patch: {}", patch.display());
            }
        } else {
            log!("Already patched: {}", patch.display());
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up paths
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let lib_path = manifest_dir.join("barretenberg/cpp");
    let assets_path = manifest_dir.join("resources/code");
    let acir_proofs_path = lib_path.join("src/barretenberg/dsl/acir_proofs");

    // Ensure barretenberg submodule is available
    if !lib_path.exists() {
        Command::new("git")
            .args(["submodule", "update", "--init", "--recursive"])
            .status()?;
    }

    // Check barretenberg patches
    check_and_apply_patches(&manifest_dir, "barretenberg")?;

    // Copy files from assets/code to barretenberg/cpp/src/barretenberg/dsl/acir_proofs
    for entry in fs::read_dir(assets_path)? {
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
    let build_info = BuildInfo::from_env_var();

    // Check if we need to rebuild using CMake
    let cmake_build_dir = lib_path.join("build");

    // Ensure the build directory exists and is not empty
    let rebuild_needed = !cmake_build_dir.exists()
        || fs::read_dir(&cmake_build_dir)?.next().is_none()
        || !PathBuf::from(env::var("OUT_DIR")?)
            .join("bindings.rs")
            .exists();

    if rebuild_needed {
        let components = [
            "common",
            "numeric",
            "polynomials",
            "transcript",
            "stdlib_circuit_builders",
            "srs",
            "crypto_keccak",
            "crypto_pedersen_commitment",
            "crypto_pedersen_hash",
            "ecc",
            "plonk",
            "execution_trace",
            "dsl",
        ];

        let lib_dirs = resolve_build_cache_dir(build_info).unwrap_or_else(|| {
            let dst = compile_static_libs(&lib_path, build_info, &components);
            format!("{}/build/lib", dst.display())
        });

        // Link the C++ standard library and custom libraries
        println!("cargo:rustc-link-search=native={lib_dirs}");
        components
            .iter()
            .rev()
            .for_each(|c| println!("cargo:rustc-link-lib=static={c}"));
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

fn resolve_build_cache_dir(build_info: BuildInfo) -> Option<String> {
    build_info
        .env_cache_suffix()
        .iter()
        .map(|s| format!("{BASE_ENV_CACHE}{s}"))
        .map(env::var)
        .filter_map(Result::ok)
        .find(|s| PathBuf::from(s).exists())
}

fn compile_static_libs(lib_path: &PathBuf, build_info: BuildInfo, components: &[&str]) -> PathBuf {
    let mut cfg = cmake::Config::new(lib_path);
    cfg.define("CMAKE_BUILD_TYPE", build_info.cpp_build_type())
        .define("MULTITHREADING", "OFF")
        .very_verbose(true);
    components.iter().for_each(|c| {
        log!("Building {}", c);
        cfg.build_target(c);
    });
    if !cfg!(target_os = "macos") {
        cfg.define("TARGET_ARCH", "x86-64");
    }
    // Build using the cmake crate
    cfg.build()
}

fn generate_bindings(include_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
        // .allowlist_function("acir_verify_proof")
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
