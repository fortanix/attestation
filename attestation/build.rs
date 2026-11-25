/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "nvml-ext")]
    build_nvml_ext();
}

#[cfg(feature = "nvml-ext")]
fn build_nvml_ext() {
    use std::{env, path::PathBuf, process::Command};

    let target = env::var("TARGET").unwrap();
    let profile = env::var("PROFILE").unwrap();
    let helper_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap()).join("../nvml-ext");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let target_dir = out_dir.join("nvml-ext-build");

    for path in [
        "../Cargo.toml",
        "../Cargo.lock",
        "../nvml-ext/.cargo/config.toml",
        "../nvml-ext/Cargo.toml",
        "../nvml-ext/src",
        "Cargo.toml",
        "src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    // Use a separate target directory and select only nvml-ext. Its attestation dependency
    // enables nvidia-evidence, so the inner build collects evidence directly without recursing.
    let mut cargo = Command::new(env::var_os("CARGO").unwrap());
    cargo
        .current_dir(helper_dir)
        .args(["build", "--locked"])
        .args(["--bin", "nvml-ext", "--target", &target, "--target-dir"])
        .arg(&target_dir);
    if profile == "release" {
        cargo.arg("--release");
    }

    if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("musl") {
        // Cargo passes RUSTFLAGS to build scripts in encoded form.
        cargo
            .env_remove("RUSTFLAGS")
            .env_remove("CARGO_ENCODED_RUSTFLAGS");
    }

    let status = cargo.status().expect("failed to start the nvml-ext build");
    assert!(status.success(), "nvml-ext build failed with {status}");

    let helper = target_dir.join(target).join(profile).join("nvml-ext");
    println!("cargo:rustc-env=NVML_EXT_PATH={}", helper.display());
}
