/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use once_cell::sync::OnceCell;

use super::{GpuError, NvidiaEvidence, Result};

static HELPER: &[u8] = include_bytes!(env!("NVML_EXT_PATH"));
static HELPER_PATH: OnceCell<PathBuf> = OnceCell::new();

fn nvml_ext_error(operation: &str, source: io::Error) -> GpuError {
    GpuError::NvmlExtError {
        operation: operation.to_owned(),
        source,
    }
}

fn helper_path() -> io::Result<&'static Path> {
    let path = HELPER_PATH.get_or_try_init(|| {
        let mut file = tempfile::Builder::new()
            .prefix("nvml-ext-")
            .suffix(std::env::consts::EXE_SUFFIX)
            .tempfile_in(std::env::current_dir()?)?;
        file.write_all(HELPER)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            file.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o700))?;
        }

        let (_, path) = file.keep().map_err(|error| error.error)?;
        Ok::<_, io::Error>(path)
    })?;
    Ok(path)
}

pub(super) fn get_nvidia_evidence_via_nvml_ext(nonce: &[u8; 32]) -> Result<Vec<NvidiaEvidence>> {
    let path = helper_path().map_err(|error| nvml_ext_error("save the executable", error))?;
    let mut helper = Command::new(path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| nvml_ext_error("start the executable", error))?;
    let nonce_result = helper.stdin.take().unwrap().write_all(nonce);
    let output = helper
        .wait_with_output()
        .map_err(|error| nvml_ext_error("read the process output", error))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let reason = format!("exited with {}\n{stderr}", output.status);
        return Err(nvml_ext_error(
            "collect GPU evidence",
            io::Error::other(reason.trim_end().to_owned()),
        ));
    }
    nonce_result.map_err(|error| nvml_ext_error("send the nonce", error))?;
    serde_json::from_slice(&output.stdout).map_err(|error| {
        nvml_ext_error(
            "decode GPU evidence",
            io::Error::new(io::ErrorKind::InvalidData, error),
        )
    })
}
