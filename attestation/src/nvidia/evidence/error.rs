/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use nvml::error::NvmlError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GpuError {
    #[error("Gpu attestation cert failure: `{0}`")]
    CertError(NvmlError),
    #[error("Gpu device error: `{0}`")]
    DeviceError(NvmlError),
    #[error("GPU initialization error: `{0}`")]
    InitError(NvmlError),
    #[error("Gpu attestation report failure: `{0}`")]
    ReportError(NvmlError),
}

pub type Result<T> = std::result::Result<T, GpuError>;
