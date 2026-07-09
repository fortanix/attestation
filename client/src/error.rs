/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use attestation::nvidia::GpuError;
use attestation::sev::AttestationCoreErr;
use attestation::tdx::AttestationErr as TdxErr;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Error occurred during app cert generation `{0}`")]
    AppCertErr(String),
    #[error("Failed to parse cert `{0}`")]
    CertErr(String),
    #[error("Node Agent Client error `{0}`")]
    NACliErr(String),
    #[error("Local attestation error `{0}`")]
    LocalAttestErr(String),
    #[error("`{0}`")]
    NvidiaAttestationError(
        #[from]
        #[source]
        GpuError,
    ),
    #[error("`{0}`")]
    SevAttestationErr(
        #[from]
        #[source]
        AttestationCoreErr,
    ),
    #[error("`{0}`")]
    TdxAttestationErr(
        #[from]
        #[source]
        TdxErr,
    ),
    #[error("Error generating attestation data `{0}`")]
    AttestErr(String),
    #[error("Error using crypto primitives `{0}`")]
    CryptoErr(String),
    #[error("Error occurred when converting data types `{0}`")]
    ConversionErr(String),
}

pub type Result<T> = std::result::Result<T, Error>;
