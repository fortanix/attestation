/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::mem::MaybeUninit;

use thiserror::Error;

pub mod csr_formats;
#[cfg(all(feature = "sev-guest", not(target_env = "sgx")))]
pub mod guest;
pub mod report;

/// An enum capturing all the things that can go wrong with attestation
/// for the core components
#[derive(Debug, Error)]
pub enum AttestationCoreErr {
    #[error("Data received is the wrong size; expected={0}; actual={1}")]
    InvalidBufferSize(usize, usize),
    #[error("Unsupported Signature Algorithm; expected 1; actual {0}")]
    UnsupportedSignatureAlgo(u32),
    #[cfg(all(feature = "sev-guest", not(target_env = "sgx")))]
    #[error("Guest Error: {0}")]
    GuestErr(#[from] guest::SevGuestErr),
    #[error("Policy error: {0}")]
    ReportVerificationError(String),
}

/// This function is unsafe because there's no way to assert that 'B' is a POD
/// "plain-old-data" type for which casting from a byte array would be safe.
pub(crate) unsafe fn try_init_from_slice_copy<B>(src: &[u8]) -> Result<B, AttestationCoreErr> {
    // This check is safe:
    let size = size_of::<B>();
    if size != src.len() {
        return Err(AttestationCoreErr::InvalidBufferSize(size, src.len()));
    }
    // unsafe part begins here, with uninitialized value of B:
    unsafe {
        let mut dest = MaybeUninit::<B>::uninit();
        core::ptr::copy_nonoverlapping(src.as_ptr(), dest.as_mut_ptr() as *mut u8, size);
        Ok(dest.assume_init())
    }
}
