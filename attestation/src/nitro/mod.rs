/* Copyright (c) Fortanix, Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod csr_format;

#[cfg(feature = "nitro-guest")]
pub mod guest;

#[cfg(feature = "nitro-guest")]
pub use guest::get_attestation_report;

use crate::utils::compute_sha256;

/// Bind the public key DER and optional 32-byte configuration ID to a Nitro report.
pub fn get_user_data(pub_key: &[u8], appconfig_id: Option<&[u8]>) -> Result<[u8; 64], String> {
    let mut data = [0; 64];
    let pub_key_hash = compute_sha256(pub_key).map_err(|e| e.to_string())?;
    data[..32].copy_from_slice(&pub_key_hash);
    if let Some(id) = appconfig_id {
        if id.len() != 32 {
            return Err("config ID must be 32 bytes".into());
        }
        let mut payload = [0; 65];
        payload[0] = 1;
        payload[1..33].copy_from_slice(&data[..32]);
        payload[33..].copy_from_slice(&id[..32]);

        // The payload is formed as follows in case of workflow report.
        // First 32 bytes is a Sha256 of (Version + public key sha256 + config-id)
        // Second 32 bytes part is the actual config-id.
        let payload_hash = compute_sha256(&payload).map_err(|e| e.to_string())?;
        data[..32].copy_from_slice(&payload_hash);
        data[32..].copy_from_slice(&id[..32]);
    }
    // if non-workflow report then first 32 bytes is the hash of the public key, second 32 bytes are all 0.

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_data_binds_key_and_configuration() {
        let key = b"public key";
        let plain = get_user_data(key, None).unwrap();
        assert_eq!(&plain[..32], &compute_sha256(key).unwrap());
        assert_eq!(&plain[32..], &[0; 32]);
        let id = [0xab; 32];
        let workflow = get_user_data(key, Some(&id)).unwrap();
        let mut payload = vec![1];
        payload.extend_from_slice(&plain[..32]);
        payload.extend_from_slice(&id);
        assert_eq!(&workflow[..32], &compute_sha256(&payload).unwrap());
        assert_eq!(&workflow[32..], &id);
        assert_ne!(workflow, get_user_data(b"another key", Some(&id)).unwrap());
        for len in [0, 1, 31, 33, 64] {
            assert!(get_user_data(key, Some(&vec![0; len])).is_err());
        }
    }
}
