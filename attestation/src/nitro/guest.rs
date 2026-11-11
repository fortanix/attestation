/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use aws_nitro_enclaves_nsm_api::{
    api::{Request, Response},
    driver,
};
use mbedtls::rng::{Random, Rdrand};

pub fn get_attestation_report(user_data: &[u8; 64]) -> Result<Vec<u8>, String> {
    let mut nonce = [0; 16];
    Rdrand
        .random(&mut nonce)
        .map_err(|e| format!("Failed generating nonce: {}", e))?;
    let nsm_fd = driver::nsm_init();
    if nsm_fd < 0 {
        return Err("Failed opening Nitro security module".into());
    }
    let response = driver::nsm_process_request(
        nsm_fd,
        Request::Attestation {
            public_key: None,
            user_data: Some(serde_bytes::ByteBuf::from(user_data.to_vec())),
            nonce: Some(serde_bytes::ByteBuf::from(nonce.to_vec())),
        },
    );
    driver::nsm_exit(nsm_fd);
    let document = match response {
        Response::Attestation { document } => document,
        Response::Error(e) => {
            return Err(format!(
                "Failed getting attestation from nsm_driver: {:?}",
                e
            ))
        }
        other => return Err(format!("Unknown response from nsm_driver: {:?}", other)),
    };
    Ok(document)
}
