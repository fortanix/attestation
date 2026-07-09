/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use client::certificate::{AppCert, AppCertMetadata};
use client::error::Result;
use client::{Attest, BaremetalSevSnp, NodeAgentClient};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    // Initialize the app cert key and cert paths from environment variables
    // Once the app cert is obtained, they key and cert will be written to disk
    let key_filename = std::env::var("APP_CERT_KEY_FILE_NAME").ok();
    let cert_filename = std::env::var("APP_CERT_FILE_NAME").ok();
    let app_cert_metadata =
        AppCertMetadata::init(key_filename.as_deref(), cert_filename.as_deref())?;

    // Initialize the RSA key pair used to request an app cert
    let mut app_cert = AppCert::init()?;

    let node_agent_cli = NodeAgentClient::init()?;

    // If attestation succeeds, app_cert is populated with the certificate
    let mut sev_snp = BaremetalSevSnp;
    sev_snp.attest_and_request_app_cert(&mut app_cert, &node_agent_cli)?;

    // Write cert and key to disk
    app_cert.write_to_fs(&app_cert_metadata)?;

    Ok(())
}
