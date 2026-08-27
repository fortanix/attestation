use client::certificate::{AppCert, AppCertMetadata};
use client::error::Result;
use client::{Attest, NodeAgentClient};

/// Common function shared between binaries to set up and execute and attestation,
/// and write the resulting private key and certificate to disk.
pub fn run_client<T: Attest>() -> Result<()> {
    // Initialize the app cert key and cert paths from environment variables
    // Once the app cert is obtained, they key and cert will be written to disk
    // be written on disk
    let key_filename = std::env::var("APP_CERT_KEY_FILE_NAME").ok();
    let cert_filename = std::env::var("APP_CERT_FILE_NAME").ok();
    let app_cert_metadata =
        AppCertMetadata::init(key_filename.as_deref(), cert_filename.as_deref())?;

    // Initialize the RSA key pair used to request an app cert
    let mut app_cert = AppCert::init()?;

    let node_agent_cli = NodeAgentClient::init()?;

    // If attestation succeeds, app_cert is populated with the certificate
    T::attest_and_request_app_cert(&mut app_cert, &node_agent_cli, None, None)?;

    // Write cert and key to disk
    app_cert.write_to_fs(&app_cert_metadata)?;

    Ok(())
}
