use client::certificate::{AppCert, AppCertMetadata};
use client::error::Result;
use client::{Attest, NodeAgentClient};

// Function to parse ALT_NAMES passed via APP_CERT_ALT_NAMES
fn get_alt_names() -> Option<Vec<String>> {
    std::env::var("APP_CERT_ALT_NAMES")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(|names| names.split(',').map(|s| s.to_string()).collect())
}

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
    let alt_names = get_alt_names();

    // Initialize the RSA key pair used to request an app cert
    let mut app_cert = AppCert::init()?;

    let node_agent_cli = NodeAgentClient::init()?;

    // If attestation succeeds, app_cert is populated with the certificate
    T::attest_and_request_app_cert(&mut app_cert, &node_agent_cli, None, alt_names)?;

    // Write cert and key to disk
    app_cert.write_to_fs(&app_cert_metadata)?;

    Ok(())
}
