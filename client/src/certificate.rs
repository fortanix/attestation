/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs;
use std::path::Path;

use crate::error::Error::*;
use crate::error::Result;
use attestation::utils::compute_sha256;
use ftx_cert_build::name_builder::NameBuilder;
use ftx_cert_build::Csr;
use mbedtls::pk::Pk;
use mbedtls::rng::Rdrand as FtxRng;
use pkix::pem::{der_to_pem, PEM_CERTIFICATE_REQUEST};
use pkix::types::Attribute;

const RSA_KEY_SIZE: u32 = 3072;
const RSA_EXPONENT: u32 = 0x10001;
const APP_CERT_FILE_NAME_DEFAULT: &str = "/opt/fortanix/attestation-client/cert.pem";
const APP_CERT_KEY_NAME_DEFAULT: &str = "/opt/fortanix/attestation-client/key.pem";
pub const DEFAULT_NODE_AGENT_VSOCK_CID: u32 = vsock::VMADDR_CID_HOST;

pub struct AppCert {
    pub key: Pk,
    pub cert: Option<String>,
}

impl AppCert {
    pub fn init() -> Result<Self> {
        let key = Self::create_cert_keypair()?;
        Ok(AppCert { key, cert: None })
    }

    fn create_cert_keypair() -> Result<Pk> {
        Pk::generate_rsa(&mut FtxRng, RSA_KEY_SIZE, RSA_EXPONENT).map_err(|e| {
            CryptoErr(format!(
                "failed to generate cert key pair : {:?}",
                e.to_string()
            ))
        })
    }

    pub(crate) fn get_spki_hash(&mut self) -> Result<[u8; 32]> {
        let pub_key_der = self
            .key
            .write_public_der_vec()
            .map_err(|_| AppCertErr("failed to get public key der".to_string()))?;
        compute_sha256(&pub_key_der)
            .map_err(|_| AppCertErr("failed to get public key hash".to_string()))
    }

    pub(crate) fn request_app_cert_csr(
        &mut self,
        attributes: Vec<Attribute>,
        alt_names: Option<Vec<String>>,
    ) -> Result<String> {
        let alt_names = alt_names.unwrap_or_default();
        let subject = match alt_names.first() {
            Some(domain) => NameBuilder::new().add_common_name(domain).build_name(),
            None => vec![].into(),
        };

        // Include [attestation_certificate, node_certificate] as extension in the body
        let pk_key = &mut self.key;
        let csr = Csr::mbedtls_crypto_builder()
            .with_self_signing_key(pk_key, pkix::types::RsaPkcs15(pkix::types::Sha256))
            .map_err(|e| CryptoErr(format!("failed to create crypto csr builder :{:?}", e)))?
            .with_subject(subject.into())
            .with_san_extension_from_strs(&alt_names)
            .with_attributes(attributes)
            .map_err(|e| AppCertErr(format!("failed to add csr attributes : {:?}", e)))?
            .build_csr()
            .map_err(|e| AppCertErr(format!("failed to build app cert csr :{:?}", e)))?;

        Ok(der_to_pem(csr.as_ref(), PEM_CERTIFICATE_REQUEST))
    }

    pub fn write_to_fs(&mut self, app_cert_metadata: &AppCertMetadata) -> Result<()> {
        let kpath = Path::new(&app_cert_metadata.key_path);
        let key_pem = self
            .key
            .write_private_pem_string()
            .map_err(|e| AppCertErr(format!("failed to obtain key pem string : {:?}", e)))?;

        // If path doesn't exist, create it
        if fs::metadata(kpath).is_err() {
            if let Some(parent) = AsRef::<Path>::as_ref(&kpath).parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| AppCertErr(format!("failed to create key path : {:?}", e)))?;
            }
        }
        fs::write(kpath, key_pem)
            .map_err(|e| AppCertErr(format!("failed to write key to key path : {:?}", e)))?;

        let cpath = Path::new(&app_cert_metadata.cert_path);

        let cert_pem = self
            .cert
            .as_ref()
            .ok_or(AppCertErr("failed to obtain app cert ref".to_string()))?;

        // If path doesn't exist, create it
        if fs::metadata(cpath).is_err() {
            if let Some(parent) = AsRef::<Path>::as_ref(cpath).parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| AppCertErr(format!("failed to create cert path : {:?}", e)))?;
            }
        }
        fs::write(cpath, cert_pem)
            .map_err(|e| AppCertErr(format!("failed to write cert to cert path : {:?}", e)))?;
        Ok(())
    }
}

pub struct AppCertMetadata {
    pub key_path: String,
    pub cert_path: String,
}

impl AppCertMetadata {
    pub fn init(key_path: Option<&str>, cert_path: Option<&str>) -> Result<Self> {
        Ok(AppCertMetadata {
            key_path: key_path.unwrap_or(APP_CERT_KEY_NAME_DEFAULT).to_string(),
            cert_path: cert_path.unwrap_or(APP_CERT_FILE_NAME_DEFAULT).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::error::Error::*;
    use crate::error::Result;
    use crate::utils::extract_oid_from_extension;
    use crate::AppCert;
    use ftx_cert_build::name_builder::NameBuilder;
    use pkix::pem::{pem_to_der, PEM_CERTIFICATE_REQUEST};
    use pkix::pkcs10::{DerCertificationRequest, ExtensionRequest};
    use pkix::types::{Extension, GeneralName, GeneralNames};
    use pkix::x509::SubjectAltName;
    use pkix::yasna::construct_der;
    use pkix::DerWrite;
    use pkix::{oid, FromDer};

    fn extract_extensions_from_csr(csr: &DerCertificationRequest) -> Result<Vec<Extension>> {
        let extensions = csr
            .get_singular_attribute::<ExtensionRequest>()
            .ok_or(CertErr("CSR has no extension request".into()))?;
        Ok(extensions.extensions.to_vec())
    }

    fn construct_san_extension(alt_names: Vec<String>) -> Vec<u8> {
        let expected_san = alt_names
            .iter()
            .map(|name| GeneralName::DnsName(name.as_str().into()))
            .collect::<Vec<_>>();
        construct_der(|w| {
            SubjectAltName {
                names: GeneralNames(expected_san),
            }
            .write(w)
        })
    }

    #[test]
    fn test_inspect_csr() {
        let alt_names = vec!["example.com".to_string(), "example.net".to_string()];

        let mut app_cert = AppCert::init().unwrap();
        let app_csr = app_cert
            .request_app_cert_csr(vec![], Some(alt_names.clone()))
            .unwrap();

        let der_csr = pem_to_der(&app_csr, Some(PEM_CERTIFICATE_REQUEST)).unwrap();
        let csr = DerCertificationRequest::from_der(&der_csr).unwrap();

        let expected_subject = NameBuilder::new()
            .add_common_name(&alt_names[0])
            .build_name();
        assert_eq!(csr.reqinfo.subject, expected_subject);

        let expected_san = construct_san_extension(alt_names);
        let extensions = extract_extensions_from_csr(&csr).unwrap();
        let actual_san =
            extract_oid_from_extension(extensions, oid::subjectAltName.clone()).unwrap();

        assert_eq!(expected_san, actual_san);
    }
}
