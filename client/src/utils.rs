/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use pkix::derives::ObjectIdentifier;
use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
use pkix::types::Extension;
use pkix::x509::GenericCertificate;
use pkix::FromDer;

use crate::error::Error::*;
use crate::error::Result;

pub fn extract_extensions_from_cert(pem_cert: &str) -> Result<Vec<Extension>> {
    let der_cert = pem_to_der(pem_cert, Some(PEM_CERTIFICATE))
        .ok_or(CertErr("failed to parse pem cert".into()))?;
    let cert = GenericCertificate::from_der(&der_cert)
        .map_err(|e| CertErr(format!("failed to parse der cert : {:?}", e)))?;
    Ok(cert.tbscert.extensions)
}

pub fn extract_oid_from_extension(extns: Vec<Extension>, oid: ObjectIdentifier) -> Result<Vec<u8>> {
    extns
        .iter()
        .find(|ext| ext.oid == oid)
        .map(|ext| ext.value.clone())
        .ok_or(CertErr(format!(
            "failed to find oid {:?} in extensions",
            oid
        )))
}

pub fn get_app_config_id() -> Option<Vec<u8>> {
    std::env::var("APPCONFIG_ID").ok().map(|s| s.into_bytes())
}
