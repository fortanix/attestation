/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use attestation::tpm_snp::pkix_compat::baremetal_snp::APPCONFIG_ID_OID;
use der::asn1::OctetString;
use der::Encode;
use ftx_cert_build::name_builder::{InitDn, NameBuilder, WithDnSet};
use pkix::derives::ObjectIdentifier;
use pkix::pem::{pem_to_der, PEM_CERTIFICATE};
use pkix::types::{Extension, TaggedDerValue};
use pkix::x509::GenericCertificate;
use pkix::FromDer;

use crate::error::Error::*;
use crate::error::Result;

pub trait NameBuilderExt {
    fn add_attestation_report(
        self,
        oid: ObjectIdentifier,
        value: TaggedDerValue,
    ) -> NameBuilder<WithDnSet>;

    fn add_appconfig_id(self, appconfig_id: Option<&[u8]>) -> Result<NameBuilder<WithDnSet>>;
}

impl<D> NameBuilderExt for NameBuilder<D>
where
    NameBuilder<D>: InitDn,
{
    fn add_attestation_report(
        self,
        oid: ObjectIdentifier,
        value: TaggedDerValue,
    ) -> NameBuilder<WithDnSet> {
        self.add_custom_oid(oid, value)
    }

    fn add_appconfig_id(self, appconfig_id: Option<&[u8]>) -> Result<NameBuilder<WithDnSet>> {
        let Some(id) = appconfig_id else {
            return Ok(self.init_dn());
        };
        let appconfig_id_value = OctetString::new(id)
            .map_err(|e| {
                AppCertErr(format!(
                    "failed to create appconfig ID octet string : {:?}",
                    e
                ))
            })?
            .to_der()
            .map_err(|e| {
                ConversionErr(format!("failed to convert appconfig ID to der : {:?}", e))
            })?;
        let appconfig_id_der =
            pkix::yasna::parse_der(&appconfig_id_value, |reader| reader.read_tagged_der())
                .map_err(|e| {
                    ConversionErr(format!(
                        "failed to convert appconfig ID to tagged der : {:?}",
                        e
                    ))
                })?;
        Ok(self.add_custom_oid(APPCONFIG_ID_OID.clone(), appconfig_id_der))
    }
}

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
