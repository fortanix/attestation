/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::sync::LazyLock;

use der::Encode;
use pkix::derives::ObjectIdentifier;
use pkix::types::{Attribute, Extension, TaggedDerValue};
use pkix::yasna;

use super::super::csr_format::baremetal_snp::{AmdSevAttestationBaremetalV1, FqpeCerts};

/// The OID for `ATTESTATION_REPORT` as provided by AMD SEV SNP
pub static ATTESTATION_REPORT_SNP_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 7].into());

/// The OID for `AmdAzureVtpmQuoteWithJwtV1` struct.
pub static BAREMETAL_SNP_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 14].into());

pub static APPCONFIG_ID_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 1, 3, 4].into());

pub static SEV_SNP_CHAIN_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 15].into());

pub static FTX_QPE_CERT_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 1].into());

impl TryFrom<&AmdSevAttestationBaremetalV1> for Attribute<'static> {
    type Error = der::Error;

    fn try_from(data: &AmdSevAttestationBaremetalV1) -> der::Result<Self> {
        Ok(Attribute {
            oid: BAREMETAL_SNP_OID.clone(),
            value: vec![data.to_der()?.into()],
        })
    }
}

impl TryFrom<&AmdSevAttestationBaremetalV1> for Extension {
    type Error = der::Error;

    fn try_from(data: &AmdSevAttestationBaremetalV1) -> der::Result<Self> {
        // Only special extensions are "critical"; despite the importance of an attestation.
        Ok(Extension {
            oid: BAREMETAL_SNP_OID.clone(),
            critical: false,
            value: data.to_der()?,
        })
    }
}

impl TryFrom<&AmdSevAttestationBaremetalV1> for TaggedDerValue {
    type Error = yasna::ASN1Error;

    fn try_from(data: &AmdSevAttestationBaremetalV1) -> Result<Self, Self::Error> {
        let der = data
            .to_der()
            .map_err(|_| yasna::ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?;
        yasna::parse_der(&der, |reader| reader.read_tagged_der())
    }
}

impl TryFrom<&FqpeCerts> for Attribute<'static> {
    type Error = der::Error;

    fn try_from(data: &FqpeCerts) -> der::Result<Self> {
        Ok(Attribute {
            oid: FTX_QPE_CERT_OID.clone(),
            value: vec![data.to_der()?.into()],
        })
    }
}
