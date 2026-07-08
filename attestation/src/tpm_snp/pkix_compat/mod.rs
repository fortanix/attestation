/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod baremetal_snp;

use std::sync::LazyLock;

pub use crate::sev::csr_formats::AmdSevAttestationV1 as PkixAmdSevAttestationV1;
use der::asn1::OctetString;
use der::Encode;
use pkix::types::{Attribute, Extension, ObjectIdentifier};

use super::csr_format::{AmdAzureVtpmQuoteWithJwtV1, AmdSevAttestationV1};

/// The OID for `AmdAzureVtpmQuoteWithJwtV1` struct.
pub static TPM_SNP_OID: LazyLock<ObjectIdentifier> =
    LazyLock::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 8].into());

/// Convert type without cloning Vec<u8>
impl TryFrom<PkixAmdSevAttestationV1> for AmdSevAttestationV1 {
    type Error = der::Error;

    fn try_from(value: PkixAmdSevAttestationV1) -> der::Result<Self> {
        let certificates = value
            .certificates
            .into_iter()
            .map(|cert| cert.value.into_owned().try_into())
            .collect::<der::Result<_>>()?;

        Ok(Self {
            attestation_report: OctetString::new(value.report.into_owned())?,
            certificates,
        })
    }
}

/// Convert type without cloning Vec<u8>
impl From<AmdSevAttestationV1> for PkixAmdSevAttestationV1 {
    fn from(value: AmdSevAttestationV1) -> Self {
        let certificates = value
            .certificates
            .into_iter()
            .map(|cert| cert.into_vec().into())
            .collect();

        Self {
            report: value.attestation_report.into_bytes().into(),
            certificates,
        }
    }
}

impl TryFrom<&AmdAzureVtpmQuoteWithJwtV1> for Attribute<'static> {
    type Error = der::Error;

    fn try_from(data: &AmdAzureVtpmQuoteWithJwtV1) -> der::Result<Self> {
        Ok(Attribute {
            oid: TPM_SNP_OID.clone(),
            value: vec![data.to_der()?.into()],
        })
    }
}

impl TryFrom<&AmdAzureVtpmQuoteWithJwtV1> for Extension {
    type Error = der::Error;

    fn try_from(data: &AmdAzureVtpmQuoteWithJwtV1) -> der::Result<Self> {
        // Only special extensions are "critical"; despite the importance of an attestation.
        Ok(Extension {
            oid: TPM_SNP_OID.clone(),
            critical: false,
            value: data.to_der()?,
        })
    }
}
