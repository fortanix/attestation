/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::{Certificate, CoprocessorAttestationSetV1, CoprocessorAttestationV1};
use crate::nvidia::csr_format::{NvidiaAttestationV1, NVIDIA_ATTESTATION_OID};
use crate::nvidia::NvidiaEvidence;
use der::asn1::OctetString;
use der::Sequence;
use der::{Decode, Encode};

/// ```asn1
/// AmdSevAttestationBaremetalV1 ::= SEQUENCE {
///     -- see the ATTESTATION_REPORT structure defined in https://www.amd.com/system/files/TechDocs/56860.pdf
///     attestation_report       OCTET STRING,
///     -- see https://fortanix.atlassian.net/wiki/spaces/A1/pages/3358982544/CCM+AMD+SEV-SNP+TPM+Platform+API+Changes
///     coprocessors             CoprocessorAttestationSetV1
/// }
/// ```
#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
pub struct AmdSevAttestationBaremetalV1 {
    pub attestation_report: OctetString,
    pub coprocessors: CoprocessorAttestationSetV1,
}

/// -- Differences from AssociatedDataPCRV1: removed join-token
/// ReportDataV1 ::= SEQUENCE {
///     -- 32 bytes, sha256sum of the CSR's public key encoded as DER
///     spki                     OCTET STRING,
///     coprocessors             CoprocessorAttestationSetV1,
///     -- 32 bytes if using workflows, otherwise omitted
///     appconfig-id         [0] EXPLICIT OCTET STRING OPTIONAL
/// }
#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
pub struct ReportDataV1 {
    pub spki: OctetString,
    pub coprocessors: CoprocessorAttestationSetV1,
    pub appconfig_id: Option<OctetString>,
}

#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
pub struct FqpeCerts {
    pub certificates: Vec<Certificate>,
}

impl TryFrom<Vec<NvidiaAttestationV1>> for CoprocessorAttestationV1 {
    type Error = der::Error;

    fn try_from(attestations: Vec<NvidiaAttestationV1>) -> der::Result<Self> {
        Ok(Self {
            coprocessor_type: NVIDIA_ATTESTATION_OID,
            data: attestations
                .into_iter()
                .map(|attestation| attestation.to_der().and_then(OctetString::new))
                .collect::<der::Result<Vec<_>>>()?,
        })
    }
}

impl TryFrom<Vec<NvidiaEvidence>> for CoprocessorAttestationV1 {
    type Error = der::Error;

    fn try_from(evidences: Vec<NvidiaEvidence>) -> der::Result<Self> {
        let attestations = evidences
            .iter()
            .map(NvidiaAttestationV1::try_from)
            .collect::<der::Result<Vec<_>>>()?;
        attestations.try_into()
    }
}

impl TryFrom<&CoprocessorAttestationV1> for Vec<NvidiaAttestationV1> {
    type Error = String;

    fn try_from(coprocessor: &CoprocessorAttestationV1) -> Result<Self, String> {
        if coprocessor.coprocessor_type != NVIDIA_ATTESTATION_OID {
            return Err("Coprocessor type does not match".to_string());
        }
        coprocessor
            .data
            .iter()
            .map(|der| NvidiaAttestationV1::from_der(der.as_bytes()).map_err(|e| e.to_string()))
            .collect()
    }
}
