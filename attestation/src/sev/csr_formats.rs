/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//!
//! This module defines the CSR format for encoding an AMD-SEV-SNP attestation
//! on ACI (and perhaps other platforms).
//!

use std::borrow::Cow;

use once_cell::sync::Lazy;
use pkix::types::{Attribute, DerSequence, Extension, ObjectIdentifier};
use pkix::yasna::{self, BERDecodable, DERWriter};
use pkix::{DerWrite, ToDer};

/// This OID identifies the ReportAndEvidence struct.
pub static ACI_OID: Lazy<ObjectIdentifier> =
    Lazy::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 10].into());

/// Since the AMD SEV-SNP attestation is signed by the Virtual Chip Encryption
/// key (which is signed by the ASK, which is signed by the ARK), we want to
/// pass a report and its supporting certificates in a CSR.
///
/// ```asn1
/// AmdSevAttestationV1 ::= SEQUENCE {
///     attestation_report OCTET STRING
///     -- see the ATTESTATION_REPORT structure defined in https://www.amd.com/system/files/TechDocs/56860.pdf
///     certificates SEQUENCE OF Certificate
///     -- this sequence of certificates includes at least the VCEK and also its chain of trust: the ASK and ARK respectively.
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct ReportAndEvidence<'a, 'b> {
    pub report: Cow<'a, [u8]>,
    pub certificates: Vec<DerSequence<'b>>,
}

/// Expose the ASN1-named style of the struct for the "owned" version.
pub type AmdSevAttestationV1 = ReportAndEvidence<'static, 'static>;

impl<'a, 'b> DerWrite for ReportAndEvidence<'a, 'b> {
    fn write(&self, writer: DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_bytes(&self.report);
            w.next().write_sequence(|w| {
                for cert in &self.certificates {
                    cert.write(w.next());
                }
            });
        });
    }
}

impl BERDecodable for ReportAndEvidence<'static, 'static> {
    fn decode_ber<'a, 'b>(reader: yasna::BERReader<'a, 'b>) -> pkix::ASN1Result<Self> {
        reader.read_sequence(|r| {
            let report = r.next().read_bytes()?;
            let certificates = r
                .next()
                .collect_sequence_of(|r| DerSequence::decode_ber(r).to_owned())?;
            Ok(Self {
                report: Cow::Owned(report),
                certificates,
            })
        })
    }
}

impl From<&AmdSevAttestationV1> for Attribute<'static> {
    fn from(data: &AmdSevAttestationV1) -> Self {
        Attribute {
            oid: ACI_OID.clone(),
            value: vec![data.to_der().into()],
        }
    }
}
impl From<&AmdSevAttestationV1> for Extension {
    fn from(data: &AmdSevAttestationV1) -> Self {
        // Only special extensions are "critical"; despite the importance of an attestation.
        Extension {
            oid: ACI_OID.clone(),
            critical: false,
            value: data.to_der(),
        }
    }
}
