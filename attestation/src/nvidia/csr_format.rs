/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use der::asn1::{ObjectIdentifier, OctetString};
use der::Sequence;

/// The OID for `NvidiaAttestationV1` as used in `tpm-snp-attestation::CoprocessorAttestationV1`
pub const NVIDIA_ATTESTATION_OID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.49690.2.2.11.1");

/// X.509 certificate
/// ```asn1
/// Certificate ::= SEQUENCE { ... }
/// ```
pub type Certificate = der::Document;

/// ```asn1
/// NvidiaAttestationV1 ::= SEQUENCE {
///     attestation-report       OCTET STRING,
///     certificates             SEQUENCE OF Certificate
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct NvidiaAttestationV1 {
    pub attestation_report: OctetString,
    pub certificates: Vec<Certificate>,
}
