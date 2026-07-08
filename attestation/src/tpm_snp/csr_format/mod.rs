/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//! ASN.1 Type definitions

pub mod baremetal_snp;

use der::asn1::{ObjectIdentifier, OctetString, SetOfVec};
use der::{Sequence, ValueOrd};

/// X.509 certificate
/// ```asn1
/// Certificate ::= SEQUENCE { ... }
/// ```
pub type Certificate = der::Document;

/// ```asn1
/// AmdAzureVtpmQuoteWithJwtV1 ::= SEQUENCE {
///     quote                    AmdAzureVtpmQuoteV1,
///     -- JSON Web Token string returned from the Microsoft Azure Attestation endpoint, after decryption via vTPM
///     -- Includes a signature from the /v1/maa_quote endpoint, so CCM can validate authenticity
///     maa-jwt                  OCTET STRING
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct AmdAzureVtpmQuoteWithJwtV1 {
    pub quote: AmdAzureVtpmQuoteV1,
    pub maa_jwt: OctetString,
}

/// ```asn1
/// AmdAzureVtpmQuoteV1 ::= SEQUENCE {
///     quote                    AmdVtpmQuoteV1,
///     -- ATTESTATION_REPORT.HclData.VariableData
///     -- tpm2_nvread -C o 0x01400001 | tail -c +1237 | gawk -F '\0' '{print $1}'
///     hcl-report-variable-data OCTET STRING
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct AmdAzureVtpmQuoteV1 {
    pub quote: AmdVtpmQuoteV1,
    pub hcl_report_variable_data: OctetString,
    pub ephemeral_key: EphemeralKeyV1,
}

/// This is a MAA-specific structure to provide the Ephemeral Key to MAA, which is used to encrypt the AES key used to encrypt the returned JWT
/// ```asn1
/// EphemeralKeyV1 ::= SEQUENCE {
///     -- TPM2B_PUBLIC structure defined in TPM 2.0 spec
///     encryption_key              OCTET STRING
///     -- TPMS_ATTEST structure defined in TPM 2.0 spec
///     certify_info                OCTET STRING
///     -- TPM2B_PUBLIC_KEY_RSA structure defined in TPM 2.0 spec
///     certify_info_signature      OCTET STRING
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct EphemeralKeyV1 {
    /// TPM2B_PUBLIC structure defined in TPM 2.0 spec
    pub encryption_key: OctetString,
    /// TPMS_ATTEST structure defined in TPM 2.0 spec
    pub certify_info: OctetString,
    /// TPM2B_PUBLIC_KEY_RSA structure defined in TPM 2.0 spec
    pub certify_info_signature: OctetString,
}

/// ```asn1
/// AmdVtpmQuoteV1 ::= SEQUENCE {
///     -- the TPM generates an AkPub/Priv/Cert and does remote attestation of it with the AMD Attestation. (hash is in report_data)
///     amd                      AmdSevAttestationV1,
///     -- the TPM quote is then signed by that AkCert.
///     tpm                      TpmQuoteV1,
///     coprocessors             CoprocessorAttestationSetV1
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct AmdVtpmQuoteV1 {
    pub amd: AmdSevAttestationV1,
    pub quote: TpmQuoteV1,
    pub coprocessors: CoprocessorAttestationSetV1,
}

/// ```asn1
/// TpmQuoteV1 ::= SEQUENCE {
///     -- TPMS_ATTEST structure defined in TPM 2.0 spec
///     message                  OCTET STRING,
///     -- TPMT_SIGNATURE structure defined in TPM 2.0 spec
///     signature                OCTET STRING,
///     -- TPMT_SIG_SCHEME strucure defined in TPM 2.0 spec
///     signature-algorithm      OCTET STRING,
///     -- List[TPM2B_DIGEST] - Length and order mapped to data in TPMS_ATTEST.attested.quote.pcrSelect, which is of type TPML_PCR_SELECTION
///     pcrs                     SEQUENCE OF OCTET STRING,
///     -- UEFI Event Log in binary format; allows for explanation and partial verification of dynamic PCRs.
///     -- /sys/kernel/security/tpm0/binary_bios_measurements
///     uefi-event-log           OCTET STRING,
///     -- cert[0] = AkCert = TPM AK Certificate: the certificate signing the
///     --           TpmQuoteV1, whose hash should be present in a corresponding AMD attestation.
///     -- Ekcert is not available in the vTPM of Azure CVM. TPM and it's quote is verified by verifying the TPM intermediate
///     -- and root CA downloaded from Microsoft.
///     -- cert[1] = EkCert = TPM EK Certificate: TPM certificate that signs the ak_cert; the primary unique
///     --           private key in a generic TPM; Microsoft's platform seems to rely on AkPub being
///     --           singular as well (created alongside generating snp report during VM boot)
///     -- The rest of the chain of trust will likely be embedded into Malbork and not presented here.
///     -- https://learn.microsoft.com/en-us/azure/confidential-computing/how-to-leverage-virtual-tpms-in-azure-confidential-vms
///     certificates             SEQUENCE OF Certificate
/// }
/// ```
#[derive(Sequence, Debug, PartialEq, Eq)]
pub struct TpmQuoteV1 {
    /// TPMS_ATTEST structure defined in TPM 2.0 spec
    pub message: OctetString,
    /// TPMT_SIGNATURE structure defined in TPM 2.0 spec
    pub signature: OctetString,
    /// TPMT_SIG_SCHEME strucure defined in TPM 2.0 spec
    pub signature_algorithm: OctetString,
    /// List[TPM2B_DIGEST] - Length and order mapped to data in TPMS_ATTEST.attested.quote.pcrSelect, which is of type TPML_PCR_SELECTION
    pub pcrs: Vec<OctetString>,
    /// UEFI Event Log in binary format; allows for explanation and partial verification of dynamic PCRs.
    /// /sys/kernel/security/tpm0/binary_bios_measurements
    pub uefi_event_log: OctetString,
    /// SEQUENCE OF Certificate
    pub certificates: Vec<Certificate>,
    /// TPM2B_PUBLIC structure defined in TPM 2.0 spec
    pub ak_pub: OctetString,
}

/// ```asn1
/// AmdSevAttestationV1 ::= SEQUENCE {
///     attestation_report       OCTET STRING,
///     -- see the ATTESTATION_REPORT structure defined in https://www.amd.com/system/files/TechDocs/56860.pdf
///     certificates             SEQUENCE OF Certificate
///     -- this sequence of certificates includes at least the VCEK and also its chain of trust: the ASK and ARK respectively.
/// }
/// ```
#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
pub struct AmdSevAttestationV1 {
    pub attestation_report: OctetString,
    pub certificates: Vec<Certificate>,
}

/// ```asn1
/// AssociatedDataPCRV1 ::= SEQUENCE {
///     -- 64 bytes
///     join-token               OCTET STRING,
///     -- 32 bytes, sha256sum of the CSR's public key encoded as DER
///     spki                     OCTET STRING,
///     coprocessors             CoprocessorAttestationSetV1,
///     -- 32 bytes if using workflows, otherwise omitted
///     appconfig-id         [0] EXPLICIT OCTET STRING OPTIONAL
/// }
/// ```
#[derive(Sequence, Clone, Debug, PartialEq, Eq)]
pub struct AssociatedDataPCRV1 {
    pub join_token: OctetString,
    pub spki: OctetString,
    pub coprocessors: CoprocessorAttestationSetV1,
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    pub appconfig_id: Option<OctetString>,
}

impl AssociatedDataPCRV1 {
    pub fn new(
        join_token: &[u8],
        spki: &[u8],
        coprocessors: CoprocessorAttestationSetV1,
    ) -> Result<Self, der::Error> {
        Ok(AssociatedDataPCRV1 {
            join_token: OctetString::new(join_token)?,
            spki: OctetString::new(spki)?,
            coprocessors,
            appconfig_id: None,
        })
    }
}

/// A sorted list of coprocessor attestations.
/// Each OID can only appear once.
/// ```asn1
/// CoprocessorAttestationSetV1 ::= SET OF CoprocessorAttestationV1
/// ```
pub type CoprocessorAttestationSetV1 = SetOfVec<CoprocessorAttestationV1>;

/// ```asn1
/// CoprocessorAttestationV1 ::= SEQUENCE {
///     -- A child OID of 1.3.6.1.4.1.49690.2.2.11
///     coprocessor-type         OBJECT IDENTIFIER,
///     -- value defined by above OID, typically a DER encoded sequence
///     data                     SEQUENCE OF OCTET STRING
/// }
/// ```
#[derive(Sequence, ValueOrd, Clone, Debug, PartialEq, Eq)]
pub struct CoprocessorAttestationV1 {
    pub coprocessor_type: ObjectIdentifier,
    pub data: Vec<OctetString>,
}
