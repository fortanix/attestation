/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#[cfg(feature = "tdx-guest")]
pub mod guest;

#[cfg(feature = "tdx-guest")]
pub use guest::*;

use std::borrow::Cow;
use std::convert::TryInto;
use std::marker::PhantomData;

use der::asn1::OctetStringRef;
use der::{Encode, Sequence};

use pkix::derives::ObjectIdentifier;
use pkix::types::{Attribute, HasOid};
use pkix::yasna::BERDecodable;
use pkix::{yasna, ASN1Error, DerWrite, ToDer};
use sgx_isa::tdx::{TdInfoV1, TdxReportTypeVersion, TdxReportV1, TeeTcbInfo};
use sgx_isa::ReportMacStruct;
use sgx_pkix::oid;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationErr {
    #[error("data received is the wrong size; expected={0}; actual={1}")]
    InvalidBufferSize(usize, usize),
    #[error("failed obtaining TDREPORT: {0}")]
    FailedObtainingTdReport(String),
    #[error("failed verifying TDREPORT: {0}")]
    ReportVerificationError(String),
    #[error("failed when generating report data: {0}")]
    ReportDataGenerationError(String),
    #[error("invalid operation: {0}")]
    InvalidOperation(String),
}

/// Wrapper type for `sgx_isa::ReportMacStruct` which can be either borrowed
/// from the `TdxReportV1` variants or owned by itself. We are wrapping the
/// `sgx_isa` type so that we can attach trait implementation to it, such as
/// `BERDecodable` and `DerWrite` without requiring it to be implemented within
/// the `sgx_isa` directly. Currently it is being used only in TDX context,
/// but maybe used further in SGX-256 attestation.
///
/// ASN.1 definition:
/// ```no_compile
///    TeeReportMac :== OCTET STRING
/// ```

#[derive(Clone)]
pub struct TeeReportMac<'a>(pub Cow<'a, ReportMacStruct>);

impl AsRef<ReportMacStruct> for TeeReportMac<'_> {
    fn as_ref(&self) -> &ReportMacStruct {
        self.0.as_ref()
    }
}

impl HasOid for TeeReportMac<'_> {
    fn oid() -> &'static pkix::types::ObjectIdentifier {
        &oid::attestationTeeReportMac
    }
}

impl BERDecodable for TeeReportMac<'_> {
    fn decode_ber<'a, 'b>(reader: yasna::BERReader<'a, 'b>) -> pkix::ASN1Result<Self> {
        let bytes = reader.read_bytes()?;
        if bytes.len() != ReportMacStruct::UNPADDED_SIZE {
            Err(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))
        } else {
            Ok(TeeReportMac(Cow::Owned(
                ReportMacStruct::try_copy_from(&bytes)
                    .ok_or(ASN1Error::new(yasna::ASN1ErrorKind::Invalid))?,
            )))
        }
    }
}

impl DerWrite for TeeReportMac<'_> {
    fn write(&self, writer: yasna::DERWriter) {
        writer.write_bytes((*self.0).as_ref());
    }
}

impl TryInto<Attribute<'static>> for &TeeReportMac<'_> {
    type Error = der::Error;

    fn try_into(self) -> Result<Attribute<'static>, der::Error> {
        Ok(Attribute {
            oid: TeeReportMac::oid().clone(),
            value: vec![self.to_der().into()],
        })
    }
}

impl TryInto<Attribute<'static>> for TeeReportMac<'_> {
    type Error = der::Error;

    fn try_into(self) -> Result<Attribute<'static>, der::Error> {
        (&self).try_into()
    }
}

/// Trait that defines the type configuration for a TDX report. This trait is technically
/// an adapter type to match the TDX report type with its actual types in the `sgx-isa`
/// crate. There may be a future update to the TDX ISA, in which we only need to create
/// a new `impl` of this trait to define the correct way to process it from our code.
pub trait TdxReportType {
    type ReportType: Clone;
    type TeeTcbInfoType: Clone + AsRef<[u8]>;
    type TdInfoType: Clone + AsRef<[u8]>;

    fn accepted_versions() -> &'static [TdxReportTypeVersion];
    fn td_info_from_report<'a>(report: &'a Self::ReportType) -> &'a Self::TdInfoType;
    fn tee_tcb_info_from_report<'a>(report: &'a Self::ReportType) -> &'a Self::TeeTcbInfoType;
    fn report_mac_from_report<'a>(report: &'a Self::ReportType) -> &'a ReportMacStruct;
    fn tee_tcb_info_from_slice(slice: &[u8]) -> Option<Self::TeeTcbInfoType>;
    fn td_info_from_slice(slice: &[u8]) -> Option<Self::TdInfoType>;

    #[cfg(all(feature = "tdx-guest", not(target_env = "sgx")))]
    fn generate_report(report_data: &[u8; 64]) -> Result<Self::ReportType, AttestationErr>;

    #[cfg(any(all(feature = "tdx-guest", not(target_env = "sgx")), test))]
    fn generate_mock_report(report_bin: &[u8]) -> Result<Self::ReportType, AttestationErr>;

    fn accepted_report(report: &Self::ReportType) -> bool {
        Self::accepted_version(Self::report_mac_from_report(report).report_type.version)
    }

    fn accepted_version(version: u8) -> bool {
        TdxReportTypeVersion::try_from(version)
            .is_ok_and(|x| Self::accepted_versions().contains(&x))
    }
}

/// `TdxReportType` definition for TDX report version 1 (in TDX ISA, it is for both version 0 and 1).
pub struct TdxReportVersion1;

impl TdxReportType for TdxReportVersion1 {
    type ReportType = TdxReportV1;
    type TeeTcbInfoType = TeeTcbInfo;
    type TdInfoType = TdInfoV1;

    fn accepted_versions() -> &'static [TdxReportTypeVersion] {
        const VERSION: [TdxReportTypeVersion; 2] = [
            TdxReportTypeVersion::NoBound,
            TdxReportTypeVersion::ServTdUsed,
        ];
        &VERSION
    }

    fn td_info_from_report<'a>(report: &'a Self::ReportType) -> &'a Self::TdInfoType {
        &report.td_info
    }

    fn tee_tcb_info_from_report<'a>(report: &'a Self::ReportType) -> &'a Self::TeeTcbInfoType {
        &report.tee_tcb_info
    }

    fn report_mac_from_report<'a>(report: &'a Self::ReportType) -> &'a ReportMacStruct {
        &report.report_mac
    }

    #[cfg(all(feature = "tdx-guest", not(target_env = "sgx")))]
    fn generate_report(report_data: &[u8; 64]) -> Result<Self::ReportType, AttestationErr> {
        use tdx_ql::tdx_ioctl;

        let report = tdx_ioctl::get_report(report_data.clone())
            .map_err(|e| AttestationErr::FailedObtainingTdReport(e.to_string()))?;

        Ok(report)
    }

    fn tee_tcb_info_from_slice(slice: &[u8]) -> Option<Self::TeeTcbInfoType> {
        TeeTcbInfo::try_copy_from(slice)
    }

    fn td_info_from_slice(slice: &[u8]) -> Option<Self::TdInfoType> {
        TdInfoV1::try_copy_from(slice)
    }

    #[cfg(any(all(feature = "tdx-guest", not(target_env = "sgx")), test))]
    fn generate_mock_report(report_bin: &[u8]) -> Result<Self::ReportType, AttestationErr> {
        TdxReportV1::try_copy_from(report_bin).ok_or_else(|| {
            AttestationErr::ReportDataGenerationError("cannot copy from bytes".to_string())
        })
    }
}

/*
 * TdxReportMeasurements ::= SEQUENCE {
 *    report_version          INTEGER,
 *    -- measurements from TDREPORT, including tee_tcb_info and td_info data structure, packed in binary
 *    tee_tcb_info            OCTET STRING,
 *    td_info                 OCTET STRING,
 *    -- see https://fortanix.atlassian.net/wiki/spaces/A1/pages/3358982544/CCM+AMD+SEV-SNP+TPM+Platform+API+Changes
 *    coprocessors            CoprocessorAttestationSetV1
 * }
 */
/// Struct definition for `TdxReportMeasurement` that encapsulates the TDX TEE measurements, in such
/// a way that it is generic enough to handle future possible changes of Intel SGX ISA without having
/// to refactor lots of codes.
#[derive(Clone)]
pub struct TdxReportMeasurements<'a, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    pub version: u8,
    pub tee_tcb_info: Cow<'a, TRT::TeeTcbInfoType>,
    pub td_info: Cow<'a, TRT::TdInfoType>,
    pub coprocessors: TCP,
    _tc_type: PhantomData<TCP>,
}

/// Notes to the API consumer: since the `TdxReportMeasurement` generic
/// is strongly typed and tied to the `TdxReportType` trait and has
/// statically defined report version in the `impl`, future addition
/// to report version requires the consumer to try each possible
/// `TdxReportType` types. The `decode_ber` will directly fail in case of
/// the actual report version in the encoded data is different than what
/// is expected in the `TdxReportType`'s `accepted_version` list.
///
/// Possible implementation:
///
/// ```no_compile
///    let report_measurement_der = vec![];
///
///    if let Ok(report_v1) = TdxReportMeasurements::<TdxReportVersion1, CoprocessorAttestationSetV1>::from_ber(report_measurement_der) {
///       // TdxReportMeasurement with TdxReportVersion1
///    } else if let Ok(report_v2) = TdxReportMeasurements::<TdxReportVersion2, CoprocessorAttestationSetV1>::from_ber(report_measurement_der) {
///       // TdxReportMeasurement with TdxReportVersion2
///    } else {
///       // Invalid report version
///    }
/// ```
impl<TRT, TCP> BERDecodable for TdxReportMeasurements<'_, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    fn decode_ber<'a, 'b>(reader: yasna::BERReader<'a, 'b>) -> pkix::ASN1Result<Self> {
        reader.read_sequence(|r| {
            let version = r.next().read_u8()?;

            let error = ASN1Error::new(yasna::ASN1ErrorKind::Invalid);
            if !TRT::accepted_version(version) {
                return Err(error);
            }

            let tee_tcb_info =
                Cow::Owned(TRT::tee_tcb_info_from_slice(&(r.next().read_bytes()?)).ok_or(error)?);
            let td_info =
                Cow::Owned(TRT::td_info_from_slice(&r.next().read_bytes()?).ok_or(error)?);
            let coprocessors = TCP::from_der(&(r.next().read_der()?)).map_err(|_| error)?;

            Ok(Self {
                version,
                tee_tcb_info,
                td_info,
                coprocessors,
                _tc_type: PhantomData,
            })
        })
    }
}

impl<TRT, TCP> DerWrite for TdxReportMeasurements<'_, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    fn write(&self, writer: yasna::DERWriter) {
        writer.write_sequence(|w| {
            w.next().write_u8(self.version);
            w.next().write_bytes((*self.tee_tcb_info).as_ref());
            w.next().write_bytes((*self.td_info).as_ref());

            let mut coprocessor_der = vec![];
            let _ = self.coprocessors.encode_to_vec(&mut coprocessor_der);

            w.next().write_der(&coprocessor_der);
        })
    }
}

// Note to maintainer: if there is a change in `CoprocessorAttestationSetV1`
// ASN.1 definition, then this OID needs to also be changed.
impl<TRT, TCP> HasOid for TdxReportMeasurements<'_, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    fn oid() -> &'static ObjectIdentifier {
        &oid::attestationTdxReportMeasurements
    }
}

impl<'a, TRT, TCP> TdxReportMeasurements<'a, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    #[cfg(any(all(feature = "tdx-guest", not(target_env = "sgx")), test))]
    pub fn new_from_report(report: &'a TRT::ReportType, coprocessors: TCP) -> Self {
        Self {
            version: TRT::report_mac_from_report(report).report_type.version,
            tee_tcb_info: Cow::Borrowed(TRT::tee_tcb_info_from_report(report)),
            td_info: Cow::Borrowed(TRT::td_info_from_report(report)),
            coprocessors,
            _tc_type: PhantomData,
        }
    }
}

impl<TRT, TCP> TdxReportMeasurements<'_, TRT, TCP>
where
    TRT: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    pub fn coprocessors(&self) -> &TCP {
        &self.coprocessors
    }

    pub fn tee_tcb_info(&self) -> &TRT::TeeTcbInfoType {
        self.tee_tcb_info.as_ref()
    }

    pub fn td_info(&self) -> &TRT::TdInfoType {
        self.td_info.as_ref()
    }
}

#[derive(Sequence)]
pub struct ReportDataV1<'a, 'b, TCP>
where
    TCP: Clone + der::Encode + der::DecodeOwned,
    'a: 'b,
{
    pub spki: OctetStringRef<'a>,
    pub coprocessors: TCP,
    pub appconfig_id: Option<OctetStringRef<'b>>,
}

fn compute_sha256(data: &[u8]) -> mbedtls::Result<[u8; 32]> {
    use mbedtls::hash::{Md, Type};
    let mut output = [0u8; 32];
    let _ = Md::hash(Type::Sha256, data, &mut output)?;
    Ok(output)
}

#[allow(unused)]
impl<'a, 'b, TCP> ReportDataV1<'a, 'b, TCP>
where
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    pub fn new(
        spki_hash: &'a [u8; 32],
        coprocessors: &TCP,
        appconfig_id: Option<&'b [u8]>,
    ) -> Result<Self, AttestationErr> {
        let config_id: Option<OctetStringRef<'b>> = appconfig_id
            .map(OctetStringRef::new)
            .transpose()
            .map_err(|e| {
                AttestationErr::ReportDataGenerationError(format!(
                    "unable to obtain appconfig id octet string : {:?}",
                    e
                ))
            })?;
        let spki = OctetStringRef::new(spki_hash).map_err(|e| {
            AttestationErr::ReportDataGenerationError(format!(
                "unable to create spki hash octet string : {:?}",
                e
            ))
        })?;
        Ok(ReportDataV1 {
            spki,
            coprocessors: coprocessors.clone(),
            appconfig_id: config_id,
        })
    }

    pub fn get_hash(
        spki_hash: &'a [u8; 32],
        coprocessors: &TCP,
        appconfig_id: Option<&'b [u8]>,
    ) -> Result<[u8; 32], AttestationErr> {
        let report_data_der = Self::new(spki_hash, coprocessors, appconfig_id)?
            .to_der()
            .map_err(|e| {
                AttestationErr::ReportDataGenerationError(format!(
                    "unable to convert report data to der : {:?}",
                    e
                ))
            })?;
        compute_sha256(&report_data_der).map_err(|e| {
            AttestationErr::ReportDataGenerationError(format!(
                "unable to hash report data : {:?}",
                e
            ))
        })
    }
}
