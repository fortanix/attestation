/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::tdx::model::{
    AttestationErr, ReportDataV1, TdxReportMeasurements, TdxReportType, TdxReportVersion1,
    TeeReportMac,
};
use std::borrow::Cow;

// TDX report: in its original TDREPORT form in the TDX guest
pub struct PackedTdxReportGuest<T, TCP>
where
    T: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    pub td_report: T::ReportType,
    pub coprocessors: TCP,
}

impl<T, TCP> PackedTdxReportGuest<T, TCP>
where
    T: TdxReportType,
    TCP: Clone + der::Encode + der::DecodeOwned,
{
    #[cfg(all(feature = "tdx-guest", not(target_env = "sgx")))]
    pub fn generate_report(
        spki_hash: &[u8; 32],
        coprocessors: TCP,
        appconfig_id: Option<&[u8]>,
    ) -> Result<Self, AttestationErr> {
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&ReportDataV1::get_hash(
            spki_hash,
            &coprocessors,
            appconfig_id,
        )?);
        let td_report = T::generate_report(&report_data)?;
        Ok(Self {
            td_report,
            coprocessors,
        })
    }

    #[cfg(any(all(feature = "tdx-guest", not(target_env = "sgx")), test))]
    pub fn from_mock_report(report_bin: &[u8], coprocessors: TCP) -> Result<Self, AttestationErr> {
        let td_report = T::generate_mock_report(report_bin)?;
        Ok(Self {
            td_report,
            coprocessors,
        })
    }

    #[cfg(any(all(feature = "tdx-guest", not(target_env = "sgx")), test))]
    pub fn build_decoupled_report<'s>(
        &'s self,
    ) -> Result<(TeeReportMac<'s>, TdxReportMeasurements<'s, T, TCP>), AttestationErr> {
        Ok((
            TeeReportMac(Cow::Borrowed(T::report_mac_from_report(&self.td_report))),
            TdxReportMeasurements::new_from_report(&self.td_report, self.coprocessors.clone()),
        ))
    }
}

pub type PackedTdxReportGuestV1<TCP> = PackedTdxReportGuest<TdxReportVersion1, TCP>;

#[cfg(test)]
mod tests {
    use crate::tdx::guest::PackedTdxReportGuestV1;
    use crate::tdx::model::{TdxReportMeasurements, TdxReportVersion1, TeeReportMac};
    use der::Sequence;
    use pkix::{FromBer, ToDer};

    #[derive(Sequence, Clone, Debug, PartialEq)]
    struct MockTCP {
        pub mock: u32,
    }

    #[test]
    fn mock_generate_decouple_report() {
        let td_report = include_bytes!("tests/data/tdreport.bin");
        let packed_report =
            PackedTdxReportGuestV1::<MockTCP>::from_mock_report(td_report, MockTCP { mock: 10 })
                .unwrap();
        let (report_mac, report_measurements) = packed_report.build_decoupled_report().unwrap();
        let report_mac_der = report_mac.to_der();
        let report_measurements_der = report_measurements.to_der();
        TdxReportMeasurements::<TdxReportVersion1, MockTCP>::from_ber(&report_measurements_der)
            .unwrap();
        TeeReportMac::from_ber(&report_mac_der).unwrap();
    }
}
