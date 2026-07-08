/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::nvidia::evidence::get_nvidia_evidence;
use crate::sev::report::{Report, USER_DATA_SIZE};
use der::asn1::OctetString;
use der::Encode;
use log::info;

use super::super::csr_format::baremetal_snp::{AmdSevAttestationBaremetalV1, ReportDataV1};
use super::super::csr_format::{CoprocessorAttestationSetV1, CoprocessorAttestationV1};
use crate::utils::compute_sha256;

impl AmdSevAttestationBaremetalV1 {
    pub fn get_evidence(spki_hash: &[u8; 32], appconfig_id: Option<&[u8]>) -> Result<Self, String> {
        let mut coprocessors: Vec<CoprocessorAttestationV1> = vec![];
        // Obtain GPU evidence
        match get_nvidia_evidence(spki_hash) {
            Ok(evidences) => {
                let coprocessor = CoprocessorAttestationV1::try_from(evidences)
                    .map_err(|e| format!("unable to convert nvidia evidence : {:?}", e))?;
                coprocessors.push(coprocessor);
            }
            Err(e) => {
                info!("GPU evidence could not be collected : {:?}", e);
            }
        }

        // Transform evidence into relevant CSR format
        let coprocessors: CoprocessorAttestationSetV1 = coprocessors
            .try_into()
            .map_err(|e| format!("failed to convert to CoprocessorAttestationSetV1 : {:?}", e))?;

        // Generate report data hash
        let report_data = ReportDataV1::new(spki_hash, coprocessors.clone(), appconfig_id)?;
        let report_data_hash = report_data.get_hash()?;

        // Populate report data hash into CPU user data
        let mut amd_user_data = [0u8; USER_DATA_SIZE];
        amd_user_data[..32].copy_from_slice(&report_data_hash);

        // Generate CPU evidence
        let sev_report = Report::request(&amd_user_data)
            .map_err(|e| format!("unable to obtain guest report : {:?}", e))?;
        let mut sev_report_vec = Vec::new();
        sev_report
            .write(&mut sev_report_vec)
            .map_err(|e| format!("unable to write guest report : {:?}", e))?;
        let attestation_report = OctetString::new(sev_report_vec)
            .map_err(|e| format!("unable to obtain sev report octet string : {:?}", e))?;

        // Return Baremetal sev-snp evidence
        Ok(AmdSevAttestationBaremetalV1 {
            attestation_report,
            coprocessors,
        })
    }

    pub fn extract_sev_report(&self) -> Result<Report, String> {
        let report_slice = self.attestation_report.as_bytes();
        Report::try_from_slice(report_slice)
            .map_err(|e| format!("unable to extract report : {:?}", e))
    }
}

impl ReportDataV1 {
    pub fn new(
        spki_hash: &[u8; 32],
        coprocessors: CoprocessorAttestationSetV1,
        appconfig_id: Option<&[u8]>,
    ) -> Result<Self, String> {
        let config_id: Option<OctetString> = appconfig_id
            .map(OctetString::new)
            .transpose()
            .map_err(|e| format!("unable to obtain appconfig id octet string : {:?}", e))?;
        let spki = OctetString::new(spki_hash)
            .map_err(|e| format!("unable to create spki hash octet string : {:?}", e))?;
        Ok(ReportDataV1 {
            spki,
            coprocessors,
            appconfig_id: config_id,
        })
    }

    fn get_hash(&self) -> Result<[u8; 32], String> {
        let report_data_der = self
            .to_der()
            .map_err(|e| format!("unable to convert report data to der : {:?}", e))?;
        compute_sha256(&report_data_der)
            .map_err(|e| format!("unable to hash report data : {:?}", e))
    }
}
