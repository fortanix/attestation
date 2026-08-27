/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![deny(warnings)]
pub mod certificate;
pub mod error;
pub mod utils;
pub mod vsock_connector;
use std::time::Duration;

use attestation::nvidia::evidence::get_nvidia_evidence;
use attestation::tdx::{
    PackedTdxReportGuestV1, TdxReportMeasurements, TdxReportVersion1, TeeReportMac,
};
use attestation::tpm_snp::csr_format::baremetal_snp::{AmdSevAttestationBaremetalV1, FqpeCerts};
use attestation::tpm_snp::csr_format::{CoprocessorAttestationSetV1, CoprocessorAttestationV1};
use attestation::tpm_snp::pkix_compat::baremetal_snp::{APPCONFIG_ID_OID, BAREMETAL_SNP_OID};
use der::asn1::OctetString;
use der::{Decode, Encode};
use em_node_agent_client::models::{
    GetFortanixAttestationRequest, GetFortanixAttestationResponse, IssueCertificateRequest,
};
use em_node_agent_client::{CertificateApi, Client, EnclaveApi, SystemApi};
use ftx_cert_build::name_builder::NameBuilder;
use ftx_cert_build::Csr;
use log::info;
use pkix::pem::{der_to_pem, pem_to_der, PEM_CERTIFICATE, PEM_CERTIFICATE_REQUEST};
use pkix::types::{Attribute, HasOid, TaggedDerValue};
use pkix::{yasna, ToDer};

use crate::certificate::AppCert;
use crate::error::Error::*;
use crate::error::Result;
use crate::utils::get_app_config_id;
use crate::vsock_connector::VsockConnector;
pub const DEFAULT_NODE_AGENT_VSOCK_CID: u32 = vsock::VMADDR_CID_HOST;
const DEFAULT_NODE_AGENT_VSOCK_ADDR: &str = "http://0.0.0.0:40/";
const MAX_RETRIES: usize = 10;
const RETRY_DELAY: Duration = Duration::from_secs(1);

pub struct BaremetalSevSnp;
pub struct BaremetalTdx;

pub struct NodeAgentClient {
    client: Client,
}

impl NodeAgentClient {
    pub fn init() -> Result<Self> {
        let client = Client::try_new_with_connector(
            DEFAULT_NODE_AGENT_VSOCK_ADDR,
            Some("http"),
            VsockConnector,
        )
        .map_err(|e| {
            NACliErr(format!(
                "failed to initialize node agent client connector: {:?}",
                e
            ))
        })?;

        for attempt in 1..=MAX_RETRIES {
            match client.get_agent_version() {
                Ok(version) => {
                    info!(
                        "Connected to Node Agent (version {}) after {} attempt(s)",
                        version.version.unwrap_or_default(),
                        attempt
                    );

                    return Ok(NodeAgentClient { client });
                }
                Err(err) => {
                    info!(
                        "Node Agent not reachable (attempt {}/{}): {:?}",
                        attempt, MAX_RETRIES, err
                    );

                    std::thread::sleep(RETRY_DELAY);
                }
            }
        }
        Err(NACliErr(format!(
            "failed to reach node agent after {} attempts. Is it installed correctly?",
            MAX_RETRIES
        )))
    }

    pub(crate) fn get_fortanix_attestation(
        &self,
        csr: Option<String>,
        report: Option<String>,
    ) -> Result<GetFortanixAttestationResponse> {
        let req = GetFortanixAttestationRequest {
            report,
            attestation_csr: csr,
        };

        self.client
            .get_fortanix_attestation(req)
            .map_err(|e| NACliErr(format!("failed to get fortanix attestation: {:?}", e)))
    }

    pub(crate) fn get_fortanix_certificate(&self, csr: String) -> Result<String> {
        let req = IssueCertificateRequest { csr: Some(csr) };

        let resp = self
            .client
            .issue_certificate(req)
            .map_err(|e| NACliErr(format!("failed to request app certificate : {:?}", e)))?;

        resp.certificate.ok_or(NACliErr(
            "failed to read certificate from fortanix response".into(),
        ))
    }
}

pub trait Attest {
    fn perform_local_attestation(
        app_cert: &mut AppCert,
        node_agent_cli: &NodeAgentClient,
        app_config_id: Option<Vec<u8>>,
    ) -> Result<GetFortanixAttestationResponse>;

    fn attest_and_request_app_cert(
        app_cert: &mut AppCert,
        node_agent_cli: &NodeAgentClient,
        app_config_id: Option<Vec<u8>>,
        alt_names: Option<Vec<String>>,
    ) -> Result<()> {
        let local_attest_resp =
            Self::perform_local_attestation(app_cert, node_agent_cli, app_config_id)?;
        let attestation_cert = local_attest_resp
            .attestation_certificate
            .clone()
            .ok_or(AttestErr("failed to obtain attestation certificate".into()))?;
        let node_cert = local_attest_resp
            .node_certificate
            .clone()
            .ok_or(AttestErr("failed to get node certificate".into()))?;

        let attestation_cert_der =
            pem_to_der(&attestation_cert, Some(PEM_CERTIFICATE)).ok_or(ConversionErr(
                "failed to convert attestation certificate from pem to der format".into(),
            ))?;
        let node_cert_der = pem_to_der(&node_cert, Some(PEM_CERTIFICATE)).ok_or(ConversionErr(
            "failed to convert node certificate from pem to der format".into(),
        ))?;

        let fqpe_certs = FqpeCerts {
            certificates: [attestation_cert_der, node_cert_der]
                .into_iter()
                .map(|cert| {
                    der::Document::from_der(&cert)
                        .map_err(|e| AttestErr(format!("failed to read fqpe certs : {:?}", e)))
                })
                .collect::<Result<_>>()?,
        };
        let attribute = Attribute::try_from(&fqpe_certs).map_err(|e| {
            AttestErr(format!(
                "failed to read attributes for fqpe certs : {:?}",
                e
            ))
        })?;

        let app_cert_csr = app_cert.request_app_cert_csr(vec![attribute], alt_names)?;
        let app_cert_cert = node_agent_cli.get_fortanix_certificate(app_cert_csr)?;
        app_cert.cert = Some(app_cert_cert);
        Ok(())
    }
}

impl Attest for BaremetalSevSnp {
    fn perform_local_attestation(
        app_cert: &mut AppCert,
        node_agent_cli: &NodeAgentClient,
        app_config_id: Option<Vec<u8>>,
    ) -> Result<GetFortanixAttestationResponse> {
        // Check if appconfig_id is available
        let appconfig_id_bind: Option<Vec<u8>> = if app_config_id.is_some() {
            app_config_id
        } else {
            get_app_config_id()
        };
        let appconfig_id: Option<&[u8]> = appconfig_id_bind.as_deref();

        // Compute the public key hash
        let spki_hash = app_cert.get_spki_hash()?;
        // Generate evidence
        let attestation_report =
            AmdSevAttestationBaremetalV1::get_evidence(&spki_hash, appconfig_id)
                .map_err(AttestErr)?;

        // Construct the local attestation CSR
        let csr = Self::get_local_attestation_csr(app_cert, &attestation_report, appconfig_id)?;
        node_agent_cli.get_fortanix_attestation(Some(csr), None)
    }
}

impl BaremetalSevSnp {
    fn get_local_attestation_csr(
        appcert: &mut AppCert,
        attestation_report: &AmdSevAttestationBaremetalV1,
        appconfig_id: Option<&[u8]>,
    ) -> Result<String> {
        let attestation_report_der: TaggedDerValue = TaggedDerValue::try_from(attestation_report)
            .map_err(|e| {
            ConversionErr(format!(
                "failed to convert attestation report to der : {:?}",
                e
            ))
        })?;
        let subject = match appconfig_id {
            Some(id) => {
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
                let appconfig_id_der: TaggedDerValue =
                    yasna::parse_der(&appconfig_id_value, |reader| reader.read_tagged_der())
                        .map_err(|e| {
                            ConversionErr(format!(
                                "failed to convert appconfig ID to tagged der : {:?}",
                                e
                            ))
                        })?;
                NameBuilder::new()
                    .add_custom_oid(BAREMETAL_SNP_OID.clone(), attestation_report_der)
                    .add_custom_oid(APPCONFIG_ID_OID.clone(), appconfig_id_der)
                    .build_subject()
            }
            None => NameBuilder::new()
                .add_custom_oid(BAREMETAL_SNP_OID.clone(), attestation_report_der)
                .build_subject(),
        };

        let pk_key = &mut appcert.key;
        let csr = Csr::mbedtls_crypto_builder()
            .with_self_signing_key(pk_key, pkix::types::RsaPkcs15(pkix::types::Sha256))
            .map_err(|e| CryptoErr(format!("failed to create crypto csr builder :{:?}", e)))?
            .with_subject(subject)
            .build_csr()
            .map_err(|e| AppCertErr(format!("failed to build local csr :{:?}", e)))?;
        Ok(der_to_pem(csr.as_ref(), PEM_CERTIFICATE_REQUEST))
    }
}

impl BaremetalTdx {
    fn get_local_attestation_csr(
        appcert: &mut AppCert,
        tee_report_mac_der: Vec<u8>,
        tdx_report_der: Vec<u8>,
        appconfig_id: Option<&[u8]>,
    ) -> Result<String> {
        let tdx_report_tagged_der: TaggedDerValue =
            yasna::parse_der(&tdx_report_der, |reader| reader.read_tagged_der()).map_err(|e| {
                ConversionErr(format!(
                    "failed to convert tdx report der to tagged der : {:?}",
                    e
                ))
            })?;

        let subject = match appconfig_id {
            Some(id) => {
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
                let appconfig_id_der: TaggedDerValue =
                    yasna::parse_der(&appconfig_id_value, |reader| reader.read_tagged_der())
                        .map_err(|e| {
                            ConversionErr(format!(
                                "failed to convert appconfig ID to tagged der : {:?}",
                                e
                            ))
                        })?;
                NameBuilder::new()
                    .add_custom_oid(
                        TdxReportMeasurements::<TdxReportVersion1, CoprocessorAttestationSetV1>::oid().clone(),
                        tdx_report_tagged_der.clone(),
                    )
                    .add_custom_oid(APPCONFIG_ID_OID.clone(), appconfig_id_der)
                    .build_subject()
            }
            None => NameBuilder::new()
                .add_custom_oid(
                    TdxReportMeasurements::<TdxReportVersion1, CoprocessorAttestationSetV1>::oid()
                        .clone(),
                    tdx_report_tagged_der.clone(),
                )
                .build_subject(),
        };

        let tee_report_mac_attribute = Attribute {
            oid: TeeReportMac::oid().clone(),
            value: vec![tee_report_mac_der.into()],
        };
        let attributes = vec![tee_report_mac_attribute];

        let pk_key = &mut appcert.key;
        let csr = Csr::mbedtls_crypto_builder()
            .with_self_signing_key(pk_key, pkix::types::RsaPkcs15(pkix::types::Sha256))
            .map_err(|e| CryptoErr(format!("failed to create crypto csr builder :{:?}", e)))?
            .with_subject(subject)
            .with_attributes(attributes)
            .map_err(|e| AppCertErr(format!("failed to add tdx attributes to csr : {:?}", e)))?
            .build_csr()
            .map_err(|e| AppCertErr(format!("failed to build local csr :{:?}", e)))?;
        Ok(der_to_pem(csr.as_ref(), PEM_CERTIFICATE_REQUEST))
    }
}
impl Attest for BaremetalTdx {
    fn perform_local_attestation(
        app_cert: &mut AppCert,
        node_agent_cli: &NodeAgentClient,
        app_config_id: Option<Vec<u8>>,
    ) -> Result<GetFortanixAttestationResponse> {
        // Check if appconfig_id is available
        let appconfig_id_bind: Option<Vec<u8>> = if app_config_id.is_some() {
            app_config_id
        } else {
            get_app_config_id()
        };
        let appconfig_id: Option<&[u8]> = appconfig_id_bind.as_deref();

        // Compute the public key hash
        let spki_hash = app_cert.get_spki_hash()?;

        // Generate GPU evidence
        let mut coprocessors: Vec<CoprocessorAttestationV1> = vec![];

        match get_nvidia_evidence(&spki_hash) {
            Ok(evidences) => {
                let coprocessor = CoprocessorAttestationV1::try_from(evidences).map_err(|e| {
                    ConversionErr(format!(
                        "failed to get CoprocessorAttestationV1 from gpu evidence : {:?}",
                        e
                    ))
                })?;
                coprocessors.push(coprocessor);
                info!("GPU evidence collected");
            }
            Err(e) => {
                info!("GPU evidence could not be collected : {:?}", e);
            }
        }

        let coprocessors_set: CoprocessorAttestationSetV1 =
            coprocessors.try_into().map_err(|e: der::Error| {
                ConversionErr(format!(
                    "failed to parse CoprocessorAttestationSetV1: {:?}",
                    e.to_string()
                ))
            })?;

        let packed_tdx_report =
            PackedTdxReportGuestV1::generate_report(&spki_hash, coprocessors_set, appconfig_id)
                .map_err(TdxAttestationErr)?;
        let (tee_report_mac, tdx_report) = packed_tdx_report
            .build_decoupled_report()
            .map_err(TdxAttestationErr)?;

        // Only print these in debug builds, not release builds
        #[cfg(debug_assertions)]
        {
            use log::debug;

            fn hex_encode(bytes: &[u8]) -> String {
                bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
            }

            debug!("TDX Machine measurements:");
            let measurements_base = &tdx_report.td_info().base;
            debug!("MRTD: {}", hex_encode(&measurements_base.mr_td));
            debug!("RTMR0: {}", hex_encode(&measurements_base.rtmr[0]));
            debug!("RTMR1: {}", hex_encode(&measurements_base.rtmr[1]));
            debug!("RTMR2: {}", hex_encode(&measurements_base.rtmr[2]));
            debug!("RTMR3: {}", hex_encode(&measurements_base.rtmr[3]));
        }

        let tee_report_mac_der = tee_report_mac.to_der();
        let tdx_report_der = tdx_report.to_der();

        // Construct the local attestation CSR
        let csr = Self::get_local_attestation_csr(
            app_cert,
            tee_report_mac_der,
            tdx_report_der,
            appconfig_id,
        )?;
        node_agent_cli.get_fortanix_attestation(Some(csr), None)
    }
}
