/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod error;
use log::debug;
use nvml::{Device, Nvml};

use super::NvidiaEvidence;
use error::{GpuError, Result};

/// Initializes the Nvidia management library
fn initialize_nvml() -> Result<Nvml> {
    Nvml::init().map_err(GpuError::InitError)
}

/// Obtains the attestation certificate chain of the given GPU device
/// including the device root certificate. The root certificate is also
/// available in Nvidia's nvtrust GitHub repository.
fn get_device_cert_chain(device: &mut Device) -> Result<Vec<u8>> {
    let cert = device.get_cc_gpu_cert().map_err(GpuError::CertError)?;
    Ok(cert.attestationCertChain[0..cert.attestationCertChainSize as usize].to_owned())
}

/// Obtains the signed attestation report of the GPU device
fn get_device_attestation_report(nonce: &[u8; 32], device: &mut Device) -> Result<Vec<u8>> {
    let report = device
        .get_cc_gpu_attestation_report(nonce)
        .map_err(GpuError::ReportError)?;
    Ok(report.attestationReport[0..report.attestationReportSize as usize].to_owned())
}

/// Retrieves the attestation evidence for a specific NVIDIA GPU device.
///
/// Uses the NVIDIA Management Library (NVML) to retrieve the device attestation report
/// and certificate chain for the GPU device specified by the `device_index`.
///
/// # Arguments
///
/// * `nvml` - A reference to the *initialized* NVML library instance.
/// * `device_index` - The index of the GPU device for which attestation evidence is being retrieved.
pub fn get_nvidia_device_evidence(
    nvml: &Nvml,
    nonce: &[u8; 32],
    device_index: u32,
) -> Result<NvidiaEvidence> {
    let mut device = nvml
        .device_by_index(device_index)
        .map_err(GpuError::DeviceError)?;
    let certificates = get_device_cert_chain(&mut device)?;
    let report = get_device_attestation_report(nonce, &mut device)?;
    debug!("collected evidence for device with index `{device_index}`.");
    Ok(NvidiaEvidence {
        certificates,
        report,
    })
}

/// Retrieves attestation evidence for all available NVIDIA GPU devices on the system.
///
/// This function initializes the NVIDIA Management Library (NVML) and collects the
/// attestation evidence for each GPU device available on the system. The evidence for
/// each device includes the attestation report and certificate chain.
pub fn get_nvidia_evidence(nonce: &[u8; 32]) -> Result<Vec<NvidiaEvidence>> {
    let nvml = initialize_nvml()?;
    let device_count = nvml.device_count().map_err(GpuError::DeviceError)?;
    debug!("discovered `{device_count}` GPU devices.");

    let evidence_list = (0..device_count)
        .map(|device_index| get_nvidia_device_evidence(&nvml, nonce, device_index))
        .collect::<Result<Vec<_>>>()?;

    Ok(evidence_list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires Confidential VM with GPU"]
    fn test_init_nvml() {
        initialize_nvml().unwrap();
    }

    #[test]
    #[ignore = "Requires Confidential VM with GPU"]
    fn test_attestation_report() {
        let nvml = initialize_nvml().unwrap();
        let mut device = nvml.device_by_index(0).unwrap();
        let nonce = [0u8; 32];
        let report = get_device_attestation_report(&nonce, &mut device).unwrap();
        assert!(!report.is_empty());
    }

    #[test]
    #[ignore = "Requires Confidential VM with GPU"]
    fn test_cert_chain() {
        let nvml = initialize_nvml().unwrap();
        let mut device = nvml.device_by_index(0).unwrap();
        let cert = get_device_cert_chain(&mut device).unwrap();
        assert!(!cert.is_empty());

        // The device root certificate can be found here: https://docs.ndis.nvidia.com/
        // It can also be obtained in PEM form from nvtrust GitHub repo
        // https://github.com/NVIDIA/nvtrust/blob/main/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/certs/verifier_device_root.pem
        let device_root_cert = "-----BEGIN CERTIFICATE-----
MIICCzCCAZCgAwIBAgIQLTZwscoQBBHB/sDoKgZbVDAKBggqhkjOPQQDAzA1MSIw
IAYDVQQDDBlOVklESUEgRGV2aWNlIElkZW50aXR5IENBMQ8wDQYDVQQKDAZOVklE
SUEwIBcNMjExMTA1MDAwMDAwWhgPOTk5OTEyMzEyMzU5NTlaMDUxIjAgBgNVBAMM
GU5WSURJQSBEZXZpY2UgSWRlbnRpdHkgQ0ExDzANBgNVBAoMBk5WSURJQTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABA5MFKM7+KViZljbQSlgfky/RRnEQScW9NDZF8SX
gAW96r6u/Ve8ZggtcYpPi2BS4VFu6KfEIrhN6FcHG7WP05W+oM+hxj7nyA1r1jkB
2Ry70YfThX3Ba1zOryOP+MJ9vaNjMGEwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAQYwHQYDVR0OBBYEFFeF/4PyY8xlfWi3Olv0jUrL+0lfMB8GA1UdIwQY
MBaAFFeF/4PyY8xlfWi3Olv0jUrL+0lfMAoGCCqGSM49BAMDA2kAMGYCMQCPeFM3
TASsKQVaT+8S0sO9u97PVGCpE9d/I42IT7k3UUOLSR/qvJynVOD1vQKVXf0CMQC+
EY55WYoDBvs2wPAH1Gw4LbcwUN8QCff8bFmV4ZxjCRr4WXTLFHBKjbfneGSBWwA=
-----END CERTIFICATE-----";

        let cert_str = std::str::from_utf8(&cert).unwrap();
        assert!(cert_str.contains(device_root_cert));
    }
}
