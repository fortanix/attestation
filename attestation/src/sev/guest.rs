/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fs::File;
use std::mem::size_of;
use std::path::Path;

use iocuddle::{Group, Ioctl, WriteRead};
use thiserror::Error;

use super::report::{Report, REPORT_SIZE, USER_DATA_SIZE};
use super::AttestationCoreErr;

/// SNP Guest ioctls are in group 0x53; which is 'S'.
const SNP: Group = Group::new(b'S');

/// An enum capturing all the things that can go wrong with requesting the
/// attestation
#[derive(Debug, Error)]
pub enum SevGuestErr {
    #[error("Could not locate any candidate guest device, e.g., /dev/sev-guest")]
    MissingGuestDevice,
    #[error("Cannot open device: {0}; reason {1:?}")]
    CannotOpenDevice(&'static str, #[source] std::io::Error),
    #[error("IO error during Ioctl {0:?}")]
    IoctlErr(#[source] std::io::Error),
    #[error("Ioctl succeeded but Firmware Error Code found in STATUS: {0}")]
    FirmwareError(u32),
    /// ignored due to MAL-9480
    #[error("Error Code found in ioctl buffer: {0:#x} - fw_error={1} vmm_error={2}")]
    SevGuestRequestError(u64, u32, u32),
}

impl SevGuestErr {
    // Currently, fw_err is stored in the lower 32 bits and vmm_err in upper 32 bits
    // when laid out. See sev-guest.h in the Linux source repo, and note the order of
    // how these fields are defined in the struct.
    pub(crate) fn create_err(fw_err: u32, vmm_err: u32) -> Self {
        let err: u64 = ((vmm_err as u64) << 32) | (fw_err as u64);
        Self::SevGuestRequestError(err, fw_err, vmm_err)
    }

    // We can check for both fw_err and vmm_err directly.
    pub(crate) fn check_err(fw_err: u32, vmm_err: u32) -> Result<(), Self> {
        if fw_err != 0 || vmm_err != 0 {
            let err_instance = Self::create_err(fw_err, vmm_err);
            log::error!("{}", err_instance);
            return Err(err_instance);
        }
        Ok(())
    }
}

/// Defined in SEV-SNP Fw ABI Spec
#[repr(C)]
pub(crate) struct ReportRequest {
    user_data: [u8; USER_DATA_SIZE],
    vmpl: u32,
    /// Must be zero.
    _reserved: [u8; 28],
}
impl Default for ReportRequest {
    fn default() -> Self {
        // This is safe because it's repr(C) and we want all zero values.
        // We're dodging stdlib lacking derive-default for large arrays.
        unsafe { std::mem::zeroed() }
    }
}

/// Defined in SEV-SNP Fw ABI Spec
#[repr(C)]
pub(crate) struct ReportResponse {
    status: u32,
    report_size: u32,
    reserved: [u8; 24],
    attestation_report: [u8; REPORT_SIZE],
    padding: [u8; 2784],
}
const _: () = assert!(size_of::<ReportResponse>() == 4000); // defined in linux/include/uapi/linux/sev-guest.h snp_report_resp
impl Default for ReportResponse {
    fn default() -> Self {
        // This is safe because it's repr(C) and we want all zero values.
        // We're dodging stdlib lacking derive-default for large arrays.
        unsafe { std::mem::zeroed() }
    }
}

/// Get a pointer to the data we own as a u64 so it can be shared with the
/// kernel; up to you to ensure it doesn't move.
unsafe fn get_addr<T>(data: &mut T) -> u64 {
    data as *mut T as u64
}

/// This module contains the API used by Azure instances during preview.
mod preview {
    use super::*;

    pub(crate) const DEVICE_PATH: &str = "/dev/sev";

    /// This is an enum element in Microsoft's code, but we only plan to use
    /// this ioctl.
    const SNP_MSG_REPORT_REQ: u8 = 5;
    /// This is also an enum element in the preview API.
    const SNP_MSG_REPORT_RSP: u8 = 6;

    /// This is a version of the guest Ioctl context that had some tricky
    /// context; req/resp version ids and req/resp lengths that were removed
    /// from the final, upstream API.
    #[derive(Debug, Default)]
    #[repr(C)]
    struct GuestRequestIoctl {
        req_msg_type: u8,
        resp_msg_type: u8,
        /// Message Version Number (non-zero)
        msg_version: u8,

        /// Request address & length:
        req_len: u16,
        req_data: u64,

        /// Response address & length:
        resp_len: u16,
        resp_data: u64,
        /// Firmware error on failure (see psp-sev.h)
        /// NOTE: this is old and should be investigated.
        /// The upstream module contains the updated way of parsing errors.
        fw_err: u32,
    }

    const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequestIoctl> = unsafe { SNP.write_read(0x1) };

    pub(crate) fn request_report(
        user_data: &[u8; USER_DATA_SIZE],
    ) -> Result<ReportResponse, SevGuestErr> {
        let mut request = ReportRequest {
            user_data: *user_data,
            ..Default::default()
        };
        let mut response = ReportResponse::default();
        let mut message = GuestRequestIoctl {
            req_msg_type: SNP_MSG_REPORT_REQ,
            resp_msg_type: SNP_MSG_REPORT_RSP,
            msg_version: 1,
            req_len: size_of::<ReportRequest>()
                .try_into()
                .expect("size fits in u16"),
            req_data: unsafe { get_addr(&mut request) },
            resp_len: size_of::<ReportResponse>()
                .try_into()
                .expect("size fits in u16"),
            resp_data: unsafe { get_addr(&mut response) },
            fw_err: 0,
        };
        let mut device =
            File::open(DEVICE_PATH).map_err(|e| SevGuestErr::CannotOpenDevice(DEVICE_PATH, e))?;

        let res = SNP_GET_REPORT.ioctl(&mut device, &mut message);
        SevGuestErr::check_err(message.fw_err, 0)?;

        // Non-negative return code indicates success.
        let _rc = res.map_err(SevGuestErr::IoctlErr)?;

        Ok(response)
    }
}

/// This module contains the sev-guest API Ioctls that landed in Linux Kernel
/// 5.19 and beyond.
mod upstream {
    use super::*;

    pub(crate) const DEVICE_PATH: &str = "/dev/sev-guest";

    /// This is the Ioctl message struct; compared to the preview API it no
    /// longer has request/response lengths.
    #[derive(Debug)]
    #[repr(C)]
    struct GuestRequestIoctl {
        /// Message Version Number (non-zero)
        msg_version: u8,
        /// Request & response structure addresses:
        req_data: u64,
        resp_data: u64,
        /// Firmware error on failure (see psp-sev.h)
        exit_info: ExitInfo,
    }

    // Defining a struct in accordance with the Linux kernel's updated way of storing SNP errors
    // See sev-guest.h in Linux source code repo
    #[derive(Debug, Default)]
    #[repr(C)]
    pub(crate) struct ExitInfo {
        /// Firmware error on failure (see psp-sev.h)
        fw_err: u32,
        /// VMM/kernel error on failure
        vmm_err: u32,
    }

    /// SNP Guest ioctls are in group 0x53; which is 'S'.
    const SNP: Group = Group::new(b'S');

    /// The only ioctl we need for now is the report:
    const SNP_GET_REPORT: Ioctl<WriteRead, &GuestRequestIoctl> = unsafe { SNP.write_read(0x0) };
    #[allow(unused)]
    const SNP_GET_DERIVED_KEY: Ioctl<WriteRead, &GuestRequestIoctl> =
        unsafe { SNP.write_read(0x1) };
    #[allow(unused)]
    const SNP_GET_EXT_REPORT: Ioctl<WriteRead, &GuestRequestIoctl> = unsafe { SNP.write_read(0x2) };

    /// Request an attestation report from the current guest device.
    pub(crate) fn request_report(
        user_data: &[u8; USER_DATA_SIZE],
    ) -> Result<ReportResponse, SevGuestErr> {
        // Open the device:
        let mut device =
            File::open(DEVICE_PATH).map_err(|e| SevGuestErr::CannotOpenDevice(DEVICE_PATH, e))?;

        // Define report-request:
        let mut request = ReportRequest::default();
        request.user_data.clone_from_slice(user_data);
        // Define report-response:
        let mut response = ReportResponse::default();

        // Define the ioctl-context: unsafe: request & response cannot be moved
        let mut message = GuestRequestIoctl {
            // Version taken from AMD's sev-guest tooling.
            msg_version: 1,
            req_data: unsafe { get_addr(&mut request) },
            resp_data: unsafe { get_addr(&mut response) },
            exit_info: ExitInfo {
                fw_err: 0,
                vmm_err: 0,
            },
        };

        let res = SNP_GET_REPORT.ioctl(&mut device, &mut message);
        SevGuestErr::check_err(message.exit_info.fw_err, message.exit_info.vmm_err)?;

        // Non-negative return code indicates success.
        let _rc = res.map_err(SevGuestErr::IoctlErr)?;

        Ok(response)
    }
}

/// Retrieve a guest report with the given user data from the SEV-Guest ioctl
/// API. This tries both the upstream /dev/sev-guest path as well as the Azure
/// preview /dev/sev path, which use slightly different Ioctl parameters.
pub fn request_guest_report(
    user_data: &[u8; USER_DATA_SIZE],
) -> Result<Report, AttestationCoreErr> {
    // Try /dev/sev-guest (upstream) and then /dev/sev (preview) device paths:
    let report = if Path::new(upstream::DEVICE_PATH).exists() {
        upstream::request_report(user_data)?
    } else if Path::new(preview::DEVICE_PATH).exists() {
        preview::request_report(user_data)?
    } else {
        return Err(SevGuestErr::MissingGuestDevice.into());
    };
    // Check for firmware errors (Table 23 in the ABI Spec)
    if report.status != 0 {
        return Err(SevGuestErr::FirmwareError(report.status).into());
    }
    // Check to make sure the kernel is giving us a report size we expect:
    let actual_size = report.report_size.try_into().expect("u32 -> usize");
    if actual_size != REPORT_SIZE {
        return Err(AttestationCoreErr::InvalidBufferSize(
            REPORT_SIZE,
            actual_size,
        ));
    }
    // Cast it into the unverified report type:
    Report::try_from_slice(&report.attestation_report)
}

#[cfg(test)]
mod tests {
    use super::super::guest::SevGuestErr;

    // check_err must return Ok(()) when both codes are zero, so a clean
    // report isn't mistaken for a firmware/VMM failure.
    #[test]
    fn test_no_errors() {
        assert!(SevGuestErr::check_err(0, 0).is_ok());
    }

    // test for fw_error only (fw_err: non-zero hexadecimal code, vmm_err: 0). Return Err(SevGuestErr::SevGuestRequestError).
    #[test]
    fn test_fw_error_only() {
        let fw_error_code: u32 = 0x000B; // corresponds to SEV_RET_BAD_MEASUREMENT error code, this is just an example
        let parsed_error = SevGuestErr::create_err(fw_error_code, 0);
        assert!(
            matches!(parsed_error, SevGuestErr::SevGuestRequestError(_, fw_code, vmm_code) if fw_code == fw_error_code && vmm_code == 0)
        )
    }

    // test for vmm_error only (fw_err: 0, vmm_err: 2). Return Err(SevGuestErr::SevGuestRequestError).
    #[test]
    fn test_vmm_error_only() {
        let vmm_error_code: u32 = 2; // This vmm_err corresponds to SNP_GUEST_VMM_ERR_BUSY (see sev-guest.h)
        let parsed_error = SevGuestErr::create_err(0, vmm_error_code);
        assert!(
            matches!(parsed_error, SevGuestErr::SevGuestRequestError(_, fw_code, vmm_code) if fw_code == 0 && vmm_code == vmm_error_code)
        )
    }

    // test for both fw_error and vmm_error (fw_err: 0x000B, vmm_err: 2). Return Err(SevGuestErr::SevGuestRequestError).
    #[test]
    fn test_fw_and_vmm_error() {
        let fw_error_code: u32 = 0x000B;
        let vmm_error_code: u32 = 2;
        let parsed_error = SevGuestErr::create_err(fw_error_code, vmm_error_code);
        assert!(
            matches!(parsed_error, SevGuestErr::SevGuestRequestError(_, fw_code, vmm_code) if fw_code == fw_error_code && vmm_code == vmm_error_code)
        )
    }
}
