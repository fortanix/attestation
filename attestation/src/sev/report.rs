/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Display, Formatter};

use super::{try_init_from_slice_copy, AttestationCoreErr};

/// This is the amount of bytes that we can provide to the report request to be
/// signed by the hardware keys.
pub const USER_DATA_SIZE: usize = 64;
/// The REPORT_SIZE is useful internally, to allocate enough space for a report.
pub const REPORT_SIZE: usize = size_of::<Report>();

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct AbiVersion {
    major: u8,
    minor: u8,
}

impl AbiVersion {
    pub fn new(major: u8, minor: u8) -> AbiVersion {
        AbiVersion { major, minor }
    }

    pub fn major(&self) -> u8 {
        self.major
    }

    pub fn minor(&self) -> u8 {
        self.minor
    }

    pub fn is_compatible_with(&self, other: Self) -> bool {
        self.major == other.major && self.minor <= other.minor
    }
}

impl Display for AbiVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Bitfield that encodes features about the guest itself.
#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(transparent)]
pub struct GuestPolicy(u64);
impl GuestPolicy {
    /// Guest policy to disable Guest access to SNP_PAGE_MOVE, SNP_SWAP_OUT, and SNP_SWAP_IN commands. If this policy
    /// option is selected to disable these Page Move commands, then these commands will return POLICY_FAILURE.
    /// 0: Do not disable Guest support for the commands.
    /// 1: Disable Guest support for the commands.
    pub fn page_swap_disabled(&self) -> bool {
        self.0 & (1 << 25) > 0
    }

    /// True: 1: Ciphertext hiding for the DRAM must be enabled
    /// False: 0: Ciphertext hiding for the DRAM may be enabled or disabled
    pub fn ciphertext_hiding_dram(&self) -> bool {
        self.0 & (1 << 24) > 0
    }

    /// 0: Allow Running Average Power Limit (RAPL).
    /// 1: RAPL must be disabled.
    pub fn rapl_disabled(&self) -> bool {
        self.0 & (1 << 23) > 0
    }

    /// False: 0: Allow either AES 128 XEX or AES 256 XTS for memory encryption.
    /// True: 1: Require AES 256 XTS for memory encryption.
    pub fn mem_aes_256_xts(&self) -> bool {
        self.0 & (1 << 22) > 0
    }

    /// False: 0: CXL cannot be populated with devices or memory.
    /// True: 1: CXL can be populated with devices or memory.
    pub fn cxl_allow(&self) -> bool {
        self.0 & (1 << 21) > 0
    }

    /// This is also up to the platform owner.
    pub fn single_socket(&self) -> bool {
        self.0 & (1 << 20) > 0
    }
    /// If debugging is allowed, this policy is not Confidential Compute.
    pub fn debugging_allowed(&self) -> bool {
        self.0 & (1 << 19) > 0
    }
    /// AMD SEV-SNP provides a mechanism for migration; but this is up to the
    /// platform owner.
    pub fn migration_allowed(&self) -> bool {
        self.0 & (1 << 18) > 0
    }

    /// SMT is not allowed in AMD SEV-SNP, but this is up to the platform owner.
    pub fn smt_allowed(&self) -> bool {
        self.0 & (1 << 16) > 0
    }

    /// Return the Major/Minor ABI considered the minimum for this guest to run.
    pub fn minimum_abi(&self) -> AbiVersion {
        let minor = (self.0 & 0xff) as u8;
        let major = ((self.0 >> 8) & 0xff) as u8;
        AbiVersion::new(major, minor)
    }
}

/// Build, (major, minor) of Firmware.
#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(C)]
#[repr(packed)]
pub struct FirmwareVersion {
    build: u8,
    minor: u8,
    major: u8,
    _reserved: u8,
}

impl FirmwareVersion {
    pub fn build(&self) -> u8 {
        self.build
    }

    pub fn minor(&self) -> u8 {
        self.minor
    }
    pub fn major(&self) -> u8 {
        self.major
    }
}

// Bit count begins at 0, Little-Endian order
// Bit 7: TIO_EN Indicates that SEV-TIO is enabled.
// Bit 6: Reserved.
// Bit 5: ALIAS_CHECK_COMPLETE
// Indicates that alias detection has completed since the
// last system reset and there are no aliasing addresses.
// Resets to 0.
// Contains mitigation for CVE-2024-21944.
// Bit 4: CIPHERTEXT_HIDING_DRAM_EN
// Indicates ciphertext hiding is enabled for the DRAM.
// Bit 3: RAPL_DIS Indicates that the RAPL feature is disabled.
// Bit 2: ECC_EN Indicates that the platform is using error correcting
// codes for memory.
// Present when EccMemReporting feature bit is set.
// Bit 1: TSME_EN Indicates that TSME is enabled in the system.
// Bit 0: SMT_EN Indicates that SMT is enabled in the system.

/// Bitfield in [`VerifiedReport`] that encodes features of the platform.
///
/// Not using a real bitfield since there's only two fields in use right now,
/// and it's effectively read-only in an attestation report.
#[derive(PartialEq, Eq, Clone, Debug)]
#[repr(transparent)]
pub struct PlatformInfo(pub u64);
impl PlatformInfo {
    /// AMD Simultaneous Multithreading (SMT)
    pub fn smt_enabled(&self) -> bool {
        self.0 & (1 << 0) > 0
    }

    /// Transparent Secure Memory Encryption
    pub fn tsme_enabled(&self) -> bool {
        self.0 & (1 << 1) > 0
    }

    /// Error Correcting Codes; Present when EccMemReporting feature bit is set
    pub fn ecc_enabled(&self) -> bool {
        self.0 & (1 << 2) > 0
    }

    /// Indicates that the RAPL feature is disabled.
    pub fn rapl_disabled(&self) -> bool {
        self.0 & (1 << 3) > 0
    }

    /// Indicates ciphertext hiding is enabled for the DRAM.
    pub fn ciphertext_hiding_dram_enabled(&self) -> bool {
        self.0 & (1 << 4) > 0
    }

    /// Indicates that alias detection has completed since the last
    /// system reset and there are no aliasing addresses. Resets to 0.
    /// Contains mitigation for CVE-2024-21944.
    pub fn alias_check_complete(&self) -> bool {
        self.0 & (1 << 5) > 0
    }

    // Bit 6 is reserved

    /// Indicates that SEV-TIO (Trusted I/O) is enabled.
    pub fn sev_tio_enabled(&self) -> bool {
        self.0 & (1 << 7) > 0
    }
}

/// VMPL Permission Mask (See Sec Table 69 - https://docs.amd.com/v/u/en-US/56860)
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u32)]
pub enum VMPL {
    ZERO = 0,
    ONE = 1,
    TWO = 2,
    THREE = 3,
    // Host variant is only available in report version 2
    HOST = 0xffffffff,
}

/// Signing key of the attestation report
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SigningKey {
    Vcek,
    Vlek,
    Reserved,
    NotSigned,
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(C)]
pub struct KeyUsageInfo(u32);

impl KeyUsageInfo {
    pub fn author_key_enabled(&self) -> bool {
        self.0 & (1 << 0) != 0
    }

    pub fn mask_chip_key(&self) -> bool {
        self.0 & (1 << 1) != 0
    }

    pub fn signing_key(&self) -> SigningKey {
        match (self.0 >> 2) & 0x7 {
            0 => SigningKey::Vcek,
            1 => SigningKey::Vlek,
            7 => SigningKey::NotSigned,
            _ => SigningKey::Reserved,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TCBVersion {
    /// SPL(Security Patch Level) of FMC firmware. This only is present on Turin platforms
    pub fmc: Option<u8>,
    /// Boot Loader version
    pub boot_loader: u8,
    /// Trusted Execution Environment version.
    pub tee: u8,
    /// SNP Firmware Version.
    pub snp: u8,
    /// CPU Microcode Version.
    pub microcode: u8,
}

impl TCBVersion {
    pub fn new(boot_loader: u8, tee: u8, snp: u8, microcode: u8, fmc: Option<u8>) -> Self {
        TCBVersion {
            boot_loader,
            tee,
            snp,
            microcode,
            fmc,
        }
    }

    fn as_iter(&self) -> impl Iterator<Item = Option<u8>> {
        [
            Some(self.boot_loader),
            Some(self.tee),
            Some(self.snp),
            Some(self.microcode),
            self.fmc,
        ]
        .into_iter()
    }

    pub fn fmc(&self) -> Option<u8> {
        self.fmc
    }

    pub fn boot_loader(&self) -> u8 {
        self.boot_loader
    }

    pub fn tee(&self) -> u8 {
        self.tee
    }

    pub fn snp(&self) -> u8 {
        self.snp
    }

    pub fn microcode(&self) -> u8 {
        self.microcode
    }
}

impl PartialOrd for TCBVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let mut cmp_combined = Ordering::Equal;
        for (a, b) in self.as_iter().zip(other.as_iter()) {
            if a.is_some() != b.is_some() {
                // Invalid comparison of TCBVersions of different architectures
                return None;
            }

            let cmp_current = a.cmp(&b);
            match (cmp_combined, cmp_current) {
                // Ordering was equal, overwrite with current element
                (Ordering::Equal, _) => cmp_combined = cmp_current,
                // Conflicting orderings: no order possible
                (Ordering::Greater, Ordering::Less) | (Ordering::Less, Ordering::Greater) => {
                    return None
                }
                // Ordering was unequal and not conflicting, keep
                _ => {}
            }
        }
        Some(cmp_combined)
    }
}

#[derive(Clone, Copy, Hash, Eq, PartialEq)]
pub struct CpuId(pub u32);

impl fmt::Debug for CpuId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CpuId")
            .field(&format_args!("0x{:08x}", self.0))
            .finish()
    }
}

impl CpuId {
    /// See AMD64 Architecture Programmer’s Manual Volume 3: General-Purpose
    /// and System Instructions, Appendix E.3.2: CPUID Fn0000_0001_EAX Family,
    /// Model, Stepping Identifiers.
    ///
    /// Returns `None` if stepping is more than `0xf`
    pub const fn from_fms(family: u8, model: u8, stepping: u8) -> Option<Self> {
        let (family_hi, family_lo) = match family.checked_sub(0x0f) {
            Some(difference) => (difference as u32, 0x0f),
            None => (0, family as u32),
        };
        let model_hi = ((model >> 4) & 0x0f) as u32;
        let model_lo = (model & 0x0f) as u32;
        if stepping > 0xf {
            return None;
        }
        let stepping_lo = stepping as u32;
        Some(CpuId(
            (family_hi << 20) | (model_hi << 16) | (family_lo << 8) | (model_lo << 4) | stepping_lo,
        ))
    }
}

/// As of Aug. 2022 there's only one valid SignatureAlgorithm, but let's leave
/// room for more.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum SignatureAlgorithm {
    EcdsaP384WithSha384 = 0x1,
    // all other reserved
}

/// Extract enum value from numeric signature: Table 105 in SEV SNP spec.
/// The u32 reflects the width of the field in the attestation report rather
/// than a reasonable bound on the number of algorithms to support in the
/// future, but perhaps there may be parameters in the other 31 bits.
impl TryFrom<u32> for SignatureAlgorithm {
    type Error = AttestationCoreErr;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::EcdsaP384WithSha384),
            other => Err(AttestationCoreErr::UnsupportedSignatureAlgo(other)),
        }
    }
}

/// AMD SEV-SNP Attestation Report defined in [AMD's SEV Secure Nested Paging Firmware ABI Specification](https://www.amd.com/content/dam/amd/en/documents/developer/56860.pdf), Table 21.
#[derive(Debug, PartialEq, Eq, Clone)]
#[repr(C)]
pub struct Report {
    /// Version number of attestation report; AMD specification defines this to
    /// be equal to 2 or 3.
    pub version: u32,
    pub guest_svn: u32,
    pub policy: GuestPolicy,
    /// Guest ID parameter.
    pub family_id: [u8; 16],
    /// Guest ID parameter.
    pub image_id: [u8; 16],
    /// VMPL Permission Mask used to generate this report.
    /// Expect this to be < 3.
    /// Support for VMPL::Host was added in VerifiedReport::Version = 3
    pub vmpl: VMPL,
    /// The signature algorithm used see [`SignatureAlgorithm`] enum.
    pub signature_algo: u32,
    /// This set of versions is influenced by the most recently downloaded
    /// firmware, but may be rolled back to committed_tcb.
    pub current_tcb: [u8; 8],
    pub platform_info: PlatformInfo,
    pub key_usage_info: KeyUsageInfo,
    /// Reserved field at 0x4c, must be zero
    pub _reserved0: u32,
    /// Guest-provided report data:
    pub report_data: [u8; 64],
    /// The measurement calculated at launch.
    pub measurement: [u8; 48],
    /// Data provided by the hypervisor at launch; on ACI this is the sha256sum
    /// of the JSON inside a policy.
    pub host_data: [u8; 32],
    /// sha-384 digest of ID public key that signed the ID block provided in
    /// SNP_LAUNCH_FINISH.
    pub id_key_digest: [u8; 48],
    /// sha-384 digest of Author public key that certified the ID key, if
    /// provided in SNP_LAUNCH_FINISH; zeros if author_key_en is 1.
    pub author_key_digest: [u8; 48],
    /// Report ID of this guest.
    pub report_id: [u8; 32],
    /// Report ID of this guest's migration agent:
    pub report_id_ma: [u8; 32],
    /// Reported TCB version used to derive VCEK that signed the report.
    pub reported_tcb: [u8; 8],
    /// Family ID (Combined Extended Family ID and Family ID
    /// Only available for VerifiedReport version 3
    pub cpuid_fam_id: u8,
    /// Model (combined Extended Model and Model fields
    /// Only available for VerifiedReport version 3
    pub cpuid_mod_id: u8,
    /// Stepping
    /// Only available for VerifiedReport version 3
    pub cpuid_step: u8,
    /// Reserved; need not be zero.
    pub _reserved1: [u8; 21],
    /// If MaskChipId is set to zero, identifier unique to chip; else set to 0.
    pub chip_id: [u8; 64],
    // SNP_COMMIT accepts the current firmware from current_tcb.
    pub committed_tcb: [u8; 8],

    /// Current firmware build, major and minor ids.
    pub current: FirmwareVersion,
    /// Committed SEV-SNP firmware build, major, and minor ids:
    pub committed: FirmwareVersion,

    /// The current_tcb at the time the guest was launched or imported.
    pub launch_tcb: [u8; 8],
    /// The verified mitigation vector value at the time the guest was launched (LaunchMitVector).
    pub launch_mitigation_vector: u64,
    /// Value is set to the current verified mitigation vector value (CurrentMitVector).
    pub current_mitigation_vector: u64,

    /// Reserved space; need not be zero.
    pub _reserved2: [u8; 152],

    pub signature: [u8; 512],
}

impl Report {
    #[cfg(all(feature = "sev-guest", not(target_env = "sgx")))]
    pub fn request(user_data: &[u8; USER_DATA_SIZE]) -> Result<Report, AttestationCoreErr> {
        super::guest::request_guest_report(user_data)
    }

    /// Try to construct a report structure from a slice; will error if it is an
    /// inappropriate size.
    pub fn try_from_slice(data: &[u8]) -> Result<Self, AttestationCoreErr> {
        unsafe { try_init_from_slice_copy(data) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts(
                (self as *const Report) as *const u8,
                size_of::<[u8; REPORT_SIZE]>(),
            )
        }
    }

    /// Write this report structure to an output stream.
    pub fn write<W: std::io::Write>(&self, out: &mut W) -> std::io::Result<()> {
        out.write_all(self.as_slice())
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn chip_id(&self) -> Option<&[u8; 64]> {
        if !self.key_usage_info.mask_chip_key() {
            Some(&self.chip_id)
        } else {
            None
        }
    }

    pub fn policy(&self) -> &GuestPolicy {
        &self.policy
    }

    pub fn report_data(&self) -> &[u8; 64] {
        &self.report_data
    }

    pub fn host_data(&self) -> &[u8; 32] {
        &self.host_data
    }

    pub fn current_raw_tcb(&self) -> [u8; 8] {
        self.current_tcb
    }

    pub fn reported_raw_tcb(&self) -> [u8; 8] {
        self.reported_tcb
    }

    pub fn committed_raw_tcb(&self) -> [u8; 8] {
        self.committed_tcb
    }

    pub fn launch_raw_tcb(&self) -> [u8; 8] {
        self.launch_tcb
    }

    pub fn launch_mitigation_vector(&self) -> u64 {
        self.launch_mitigation_vector
    }

    pub fn current_mitigation_vector(&self) -> u64 {
        self.current_mitigation_vector
    }

    pub fn vmpl(&self) -> &VMPL {
        &self.vmpl
    }

    pub fn guest_svn(&self) -> u32 {
        self.guest_svn
    }

    pub fn cpuid_fam_id(&self) -> Result<u8, AttestationCoreErr> {
        if self.version <= 2 {
            return Err(AttestationCoreErr::ReportVerificationError(
                "CPUID Family ID is not supported for this report version".into(),
            ));
        }

        Ok(self.cpuid_fam_id)
    }

    pub fn cpuid_mod_id(&self) -> Result<u8, AttestationCoreErr> {
        if self.version <= 2 {
            return Err(AttestationCoreErr::ReportVerificationError(
                "CPUID Model ID is not supported for this report version".into(),
            ));
        }

        Ok(self.cpuid_mod_id)
    }

    pub fn cpuid_step(&self) -> Result<u8, AttestationCoreErr> {
        if self.version <= 2 {
            return Err(AttestationCoreErr::ReportVerificationError(
                "CPUID Step is not supported for this report version".into(),
            ));
        }

        Ok(self.cpuid_step)
    }

    pub fn cpuid(&self) -> Result<CpuId, AttestationCoreErr> {
        let family = self.cpuid_fam_id()?;
        let model = self.cpuid_mod_id()?;
        let step = self.cpuid_step()?;
        let cpuid = CpuId::from_fms(family, model, step).ok_or(
            AttestationCoreErr::ReportVerificationError(format!(
                "Unable to get cpuid from family: 0x{:x}, model: 0x{:x}, step: 0x{:x}",
                family, model, step,
            )),
        )?;
        Ok(cpuid)
    }

    /// Extract the signature algorithm from the report contents.
    pub fn signature_algorithm(&self) -> Result<SignatureAlgorithm, AttestationCoreErr> {
        // convert to an algorithm; only one possibility for now.
        SignatureAlgorithm::try_from(self.signature_algo)
            .map_err(|_| AttestationCoreErr::UnsupportedSignatureAlgo(self.signature_algo))
    }

    /// Access the 'measurement' field; we may want to peek at this so we can query to see
    /// if a build was even registered with this hash.
    pub fn claimed_measurement(&self) -> &[u8; 48] {
        &self.measurement
    }
}
