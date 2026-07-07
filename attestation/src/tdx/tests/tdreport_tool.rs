use attestation::tdx::{AttestationErr, TdxReportType, TdxReportVersion1};
use std::fs;

fn main() -> Result<(), AttestationErr> {
    let report_data = [0u8; 64];
    let report = TdxReportVersion1::generate_report(&report_data)?;
    fs::write("tdreport.bin", &report).expect("failed to write tdreport.bin");
    println!("TDREPORT saved to tdreport.bin");

    Ok(())
}
