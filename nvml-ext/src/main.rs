/* Copyright (c) Fortanix, Inc.
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{self, IsTerminal, Read, Write};
use std::process::ExitCode;

use attestation::nvidia::evidence::get_nvidia_evidence_in_process;

fn collect_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let mut stdin = io::stdin().lock();
    if stdin.is_terminal() {
        return Err("pipe a raw 32-byte attestation nonce into stdin".into());
    }

    let mut nonce = [0u8; 32];
    stdin.read_exact(&mut nonce)?;
    let evidence = get_nvidia_evidence_in_process(&nonce)?;

    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &evidence)?;
    writeln!(stdout)?;
    stdout.flush()?;
    Ok(())
}

fn main() -> ExitCode {
    match collect_evidence() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("nvml-ext: {error}");
            ExitCode::FAILURE
        }
    }
}
