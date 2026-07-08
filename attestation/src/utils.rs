/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub fn compute_sha256(data: &[u8]) -> mbedtls::Result<[u8; 32]> {
    use mbedtls::hash::{Md, Type};
    let mut output = [0u8; 32];
    let _ = Md::hash(Type::Sha256, data, &mut output)?;
    Ok(output)
}
