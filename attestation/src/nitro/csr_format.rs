/* Copyright (c) Fortanix, Inc.
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
 * You can obtain one at http://mozilla.org/MPL/2.0/. */

use once_cell::sync::Lazy;
use pkix::types::ObjectIdentifier;

/// CSR attribute containing the Nitro attestation document.
pub static NITRO_ATTESTATION_OID: Lazy<ObjectIdentifier> =
    Lazy::new(|| vec![1, 3, 6, 1, 4, 1, 49690, 2, 2, 6].into());
