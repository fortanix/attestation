/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub mod model;
pub use model::*;

#[cfg(feature = "tdx-guest")]
pub mod guest;

#[cfg(feature = "tdx-guest")]
pub use guest::*;

