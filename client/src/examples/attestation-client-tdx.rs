/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

mod common;

use client::error::Result;
use client::BaremetalTdx;
use common::run_client;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    run_client::<BaremetalTdx>()
}
