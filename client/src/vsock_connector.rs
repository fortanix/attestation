/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Creating a wrapper for VsockStream here that is acceptable to hyper v0.10.
// This is the version of hyper used in em-node-agent-client. This older version
// of hyper doesn't accept VsockStream directly and requires us to implement
// NetworkStream and NetworkConnector
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr};
use std::time::Duration;

use hyper::net::{NetworkConnector, NetworkStream};
use vsock::{VsockAddr, VsockStream};

use crate::DEFAULT_NODE_AGENT_VSOCK_CID;

#[derive(Debug, Clone, Default)]
pub struct VsockConnector;

#[derive(Debug)]
pub struct HyperVsockStream(VsockStream);

impl Read for HyperVsockStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for HyperVsockStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl NetworkStream for HyperVsockStream {
    fn peer_addr(&mut self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(dur)
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(dur)
    }

    fn close(&mut self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(match how {
            Shutdown::Read => std::net::Shutdown::Read,
            Shutdown::Write => std::net::Shutdown::Write,
            Shutdown::Both => std::net::Shutdown::Both,
        })
    }
}

impl NetworkConnector for VsockConnector {
    type Stream = HyperVsockStream;

    fn connect(&self, _host: &str, port: u16, scheme: &str) -> hyper::Result<Self::Stream> {
        if scheme != "http" {
            return Err(hyper::Error::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VsockConnector only supports http scheme",
            )));
        }

        let addr = VsockAddr::new(DEFAULT_NODE_AGENT_VSOCK_CID, port as u32);
        let stream = VsockStream::connect(&addr).map_err(hyper::Error::Io)?;
        Ok(HyperVsockStream(stream))
    }
}
