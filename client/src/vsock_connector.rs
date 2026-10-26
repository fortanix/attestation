/* Copyright (c) Fortanix, Inc.
|*
|* This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
|* the MPL was not distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. */

// Creating a wrapper for VsockStream here that is acceptable to simple-hyper-client=0.4.0
// This is the version of hyper used in em-node-agent-client. This version
// of hyper doesn't accept VsockStream directly and requires us to implement
// NetworkStream and NetworkConnector
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use simple_hyper_client::compat::{Connected, Connection};
use simple_hyper_client::{NetworkConnection, NetworkConnector, Uri};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_vsock::{VsockAddr, VsockStream};

use crate::DEFAULT_NODE_AGENT_VSOCK_CID;

#[derive(Debug, Clone, Default)]
pub struct VsockConnector;

#[derive(Debug)]
pub struct HyperVsockStream(VsockStream);

impl Connection for HyperVsockStream {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl AsyncRead for HyperVsockStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for HyperVsockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl NetworkConnector for VsockConnector {
    fn connect(
        &self,
        uri: Uri,
    ) -> Pin<Box<dyn Future<Output = Result<NetworkConnection, Box<dyn Error + Send + Sync>>> + Send>>
    {
        Box::pin(async move {
            if uri.scheme_str() != Some("http") {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "VsockConnector only supports http scheme",
                )
                .into());
            }

            let port = u32::from(uri.port_u16().unwrap_or(80));
            let addr = VsockAddr::new(DEFAULT_NODE_AGENT_VSOCK_CID, port);
            let stream = VsockStream::connect(addr).await?;

            Ok(NetworkConnection::new(HyperVsockStream(stream)))
        })
    }
}
