//! Async TLS streams backed by BoringSSL
//!
//! This library is an implementation of TLS streams using BoringSSL for
//! negotiating the connection. Each TLS stream implements the `Read` and
//! `Write` traits to interact and interoperate with the rest of the futures I/O
//! ecosystem. Client connections initiated from this crate verify hostnames
//! automatically and by default.
//!
//! `tokio-boring` exports this ability through [`accept`] and [`connect`]. `accept` should
//! be used by servers, and `connect` by clients. These augment the functionality provided by the
//! [`boring`] crate, on which this crate is built. Configuration of TLS parameters is still
//! primarily done through the [`boring`] crate.
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use boring::error::ErrorStack;
use boring::ssl::{
    self, ConnectConfiguration, ErrorCode, MidHandshakeSslStream, ShutdownResult, SslAcceptor,
    SslRef,
};
use boring_sys as ffi;
use std::error::Error;
use std::fmt;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

mod async_callbacks;
mod bridge;

use self::bridge::AsyncStreamBridge;

pub use crate::async_callbacks::SslContextBuilderExt;
pub use boring::ssl::{
    AsyncPrivateKeyMethod, AsyncPrivateKeyMethodError, AsyncSelectCertError, BoxGetSessionFinish,
    BoxGetSessionFuture, BoxPrivateKeyMethodFinish, BoxPrivateKeyMethodFuture, BoxSelectCertFinish,
    BoxSelectCertFuture, ExDataFuture,
};

/// Asynchronously performs a client-side TLS handshake over the provided stream.
///
/// This function automatically sets the task waker on the `Ssl` from `config` to
/// allow to make use of async callbacks provided by the boring crate.
pub fn connect<S>(
    config: ConnectConfiguration,
    domain: &str,
    stream: S,
) -> Result<HandshakeFuture<S>, ErrorStack>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(|s| config.setup_connect(domain, s), stream)
}

/// Asynchronously performs a server-side TLS handshake over the provided stream.
///
/// This function automatically sets the task waker on the `Ssl` from `config` to
/// allow to make use of async callbacks provided by the boring crate.
pub fn accept<S>(acceptor: &SslAcceptor, stream: S) -> Result<HandshakeFuture<S>, ErrorStack>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(|s| acceptor.setup_accept(s), stream)
}

fn handshake<S>(
    f: impl FnOnce(
        AsyncStreamBridge<S>,
    ) -> Result<MidHandshakeSslStream<AsyncStreamBridge<S>>, ErrorStack>,
    stream: S,
) -> Result<HandshakeFuture<S>, ErrorStack>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ongoing_handshake = Some(f(AsyncStreamBridge::new(stream))?);

    Ok(HandshakeFuture(ongoing_handshake))
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
    }
}

/// A partially constructed `SslStream`, useful for unusual handshakes.
pub struct SslStreamBuilder<S> {
    inner: ssl::SslStreamBuilder<AsyncStreamBridge<S>>,
}

impl<S> SslStreamBuilder<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Begins creating an `SslStream` atop `stream`.
    pub fn new(ssl: ssl::Ssl, stream: S) -> Self {
        Self {
            inner: ssl::SslStreamBuilder::new(ssl, AsyncStreamBridge::new(stream)),
        }
    }

    /// Initiates a client-side TLS handshake.
    pub async fn accept(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mid_handshake = self.inner.setup_accept();

        HandshakeFuture(Some(mid_handshake)).await
    }

    /// Initiates a server-side TLS handshake.
    pub async fn connect(self) -> Result<SslStream<S>, HandshakeError<S>> {
        let mid_handshake = self.inner.setup_connect();

        HandshakeFuture(Some(mid_handshake)).await
    }
}

impl<S> SslStreamBuilder<S> {
    /// Returns a shared reference to the `Ssl` object associated with this builder.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.inner.ssl()
    }

    /// Returns a mutable reference to the `Ssl` object associated with this builder.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.inner.ssl_mut()
    }
}

/// A wrapper around an underlying raw stream which implements the SSL
/// protocol.
///
/// A `SslStream<S>` represents a handshake that has been completed successfully
/// and both the server and the client are ready for receiving and sending
/// data. Bytes read from a `SslStream` are decrypted from `S` and bytes written
/// to a `SslStream` are encrypted when passing through to `S`.
#[derive(Debug)]
pub struct SslStream<S>(ssl::SslStream<AsyncStreamBridge<S>>);

impl<S> SslStream<S> {
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    #[must_use]
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    /// Returns a mutable reference to the `Ssl` object associated with this stream.
    pub fn ssl_mut(&mut self) -> &mut SslRef {
        self.0.ssl_mut()
    }

    /// Returns a shared reference to the underlying stream.
    #[must_use]
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    fn run_in_context<F, R>(&mut self, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut ssl::SslStream<AsyncStreamBridge<S>>) -> R,
    {
        self.0.get_mut().set_waker(Some(ctx));

        let result = f(&mut self.0);

        // NOTE(nox): This should also be executed when `f` panics,
        // but it's not that important as boring segfaults on panics
        // and we always set the context prior to doing anything with
        // the inner async stream.
        self.0.get_mut().set_waker(None);

        result
    }
}

impl<S> SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Constructs an `SslStream` from a pointer to the underlying OpenSSL `SSL` struct.
    ///
    /// This is useful if the handshake has already been completed elsewhere.
    ///
    /// # Safety
    ///
    /// The caller must ensure the pointer is valid.
    pub unsafe fn from_raw_parts(ssl: *mut ffi::SSL, stream: S) -> Self {
        Self(ssl::SslStream::from_raw_parts(
            ssl,
            AsyncStreamBridge::new(stream),
        ))
    }
}

impl<S> AsyncRead for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        self.run_in_context(ctx, |s| {
            // SAFETY: read_uninit does not de-initialize the buffer.
            match cvt(s.read_uninit(unsafe { buf.unfilled_mut() }))? {
                Poll::Ready(nread) => {
                    unsafe {
                        buf.assume_init(nread);
                    }
                    buf.advance(nread);
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }
}

impl<S> AsyncWrite for SslStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.run_in_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.run_in_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match self.run_in_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent | ShutdownResult::Received) => {}
            Err(ref e) if e.code() == ErrorCode::ZERO_RETURN => {}
            Err(ref e) if e.code() == ErrorCode::WANT_READ || e.code() == ErrorCode::WANT_WRITE => {
                return Poll::Pending;
            }
            Err(e) => {
                return Poll::Ready(Err(e.into_io_error().unwrap_or_else(io::Error::other)));
            }
        }

        Pin::new(&mut self.0.get_mut().stream).poll_shutdown(ctx)
    }
}

/// The error type returned after a failed handshake.
pub struct HandshakeError<S>(MidHandshakeSslStream<AsyncStreamBridge<S>>);

impl<S> HandshakeError<S> {
    /// Returns a shared reference to the `Ssl` object associated with this error.
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    /// Converts error to the source data stream that was used for the handshake.
    pub fn into_source_stream(self) -> S {
        self.0.into_source_stream().stream
    }

    /// Returns a reference to the source data stream.
    pub fn as_source_stream(&self) -> &S {
        &self.0.get_ref().stream
    }

    /// Returns the error code, if any.
    pub fn code(&self) -> ErrorCode {
        self.0.error().code()
    }

    /// Returns a reference to the inner I/O error, if any.
    #[must_use]
    pub fn as_io_error(&self) -> Option<&io::Error> {
        self.0.error().io_error()
    }
}

impl<S> fmt::Debug for HandshakeError<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, fmt)
    }
}

impl<S> fmt::Display for HandshakeError<S> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.display_error().fmt(fmt)
    }
}

impl<S> Error for HandshakeError<S>
where
    S: fmt::Debug,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.error().source()
    }
}

/// Future for an ongoing TLS handshake.
///
/// See [`connect`] and [`accept`].
pub struct HandshakeFuture<S>(Option<MidHandshakeSslStream<AsyncStreamBridge<S>>>);

impl<S> Future for HandshakeFuture<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<SslStream<S>, HandshakeError<S>>;

    fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut mid_handshake = self.0.take().expect("future polled after completion");

        mid_handshake.get_mut().set_waker(Some(ctx));
        mid_handshake
            .ssl_mut()
            .set_task_waker(Some(ctx.waker().clone()));

        match mid_handshake.handshake() {
            Ok(mut stream) => {
                stream.get_mut().set_waker(None);
                stream.ssl_mut().set_task_waker(None);

                Poll::Ready(Ok(SslStream(stream)))
            }
            Err(mut mid_handshake) if mid_handshake.error().would_block() => {
                mid_handshake.get_mut().set_waker(None);
                mid_handshake.ssl_mut().set_task_waker(None);

                self.0 = Some(mid_handshake);

                Poll::Pending
            }
            Err(mut mid_handshake) => {
                mid_handshake.get_mut().set_waker(None);

                Poll::Ready(Err(HandshakeError(mid_handshake)))
            }
        }
    }
}
