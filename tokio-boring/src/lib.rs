//! Async TLS streams backed by BoringSSL
//!
//! This library is an implementation of TLS streams using BoringSSL for
//! negotiating the connection. Each TLS stream implements the `Read` and
//! `Write` traits to interact and interoperate with the rest of the futures I/O
//! ecosystem. Client connections initiated from this crate verify hostnames
//! automatically and by default.
//!
//! This crate primarily exports this ability through two extension traits,
//! `SslConnectorExt` and `SslAcceptorExt`. These traits augment the
//! functionality provided by the [`boring` crate](https://github.com/cloudflare/boring) crate,
//! on which this crate is built. Configuration of TLS parameters is still primarily done through
//! the [`boring` crate](https://github.com/cloudflare/boring)
#![warn(missing_docs)]

use boring::ssl::{
    self, ConnectConfiguration, MidHandshakeSslStream, ShutdownResult, SslAcceptor, SslRef,
};
use boring_sys as ffi;
use std::fmt;
use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub use boring::ssl::HandshakeError;

/// Asynchronously performs a client-side TLS handshake over the provided stream.
pub async fn connect<S>(
    config: ConnectConfiguration,
    domain: &str,
    stream: S,
) -> Result<SslStream<S>, HandshakeError<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(|s| config.connect(domain, s), stream).await
}

/// Asynchronously performs a server-side TLS handshake over the provided stream.
pub async fn accept<S>(acceptor: &SslAcceptor, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(|s| acceptor.accept(s), stream).await
}

async fn handshake<F, S>(f: F, stream: S) -> Result<SslStream<S>, HandshakeError<S>>
where
    F: FnOnce(
            StreamWrapper<S>,
        ) -> Result<
            ssl::HandshakeStream<StreamWrapper<S>>,
            ssl::HandshakeError<StreamWrapper<S>>,
        > + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let start = StartHandshakeFuture(Some(StartHandshakeFutureInner { f, stream }));

    match start.await? {
        StartedHandshake::Done(s) => Ok(s),
        StartedHandshake::Mid(s) => HandshakeFuture(Some(s)).await,
    }
}

struct StreamWrapper<S> {
    stream: S,
    context: usize,
}

impl<S> StreamWrapper<S> {
    /// # Safety
    ///
    /// Must be called with `context` set to a valid pointer to a live `Context` object, and the
    /// wrapper must be pinned in memory.
    unsafe fn parts(&mut self) -> (Pin<&mut S>, &mut Context<'_>) {
        debug_assert_ne!(self.context, 0);
        let stream = Pin::new_unchecked(&mut self.stream);
        let context = &mut *(self.context as *mut _);
        (stream, context)
    }
}

impl<S> fmt::Debug for StreamWrapper<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}

impl<S> StreamWrapper<S>
where
    S: Unpin,
{
    fn with_context<F, R>(&mut self, f: F) -> R
    where
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> R,
    {
        unsafe {
            assert_ne!(self.context, 0);
            let waker = &mut *(self.context as *mut _);
            f(waker, Pin::new(&mut self.stream))
        }
    }
}

impl<S> Read for StreamWrapper<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let (stream, cx) = unsafe { self.parts() };
        let mut buf = ReadBuf::new(buf);
        match stream.poll_read(cx, &mut buf)? {
            Poll::Ready(()) => Ok(buf.filled().len()),
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

impl<S> Write for StreamWrapper<S>
where
    S: AsyncWrite + Unpin,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.with_context(|ctx, stream| stream.poll_write(ctx, buf)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.with_context(|ctx, stream| stream.poll_flush(ctx)) {
            Poll::Ready(r) => r,
            Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
        }
    }
}

fn cvt<T>(r: io::Result<T>) -> Poll<io::Result<T>> {
    match r {
        Ok(v) => Poll::Ready(Ok(v)),
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
        Err(e) => Poll::Ready(Err(e)),
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
pub struct SslStream<S>(ssl::SslStream<StreamWrapper<S>>);

impl<S> SslStream<S> {
    /// Returns a shared reference to the `Ssl` object associated with this stream.
    pub fn ssl(&self) -> &SslRef {
        self.0.ssl()
    }

    /// Returns a shared reference to the underlying stream.
    pub fn get_ref(&self) -> &S {
        &self.0.get_ref().stream
    }

    /// Returns a mutable reference to the underlying stream.
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.0.get_mut().stream
    }

    fn with_context<F, R>(&mut self, ctx: &mut Context<'_>, f: F) -> R
    where
        F: FnOnce(&mut ssl::SslStream<StreamWrapper<S>>) -> R,
    {
        self.0.get_mut().context = ctx as *mut _ as usize;
        let r = f(&mut self.0);
        self.0.get_mut().context = 0;
        r
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
        let stream = StreamWrapper { stream, context: 0 };
        SslStream(ssl::SslStream::from_raw_parts(ssl, stream))
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
        self.with_context(ctx, |s| {
            // This isn't really "proper", but rust-openssl doesn't currently expose a suitable interface even though
            // OpenSSL itself doesn't require the buffer to be initialized. So this is good enough for now.
            let slice = unsafe {
                let buf = buf.unfilled_mut();
                std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast::<u8>(), buf.len())
            };
            match cvt(s.read(slice))? {
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
        self.with_context(ctx, |s| cvt(s.write(buf)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        self.with_context(ctx, |s| cvt(s.flush()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context) -> Poll<io::Result<()>> {
        match self.with_context(ctx, |s| s.shutdown()) {
            Ok(ShutdownResult::Sent) | Ok(ShutdownResult::Received) => {
                Pin::new(&mut self.0.get_mut().stream).poll_shutdown(ctx)
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

enum StartedHandshake<S> {
    Done(SslStream<S>),
    Mid(MidHandshakeSslStream<StreamWrapper<S>>),
}

struct StartHandshakeFuture<F, S>(Option<StartHandshakeFutureInner<F, S>>);

struct StartHandshakeFutureInner<F, S> {
    f: F,
    stream: S,
}

impl<F, S> Future for StartHandshakeFuture<F, S>
where
    F: FnOnce(
            StreamWrapper<S>,
        ) -> Result<
            ssl::HandshakeStream<StreamWrapper<S>>,
            ssl::HandshakeError<StreamWrapper<S>>,
        > + Unpin,
    S: Unpin,
{
    type Output = Result<StartedHandshake<S>, HandshakeError<S>>;

    fn poll(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<StartedHandshake<S>, HandshakeError<S>>> {
        let inner = self.0.take().expect("future polled after completion");

        let stream = StreamWrapper {
            stream: inner.stream,
            context: ctx as *mut _ as usize,
        };
        match (inner.f)(stream) {
            Ok(ssl::HandshakeStream::Done(mut s)) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(StartedHandshake::Done(SslStream(s))))
            }
            Ok(ssl::HandshakeStream::Mid(mut s)) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(StartedHandshake::Mid(s)))
            }
            Err(e) => {
                let (stream, error) = e.into_parts();
                Poll::Ready(Err(HandshakeError::new(stream.stream, error)))
            }
        }
    }
}

struct HandshakeFuture<S>(Option<MidHandshakeSslStream<StreamWrapper<S>>>);

impl<S> Future for HandshakeFuture<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<SslStream<S>, HandshakeError<S>>;

    fn poll(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
    ) -> Poll<Result<SslStream<S>, HandshakeError<S>>> {
        let mut s = self.0.take().expect("future polled after completion");

        s.get_mut().context = ctx as *mut _ as usize;
        match s.handshake() {
            Ok(ssl::HandshakeStream::Done(mut s)) => {
                s.get_mut().context = 0;
                Poll::Ready(Ok(SslStream(s)))
            }
            Ok(ssl::HandshakeStream::Mid(mut s)) => {
                s.get_mut().context = 0;
                self.0 = Some(s);
                Poll::Pending
            }
            Err(e) => {
                let (wrapper, error) = e.into_parts();
                Poll::Ready(Err(HandshakeError::new(wrapper.stream, error)))
            }
        }
    }
}
