use std::{
    fmt,
    io::{self, IoSlice},
    pin::Pin,
    task::{Context, Poll},
};

use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::{
    client::legacy::connect::{Connected, Connection},
    rt::TokioIo,
};
use tokio_boring::SslStream;

/// A stream which may be wrapped with TLS.
pub enum MaybeHttpsStream<T> {
    /// A raw HTTP stream.
    Http(T),
    /// An SSL-wrapped HTTP stream.
    Https(TokioIo<SslStream<TokioIo<T>>>),
}

// ===== impl MaybeHttpsStream =====

impl<T> fmt::Debug for MaybeHttpsStream<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            MaybeHttpsStream::Http(..) => f.pad("Http(..)"),
            MaybeHttpsStream::Https(..) => f.pad("Https(..)"),
        }
    }
}

impl<T> From<T> for MaybeHttpsStream<T> {
    fn from(inner: T) -> Self {
        MaybeHttpsStream::Http(inner)
    }
}

impl<T> From<SslStream<TokioIo<T>>> for MaybeHttpsStream<T> {
    fn from(inner: SslStream<TokioIo<T>>) -> Self {
        MaybeHttpsStream::Https(TokioIo::new(inner))
    }
}

impl<T> From<TokioIo<SslStream<TokioIo<T>>>> for MaybeHttpsStream<T> {
    fn from(inner: TokioIo<SslStream<TokioIo<T>>>) -> Self {
        MaybeHttpsStream::Https(inner)
    }
}

impl<T: Read + Write + Unpin> Read for MaybeHttpsStream<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_read(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl<T: Write + Read + Unpin> Write for MaybeHttpsStream<T> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write(cx, buf),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeHttpsStream::Http(s) => s.is_write_vectored(),
            MaybeHttpsStream::Https(s) => s.is_write_vectored(),
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_flush(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_flush(cx),
        }
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        match Pin::get_mut(self) {
            MaybeHttpsStream::Http(s) => Pin::new(s).poll_shutdown(cx),
            MaybeHttpsStream::Https(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

impl<T: Write + Read + Connection + Unpin> Connection for MaybeHttpsStream<T> {
    fn connected(&self) -> Connected {
        match self {
            MaybeHttpsStream::Http(s) => s.connected(),
            MaybeHttpsStream::Https(s) => {
                let c = s.inner().get_ref().inner().connected();
                if s.inner().ssl().selected_alpn_protocol() == Some(b"h2") {
                    c.negotiated_h2()
                } else {
                    c
                }
            }
        }
    }
}
