//! Bridge between sync IO traits and async tokio IO traits.
use std::fmt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct AsyncStreamBridge<S> {
    pub(crate) stream: S,
    waker: Option<Waker>,
}

impl<S> AsyncStreamBridge<S> {
    pub(crate) fn new(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        Self {
            stream,
            waker: None,
        }
    }

    pub(crate) fn set_waker(&mut self, ctx: Option<&mut Context<'_>>) {
        self.waker = ctx.map(|ctx| ctx.waker().clone())
    }

    /// # Panics
    ///
    /// Panics if the bridge has no waker.
    pub(crate) fn with_context<F, R>(&mut self, f: F) -> R
    where
        S: Unpin,
        F: FnOnce(&mut Context<'_>, Pin<&mut S>) -> R,
    {
        let mut ctx =
            Context::from_waker(self.waker.as_ref().expect("BUG: missing waker in bridge"));

        f(&mut ctx, Pin::new(&mut self.stream))
    }
}

impl<S> io::Read for AsyncStreamBridge<S>
where
    S: AsyncRead + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.with_context(|ctx, stream| {
            let mut buf = ReadBuf::new(buf);

            match stream.poll_read(ctx, &mut buf)? {
                Poll::Ready(()) => Ok(buf.filled().len()),
                Poll::Pending => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            }
        })
    }
}

impl<S> io::Write for AsyncStreamBridge<S>
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

impl<S> fmt::Debug for AsyncStreamBridge<S>
where
    S: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.stream, fmt)
    }
}
