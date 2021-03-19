use ffi;
use libc::c_int;
use std::error;
use std::error::Error as StdError;
use std::fmt;
use std::io;

use error::ErrorStack;

/// An error code returned from SSL functions.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ErrorCode(c_int);

impl ErrorCode {
    /// The SSL session has been closed.
    pub const ZERO_RETURN: ErrorCode = ErrorCode(ffi::SSL_ERROR_ZERO_RETURN);

    /// An attempt to read data from the underlying socket returned `WouldBlock`.
    ///
    /// Wait for read readiness and retry the operation.
    pub const WANT_READ: ErrorCode = ErrorCode(ffi::SSL_ERROR_WANT_READ);

    /// An attempt to write data to the underlying socket returned `WouldBlock`.
    ///
    /// Wait for write readiness and retry the operation.
    pub const WANT_WRITE: ErrorCode = ErrorCode(ffi::SSL_ERROR_WANT_WRITE);

    /// A non-recoverable IO error occurred.
    pub const SYSCALL: ErrorCode = ErrorCode(ffi::SSL_ERROR_SYSCALL);

    /// An error occurred in the SSL library.
    pub const SSL: ErrorCode = ErrorCode(ffi::SSL_ERROR_SSL);

    pub fn from_raw(raw: c_int) -> ErrorCode {
        ErrorCode(raw)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

/// An SSL error.
#[derive(Debug)]
pub struct Error {
    pub(crate) code: ErrorCode,
    pub(crate) stack: ErrorStack,
}

impl Error {
    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn into_parts(self) -> (ErrorCode, ErrorStack) {
        (self.code, self.stack)
    }
}

impl From<ErrorStack> for Error {
    fn from(stack: ErrorStack) -> Error {
        Self {
            code: ErrorCode::SSL,
            stack,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let prefix = match self.code {
            ErrorCode::ZERO_RETURN => "the SSL session has been shut down",
            ErrorCode::WANT_READ => "a nonblocking read call would have blocked",
            ErrorCode::WANT_WRITE => "a nonblocking write call would have blocked",
            ErrorCode::SYSCALL => "a syscall failed",
            ErrorCode::SSL => "TLS protocol error",
            ErrorCode(code) => {
                return write!(fmt, "unknown TLS error (code {}): {}", code, self.stack)
            }
        };
        write!(fmt, "{}: {}", prefix, self.stack)
    }
}

impl error::Error for Error {}

#[derive(Debug)]
pub struct HandshakeError<S> {
    stream: S,
    error: io::Error,
}

impl<S> HandshakeError<S> {
    pub fn new(stream: S, error: io::Error) -> Self {
        Self { stream, error }
    }

    pub fn into_parts(self) -> (S, io::Error) {
        (self.stream, self.error)
    }
}

impl<S: fmt::Debug> StdError for HandshakeError<S> {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.error)
    }
}

impl<S> fmt::Display for HandshakeError<S> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("TLS handshake failed:")?;
        write!(f, "TLS handshake failed: {}", self.error)
    }
}
