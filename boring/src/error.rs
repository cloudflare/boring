//! Errors returned by OpenSSL library.
//!
//! OpenSSL errors are stored in an `ErrorStack`.  Most methods in the crate
//! returns a `Result<T, ErrorStack>` type.
//!
//! # Examples
//!
//! ```
//! use boring::error::ErrorStack;
//! use boring::bn::BigNum;
//!
//! let an_error = BigNum::from_dec_str("Cannot parse letters");
//! match an_error {
//!     Ok(_)  => (),
//!     Err(e) => println!("Parsing Error: {:?}", e),
//! }
//! ```
use libc::{c_char, c_uint};
use std::borrow::Cow;
use std::error;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::ptr;
use std::str;

use crate::ffi;

/// Collection of [`Error`]s from OpenSSL.
///
/// [`Error`]: struct.Error.html
#[derive(Debug, Clone)]
pub struct ErrorStack(Vec<Error>);

impl ErrorStack {
    /// Pops the contents of the OpenSSL error stack, and returns it.
    #[allow(clippy::must_use_candidate)]
    pub fn get() -> ErrorStack {
        let mut vec = vec![];
        while let Some(err) = Error::get() {
            vec.push(err);
        }
        ErrorStack(vec)
    }

    /// Pushes the errors back onto the OpenSSL error stack.
    pub fn put(&self) {
        for error in self.errors() {
            error.put();
        }
    }

    /// Used to report errors from the Rust crate
    #[cold]
    pub(crate) fn internal_error(err: impl error::Error) -> Self {
        Self(vec![Error::new_internal(err.to_string())])
    }
}

impl ErrorStack {
    /// Returns the errors in the stack.
    #[must_use]
    pub fn errors(&self) -> &[Error] {
        &self.0
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            return fmt.write_str("unknown BoringSSL error");
        }

        let mut first = true;
        for err in &self.0 {
            if !first {
                fmt.write_str(" ")?;
            }
            first = false;
            write!(
                fmt,
                "[{}]",
                err.reason_internal().unwrap_or("unknown reason")
            )?;
        }
        Ok(())
    }
}

impl error::Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(e: ErrorStack) -> io::Error {
        io::Error::other(e)
    }
}

impl From<ErrorStack> for fmt::Error {
    fn from(_: ErrorStack) -> fmt::Error {
        fmt::Error
    }
}

/// An error reported from OpenSSL.
#[derive(Clone)]
pub struct Error {
    code: c_uint,
    file: *const c_char,
    line: c_uint,
    data: Option<Cow<'static, str>>,
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

static BORING_INTERNAL: &CStr = c"boring-rust";

impl Error {
    /// Pops the first error off the OpenSSL error stack.
    #[allow(clippy::must_use_candidate)]
    pub fn get() -> Option<Error> {
        unsafe {
            ffi::init();

            let mut file = ptr::null();
            let mut line = 0;
            let mut data = ptr::null();
            let mut flags = 0;
            match ffi::ERR_get_error_line_data(&mut file, &mut line, &mut data, &mut flags) {
                0 => None,
                code => {
                    // The memory referenced by data is only valid until that slot is overwritten
                    // in the error stack, so we'll need to copy it off if it's dynamic
                    let data = if flags & ffi::ERR_FLAG_STRING != 0 {
                        let bytes = CStr::from_ptr(data as *const _).to_bytes();
                        let data = String::from_utf8_lossy(bytes).into_owned();
                        Some(data.into())
                    } else {
                        None
                    };
                    Some(Error {
                        code,
                        file,
                        line: line as c_uint,
                        data,
                    })
                }
            }
        }
    }

    /// Pushes the error back onto the OpenSSL error stack.
    pub fn put(&self) {
        unsafe {
            ffi::ERR_put_error(
                ffi::ERR_GET_LIB(self.code),
                ffi::ERR_GET_FUNC(self.code),
                ffi::ERR_GET_REASON(self.code),
                self.file,
                self.line,
            );
            let ptr = match self.data {
                Some(Cow::Borrowed(data)) => Some(data.as_ptr() as *mut c_char),
                Some(Cow::Owned(ref data)) => {
                    let ptr = ffi::OPENSSL_malloc((data.len() + 1) as _) as *mut c_char;
                    if ptr.is_null() {
                        None
                    } else {
                        ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len());
                        *ptr.add(data.len()) = 0;
                        Some(ptr)
                    }
                }
                None => None,
            };
            if let Some(ptr) = ptr {
                ffi::ERR_add_error_data(1, ptr);
            }
        }
    }

    /// Returns the raw OpenSSL error code for this error.
    #[must_use]
    pub fn code(&self) -> c_uint {
        self.code
    }

    /// Returns the name of the library reporting the error, if available.
    #[must_use]
    pub fn library(&self) -> Option<&'static str> {
        if self.is_internal() {
            return None;
        }
        unsafe {
            let cstr = ffi::ERR_lib_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            str::from_utf8(bytes).ok()
        }
    }

    /// Returns the raw OpenSSL error constant for the library reporting the
    /// error.
    #[must_use]
    pub fn library_code(&self) -> libc::c_int {
        ffi::ERR_GET_LIB(self.code)
    }

    /// Returns `None`. Boring doesn't use function codes.
    pub fn function(&self) -> Option<&'static str> {
        None
    }

    /// Returns the reason for the error.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        unsafe {
            let cstr = ffi::ERR_reason_error_string(self.code);
            if cstr.is_null() {
                return None;
            }
            let bytes = CStr::from_ptr(cstr as *const _).to_bytes();
            str::from_utf8(bytes).ok()
        }
    }

    /// Returns the raw OpenSSL error constant for the reason for the error.
    #[must_use]
    pub fn reason_code(&self) -> libc::c_int {
        ffi::ERR_GET_REASON(self.code)
    }

    /// Returns the name of the source file which encountered the error.
    #[must_use]
    pub fn file(&self) -> &'static str {
        unsafe {
            if self.file.is_null() {
                return "";
            }
            let bytes = CStr::from_ptr(self.file as *const _).to_bytes();
            str::from_utf8(bytes).unwrap_or_default()
        }
    }

    /// Returns the line in the source file which encountered the error.
    ///
    /// 0 if unknown
    #[allow(clippy::unnecessary_cast)]
    #[must_use]
    pub fn line(&self) -> u32 {
        self.line as u32
    }

    /// Returns additional data describing the error.
    #[must_use]
    pub fn data(&self) -> Option<&str> {
        self.data.as_deref()
    }

    fn new_internal(msg: String) -> Self {
        Self {
            code: ffi::ERR_PACK(ffi::ERR_LIB_NONE.0 as _, 0, 0) as _,
            file: BORING_INTERNAL.as_ptr(),
            line: 0,
            data: Some(msg.into()),
        }
    }

    fn is_internal(&self) -> bool {
        std::ptr::eq(self.file, BORING_INTERNAL.as_ptr())
    }

    // reason() needs 'static
    fn reason_internal(&self) -> Option<&str> {
        if self.is_internal() {
            self.data()
        } else {
            self.reason()
        }
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = fmt.debug_struct("Error");
        builder.field("code", &self.code());
        if let Some(library) = self.library() {
            builder.field("library", &library);
        }
        builder.field("library_code", &self.library_code());
        if let Some(reason) = self.reason() {
            builder.field("reason", &reason);
        }
        builder.field("reason_code", &self.reason_code());
        builder.field("file", &self.file());
        builder.field("line", &self.line());
        if let Some(data) = self.data() {
            builder.field("data", &data);
        }
        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{}\n\nCode: {:08X}\nLoc: {}:{}",
            self.reason_internal().unwrap_or("unknown TLS error"),
            self.code(),
            self.file(),
            self.line()
        )
    }
}

impl error::Error for Error {}

#[test]
fn internal_err() {
    let e = ErrorStack::internal_error(io::Error::other("hello, boring"));
    assert_eq!(1, e.errors().len());
    assert!(e.to_string().contains("hello, boring"), "{e} {e:?}");

    e.put();
    let e = ErrorStack::get();
    assert!(e.to_string().contains("hello, boring"), "{e} {e:?}");
}
