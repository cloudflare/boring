use std::marker::PhantomData;
use std::ptr;

use crate::error::ErrorStack;
use crate::ffi;
use crate::ffi::BIO_new_mem_buf;
use crate::{cvt, cvt_p};
use crate::{try_int, try_slice};

pub struct MemBioSlice<'a>(*mut ffi::BIO, PhantomData<&'a [u8]>);

impl Drop for MemBioSlice<'_> {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl<'a> MemBioSlice<'a> {
    pub fn new(buf: &'a [u8]) -> Result<MemBioSlice<'a>, ErrorStack> {
        ffi::init();

        let bio = unsafe { cvt_p(BIO_new_mem_buf(buf.as_ptr().cast(), try_int(buf.len())?))? };

        Ok(MemBioSlice(bio, PhantomData))
    }

    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }
}

pub struct MemBio(*mut ffi::BIO);

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe {
            ffi::BIO_free_all(self.0);
        }
    }
}

impl MemBio {
    pub fn new() -> Result<MemBio, ErrorStack> {
        ffi::init();

        let bio = unsafe { cvt_p(ffi::BIO_new(ffi::BIO_s_mem()))? };
        Ok(MemBio(bio))
    }

    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }

    /// An empty slice may indicate an error, use [`Self::try_get_buf`] instead.
    pub fn get_buf(&self) -> &[u8] {
        self.try_get_buf().unwrap_or(&[])
    }

    pub fn try_get_buf(&self) -> Result<&[u8], ErrorStack> {
        unsafe {
            let mut ptr: *const u8 = ptr::null_mut();
            let mut len = 0;
            cvt(ffi::BIO_mem_contents(self.0, &mut ptr, &mut len))?;
            try_slice(ptr, len).ok_or_else(|| ErrorStack::internal_error_str("invalid slice"))
        }
    }
}
