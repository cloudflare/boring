#![allow(bad_style, clippy::all)]

extern crate boring_sys;
extern crate libc;

use boring_sys::*;
use libc::*;

include!(concat!(env!("OUT_DIR"), "/all.rs"));
