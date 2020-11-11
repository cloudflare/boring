use *;

extern "C" {
    pub fn NCONF_new(meth: *mut c_void) -> *mut CONF;
    pub fn NCONF_free(conf: *mut CONF);
}
