# SSL callback safety

- Call `ffi::SSL_new` only from `SslBuilder<Unconfigured>::new` in
  `boring/src/ex_data.rs`, which retains the session context.
- Raw callbacks in `boring/src/ssl/callbacks.rs` must use the session-context
  helpers instead of extending ex-data reference lifetimes with pointer casts.
- The session-context helpers may detach the context reference from the
  callback argument borrow because the private session-context field is
  initialized once and cannot be mutated through callback arguments.
