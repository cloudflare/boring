use boring::ssl::{
    AsyncPrivateKeyMethod, AsyncSelectCertError, BoxGetSessionFuture, BoxSelectCertActionFuture,
    BoxSelectCertFuture, ClientHello, SslContextBuilder, SslRef,
};

/// Extensions to [`SslContextBuilder`].
///
/// This trait provides additional methods to use async callbacks with boring.
pub trait SslContextBuilderExt: private::Sealed {
    /// Sets a callback that is called before most [`ClientHello`] processing
    /// and before the decision whether to resume a session is made. The
    /// callback may inspect the [`ClientHello`] and configure the connection.
    ///
    /// This method uses a function that returns a future whose output is
    /// itself a closure that will be passed [`ClientHello`] to configure
    /// the connection based on the computations done in the future.
    ///
    /// See [`SslContextBuilder::set_select_certificate_callback`] for the sync
    /// setter of this callback.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    fn set_async_select_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static;

    /// Sets an action-aware asynchronous certificate selection callback.
    ///
    /// A task waker must be set on `Ssl` values associated with the resulting `SslContext` with
    /// [`SslRef::set_task_waker`]. Returning [`boring::ssl::SelectCertAction::DisableEch`]
    /// discards an inner ClientHello and invokes the callback again with the outer ClientHello.
    /// It is only valid when ECH has been accepted; returning it otherwise fails the handshake.
    /// The future-producing callback runs again for the outer ClientHello, so per-connection
    /// state must handle both calls.
    ///
    /// A context has a single certificate selection callback. Calling this method replaces the
    /// callback set by any of [`SslContextBuilder::set_select_certificate_callback`],
    /// [`SslContextBuilder::set_select_certificate_callback_with_action`],
    /// [`SslContextBuilder::set_async_select_certificate_callback`], or
    /// [`SslContextBuilder::set_async_select_certificate_callback_with_action`].
    fn set_async_select_certificate_callback_with_action<F>(&mut self, callback: F)
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertActionFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static;

    /// Configures a custom private key method on the context.
    ///
    /// See [`AsyncPrivateKeyMethod`] for more details.
    fn set_async_private_key_method(&mut self, method: impl AsyncPrivateKeyMethod);

    /// Sets a callback that is called when a client proposed to resume a session
    /// but it was not found in the internal cache.
    ///
    /// The callback is passed a reference to the session ID provided by the client.
    /// It should return the session corresponding to that ID if available. This is
    /// only used for servers, not clients.
    ///
    /// See [`SslContextBuilder::set_get_session_callback`] for the sync setter
    /// of this callback.
    ///
    /// # Safety
    ///
    /// The returned [`boring::ssl::SslSession`] must not be associated with a different [`boring::ssl::SslContext`].
    unsafe fn set_async_get_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &[u8]) -> Option<BoxGetSessionFuture> + Send + Sync + 'static;
}

impl SslContextBuilderExt for SslContextBuilder {
    fn set_async_select_certificate_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        self.set_async_select_certificate_callback(callback);
    }

    fn set_async_select_certificate_callback_with_action<F>(&mut self, callback: F)
    where
        F: Fn(&mut ClientHello<'_>) -> Result<BoxSelectCertActionFuture, AsyncSelectCertError>
            + Send
            + Sync
            + 'static,
    {
        self.set_async_select_certificate_callback_with_action(callback);
    }

    fn set_async_private_key_method(&mut self, method: impl AsyncPrivateKeyMethod) {
        self.set_async_private_key_method(method);
    }

    unsafe fn set_async_get_session_callback<F>(&mut self, callback: F)
    where
        F: Fn(&mut SslRef, &[u8]) -> Option<BoxGetSessionFuture> + Send + Sync + 'static,
    {
        unsafe {
            self.set_async_get_session_callback(callback);
        }
    }
}

mod private {
    pub trait Sealed {}
}

impl private::Sealed for SslContextBuilder {}
