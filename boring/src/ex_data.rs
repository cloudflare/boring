use crate::error::ErrorStack;
use crate::ssl::callbacks::{SslCallbacks, SslContextCallbacks};
use crate::ssl::{Ssl, SslContext, SslContextBuilder, SslContextRef, SslRef};
#[cfg(feature = "credential")]
use crate::ssl::{SslCredential, SslCredentialBuilder, SslCredentialRef};
use crate::x509::{X509StoreContext, X509StoreContextRef};
use crate::{cvt, cvt_n, ffi};
use foreign_types::ForeignTypeRef;
use libc::{c_int, c_long, c_void};
use openssl_macros::corresponds;
use std::any::TypeId;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::mem;
use std::ptr::{self, NonNull};
use std::sync::{LazyLock, Mutex, OnceLock};

static SSL_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub(crate) trait Free {
    unsafe fn free(ptr: *mut c_void);
}

struct BoxFree<T>(PhantomData<fn() -> T>);

impl<T> Free for BoxFree<T> {
    unsafe fn free(ptr: *mut c_void) {
        unsafe { drop(Box::<T>::from_raw(ptr.cast())) };
    }
}

unsafe extern "C" fn free_ex_data<F: Free>(
    _parent: *mut c_void,
    ptr: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _idx: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if !ptr.is_null() {
        unsafe { F::free(ptr) };
    }
}

#[derive(Default)]
pub(crate) struct SslContextOwnership {
    pub(crate) has_shared_cert_store: bool,
    pub(crate) callbacks: Option<Box<SslContextCallbacks>>,
}

#[derive(Default)]
pub(crate) struct SslOwnership {
    pub(crate) session_ctx: Option<SslContext>,
    pub(crate) callbacks: Option<Box<SslCallbacks>>,
}

#[cfg(feature = "credential")]
#[derive(Default)]
pub(crate) struct SslCredentialOwnership {
    pub(crate) private_key_method: Option<Box<dyn crate::ssl::PrivateKeyMethod>>,
}

/// A slot in a type's "extra data" structure.
///
/// It is parameterized over the type containing the extra data as well as the
/// type of the data in the slot.
pub struct Index<T, U>(c_int, PhantomData<(T, U)>);

impl<T, U> Copy for Index<T, U> {}

impl<T, U> Clone for Index<T, U> {
    fn clone(&self) -> Index<T, U> {
        *self
    }
}

impl<T, U> Index<T, U> {
    /// Creates an `Index` from a raw integer index.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the index correctly maps to a `U` value stored in a `T`.
    #[must_use]
    pub unsafe fn from_raw(idx: c_int) -> Index<T, U> {
        Index(idx, PhantomData)
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    #[must_use]
    pub fn as_raw(&self) -> c_int {
        self.0
    }
}

pub(crate) struct OnceIndex<O, T> {
    cell: OnceLock<Index<O, T>>,
    init_lock: Mutex<()>,
}

impl<O, T> OnceIndex<O, T> {
    const fn new() -> Self {
        Self {
            cell: OnceLock::new(),
            init_lock: Mutex::new(()),
        }
    }

    fn get(&self) -> Option<Index<O, T>> {
        self.cell.get().copied()
    }

    // TODO: Use `OnceLock::get_or_try_init` once it is stable at the MSRV.
    // https://github.com/rust-lang/rust/issues/109737
    fn get_or_try_init<E>(
        &self,
        init: impl FnOnce() -> Result<Index<O, T>, E>,
    ) -> Result<Index<O, T>, E> {
        if let Some(index) = self.get() {
            return Ok(index);
        }

        let _guard = self
            .init_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(index) = self.get() {
            return Ok(index);
        }

        let index = init()?;
        assert!(self.cell.set(index).is_ok());
        Ok(index)
    }
}

macro_rules! ex_data_indexes {
    ($($vis:vis static $name:ident: $owner:ty => $data:ty,)+) => {
        $($vis static $name: std::sync::LazyLock<$crate::ex_data::Index<$owner, $data>> =
            std::sync::LazyLock::new(|| <$owner>::new_ex_index::<$data>().unwrap());)*
    };
}

pub(crate) use ex_data_indexes;

type NewExDataIndex = unsafe extern "C" fn(
    c_long,
    *mut c_void,
    *mut ffi::CRYPTO_EX_unused,
    ffi::CRYPTO_EX_dup,
    ffi::CRYPTO_EX_free,
) -> c_int;
type GetExData<T> = unsafe extern "C" fn(*mut <T as ForeignTypeRef>::CType, c_int) -> *mut c_void;
type SetExData<T> =
    unsafe extern "C" fn(*mut <T as ForeignTypeRef>::CType, c_int, *mut c_void) -> c_int;

pub(crate) unsafe trait ExData {
    type Owner: 'static;
    type Ref: ForeignTypeRef;
    type Ownership: Default + 'static;

    const NEW_INDEX: NewExDataIndex;
    const GET: GetExData<Self::Ref>;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership>;
}

pub(crate) unsafe trait ExDataMut: ExData {
    const SET: SetExData<Self::Ref>;
}

pub(crate) fn new_raw_ex_index<E, T, F>() -> Result<Index<E::Owner, T>, ErrorStack>
where
    E: ExData,
    F: Free,
{
    unsafe {
        ffi::init();
        let idx = cvt_n(E::NEW_INDEX(
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            None,
            Some(free_ex_data::<F>),
        ))?;
        Ok(Index::from_raw(idx))
    }
}

fn ownership_ex_index<E>() -> Result<Index<E::Owner, E::Ownership>, ErrorStack>
where
    E: ExData,
{
    E::OWNERSHIP_INDEX.get_or_try_init(new_raw_ex_index::<E, E::Ownership, BoxFree<E::Ownership>>)
}

fn has_ownership_ex_data<E>(ptr: *mut <E::Ref as ForeignTypeRef>::CType) -> bool
where
    E: ExData,
{
    E::OWNERSHIP_INDEX
        .get()
        .is_some_and(|index| unsafe { !E::GET(ptr, index.as_raw()).is_null() })
}

fn ownership_ex_data<E>(ptr: *mut <E::Ref as ForeignTypeRef>::CType) -> *mut E::Ownership
where
    E: ExData,
{
    let index = E::OWNERSHIP_INDEX
        .get()
        .expect("BUG: extra data ownership index missing");
    let ownership: *mut E::Ownership = unsafe { E::GET(ptr, index.as_raw()).cast() };
    assert!(!ownership.is_null(), "BUG: extra data ownership missing");
    ownership
}

fn try_ensure_ownership_ex_data<E>(
    ptr: *mut <E::Ref as ForeignTypeRef>::CType,
) -> Result<*mut E::Ownership, ErrorStack>
where
    E: ExDataMut,
{
    let index = ownership_ex_index::<E>()?;
    let ownership: *mut E::Ownership = unsafe { E::GET(ptr, index.as_raw()).cast() };
    if !ownership.is_null() {
        return Ok(ownership);
    }

    let mut ownership = Box::new(E::Ownership::default());
    unsafe {
        cvt(E::SET(
            ptr,
            index.as_raw(),
            ptr::from_mut(ownership.as_mut()).cast(),
        ))?;
    }
    Ok(Box::into_raw(ownership))
}

unsafe fn get_slot<E, T>(
    ptr: *mut <E::Ref as ForeignTypeRef>::CType,
    index: Index<E::Owner, T>,
) -> Option<NonNull<T>>
where
    E: ExData,
{
    NonNull::new(unsafe { E::GET(ptr, index.as_raw()).cast() })
}

pub(crate) fn get<E, T>(parent: &E::Ref, index: Index<E::Owner, T>) -> Option<&T>
where
    E: ExData,
{
    unsafe { get_slot::<E, T>(parent.as_ptr(), index) }.map(|ptr| unsafe { ptr.as_ref() })
}

pub(crate) fn get_mut<E, T>(parent: &mut E::Ref, index: Index<E::Owner, T>) -> Option<&mut T>
where
    E: ExDataMut,
{
    unsafe { get_slot::<E, T>(parent.as_ptr(), index) }.map(|mut ptr| unsafe { ptr.as_mut() })
}

pub(crate) fn try_set<E, T>(
    parent: &mut E::Ref,
    index: Index<E::Owner, T>,
    data: T,
) -> Result<Option<T>, ErrorStack>
where
    E: ExDataMut,
{
    if let Some(old) = get_mut::<E, T>(parent, index) {
        return Ok(Some(mem::replace(old, data)));
    }

    let ptr = parent.as_ptr();
    let mut data = Box::new(data);
    unsafe {
        cvt(E::SET(
            ptr,
            index.as_raw(),
            ptr::from_mut(data.as_mut()).cast(),
        ))?;
    }
    mem::forget(data);
    Ok(None)
}

pub(crate) fn remove<E, T>(parent: &mut E::Ref, index: Index<E::Owner, T>) -> Option<T>
where
    E: ExDataMut,
{
    let ownership_index =
        ownership_ex_index::<E>().unwrap_or_else(|error| panic_ex_data("remove", error));
    if index.as_raw() < ownership_index.as_raw() {
        panic_borrowed_ex_data();
    }

    let ptr = parent.as_ptr();
    let old = unsafe { get_slot::<E, T>(ptr, index) }?;
    unsafe {
        cvt(E::SET(ptr, index.as_raw(), ptr::null_mut())).expect("failed to remove extra data");
        Some(*Box::from_raw(old.as_ptr()))
    }
}

#[cold]
#[inline(never)]
fn panic_borrowed_ex_data() -> ! {
    panic!("cannot take ownership of borrowed extra data");
}

#[cold]
#[inline(never)]
fn panic_ex_data(operation: &str, error: ErrorStack) -> ! {
    panic!("failed to {operation} extra data: {error}")
}

macro_rules! api {
    (
        receiver = $receiver:ident $(<$receiver_data:ident>)?,
        mut_receiver = $mut_receiver:ident $(<$mut_receiver_data:ident>)?,
        owner = $owner:ty,
        data = $data:ident,
    ) => {
        impl $owner {
            /// Returns a new extra data index.
            ///
            /// Each invocation returns a distinct index that can be used to store extra data on
            /// values of this type.
            pub fn new_ex_index<$data>() -> Result<Index<Self, $data>, ErrorStack>
            where
                $data: 'static + Sync + Send,
            {
                ownership_ex_index::<Self>()?;
                new_raw_ex_index::<Self, $data, BoxFree<$data>>()
            }

        }

        impl$(<$receiver_data>)? $receiver$(<$receiver_data>)? {
            /// Returns a reference to the extra data at `index`.
            #[must_use]
            pub fn ex_data<$data>(&self, index: Index<$owner, $data>) -> Option<&$data> {
                get::<Self, $data>(self, index)
            }

        }

        impl$(<$mut_receiver_data>)? $mut_receiver$(<$mut_receiver_data>)? {
            /// Returns a mutable reference to the extra data at `index`.
            pub fn ex_data_mut<T>(&mut self, index: Index<$owner, T>) -> Option<&mut T> {
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                get_mut::<Self, T>(parent, index)
            }

            /// Sets or overwrites the extra data at `index`.
            pub fn set_ex_data<T>(&mut self, index: Index<$owner, T>, data: T) {
                if let Err(error) = self.try_set_ex_data(index, data) {
                    panic_ex_data("set", error);
                }
            }

            /// Replaces the extra data at `index`, returning the previous value.
            pub fn replace_ex_data<T>(&mut self, index: Index<$owner, T>, data: T) -> Option<T> {
                match self.try_replace_ex_data(index, data) {
                    Ok(previous) => previous,
                    Err(error) => panic_ex_data("replace", error),
                }
            }

            /// Removes and returns the extra data at `index`.
            pub fn remove_ex_data<T>(&mut self, index: Index<$owner, T>) -> Option<T> {
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                remove::<Self, T>(parent, index)
            }

            /// Tries to set or overwrite the extra data at `index`.
            pub fn try_set_ex_data<T>(
                &mut self,
                index: Index<$owner, T>,
                data: T,
            ) -> Result<(), ErrorStack> {
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                try_set::<Self, T>(parent, index, data).map(drop)
            }

            /// Tries to replace the extra data at `index`, returning the previous value.
            pub fn try_replace_ex_data<T>(
                &mut self,
                index: Index<$owner, T>,
                data: T,
            ) -> Result<Option<T>, ErrorStack> {
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                try_set::<Self, T>(parent, index, data)
            }
        }
    };
}

impl SslContextBuilder {
    pub(crate) fn try_callbacks_mut(&mut self) -> Result<&mut SslContextCallbacks, ErrorStack> {
        let ownership = try_ensure_ownership_ex_data::<Self>(self.as_ptr())?;
        Ok(unsafe { &mut (*ownership).callbacks }
            .get_or_insert_with(|| Box::new(SslContextCallbacks::default())))
    }

    pub(crate) fn callbacks_mut(&mut self) -> &mut SslContextCallbacks {
        self.try_callbacks_mut()
            .expect("failed to initialize SSL context callback state")
    }

    pub(crate) fn set_has_shared_cert_store(&mut self, value: bool) {
        let ownership = try_ensure_ownership_ex_data::<Self>(self.as_ptr())
            .expect("failed to set shared certificate store state");
        unsafe { (*ownership).has_shared_cert_store = value };
    }
}

impl SslContextRef {
    pub(crate) fn callbacks(&self) -> Option<&SslContextCallbacks> {
        if !has_ownership_ex_data::<Self>(self.as_ptr()) {
            return None;
        }
        let ownership = ownership_ex_data::<Self>(self.as_ptr());
        unsafe { (*ownership).callbacks.as_deref() }
    }

    pub(crate) fn has_shared_cert_store(&self) -> bool {
        if !has_ownership_ex_data::<Self>(self.as_ptr()) {
            return false;
        }
        let ownership = ownership_ex_data::<Self>(self.as_ptr());
        unsafe { (*ownership).has_shared_cert_store }
    }
}

unsafe impl ExData for SslContext {
    type Owner = SslContext;
    type Ref = SslContextRef;
    type Ownership = SslContextOwnership;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_CTX_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL_CTX, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_CTX_get_ex_data)
    };
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> = {
        static INDEX: OnceIndex<SslContext, SslContextOwnership> = OnceIndex::new();
        &INDEX
    };
}

unsafe impl ExData for SslContextRef {
    type Owner = SslContext;
    type Ref = SslContextRef;
    type Ownership = SslContextOwnership;

    const NEW_INDEX: NewExDataIndex = <SslContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslContext as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <SslContext as ExData>::OWNERSHIP_INDEX;
}

unsafe impl ExDataMut for SslContextRef {
    const SET: SetExData<Self::Ref> = ffi::SSL_CTX_set_ex_data;
}

unsafe impl ExData for SslContextBuilder {
    type Owner = SslContext;
    type Ref = SslContextRef;
    type Ownership = SslContextOwnership;

    const NEW_INDEX: NewExDataIndex = <SslContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslContext as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <SslContext as ExData>::OWNERSHIP_INDEX;
}

unsafe impl ExDataMut for SslContextBuilder {
    const SET: SetExData<Self::Ref> = ffi::SSL_CTX_set_ex_data;
}

api!(
    receiver = SslContextRef,
    mut_receiver = SslContextBuilder,
    owner = SslContext,
    data = T,
);

impl Ssl {
    /// Returns the process-wide extra data index associated with `T`.
    ///
    /// The index is allocated lazily on first use and reused by subsequent calls for the same
    /// type. Callers must coordinate all uses of a given `T`, since they share one slot on every
    /// [`Ssl`].
    // FIXME should return a result?
    pub fn cached_ex_index<T>() -> Index<Ssl, T>
    where
        T: 'static + Sync + Send,
    {
        unsafe {
            let idx = *SSL_INDEXES
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .entry(TypeId::of::<T>())
                .or_insert_with(|| Ssl::new_ex_index::<T>().unwrap().as_raw());
            Index::from_raw(idx)
        }
    }
}

unsafe impl ExData for Ssl {
    type Owner = Ssl;
    type Ref = SslRef;
    type Ownership = SslOwnership;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_get_ex_data)
    };
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> = {
        static INDEX: OnceIndex<Ssl, SslOwnership> = OnceIndex::new();
        &INDEX
    };
}

unsafe impl ExData for SslRef {
    type Owner = Ssl;
    type Ref = SslRef;
    type Ownership = SslOwnership;

    const NEW_INDEX: NewExDataIndex = <Ssl as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <Ssl as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <Ssl as ExData>::OWNERSHIP_INDEX;
}

unsafe impl ExDataMut for SslRef {
    const SET: SetExData<Self::Ref> = ffi::SSL_set_ex_data;
}

api!(
    receiver = SslRef,
    mut_receiver = SslRef,
    owner = Ssl,
    data = T,
);

impl SslRef {
    pub(crate) fn initialize_ownership(
        &mut self,
        context: &SslContextRef,
    ) -> Result<(), ErrorStack> {
        let ownership = try_ensure_ownership_ex_data::<Self>(self.as_ptr())?;
        unsafe { (*ownership).session_ctx = Some(context.to_owned()) };
        Ok(())
    }

    pub(crate) fn ownership(&self) -> &SslOwnership {
        let ownership = ownership_ex_data::<Self>(self.as_ptr());
        unsafe { &*ownership }
    }

    pub(crate) fn ownership_mut(&mut self) -> &mut SslOwnership {
        let ownership = ownership_ex_data::<Self>(self.as_ptr());
        unsafe { &mut *ownership }
    }

    pub(crate) fn session_ctx(&self) -> &SslContextRef {
        self.ownership()
            .session_ctx
            .as_deref()
            .expect("BUG: SSL session context missing")
    }

    pub(crate) fn callbacks_mut(&mut self) -> &mut SslCallbacks {
        self.ownership_mut()
            .callbacks
            .get_or_insert_with(|| Box::new(SslCallbacks::default()))
    }

    pub(crate) fn with_session_callbacks<R>(
        &mut self,
        invoke: impl FnOnce(&SslContextCallbacks, &mut Self) -> R,
    ) -> R {
        let context = self.session_ctx();
        // SAFETY: the private session-context field cannot be mutated through `self`.
        let context = unsafe { &*ptr::from_ref(context) };
        let callbacks = context
            .callbacks()
            .expect("BUG: SSL context callback state missing");
        invoke(callbacks, self)
    }
}

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredential {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;
    type Ownership = SslCredentialOwnership;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_CREDENTIAL_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL_CREDENTIAL, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_CREDENTIAL_get_ex_data)
    };
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> = {
        static INDEX: OnceIndex<SslCredential, SslCredentialOwnership> = OnceIndex::new();
        &INDEX
    };
}

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredentialRef {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;
    type Ownership = SslCredentialOwnership;

    const NEW_INDEX: NewExDataIndex = <SslCredential as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslCredential as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <SslCredential as ExData>::OWNERSHIP_INDEX;
}

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredentialBuilder {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;
    type Ownership = SslCredentialOwnership;

    const NEW_INDEX: NewExDataIndex = <SslCredential as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslCredential as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <SslCredential as ExData>::OWNERSHIP_INDEX;
}

#[cfg(feature = "credential")]
unsafe impl ExDataMut for SslCredentialBuilder {
    const SET: SetExData<Self::Ref> = ffi::SSL_CREDENTIAL_set_ex_data;
}

#[cfg(feature = "credential")]
impl SslCredentialBuilder {
    pub(crate) fn try_ownership_mut(&mut self) -> Result<&mut SslCredentialOwnership, ErrorStack> {
        let ownership = try_ensure_ownership_ex_data::<Self>(self.as_ptr())?;
        Ok(unsafe { &mut *ownership })
    }
}

#[cfg(feature = "credential")]
impl SslCredentialRef {
    pub(crate) fn ownership(&self) -> Option<&SslCredentialOwnership> {
        if !has_ownership_ex_data::<Self>(self.as_ptr()) {
            return None;
        }
        let ownership = ownership_ex_data::<Self>(self.as_ptr());
        Some(unsafe { &*ownership })
    }
}

#[cfg(feature = "credential")]
api!(
    receiver = SslCredentialRef,
    mut_receiver = SslCredentialBuilder,
    owner = SslCredential,
    data = T,
);

static X509_STORE_CONTEXT_SSL_INDEX: LazyLock<Index<X509StoreContext, SslRef>> =
    LazyLock::new(|| unsafe {
        let index = cvt_n(ffi::SSL_get_ex_data_X509_STORE_CTX_idx())
            .expect("BUG: store context SSL index missing");
        Index::from_raw(index)
    });

unsafe impl ExData for X509StoreContext {
    type Owner = X509StoreContext;
    type Ref = X509StoreContextRef;
    type Ownership = ();

    const NEW_INDEX: NewExDataIndex = ffi::X509_STORE_CTX_get_ex_new_index;
    const GET: GetExData<Self::Ref> = ffi::X509_STORE_CTX_get_ex_data;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> = {
        static INDEX: OnceIndex<X509StoreContext, ()> = OnceIndex::new();
        &INDEX
    };
}

unsafe impl ExData for X509StoreContextRef {
    type Owner = X509StoreContext;
    type Ref = X509StoreContextRef;
    type Ownership = ();

    const NEW_INDEX: NewExDataIndex = <X509StoreContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <X509StoreContext as ExData>::GET;
    const OWNERSHIP_INDEX: &'static OnceIndex<Self::Owner, Self::Ownership> =
        <X509StoreContext as ExData>::OWNERSHIP_INDEX;
}

unsafe impl ExDataMut for X509StoreContextRef {
    const SET: SetExData<Self::Ref> = ffi::X509_STORE_CTX_set_ex_data;
}

impl X509StoreContext {
    /// Returns the index which can be used to obtain a reference to the `Ssl` associated with a
    /// context.
    #[corresponds(SSL_get_ex_data_X509_STORE_CTX_idx)]
    pub fn ssl_idx() -> Result<Index<X509StoreContext, SslRef>, ErrorStack> {
        Ok(*X509_STORE_CONTEXT_SSL_INDEX)
    }
}

api!(
    receiver = X509StoreContextRef,
    mut_receiver = X509StoreContextRef,
    owner = X509StoreContext,
    data = T,
);

impl X509StoreContextRef {
    /// Returns the SSL connection associated with this store context, if any.
    #[must_use]
    pub fn ssl(&self) -> Option<&SslRef> {
        self.ex_data(*X509_STORE_CONTEXT_SSL_INDEX)
    }

    pub(crate) fn with_session_callbacks<R>(
        &mut self,
        invoke: impl FnOnce(&SslContextCallbacks, &mut Self) -> R,
    ) -> R {
        let context = self
            .ssl()
            .expect("BUG: store context missing SSL")
            .session_ctx();
        // SAFETY: the private session-context field cannot be mutated through `self`.
        let context = unsafe { &*ptr::from_ref(context) };
        let callbacks = context
            .callbacks()
            .expect("BUG: SSL context callback state missing");
        invoke(callbacks, self)
    }
}
