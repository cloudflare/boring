use crate::error::ErrorStack;
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
use std::sync::{LazyLock, Mutex};

static SSL_CONTEXT_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static SSL_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
#[cfg(feature = "credential")]
static SSL_CREDENTIAL_INDEXES: LazyLock<Mutex<HashMap<TypeId, c_int>>> =
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
    type Owner;
    type Ref: ForeignTypeRef;

    const NEW_INDEX: NewExDataIndex;
    const GET: GetExData<Self::Ref>;
}

pub(crate) unsafe trait ExDataMut: ExData {
    const SET: SetExData<Self::Ref>;

    #[allow(dead_code)]
    fn validate_remove_index(_index: c_int) {}
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

#[allow(dead_code)]
pub(crate) fn remove<E, T>(parent: &mut E::Ref, index: Index<E::Owner, T>) -> Option<T>
where
    E: ExDataMut,
{
    E::validate_remove_index(index.as_raw());
    let ptr = parent.as_ptr();
    let old = unsafe { get_slot::<E, T>(ptr, index) }?;
    unsafe {
        cvt(E::SET(ptr, index.as_raw(), ptr::null_mut())).expect("failed to remove extra data");
        Some(*Box::from_raw(old.as_ptr()))
    }
}

macro_rules! cached_api {
    (owner = Ssl, indexes = $indexes:ident,) => {
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
            cached_ex_index::<Ssl, T>(&$indexes)
        }
    };
    (owner = $owner:ident, indexes = $indexes:ident,) => {
        // FIXME should return a result?
        pub(crate) fn cached_ex_index<T>() -> Index<$owner, T>
        where
            T: 'static + Sync + Send,
        {
            cached_ex_index::<$owner, T>(&$indexes)
        }
    };
    (owner = $owner:ident,) => {};
}

fn cached_ex_index<O, T>(indexes: &Mutex<HashMap<TypeId, c_int>>) -> Index<O, T>
where
    O: ExData<Owner = O>,
    T: 'static + Sync + Send,
{
    unsafe {
        let idx = *indexes
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .entry(TypeId::of::<T>())
            .or_insert_with(|| new_raw_ex_index::<O, T, BoxFree<T>>().unwrap().as_raw());
        Index::from_raw(idx)
    }
}

macro_rules! api {
    (
        receiver = $receiver:ident $(<$receiver_data:ident>)?,
        mut_receiver = $mut_receiver:ident $(<$mut_receiver_data:ident>)?,
        owner = $owner:ident,
        data = $data:ident,
        $(cached = $indexes:ident,) ?
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
                new_raw_ex_index::<Self, $data, BoxFree<$data>>()
            }

            cached_api!(
                owner = $owner,
                $(indexes = $indexes,)?
            );
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
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                drop(
                    try_set::<Self, T>(parent, index, data)
                    .expect("failed to set extra data"),
                );
            }

            /// Replaces the extra data at `index`, returning the previous value.
            pub fn replace_ex_data<T>(&mut self, index: Index<$owner, T>, data: T) -> Option<T> {
                let parent = unsafe {
                    <<Self as ExData>::Ref as ForeignTypeRef>::from_ptr_mut(self.as_ptr())
                };
                try_set::<Self, T>(parent, index, data)
                    .expect("failed to replace extra data")
            }
        }
    };
}

unsafe impl ExData for SslContext {
    type Owner = SslContext;
    type Ref = SslContextRef;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_CTX_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL_CTX, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_CTX_get_ex_data)
    };
}

unsafe impl ExData for SslContextRef {
    type Owner = SslContext;
    type Ref = SslContextRef;

    const NEW_INDEX: NewExDataIndex = <SslContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslContext as ExData>::GET;
}

unsafe impl ExDataMut for SslContextRef {
    const SET: SetExData<Self::Ref> = ffi::SSL_CTX_set_ex_data;
}

unsafe impl ExData for SslContextBuilder {
    type Owner = SslContext;
    type Ref = SslContextRef;

    const NEW_INDEX: NewExDataIndex = <SslContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslContext as ExData>::GET;
}

unsafe impl ExDataMut for SslContextBuilder {
    const SET: SetExData<Self::Ref> = ffi::SSL_CTX_set_ex_data;
}

api!(
    receiver = SslContextRef,
    mut_receiver = SslContextBuilder,
    owner = SslContext,
    data = T,
    cached = SSL_CONTEXT_INDEXES,
);

unsafe impl ExData for Ssl {
    type Owner = Ssl;
    type Ref = SslRef;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_get_ex_data)
    };
}

unsafe impl ExData for SslRef {
    type Owner = Ssl;
    type Ref = SslRef;

    const NEW_INDEX: NewExDataIndex = <Ssl as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <Ssl as ExData>::GET;
}

unsafe impl ExDataMut for SslRef {
    const SET: SetExData<Self::Ref> = ffi::SSL_set_ex_data;
}

api!(
    receiver = SslRef,
    mut_receiver = SslRef,
    owner = Ssl,
    data = T,
    cached = SSL_INDEXES,
);

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredential {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;

    const NEW_INDEX: NewExDataIndex = ffi::SSL_CREDENTIAL_get_ex_new_index;
    const GET: GetExData<Self::Ref> = unsafe {
        mem::transmute::<
            unsafe extern "C" fn(*const ffi::SSL_CREDENTIAL, c_int) -> *mut c_void,
            GetExData<Self::Ref>,
        >(ffi::SSL_CREDENTIAL_get_ex_data)
    };
}

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredentialRef {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;

    const NEW_INDEX: NewExDataIndex = <SslCredential as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslCredential as ExData>::GET;
}

#[cfg(feature = "credential")]
unsafe impl ExData for SslCredentialBuilder {
    type Owner = SslCredential;
    type Ref = SslCredentialRef;

    const NEW_INDEX: NewExDataIndex = <SslCredential as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <SslCredential as ExData>::GET;
}

#[cfg(feature = "credential")]
unsafe impl ExDataMut for SslCredentialBuilder {
    const SET: SetExData<Self::Ref> = ffi::SSL_CREDENTIAL_set_ex_data;
}

#[cfg(feature = "credential")]
api!(
    receiver = SslCredentialRef,
    mut_receiver = SslCredentialBuilder,
    owner = SslCredential,
    data = T,
    cached = SSL_CREDENTIAL_INDEXES,
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

    const NEW_INDEX: NewExDataIndex = ffi::X509_STORE_CTX_get_ex_new_index;
    const GET: GetExData<Self::Ref> = ffi::X509_STORE_CTX_get_ex_data;
}

unsafe impl ExData for X509StoreContextRef {
    type Owner = X509StoreContext;
    type Ref = X509StoreContextRef;

    const NEW_INDEX: NewExDataIndex = <X509StoreContext as ExData>::NEW_INDEX;
    const GET: GetExData<Self::Ref> = <X509StoreContext as ExData>::GET;
}

unsafe impl ExDataMut for X509StoreContextRef {
    const SET: SetExData<Self::Ref> = ffi::X509_STORE_CTX_set_ex_data;

    fn validate_remove_index(index: c_int) {
        if index == X509_STORE_CONTEXT_SSL_INDEX.as_raw() {
            panic_borrowed_ssl_ex_data();
        }
    }
}

#[cold]
#[inline(never)]
#[allow(dead_code)]
fn panic_borrowed_ssl_ex_data() -> ! {
    panic!("cannot take ownership of borrowed SSL extra data");
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
}
