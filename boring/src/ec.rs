//! Elliptic Curve
//!
//! Cryptology relies on the difficulty of solving mathematical problems, such as the factor
//! of large integers composed of two large prime numbers and the discrete logarithm of a
//! random eliptic curve.  This module provides low-level features of the latter.
//! Elliptic Curve protocols can provide the same security with smaller keys.
//!
//! There are 2 forms of elliptic curves, `Fp` and `F2^m`.  These curves use irreducible
//! trinomial or pentanomial .  Being a generic interface to a wide range of algorithms,
//! the cuves are generally referenced by [`EcGroup`].  There are many built in groups
//! found in [`Nid`].
//!
//! OpenSSL Wiki explains the fields and curves in detail at [Eliptic Curve Cryptography].
//!
//! [`EcGroup`]: struct.EcGroup.html
//! [`Nid`]: ../nid/struct.Nid.html
//! [Eliptic Curve Cryptography]: https://wiki.openssl.org/index.php/Elliptic_Curve_Cryptography
use crate::ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use libc::c_int;
use std::fmt;
use std::ptr;

use crate::bn::{BigNumContextRef, BigNumRef};
use crate::error::ErrorStack;
use crate::nid::Nid;
use crate::pkey::{HasParams, HasPrivate, HasPublic, Params, Private, Public};
use crate::{cvt, cvt_n, cvt_p, init};

/// Compressed or Uncompressed conversion
///
/// Conversion from the binary value of the point on the curve is performed in one of
/// compressed, uncompressed, or hybrid conversions.  The default is compressed, except
/// for binary curves.
///
/// Further documentation is available in the [X9.62] standard.
///
/// [X9.62]: http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.202.2977&rep=rep1&type=pdf
#[derive(Copy, Clone)]
pub struct PointConversionForm(ffi::point_conversion_form_t);

impl PointConversionForm {
    /// Compressed conversion from point value.
    pub const COMPRESSED: PointConversionForm =
        PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED);

    /// Uncompressed conversion from point value.
    pub const UNCOMPRESSED: PointConversionForm =
        PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED);

    /// Performs both compressed and uncompressed conversions.
    pub const HYBRID: PointConversionForm =
        PointConversionForm(ffi::point_conversion_form_t::POINT_CONVERSION_HYBRID);
}

/// Named Curve or Explicit
///
/// This type acts as a boolean as to whether the `EcGroup` is named or explicit.
#[derive(Copy, Clone)]
pub struct Asn1Flag(c_int);

impl Asn1Flag {
    /// Curve defined using polynomial parameters
    ///
    /// Most applications use a named EC_GROUP curve, however, support
    /// is included to explicitly define the curve used to calculate keys
    /// This information would need to be known by both endpoint to make communication
    /// effective.
    ///
    /// OPENSSL_EC_EXPLICIT_CURVE, but that was only added in 1.1.
    /// Man page documents that 0 can be used in older versions.
    ///
    /// OpenSSL documentation at [`EC_GROUP`]
    ///
    /// [`EC_GROUP`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_seed_len.html
    pub const EXPLICIT_CURVE: Asn1Flag = Asn1Flag(0);

    /// Standard Curves
    ///
    /// Curves that make up the typical encryption use cases.  The collection of curves
    /// are well known but extensible.
    ///
    /// OpenSSL documentation at [`EC_GROUP`]
    ///
    /// [`EC_GROUP`]: https://www.openssl.org/docs/manmaster/man3/EC_GROUP_order_bits.html
    pub const NAMED_CURVE: Asn1Flag = Asn1Flag(ffi::OPENSSL_EC_NAMED_CURVE);
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_GROUP;
    fn drop = ffi::EC_GROUP_free;

    /// Describes the curve
    ///
    /// A curve can be of the named curve type.  These curves can be discovered
    /// using openssl binary `openssl ecparam -list_curves`.  Other operations
    /// are available in the [wiki].  These named curves are available in the
    /// [`Nid`] module.
    ///
    /// Curves can also be generated using prime field parameters or a binary field.
    ///
    /// Prime fields use the formula `y^2 mod p = x^3 + ax + b mod p`.  Binary
    /// fields use the formula `y^2 + xy = x^3 + ax^2 + b`.  Named curves have
    /// assured security.  To prevent accidental vulnerabilities, they should
    /// be preferred.
    ///
    /// [wiki]: https://wiki.openssl.org/index.php/Command_Line_Elliptic_Curve_Operations
    /// [`Nid`]: ../nid/index.html
    pub struct EcGroup;
}

impl EcGroup {
    /// Returns the group of a standard named curve.
    ///
    /// OpenSSL documentation at [`EC_GROUP_new`].
    ///
    /// [`EC_GROUP_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_new.html
    pub fn from_curve_name(nid: Nid) -> Result<EcGroup, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_GROUP_new_by_curve_name(nid.as_raw())).map(|p| EcGroup::from_ptr(p))
        }
    }
}

impl EcGroupRef {
    /// Places the components of a curve over a prime field in the provided `BigNum`s.
    /// The components make up the formula `y^2 mod p = x^3 + ax + b mod p`.
    ///
    /// OpenSSL documentation available at [`EC_GROUP_get_curve_GFp`]
    ///
    /// [`EC_GROUP_get_curve_GFp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_curve_GFp.html
    pub fn components_gfp(
        &self,
        p: &mut BigNumRef,
        a: &mut BigNumRef,
        b: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_curve_GFp(
                self.as_ptr(),
                p.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Places the cofactor of the group in the provided `BigNum`.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_cofactor`]
    ///
    /// [`EC_GROUP_get_cofactor`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_cofactor.html
    pub fn cofactor(
        &self,
        cofactor: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_cofactor(
                self.as_ptr(),
                cofactor.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Returns the degree of the curve.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_degree`]
    ///
    /// [`EC_GROUP_get_degree`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_degree.html
    #[allow(clippy::unnecessary_cast)]
    pub fn degree(&self) -> u32 {
        unsafe { ffi::EC_GROUP_get_degree(self.as_ptr()) as u32 }
    }

    /// Returns the number of bits in the group order.
    ///
    /// OpenSSL documentation at [`EC_GROUP_order_bits`]
    ///
    /// [`EC_GROUP_order_bits`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_order_bits.html
    pub fn order_bits(&self) -> u32 {
        unsafe { ffi::EC_GROUP_order_bits(self.as_ptr()) as u32 }
    }

    /// Returns the generator for the given curve as a [`EcPoint`].
    ///
    /// OpenSSL documentation at [`EC_GROUP_get0_generator`]
    ///
    /// [`EC_GROUP_get0_generator`]: https://www.openssl.org/docs/man1.1.0/man3/EC_GROUP_get0_generator.html
    pub fn generator(&self) -> &EcPointRef {
        unsafe {
            let ptr = ffi::EC_GROUP_get0_generator(self.as_ptr());
            EcPointRef::from_ptr(ptr as *mut _)
        }
    }

    /// Places the order of the curve in the provided `BigNum`.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_order`]
    ///
    /// [`EC_GROUP_get_order`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_order.html
    pub fn order(
        &self,
        order: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_GROUP_get_order(
                self.as_ptr(),
                order.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Sets the flag determining if the group corresponds to a named curve or must be explicitly
    /// parameterized.
    ///
    /// This defaults to `EXPLICIT_CURVE` in OpenSSL 1.0.1 and 1.0.2, but `NAMED_CURVE` in OpenSSL
    /// 1.1.0.
    pub fn set_asn1_flag(&mut self, flag: Asn1Flag) {
        unsafe {
            ffi::EC_GROUP_set_asn1_flag(self.as_ptr(), flag.0);
        }
    }

    /// Returns the name of the curve, if a name is associated.
    ///
    /// OpenSSL documentation at [`EC_GROUP_get_curve_name`]
    ///
    /// [`EC_GROUP_get_curve_name`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_GROUP_get_curve_name.html
    pub fn curve_name(&self) -> Option<Nid> {
        let nid = unsafe { ffi::EC_GROUP_get_curve_name(self.as_ptr()) };
        if nid > 0 {
            Some(Nid::from_raw(nid))
        } else {
            None
        }
    }
}

foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_POINT;
    fn drop = ffi::EC_POINT_free;

    /// Represents a point on the curve
    ///
    /// OpenSSL documentation at [`EC_POINT_new`]
    ///
    /// [`EC_POINT_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_new.html
    pub struct EcPoint;
}

impl EcPointRef {
    /// Computes `a + b`, storing the result in `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_add`]
    ///
    /// [`EC_POINT_add`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_add.html
    pub fn add(
        &mut self,
        group: &EcGroupRef,
        a: &EcPointRef,
        b: &EcPointRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_add(
                group.as_ptr(),
                self.as_ptr(),
                a.as_ptr(),
                b.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Computes `q * m`, storing the result in `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_mul`]
    ///
    /// [`EC_POINT_mul`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_mul.html
    pub fn mul(
        &mut self,
        group: &EcGroupRef,
        q: &EcPointRef,
        m: &BigNumRef,
        // FIXME should be &mut
        ctx: &BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                ptr::null(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Computes `generator * n`, storing the result in `self`.
    pub fn mul_generator(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        // FIXME should be &mut
        ctx: &BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                ptr::null(),
                ptr::null(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Computes `generator * n + q * m`, storing the result in `self`.
    pub fn mul_full(
        &mut self,
        group: &EcGroupRef,
        n: &BigNumRef,
        q: &EcPointRef,
        m: &BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_mul(
                group.as_ptr(),
                self.as_ptr(),
                n.as_ptr(),
                q.as_ptr(),
                m.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Inverts `self`.
    ///
    /// OpenSSL documentation at [`EC_POINT_invert`]
    ///
    /// [`EC_POINT_invert`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_invert.html
    pub fn invert(&mut self, group: &EcGroupRef, ctx: &BigNumContextRef) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_invert(
                group.as_ptr(),
                self.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }

    /// Serializes the point to a binary representation.
    ///
    /// OpenSSL documentation at [`EC_POINT_point2oct`]
    ///
    /// [`EC_POINT_point2oct`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_point2oct.html
    pub fn to_bytes(
        &self,
        group: &EcGroupRef,
        form: PointConversionForm,
        ctx: &mut BigNumContextRef,
    ) -> Result<Vec<u8>, ErrorStack> {
        unsafe {
            let len = ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                ptr::null_mut(),
                0,
                ctx.as_ptr(),
            );
            if len == 0 {
                return Err(ErrorStack::get());
            }
            let mut buf = vec![0; len];
            let len = ffi::EC_POINT_point2oct(
                group.as_ptr(),
                self.as_ptr(),
                form.0,
                buf.as_mut_ptr(),
                len,
                ctx.as_ptr(),
            );
            if len == 0 {
                Err(ErrorStack::get())
            } else {
                Ok(buf)
            }
        }
    }

    /// Creates a new point on the specified curve with the same value.
    ///
    /// OpenSSL documentation at [`EC_POINT_dup`]
    ///
    /// [`EC_POINT_dup`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_dup.html
    pub fn to_owned(&self, group: &EcGroupRef) -> Result<EcPoint, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_POINT_dup(self.as_ptr(), group.as_ptr())).map(|p| EcPoint::from_ptr(p))
        }
    }

    /// Determines if this point is equal to another.
    ///
    /// OpenSSL doucmentation at [`EC_POINT_cmp`]
    ///
    /// [`EC_POINT_cmp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_cmp.html
    pub fn eq(
        &self,
        group: &EcGroupRef,
        other: &EcPointRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<bool, ErrorStack> {
        unsafe {
            let res = cvt_n(ffi::EC_POINT_cmp(
                group.as_ptr(),
                self.as_ptr(),
                other.as_ptr(),
                ctx.as_ptr(),
            ))?;
            Ok(res == 0)
        }
    }

    /// Place affine coordinates of a curve over a prime field in the provided
    /// `x` and `y` `BigNum`s
    ///
    /// OpenSSL documentation at [`EC_POINT_get_affine_coordinates_GFp`]
    ///
    /// [`EC_POINT_get_affine_coordinates_GFp`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_get_affine_coordinates_GFp.html
    pub fn affine_coordinates_gfp(
        &self,
        group: &EcGroupRef,
        x: &mut BigNumRef,
        y: &mut BigNumRef,
        ctx: &mut BigNumContextRef,
    ) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::EC_POINT_get_affine_coordinates_GFp(
                group.as_ptr(),
                self.as_ptr(),
                x.as_ptr(),
                y.as_ptr(),
                ctx.as_ptr(),
            ))
            .map(|_| ())
        }
    }
}

impl EcPoint {
    /// Creates a new point on the specified curve.
    ///
    /// OpenSSL documentation at [`EC_POINT_new`]
    ///
    /// [`EC_POINT_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_new.html
    pub fn new(group: &EcGroupRef) -> Result<EcPoint, ErrorStack> {
        unsafe { cvt_p(ffi::EC_POINT_new(group.as_ptr())).map(|p| EcPoint::from_ptr(p)) }
    }

    /// Creates point from a binary representation
    ///
    /// OpenSSL documentation at [`EC_POINT_oct2point`]
    ///
    /// [`EC_POINT_oct2point`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_POINT_oct2point.html
    pub fn from_bytes(
        group: &EcGroupRef,
        buf: &[u8],
        ctx: &mut BigNumContextRef,
    ) -> Result<EcPoint, ErrorStack> {
        let point = EcPoint::new(group)?;
        unsafe {
            cvt(ffi::EC_POINT_oct2point(
                group.as_ptr(),
                point.as_ptr(),
                buf.as_ptr(),
                buf.len(),
                ctx.as_ptr(),
            ))?;
        }
        Ok(point)
    }
}

generic_foreign_type_and_impl_send_sync! {
    type CType = ffi::EC_KEY;
    fn drop = ffi::EC_KEY_free;

    /// Public and optional Private key on the given curve
    ///
    /// OpenSSL documentation at [`EC_KEY_new`]
    ///
    /// [`EC_KEY_new`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_new.html
    pub struct EcKey<T>;

    /// Reference to [`EcKey`]
    ///
    /// [`EcKey`]: struct.EcKey.html
    pub struct EcKeyRef<T>;
}

impl<T> EcKeyRef<T>
where
    T: HasPrivate,
{
    private_key_to_pem! {
        /// Serializes the private key to a PEM-encoded ECPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN EC PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_ECPrivateKey`].
        ///
        /// [`PEM_write_bio_ECPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_ECPrivateKey.html
        private_key_to_pem,
        /// Serializes the private key to a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The output will have a header of `-----BEGIN EC PRIVATE KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_ECPrivateKey`].
        ///
        /// [`PEM_write_bio_ECPrivateKey`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_ECPrivateKey.html
        private_key_to_pem_passphrase,
        ffi::PEM_write_bio_ECPrivateKey
    }

    to_der! {
        /// Serializes the private key into a DER-encoded ECPrivateKey structure.
        ///
        /// This corresponds to [`i2d_ECPrivateKey`].
        ///
        /// [`i2d_ECPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_ECPrivate_key.html
        private_key_to_der,
        ffi::i2d_ECPrivateKey
    }

    /// Return [`EcPoint`] associated with the private key
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_private_key`]
    ///
    /// [`EC_KEY_get0_private_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_private_key.html
    pub fn private_key(&self) -> &BigNumRef {
        unsafe {
            let ptr = ffi::EC_KEY_get0_private_key(self.as_ptr());
            BigNumRef::from_ptr(ptr as *mut _)
        }
    }
}

impl<T> EcKeyRef<T>
where
    T: HasPublic,
{
    /// Returns the public key.
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_public_key`]
    ///
    /// [`EC_KEY_get0_public_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_public_key.html
    pub fn public_key(&self) -> &EcPointRef {
        unsafe {
            let ptr = ffi::EC_KEY_get0_public_key(self.as_ptr());
            EcPointRef::from_ptr(ptr as *mut _)
        }
    }

    to_pem! {
        /// Serialies the public key into a PEM-encoded SubjectPublicKeyInfo structure.
        ///
        /// The output will have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_write_bio_EC_PUBKEY`].
        ///
        /// [`PEM_write_bio_EC_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_write_bio_EC_PUBKEY.html
        public_key_to_pem,
        ffi::PEM_write_bio_EC_PUBKEY
    }

    to_der! {
        /// Serializes the public key into a DER-encoded SubjectPublicKeyInfo structure.
        ///
        /// This corresponds to [`i2d_EC_PUBKEY`].
        ///
        /// [`i2d_EC_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/i2d_EC_PUBKEY.html
        public_key_to_der,
        ffi::i2d_EC_PUBKEY
    }
}

impl<T> EcKeyRef<T>
where
    T: HasParams,
{
    /// Return [`EcGroup`] of the `EcKey`
    ///
    /// OpenSSL documentation at [`EC_KEY_get0_group`]
    ///
    /// [`EC_KEY_get0_group`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_get0_group.html
    pub fn group(&self) -> &EcGroupRef {
        unsafe {
            let ptr = ffi::EC_KEY_get0_group(self.as_ptr());
            EcGroupRef::from_ptr(ptr as *mut _)
        }
    }

    /// Checks the key for validity.
    ///
    /// OpenSSL documentation at [`EC_KEY_check_key`]
    ///
    /// [`EC_KEY_check_key`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_check_key.html
    pub fn check_key(&self) -> Result<(), ErrorStack> {
        unsafe { cvt(ffi::EC_KEY_check_key(self.as_ptr())).map(|_| ()) }
    }
}

impl<T> ToOwned for EcKeyRef<T> {
    type Owned = EcKey<T>;

    fn to_owned(&self) -> EcKey<T> {
        unsafe {
            let r = ffi::EC_KEY_up_ref(self.as_ptr());
            assert!(r == 1);
            EcKey::from_ptr(self.as_ptr())
        }
    }
}

impl EcKey<Params> {
    /// Constructs an `EcKey` corresponding to a known curve.
    ///
    /// It will not have an associated public or private key. This kind of key is primarily useful
    /// to be provided to the `set_tmp_ecdh` methods on `Ssl` and `SslContextBuilder`.
    ///
    /// OpenSSL documentation at [`EC_KEY_new_by_curve_name`]
    ///
    /// [`EC_KEY_new_by_curve_name`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_new_by_curve_name.html
    pub fn from_curve_name(nid: Nid) -> Result<EcKey<Params>, ErrorStack> {
        unsafe {
            init();
            cvt_p(ffi::EC_KEY_new_by_curve_name(nid.as_raw())).map(|p| EcKey::from_ptr(p))
        }
    }

    /// Constructs an `EcKey` corresponding to a curve.
    ///
    /// This corresponds to [`EC_KEY_set_group`].
    ///
    /// [`EC_KEY_set_group`]: https://www.openssl.org/docs/man1.1.0/crypto/EC_KEY_new.html
    pub fn from_group(group: &EcGroupRef) -> Result<EcKey<Params>, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new())
                .map(|p| EcKey::from_ptr(p))
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr())).map(|_| key)
                })
        }
    }
}

impl EcKey<Public> {
    /// Constructs an `EcKey` from the specified group with the associated `EcPoint`, public_key.
    ///
    /// This will only have the associated public_key.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use boring::bn::BigNumContext;
    /// use boring::ec::*;
    /// use boring::nid::Nid;
    /// use boring::pkey::PKey;
    ///
    /// // get bytes from somewhere, i.e. this will not produce a valid key
    /// let public_key: Vec<u8> = vec![];
    ///
    /// // create an EcKey from the binary form of a EcPoint
    /// let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    /// let mut ctx = BigNumContext::new().unwrap();
    /// let point = EcPoint::from_bytes(&group, &public_key, &mut ctx).unwrap();
    /// let key = EcKey::from_public_key(&group, &point);
    /// ```
    pub fn from_public_key(
        group: &EcGroupRef,
        public_key: &EcPointRef,
    ) -> Result<EcKey<Public>, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new())
                .map(|p| EcKey::from_ptr(p))
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr())).map(|_| key)
                })
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_public_key(
                        key.as_ptr(),
                        public_key.as_ptr(),
                    ))
                    .map(|_| key)
                })
        }
    }

    /// Constructs a public key from its affine coordinates.
    pub fn from_public_key_affine_coordinates(
        group: &EcGroupRef,
        x: &BigNumRef,
        y: &BigNumRef,
    ) -> Result<EcKey<Public>, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new())
                .map(|p| EcKey::from_ptr(p))
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr())).map(|_| key)
                })
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_public_key_affine_coordinates(
                        key.as_ptr(),
                        x.as_ptr(),
                        y.as_ptr(),
                    ))
                    .map(|_| key)
                })
        }
    }

    from_pem! {
        /// Decodes a PEM-encoded SubjectPublicKeyInfo structure containing a EC key.
        ///
        /// The input should have a header of `-----BEGIN PUBLIC KEY-----`.
        ///
        /// This corresponds to [`PEM_read_bio_EC_PUBKEY`].
        ///
        /// [`PEM_read_bio_EC_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_EC_PUBKEY.html
        public_key_from_pem,
        EcKey<Public>,
        ffi::PEM_read_bio_EC_PUBKEY
    }

    from_der! {
        /// Decodes a DER-encoded SubjectPublicKeyInfo structure containing a EC key.
        ///
        /// This corresponds to [`d2i_EC_PUBKEY`].
        ///
        /// [`d2i_EC_PUBKEY`]: https://www.openssl.org/docs/man1.1.0/crypto/d2i_EC_PUBKEY.html
        public_key_from_der,
        EcKey<Public>,
        ffi::d2i_EC_PUBKEY,
        ::libc::c_long
    }
}

impl EcKey<Private> {
    /// Generates a new public/private key pair on the specified curve.
    pub fn generate(group: &EcGroupRef) -> Result<EcKey<Private>, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new())
                .map(|p| EcKey::from_ptr(p))
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr())).map(|_| key)
                })
                .and_then(|key| cvt(ffi::EC_KEY_generate_key(key.as_ptr())).map(|_| key))
        }
    }

    /// Constructs an public/private key pair given a curve, a private key and a public key point.
    pub fn from_private_components(
        group: &EcGroupRef,
        private_number: &BigNumRef,
        public_key: &EcPointRef,
    ) -> Result<EcKey<Private>, ErrorStack> {
        unsafe {
            cvt_p(ffi::EC_KEY_new())
                .map(|p| EcKey::from_ptr(p))
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_group(key.as_ptr(), group.as_ptr())).map(|_| key)
                })
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_private_key(
                        key.as_ptr(),
                        private_number.as_ptr(),
                    ))
                    .map(|_| key)
                })
                .and_then(|key| {
                    cvt(ffi::EC_KEY_set_public_key(
                        key.as_ptr(),
                        public_key.as_ptr(),
                    ))
                    .map(|_| key)
                })
        }
    }

    private_key_from_pem! {
        /// Deserializes a private key from a PEM-encoded ECPrivateKey structure.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        ///
        /// This corresponds to `PEM_read_bio_ECPrivateKey`.
        private_key_from_pem,

        /// Deserializes a private key from a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        ///
        /// This corresponds to `PEM_read_bio_ECPrivateKey`.
        private_key_from_pem_passphrase,

        /// Deserializes a private key from a PEM-encoded encrypted ECPrivateKey structure.
        ///
        /// The callback should fill the password into the provided buffer and return its length.
        ///
        /// The input should have a header of `-----BEGIN EC PRIVATE KEY-----`.
        ///
        /// This corresponds to `PEM_read_bio_ECPrivateKey`.
        private_key_from_pem_callback,
        EcKey<Private>,
        ffi::PEM_read_bio_ECPrivateKey
    }

    from_der! {
        /// Decodes a DER-encoded elliptic curve private key structure.
        ///
        /// This corresponds to [`d2i_ECPrivateKey`].
        ///
        /// [`d2i_ECPrivateKey`]: https://www.openssl.org/docs/man1.0.2/crypto/d2i_ECPrivate_key.html
        private_key_from_der,
        EcKey<Private>,
        ffi::d2i_ECPrivateKey,
        ::libc::c_long
    }
}

impl<T> Clone for EcKey<T> {
    fn clone(&self) -> EcKey<T> {
        (**self).to_owned()
    }
}

impl<T> fmt::Debug for EcKey<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EcKey")
    }
}

#[cfg(test)]
mod test {
    use hex::FromHex;

    use super::*;
    use crate::bn::{BigNum, BigNumContext};
    use crate::nid::Nid;

    #[test]
    fn key_new_by_curve_name() {
        EcKey::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    }

    #[test]
    fn generate() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        EcKey::generate(&group).unwrap();
    }

    #[test]
    fn cofactor() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut cofactor = BigNum::new().unwrap();
        group.cofactor(&mut cofactor, &mut ctx).unwrap();
        let one = BigNum::from_u32(1).unwrap();
        assert_eq!(cofactor, one);
    }

    #[test]
    #[allow(clippy::redundant_clone)]
    fn dup() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        drop(key.clone());
    }

    #[test]
    fn point_new() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        EcPoint::new(&group).unwrap();
    }

    #[test]
    fn point_bytes() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let point = key.public_key();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = point
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();
        let point2 = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        assert!(point.eq(&group, &point2, &mut ctx).unwrap());
    }

    #[test]
    fn point_owned() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let point = key.public_key();
        let owned = point.to_owned(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        assert!(owned.eq(&group, point, &mut ctx).unwrap());
    }

    #[test]
    fn mul_generator() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut public_key = EcPoint::new(&group).unwrap();
        public_key
            .mul_generator(&group, key.private_key(), &ctx)
            .unwrap();
        assert!(public_key.eq(&group, key.public_key(), &mut ctx).unwrap());
    }

    #[test]
    fn generator() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let gen = group.generator();
        let one = BigNum::from_u32(1).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let mut ecp = EcPoint::new(&group).unwrap();
        ecp.mul_generator(&group, &one, &ctx).unwrap();
        assert!(ecp.eq(&group, gen, &mut ctx).unwrap());
    }

    #[test]
    fn key_from_public_key() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let bytes = key
            .public_key()
            .to_bytes(&group, PointConversionForm::COMPRESSED, &mut ctx)
            .unwrap();

        drop(key);
        let public_key = EcPoint::from_bytes(&group, &bytes, &mut ctx).unwrap();
        let ec_key = EcKey::from_public_key(&group, &public_key).unwrap();
        assert!(ec_key.check_key().is_ok());
    }

    #[test]
    fn key_from_private_components() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();

        let dup_key =
            EcKey::from_private_components(&group, key.private_key(), key.public_key()).unwrap();
        dup_key.check_key().unwrap();

        assert!(key.private_key() == dup_key.private_key());
    }

    #[test]
    fn key_from_affine_coordinates() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let x = Vec::from_hex("30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e")
            .unwrap();
        let y = Vec::from_hex("e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
            .unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();
        assert!(ec_key.check_key().is_ok());
    }

    #[test]
    fn get_affine_coordinates() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let x = Vec::from_hex("30a0424cd21c2944838a2d75c92b37e76ea20d9f00893a3b4eee8a3c0aafec3e")
            .unwrap();
        let y = Vec::from_hex("e04b65e92456d9888b52b379bdfbd51ee869ef1f0fc65b6659695b6cce081723")
            .unwrap();

        let xbn = BigNum::from_slice(&x).unwrap();
        let ybn = BigNum::from_slice(&y).unwrap();

        let ec_key = EcKey::from_public_key_affine_coordinates(&group, &xbn, &ybn).unwrap();

        let mut xbn2 = BigNum::new().unwrap();
        let mut ybn2 = BigNum::new().unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let ec_key_pk = ec_key.public_key();
        ec_key_pk
            .affine_coordinates_gfp(&group, &mut xbn2, &mut ybn2, &mut ctx)
            .unwrap();
        assert_eq!(xbn2, xbn);
        assert_eq!(ybn2, ybn);
    }
}
