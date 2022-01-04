// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

// Note: This group implementation of p256 is experimental for now, until
// hash-to-curve or crypto-bigint are fully supported.

#![allow(
    clippy::borrow_interior_mutable_const,
    clippy::declare_interior_mutable_const
)]

use core::ops::Add;
use core::str::FromStr;

use digest::core_api::BlockSizeUser;
use digest::{Digest, FixedOutputReset};
use generic_array::typenum::{U1, U2, U32, U33, U48};
use generic_array::{ArrayLength, GenericArray};
use num_bigint::{BigInt, Sign};
use num_integer::Integer;
use once_cell::unsync::Lazy;
use p256_::elliptic_curve::group::GroupEncoding;
use p256_::elliptic_curve::ops::Reduce;
use p256_::elliptic_curve::sec1::ToEncodedPoint;
use p256_::elliptic_curve::Field;
use p256_::ProjectivePoint;
use rand_core::{CryptoRng, RngCore};

use super::Group;
use crate::{Error, Result};

// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-8.2
// `L: 48`
pub type L = U48;

#[cfg(feature = "p256")]
impl Group for ProjectivePoint {
    const SUITE_ID: usize = 0x0003;

    // Implements the `hash_to_curve()` function from
    // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-3
    fn hash_to_curve<H: BlockSizeUser + Digest + FixedOutputReset, D: ArrayLength<u8> + Add<U1>>(
        msg: &[u8],
        dst: GenericArray<u8, D>,
    ) -> Result<Self>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        Ok(ProjectivePoint::hash_from_bytes::<
            p256_::hash2field::ExpandMsgXmd<H>,
        >(msg, &dst))
    }

    // Implements the `HashToScalar()` function
    fn hash_to_scalar<
        'a,
        H: BlockSizeUser + Digest + FixedOutputReset,
        D: ArrayLength<u8> + Add<U1>,
        I: IntoIterator<Item = &'a [u8]>,
    >(
        input: I,
        dst: GenericArray<u8, D>,
    ) -> Result<Self::Scalar>
    where
        <D as Add<U1>>::Output: ArrayLength<u8>,
    {
        // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf#[{%22num%22:211,%22gen%22:0},{%22name%22:%22XYZ%22},70,700,0]
        // P-256 `n` is defined as
        // `115792089210356248762697446949407573529996955224135760342
        // 422259061068512044369`
        const N: Lazy<BigInt> = Lazy::new(|| {
            BigInt::from_str(
                "115792089210356248762697446949407573529996955224135760342422259061068512044369",
            )
            .unwrap()
        });

        // https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-11#section-5.3
        // `HashToScalar` is `hash_to_field`
        let uniform_bytes = super::expand::expand_message_xmd::<H, L, _, _>(input, dst)?;
        let bytes = BigInt::from_bytes_be(Sign::Plus, &uniform_bytes)
            .mod_floor(&N)
            .to_bytes_be()
            .1;
        let mut result = GenericArray::default();
        result[..bytes.len()].copy_from_slice(&bytes);

        Ok(p256_::Scalar::from_be_bytes_reduced(result))
    }

    type ElemLen = U33;
    type Scalar = p256_::Scalar;
    type ScalarLen = U32;

    fn from_scalar_slice_unchecked(
        scalar_bits: &GenericArray<u8, Self::ScalarLen>,
    ) -> Result<Self::Scalar> {
        Ok(Self::Scalar::from_be_bytes_reduced(*scalar_bits))
    }

    fn random_nonzero_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::random(rng)
    }

    fn scalar_as_bytes(scalar: Self::Scalar) -> GenericArray<u8, Self::ScalarLen> {
        scalar.into()
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert().unwrap_or(Self::Scalar::zero())
    }

    fn from_element_slice_unchecked(
        element_bits: &GenericArray<u8, Self::ElemLen>,
    ) -> Result<Self> {
        Option::from(Self::from_bytes(element_bits)).ok_or(Error::PointError)
    }

    fn to_arr(&self) -> GenericArray<u8, Self::ElemLen> {
        let bytes = self.to_affine().to_encoded_point(true);
        let bytes = bytes.as_bytes();
        let mut result = GenericArray::default();
        result[..bytes.len()].copy_from_slice(bytes);
        result
    }

    fn base_point() -> Self {
        Self::generator()
    }

    fn identity() -> Self {
        Self::identity()
    }

    fn scalar_zero() -> Self::Scalar {
        Self::Scalar::zero()
    }
}
