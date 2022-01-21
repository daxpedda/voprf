// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Handles the serialization of each of the components used in the VOPRF
//! protocol

use core::ops::Add;

use digest::core_api::BlockSizeUser;
use digest::OutputSizeUser;
use generic_array::sequence::Concat;
use generic_array::typenum::{IsLess, IsLessOrEqual, Sum, U256};
use generic_array::{ArrayLength, GenericArray};

use crate::{
    BlindedElement, CipherSuite, Error, EvaluationElement, Group, NonVerifiableClient,
    NonVerifiableServer, Proof, Result, VerifiableClient, VerifiableServer,
};

//////////////////////////////////////////////////////////
// Serialization and Deserialization for High-Level API //
// ==================================================== //
//////////////////////////////////////////////////////////

/// Length of [`NonVerifiableClient`] in bytes for serialization.
pub type NonVerifiableClientLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> NonVerifiableClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, NonVerifiableClientLen<CS>> {
        CS::Group::serialize_scalar(self.blind)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;

        Ok(Self { blind })
    }
}

/// Length of [`VerifiableClient`] in bytes for serialization.
pub type VerifiableClientLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VerifiableClient<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableClientLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableClientLen<CS>: ArrayLength<u8>,
    {
        <CS::Group as Group>::serialize_scalar(self.blind)
            .concat(<CS::Group as Group>::serialize_elem(self.blinded_element))
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let blind = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;
        let blinded_element = CS::Group::deserialize_elem(&deserialize(&mut input)?)?;

        Ok(Self {
            blind,
            blinded_element,
        })
    }
}

/// Length of [`NonVerifiableServer`] in bytes for serialization.
pub type NonVerifiableServerLen<CS> = <<CS as CipherSuite>::Group as Group>::ScalarLen;

impl<CS: CipherSuite> NonVerifiableServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, NonVerifiableServerLen<CS>> {
        CS::Group::serialize_scalar(self.sk)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;

        Ok(Self { sk })
    }
}

/// Length of [`VerifiableServer`] in bytes for serialization.
pub type VerifiableServerLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ElemLen,
>;

impl<CS: CipherSuite> VerifiableServer<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, VerifiableServerLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ElemLen>,
        VerifiableServerLen<CS>: ArrayLength<u8>,
    {
        CS::Group::serialize_scalar(self.sk).concat(CS::Group::serialize_elem(self.pk))
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let sk = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;
        let pk = CS::Group::deserialize_elem(&deserialize(&mut input)?)?;

        Ok(Self { sk, pk })
    }
}

/// Length of [`Proof`] in bytes for serialization.
pub type ProofLen<CS> = Sum<
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
    <<CS as CipherSuite>::Group as Group>::ScalarLen,
>;

impl<CS: CipherSuite> Proof<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, ProofLen<CS>>
    where
        <CS::Group as Group>::ScalarLen: Add<<CS::Group as Group>::ScalarLen>,
        ProofLen<CS>: ArrayLength<u8>,
    {
        CS::Group::serialize_scalar(self.c_scalar)
            .concat(CS::Group::serialize_scalar(self.s_scalar))
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let c_scalar = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;
        let s_scalar = CS::Group::deserialize_scalar(&deserialize(&mut input)?)?;

        Ok(Proof { c_scalar, s_scalar })
    }
}

/// Length of [`BlindedElement`] in bytes for serialization.
pub type BlindedElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> BlindedElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, BlindedElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = CS::Group::deserialize_elem(&deserialize(&mut input)?)?;

        Ok(Self(value))
    }
}

/// Length of [`EvaluationElement`] in bytes for serialization.
pub type EvaluationElementLen<CS> = <<CS as CipherSuite>::Group as Group>::ElemLen;

impl<CS: CipherSuite> EvaluationElement<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
{
    /// Serialization into bytes
    pub fn serialize(&self) -> GenericArray<u8, EvaluationElementLen<CS>> {
        CS::Group::serialize_elem(self.0)
    }

    /// Deserialization from bytes
    pub fn deserialize(input: &[u8]) -> Result<Self> {
        let mut input = input.iter().copied();

        let value = CS::Group::deserialize_elem(&deserialize(&mut input)?)?;

        Ok(Self(value))
    }
}

fn deserialize<L: ArrayLength<u8>>(
    input: &mut impl Iterator<Item = u8>,
) -> Result<GenericArray<u8, L>> {
    let input = input.by_ref().take(L::USIZE);
    GenericArray::from_exact_iter(input).ok_or(Error::SizeError)
}
