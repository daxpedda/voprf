// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under both the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree and the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree.

//! Includes a series of tests for the group implementations

use crate::{Error, Group, Result};

// Test that the deserialization of a group element should throw an error if the
// identity element can be deserialized properly

#[test]
fn test_group_properties() -> Result<()> {
    use p256::NistP256;

    #[cfg(feature = "ristretto255")]
    {
        use crate::Ristretto255;

        test_identity_element_error::<Ristretto255>()?;
        test_zero_scalar_error::<Ristretto255>()?;
        #[cfg(feature = "serde")]
        test_serde::<Ristretto255>()?;
    }

    test_identity_element_error::<NistP256>()?;
    test_zero_scalar_error::<NistP256>()?;
    #[cfg(feature = "serde")]
    test_serde::<NistP256>()?;

    Ok(())
}

// Checks that the identity element cannot be deserialized
fn test_identity_element_error<G: Group>() -> Result<()> {
    let identity = G::identity_elem();
    let result = G::deserialize_elem(&G::serialize_elem(identity));
    assert!(matches!(result, Err(Error::Deserialization)));

    Ok(())
}

// Checks that the zero scalar cannot be deserialized
fn test_zero_scalar_error<G: Group>() -> Result<()> {
    let zero_scalar = G::zero_scalar();
    let result = G::deserialize_scalar(&G::serialize_scalar(zero_scalar));
    assert!(matches!(result, Err(Error::Deserialization)));

    Ok(())
}

#[cfg(feature = "serde")]
fn test_serde<G: Group>() -> Result<()>
where
    G::Elem: core::fmt::Debug + PartialEq,
    G::Scalar: core::fmt::Debug + PartialEq,
{
    use super::{Element, Scalar};

    let scalar = Scalar(G::random_scalar(&mut rand_core::OsRng));
    let element = Element::<G>(G::base_elem() * &scalar.0);

    let serialized_element = bincode::serialize(&element).unwrap();
    let deserialized_element_1: Element<G> = bincode::deserialize(&serialized_element).unwrap();
    let deserialized_element_2: Element<G> =
        bincode::deserialize_from(serialized_element.as_slice()).unwrap();

    assert_eq!(element, deserialized_element_1);
    assert_eq!(element, deserialized_element_2);

    let serialized_scalar = bincode::serialize(&scalar).unwrap();
    let deserialized_scalar_1: Scalar<G> = bincode::deserialize(&serialized_scalar).unwrap();
    let deserialized_scalar_2: Scalar<G> =
        bincode::deserialize_from(serialized_scalar.as_slice()).unwrap();

    assert_eq!(scalar, deserialized_scalar_1);
    assert_eq!(scalar, deserialized_scalar_2);

    Ok(())
}
