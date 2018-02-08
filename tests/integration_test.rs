extern crate crypto_conditions;

use crypto_conditions::{Condition, Fulfillment};

#[test]
fn preimage_condition_verifies() {

  let f = Fulfillment::Preimage { preimage: b"test".to_vec() };

  let c = Condition::from(&f);

  assert!(f.verify(&c));
}