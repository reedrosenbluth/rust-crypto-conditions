extern crate crypto_hash;

use condition::{Condition, PreimageSha256Condition};

use self::crypto_hash::{Algorithm, hex_digest};

type Bytes = Vec<u8>;

pub trait Fulfillment {
  fn verify<C: Condition>(&self, condition: &C) -> bool;
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PreimageSha256Fulfillment { preimage: Bytes }

impl Fulfillment for PreimageSha256Fulfillment {
  fn verify<PreimageSha256Condition>(&self, condition: &PreimageSha256Condition) -> bool {
    let derived_condition = PreimageSha256Condition::from(self);
    derived_condition == *condition
  }
}

impl<'a> From<&'a PreimageSha256Fulfillment> for PreimageSha256Condition {
  fn from(f: &'a PreimageSha256Fulfillment) -> Self {
    let preimage = String::from_utf8(f.preimage.clone()).unwrap();
    let fingerprint = hex_digest(Algorithm::SHA256, preimage.as_bytes());

    PreimageSha256Condition {
      fingerprint: fingerprint.into_bytes(),
      cost: preimage.len()
    }
  }
}

#[test]
fn generate_condition() {
  let f = PreimageSha256Fulfillment { preimage: b"test".to_vec() };

  let c = PreimageSha256Condition::from(&f);

  println!("{:?}", c)

  // assert!(f.verify(&c));
}