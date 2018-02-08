extern crate crypto_hash;

use self::crypto_hash::{Algorithm, hex_digest};

type Bytes = Vec<u8>;

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Condition {
  Preimage { fingerprint: Bytes },
  Prefix {
    prefix: Bytes,
    max_message_length: usize,
    subcondition: Box<Condition>
  },
  Threshold {
    threshold: usize,
    subconditions: Vec<Condition>
  },
  Rsa { modulus: Bytes },
  Ed25519 { public_key: Bytes }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Fulfillment {
  Preimage { preimage: Bytes },
  Prefix {
    prefix: Bytes,
    max_message_length: usize,
    subfulfillment: Box<Fulfillment>
  },
  Threshold {
    subfulfillments: Vec<Fulfillment>,
    subconditions: Vec<Condition>
  },
  Rsa {
    modulus: Bytes,
    signature: Bytes
  },
  Ed25519 {
    public_key: Bytes,
    signature: Bytes
  }
}

impl From<Fulfillment> for Condition {
  fn from(f: Fulfillment) -> Self {
    match f {
      Fulfillment::Preimage { preimage } => {
        let preimage = String::from_utf8(preimage).unwrap();
        let fingerprint = hex_digest(Algorithm::SHA256, preimage.as_bytes());
        Condition::Preimage { fingerprint: fingerprint.into_bytes() }
      },
      Fulfillment::Prefix { prefix, max_message_length, subfulfillment } => {
        let subcondition = Box::new(Condition::from(*subfulfillment));
        Condition::Prefix { prefix, max_message_length, subcondition }
      },
      _ => Condition::Preimage { fingerprint: vec![1,2,3] }
    }
  }
}

impl<'a> From<&'a Fulfillment> for Condition {
  fn from(f: &'a Fulfillment) -> Self {
    match *f {
      Fulfillment::Preimage { ref preimage } => {
        let preimage = String::from_utf8(preimage.clone()).unwrap();
        let fingerprint = hex_digest(Algorithm::SHA256, preimage.as_bytes());
        Condition::Preimage { fingerprint: fingerprint.into_bytes() }
      },
      Fulfillment::Prefix { ref prefix, max_message_length, ref subfulfillment } => {
        let subcondition = Box::new(Condition::from(&*subfulfillment.clone()));
        Condition::Prefix { prefix: prefix.clone(), max_message_length, subcondition }
      },
      _ => Condition::Preimage { fingerprint: vec![1,2,3] }
    }
  }
}

impl Fulfillment {
  pub fn verify(self: &Self, c: &Condition) -> bool {
    let derived_condition = Condition::from(self);
    derived_condition == *c
  }
}

