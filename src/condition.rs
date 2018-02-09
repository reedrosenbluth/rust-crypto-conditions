extern crate crypto_hash;

use self::crypto_hash::{Algorithm, hex_digest};

type Bytes = Vec<u8>;

const MAX_COST: usize = 2097152;

pub trait Condition {
  fn get_type_name(&self) -> String;

  fn is_compound(&self) -> bool { false }

  fn get_cost(&self) -> usize;

  fn get_fingerprint(&self) -> String;

  fn get_subtypes(&self) -> Vec<String> { Vec::new() }

  fn serialize_uri(&self) -> String {
    let fingerprint = self.get_fingerprint();
    let name = self.get_type_name();
    let cost = self.get_cost();

    if self.is_compound() {
      let subtypes = self.get_subtypes().join(",");
      format!("ni:///sha-256;{}?fpt={}&cost={}&subtypes={}", fingerprint, name, cost, subtypes)
    } else {
      format!("ni:///sha-256;{}?fpt={}&cost={}", fingerprint, name, cost)
    }
  }
}


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PreimageSha256Condition { pub fingerprint: Bytes, pub cost: usize }

impl Condition for PreimageSha256Condition {
  fn get_type_name(&self) -> String { String::from("preimage-sha-256") }

  fn is_compound(&self) -> bool { false }

  fn get_cost(&self) -> usize { self.cost }

  fn get_fingerprint(&self) -> String {
    String::from_utf8(self.fingerprint.clone()).unwrap()
  }
}

pub struct PrefixSha256Condition<C: Condition> {
  prefix: Bytes,
  max_message_length: usize,
  subcondition: Box<C>,
  cost: usize
}

impl<T: Condition> Condition for PrefixSha256Condition<T> {
  fn get_type_name(&self) -> String { String::from("prefix-sha-256") }

  fn is_compound(&self) -> bool { true }

  fn get_cost(&self) -> usize {
    let subcondition_cost = self.subcondition.get_cost();
    self.prefix.len() + self.max_message_length + subcondition_cost + 1024
  }

  fn get_fingerprint(&self) -> String {
    String::from("test")
  }

  fn get_subtypes(&self) -> Vec<String> {
    let subtype = self.subcondition.get_type_name();
    vec![subtype]
  }
}

pub struct Threshold<C: Condition> {
  threshold: usize,
  subconditions: Vec<C>,
  cost: usize
}

pub struct Rsa { modulus: Bytes, cost: usize }

pub struct Ed25519 { public_key: Bytes, cost: usize }


#[test]
fn serialize() {
  let f = vec![57, 102, 56, 54, 100, 48, 56, 49, 56, 56, 52, 99, 55, 100, 54, 53, 57, 97, 50, 102, 101, 97, 97, 48, 99, 53, 53, 97, 100, 48, 49, 53, 97, 51, 98, 102, 52, 102, 49, 98, 50, 98, 48, 98, 56, 50, 50, 99, 100, 49, 53, 100, 54, 99, 49, 53, 98, 48, 102, 48, 48, 97, 48, 56];
  let p = PreimageSha256Condition { fingerprint: f, cost: 100 };
  println!("{:?}", p.serialize_uri());
}