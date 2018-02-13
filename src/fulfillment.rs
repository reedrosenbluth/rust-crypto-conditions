extern crate crypto_hash;

use condition::{Condition, PreimageSha256Condition, PrefixSha256Condition};

use self::crypto_hash::{Algorithm, hex_digest};

type Bytes = Vec<u8>;

pub trait Fulfillment {
    type C: Condition + PartialEq;

    fn verify(&self, condition: &Self::C) -> bool;

    fn get_condition(&self) -> Self::C;
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PreimageSha256Fulfillment { preimage: Bytes }

impl Fulfillment for PreimageSha256Fulfillment {
    type C = PreimageSha256Condition;

    fn verify(&self, condition: &Self::C) -> bool {
        let derived_condition = self.get_condition();
        derived_condition == *condition
    }

    fn get_condition(&self) -> Self::C {
        let preimage = String::from_utf8(self.preimage.clone()).unwrap();
        let fingerprint = hex_digest(Algorithm::SHA256, preimage.as_bytes());

        PreimageSha256Condition {
            fingerprint: fingerprint.into_bytes(),
            cost: preimage.len()
        }
    }
}

impl<'a> From<&'a PreimageSha256Fulfillment> for PreimageSha256Condition {
    fn from(f: &'a PreimageSha256Fulfillment) -> Self { f.get_condition() }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PrefixSha256Fulfillment<F: Fulfillment> {
    pub prefix: Bytes,
    pub max_message_length: usize,
    pub subfulfillment: Box<F>
}

impl<F: Fulfillment> Fulfillment for PrefixSha256Fulfillment<F> {
    type C = PrefixSha256Condition<F::C>;

    fn verify(&self, condition: &Self::C) -> bool {
        let derived_condition = self.get_condition();
        derived_condition == *condition
    }

    fn get_condition(&self) -> Self::C {
        let max_message_length = self.max_message_length;
        let subcondition = Box::new(self.subfulfillment.get_condition());

        PrefixSha256Condition {
            cost: self.prefix.len() + max_message_length + &subcondition.get_cost() + 1024,
            prefix: self.prefix.clone(),
            max_message_length,
            subcondition: subcondition
        }
    }
}

impl<'a, F: Fulfillment> From<&'a PrefixSha256Fulfillment<F>> for PrefixSha256Condition<F::C> {
    fn from(f: &'a PrefixSha256Fulfillment<F>) -> Self { f.get_condition() }
}


#[test]
fn generate_condition() {
    let f1 = PreimageSha256Fulfillment { preimage: b"test".to_vec() };

    let f2 = PrefixSha256Fulfillment {
        prefix: b"pre".to_vec(),
        max_message_length: 100,
        subfulfillment: Box::new(f1.clone())
    };

    let c1 = PreimageSha256Condition::from(&f1);
    let c2 = PrefixSha256Condition::from(&f2);

    println!("{:?}", c2);

    assert!(f2.verify(&c2));
}