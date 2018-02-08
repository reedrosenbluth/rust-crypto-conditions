extern crate crypto_conditions;

#[allow(unused_imports)]
use crypto_conditions::{Condition, Fulfillment};

fn main() {

  let f1 = Fulfillment::Preimage { preimage: b"test".to_vec() };

  let f2 = Fulfillment::Prefix { 
    prefix: b"pre".to_vec(),
    max_message_length: 100,
    subfulfillment: Box::new(f1.clone())
  };

  let c1 = Condition::from(&f1);
  let c2 = Condition::from(&f2);

  println!("\n{:?}", c1);

  println!("\n{}", f1.verify(&c1));
  println!("\n{}\n", f2.verify(&c2));
}

