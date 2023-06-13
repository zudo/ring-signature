use rand_core::OsRng;
use ring_signature::blsag::BLSAG;
use ring_signature::Ring;
use ring_signature::Secret;
use sha2::Sha512;
const X: usize = 11;
const DATA: &[u8] = b"hi";
fn main() {
    let rng = &mut OsRng {};
    let secret = Secret::new(rng);
    let ring = Ring::random(X - 1);
    let blsag = BLSAG::sign::<Sha512>(rng, &secret, ring, DATA).unwrap();
    println!("{:?}", blsag);
    println!("Bytes: {}", bincode::serialize(&blsag).unwrap().len());
    println!("Valid: {}", blsag.verify::<Sha512>(DATA));
}
