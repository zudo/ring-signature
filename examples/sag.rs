use rand_core::OsRng;
use ring_signature::sag::SAG;
use ring_signature::Ring;
use ring_signature::Secret;
use sha2::Sha512;
const X: usize = 11;
const DATA: &[u8] = b"hi";
fn main() {
    let rng = &mut OsRng {};
    let secret = Secret::new(rng);
    let ring = Ring::random(rng, X - 1);
    let sag = SAG::sign::<Sha512>(rng, &secret, ring, DATA).unwrap();
    println!("{:?}", sag);
    println!("Bytes: {}", bincode::serialize(&sag).unwrap().len());
    println!("Valid: {}", sag.verify::<Sha512>(DATA));
}
