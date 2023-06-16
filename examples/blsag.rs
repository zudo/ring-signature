use rand_core::OsRng;
use ring_signature::blsag::BLSAG;
use ring_signature::point_random;
use ring_signature::scalar_random;
use sha2::Sha512;
const X: usize = 11;
const DATA: &[u8] = b"hi";
fn main() {
    let rng = &mut OsRng {};
    let secret = scalar_random(rng);
    let ring = (0..X - 1).map(|_| point_random(rng)).collect();
    let blsag = BLSAG::sign::<Sha512>(rng, &secret, ring, DATA).unwrap();
    println!("{:?}", blsag);
    println!("Bytes: {}", bincode::serialize(&blsag).unwrap().len());
    println!("Valid: {}", blsag.verify::<Sha512>(DATA));
}
