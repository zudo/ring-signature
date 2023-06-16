use rand_core::OsRng;
use ring_signature::point_random;
use ring_signature::sag::SAG;
use ring_signature::scalar_random;
use sha2::Sha512;
const X: usize = 11;
const DATA: &[u8] = b"hi";
fn main() {
    let rng = &mut OsRng {};
    let secret = scalar_random(rng);
    let ring = (0..X - 1).map(|_| point_random(rng)).collect();
    let sag = SAG::sign::<Sha512>(rng, &secret, ring, DATA).unwrap();
    println!("{:?}", sag);
    println!("Bytes: {}", bincode::serialize(&sag).unwrap().len());
    println!("Valid: {}", sag.verify::<Sha512>(DATA));
}
