use rand_core::OsRng;
use ring_signature::mlsag::MLSAG;
use ring_signature::point_random;
use ring_signature::scalar_random;
use sha2::Sha512;
const X: usize = 11;
const Y: usize = 2;
const DATA: &[u8] = b"hi";
fn main() {
    let rng = &mut OsRng;
    let secrets = (0..Y).map(|_| scalar_random(rng)).collect::<Vec<_>>();
    let ring = (0..X)
        .map(|_| (0..Y).map(|_| point_random(&mut OsRng)).collect())
        .collect();
    let mlsag = MLSAG::sign::<Sha512>(rng, &secrets, ring, DATA).unwrap();
    println!("{:?}", mlsag);
    println!("Bytes: {}", bincode::serialize(&mlsag).unwrap().len());
    println!("Valid: {}", mlsag.verify::<Sha512>(DATA));
}
