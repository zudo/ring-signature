use rand_core::OsRng;
use ring_signature::point;
use ring_signature::sag::SAG;
use ring_signature::Secret;
use sha2::Sha512;
fn main() {
    let rng = &mut OsRng {};
    let secret = Secret::new(rng);
    let n = 2;
    let ring = point::vec_1d::to_bytes(&point::vec_1d::random(n));
    let data = "hello world";
    let sag = SAG::sign::<Sha512>(rng, &secret, &ring, data).unwrap();
    println!("{:?}", sag);
    println!("{:?}", sag.verify::<Sha512>(data));
}
