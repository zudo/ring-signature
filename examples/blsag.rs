use rand_core::OsRng;
use ring_signature::blsag::BLSAG;
use ring_signature::PointVec;
use ring_signature::Secret;
use sha2::Sha512;
fn main() {
    let rng = &mut OsRng {};
    let secret = Secret::new(rng);
    let n = 2;
    let data_0 = b"hello";
    let data_1 = b"world";
    let ring_0 = PointVec::random(n - 1);
    let ring_1 = PointVec::random(n - 1);
    let blsag_0 = BLSAG::sign::<Sha512>(rng, &secret, ring_0, data_0).unwrap();
    let blsag_1 = BLSAG::sign::<Sha512>(rng, &secret, ring_1, data_1).unwrap();
    println!("{:?}", blsag_0);
    println!("{:?}", blsag_1);
    println!("{:?}", blsag_0.verify::<Sha512>(data_0));
    println!("{:?}", blsag_1.verify::<Sha512>(data_1));
    println!("{}", BLSAG::link(&[blsag_0.key_image, blsag_1.key_image]));
}
