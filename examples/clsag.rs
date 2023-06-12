use rand_core::OsRng;
use ring_signature::clsag::CLSAG;
use ring_signature::point;
use ring_signature::scalar;
use sha2::Sha512;
fn main() {
    let rng = &mut OsRng {};
    let ring_size = 11; // 10 decoys
    let ring_layers = 2; // 2 inputs
    let secrets = (0..ring_layers)
        .map(|_| scalar::random(rng).to_bytes())
        .collect::<Vec<_>>();
    let data_0 = b"hello";
    let data_1 = b"world";
    let ring_0 = (0..(ring_size - 1))
        .map(|_| {
            (0..ring_layers)
                .map(|_| point::random().compress().to_bytes())
                .collect()
        })
        .collect::<Vec<Vec<_>>>();
    let ring_1 = (0..(ring_size - 1))
        .map(|_| {
            (0..ring_layers)
                .map(|_| point::random().compress().to_bytes())
                .collect()
        })
        .collect::<Vec<Vec<_>>>();
    let blsag_0 = CLSAG::sign::<Sha512>(rng, &secrets.clone(), &ring_0, data_0).unwrap();
    let blsag_1 = CLSAG::sign::<Sha512>(rng, &secrets.clone(), &ring_1, data_1).unwrap();
    println!("{:?}", blsag_0);
    println!("{:?}", blsag_1);
    println!("{:?}", blsag_0.verify::<Sha512>(data_0));
    println!("{:?}", blsag_1.verify::<Sha512>(data_1));
    println!(
        "{}",
        CLSAG::link(&[&blsag_0.key_images, &blsag_1.key_images])
    );
    println!("{}", bincode::serialize(&blsag_0).unwrap().len())
}
