use crate::point;
use crate::scalar;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::MultiscalarMul;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::Deserialize;
use serde::Serialize;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CLSAG {
    pub challenge: [u8; 32],
    pub responses: Vec<[u8; 32]>,
    pub rings: Vec<Vec<[u8; 32]>>,
    pub key_images: Vec<[u8; 32]>,
}
impl CLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret_keys: &Vec<[u8; 32]>,
        rings: &Vec<Vec<[u8; 32]>>,
        data: impl AsRef<[u8]>,
    ) -> Option<CLSAG> {
        let secret_scalars = scalar::vec_1d::from_slice(secret_keys);
        let key_images = CLSAG::key_image::<Hash>(&secret_scalars);
        let mut rings = point::vec_2d::from_slice(rings)?;
        let public_points = secret_scalars
            .iter()
            .map(|x| x * constants::RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        let base_point = point::hash::<Hash>(public_points[0]);
        let secret_index = rng.gen_range(0..=rings.len());
        rings.insert(secret_index, public_points);
        let ring_size = rings.len();
        let ring_layers = rings[0].len();
        let prefixed_hashes_with_key_images =
            CLSAG::prefixed_hashes_with_key_images::<Hash>(&rings, &key_images);
        let aggregate_private_key =
            CLSAG::aggregate_private_key(&rings, &prefixed_hashes_with_key_images, &secret_scalars);
        let aggregate_public_keys =
            CLSAG::aggregate_public_keys(&rings, &prefixed_hashes_with_key_images);
        let aggregate_key_image = CLSAG::aggregate_key_image::<Hash>(
            &rings,
            &prefixed_hashes_with_key_images,
            &key_images,
        );
        let mut hashes = (0..ring_size)
            .map(|_| {
                let mut hash = Hash::new();
                hash.update(format!("CLSAG_c"));
                for i in 0..ring_size {
                    for j in 0..ring_layers {
                        hash.update(rings[i][j].compress().as_bytes());
                    }
                }
                hash.update(&data);
                hash
            })
            .collect::<Vec<_>>();
        let secret_scalar = scalar::random(rng);
        let mut current_index = (secret_index + 1) % ring_size;
        hashes[current_index].update(
            (secret_scalar * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        hashes[current_index].update((secret_scalar * base_point).compress().as_bytes());
        let mut challenges = vec![scalar::zero(); ring_size];
        challenges[current_index] = scalar::from_hash(hashes[current_index].clone());
        let mut responses = (0..ring_size)
            .map(|_| scalar::random(rng))
            .collect::<Vec<_>>();
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[
                        responses[current_index % ring_size],
                        challenges[current_index % ring_size],
                    ],
                    &[
                        constants::RISTRETTO_BASEPOINT_POINT,
                        aggregate_public_keys[current_index % ring_size],
                    ],
                )
                .compress()
                .as_bytes(),
            );
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[
                        responses[current_index % ring_size],
                        challenges[current_index % ring_size],
                    ],
                    &[
                        point::hash::<Hash>(rings[current_index % ring_size][0]),
                        aggregate_key_image,
                    ],
                )
                .compress()
                .as_bytes(),
            );
            challenges[next_index] = scalar::from_hash(hashes[next_index].clone());
            if (secret_index >= 1 && current_index % ring_size == (secret_index - 1) % ring_size)
                || (secret_index == 0 && current_index % ring_size == ring_size - 1)
            {
                break;
            }
            current_index = next_index;
        }
        responses[secret_index] =
            secret_scalar - (challenges[secret_index] * aggregate_private_key);
        Some(CLSAG {
            challenge: challenges[0].to_bytes(),
            responses: scalar::vec_1d::to_bytes(&responses),
            rings: point::vec_2d::to_bytes(&rings),
            key_images: point::vec_1d::to_bytes(&key_images),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        let ring_size = self.rings.len();
        let ring_layers = self.rings[0].len();
        let rings = match point::vec_2d::from_slice(&self.rings) {
            Some(x) => x,
            None => return false,
        };
        let key_images = match point::vec_1d::from_slice(&self.key_images) {
            Some(x) => x,
            None => return false,
        };
        let responses = scalar::vec_1d::from_slice(&self.responses);
        let challenge_0 = scalar::from_slice(&self.challenge);
        let mut challenge_1 = challenge_0;
        let prefixed_hashes_with_key_images =
            CLSAG::prefixed_hashes_with_key_images::<Hash>(&rings, &key_images);
        let aggregate_public_keys =
            CLSAG::aggregate_public_keys(&rings, &prefixed_hashes_with_key_images);
        let aggregate_key_image = CLSAG::aggregate_key_image::<Hash>(
            &rings,
            &prefixed_hashes_with_key_images,
            &key_images,
        );
        for i in 0..ring_size {
            let mut hash: Hash = Hash::new();
            hash.update(format!("CLSAG_c"));
            for j in 0..ring_size {
                for k in 0..ring_layers {
                    hash.update(rings[j][k].compress().as_bytes());
                }
            }
            hash.update(&data);
            hash.update(
                RistrettoPoint::multiscalar_mul(
                    &[responses[i], challenge_1],
                    &[
                        constants::RISTRETTO_BASEPOINT_POINT,
                        aggregate_public_keys[i],
                    ],
                )
                .compress()
                .as_bytes(),
            );
            hash.update(
                RistrettoPoint::multiscalar_mul(
                    &[responses[i], challenge_1],
                    &[point::hash::<Hash>(rings[i][0]), aggregate_key_image],
                )
                .compress()
                .as_bytes(),
            );
            challenge_1 = scalar::from_hash(hash);
        }
        challenge_0 == challenge_1
    }
    pub fn key_image<Hash: Digest<OutputSize = U64>>(
        secret_keys: &[Scalar],
    ) -> Vec<RistrettoPoint> {
        let a = secret_keys[0] * constants::RISTRETTO_BASEPOINT_POINT;
        let b = point::hash::<Hash>(a);
        secret_keys.iter().map(|x| x * b).collect()
    }
    pub fn link(key_images: &[&[[u8; 32]]]) -> bool {
        if key_images.is_empty() || key_images[0].is_empty() {
            return false;
        }
        key_images
            .iter()
            .skip(1)
            .all(|x| !x.is_empty() && x[0] == key_images[0][0])
    }
    fn prefixed_hashes_with_key_images<Hash: Digest<OutputSize = U64>>(
        rings: &Vec<Vec<RistrettoPoint>>,
        key_images: &Vec<RistrettoPoint>,
    ) -> Vec<Hash> {
        let ring_size = rings.len();
        let ring_layers = rings[0].len();
        (0..ring_layers)
            .map(|i| {
                let mut hash = Hash::new();
                hash.update(format!("CLSAG_{}", i));
                for j in 0..ring_size {
                    for k in 0..ring_layers {
                        hash.update(rings[j][k].compress().as_bytes());
                    }
                }
                for j in 0..ring_layers {
                    hash.update(key_images[j].compress().as_bytes());
                }
                hash
            })
            .collect()
    }
    fn aggregate_private_key<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Vec<Vec<RistrettoPoint>>,
        prefixed_hashes_with_key_images: &Vec<Hash>,
        secret_scalars: &Vec<Scalar>,
    ) -> Scalar {
        let ring_layers = rings[0].len();
        (0..ring_layers)
            .map(|i| {
                scalar::from_hash(prefixed_hashes_with_key_images[i].clone()) * secret_scalars[i]
            })
            .sum()
    }
    fn aggregate_public_keys<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Vec<Vec<RistrettoPoint>>,
        prefixed_hashes_with_key_images: &Vec<Hash>,
    ) -> Vec<RistrettoPoint> {
        let ring_size = rings.len();
        let ring_layers = rings[0].len();
        (0..ring_size)
            .map(|i| {
                (0..ring_layers)
                    .map(|j| {
                        scalar::from_hash(prefixed_hashes_with_key_images[j].clone()) * rings[i][j]
                    })
                    .sum()
            })
            .collect()
    }
    fn aggregate_key_image<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Vec<Vec<RistrettoPoint>>,
        prefixed_hashes_with_key_images: &Vec<Hash>,
        key_images: &Vec<RistrettoPoint>,
    ) -> RistrettoPoint {
        let ring_layers = rings[0].len();
        (0..ring_layers)
            .map(|i| scalar::from_hash(prefixed_hashes_with_key_images[i].clone()) * key_images[i])
            .sum()
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha512;
    #[test]
    fn blsag() {
        let rng = &mut OsRng {};
        let ring_size = 2;
        let ring_layers = 2;
        let secret_keys = scalar::vec_1d::to_bytes(&scalar::vec_1d::random(rng, ring_layers));
        let data_0 = b"hello";
        let data_1 = b"world";
        let ring_0 = point::vec_2d::to_bytes(&point::vec_2d::random(ring_size - 1, ring_layers));
        let ring_1 = point::vec_2d::to_bytes(&point::vec_2d::random(ring_size - 1, ring_layers));
        let blsag_0 = CLSAG::sign::<Sha512>(rng, &secret_keys, &ring_0, data_0).unwrap();
        let blsag_1 = CLSAG::sign::<Sha512>(rng, &secret_keys, &ring_1, data_1).unwrap();
        assert!((blsag_0.verify::<Sha512>(data_0)));
        assert!((blsag_1.verify::<Sha512>(data_1)));
        println!("{:?}", blsag_0.key_images);
        println!("{:?}", blsag_1.key_images);
        assert!((CLSAG::link(&[&blsag_0.key_images, &blsag_1.key_images])));
    }
}
