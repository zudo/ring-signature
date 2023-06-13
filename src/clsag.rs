use crate::point;
use crate::scalar;
use crate::Images;
use crate::Response;
use crate::Rings;
use crate::Secret;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
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
    pub response: Vec<[u8; 32]>,
    pub rings: Vec<Vec<[u8; 32]>>,
    pub images: Vec<[u8; 32]>,
}
impl CLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secrets: &[Secret],
        mut rings: Rings,
        data: impl AsRef<[u8]>,
    ) -> Option<CLSAG> {
        let images = Images::new::<Hash>(secrets);
        let public_points = secrets
            .iter()
            .map(|x| x.0 * RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        let base_point = point::hash::<Hash>(public_points[0]);
        let secret_index = rng.gen_range(0..=rings.0.len());
        rings.0.insert(secret_index, public_points);
        let ring_size = rings.0.len();
        let ring_layers = rings.0[0].len();
        let prefixed_hashes_with_images =
            CLSAG::prefixed_hashes_with_images::<Hash>(&rings, &images);
        let aggregate_private_key =
            CLSAG::aggregate_private_key(&rings, &prefixed_hashes_with_images, secrets);
        let aggregate_public_keys =
            CLSAG::aggregate_public_keys(&rings, &prefixed_hashes_with_images);
        let aggregate_image =
            CLSAG::aggregate_image::<Hash>(&rings, &prefixed_hashes_with_images, &images);
        let mut hashes = (0..ring_size)
            .map(|_| {
                let mut hash = Hash::new();
                hash.update(format!("CLSAG_c"));
                for i in 0..ring_size {
                    for j in 0..ring_layers {
                        hash.update(rings.0[i][j].compress().as_bytes());
                    }
                }
                hash.update(&data);
                hash
            })
            .collect::<Vec<_>>();
        let secret_scalar = scalar::random(rng);
        let mut current_index = (secret_index + 1) % ring_size;
        hashes[current_index].update(
            (secret_scalar * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        hashes[current_index].update((secret_scalar * base_point).compress().as_bytes());
        let mut challenges = vec![scalar::zero(); ring_size];
        challenges[current_index] = scalar::from_hash(hashes[current_index].clone());
        let mut response = Response::random(rng, ring_size);
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[
                        response.0[current_index % ring_size],
                        challenges[current_index % ring_size],
                    ],
                    &[
                        RISTRETTO_BASEPOINT_POINT,
                        aggregate_public_keys[current_index % ring_size],
                    ],
                )
                .compress()
                .as_bytes(),
            );
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[
                        response.0[current_index % ring_size],
                        challenges[current_index % ring_size],
                    ],
                    &[
                        point::hash::<Hash>(rings.0[current_index % ring_size][0]),
                        aggregate_image,
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
        response.0[secret_index] =
            secret_scalar - (challenges[secret_index] * aggregate_private_key);
        Some(CLSAG {
            challenge: challenges[0].to_bytes(),
            response: response.to_bytes(),
            rings: rings.compress(),
            images: images.compress(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        match || -> Option<bool> {
            let ring_size = self.rings.len();
            let ring_layers = self.rings[0].len();
            let rings = Rings::decompress(&self.rings)?;
            let images = Images::decompress(&self.images)?;
            let response = Response::from_canonical(&self.response)?;
            let challenge_0 = scalar::from_canonical(self.challenge)?;
            let mut challenge_1 = challenge_0;
            let prefixed_hashes_with_images =
                CLSAG::prefixed_hashes_with_images::<Hash>(&rings, &images);
            let aggregate_public_keys =
                CLSAG::aggregate_public_keys(&rings, &prefixed_hashes_with_images);
            let aggregate_image =
                CLSAG::aggregate_image::<Hash>(&rings, &prefixed_hashes_with_images, &images);
            for i in 0..ring_size {
                let mut hash: Hash = Hash::new();
                hash.update(format!("CLSAG_c"));
                for j in 0..ring_size {
                    for k in 0..ring_layers {
                        hash.update(rings.0[j][k].compress().as_bytes());
                    }
                }
                hash.update(&data);
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[response.0[i], challenge_1],
                        &[RISTRETTO_BASEPOINT_POINT, aggregate_public_keys[i]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[response.0[i], challenge_1],
                        &[point::hash::<Hash>(rings.0[i][0]), aggregate_image],
                    )
                    .compress()
                    .as_bytes(),
                );
                challenge_1 = scalar::from_hash(hash);
            }
            Some(challenge_0 == challenge_1)
        }() {
            Some(x) => x,
            None => false,
        }
    }
    pub fn link(images: &[&[[u8; 32]]]) -> bool {
        if images.is_empty() || images[0].is_empty() {
            return false;
        }
        images
            .iter()
            .skip(1)
            .all(|x| !x.is_empty() && x[0] == images[0][0])
    }
    fn prefixed_hashes_with_images<Hash: Digest<OutputSize = U64>>(
        rings: &Rings,
        images: &Images,
    ) -> Vec<Hash> {
        let ring_size = rings.0.len();
        let ring_layers = rings.0[0].len();
        (0..ring_layers)
            .map(|i| {
                let mut hash = Hash::new();
                hash.update(format!("CLSAG_{}", i));
                for j in 0..ring_size {
                    for k in 0..ring_layers {
                        hash.update(rings.0[j][k].compress().as_bytes());
                    }
                }
                for j in 0..ring_layers {
                    hash.update(images.0[j].compress().as_bytes());
                }
                hash
            })
            .collect()
    }
    fn aggregate_private_key<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Rings,
        prefixed_hashes_with_images: &Vec<Hash>,
        secrets: &[Secret],
    ) -> Scalar {
        let ring_layers = rings.0[0].len();
        (0..ring_layers)
            .map(|i| scalar::from_hash(prefixed_hashes_with_images[i].clone()) * secrets[i].0)
            .sum()
    }
    fn aggregate_public_keys<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Rings,
        prefixed_hashes_with_images: &Vec<Hash>,
    ) -> Vec<RistrettoPoint> {
        let ring_size = rings.0.len();
        let ring_layers = rings.0[0].len();
        (0..ring_size)
            .map(|i| {
                (0..ring_layers)
                    .map(|j| {
                        scalar::from_hash(prefixed_hashes_with_images[j].clone()) * rings.0[i][j]
                    })
                    .sum()
            })
            .collect()
    }
    fn aggregate_image<Hash: Digest<OutputSize = U64> + Clone>(
        rings: &Rings,
        prefixed_hashes_with_images: &Vec<Hash>,
        images: &Images,
    ) -> RistrettoPoint {
        let ring_layers = rings.0[0].len();
        (0..ring_layers)
            .map(|i| scalar::from_hash(prefixed_hashes_with_images[i].clone()) * images.0[i])
            .sum()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rings;
    use lazy_static::lazy_static;
    use rand_core::OsRng;
    use sha2::Sha512;
    const DATA_0: &[u8] = b"hello from";
    const DATA_1: &str = "zudo";
    const X: usize = 2;
    const Y: usize = 2;
    lazy_static! {
        static ref SECRETS_0: Vec<Secret> = (0..Y).map(|_| Secret::new(&mut OsRng {})).collect();
        static ref SECRETS_1: Vec<Secret> = (0..Y).map(|_| Secret::new(&mut OsRng {})).collect();
        static ref RINGS_0: Rings = Rings::random(X, Y);
        static ref RINGS_1: Rings = Rings::random(X, Y);
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng {};
        let a = CLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_0.clone(), DATA_0).unwrap();
        let b = CLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_0).unwrap();
        let c = CLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_0).unwrap();
        let d = CLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_1.clone(), DATA_0).unwrap();
        assert!((a.verify::<Sha512>(DATA_0)));
        assert!((b.verify::<Sha512>(DATA_0)));
        assert!((c.verify::<Sha512>(DATA_0)));
        assert!((d.verify::<Sha512>(DATA_0)));
    }
    #[test]
    fn link() {
        let rng = &mut OsRng {};
        let a = CLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_0.clone(), DATA_1).unwrap();
        let b = CLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_0).unwrap();
        let c = CLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_0).unwrap();
        let d = CLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_1).unwrap();
        let e = CLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_1).unwrap();
        let f = CLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_1.clone(), DATA_1).unwrap();
        assert!((CLSAG::link(&[&a.images, &b.images])));
        assert!((!CLSAG::link(&[&a.images, &c.images])));
        assert!((CLSAG::link(&[&a.images, &d.images])));
        assert!((!CLSAG::link(&[&a.images, &e.images])));
        assert!((!CLSAG::link(&[&a.images, &f.images])));
    }
}
