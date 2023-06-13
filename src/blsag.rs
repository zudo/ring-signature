use crate::point;
use crate::scalar;
use crate::Ring;
use crate::ScalarVec;
use crate::Secret;
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
pub struct BLSAG {
    pub challenge: [u8; 32],
    pub responses: Vec<[u8; 32]>,
    pub ring: Vec<[u8; 32]>,
    pub key_image: [u8; 32],
}
impl BLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret: &Secret,
        mut ring: Ring,
        data: impl AsRef<[u8]>,
    ) -> Option<BLSAG> {
        let key_image = BLSAG::key_image::<Hash>(secret.0);
        let secret_index = rng.gen_range(0..=ring.0.len());
        ring.0.insert(
            secret_index,
            secret.0 * constants::RISTRETTO_BASEPOINT_POINT,
        );
        let ring_size = ring.0.len();
        let hash = Hash::new().chain_update(data);
        let mut hashes = (0..ring_size).map(|_| hash.clone()).collect::<Vec<_>>();
        let mut current_index = (secret_index + 1) % ring_size;
        let secret_scalar_1 = scalar::random(rng);
        hashes[current_index].update(
            (secret_scalar_1 * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        hashes[current_index].update(
            (secret_scalar_1 * point::hash::<Hash>(ring.0[secret_index]))
                .compress()
                .as_bytes(),
        );
        let mut challenges = vec![scalar::zero(); ring_size];
        challenges[current_index] = scalar::from_hash(hashes[current_index].clone());
        let mut responses = ScalarVec::random(rng, ring_size);
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[responses.0[current_index], challenges[current_index]],
                    &[constants::RISTRETTO_BASEPOINT_POINT, ring.0[current_index]],
                )
                .compress()
                .as_bytes(),
            );
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[responses.0[current_index], challenges[current_index]],
                    &[point::hash::<Hash>(ring.0[current_index]), key_image],
                )
                .compress()
                .as_bytes(),
            );
            challenges[next_index] = scalar::from_hash(hashes[next_index].clone());
            if (secret_index >= 1 && current_index == (secret_index - 1) % ring_size)
                || (secret_index == 0 && current_index == ring_size - 1)
            {
                break;
            }
            current_index = next_index;
        }
        responses.0[secret_index] = secret_scalar_1 - (challenges[secret_index] * secret.0);
        Some(BLSAG {
            challenge: challenges[0].to_bytes(),
            responses: responses.to_bytes(),
            ring: ring.compress(),
            key_image: key_image.compress().to_bytes(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        let hash = Hash::new().chain_update(data);
        let challenge_0 = match scalar::from_canonical(self.challenge) {
            Some(x) => x,
            None => return false,
        };
        let mut challenge_1 = challenge_0;
        let responses = match ScalarVec::from_canonical(&self.responses) {
            Some(x) => x,
            None => return false,
        };
        let ring = match Ring::decompress(&self.ring) {
            Some(x) => x,
            None => return false,
        };
        let key_image = match point::from_slice(&self.key_image) {
            Some(x) => x,
            None => return false,
        };
        for i in 0..self.ring.len() {
            let mut hash = hash.clone();
            hash.update(
                RistrettoPoint::multiscalar_mul(
                    &[responses.0[i], challenge_1],
                    &[constants::RISTRETTO_BASEPOINT_POINT, ring.0[i]],
                )
                .compress()
                .as_bytes(),
            );
            hash.update(
                RistrettoPoint::multiscalar_mul(
                    &[responses.0[i], challenge_1],
                    &[
                        point::from_hash(Hash::new().chain_update(self.ring[i])),
                        key_image,
                    ],
                )
                .compress()
                .as_bytes(),
            );
            challenge_1 = scalar::from_hash(hash);
        }
        challenge_0 == challenge_1
    }
    pub fn key_image<Hash: Digest<OutputSize = U64>>(secret_key: Scalar) -> RistrettoPoint {
        secret_key
            * point::from_hash(
                Hash::new().chain_update(
                    (secret_key * constants::RISTRETTO_BASEPOINT_POINT)
                        .compress()
                        .as_bytes(),
                ),
            )
    }
    pub fn link(key_images: &[[u8; 32]]) -> bool {
        if key_images.is_empty() {
            return false;
        }
        key_images.iter().skip(1).all(|x| x == &key_images[0])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha512;
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng {};
        let secret_key_0 = Secret::new(rng);
        let secret_key_1 = Secret::new(rng);
        let data_0 = b"hello";
        let data_1 = b"world";
        for n in 2..11 {
            let ring_0 = Ring::random(n - 1);
            let ring_1 = Ring::random(n - 1);
            let blsag_0 =
                BLSAG::sign::<Sha512>(rng, &secret_key_0, ring_0.clone(), data_0).unwrap();
            let blsag_1 = BLSAG::sign::<Sha512>(rng, &secret_key_0, ring_1, data_1).unwrap();
            assert!((blsag_0.verify::<Sha512>(data_0)));
            assert!((blsag_1.verify::<Sha512>(data_1)));
            assert!((BLSAG::link(&[blsag_0.key_image, blsag_1.key_image])));
            // since the key images are different, the signatures are not linked
            let blsag_2 = BLSAG::sign::<Sha512>(rng, &secret_key_1, ring_0, data_0).unwrap();
            assert!((blsag_2.verify::<Sha512>(data_0)));
            assert!(!(BLSAG::link(&[blsag_0.key_image, blsag_2.key_image])));
            assert!(!(BLSAG::link(&[blsag_1.key_image, blsag_2.key_image])));
        }
    }
}
