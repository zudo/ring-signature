use crate::point;
use crate::scalar;
use crate::Ring;
use crate::Secret;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use digest::typenum::U64;
use digest::Digest;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::Deserialize;
use serde::Serialize;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SAG {
    pub challenge: [u8; 32],
    pub responses: Vec<[u8; 32]>,
    pub ring: Vec<[u8; 32]>,
}
impl SAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret: &Secret,
        ring: Ring,
        data: impl AsRef<[u8]>,
    ) -> Option<SAG> {
        let secret_scalar_0 = secret.0;
        let mut ring_0 = ring.0;
        let secret_index = rng.gen_range(0..=ring_0.len());
        ring_0.insert(
            secret_index,
            secret_scalar_0 * constants::RISTRETTO_BASEPOINT_POINT,
        );
        let ring_size = ring_0.len();
        let hash = Hash::new().chain_update(data);
        let mut hashes = (0..ring_size).map(|_| hash.clone()).collect::<Vec<_>>();
        let mut current_index = (secret_index + 1) % ring_size;
        let secret_scalar_1 = scalar::random(rng);
        hashes[current_index].update(
            (secret_scalar_1 * constants::RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        let mut challenges = vec![scalar::zero(); ring_size];
        challenges[current_index] = scalar::from_hash(hashes[current_index].clone());
        let mut responses = (0..ring_size)
            .map(|_| scalar::random(rng))
            .collect::<Vec<_>>();
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[responses[current_index], challenges[current_index]],
                    &[constants::RISTRETTO_BASEPOINT_POINT, ring_0[current_index]],
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
        responses[secret_index] = secret_scalar_1 - (challenges[secret_index] * secret_scalar_0);
        Some(SAG {
            challenge: challenges[0].to_bytes(),
            responses: scalar::vec_1d::to_bytes(&responses),
            ring: point::vec_1d::to_bytes(&ring_0),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        let hash = Hash::new().chain_update(data);
        let challenge_0 = scalar::from_slice(&self.challenge);
        let mut challenge_1 = challenge_0;
        let responses = scalar::vec_1d::from_slice(&self.responses);
        let ring = match point::vec_1d::from_slice(&self.ring) {
            Some(x) => x,
            None => return false,
        };
        for i in 0..self.ring.len() {
            let mut hash = hash.clone();
            hash.update(
                RistrettoPoint::multiscalar_mul(
                    &[responses[i], challenge_1],
                    &[constants::RISTRETTO_BASEPOINT_POINT, ring[i]],
                )
                .compress()
                .as_bytes(),
            );
            challenge_1 = scalar::from_hash(hash);
        }
        challenge_0 == challenge_1
    }
}
#[cfg(test)]
pub mod test {
    use super::*;
    use crate::point;
    use rand_core::OsRng;
    use sha2::Sha512;
    #[test]
    fn sag() {
        let rng = &mut OsRng {};
        let secret = Secret::new(rng);
        let data = b"hello world";
        for n in 2..11 {
            let ring =
                Ring::decompress(&point::vec_1d::to_bytes(&point::vec_1d::random(n - 1))).unwrap();
            let sag = SAG::sign::<Sha512>(rng, &secret, ring, data).unwrap();
            assert!((sag.verify::<Sha512>(data)));
        }
    }
}
