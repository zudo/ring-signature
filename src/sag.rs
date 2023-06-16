use crate::point_from_slice;
use crate::scalar_from_canonical;
use crate::scalar_from_hash;
use crate::scalar_random;
use crate::scalar_zero;
use crate::G;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::Scalar;
use digest::typenum::U64;
use digest::Digest;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::Deserialize;
use serde::Serialize;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SAG {
    pub challenge: [u8; 32],
    pub response: Vec<[u8; 32]>,
    pub ring: Vec<[u8; 32]>,
}
impl SAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret: &Scalar,
        mut ring: Vec<RistrettoPoint>,
        data: impl AsRef<[u8]>,
    ) -> Option<SAG> {
        let secret_index = rng.gen_range(0..=ring.len());
        ring.insert(secret_index, secret * G);
        let ring_size = ring.len();
        let hash = Hash::new().chain_update(data);
        let mut hashes = (0..ring_size).map(|_| hash.clone()).collect::<Vec<_>>();
        let mut current_index = (secret_index + 1) % ring_size;
        let secret_scalar_1 = scalar_random(rng);
        hashes[current_index].update((secret_scalar_1 * G).compress().as_bytes());
        let mut challenges = vec![scalar_zero(); ring_size];
        challenges[current_index] = scalar_from_hash(hashes[current_index].clone());
        let mut response = (0..ring_size)
            .map(|_| scalar_random(rng))
            .collect::<Vec<_>>();
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[response[current_index], challenges[current_index]],
                    &[G, ring[current_index]],
                )
                .compress()
                .as_bytes(),
            );
            challenges[next_index] = scalar_from_hash(hashes[next_index].clone());
            if (secret_index >= 1 && current_index == (secret_index - 1) % ring_size)
                || (secret_index == 0 && current_index == ring_size - 1)
            {
                break;
            }
            current_index = next_index;
        }
        response[secret_index] = secret_scalar_1 - (challenges[secret_index] * secret);
        Some(SAG {
            challenge: challenges[0].to_bytes(),
            response: response.iter().map(|x| x.to_bytes()).collect(),
            ring: ring.iter().map(|x| x.compress().to_bytes()).collect(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        match || -> Option<bool> {
            let hash = Hash::new().chain_update(data);
            let challenge_0 = scalar_from_canonical(self.challenge)?;
            let mut challenge_1 = challenge_0;
            let response = self
                .response
                .iter()
                .map(|&bytes| scalar_from_canonical(bytes))
                .collect::<Option<Vec<_>>>()?;
            let ring = self
                .ring
                .iter()
                .map(|x| point_from_slice(x))
                .collect::<Option<Vec<_>>>()?;
            for i in 0..self.ring.len() {
                let mut hash = hash.clone();
                hash.update(
                    RistrettoPoint::multiscalar_mul(&[response[i], challenge_1], &[G, ring[i]])
                        .compress()
                        .as_bytes(),
                );
                challenge_1 = scalar_from_hash(hash);
            }
            Some(challenge_0 == challenge_1)
        }() {
            Some(x) => x,
            None => false,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::point_random;
    use lazy_static::lazy_static;
    use rand_core::OsRng;
    use sha2::Sha512;
    const DATA: &[u8] = b"hello from zudo";
    const X: usize = 2;
    lazy_static! {
        static ref SECRET_0: Scalar = scalar_random(&mut OsRng);
        static ref SECRET_1: Scalar = scalar_random(&mut OsRng);
        static ref RING_0: Vec<RistrettoPoint> = (0..X).map(|_| point_random(&mut OsRng)).collect();
        static ref RING_1: Vec<RistrettoPoint> = (0..X).map(|_| point_random(&mut OsRng)).collect();
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng;
        let a = SAG::sign::<Sha512>(rng, &SECRET_0, RING_0.clone(), DATA).unwrap();
        let b = SAG::sign::<Sha512>(rng, &SECRET_0, RING_1.clone(), DATA).unwrap();
        let c = SAG::sign::<Sha512>(rng, &SECRET_1, RING_0.clone(), DATA).unwrap();
        let d = SAG::sign::<Sha512>(rng, &SECRET_1, RING_1.clone(), DATA).unwrap();
        assert!((a.verify::<Sha512>(DATA)));
        assert!((b.verify::<Sha512>(DATA)));
        assert!((c.verify::<Sha512>(DATA)));
        assert!((d.verify::<Sha512>(DATA)));
    }
}
