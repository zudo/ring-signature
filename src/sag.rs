use crate::scalar;
use crate::Response;
use crate::Ring;
use crate::Secret;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
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
    pub response: Vec<[u8; 32]>,
    pub ring: Vec<[u8; 32]>,
}
impl SAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret: &Secret,
        mut ring: Ring,
        data: impl AsRef<[u8]>,
    ) -> Option<SAG> {
        let secret_index = rng.gen_range(0..=ring.0.len());
        ring.0
            .insert(secret_index, secret.0 * RISTRETTO_BASEPOINT_POINT);
        let ring_size = ring.0.len();
        let hash = Hash::new().chain_update(data);
        let mut hashes = (0..ring_size).map(|_| hash.clone()).collect::<Vec<_>>();
        let mut current_index = (secret_index + 1) % ring_size;
        let secret_scalar_1 = scalar::random(rng);
        hashes[current_index].update(
            (secret_scalar_1 * RISTRETTO_BASEPOINT_POINT)
                .compress()
                .as_bytes(),
        );
        let mut challenges = vec![scalar::zero(); ring_size];
        challenges[current_index] = scalar::from_hash(hashes[current_index].clone());
        let mut response = Response::random(rng, ring_size);
        loop {
            let next_index = (current_index + 1) % ring_size;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[response.0[current_index], challenges[current_index]],
                    &[RISTRETTO_BASEPOINT_POINT, ring.0[current_index]],
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
        response.0[secret_index] = secret_scalar_1 - (challenges[secret_index] * secret.0);
        Some(SAG {
            challenge: challenges[0].to_bytes(),
            response: response.to_bytes(),
            ring: ring.compress(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        match || -> Option<bool> {
            let hash = Hash::new().chain_update(data);
            let challenge_0 = scalar::from_canonical(self.challenge)?;
            let mut challenge_1 = challenge_0;
            let response = Response::from_canonical(&self.response)?;
            let ring = Ring::decompress(&self.ring)?;
            for i in 0..self.ring.len() {
                let mut hash = hash.clone();
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[response.0[i], challenge_1],
                        &[RISTRETTO_BASEPOINT_POINT, ring.0[i]],
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
}
#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use rand_core::OsRng;
    use sha2::Sha512;
    const DATA: &[u8] = b"hello from";
    const X: usize = 2;
    lazy_static! {
        static ref SECRET_0: Secret = Secret::new(&mut OsRng {});
        static ref SECRET_1: Secret = Secret::new(&mut OsRng {});
        static ref RING_0: Ring = Ring::random(X);
        static ref RING_1: Ring = Ring::random(X);
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng {};
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
