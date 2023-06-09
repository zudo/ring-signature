use crate::image;
use crate::point_from_slice;
use crate::point_hash;
use crate::scalar_from_canonical;
use crate::scalar_from_hash;
use crate::scalar_random;
use crate::scalar_zero;
use crate::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::MultiscalarMul;
use curve25519_dalek::Scalar;
use digest::generic_array::typenum::U64;
use digest::Digest;
use rand::Rng;
use rand_core::CryptoRngCore;
use serde::Deserialize;
use serde::Serialize;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BLSAG {
    pub challenge: [u8; 32],
    pub response: Vec<[u8; 32]>,
    pub ring: Vec<[u8; 32]>,
    pub image: [u8; 32],
}
impl BLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secret: &Scalar,
        mut ring: Vec<RistrettoPoint>,
        data: impl AsRef<[u8]>,
    ) -> Option<BLSAG> {
        let image = image::<Hash>(secret);
        let secret_index = rng.gen_range(0..=ring.len());
        ring.insert(secret_index, secret * RISTRETTO_BASEPOINT_POINT);
        let x = ring.len();
        let hash = Hash::new().chain_update(data);
        let mut hashes = (0..x).map(|_| hash.clone()).collect::<Vec<_>>();
        let mut current_index = (secret_index + 1) % x;
        let r = scalar_random(rng);
        hashes[current_index].update((r * RISTRETTO_BASEPOINT_POINT).compress().as_bytes());
        hashes[current_index].update(
            (r * point_hash::<Hash>(ring[secret_index]))
                .compress()
                .as_bytes(),
        );
        let mut challenges = vec![scalar_zero(); x];
        challenges[current_index] = scalar_from_hash(hashes[current_index].clone());
        let mut response = (0..x).map(|_| scalar_random(rng)).collect::<Vec<_>>();
        loop {
            let next_index = (current_index + 1) % x;
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[response[current_index], challenges[current_index]],
                    &[RISTRETTO_BASEPOINT_POINT, ring[current_index]],
                )
                .compress()
                .as_bytes(),
            );
            hashes[next_index].update(
                RistrettoPoint::multiscalar_mul(
                    &[response[current_index], challenges[current_index]],
                    &[point_hash::<Hash>(ring[current_index]), image],
                )
                .compress()
                .as_bytes(),
            );
            challenges[next_index] = scalar_from_hash(hashes[next_index].clone());
            if (secret_index >= 1 && current_index == (secret_index - 1) % x)
                || (secret_index == 0 && current_index == x - 1)
            {
                break;
            }
            current_index = next_index;
        }
        response[secret_index] = r - (challenges[secret_index] * secret);
        Some(BLSAG {
            challenge: challenges[0].to_bytes(),
            response: response.iter().map(|scalar| scalar.to_bytes()).collect(),
            ring: ring
                .iter()
                .map(|point| point.compress().to_bytes())
                .collect(),
            image: image.compress().to_bytes(),
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
                .map(|bytes| point_from_slice(bytes))
                .collect::<Option<Vec<_>>>()?;
            let image = point_from_slice(&self.image)?;
            for i in 0..ring.len() {
                let mut hash = hash.clone();
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[response[i], challenge_1],
                        &[RISTRETTO_BASEPOINT_POINT, ring[i]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[response[i], challenge_1],
                        &[point_hash::<Hash>(ring[i]), image],
                    )
                    .compress()
                    .as_bytes(),
                );
                challenge_1 = scalar_from_hash(hash);
            }
            Some(challenge_0 == challenge_1)
        }() {
            Some(x) => x,
            None => return false,
        }
    }
    pub fn link(images: &[[u8; 32]]) -> bool {
        if images.is_empty() {
            return false;
        }
        images.iter().skip(1).all(|bytes| bytes == &images[0])
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::point_random;
    use lazy_static::lazy_static;
    use rand_core::OsRng;
    use sha2::Sha512;
    const DATA_0: &[u8] = b"hello from";
    const DATA_1: &str = "zudo";
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
        let a = BLSAG::sign::<Sha512>(rng, &SECRET_0, RING_0.clone(), DATA_0).unwrap();
        let b = BLSAG::sign::<Sha512>(rng, &SECRET_0, RING_1.clone(), DATA_0).unwrap();
        let c = BLSAG::sign::<Sha512>(rng, &SECRET_1, RING_0.clone(), DATA_0).unwrap();
        let d = BLSAG::sign::<Sha512>(rng, &SECRET_1, RING_1.clone(), DATA_0).unwrap();
        assert!((a.verify::<Sha512>(DATA_0)));
        assert!((b.verify::<Sha512>(DATA_0)));
        assert!((c.verify::<Sha512>(DATA_0)));
        assert!((d.verify::<Sha512>(DATA_0)));
    }
    #[test]
    fn link() {
        let rng = &mut OsRng;
        let a = BLSAG::sign::<Sha512>(rng, &SECRET_0, RING_0.clone(), DATA_1).unwrap();
        let b = BLSAG::sign::<Sha512>(rng, &SECRET_0, RING_1.clone(), DATA_0).unwrap();
        let c = BLSAG::sign::<Sha512>(rng, &SECRET_1, RING_0.clone(), DATA_0).unwrap();
        let d = BLSAG::sign::<Sha512>(rng, &SECRET_0, RING_1.clone(), DATA_1).unwrap();
        let e = BLSAG::sign::<Sha512>(rng, &SECRET_1, RING_0.clone(), DATA_1).unwrap();
        let f = BLSAG::sign::<Sha512>(rng, &SECRET_1, RING_1.clone(), DATA_1).unwrap();
        assert!((BLSAG::link(&[a.image, b.image])));
        assert!((!BLSAG::link(&[a.image, c.image])));
        assert!((BLSAG::link(&[a.image, d.image])));
        assert!((!BLSAG::link(&[a.image, e.image])));
        assert!((!BLSAG::link(&[a.image, f.image])));
    }
}
