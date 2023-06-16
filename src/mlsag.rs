use crate::point_from_slice;
use crate::point_hash;
use crate::scalar_from_canonical;
use crate::scalar_from_hash;
use crate::scalar_random;
use crate::scalar_zero;
use crate::RISTRETTO_BASEPOINT_POINT;
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
pub struct MLSAG {
    pub challenge: [u8; 32],
    pub responses: Vec<Vec<[u8; 32]>>,
    pub rings: Vec<Vec<[u8; 32]>>,
    pub images: Vec<[u8; 32]>,
}
impl MLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secrets: &[Scalar],
        mut rings: Vec<Vec<RistrettoPoint>>,
        message: impl AsRef<[u8]>,
    ) -> Option<MLSAG> {
        let x = rings.len() + 1;
        let y = rings[0].len();
        let k_points = secrets
            .iter()
            .map(|scalar| scalar * RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        let images = MLSAG::image::<Hash>(secrets);
        let secret_index = rng.gen_range(0..x);
        rings.insert(secret_index, k_points.clone());
        let a: Vec<Scalar> = (0..y).map(|_| scalar_random(rng)).collect();
        let mut responses = (0..x)
            .map(|_| (0..y).map(|_| scalar_random(rng)).collect())
            .collect::<Vec<Vec<_>>>();
        let mut challenges: Vec<Scalar> = (0..x).map(|_| scalar_zero()).collect();
        let mut hash = Hash::new();
        hash.update(message);
        let mut hashes: Vec<Hash> = (0..x).map(|_| hash.clone()).collect();
        for j in 0..y {
            hashes[(secret_index + 1) % x]
                .update((a[j] * RISTRETTO_BASEPOINT_POINT).compress().as_bytes());
            hashes[(secret_index + 1) % x].update(
                (a[j] * point_hash::<Hash>(k_points[j]))
                    .compress()
                    .as_bytes(),
            );
        }
        challenges[(secret_index + 1) % x] =
            scalar_from_hash(hashes[(secret_index + 1) % x].clone());
        let mut i = (secret_index + 1) % x;
        loop {
            for j in 0..y {
                hashes[(i + 1) % x].update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses[i % x][j], challenges[i % x]],
                        &[RISTRETTO_BASEPOINT_POINT, rings[i % x][j]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hashes[(i + 1) % x].update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses[i % x][j], challenges[i % x]],
                        &[point_hash::<Hash>(rings[i % x][j]), images[j]],
                    )
                    .compress()
                    .as_bytes(),
                );
            }
            challenges[(i + 1) % x] = scalar_from_hash(hashes[(i + 1) % x].clone());
            if secret_index >= 1 && i % x == (secret_index - 1) % x {
                break;
            } else if secret_index == 0 && i % x == x - 1 {
                break;
            } else {
                i = (i + 1) % x;
            }
        }
        for j in 0..y {
            responses[secret_index][j] = a[j] - (challenges[secret_index] * secrets[j]);
        }
        Some(MLSAG {
            challenge: challenges[0].to_bytes(),
            responses: responses
                .iter()
                .map(|vec| vec.iter().map(|scalar| scalar.to_bytes()).collect())
                .collect::<Vec<Vec<_>>>(),
            rings: rings
                .iter()
                .map(|vec| {
                    vec.iter()
                        .map(|point| point.compress().to_bytes())
                        .collect()
                })
                .collect::<Vec<Vec<_>>>(),
            images: images
                .iter()
                .map(|point| point.compress().to_bytes())
                .collect(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        match || -> Option<bool> {
            let rings = self
                .rings
                .iter()
                .map(|vec| vec.iter().map(|bytes| point_from_slice(bytes)).collect())
                .collect::<Option<Vec<Vec<_>>>>()?;
            let images = self
                .images
                .iter()
                .map(|bytes| point_from_slice(bytes))
                .collect::<Option<Vec<_>>>()?;
            let responses = self
                .responses
                .iter()
                .map(|vec| {
                    vec.iter()
                        .map(|&bytes| scalar_from_canonical(bytes))
                        .collect()
                })
                .collect::<Option<Vec<Vec<_>>>>()?;
            let challenge_0 = scalar_from_canonical(self.challenge)?;
            let mut challenge_1 = challenge_0;
            let x = self.rings.len();
            let y = self.rings[0].len();
            for i in 0..x {
                let mut hash = Hash::new();
                hash.update(&data);
                for j in 0..y {
                    hash.update(
                        RistrettoPoint::multiscalar_mul(
                            &[responses[i][j], challenge_1],
                            &[RISTRETTO_BASEPOINT_POINT, rings[i][j]],
                        )
                        .compress()
                        .as_bytes(),
                    );
                    hash.update(
                        RistrettoPoint::multiscalar_mul(
                            &[responses[i][j], challenge_1],
                            &[point_hash::<Hash>(rings[i][j]), images[j]],
                        )
                        .compress()
                        .as_bytes(),
                    );
                }
                challenge_1 = scalar_from_hash(hash);
            }
            Some(challenge_0 == challenge_1)
        }() {
            Some(x) => x,
            None => return false,
        }
    }
    pub fn image<Hash: Digest<OutputSize = U64>>(secrets: &[Scalar]) -> Vec<RistrettoPoint> {
        let x = secrets.len();
        let publics = secrets
            .iter()
            .map(|scalar| scalar * RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        (0..x)
            .map(|i| secrets[i] * point_hash::<Hash>(publics[i]))
            .collect()
    }
    pub fn link(images: &[&[[u8; 32]]]) -> bool {
        if images.is_empty() || images[0].is_empty() {
            return false;
        }
        images
            .iter()
            .skip(1)
            .all(|&slice| !slice.is_empty() && slice[0] == images[0][0])
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
    const Y: usize = 2;
    lazy_static! {
        static ref SECRETS_0: Vec<Scalar> = (0..Y).map(|_| scalar_random(&mut OsRng)).collect();
        static ref SECRETS_1: Vec<Scalar> = (0..Y).map(|_| scalar_random(&mut OsRng)).collect();
        static ref RINGS_0: Vec<Vec<RistrettoPoint>> = (0..X)
            .map(|_| (0..Y).map(|_| point_random(&mut OsRng)).collect())
            .collect();
        static ref RINGS_1: Vec<Vec<RistrettoPoint>> = (0..X)
            .map(|_| (0..Y).map(|_| point_random(&mut OsRng)).collect())
            .collect();
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng;
        let a = MLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_0.clone(), DATA_0).unwrap();
        let b = MLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_0).unwrap();
        let c = MLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_0).unwrap();
        let d = MLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_1.clone(), DATA_0).unwrap();
        assert!((a.verify::<Sha512>(DATA_0)));
        assert!((b.verify::<Sha512>(DATA_0)));
        assert!((c.verify::<Sha512>(DATA_0)));
        assert!((d.verify::<Sha512>(DATA_0)));
    }
    #[test]
    fn link() {
        let rng = &mut OsRng;
        let a = MLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_0.clone(), DATA_1).unwrap();
        let b = MLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_0).unwrap();
        let c = MLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_0).unwrap();
        let d = MLSAG::sign::<Sha512>(rng, &SECRETS_0, RINGS_1.clone(), DATA_1).unwrap();
        let e = MLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_0.clone(), DATA_1).unwrap();
        let f = MLSAG::sign::<Sha512>(rng, &SECRETS_1, RINGS_1.clone(), DATA_1).unwrap();
        assert!((MLSAG::link(&[&a.images, &b.images])));
        assert!((!MLSAG::link(&[&a.images, &c.images])));
        assert!((MLSAG::link(&[&a.images, &d.images])));
        assert!((!MLSAG::link(&[&a.images, &e.images])));
        assert!((!MLSAG::link(&[&a.images, &f.images])));
    }
}
