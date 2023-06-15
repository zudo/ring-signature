use crate::point_hash;
use crate::scalar_from_canonical;
use crate::scalar_from_hash;
use crate::scalar_random;
use crate::scalar_zero;
use crate::Images;
use crate::Responses;
use crate::Rings;
use crate::G;
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
    pub ring: Vec<Vec<[u8; 32]>>,
    pub images: Vec<[u8; 32]>,
}
impl MLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secrets: &[Scalar],
        mut rings: Rings,
        message: impl AsRef<[u8]>,
    ) -> Option<MLSAG> {
        let nr = rings.0.len() + 1;
        let nc = rings.0[0].len();
        let k_points = secrets.iter().map(|secret| secret * G).collect::<Vec<_>>();
        let images = MLSAG::image::<Hash>(secrets);
        let secret_index = rng.gen_range(0..nr);
        rings.0.insert(secret_index, k_points.clone());
        let a: Vec<Scalar> = (0..nc).map(|_| scalar_random(rng)).collect();
        let mut responses = Responses::random(rng, nr, nc);
        let mut challenges: Vec<Scalar> = (0..nr).map(|_| scalar_zero()).collect();
        let mut hash = Hash::new();
        hash.update(message);
        let mut hashes: Vec<Hash> = (0..nr).map(|_| hash.clone()).collect();
        for j in 0..nc {
            hashes[(secret_index + 1) % nr].update((a[j] * G).compress().as_bytes());
            hashes[(secret_index + 1) % nr].update(
                (a[j] * point_hash::<Hash>(k_points[j]))
                    .compress()
                    .as_bytes(),
            );
        }
        challenges[(secret_index + 1) % nr] =
            scalar_from_hash(hashes[(secret_index + 1) % nr].clone());
        let mut i = (secret_index + 1) % nr;
        loop {
            for j in 0..nc {
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses.0[i % nr][j], challenges[i % nr]],
                        &[G, rings.0[i % nr][j]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses.0[i % nr][j], challenges[i % nr]],
                        &[point_hash::<Hash>(rings.0[i % nr][j]), images.0[j]],
                    )
                    .compress()
                    .as_bytes(),
                );
            }
            challenges[(i + 1) % nr] = scalar_from_hash(hashes[(i + 1) % nr].clone());
            if secret_index >= 1 && i % nr == (secret_index - 1) % nr {
                break;
            } else if secret_index == 0 && i % nr == nr - 1 {
                break;
            } else {
                i = (i + 1) % nr;
            }
        }
        for j in 0..nc {
            responses.0[secret_index][j] = a[j] - (challenges[secret_index] * secrets[j]);
        }
        Some(MLSAG {
            challenge: challenges[0].to_bytes(),
            responses: responses.to_bytes(),
            ring: rings.compress(),
            images: images.compress(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, data: impl AsRef<[u8]>) -> bool {
        match || -> Option<bool> {
            let rings = Rings::decompress(&self.ring)?;
            let images = Images::decompress(&self.images)?;
            let responses = Responses::from_canonical(&self.responses)?;
            let challenge_0 = scalar_from_canonical(self.challenge)?;
            let mut challenge_1 = challenge_0;
            let nr = self.ring.len();
            let nc = self.ring[0].len();
            for i in 0..nr {
                let mut hash = Hash::new();
                hash.update(&data);
                for j in 0..nc {
                    hash.update(
                        RistrettoPoint::multiscalar_mul(
                            &[responses.0[i][j], challenge_1],
                            &[G, rings.0[i][j]],
                        )
                        .compress()
                        .as_bytes(),
                    );
                    hash.update(
                        RistrettoPoint::multiscalar_mul(
                            &[responses.0[i][j], challenge_1],
                            &[point_hash::<Hash>(rings.0[i][j]), images.0[j]],
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
    pub fn image<Hash: Digest<OutputSize = U64>>(secrets: &[Scalar]) -> Images {
        let nc = secrets.len();
        let publics = secrets.iter().map(|secret| secret * G).collect::<Vec<_>>();
        Images(
            (0..nc)
                .map(|i| secrets[i] * point_hash::<Hash>(publics[i]))
                .collect(),
        )
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
        static ref SECRETS_0: Vec<Scalar> = (0..Y).map(|_| scalar_random(&mut OsRng {})).collect();
        static ref SECRETS_1: Vec<Scalar> = (0..Y).map(|_| scalar_random(&mut OsRng {})).collect();
        static ref RINGS_0: Rings = Rings::random(&mut OsRng {}, X, Y);
        static ref RINGS_1: Rings = Rings::random(&mut OsRng {}, X, Y);
    }
    #[test]
    fn sign_verify() {
        let rng = &mut OsRng {};
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
        let rng = &mut OsRng {};
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
