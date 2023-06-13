use crate::point;
use crate::scalar;
use crate::Responses2d;
use crate::Ring;
use crate::Rings;
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
pub struct MLSAG {
    pub challenge: [u8; 32],
    pub responses: Vec<Vec<[u8; 32]>>,
    pub ring: Vec<Vec<[u8; 32]>>,
    pub key_images: Vec<[u8; 32]>,
}
impl MLSAG {
    pub fn sign<Hash: Digest<OutputSize = U64> + Clone>(
        rng: &mut impl CryptoRngCore,
        secrets: &[Secret],
        mut rings: Rings,
        message: impl AsRef<[u8]>,
    ) -> Option<MLSAG> {
        let nr = rings.0.len() + 1;
        let nc = rings.0[0].len();
        let k_points = secrets
            .iter()
            .map(|x| x.0 * constants::RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        let key_images = MLSAG::image::<Hash>(secrets);
        let secret_index = rng.gen_range(0..nr);
        rings.0.insert(secret_index, k_points.clone());
        let a: Vec<Scalar> = (0..nc).map(|_| scalar::random(rng)).collect();
        let mut rs = Responses2d::random(rng, nr, nc);
        let mut cs: Vec<Scalar> = (0..nr).map(|_| scalar::zero()).collect();
        let mut hash = Hash::new();
        hash.update(message);
        let mut hashes: Vec<Hash> = (0..nr).map(|_| hash.clone()).collect();
        for j in 0..nc {
            hashes[(secret_index + 1) % nr].update(
                (a[j] * constants::RISTRETTO_BASEPOINT_POINT)
                    .compress()
                    .as_bytes(),
            );
            hashes[(secret_index + 1) % nr].update(
                (a[j] * point::hash::<Hash>(k_points[j]))
                    .compress()
                    .as_bytes(),
            );
        }
        cs[(secret_index + 1) % nr] = scalar::from_hash(hashes[(secret_index + 1) % nr].clone());
        let mut i = (secret_index + 1) % nr;
        loop {
            for j in 0..nc {
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs.0[i % nr][j], cs[i % nr]],
                        &[constants::RISTRETTO_BASEPOINT_POINT, rings.0[i % nr][j]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hashes[(i + 1) % nr].update(
                    RistrettoPoint::multiscalar_mul(
                        &[rs.0[i % nr][j], cs[i % nr]],
                        &[point::hash::<Hash>(rings.0[i % nr][j]), key_images.0[j]],
                    )
                    .compress()
                    .as_bytes(),
                );
            }
            cs[(i + 1) % nr] = scalar::from_hash(hashes[(i + 1) % nr].clone());
            if secret_index >= 1 && i % nr == (secret_index - 1) % nr {
                break;
            } else if secret_index == 0 && i % nr == nr - 1 {
                break;
            } else {
                i = (i + 1) % nr;
            }
        }
        for j in 0..nc {
            rs.0[secret_index][j] = a[j] - (cs[secret_index] * secrets[j].0);
        }
        Some(MLSAG {
            challenge: cs[0].to_bytes(),
            responses: rs.to_bytes(),
            ring: rings.compress(),
            key_images: key_images.compress(),
        })
    }
    pub fn verify<Hash: Digest<OutputSize = U64> + Clone>(&self, message: &Vec<u8>) -> bool {
        let rings = match Rings::decompress(&self.ring) {
            Some(x) => x,
            None => return false,
        };
        let key_images = match Ring::decompress(&self.key_images) {
            Some(x) => x,
            None => return false,
        };
        let responses = match Responses2d::from_canonical(&self.responses) {
            Some(x) => x,
            None => return false,
        };
        let challenge_0 = match scalar::from_canonical(self.challenge) {
            Some(x) => x,
            None => return false,
        };
        let mut challenge_1 = challenge_0;
        let nr = self.ring.len();
        let nc = self.ring[0].len();
        for i in 0..nr {
            let mut hash = Hash::new();
            hash.update(message);
            for j in 0..nc {
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses.0[i][j], challenge_1],
                        &[constants::RISTRETTO_BASEPOINT_POINT, rings.0[i][j]],
                    )
                    .compress()
                    .as_bytes(),
                );
                hash.update(
                    RistrettoPoint::multiscalar_mul(
                        &[responses.0[i][j], challenge_1],
                        &[point::hash::<Hash>(rings.0[i][j]), key_images.0[j]],
                    )
                    .compress()
                    .as_bytes(),
                );
            }
            challenge_1 = scalar::from_hash(hash);
        }
        challenge_0 == challenge_1
    }
    pub fn image<Hash: Digest<OutputSize = U64>>(secrets: &[Secret]) -> Ring {
        let nc = secrets.len();
        let publics = secrets
            .iter()
            .map(|x| x.0 * constants::RISTRETTO_BASEPOINT_POINT)
            .collect::<Vec<_>>();
        Ring(
            (0..nc)
                .map(|i| secrets[i].0 * point::hash::<Hash>(publics[i]))
                .collect(),
        )
    }
    pub fn link(key_images: &[Vec<[u8; 32]>]) -> bool {
        if key_images.is_empty() || key_images[0].is_empty() {
            return false;
        }
        key_images
            .iter()
            .skip(1)
            .all(|x| !x.is_empty() && x[0] == key_images[0][0])
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;
    use sha2::Sha512;
    #[test]
    fn mlsag() {
        let rng = &mut OsRng {};
        let nr = 2;
        let nc = 2;
        let secrets = (0..nc).map(|_| Secret::new(rng)).collect::<Vec<_>>();
        let rings = Rings::random(nr - 1, nc);
        let message: Vec<u8> = b"This is the message".iter().cloned().collect();
        let mlsag = MLSAG::sign::<Sha512>(rng, &secrets, rings.clone(), &message).unwrap();
        let result = mlsag.verify::<Sha512>(&message);
        assert!(result);
        let another_rings: Vec<Vec<[u8; 32]>> = (0..(nr - 1))
            .map(|_| {
                (0..nc)
                    .map(|_| point::random().compress().to_bytes())
                    .collect()
            })
            .collect();
        let another_rings = Rings::decompress(&another_rings).unwrap();
        let another_message: Vec<u8> = b"This is another message".iter().cloned().collect();
        let mlsag_1 =
            MLSAG::sign::<Sha512>(rng, &secrets, another_rings, &another_message).unwrap();
        let mlsag_2 = MLSAG::sign::<Sha512>(rng, &secrets, rings, &message).unwrap();
        let result = MLSAG::link(&[mlsag_1.key_images, mlsag_2.key_images]);
        assert!(result);
    }
}
