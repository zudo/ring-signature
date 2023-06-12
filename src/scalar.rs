use curve25519_dalek::Scalar;
use digest::typenum::U64;
use digest::Digest;
use rand_core::CryptoRngCore;
pub fn random(rng: &mut impl CryptoRngCore) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
pub fn from_canonical(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}
pub fn zero() -> Scalar {
    Scalar::from_bytes_mod_order([0; 32])
}
pub fn from_hash<Hash: Digest<OutputSize = U64>>(hash: Hash) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}
pub fn from_slice(bytes: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_mod_order(*bytes)
}
pub mod vec_1d {
    use curve25519_dalek::Scalar;
    use rand_core::CryptoRngCore;
    pub fn random(rng: &mut impl CryptoRngCore, x: usize) -> Vec<Scalar> {
        (0..x).map(|_| super::random(rng)).collect()
    }
    pub fn to_bytes(ring: &Vec<Scalar>) -> Vec<[u8; 32]> {
        ring.iter().map(|x| x.to_bytes()).collect()
    }
    pub fn from_slice(ring: &Vec<[u8; 32]>) -> Vec<Scalar> {
        ring.iter().map(super::from_slice).collect::<Vec<_>>()
    }
}
pub mod vec_2d {
    use curve25519_dalek::Scalar;
    pub fn to_bytes(vec: &Vec<Vec<Scalar>>) -> Vec<Vec<[u8; 32]>> {
        vec.iter().map(super::vec_1d::to_bytes).collect()
    }
    pub fn from_slice(vec: &Vec<Vec<[u8; 32]>>) -> Vec<Vec<Scalar>> {
        vec.iter().map(super::vec_1d::from_slice).collect()
    }
}
