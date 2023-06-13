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
