use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use digest::typenum::U64;
use digest::Digest;
use rand_core::OsRng;
use rand_core::RngCore;
pub fn from_slice(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).unwrap().decompress()
}
pub fn random() -> RistrettoPoint {
    let mut rng = OsRng {};
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    RistrettoPoint::from_uniform_bytes(&bytes)
}
pub fn from_hash<Hash: Digest<OutputSize = U64>>(hash: Hash) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(&hash.finalize().into())
}
pub fn hash<Hash: Digest<OutputSize = U64>>(point: RistrettoPoint) -> RistrettoPoint {
    from_hash(Hash::new().chain_update(point.compress().as_bytes()))
}
