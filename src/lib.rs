pub mod blsag;
pub mod clsag;
pub mod mlsag;
pub mod sag;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U64;
use digest::Digest;
use rand_core::CryptoRngCore;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
pub fn point_from_slice(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    CompressedRistretto::from_slice(bytes).unwrap().decompress()
}
pub fn point_random(rng: &mut impl CryptoRngCore) -> RistrettoPoint {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    RistrettoPoint::from_uniform_bytes(&bytes)
}
pub fn point_hash<Hash: Digest<OutputSize = U64>>(point: RistrettoPoint) -> RistrettoPoint {
    RistrettoPoint::from_uniform_bytes(
        &Hash::new()
            .chain_update(point.compress().as_bytes())
            .finalize()
            .into(),
    )
}
pub fn scalar_random(rng: &mut impl CryptoRngCore) -> Scalar {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order(bytes)
}
pub fn scalar_from_canonical(bytes: [u8; 32]) -> Option<Scalar> {
    Scalar::from_canonical_bytes(bytes).into()
}
pub fn scalar_zero() -> Scalar {
    Scalar::from_bytes_mod_order([0; 32])
}
pub fn scalar_from_hash<Hash: Digest<OutputSize = U64>>(hash: Hash) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&hash.finalize().into())
}
pub fn image<Hash: Digest<OutputSize = U64>>(secret: &Scalar) -> RistrettoPoint {
    let a = secret * G;
    let b = point_hash::<Hash>(a);
    secret * b
}
pub fn images<Hash: Digest<OutputSize = U64>>(secrets: &[Scalar]) -> Vec<RistrettoPoint> {
    let a = secrets[0] * G;
    let b = point_hash::<Hash>(a);
    secrets.iter().map(|x| x * b).collect()
}
