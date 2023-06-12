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
pub mod vec_1d {
    use curve25519_dalek::RistrettoPoint;
    pub fn random(x: usize) -> Vec<RistrettoPoint> {
        (0..x).map(|_| super::random()).collect()
    }
    pub fn to_bytes(vec: &Vec<RistrettoPoint>) -> Vec<[u8; 32]> {
        vec.iter().map(|x| x.compress().to_bytes()).collect()
    }
    pub fn from_slice(vec: &Vec<[u8; 32]>) -> Option<Vec<RistrettoPoint>> {
        vec.iter().map(super::from_slice).collect()
    }
}
pub mod vec_2d {
    use curve25519_dalek::RistrettoPoint;
    pub fn random(x: usize, y: usize) -> Vec<Vec<RistrettoPoint>> {
        (0..x)
            .map(|_| (0..y).map(|_| super::random()).collect())
            .collect()
    }
    pub fn to_bytes(vec: &Vec<Vec<RistrettoPoint>>) -> Vec<Vec<[u8; 32]>> {
        vec.iter().map(super::vec_1d::to_bytes).collect()
    }
    pub fn from_slice(vec: &Vec<Vec<[u8; 32]>>) -> Option<Vec<Vec<RistrettoPoint>>> {
        vec.iter().map(super::vec_1d::from_slice).collect()
    }
}
