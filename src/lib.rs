use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use rand_core::CryptoRngCore;
pub mod blsag;
pub mod clsag;
pub mod mlsag;
pub mod point;
pub mod sag;
pub mod scalar;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Public(RistrettoPoint);
impl Public {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    pub fn from_slice(bytes: &[u8; 32]) -> Option<Public> {
        Some(Public(point::from_slice(bytes)?))
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secret(Scalar);
impl Secret {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
    pub fn from_canonical(bytes: [u8; 32]) -> Option<Secret> {
        Some(Secret(scalar::from_canonical(bytes)?))
    }
    pub fn public(&self) -> Public {
        Public(self.0 * G)
    }
    pub fn new(rng: &mut impl CryptoRngCore) -> Secret {
        Secret(scalar::random(rng))
    }
}
