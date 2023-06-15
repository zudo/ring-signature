use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::RistrettoPoint;
use curve25519_dalek::Scalar;
use digest::typenum::U64;
use digest::Digest;
use rand_core::CryptoRngCore;
pub mod blsag;
pub mod clsag;
pub mod mlsag;
pub mod point;
pub mod sag;
pub mod scalar;
pub const G: RistrettoPoint = RISTRETTO_BASEPOINT_POINT;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Secret(pub Scalar);
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
    pub fn new(rng: &mut impl CryptoRngCore) -> Secret {
        Secret(scalar::random(rng))
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ring(pub Vec<RistrettoPoint>);
impl Ring {
    pub fn compress(&self) -> Vec<[u8; 32]> {
        self.0.iter().map(|x| x.compress().to_bytes()).collect()
    }
    pub fn decompress(vec: &Vec<[u8; 32]>) -> Option<Ring> {
        Some(Ring(
            vec.iter()
                .map(|x| point::from_slice(x))
                .collect::<Option<Vec<_>>>()?,
        ))
    }
    pub fn random(x: usize) -> Ring {
        Ring((0..x).map(|_| point::random()).collect())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rings(pub Vec<Vec<RistrettoPoint>>);
impl Rings {
    pub fn compress(&self) -> Vec<Vec<[u8; 32]>> {
        self.0
            .iter()
            .map(|x| x.iter().map(|y| y.compress().to_bytes()).collect())
            .collect()
    }
    pub fn decompress(vec_2d: &Vec<Vec<[u8; 32]>>) -> Option<Rings> {
        Some(Rings(
            vec_2d
                .iter()
                .map(|x| {
                    x.iter()
                        .map(|y| point::from_slice(y))
                        .collect::<Option<Vec<_>>>()
                })
                .collect::<Option<Vec<_>>>()?,
        ))
    }
    pub fn random(x: usize, y: usize) -> Rings {
        Rings(
            (0..x)
                .map(|_| (0..y).map(|_| point::random()).collect())
                .collect(),
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response(pub Vec<Scalar>);
impl Response {
    pub fn to_bytes(&self) -> Vec<[u8; 32]> {
        self.0.iter().map(|x| x.to_bytes()).collect()
    }
    pub fn from_canonical(vec: &Vec<[u8; 32]>) -> Option<Response> {
        Some(Response(
            vec.iter()
                .map(|&x| scalar::from_canonical(x))
                .collect::<Option<Vec<_>>>()?,
        ))
    }
    pub fn random(rng: &mut impl CryptoRngCore, x: usize) -> Response {
        Response((0..x).map(|_| scalar::random(rng)).collect())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Responses(pub Vec<Vec<Scalar>>);
impl Responses {
    pub fn to_bytes(&self) -> Vec<Vec<[u8; 32]>> {
        self.0
            .iter()
            .map(|x| x.iter().map(|y| y.to_bytes()).collect())
            .collect()
    }
    pub fn from_canonical(vec_2d: &Vec<Vec<[u8; 32]>>) -> Option<Responses> {
        Some(Responses(
            vec_2d
                .iter()
                .map(|x| x.iter().map(|&y| scalar::from_canonical(y)).collect())
                .collect::<Option<Vec<_>>>()?,
        ))
    }
    pub fn random(rng: &mut impl CryptoRngCore, x: usize, y: usize) -> Responses {
        Responses(
            (0..x)
                .map(|_| (0..y).map(|_| scalar::random(rng)).collect())
                .collect(),
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Image(pub RistrettoPoint);
impl Image {
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress().to_bytes()
    }
    pub fn decompress(bytes: &[u8; 32]) -> Option<Image> {
        Some(Image(point::from_slice(bytes)?))
    }
    pub fn new<Hash: Digest<OutputSize = U64>>(secret: &Secret) -> Image {
        let a = secret.0 * RISTRETTO_BASEPOINT_POINT;
        let b = point::hash::<Hash>(a);
        Image(secret.0 * b)
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Images(pub Vec<RistrettoPoint>);
impl Images {
    pub fn compress(&self) -> Vec<[u8; 32]> {
        self.0.iter().map(|x| x.compress().to_bytes()).collect()
    }
    pub fn decompress(bytes: &Vec<[u8; 32]>) -> Option<Images> {
        Some(Images(
            bytes
                .iter()
                .map(|x| point::from_slice(x))
                .collect::<Option<Vec<_>>>()?,
        ))
    }
    pub fn new<Hash: Digest<OutputSize = U64>>(secrets: &[Secret]) -> Images {
        let a = secrets[0].0 * RISTRETTO_BASEPOINT_POINT;
        let b = point::hash::<Hash>(a);
        Images(secrets.iter().map(|x| x.0 * b).collect())
    }
}
