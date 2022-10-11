use accumulator::{
    utils::Polynomial,
    Element,
    PublicKey,
};
use bls12_381_plus::{ExpandMsgXmd, G1Projective, G2Projective, Scalar};
use group::{GroupEncoding};
use merlin::Transcript;
use serde::{Deserialize, Serialize};

pub const SECURITY:usize = 128;

pub type UserID = Element;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct PublicKeys {
    pub witness_key: PublicKey,
    pub sign_key: PublicKey,
}

// Group parameters
#[derive(Copy, Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AccParams {
    p1: G1Projective,
    p2: G2Projective,
    k0: G1Projective,
    k1: G1Projective,
    k2: G2Projective,
    x1: G1Projective,
    y1: G1Projective,
    z1: G1Projective,
}

impl Default for AccParams {
    fn default() -> AccParams {
        const DST_G1: &[u8] = b"BLS12381G1_XMD:SHA-256_SSWU_RO_";
        const DST_G2: &[u8] = b"BLS12381G2_XMD:SHA-256_SSWU_RO_";
        let mut array = [0xFFu8; 32];
        let k0 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFE;
        let k1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFD;
        let k2 = G2Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G2);
        array[0] = 0xFC;
        let x1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFB;
        let y1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        array[0] = 0xFA;
        let z1 = G1Projective::hash::<ExpandMsgXmd<sha2::Sha256>>(&array, DST_G1);
        AccParams {
            p1: G1Projective::generator(),
            p2: G2Projective::generator(),
            k0,
            k1,
            k2,
            x1,
            y1,
            z1,
        }
    }
}

impl AccParams {
    // read-only
    pub fn get_p1(&self) -> G1Projective {
        self.p1
    }
    pub fn get_p2(&self) -> G2Projective {
        self.p2
    }
    pub fn get_k1(&self) -> G1Projective {
        self.k1
    }
    pub fn get_k0(&self) -> G1Projective {
        self.k0
    }
    pub fn get_k2(&self) -> G2Projective {
        self.k2
    }
    pub fn get_x1(&self) -> G1Projective {
        self.x1
    }
    pub fn get_y1(&self) -> G1Projective {
        self.y1
    }
    pub fn get_z1(&self) -> G1Projective {
        self.z1
    }

    /// Add these proof params to the transcript
    pub fn add_to_transcript(&self, transcript: &mut Transcript) {
        transcript.append_message(b"Proof Param K", self.k1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param X", self.x1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Y", self.y1.to_bytes().as_ref());
        transcript.append_message(b"Proof Param Z", self.z1.to_bytes().as_ref());
    }
}

// Divides a secret into Shamir shares with a given threshold
// The returned vector consists of (value, share)
// such that the there is a degree-(threshold) polynomial p such that
// p(value) = share
pub fn shamir_share(threshold: usize, num_shares: usize, secret: Scalar) -> Vec<(Scalar, Scalar)> {
    let mut p: Vec<Scalar> = (1..threshold - 1).map(|_| Element::random().0).collect();
    p.insert(0, secret);
    let p = Polynomial::from(p);
    let mut shares = Vec::new();
    let mut point = Scalar::one();
    for _ in 0..num_shares {
        shares.push((point, p.eval(point)));
        point = point + Scalar::one();
    }
    shares
}

// Produces just the coefficients necessary to rebuild from these shares
// These save on computation because the user can build them once
pub fn shamir_ceofficients<T>(
    threshold: usize,
    shares: &Vec<(Scalar, T)>,
) -> (Vec<Scalar>, Option<Vec<Scalar>>) {
    let product = shares[0..threshold]
        .iter()
        .fold(Scalar::one(), |a, y| a * y.0);
    let mut coefficients = vec![product; threshold];
    // Compact formula for coefficients to rebuild Shamir shares
    for i in 0..threshold {
        for ii in 0..threshold {
            if i == ii {
                coefficients[i] *= shares[i].0.invert().unwrap();
            } else {
                coefficients[i] *= (shares[ii].0 - shares[i].0).invert().unwrap();
            }
        }
    }
    // add a check
    // This is just a shift of the old shares, so there's less arithmetic to compute it
    if shares.len() > threshold {
        let mut check_coefficients = coefficients.clone();
        let adjustment = shares[threshold].0 * shares[0].0.invert().unwrap();
        check_coefficients[0] = product * shares[0].0;
        for i in 1..threshold {
            check_coefficients[i] *= adjustment
                * (shares[0].0 - shares[i].0)
                * (shares[threshold].0 - shares[i].0).invert().unwrap();
            check_coefficients[0] *= (shares[i].0 - shares[threshold].0).invert().unwrap();
        }

        return (coefficients, Some(check_coefficients));
    }
    (coefficients, None)
}

// Multiplies the coefficients by the returned shares to produce the output at 0
pub fn shamir_rebuild_scalar(
    shares: &Vec<(Scalar, Scalar)>,
    coefficients: &Vec<Scalar>,
    check_coefficients: &Option<Vec<Scalar>>,
) -> Option<Scalar> {
    let mut result = Scalar::zero();
    for i in 0..coefficients.len() {
        result += shares[i].1 * coefficients[i];
    }
    match check_coefficients {
        Some(checks) => {
            let threshold = coefficients.len();
            let mut check_result = checks[0] * shares[threshold].1;
            for i in 1..threshold {
                check_result += checks[i] * shares[i].1;
            }
            if check_result == result {
                return Some(result);
            }
            return None;
        }
        None => {}
    }
    Some(result)
}

// Multiplies the coefficients by the returned shares of an elliptic curve point to produce the output at 0
// If check coefficients are given, the user will evaluate on the check coefficients and if they do not 
// match what the other shares, the user returns nothing.
pub fn shamir_rebuild_point(
    shares: &Vec<(Scalar, G1Projective)>,
    coefficients: &Vec<Scalar>,
    check_coefficients: &Option<Vec<Scalar>>,
) -> Option<G1Projective> {
    let mut result = G1Projective::identity();
    for i in 0..coefficients.len() {
        result += shares[i].1 * coefficients[i];
    }
    match check_coefficients {
        Some(checks) => {
            let threshold = coefficients.len();
            let mut check_result = shares[threshold].1 * checks[0];
            for i in 1..threshold {
                check_result += shares[i].1 * checks[i];
            }
            if check_result == result {
                return Some(result);
            }
            return None;
        }
        None => {}
    }
    Some(result)
}
