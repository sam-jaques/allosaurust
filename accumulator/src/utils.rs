use super::Element;
use bls12_381_plus::{ExpandMsgXof, G1Projective, Scalar};
use digest::{ExtendableOutput, Update, XofReader};
use rand_core::{CryptoRng, RngCore};
use sha3::Shake256;

/// Similar to https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04#section-2.3
/// info is left blank
pub fn generate_fr(salt: &[u8], ikm: Option<&[u8]>, mut rng: impl RngCore + CryptoRng) -> Scalar {
    let mut hasher = Shake256::default();
    match ikm {
        Some(v) => {
            hasher.update(salt);
            hasher.update(v);
        }
        None => {
            hasher.update(salt);
            let mut arr = [0u8; 32];
            rng.fill_bytes(&mut arr);
            hasher.update(arr);
        }
    };
    let mut okm = [0u8; 64];
    let mut xof = hasher.finalize_xof();
    xof.read(&mut okm);
    Scalar::from_bytes_wide(&okm)
}

pub fn hash_to_g1<I: AsRef<[u8]>>(data: I) -> G1Projective {
    const DST: &[u8] = b"BLS12381G1_XOF:SHAKE256_SSWU_RO_VB_ACCUMULATOR:1_0_0";
    G1Projective::hash::<ExpandMsgXof<Shake256>>(data.as_ref(), DST)
}

/// dA(x) and dD(x)
pub fn dad(values: &[Element], y: Scalar) -> Scalar {
    if values.len() == 1 {
        values[0].0 - y
    } else {
        values
            .iter()
            .map(|v| v.0 - y)
            .fold(Scalar::one(), |a, y| a * y)
    }
}

/// Salt used for hashing values into the accumulator
/// Giuseppe Vitto, Alex Biryukov = VB
/// Accumulator = ACC
pub const SALT: &[u8] = b"VB-ACC-HASH-SALT-";

/// A Polynomial for Points
pub struct PolynomialG1(pub Vec<G1Projective>);

impl PolynomialG1 {
    #[cfg(any(feature = "std", feature = "alloc"))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(_size: usize) -> Self {
        Self(Vec::new())
    }

    /// Return the result of evaluating the polynomial with the specified point
    pub fn evaluate(&self, x: Scalar) -> Option<G1Projective> {
        if self.0.is_empty() {
            return None;
        }

        let mut p = x;
        let mut res = self.0[0];

        for i in 1..self.0.len() {
            res += self.0[i] * p;
            p *= x;
        }
        Some(res)
    }
}

impl core::ops::AddAssign for PolynomialG1 {
    fn add_assign(&mut self, rhs: Self) {
        let min_len = core::cmp::min(self.0.len(), rhs.0.len());

        if self.0.len() == min_len {
            for i in min_len..rhs.0.len() {
                self.0.push(rhs.0[i]);
            }
        }
        for i in 0..min_len {
            self.0[i] += rhs.0[i];
        }
    }
}

impl core::ops::MulAssign<Scalar> for PolynomialG1 {
    fn mul_assign(&mut self, rhs: Scalar) {
        for i in 0..self.0.len() {
            self.0[i] *= rhs;
        }
    }
}

/// A Polynomial for scalars
#[derive(Default, Clone)]
pub struct Polynomial(pub Vec<Scalar>);

impl Polynomial {
    #[cfg(any(feature = "std", feature = "alloc"))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    /// Initialize this polynomial with the expected capacity
    pub fn with_capacity(_size: usize) -> Self {
        Self(Vec::new())
    }

    /// Add the scalar to the end of the polynomial
    pub fn push(&mut self, value: Scalar) {
        self.0.push(value);
    }

    /// Evaluate the polynomial
    pub fn eval(&self, value: Scalar) -> Scalar {
        // Compute the polynomial value using Horner's method
        let degree = self.0.len() - 1;
        let mut r = self.0[degree];
        for i in (0..degree).rev() {
            // b_{n-1} = a_{n-1} + b_n * x
            r *= value;
            r += self.0[i];
        }
        r
    }

    /// Calculate the polynomial degree
    pub fn degree(&self) -> usize {
        self.0.len() - 1
    }
}

impl From<Vec<Scalar>> for Polynomial {
    fn from(scalars: Vec<Scalar>) -> Self {
        Self(scalars)
    }
}

impl core::ops::AddAssign for Polynomial {
    fn add_assign(&mut self, rhs: Self) {
        *self += rhs.0.as_slice();
    }
}

impl core::ops::AddAssign<&[Scalar]> for Polynomial {
    fn add_assign(&mut self, rhs: &[Scalar]) {
        let min_len = core::cmp::min(self.0.len(), rhs.len());

        if self.0.len() == min_len {
            for i in rhs.iter().skip(min_len) {
                self.0.push(*i);
            }
        }
        for (i, item) in rhs.iter().enumerate().take(min_len) {
            self.0[i] += item;
        }
    }
}

impl core::ops::SubAssign for Polynomial {
    fn sub_assign(&mut self, rhs: Self) {
        *self -= rhs.0.as_slice();
    }
}

impl core::ops::SubAssign<&[Scalar]> for Polynomial {
    fn sub_assign(&mut self, rhs: &[Scalar]) {
        let min_len = core::cmp::min(self.0.len(), rhs.len());
        if self.0.len() == min_len {
            for item in rhs.iter().skip(min_len) {
                self.0.push(-item);
            }
        }
        for (i, item) in rhs.iter().enumerate().take(min_len) {
            self.0[i] -= item;
        }
    }
}

impl core::ops::MulAssign for Polynomial {
    fn mul_assign(&mut self, rhs: Self) {
        *self *= rhs.0.as_slice();
    }
}

impl core::ops::MulAssign<&[Scalar; 2]> for Polynomial {
    fn mul_assign(&mut self, rhs: &[Scalar; 2]) {
        *self *= &rhs[..];
    }
}

impl core::ops::MulAssign<&[Scalar]> for Polynomial {
    fn mul_assign(&mut self, rhs: &[Scalar]) {
        let orig = self.0.clone();

        // Both vectors can't be empty
        if !self.0.is_empty() || !rhs.is_empty() {
            for i in 0..self.0.len() {
                self.0[i] = Scalar::zero();
            }
            // M + N - 1
            self.0
                .resize_with(self.0.len() + rhs.len() - 1, Scalar::zero);

            // Calculate product
            for (i, item) in orig.iter().enumerate() {
                for (j, jitem) in rhs.iter().enumerate() {
                    self.0[i + j] += jitem * item;
                }
            }
        }
    }
}

impl core::ops::MulAssign<Scalar> for Polynomial {
    fn mul_assign(&mut self, rhs: Scalar) {
        for i in 0..self.0.len() {
            self.0[i] *= rhs;
        }
    }
}
