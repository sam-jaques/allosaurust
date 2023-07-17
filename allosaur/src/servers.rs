use accumulator::{
    utils::Polynomial,
    Element, SecretKey,
    Accumulator, MembershipWitness, PublicKey,
};
use bls12_381_plus::{G1Projective, Scalar};
use group::{GroupEncoding};
use merlin::Transcript;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, hash_map::RandomState};
use crate::{
    utils::{UserID, PublicKeys, AccParams},
};



#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Server {
    pub accumulators: Vec<Accumulator>,
    pub wit_secret_key: SecretKey,                         // alpha
    pub public_keys: PublicKeys,                           // \tilde{Q}, \tilde{Q}_m
    pub sign_secret_key: SecretKey,                        // s_m
    pub all_users: HashSet<UserID>,                        // \mathcal{Y}
    pub all_witnesses: HashMap<UserID, MembershipWitness>, // wits
    pub deletions: Vec<UserID>,                            // list of deletions y_1,...,y_d
}


impl Server {
    // Creates a new server with random parameters
    pub fn gen(params: &AccParams) -> Server {
        let alpha = SecretKey::new(None);
        let s_m = SecretKey::new(None);
        let q = params.get_p2() * alpha.0;
        let q_m = params.get_k2() * s_m.0;
        let v = params.get_p1() * SecretKey::new(None).0;
        Server {
            accumulators: (&[Accumulator(v)]).to_vec(),
            wit_secret_key: alpha,
            sign_secret_key: s_m,
            public_keys: PublicKeys {
                witness_key: PublicKey(q),
                sign_key: PublicKey(q_m),
            },
            all_users: HashSet::new(),
            all_witnesses: HashMap::new(),
            deletions: Vec::new(),
        }
    }

    // "Adds" a new element by create a witness for it and inserting it into the internal list
    pub fn add(&mut self, y: UserID) -> Option<MembershipWitness> {
        if self.all_witnesses.contains_key(&y) {
            return None;
        }
        // Add to set of accumulated elements
        self.all_users.insert(y);
        // Create a new witness
        let wit = MembershipWitness(
            self.accumulators.last().unwrap().0 * (y.0 + self.wit_secret_key.0).invert().unwrap(),
        );
        // Keep track of all witnesses
        self.all_witnesses.insert(y, wit);
        // In the MPC setting all servers would run this check
        // // let lhs = pair(*self.all_witnesses.get(&y).unwrap(), params.get_P2()*y.0 + self.wit_public_key);
        // // let rhs = pair(*self.accumulators.last().unwrap(), params.get_P2());
        // // assert_eq!(lhs, rhs);
        Some(wit)
    }

    // Deletes an element by using the built-in array
    // When the number of users is large this is SLOW
    // While it conforms to the specification, likely an improvement
    // will be to keep an epoch with each witness and run a batch update
    // when the witness is needed for a deletion
    pub fn delete(&mut self, user_id: UserID) -> Option<Accumulator> {
        match self.all_witnesses.remove(&user_id) {
            None => return None,
            Some(wit) => {
                let new_accumulator = Accumulator(wit.0);
                self.accumulators.push(new_accumulator);

                // Update all witnesses for the new accumulator
                for (other_y, other_witness) in self.all_witnesses.iter_mut() {
                    // (C - V') * (1 / {y - y'})
                    let t = (other_witness.0 - new_accumulator.0)
                        * (user_id.0 - other_y.0).invert().unwrap();
                    other_witness.0 = t;
                }
                self.deletions.push(user_id);
                Some(new_accumulator)
            }
        }
    }
  

    // Uses the secret key to quickly delete an element
    // Does not update witnesses for other users
    pub fn quick_del(&mut self, y: UserID) -> Option<Accumulator> {
        if !self.all_witnesses.contains_key(&y) {
            return None;
        }
        self.all_witnesses.remove(&y);

        let new_accumulator = Accumulator(
            self.accumulators.last().unwrap().0 * (y.0 + self.wit_secret_key.0).invert().unwrap(),
        );
        self.accumulators.push(new_accumulator);
        // Update all witnesses for the new accumulator

        self.deletions.push(y.clone());
        return Some(new_accumulator);
    }


    // Given a user ID y and a signature proof (via challenge and response),
    // returns (C,R) such that C is a witness for y and R is a long-term 
    // signature
    pub fn wit(
        &self,
        params: &AccParams,
        y: &UserID,
        challenge: &Element,
        response: &Element,
        user_pub_key: &G1Projective,
    ) -> Option<(MembershipWitness, G1Projective)> {
        // Only issue a full witness once a user is added
        if !self.all_witnesses.contains_key(&y) {
            return None;
        }
        // Check quick Schnoor proof that user knows a secret key for this public key
        let mut transcript = Transcript::new(b"user_signature_proof");
        transcript.append_message(b"user_pub_key", user_pub_key.to_bytes().as_ref());
        transcript.append_message(
            b"commitment",
            (params.get_k1() * response.0 + user_pub_key * challenge.0)
                .to_bytes()
                .as_ref(),
        );
        let check = Element::from_transcript(b"challenge", &mut transcript);
        if check != *challenge {
            return None;
        }
        // Look up witness (could compute as needed, but lookup is better for MPC version)
        let acc_witness = self.all_witnesses.get(&y).unwrap().clone();
        // Sign y and (user_pub_key + K0) using the signing secret key
        let signature =
            (user_pub_key + params.get_k0()) * ((y.0 + self.sign_secret_key.0).invert().unwrap());
        Some((acc_witness, signature))
    }

    // Generates random uid for benchmarking and passes on to regular register user 
    pub fn register_user_no_id(&mut self, params: &AccParams, witu: (&Element, &Element, &G1Projective))  -> Option<(MembershipWitness, G1Projective, usize, Accumulator)> {
        let y = UserID::random();
        self.register_user(params, y, witu)
    }

    pub fn register_user(&mut self, params: &AccParams, y: UserID, witu: (&Element, &Element, &G1Projective))  -> Option<(MembershipWitness, G1Projective, usize, Accumulator)> {
        self.add(y);
        match self.wit(params, &y, witu.0,witu.1,witu.2){
            None => return None,
            Some((acc_witness, signature)) => {
                let epoch = self.get_epoch();
                let acc = self.get_accumulator();
                Some((acc_witness, signature, epoch, acc))
            }
        }
    }
    // Given shares from a user, returns the array of (d,W) which can each be used as 
    // C <- (C - W)*(1/d) 
    // for an update
    pub fn update(
        &self,
        num_epochs: usize,
        y_shares: &Vec<Scalar>,
    ) -> (Vec<Scalar>, Vec<G1Projective>) {
        // If user requests more updates than possible
        if num_epochs > self.deletions.len() {
            return (Vec::new(), Vec::new());
        }
        
        // Degree of user shares
        let k = y_shares.len() + 1;

        // The arrays to return
        let mut ds = Vec::new();
        let mut vs = Vec::new();

        let n_del = self.deletions.len();
        let n_acc = self.accumulators.len();

        // Index of updates to build arrays
        let mut del_start = n_del - num_epochs;
        let mut acc_start = n_acc - num_epochs;

        let m1 = -Scalar::one();

        // Iterate over all updates in chunks of size k
        while del_start < n_del {
            let mut d_poly = Polynomial::default();
            let mut v_polys: Vec<Polynomial> = Vec::new();
            d_poly.push(Scalar::one());
            // Create the update polynomials
            for i in del_start..std::cmp::min(del_start+k-1,n_del) {
                v_polys.push(d_poly.clone());
                d_poly *= &[self.deletions[i].0, m1];
            } 

            // Evalute d_poly
            let mut d = d_poly.0[0];
            for i in 1..d_poly.0.len() {
                d += d_poly.0[i]*y_shares[i-1];
            }
            ds.push(d);

            // Evaluate all v polys
            let mut v_poly_evals = vec![Scalar::zero(); v_polys.len()];
            for (i,v) in v_polys.iter().enumerate() {
                v_poly_evals[i] = v.0[0];
                for ii in 1..v.0.len() {
                    v_poly_evals[i] += v.0[ii]*y_shares[ii-1];
                }
            }

            // Evaluate the v-polynomial on accumulator points
            let mut v_point = G1Projective::identity();
            for (i, v) in v_poly_evals.iter().enumerate() {
                v_point += self.accumulators[acc_start + i].0 * v;
            }
            vs.push(v_point);

            del_start += k-1;
            acc_start += k-1;
        }
        (ds, vs)
    }

    // The latest epoch of the accumulator
    pub fn get_epoch(&self) -> usize {
        self.accumulators.len()
    }

    pub fn get_accumulator(&self) -> Accumulator {
        *(self.accumulators.last().unwrap())
    }

    pub fn get_wit_public_key(&self) -> PublicKey {
        self.public_keys.witness_key
    }

    pub fn get_sign_public_key(&self) -> PublicKey {
        self.public_keys.sign_key
    }

    pub fn get_public_keys(&self) -> PublicKeys {
        self.public_keys.clone()
    }

}
