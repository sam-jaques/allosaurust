use accumulator::{
    SecretKey, Element, Accumulator,MembershipWitness,
    PublicKey, Coefficient
};
use bls12_381_plus::{Scalar,G1Projective, G2Projective};
use group::GroupEncoding;
use rand_core::SeedableRng;
use rayon::prelude::*;
use serde::{Serialize, Serializer};
use std::collections::{HashMap, HashSet};
use std::vec::Vec;
use uint_zigzag::Uint;

use criterion::{
    criterion_group, criterion_main, Criterion,
};

use allosaur::{
    Server,User,PublicKeys,AccParams,UserID
};



//-------BENCHMARK PARAMETERS ------//

const USERS: usize = 15000; // Total number of elements originally added
const SHARES: usize = 5; // Number of servers for ALLOSAUR
const THRESHOLD: usize = 3; // Threshold for ALLOSAUR secret sharing
const SLICES: usize = 50; // Size of each "slice" of the optimized single-server update
// Size of updates as (number of additions, number of deletions) for
// the original batch update protocols
const BATCH_UPDATE_CHANGES: [(usize, usize); 6] = [
        (0, 10),
        (10, 10),
        (0, 100),
        (100, 100),
        (0, 1000),
        (1000, 1000),
    ];
// Number of deletions for the single-server and threshold updates of ALLOSAUR
// Additions are not included, as both cases ignore additions
const ALLOSAUR_CHANGES: [usize; 4] = [10, 100, 1000, 10000];
const NUM_SAMPLES: usize = 50; // the number of samples for each benchmark
//------------------------- ------//




criterion_group!(name = benches;
    config = Criterion::default().sample_size(NUM_SAMPLES);
    targets = allosaur_update, single_server, batch_update
);
criterion_main!(benches);


// Benchmarks the single-server update of Section 3
fn single_server(c: &mut Criterion) {
    c.benchmark_group("single_server");


    for num_dels in ALLOSAUR_CHANGES {
        println!("=================================================");
        println!(
            "=Single-server Benchmark with {} deletions=",
            num_dels
        );
        println!("=================================================");

        // Creates a random array of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
        let mut acc = Accumulator::with_elements(&key, items.as_slice());

        // Creats a witness for some user
        let y = items.last().unwrap().clone();
        let witness = MembershipWitness::new(y, acc, &key).unwrap();

        // Gets set of deletions
        let (deletions, _) = items.split_at(num_dels);

        let deletions = deletions.to_vec();
        // Divides deletions into chunks of length SLICES
        let split_deletions: Vec<&[Element]> = deletions.chunks(SLICES).collect();

        // Benchmark of deletion method
        c.bench_function("Single-server server-side update", |b| {
            b.iter(|| {
                let mut new_acc = acc.clone();
                let mut deltas = vec![Vec::new(); split_deletions.len()];
                for (i, deletion) in split_deletions.iter().enumerate() {
                    deltas[i] = new_acc.update_assign(&key, &[], deletion);
                }
            })
        });

        // Repeatedly updates the accumulator with the deletions
        // Collects all coefficients from this
        let mut deltas = vec![Vec::new(); split_deletions.len()];
        for (i, deletion) in split_deletions.iter().enumerate() {
            deltas[i] = acc.update_assign(&key, &[], deletion);
        }
        // Adds up the length of each message that must be sent
        // from each deletion update
        let mut message_length = 0;
        for (i, deletion) in split_deletions.iter().enumerate() {
            let server_message = VBUpdateMessage {
                additions: Vec::new(),
                deletions: deletion.to_vec().clone(),
                deltas: deltas[i].clone(),
            };
            message_length += serde_cbor::to_vec(&server_message).unwrap().len();
        }
        println!("Single-server server->user message size {} bytes", message_length);

        // User repeatedly processes these deletions
        c.bench_function("Single-server user-side update", |b| {
            b.iter(|| {
                let mut new_witness = witness.clone();
                for (i, deletion) in split_deletions.iter().enumerate() {
                    new_witness.batch_update_assign(y, &[], &deletion, &deltas[i]);
                }
            })
        });
    }
}

// Batch update protocol of Vitto and Biryukov 2020 (https://eprint.iacr.org/2020/777)
fn batch_update(c: &mut Criterion) {
    c.benchmark_group("batch_update");

    for (num_adds, num_dels) in BATCH_UPDATE_CHANGES {
        println!("=================================================");
        println!(
            "=Batch update Benchmark with {} additions and {} deletions=",
            num_adds, num_dels
        );
        println!("=================================================");

        // Creates an accumulator with the number of users
        let key = SecretKey::new(None);
        let items: Vec<Element> = (0..USERS).map(|_| Element::random()).collect();
        let mut acc = Accumulator::with_elements(&key, items.as_slice());

        // Takes the last user, gives them a witness
        let y = items.last().unwrap().clone();
        let witness = MembershipWitness::new(y, acc, &key).unwrap();

        // Creates lists of elements to add and delete
        let additions: Vec<Element> = (0..num_adds).map(|_| Element::random()).collect();
        let (deletions, _) = items.split_at(num_dels);

        let deletions = deletions.to_vec();

        // Benchmarks the creation of the update polynomials
        c.bench_function("Batch update server-side update", |b| {
            b.iter(|| {
                acc.update(&key, additions.as_slice(), deletions.as_slice());
            })
        });

        // Actually creates update polynomials
        let coefficients = acc.update_assign(&key, additions.as_slice(), deletions.as_slice());

        // Builds a data structure to transform the polynomials into bytes
        let server_message = VBUpdateMessage {
            additions: additions.clone(),
            deletions: deletions.clone(),
            deltas: coefficients.clone(),
        };
        println!(
            "Batch update server->user message size {} bytes",
            serde_cbor::to_vec(&server_message).unwrap().len()
        );

        // Benchmarks user response
        c.bench_function("Batch update user-side update", |b| {
            b.iter(|| {
                witness.batch_update(y, &additions, &deletions, &coefficients);
            })
        });
    }
}


// Multiparty threshold updates in ALLOSAUR
fn allosaur_update(c: &mut Criterion) {
    c.benchmark_group("allosaur_update");

    for num_dels in ALLOSAUR_CHANGES {
        println!("=================================================");
        println!("=ALLOSAUR Benchmark with {} deletions and threshold {} =", num_dels, THRESHOLD);
        println!("=================================================");

        // Creates secrets from shares, somewhat needlessly
       let alpha = SecretKey::new(None);
        let s =  SecretKey::new(None);
        let public_key_alpha = PublicKey(G2Projective::generator() * alpha.0);
        let public_key_s = PublicKey(G2Projective::generator() * s.0);

        let public_keys = PublicKeys {
            witness_key: public_key_alpha,
            sign_key: public_key_s,
        };

        let mut rng = rand_chacha::ChaChaRng::from_seed([1u8; 32]);

        let accumulator = Accumulator::random(&mut rng);
        let acc_params = AccParams::default();

        // Generates users with valid witnesses using the secret
        let users: Vec<User> = (0..USERS)
            .map(|_| {
                User::random(
                    &alpha,
                    &s,
                    acc_params,
                    accumulator,
                    public_keys,
                    1,
                    &mut rng,
                )
            })
            .collect();

        // Gets all the user witnesses to give to the servers
        let all_witnesses: HashMap<UserID, MembershipWitness> = users
            .iter()
            .map(|u| (u.get_id(), u.witness.as_ref().unwrap().witness))
            .collect();
        let all_users: HashSet<UserID> = users.iter().map(|u| u.id).collect();

        // Generates an array of servers
        // Here each server has the full accumulator secret key;
        // this is necessary for our fast and lazy delete to run the benchmark
        // but does not reflect how servers would actually handle secret keys
        let mut servers: Vec<Server> = (0..SHARES)
            .map(|_| Server {
                accumulators: vec![accumulator],
                wit_secret_key: alpha.clone(),
                public_keys,
                sign_secret_key: s.clone(),
                all_users: all_users.clone(),
                all_witnesses: all_witnesses.clone(),
                deletions: Vec::new(),
            })
            .collect();

        // Step 1 - remove a user from the accumulator which triggers an update
        servers.par_iter_mut().for_each(|s| {
            for u in &users[..num_dels] {
                let _ = s.quick_del(u.id).unwrap();
            }
        });

        // Benchmark the pre-update computations from the user
        let user = users[num_dels].clone();
        c.bench_function(
            "ALLOSAUR user-side pre-update",
            |b| {
                b.iter(|| {
                    user
                        .pre_update(servers[0].get_epoch(), SHARES, THRESHOLD)
                        .unwrap();
                })
            },
        );

        // Compute the actual pre-update data
        let (user_d, user_shares, user_values) = user
            .pre_update(servers[0].get_epoch(), SHARES, THRESHOLD)
            .unwrap();

        // Get the length of the data the user must send to each server
        let user_server_message = UserUpdateMessage {
            epoch: user_d,
            shares: user_shares[0].clone(),
        };
        // Print the length of data sent to *all* servers
        println!(
            "ALLOSAUR user 1 user->server message size {} bytes",
            serde_cbor::to_vec(&user_server_message).unwrap().len()*SHARES
        );

        // Benchmark the server side, for only one server
        c.bench_function(
            "ALLOSAUR server-side update ",
            |b| b.iter(|| servers[0].update(user_d, &user_shares[0])),
        );

        // Actually get the server responses, from all servers
        let dvs: Vec<(Vec<Scalar>, Vec<G1Projective>)> = (0..SHARES)
            .map(|i| servers[i].update(user_d, &user_shares[i]))
            .collect();

        // Get the length of data sent back to the user 
        let server_user_message = ServerUpdateMessage {
            d_poly: dvs[0].0.clone(),
            v_poly: dvs[0].1.clone(),
        };
         // Print the length of data sent from *all* servers
        println!(
            "ALLOSAUR user 1 server->user message size {} bytes",
            serde_cbor::to_vec(&server_user_message).unwrap().len()*SHARES
        );

        // Benchmark the user's computation on the resulting data
        c.bench_function("user-side post-update ", |b| {
            b.iter(|| {
                user
                    .post_update(
                        user.witness.as_ref().unwrap().witness,
                        THRESHOLD,
                        &user_shares,
                        &user_values,
                        &dvs,
                    )
                    .unwrap();
            })
        });

    }
}


// Various helper data structures to serialize update messages into byte strings

#[derive(Debug)]
struct UserUpdateMessage {
    epoch: usize,
    shares: Vec<Scalar>,
}

impl Serialize for UserUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.epoch).to_vec());
        output.append(&mut Uint::from(self.shares.len()).to_vec());
        for s in &self.shares {
            output.extend_from_slice(&s.to_bytes());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct ServerUpdateMessage {
    d_poly: Vec<Scalar>,
    v_poly: Vec<G1Projective>,
}

impl Serialize for ServerUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.d_poly.len()).to_vec());
        for s in &self.d_poly {
            output.extend_from_slice(&s.to_bytes());
        }
        output.append(&mut Uint::from(self.v_poly.len()).to_vec());
        for s in &self.v_poly {
            output.extend_from_slice(&s.to_bytes().as_ref());
        }
        serializer.serialize_bytes(&output)
    }
}

#[derive(Debug)]
struct VBUpdateMessage {
    additions: Vec<Element>,
    deletions: Vec<Element>,
    deltas: Vec<Coefficient>,
}

impl Serialize for VBUpdateMessage {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut output = Vec::with_capacity(64);
        output.append(&mut Uint::from(self.additions.len()).to_vec());
        for s in &self.additions {
            output.extend_from_slice(&s.0.to_bytes());
        }
        output.append(&mut Uint::from(self.deletions.len()).to_vec());
        for s in &self.deletions {
            output.extend_from_slice(&s.0.to_bytes());
        }
        output.append(&mut Uint::from(self.deltas.len()).to_vec());
        for s in &self.deltas {
            output.extend_from_slice(&s.0.to_bytes().as_ref());
        }
        serializer.serialize_bytes(&output)
    }
}
