# ALLOSAUR

[ALLOSAUR](https://eprint.iacr.org/2022/1362/) is a pairing-based accumulator with good anonymity properties. This is a proof-of-concept implementation of the single-server functionality of ALLOSAUR and a multi-server threshold update process.

## Current Features

- a single server object to maintain an accumulator and accumulated

- users to obtain membership witnesses and produce zero-knowledge proofs of membership

- users and servers to interact to efficiently update a user's witness

## Missing Features

Critical features of the ALLOSAUR protocol that are missing from this implementation:

- multi-party computation of core accumulator functionality

- interfaces for users and servers to send data to each other 

- constant-time implementations of the underlying cryptography functions

# Packages

- accumulator: Code from [accumulator-rs](https://github.com/mikelodder7/accumulator-rs) which formed the basis of our implementation

- allosaur: Implementation of the basic functionality of ALLOSAUR

- benches: Runs all benchmarks


# Functions

The main functions we implement are:

- A struct `server` which keeps the secret and auxiliary data of an accumulator over many updates. It also implements the main functions: `wit`, `update`, `add`, `delete` that the protocol specifies.

- A struct `user` that, similarly, keeps an ID and a witness and implements the functions necessary to produce membership proofs and engage in the update protocol

- A struct `witness` that contains the secret data for a membership witness, and has static functions to produce and check membership proofs as byte strings

# Benchmarks

To run the benchmarks, from this directory call

`cargo bench`

and the results will be output to the terminal.

The benchmarks cover three different methods to anonymously update a user's witness: the original implementation from [accumulator-rs](https://github.com/mikelodder7/accumulator-rs) with the full batch update polynomials, the split batch updates from the single-server approach of our paper, and ALLOSAUR's multi-party updates. 

The parameters to these benchmarks are in `benches/updates.rs`.

# Credits

ALLOSAUR is a joint work of Sam Jaques, Mike Lodder, and Hart Montgomery.

This repository draws heavily from Mike Lodder's [accumulator implementation](https://github.com/mikelodder7/accumulator-rs).

# License

MIT License

Copyright 2022 Sam Jaques, Mike Lodder, and Hart Montgomery.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.