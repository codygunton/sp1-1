# The Succinct Library of Polynomials (SLOP)

`slop` is a library of polynomial interactive oracle proofs used in the SP1 Hypercube proof system. It is also a wrapping layer for primitives from [Plonky3](https://github.com/Plonky3/Plonky3/) to maintain compatibility of its APIs with SP1.


Notably, it contains CPU implementations of:

0. Data structures and memory allocation infrastructure (e.g. the `Backend` trait and the `Tensor` struct) for the underlying data processed in the polynomial IOPs of SP1 Hypercube.
1. Sumchecks for a product of multilinear polynomials.
2. The [BaseFold](https://eprint.iacr.org/2023/1705) and [WHIR](https://eprint.iacr.org/2024/1586) multilinear polynomial commitment schemes.
3. The [Spartan](https://eprint.iacr.org/2019/550) proof system for rank-one constraint system instances with a "naive" sparse multilinear polynomial commitment scheme which we call the "pretty good sparse polynomial commitment scheme" (PGSPCS).
4. The [jagged](https://eprint.iacr.org/2025/917) sparse-to-dense polynomial adapter to convert evaluation claims on the tables of the SP1 hypercube arithmetization into evaluation claims on a densely packed batch BaseFold/WHIR instance. In particular, "naive" jagged with the "jagged assist" is the version implemented here.


**NOTE**: As of November 2025, only the jagged, BaseFold, stacked BaseFold, and sumcheck verifiers are audited. It should be possible to use those in contexts outside SP1 Hypercube, but some API choices have been made that limit the generality at which they can be applied (e.g. it is necessary for the verifier to know ahead of time how many rounds of commitments there will be in the protocol) The other protocol implementations are not audited for production use.