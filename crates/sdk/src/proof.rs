//! # SP1 Proof
//!
//! A library of types and functions for SP1 proofs.
#![allow(missing_docs)]
#![allow(clippy::double_parens)] // For some reason we need this to use EnumTryAs

use sp1_primitives::io::SP1PublicValues;
use sp1_prover::{HashableKey, SP1VerifyingKey};

// Re-export the types from the verifier crate in order to avoid importing the verifier crate
// for downstream dependencies.
pub use sp1_verifier::{ProofFromNetwork, SP1Proof, SP1ProofMode};

// Re-export SP1ProofWithPublicValues from sp1-sdk-types for SDK consumers.
pub use sp1_sdk_types::SP1ProofWithPublicValues;

/// Verify that the mock proof's public inputs match the expected values.
///
/// This is used by both the async and blocking mock provers to verify mock Plonk and Groth16 proofs.
pub(crate) fn verify_mock_public_inputs(
    vkey: &SP1VerifyingKey,
    public_values: &SP1PublicValues,
    public_inputs: &[String; 5],
) -> anyhow::Result<()> {
    // Verify vkey hash matches (public_inputs[0]).
    let expected_vkey_hash = vkey.hash_bn254().to_string();
    if public_inputs[0] != expected_vkey_hash {
        anyhow::bail!(
            "vkey hash mismatch: expected {}, got {}",
            expected_vkey_hash,
            public_inputs[0]
        );
    }

    // Verify public values hash matches (public_inputs[1]).
    let expected_pv_hash = public_values.hash_bn254().to_string();
    if public_inputs[1] != expected_pv_hash {
        anyhow::bail!(
            "public values hash mismatch: expected {}, got {}",
            expected_pv_hash,
            public_inputs[1]
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::print_stdout)]

    use sp1_primitives::io::SP1PublicValues;
    use sp1_prover::{Groth16Bn254Proof, PlonkBn254Proof};

    use super::*;

    #[test]
    fn test_plonk_proof_bytes() {
        let plonk_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(PlonkBn254Proof {
                encoded_proof: "ab".to_string(),
                plonk_vkey_hash: [0; 32],
                public_inputs: [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                raw_proof: String::new(),
            }),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        let expected_bytes = [vec![0, 0, 0, 0], hex::decode("ab").unwrap()].concat();
        assert_eq!(plonk_proof.bytes(), expected_bytes);
    }

    #[test]
    fn test_groth16_proof_bytes() {
        let groth16_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(Groth16Bn254Proof {
                encoded_proof: "ab".to_string(),
                groth16_vkey_hash: [0; 32],
                public_inputs: [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                raw_proof: String::new(),
            }),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        let expected_bytes = [vec![0, 0, 0, 0], hex::decode("ab").unwrap()].concat();
        assert_eq!(groth16_proof.bytes(), expected_bytes);
    }

    #[test]
    fn test_mock_plonk_proof_bytes() {
        let mock_plonk_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Plonk(PlonkBn254Proof {
                encoded_proof: String::new(),
                plonk_vkey_hash: [0; 32],
                public_inputs: [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                raw_proof: String::new(),
            }),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        assert_eq!(mock_plonk_proof.bytes(), Vec::<u8>::new());
    }

    #[test]
    fn test_mock_groth16_proof_bytes() {
        let mock_groth16_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Groth16(Groth16Bn254Proof {
                encoded_proof: String::new(),
                groth16_vkey_hash: [0; 32],
                public_inputs: [
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                    String::new(),
                ],
                raw_proof: String::new(),
            }),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        assert_eq!(mock_groth16_proof.bytes(), Vec::<u8>::new());
    }

    #[test]
    #[should_panic(
        expected = "Proof type Core is not supported for onchain verification. Only Plonk and Groth16 proofs are verifiable onchain"
    )]
    fn test_core_proof_bytes_unimplemented() {
        let core_proof = SP1ProofWithPublicValues {
            proof: SP1Proof::Core(vec![]),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };
        println!("{:?}", core_proof.bytes());
    }

    #[test]
    fn test_deser_backwards_compat() {
        let round_trip = SP1ProofWithPublicValues {
            proof: SP1Proof::Core(vec![]),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
            tee_proof: None,
        };

        let round_trip_bytes = bincode::serialize(&round_trip).unwrap();

        bincode::deserialize::<SP1ProofWithPublicValues>(&round_trip_bytes).unwrap();

        let _ = ProofFromNetwork {
            proof: SP1Proof::Core(vec![]),
            public_values: SP1PublicValues::new(),
            sp1_version: String::new(),
        };

        let _ = bincode::deserialize::<ProofFromNetwork>(&round_trip_bytes).unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "slow-tests")]
    async fn test_round_trip_proof_save_load() {
        use crate::{ProveRequest, Prover};

        let prover = crate::CpuProver::new().await;
        let pk = prover.setup(test_artifacts::FIBONACCI_BLAKE3_ELF).await.unwrap();
        let proof = prover.prove(&pk, crate::SP1Stdin::new()).compressed().await.unwrap();

        // Verify the original proof
        prover.verify(&proof, &pk.vk, None).unwrap();

        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("proof.bin");
        std::fs::File::create(&path).unwrap();
        proof.save(&path).unwrap();

        let proof_loaded = SP1ProofWithPublicValues::load(&path).unwrap();

        // Verify the loaded proof
        prover.verify(&proof_loaded, &pk.vk, None).unwrap();
    }
}
