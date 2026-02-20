//! # SP1 SDK Types
//!
//! Shared types for the SP1 SDK and SP1 network client, without local proving dependencies.

#![warn(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::bool_to_int_with_if)]
#![allow(clippy::should_panic_without_expect)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::manual_assert)]
#![allow(clippy::unreadable_literal)]
#![allow(clippy::match_wildcard_for_single_variants)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::explicit_iter_loop)]
#![warn(missing_docs)]

mod execute;
mod proof;
mod prove;
mod verify;

pub use execute::ExecuteRequest;
pub use proof::SP1ProofWithPublicValues;
pub use prove::{BaseProveRequest, ProveRequest, SP1ProvingKey};
pub use verify::{verify_proof, SP1VerificationError};

// Re-export commonly needed items from dependencies so downstream crates (sp1-network)
// don't need to depend on all these crates directly.
pub use sp1_core_executor::StatusCode;
pub use sp1_core_machine::io::SP1Stdin;
pub use sp1_primitives::types::Elf;
pub use sp1_prover::{worker::SP1NodeCore, SP1VerifyingKey, SP1_CIRCUIT_VERSION};
pub use sp1_verifier::{ProofFromNetwork, SP1Proof, SP1ProofMode};

/// Utility functions.
pub mod utils {
    use sp1_core_machine::io::SP1Stdin;

    /// Dump the program and stdin to files for debugging if `SP1_DUMP` is set.
    pub fn sp1_dump(elf: &[u8], stdin: &SP1Stdin) {
        if std::env::var("SP1_DUMP").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")) {
            std::fs::write("program.bin", elf).unwrap();
            let stdin = bincode::serialize(&stdin).unwrap();
            std::fs::write("stdin.bin", stdin).unwrap();

            tracing::info!("Dumped program.bin and stdin.bin.");
            std::process::exit(0);
        }
    }
}

use std::{
    fmt,
    future::{Future, IntoFuture},
};

/// The entire user-facing functionality of a prover.
pub trait Prover: Clone + Send + Sync {
    /// The proving key used for this prover type.
    type ProvingKey: ProvingKey;

    /// The possible errors that can occur when proving.
    type Error: fmt::Debug + fmt::Display;

    /// The prove request builder.
    type ProveRequest<'a>: ProveRequest<'a, Self>
    where
        Self: 'a;

    /// The inner [`SP1NodeCore`] struct used by the prover.
    fn inner(&self) -> &sp1_prover::worker::SP1NodeCore;

    /// The version of the current SP1 circuit.
    fn version(&self) -> &str {
        sp1_prover::SP1_CIRCUIT_VERSION
    }

    /// Setup the prover with the given ELF.
    fn setup(
        &self,
        elf: sp1_primitives::types::Elf,
    ) -> impl SendFutureResult<Self::ProvingKey, Self::Error>;

    /// Prove the given program on the given input in the given proof mode.
    fn prove<'a>(
        &'a self,
        pk: &'a Self::ProvingKey,
        stdin: sp1_core_machine::io::SP1Stdin,
    ) -> Self::ProveRequest<'a>;

    /// Execute the program on the given input.
    fn execute(
        &self,
        elf: sp1_primitives::types::Elf,
        stdin: sp1_core_machine::io::SP1Stdin,
    ) -> ExecuteRequest<'_, Self> {
        ExecuteRequest::new(self, elf, stdin)
    }

    /// Verify the given proof.
    ///
    /// Note: If the status code is not set, the verification process will check for success.
    fn verify(
        &self,
        proof: &SP1ProofWithPublicValues,
        vkey: &sp1_prover::SP1VerifyingKey,
        status_code: Option<sp1_core_executor::StatusCode>,
    ) -> Result<(), SP1VerificationError> {
        verify_proof(self.inner(), self.version(), proof, vkey, status_code)
    }
}

/// A trait that represents a prover's proving key.
pub trait ProvingKey: Clone + Send + Sync {
    /// Get the verifying key corresponding to the proving key.
    fn verifying_key(&self) -> &sp1_prover::SP1VerifyingKey;

    /// Get the ELF corresponding to the proving key.
    fn elf(&self) -> &sp1_primitives::types::Elf;
}

/// A trait for [`Future`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`Prover`] trait signature.
pub trait SendFutureResult<T, E>: Future<Output = anyhow::Result<T, E>> + Send {}

impl<F, T, E> SendFutureResult<T, E> for F where F: Future<Output = anyhow::Result<T, E>> + Send {}

/// A trait for [`IntoFuture`]s that are send and return a [`Result`].
///
/// This is just slightly better for the [`Prover`] trait signature.
pub trait IntoSendFutureResult<T, E>: IntoFuture<Output = anyhow::Result<T, E>> + Send {}

impl<F, T, E> IntoSendFutureResult<T, E> for F where
    F: IntoFuture<Output = anyhow::Result<T, E>> + Send
{
}
