//! # SP1 Prover Trait
//!
//! A trait that each prover variant must implement.

/// The module that exposes the [`ExecuteRequest`] type.
mod execute;

/// The module that exposes the [`ProveRequest`] trait.
mod prove;

pub use execute::ExecuteRequest;
pub use sp1_sdk_types::{
    BaseProveRequest, IntoSendFutureResult, Prover, ProvingKey, SP1VerificationError,
    SendFutureResult,
};
// Re-export ProveRequest and SP1ProvingKey via the prove module (which re-exports from sp1_sdk_types).
pub use prove::{ProveRequest, SP1ProvingKey};
