use super::{IntoSendFutureResult, Prover, ProvingKey};
use crate::proof::SP1ProofWithPublicValues;
use sp1_core_executor::{SP1ContextBuilder, StatusCode};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::types::Elf;
use sp1_prover::SP1VerifyingKey;
use sp1_verifier::SP1ProofMode;

/// A proving key for the SP1 prover.
///
/// Contains only the minimal information required to implement the [`ProvingKey`] trait.
#[derive(Clone)]
pub struct SP1ProvingKey {
    /// Verifying key for verifying a proof created with this proving key.
    pub vk: SP1VerifyingKey,
    /// ELF of the program to be proven.
    pub elf: Elf,
}

impl SP1ProvingKey {
    /// Creates a new `SP1ProvingKey` from a verifying key and ELF.
    #[must_use]
    pub fn new(vk: SP1VerifyingKey, elf: Elf) -> Self {
        Self { vk, elf }
    }
}

impl ProvingKey for SP1ProvingKey {
    fn verifying_key(&self) -> &SP1VerifyingKey {
        &self.vk
    }

    fn elf(&self) -> &Elf {
        &self.elf
    }
}

/// A unified collection of methods for all prover types.
pub trait ProveRequest<'a, P>
where
    Self: IntoSendFutureResult<SP1ProofWithPublicValues, P::Error> + Sized + Send,
    P: Prover + 'a,
{
    /// Get the base request for the prover.
    fn base(&mut self) -> &mut BaseProveRequest<'a, P>;

    /// Set the proof mode to the given [`SP1ProofMode`].
    #[must_use]
    fn mode(mut self, mode: SP1ProofMode) -> Self {
        self.base().mode(mode);
        self
    }

    /// Set the proof kind to [`SP1ProofMode::Compressed`] mode.
    #[must_use]
    fn compressed(mut self) -> Self {
        self.base().compressed();
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Plonk`] mode.
    #[must_use]
    fn plonk(mut self) -> Self {
        self.base().plonk();
        self
    }

    /// Set the proof mode to [`SP1ProofMode::Groth16`] mode.
    #[must_use]
    fn groth16(mut self) -> Self {
        self.base().groth16();
        self
    }

    /// Set the proof kind to [`SP1ProofMode::Core`] mode.
    #[must_use]
    fn core(mut self) -> Self {
        self.base().core();
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    #[must_use]
    fn cycle_limit(mut self, cycle_limit: u64) -> Self {
        self.base().cycle_limit(cycle_limit);
        self
    }

    /// Whether to enable deferred proof verification in the executor.
    #[must_use]
    fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.base().deferred_proof_verification(value);
        self
    }

    /// Set the expected exit code of the program.
    #[must_use]
    fn expected_exit_code(mut self, code: StatusCode) -> Self {
        self.base().expected_exit_code(code);
        self
    }

    /// Set the proof nonce for this execution.
    ///
    /// The nonce ensures each proof is unique even for identical programs and inputs.
    /// If not provided, will default to 0.
    #[must_use]
    fn with_proof_nonce(mut self, nonce: [u32; 4]) -> Self {
        self.base().context_builder.proof_nonce(nonce);
        self
    }
}

/// The base prove request for a prover.
///
/// This exposes all the options that are shared across different prover types.
pub struct BaseProveRequest<'a, P: Prover> {
    /// The prover to use.
    pub prover: &'a P,
    /// The proving key to use.
    pub pk: &'a P::ProvingKey,
    /// The stdin to use.
    pub stdin: SP1Stdin,
    /// The proof mode to use.
    pub mode: SP1ProofMode,
    /// The context builder to use.
    pub context_builder: SP1ContextBuilder<'static>,
}

impl<'a, P: Prover> BaseProveRequest<'a, P> {
    /// Create a new [`BaseProveRequest`] with the given prover, proving key, and stdin.
    pub const fn new(prover: &'a P, pk: &'a P::ProvingKey, stdin: SP1Stdin) -> Self {
        Self {
            prover,
            pk,
            stdin,
            mode: SP1ProofMode::Core,
            context_builder: SP1ContextBuilder::new(),
        }
    }

    /// See [`ProveRequest::compressed`].
    pub fn compressed(&mut self) {
        self.mode = SP1ProofMode::Compressed;
    }

    /// See [`ProveRequest::plonk`].
    pub fn plonk(&mut self) {
        self.mode = SP1ProofMode::Plonk;
    }

    /// See [`ProveRequest::groth16`].
    pub fn groth16(&mut self) {
        self.mode = SP1ProofMode::Groth16;
    }

    /// See [`ProveRequest::core`].
    pub fn core(&mut self) {
        self.mode = SP1ProofMode::Core;
    }

    /// See [`ProveRequest::mode`].
    pub fn mode(&mut self, mode: SP1ProofMode) {
        self.mode = mode;
    }

    /// See [`ProveRequest::cycle_limit`].
    pub fn cycle_limit(&mut self, cycle_limit: u64) {
        self.context_builder.max_cycles(cycle_limit);
    }

    /// See [`ProveRequest::deferred_proof_verification`].
    pub fn deferred_proof_verification(&mut self, value: bool) {
        self.context_builder.set_deferred_proof_verification(value);
    }

    /// See [`ProveRequest::expected_exit_code`].
    pub fn expected_exit_code(&mut self, code: StatusCode) {
        self.context_builder.expected_exit_code(code);
    }

    /// Set the nonce for this proof.
    pub fn with_nonce(&mut self, nonce: [u32; 4]) {
        self.context_builder.proof_nonce(nonce);
    }
}
