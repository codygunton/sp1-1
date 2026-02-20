use super::Prover;
use sp1_core_executor::{ExecutionError, ExecutionReport, HookEnv, SP1ContextBuilder, StatusCode};
use sp1_core_machine::io::SP1Stdin;
use sp1_primitives::{io::SP1PublicValues, types::Elf};
use std::{
    future::{Future, IntoFuture},
    pin::Pin,
};

/// A request for executing a program.
pub struct ExecuteRequest<'a, P: Prover> {
    /// The prover to use.
    pub prover: &'a P,
    /// The ELF to execute.
    pub elf: Elf,
    /// The stdin to use.
    pub stdin: SP1Stdin,
    /// The context builder to use.
    pub context_builder: SP1ContextBuilder<'static>,
}

impl<'a, P: Prover> ExecuteRequest<'a, P> {
    pub(crate) fn new(prover: &'a P, elf: Elf, stdin: SP1Stdin) -> Self {
        Self { prover, elf, stdin, context_builder: SP1ContextBuilder::new() }
    }

    /// Add an executor [`sp1_core_executor::Hook`] into the context.
    ///
    /// # Arguments
    /// * `fd` - The file descriptor that triggers this execution hook.
    /// * `f` - The function to invoke when the hook is triggered.
    ///
    /// # Details
    /// Hooks may be invoked from within SP1 by writing to the specified file descriptor `fd`
    /// with [`sp1_zkvm::io::write`], returning a list of arbitrary data that may be read
    /// with successive calls to [`sp1_zkvm::io::read`].
    #[must_use]
    pub fn with_hook(
        mut self,
        fd: u32,
        f: impl FnMut(HookEnv, &[u8]) -> Vec<Vec<u8>> + Send + Sync + 'static,
    ) -> Self {
        self.context_builder.hook(fd, f);
        self
    }

    /// Set the maximum number of cpu cycles to use for execution.
    #[must_use]
    pub fn cycle_limit(mut self, max_cycles: u64) -> Self {
        self.context_builder.max_cycles(max_cycles);
        self
    }

    /// Whether to enable deferred proof verification in the executor.
    #[must_use]
    pub fn deferred_proof_verification(mut self, value: bool) -> Self {
        self.context_builder.set_deferred_proof_verification(value);
        self
    }

    /// Whether to enable gas calculation in the executor.
    #[must_use]
    pub fn calculate_gas(mut self, value: bool) -> Self {
        self.context_builder.calculate_gas(value);
        self
    }

    /// Set the expected exit code of the program.
    #[must_use]
    pub fn expected_exit_code(mut self, code: StatusCode) -> Self {
        self.context_builder.expected_exit_code(code);
        self
    }
}

impl<'a, P: Prover> IntoFuture for ExecuteRequest<'a, P> {
    type Output = Result<(SP1PublicValues, ExecutionReport), ExecutionError>;

    type IntoFuture = Pin<Box<dyn Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        let task = async move {
            let Self { prover, elf, stdin, mut context_builder } = self;
            let inner = prover.inner();
            let context = context_builder.build();
            let (pv, _digest, report) = inner
                .execute(&elf, stdin, context)
                .await
                .map_err(|e| ExecutionError::Other(e.to_string()))?;

            Ok((pv, report))
        };
        Box::pin(task)
    }
}
