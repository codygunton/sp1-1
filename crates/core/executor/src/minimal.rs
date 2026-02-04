#![allow(clippy::items_after_statements)]
use std::sync::{mpsc, Arc};

use crate::{events::MemoryRecord, ExecutionRecord, Program, SupervisorMode, UserMode};
pub use arch::{MinimalExecutor, UnsafeMemory};
use hashbrown::HashSet;
pub use postprocess::chunked_memory_init_events;
use sp1_jit::{
    debug::{self as jit_debug, DebugState},
    PageProtValue,
};
pub use sp1_jit::{MemValue, TraceChunkRaw};

mod arch;
mod debug;
mod ecall;
mod hint;
mod postprocess;
mod precompiles;
mod write;

#[cfg(feature = "profiling")]
use hashbrown::HashMap;

#[cfg(test)]
mod tests;

/// Wrapper enum to handle `MinimalExecutor` with different execution modes at runtime.
pub enum MinimalExecutorEnum {
    /// `MinimalExecutor` for `SupervisorMode`.
    Supervisor(MinimalExecutor<SupervisorMode>),
    /// `MinimalExecutor` for `UserMode`.
    User(MinimalExecutor<UserMode>),
}

impl MinimalExecutorEnum {
    /// Create a new `MinimalExecutorEnum` based on program's `enable_untrusted_programs` flag.
    #[must_use]
    pub fn new(program: Arc<Program>, debug: bool, max_trace_entries: Option<u64>) -> Self {
        if program.enable_untrusted_programs {
            Self::User(MinimalExecutor::<UserMode>::new(program, debug, max_trace_entries))
        } else {
            Self::Supervisor(MinimalExecutor::<SupervisorMode>::new(
                program,
                debug,
                max_trace_entries,
            ))
        }
    }

    /// Calls `with_input` to respective `MinimalExecutor`.
    pub fn with_input(&mut self, input: &[u8]) {
        match self {
            Self::Supervisor(e) => e.with_input(input),
            Self::User(e) => e.with_input(input),
        }
    }

    /// Calls `execute_chunk` to respective `MinimalExecutor`.
    #[must_use]
    pub fn execute_chunk(&mut self) -> Option<TraceChunkRaw> {
        match self {
            Self::Supervisor(e) => e.execute_chunk(),
            Self::User(e) => e.execute_chunk(),
        }
    }

    /// Calls `is_done` to respective `MinimalExecutor`.
    #[must_use]
    pub fn is_done(&self) -> bool {
        match self {
            Self::Supervisor(e) => e.is_done(),
            Self::User(e) => e.is_done(),
        }
    }

    /// Calls `exit_code` to respective `MinimalExecutor`.
    #[must_use]
    pub fn exit_code(&self) -> u32 {
        match self {
            Self::Supervisor(e) => e.exit_code(),
            Self::User(e) => e.exit_code(),
        }
    }

    /// Calls `global_clk` to respective `MinimalExecutor`.
    #[must_use]
    pub fn global_clk(&self) -> u64 {
        match self {
            Self::Supervisor(e) => e.global_clk(),
            Self::User(e) => e.global_clk(),
        }
    }

    /// Calls `into_public_values_stream` to respective `MinimalExecutor`.
    #[must_use]
    pub fn into_public_values_stream(self) -> Vec<u8> {
        match self {
            Self::Supervisor(e) => e.into_public_values_stream(),
            Self::User(e) => e.into_public_values_stream(),
        }
    }

    /// Calls `public_values_stream` to respective `MinimalExecutor`.
    #[must_use]
    pub fn public_values_stream(&self) -> &Vec<u8> {
        match self {
            Self::Supervisor(e) => e.public_values_stream(),
            Self::User(e) => e.public_values_stream(),
        }
    }

    /// Calls `emit_globals` to respective `MinimalExecutor`.
    pub fn emit_globals(
        &self,
        record: &mut ExecutionRecord,
        final_registers: [MemoryRecord; 32],
        touched_addresses: HashSet<u64>,
        touched_pages: HashSet<u64>,
    ) {
        match self {
            Self::Supervisor(e) => {
                e.emit_globals(record, final_registers, touched_addresses, touched_pages);
            }
            Self::User(e) => {
                e.emit_globals(record, final_registers, touched_addresses, touched_pages);
            }
        }
    }

    /// Calls `unsafe_memory` to respective `MinimalExecutor`.
    #[must_use]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        match self {
            Self::Supervisor(e) => e.unsafe_memory(),
            Self::User(e) => e.unsafe_memory(),
        }
    }

    /// Calls `hints` to respective `MinimalExecutor`.
    #[must_use]
    pub fn hints(&self) -> &[(u64, Vec<u8>)] {
        match self {
            Self::Supervisor(e) => e.hints(),
            Self::User(e) => e.hints(),
        }
    }

    /// Calls `registers` to respective `MinimalExecutor`.
    #[must_use]
    pub fn registers(&self) -> [u64; 32] {
        match self {
            Self::Supervisor(e) => e.registers(),
            Self::User(e) => e.registers(),
        }
    }

    /// Calls `pc` to respective `MinimalExecutor`.
    #[must_use]
    pub fn pc(&self) -> u64 {
        match self {
            Self::Supervisor(e) => e.pc(),
            Self::User(e) => e.pc(),
        }
    }

    /// Calls `get_memory_value` to respective `MinimalExecutor`.
    #[must_use]
    pub fn get_memory_value(&self, addr: u64) -> MemValue {
        match self {
            Self::Supervisor(e) => e.get_memory_value(addr),
            Self::User(e) => e.get_memory_value(addr),
        }
    }

    /// Calls `get_page_prot` to respective `MinimalExecutor`.
    #[must_use]
    pub fn get_page_prot_record(&self, page_idx: u64) -> Option<PageProtValue> {
        match self {
            Self::Supervisor(e) => e.get_page_prot_record(page_idx),
            Self::User(e) => e.get_page_prot_record(page_idx),
        }
    }

    /// Calls `reset` to respective `MinimalExecutor`.
    pub fn reset(&mut self) {
        match self {
            Self::Supervisor(e) => e.reset(),
            Self::User(e) => e.reset(),
        }
    }

    #[cfg(feature = "profiling")]
    /// Take the cycle tracker totals, consuming them.
    pub fn take_cycle_tracker_totals(&mut self) -> HashMap<String, u64> {
        match self {
            Self::Supervisor(e) => e.take_cycle_tracker_totals(),
            Self::User(e) => e.take_cycle_tracker_totals(),
        }
    }

    #[cfg(feature = "profiling")]
    /// Take the invocation tracker, consuming it.
    pub fn take_invocation_tracker(&mut self) -> HashMap<String, u64> {
        match self {
            Self::Supervisor(e) => e.take_invocation_tracker(),
            Self::User(e) => e.take_invocation_tracker(),
        }
    }
}

impl DebugState for MinimalExecutorEnum {
    fn current_state(&self) -> jit_debug::State {
        match self {
            Self::Supervisor(e) => e.current_state(),
            Self::User(e) => e.current_state(),
        }
    }

    fn new_debug_receiver(&mut self) -> Option<mpsc::Receiver<Option<jit_debug::State>>> {
        match self {
            Self::Supervisor(e) => e.new_debug_receiver(),
            Self::User(e) => e.new_debug_receiver(),
        }
    }
}
