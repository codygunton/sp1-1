use crate::{
    events::{
        MemoryLocalEvent, MemoryReadRecord, MemoryWriteRecord, PageProtLocalEvent, PageProtRecord,
        PrecompileEvent, SyscallEvent,
    },
    syscalls::SyscallCode,
    ExecutionRecord, Register,
};
use sp1_curves::{
    edwards::ed25519::Ed25519,
    weierstrass::{
        bls12_381::{Bls12381, Bls12381BaseField},
        bn254::{Bn254, Bn254BaseField},
        secp256k1::Secp256k1,
        secp256r1::Secp256r1,
    },
};
use sp1_jit::PageProtValue;
use sp1_primitives::consts::{LOG_PAGE_SIZE, PROT_READ, PROT_WRITE};

use super::CoreVM;

mod commit;
mod deferred;
mod halt;
mod hint;
mod mprotect;
mod poseidon2;
mod precompiles;
mod u256x2048_mul;
mod uint256;
mod uint256_ops;

pub trait SyscallRuntime<'a> {
    const TRACING: bool;

    fn core(&self) -> &CoreVM<'a>;

    fn core_mut(&mut self) -> &mut CoreVM<'a>;

    #[allow(clippy::too_many_arguments)]
    fn syscall_event(
        &self,
        _clk: u64,
        _syscall_code: SyscallCode,
        _arg1: u64,
        _arg2: u64,
        _op_a_0: bool,
        _next_pc: u64,
        _exit_code: u32,
    ) -> SyscallEvent {
        unreachable!("SyscallRuntime::syscall_event is not intended to be called by default.");
    }

    fn add_precompile_event(
        &mut self,
        _syscall_code: SyscallCode,
        _syscall_event: SyscallEvent,
        _event: PrecompileEvent,
    ) {
        unreachable!(
            "SyscallRuntime::add_precompile_event is not intended to be called by default."
        );
    }

    /// Increment the clock by 1, used for precompiles that access memory,
    /// that potentially overlap.
    fn increment_clk(&mut self) {
        let clk = self.core_mut().clk();

        self.core_mut().set_clk(clk + 1);
    }

    fn record_mut(&mut self) -> &mut ExecutionRecord {
        unreachable!("SyscallRuntime::record_mut is not intended to be called by default.");
    }

    /// Postprocess the precompile memory access.
    fn postprocess_precompile(&mut self) -> (Vec<MemoryLocalEvent>, Vec<PageProtLocalEvent>) {
        unreachable!(
            "SyscallRuntime::postprocess_precompile is not intended to be called by default."
        );
    }

    /// Update page permission, returns the old permission(for tracing)
    fn page_prot_write(&mut self, page_idx: u64, _prot: u8) -> PageProtRecord {
        let addr = page_idx << LOG_PAGE_SIZE;
        assert!(
            self.core().program.untrusted_memory.is_some_and(|(s, e)| addr >= s && addr < e),
            "untrusted mode must be turned on, the requested page must be in untrusted memory region",
        );

        let mem_writes = self.core_mut().mem_reads();
        let prev_value: PageProtValue =
            mem_writes.next().expect("Precompile memory read out of bounds").into();
        PageProtRecord {
            external_flag: false,
            page_idx,
            timestamp: prev_value.timestamp,
            page_prot: prev_value.value,
        }
    }

    /// Check page permission for a slice of pages
    #[inline]
    fn page_prot_range_check(
        &mut self,
        start_page_idx: u64,
        end_page_idx: u64,
        page_prot_bitmap: u8,
    ) -> Vec<PageProtRecord> {
        let mut records = Vec::new();
        for page_idx in start_page_idx..=end_page_idx {
            if let Some(record) = self.page_prot_check(page_idx, page_prot_bitmap) {
                records.push(record);
            }
        }
        records
    }

    #[inline]
    fn page_prot_check(&mut self, page_idx: u64, page_prot_bitmap: u8) -> Option<PageProtRecord> {
        if self.core().program.enable_untrusted_programs {
            let mem_writes = self.core_mut().mem_reads();
            let prot_value: PageProtValue =
                mem_writes.next().expect("Precompile memory read out of bounds").into();
            assert!(prot_value.value & page_prot_bitmap == page_prot_bitmap);
            Some(PageProtRecord {
                external_flag: false,
                page_idx,
                timestamp: prot_value.timestamp,
                page_prot: prot_value.value,
            })
        } else {
            None
        }
    }

    #[inline]
    fn mr(&mut self, addr: u64) -> MemoryReadRecord {
        self.core_mut().mr_instr(addr, PROT_READ, None)
    }

    #[inline]
    fn mr_without_prot(&mut self, addr: u64) -> MemoryReadRecord {
        #[allow(clippy::manual_let_else)]
        let record = match self.core_mut().mem_reads.next() {
            Some(next) => next,
            None => {
                unreachable!(
                    "memory reads unexpectdely exhausted at {addr}, clk {}",
                    self.core().clk()
                );
            }
        };

        MemoryReadRecord {
            value: record.value,
            timestamp: self.core().clk(),
            prev_timestamp: record.clk,
            prev_page_prot_record: None,
        }
    }

    #[inline]
    fn mw(&mut self, addr: u64) -> MemoryWriteRecord {
        let prev_page_prot_record = self.page_prot_check(addr >> LOG_PAGE_SIZE, PROT_WRITE);

        let mem_writes = self.core_mut().mem_reads();

        let old = mem_writes.next().expect("Precompile memory read out of bounds");
        let new = mem_writes.next().expect("Precompile memory read out of bounds");

        let record = MemoryWriteRecord {
            prev_timestamp: old.clk,
            prev_value: old.value,
            timestamp: self.core().clk(),
            value: new.value,
            prev_page_prot_record,
        };

        record
    }

    #[inline]
    fn mw_without_prot(&mut self, _addr: u64) -> MemoryWriteRecord {
        let mem_writes = self.core_mut().mem_reads();

        let old = mem_writes.next().expect("Precompile memory read out of bounds");
        let new = mem_writes.next().expect("Precompile memory read out of bounds");

        let record = MemoryWriteRecord {
            prev_timestamp: old.clk,
            prev_value: old.value,
            timestamp: self.core().clk(),
            value: new.value,
            prev_page_prot_record: None,
        };

        record
    }

    #[inline]
    fn mr_slice(&mut self, addr: u64, len: usize) -> (Vec<MemoryReadRecord>, Vec<PageProtRecord>) {
        let first_page_idx = addr >> LOG_PAGE_SIZE;
        let last_page_idx = (addr + (len - 1) as u64 * 8) >> LOG_PAGE_SIZE;
        let page_prot_records =
            self.page_prot_range_check(first_page_idx, last_page_idx, PROT_READ);

        let current_clk = self.core().clk();
        let mem_reads = self.core_mut().mem_reads();

        let records: Vec<MemoryReadRecord> = mem_reads
            .take(len)
            .map(|value| MemoryReadRecord {
                value: value.value,
                timestamp: current_clk,
                prev_timestamp: value.clk,
                prev_page_prot_record: None,
            })
            .collect();

        (records, page_prot_records)
    }

    fn mw_slice(&mut self, addr: u64, len: usize) -> (Vec<MemoryWriteRecord>, Vec<PageProtRecord>) {
        let first_page_idx = addr >> LOG_PAGE_SIZE;
        let last_page_idx = (addr + (len - 1) as u64 * 8) >> LOG_PAGE_SIZE;
        let page_prot_records =
            self.page_prot_range_check(first_page_idx, last_page_idx, PROT_WRITE);

        let mem_writes = self.core_mut().mem_reads();

        let raw_records: Vec<_> = mem_writes.take(len * 2).collect();
        let records: Vec<MemoryWriteRecord> = raw_records
            .chunks(2)
            .map(|chunk| {
                #[allow(clippy::manual_let_else)]
                let (old, new) = match (chunk.first(), chunk.last()) {
                    (Some(old), Some(new)) => (old, new),
                    _ => unreachable!("Precompile memory write out of bounds"),
                };

                MemoryWriteRecord {
                    prev_timestamp: old.clk,
                    prev_value: old.value,
                    timestamp: new.clk,
                    value: new.value,
                    prev_page_prot_record: None,
                }
            })
            .collect();

        (records, page_prot_records)
    }

    fn mr_slice_unsafe(&mut self, len: usize) -> Vec<u64> {
        let mem_reads = self.core_mut().mem_reads();

        mem_reads.take(len).map(|value| value.value).collect()
    }

    fn rr(&mut self, register: usize) -> MemoryReadRecord {
        self.core_mut().rr(Register::from_u8(register as u8), None)
    }
}

impl<'a> SyscallRuntime<'a> for CoreVM<'a> {
    const TRACING: bool = false;

    fn core(&self) -> &CoreVM<'a> {
        self
    }

    fn core_mut(&mut self) -> &mut CoreVM<'a> {
        self
    }
}

pub(crate) fn sp1_ecall_handler<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    code: SyscallCode,
    args1: u64,
    args2: u64,
) -> Option<u64> {
    // Precompiles may directly modify the clock, so we need to save the current clock
    // and reset it after the syscall.
    let clk = rt.core().clk();

    #[allow(clippy::match_same_arms)]
    let ret = match code {
        // Noop: This method just writes to uninitialized memory.
        // Since the tracing VM relies on oracled memory, this method is a no-op.
        SyscallCode::HINT_LEN => hint::hint_len_syscall(rt, code, args1, args2),
        SyscallCode::HALT => halt::halt_syscall(rt, code, args1, args2),
        SyscallCode::COMMIT => commit::commit_syscall(rt, code, args1, args2),
        SyscallCode::COMMIT_DEFERRED_PROOFS => {
            deferred::commit_deferred_proofs_syscall(rt, code, args1, args2)
        }
        // Weierstrass curve operations
        SyscallCode::SECP256K1_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Secp256k1>(rt, code, args1, args2)
        }
        SyscallCode::SECP256K1_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Secp256k1>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Bls12381>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Bls12381>(rt, code, args1, args2)
        }
        SyscallCode::BN254_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Bn254>(rt, code, args1, args2)
        }
        SyscallCode::BN254_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Bn254>(rt, code, args1, args2)
        }
        SyscallCode::SECP256R1_ADD => {
            precompiles::weierstrass::weierstrass_add::<_, Secp256r1>(rt, code, args1, args2)
        }
        SyscallCode::SECP256R1_DOUBLE => {
            precompiles::weierstrass::weierstrass_double::<_, Secp256r1>(rt, code, args1, args2)
        }
        // Edwards curve operations
        SyscallCode::ED_ADD => {
            precompiles::edwards::edwards_add::<RT, Ed25519>(rt, code, args1, args2)
        }
        SyscallCode::ED_DECOMPRESS => {
            precompiles::edwards::edwards_decompress(rt, code, args1, args2)
        }
        SyscallCode::UINT256_MUL => uint256::uint256_mul(rt, code, args1, args2),
        SyscallCode::UINT256_MUL_CARRY | SyscallCode::UINT256_ADD_CARRY => {
            uint256_ops::uint256_ops(rt, code, args1, args2)
        }
        SyscallCode::U256XU2048_MUL => u256x2048_mul::u256xu2048_mul(rt, code, args1, args2),
        SyscallCode::SHA_COMPRESS => precompiles::sha256::sha256_compress(rt, code, args1, args2),
        SyscallCode::SHA_EXTEND => precompiles::sha256::sha256_extend(rt, code, args1, args2),
        SyscallCode::KECCAK_PERMUTE => {
            precompiles::keccak256::keccak256_permute(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP2_ADD | SyscallCode::BLS12381_FP2_SUB => {
            precompiles::fptower::fp2_add::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP2_ADD | SyscallCode::BN254_FP2_SUB => {
            precompiles::fptower::fp2_add::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP2_MUL => {
            precompiles::fptower::fp2_mul::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP2_MUL => {
            precompiles::fptower::fp2_mul::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BLS12381_FP_ADD
        | SyscallCode::BLS12381_FP_SUB
        | SyscallCode::BLS12381_FP_MUL => {
            precompiles::fptower::fp_op::<_, Bls12381BaseField>(rt, code, args1, args2)
        }
        SyscallCode::BN254_FP_ADD | SyscallCode::BN254_FP_SUB | SyscallCode::BN254_FP_MUL => {
            precompiles::fptower::fp_op::<_, Bn254BaseField>(rt, code, args1, args2)
        }
        SyscallCode::MPROTECT => mprotect::mprotect(rt, code, args1, args2),
        SyscallCode::POSEIDON2 => poseidon2::poseidon2(rt, code, args1, args2),
        SyscallCode::VERIFY_SP1_PROOF
        | SyscallCode::WRITE
        | SyscallCode::ENTER_UNCONSTRAINED
        | SyscallCode::EXIT_UNCONSTRAINED
        | SyscallCode::HINT_READ => None,
        code @ (SyscallCode::SECP256K1_DECOMPRESS
        | SyscallCode::BLS12381_DECOMPRESS
        | SyscallCode::SECP256R1_DECOMPRESS) => {
            unreachable!("{code} is not yet supported by the native executor.")
        }
    };

    rt.core_mut().set_clk(clk);

    ret
}
