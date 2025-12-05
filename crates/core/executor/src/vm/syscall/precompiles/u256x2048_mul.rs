use crate::{
    events::{
        MemoryReadRecord, MemoryWriteRecord, PrecompileEvent, U256xU2048MulEvent,
        U256xU2048MulPageProtRecords,
    },
    vm::syscall::SyscallRuntime,
    ExecutionMode, SyscallCode, TrapError,
};

const U256_NUM_WORDS: usize = 4;
const U2048_NUM_WORDS: usize = 32;

/// Check page permissions for u256x2048 mul. Returns early if permission check fails.
fn trap_u256xu2048_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    a_ptr: u64,
    b_ptr: u64,
    lo_ptr: u64,
    hi_ptr: u64,
) -> (U256xU2048MulPageProtRecords, Option<TrapError>) {
    let mut ret = U256xU2048MulPageProtRecords {
        read_a_page_prot_records: Vec::new(),
        read_b_page_prot_records: Vec::new(),
        write_lo_page_prot_records: Vec::new(),
        write_hi_page_prot_records: Vec::new(),
    };

    let (a_page_prot_records, a_error) = rt.read_slice_check(a_ptr, U256_NUM_WORDS);
    ret.read_a_page_prot_records = a_page_prot_records;
    if a_error.is_some() {
        return (ret, a_error);
    }

    rt.increment_clk();

    let (b_page_prot_records, b_error) = rt.read_slice_check(b_ptr, U2048_NUM_WORDS);
    ret.read_b_page_prot_records = b_page_prot_records;
    if b_error.is_some() {
        return (ret, b_error);
    }

    rt.increment_clk();

    let (lo_page_prot_records, lo_error) = rt.write_slice_check(lo_ptr, U2048_NUM_WORDS);
    ret.write_lo_page_prot_records = lo_page_prot_records;
    if lo_error.is_some() {
        return (ret, lo_error);
    }

    rt.increment_clk();

    let (hi_page_prot_records, hi_error) = rt.write_slice_check(hi_ptr, U256_NUM_WORDS);
    ret.write_hi_page_prot_records = hi_page_prot_records;
    if hi_error.is_some() {
        return (ret, hi_error);
    }

    (ret, None)
}

pub(crate) fn u256xu2048_mul<'a, M: ExecutionMode, RT: SyscallRuntime<'a, M>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, TrapError> {
    let clk = rt.core().clk();

    let a_ptr = arg1;
    let b_ptr = arg2;

    // Read lo_ptr and hi_ptr from registers X12 and X13
    let lo_ptr_memory = rt.rr(12 /* X12 */);
    let hi_ptr_memory = rt.rr(13 /* X13 */);
    let lo_ptr = lo_ptr_memory.value;
    let hi_ptr = hi_ptr_memory.value;

    let (page_prot_records, is_trap) = trap_u256xu2048_mul(rt, a_ptr, b_ptr, lo_ptr, hi_ptr);

    // Default values if trap occurs
    let mut a: Vec<u64> = vec![0; U256_NUM_WORDS];
    let mut b: Vec<u64> = vec![0; U2048_NUM_WORDS];
    let mut lo: Vec<u64> = vec![0; U2048_NUM_WORDS];
    let mut hi: Vec<u64> = vec![0; U256_NUM_WORDS];
    let mut a_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut b_memory_records: Vec<MemoryReadRecord> = Vec::new();
    let mut lo_memory_records: Vec<MemoryWriteRecord> = Vec::new();
    let mut hi_memory_records: Vec<MemoryWriteRecord> = Vec::new();

    rt.reset_clk(clk);
    if is_trap.is_none() {
        // Read input values from memory records
        a_memory_records = rt.mr_slice_without_prot(a_ptr, U256_NUM_WORDS);
        a = a_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        b_memory_records = rt.mr_slice_without_prot(b_ptr, U2048_NUM_WORDS);
        b = b_memory_records.iter().map(|record| record.value).collect();

        // Increment clk so that the write is not at the same cycle as the read
        rt.increment_clk();

        // Read the computed results from memory records using mw_slice
        lo_memory_records = rt.mw_slice_without_prot(lo_ptr, U2048_NUM_WORDS);
        lo = lo_memory_records.iter().map(|record| record.value).collect();

        rt.increment_clk();

        hi_memory_records = rt.mw_slice_without_prot(hi_ptr, U256_NUM_WORDS);
        hi = hi_memory_records.iter().map(|record| record.value).collect();
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Create and add the event
        let event = PrecompileEvent::U256xU2048Mul(U256xU2048MulEvent {
            clk,
            a_ptr,
            a,
            b_ptr,
            b,
            lo_ptr,
            lo_ptr_memory,
            lo,
            hi_ptr,
            hi_ptr_memory,
            hi,
            a_memory_records,
            b_memory_records,
            lo_memory_records,
            hi_memory_records,
            local_mem_access,
            page_prot_records,
            local_page_prot_access,
        });

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            rt.core().next_pc(),
            rt.core().exit_code(),
            None,
            None,
            is_trap,
        );

        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    if let Some(err) = is_trap {
        return Err(err);
    }

    Ok(None)
}
