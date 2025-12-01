use sp1_curves::{
    params::NumWords,
    weierstrass::{FieldType, FpOpField},
};
use typenum::Unsigned;

use crate::{
    events::{Fp2MulEvent, FpPageProtRecords, PrecompileEvent},
    vm::syscall::SyscallRuntime,
    ExecutionError, SyscallCode,
};

pub fn fp2_mul<'a, RT: SyscallRuntime<'a>, P: FpOpField>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, ExecutionError> {
    let x_ptr = arg1;
    assert!(x_ptr.is_multiple_of(8), "x_ptr must be 8-byte aligned");
    let y_ptr = arg2;
    assert!(y_ptr.is_multiple_of(8), "y_ptr must be 8-byte aligned");

    let clk = rt.core().clk();

    let num_words = <P as NumWords>::WordsCurvePoint::USIZE;

    let y_page_prot_records = rt.read_slice_check(y_ptr, num_words)?;
    rt.increment_clk();
    let x_page_prot_records = rt.read_write_slice_check(x_ptr, num_words)?;

    // Read x (current value that will be overwritten) using mr_slice_unsafe
    // No pointer needed - just reads next num_words from memory
    let x = rt.mr_slice_unsafe(num_words);

    let y_memory_records = rt.mr_slice_without_prot(y_ptr, num_words);
    let y: Vec<u64> = y_memory_records.iter().map(|record| record.value).collect();

    rt.increment_clk();

    // Write result to x (we don't compute the actual result in tracing mode)
    let x_memory_records = rt.mw_slice_without_prot(x_ptr, num_words);

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = Fp2MulEvent {
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            x_memory_records,
            y_memory_records,
            local_mem_access,
            page_prot_records: FpPageProtRecords {
                read_page_prot_records: y_page_prot_records,
                write_page_prot_records: x_page_prot_records,
            },
            local_page_prot_access,
        };

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );

        match P::FIELD_TYPE {
            FieldType::Bn254 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bn254Fp2Mul(event),
            ),
            FieldType::Bls12381 => rt.add_precompile_event(
                syscall_code,
                syscall_event,
                PrecompileEvent::Bls12381Fp2Mul(event),
            ),
        }
    }

    Ok(None)
}
