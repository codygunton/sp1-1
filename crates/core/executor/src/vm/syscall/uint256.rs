use sp1_curves::edwards::WORDS_FIELD_ELEMENT;

use crate::{
    events::{PrecompileEvent, Uint256MulEvent, Uint256MulPageProtRecords},
    vm::syscall::SyscallRuntime,
    ExecutionError, SyscallCode,
};

pub(crate) fn uint256_mul<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, ExecutionError> {
    let x_ptr = arg1;
    if !x_ptr.is_multiple_of(8) {
        panic!();
    }
    let y_ptr = arg2;
    if !y_ptr.is_multiple_of(8) {
        panic!();
    }

    let clk = rt.core().clk();

    let read_y_modulus_page_prot_records = rt.read_slice_check(y_ptr, WORDS_FIELD_ELEMENT * 2)?;
    rt.increment_clk();
    let x_page_prot_records = rt.read_write_slice_check(x_ptr, 4)?;

    // First read the words for the x value. We can read a slice_unsafe here because we write
    // the computed result to x later.
    let x = rt.mr_slice_unsafe(WORDS_FIELD_ELEMENT);

    // Read the y and modulus values.
    let combined_memory_records = rt.mr_slice_without_prot(y_ptr, WORDS_FIELD_ELEMENT * 2);

    let (y_memory_records, modulus_memory_records) =
        combined_memory_records.split_at(WORDS_FIELD_ELEMENT);

    let y = y_memory_records.iter().map(|record| record.value).collect();
    let modulus = modulus_memory_records.iter().map(|record| record.value).collect();

    rt.increment_clk();

    // Write the result to x and keep track of the memory records.
    let x_memory_records = rt.mw_slice_without_prot(x_ptr, 4);

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = PrecompileEvent::Uint256Mul(Uint256MulEvent {
            clk,
            x_ptr,
            x,
            y_ptr,
            y,
            modulus,
            x_memory_records,
            y_memory_records: y_memory_records.to_vec(),
            modulus_memory_records: modulus_memory_records.to_vec(),
            local_mem_access,
            page_prot_records: Uint256MulPageProtRecords {
                write_x_page_prot_records: x_page_prot_records,
                read_y_modulus_page_prot_records,
            },
            local_page_prot_access,
        });
        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            arg1,
            arg2,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );
        rt.add_precompile_event(syscall_code, syscall_event, event);
    }

    Ok(None)
}
