use sp1_primitives::consts::{LOG_PAGE_SIZE, PROT_READ, PROT_WRITE};

use crate::{
    events::{PrecompileEvent, ShaExtendEvent, ShaExtendMemoryRecords, ShaExtendPageProtRecords},
    vm::syscall::SyscallRuntime,
    ExecutionError, SyscallCode,
};

pub(crate) fn sha256_extend<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, ExecutionError> {
    let w_ptr = arg1;
    assert!(arg2 == 0, "arg2 must be 0");
    assert!(arg1.is_multiple_of(8));

    let clk = rt.core().clk();
    let initial_page_prot_records = rt.page_prot_range_check(
        w_ptr >> LOG_PAGE_SIZE,
        (w_ptr + 15 * 8) >> LOG_PAGE_SIZE,
        PROT_READ,
    )?;
    rt.increment_clk();
    let extension_page_prot_records = rt.page_prot_range_check(
        (w_ptr + 16 * 8) >> LOG_PAGE_SIZE,
        (w_ptr + 63 * 8) >> LOG_PAGE_SIZE,
        PROT_READ | PROT_WRITE,
    )?;

    let mut sha_extend_memory_records = Vec::with_capacity(48);
    for i in 16..64 {
        // Read w[i-15].
        let w_i_minus_15_reads = rt.mr_without_prot(w_ptr + (i - 15) * 8);

        // Read w[i-2].
        let w_i_minus_2_reads = rt.mr_without_prot(w_ptr + (i - 2) * 8);

        // Read w[i-16].
        let w_i_minus_16_reads = rt.mr_without_prot(w_ptr + (i - 16) * 8);

        // Read w[i-7].
        let w_i_minus_7_reads = rt.mr_without_prot(w_ptr + (i - 7) * 8);
        // Write w[i].
        let w_i_write = rt.mw_without_prot(w_ptr + i * 8);

        rt.increment_clk();

        sha_extend_memory_records.push(ShaExtendMemoryRecords {
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_write,
        });
    }

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Push the SHA extend event.
        #[allow(clippy::default_trait_access)]
        let event = PrecompileEvent::ShaExtend(ShaExtendEvent {
            clk,
            w_ptr,
            local_mem_access,
            memory_records: sha_extend_memory_records,
            page_prot_records: ShaExtendPageProtRecords {
                initial_page_prot_records,
                extension_page_prot_records,
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
