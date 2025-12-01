use crate::{
    events::{PrecompileEvent, ShaCompressEvent, ShaCompressPageProtAccess},
    vm::syscall::SyscallRuntime,
    ExecutionError, SyscallCode,
};

pub(crate) fn sha256_compress<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, ExecutionError> {
    let w_ptr = arg1;
    let h_ptr = arg2;
    assert_ne!(w_ptr, h_ptr);

    let clk = rt.core().clk();

    let h_read_page_prot_records = rt.read_slice_check(h_ptr, 8)?;
    let w_read_page_prot_records = rt.read_slice_check(w_ptr, 64)?;
    rt.increment_clk();
    let h_write_page_prot_records = rt.write_slice_check(h_ptr, 8)?;

    // Execute the "initialize" phase where we read in the h values.

    let h_read_records = rt.mr_slice_without_prot(h_ptr, 8);
    let hx = h_read_records.iter().map(|r| r.value as u32).collect::<Vec<_>>();

    rt.increment_clk();
    let w_i_read_records = rt.mr_slice_without_prot(w_ptr, 64);
    let original_w = w_i_read_records.iter().map(|r| r.value as u32).collect::<Vec<_>>();

    rt.increment_clk();
    let h_write_records = rt.mw_slice_without_prot(h_ptr, 8);

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        // Push the SHA extend event.
        let event = PrecompileEvent::ShaCompress(ShaCompressEvent {
            clk,
            w_ptr,
            h_ptr,
            w: original_w,
            h: hx.try_into().unwrap(),
            h_read_records: h_read_records.try_into().unwrap(),
            w_i_read_records,
            h_write_records: h_write_records.try_into().unwrap(),
            local_mem_access,
            page_prot_access: ShaCompressPageProtAccess {
                h_read_page_prot_records,
                w_read_page_prot_records,
                h_write_page_prot_records,
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
