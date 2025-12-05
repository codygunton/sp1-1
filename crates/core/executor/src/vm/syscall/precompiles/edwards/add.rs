use sp1_curves::{edwards::EdwardsParameters, params::NumWords, EllipticCurve};

use crate::{
    events::{EllipticCurveAddEvent, EllipticCurvePageProtRecords, PrecompileEvent},
    syscalls::SyscallCode,
    vm::syscall::SyscallRuntime,
};
use typenum::Unsigned;

pub(crate) fn edwards_add<'a, RT: SyscallRuntime<'a>, E: EllipticCurve + EdwardsParameters>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    arg1: u64,
    arg2: u64,
) -> Option<u64> {
    let p_ptr = arg1;
    if !p_ptr.is_multiple_of(4) {
        panic!();
    }
    let q_ptr = arg2;
    if !q_ptr.is_multiple_of(4) {
        panic!();
    }

    let clk = rt.core().clk();

    let num_words = <E::BaseField as NumWords>::WordsCurvePoint::USIZE;

    // Accessed via slice unsafe, so ununsed.
    let p: Vec<u64> = rt.mr_slice_unsafe(num_words);

    let (q_memory_records, q_page_prot_records) = rt.mr_slice(q_ptr, num_words);
    let q = q_memory_records.iter().map(|r| r.value).collect::<Vec<_>>();

    rt.increment_clk();

    let (write_record, write_page_prot_records) = rt.mw_slice(p_ptr, num_words);

    if RT::TRACING {
        let (local_mem_access, local_page_prot_access) = rt.postprocess_precompile();

        let event = EllipticCurveAddEvent {
            clk,
            p_ptr,
            p,
            q_ptr,
            q,
            p_memory_records: write_record,
            q_memory_records,
            local_mem_access,
            page_prot_records: EllipticCurvePageProtRecords {
                read_page_prot_records: q_page_prot_records,
                write_page_prot_records,
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

        rt.add_precompile_event(syscall_code, syscall_event, PrecompileEvent::EdAdd(event));
    }

    None
}
