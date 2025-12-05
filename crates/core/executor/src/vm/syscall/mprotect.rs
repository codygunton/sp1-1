use crate::{
    events::{MProtectEvent, PrecompileEvent},
    memory::MAX_LOG_ADDR,
    SyscallCode,
    vm::syscall::SyscallRuntime,
};

use sp1_primitives::consts::PAGE_SIZE;

pub(crate) fn mprotect<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    syscall_code: SyscallCode,
    addr: u64,
    prot: u64,
) -> Option<u64> {
    let prot: u8 = prot.try_into().expect("prot must be 8 bits");

    assert!(addr.is_multiple_of(PAGE_SIZE as u64), "addr must be page aligned");
    assert!(addr < 1 << MAX_LOG_ADDR, "addr must be less than 2^48");

    let page_idx = addr / PAGE_SIZE as u64;

    rt.page_prot_write(page_idx, prot);

    if RT::TRACING {
        let clk = rt.core().clk();
        let (_, local_page_prot_access) = rt.postprocess_precompile();
        let mprotect_event = MProtectEvent { addr, local_page_prot_access };

        let syscall_event = rt.syscall_event(
            clk,
            syscall_code,
            addr,
            prot as u64,
            false,
            rt.core().next_pc(),
            rt.core().exit_code(),
        );

        rt.add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::Mprotect(mprotect_event),
        );
    }

    None
}
