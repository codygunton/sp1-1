use crate::{SyscallCode, vm::syscall::SyscallRuntime, ExecutionError, Register};

pub(crate) fn sig_return<'a, RT: SyscallRuntime<'a>>(
    rt: &mut RT,
    _syscall_code: SyscallCode,
    addr: u64,
    _: u64,
) -> Result<Option<u64>, ExecutionError> {
    let _page_prot_records = rt.read_slice_check(addr, 32)?;

    let regs = rt.mr_slice_without_prot(addr, 32).iter().map(|r| r.value).collect::<Vec<_>>();

    rt.core_mut().set_next_pc(regs[0]);

    for (i, value) in regs.iter().enumerate().skip(1) {
        rt.core_mut().rw(Register::from_u8(i as u8), *value);
    }

    if RT::TRACING {
        todo!("tracing mode");
    }

    // SP1 forces updating of X5 with ecall result
    Ok(Some(regs[Register::X5 as usize]))
}
