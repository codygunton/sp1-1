use sp1_jit::{Interrupt, RiscRegister, SyscallContext};

pub fn sig_return_syscall(
    ctx: &mut impl SyscallContext,
    addr: u64,
    _: u64,
) -> Result<Option<u64>, Interrupt> {
    ctx.read_slice_check(addr, 32)?;

    let regs: Vec<_> = ctx.mr_slice_without_prot(addr, 32).into_iter().map(|v| *v).collect();

    ctx.set_next_pc(regs[0]);

    for (reg, value) in RiscRegister::all_registers().into_iter().zip(regs.iter()).skip(1) {
        ctx.rw(*reg, *value);
    }

    // SP1 forces updating of X5 with ecall result
    Ok(Some(regs[RiscRegister::X5 as usize]))
}
