use crate::{
    debug, ElfInfo, Interrupt, JitFunction, LazyPageProtValue, MemValue, PageProtValue,
    RiscRegister, TraceChunkHeader, UnsafeMemory,
};
use memmap2::{MmapMut, MmapOptions};
use sp1_primitives::consts::{
    LOG_PAGE_SIZE, PAGE_SIZE, PROT_EXEC, PROT_FAILURE_EXEC, PROT_FAILURE_READ, PROT_FAILURE_WRITE,
    PROT_READ, PROT_WRITE,
};
use std::{collections::VecDeque, io, ptr::NonNull, sync::mpsc};

pub trait SyscallContext {
    /// Read a value from a register.
    fn rr(&self, reg: RiscRegister) -> u64;
    /// Write a value to a register
    fn rw(&mut self, reg: RiscRegister, value: u64);
    /// Write next pc
    fn set_next_pc(&mut self, pc: u64);
    /// Read a value from memory.
    fn mr_without_prot(&mut self, addr: u64) -> u64;
    /// Write a value to memory.
    fn mw_without_prot(&mut self, addr: u64, val: u64);
    /// Read a slice of values from memory.
    fn mr_slice(
        &mut self,
        addr: u64,
        len: usize,
    ) -> Result<impl IntoIterator<Item = &u64>, Interrupt> {
        self.prot_slice_check(addr, len, PROT_READ)?;
        Ok(self.mr_slice_without_prot(addr, len))
    }
    /// Read a slice of values from memory, without checking page permissions
    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Read a slice of values from memory, without updating the memory clock
    /// Note that it still traces the access when tracing is enabled.
    fn mr_slice_unsafe(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Read a slice of values from memory, without updating the memory clock or tracing the access.
    fn mr_slice_no_trace(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64>;
    /// Write a slice of values to memory.
    fn mw_slice(&mut self, addr: u64, vals: &[u64]) -> Result<(), Interrupt> {
        self.prot_slice_check(addr, vals.len(), PROT_WRITE)?;
        self.mw_slice_without_prot(addr, vals);
        Ok(())
    }
    /// Write a slice of values to memory, without checking page permissions
    fn mw_slice_without_prot(&mut self, addr: u64, vals: &[u64]);
    #[inline]
    fn read_slice_check(&mut self, addr: u64, len: usize) -> Result<(), Interrupt> {
        self.prot_slice_check(addr, len, PROT_READ)
    }
    #[inline]
    fn write_slice_check(&mut self, addr: u64, len: usize) -> Result<(), Interrupt> {
        self.prot_slice_check(addr, len, PROT_WRITE)
    }
    #[inline]
    fn read_write_slice_check(&mut self, addr: u64, len: usize) -> Result<(), Interrupt> {
        self.prot_slice_check(addr, len, PROT_READ | PROT_WRITE)
    }
    fn prot_slice_check(&mut self, addr: u64, len: usize, prot_bitmap: u8)
        -> Result<(), Interrupt>;
    fn page_prot_write(&mut self, addr: u64, val: u8);
    /// Flush all page prot writes, by default this is a no-op. It will be used
    /// in native executor to buffer permission changes so we can issue a number
    /// of them in one single OS-level syscall.
    fn page_prot_flush(&mut self) {}
    /// Get the input buffer
    fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>>;
    /// Get the public values stream.
    fn public_values_stream(&mut self) -> &mut Vec<u8>;
    /// Enter the unconstrained context.
    fn enter_unconstrained(&mut self) -> io::Result<()>;
    /// Exit the unconstrained context.
    fn exit_unconstrained(&mut self);
    /// Trace a hint.
    fn trace_hint(&mut self, addr: u64, value: Vec<u8>);
    /// Write a hint to memory, which is like setting uninitialized memory to a nonzero value
    /// The clk will be set to 0, just like for uninitialized memory.
    fn mw_hint(&mut self, addr: u64, val: u64);
    /// Used for precompiles that access memory, that need to bump the clk.
    /// This increment is local to the precompile, and does not affect the number of cycles
    /// the precompile itself takes up.
    fn bump_memory_clk(&mut self);
    fn get_current_clk(&self) -> u64;
    fn set_clk(&mut self, clk: u64);
    /// Set the exit code of the program.
    fn set_exit_code(&mut self, exit_code: u32);
    /// Returns if were in unconstrained mode.
    fn is_unconstrained(&self) -> bool;
    /// Get the global clock (total cycles executed).
    fn global_clk(&self) -> u64;

    /// Start tracking cycles for a label (profiling only).
    /// Records the current `global_clk` as the start time.
    /// Returns the nesting depth (0 for top-level, 1 for first nested, etc.).
    #[cfg(feature = "profiling")]
    fn cycle_tracker_start(&mut self, name: &str) -> u32;

    /// End tracking cycles for a label (profiling only).
    /// Returns (cycles_elapsed, depth) or None if no matching start.
    #[cfg(feature = "profiling")]
    fn cycle_tracker_end(&mut self, name: &str) -> Option<(u64, u32)>;

    /// End tracking cycles for a label and accumulate to report totals (profiling only).
    /// This is for "report" variants that should be included in ExecutionReport.
    /// Returns (cycles_elapsed, depth) or None if no matching start.
    #[cfg(feature = "profiling")]
    fn cycle_tracker_report_end(&mut self, name: &str) -> Option<(u64, u32)>;

    /// Fetch loaded ELF information
    fn elf_info(&self) -> ElfInfo;
    /// Iterate throgh all initialized addresses
    fn init_addr_iter(&self) -> impl IntoIterator<Item = u64>;
    /// Iterate throgh all non-default page permissions
    fn page_prot_iter(&self) -> impl IntoIterator<Item = (&u64, &PageProtValue)>;
    /// Dump all profiler data for dump-elf / bootloader use. This includes:
    /// * All known function symbols, including parsed symbols from ELF, and
    ///   dynamically added ones.
    /// * Current profiler stack.
    fn maybe_dump_profiler_data(&self) -> (Vec<(String, u64, u64)>, Vec<u64>);
    /// Insert function symbols in profiler mode
    fn maybe_insert_profiler_symbols<I: Iterator<Item = (String, u64, u64)>>(&mut self, iter: I);
    /// Delete function symbols in profiler mode
    fn maybe_delete_profiler_symbols<I: Iterator<Item = u64>>(&mut self, iter: I);
}

impl SyscallContext for JitContext {
    #[inline]
    fn bump_memory_clk(&mut self) {
        self.clk += 1;
    }

    #[inline]
    fn get_current_clk(&self) -> u64 {
        self.clk
    }

    #[inline]
    fn set_clk(&mut self, clk: u64) {
        self.clk = clk;
    }

    fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    fn rw(&mut self, _reg: RiscRegister, _value: u64) {
        unimplemented!()
    }

    fn set_next_pc(&mut self, _pc: u64) {
        unimplemented!()
    }

    fn mr_without_prot(&mut self, addr: u64) -> u64 {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();
        let entry = unsafe { memory.get(addr) };

        if self.tracing() {
            unsafe {
                self.trace_mem_access(&[entry]);

                // Bump the clk
                let new_entry = MemValue { value: entry.value, clk: self.clk };
                memory.set(addr, &new_entry);
            }
        }

        entry.value
    }

    fn mw_without_prot(&mut self, addr: u64, val: u64) {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();

        // Bump the clk and insert the new value.
        let value = MemValue { value: val, clk: self.clk };

        // Trace the current entry.
        if self.tracing() {
            unsafe {
                // Trace the current entry, the clock is bumped in the subsequent write.
                let current_entry = memory.get(addr);
                self.trace_mem_access(&[current_entry, value]);
            }
        }

        // SAFETY: The pointer is valid to write to, as it was aligned by us during allocation.
        // See [JitFunction::new] for more details.
        unsafe { memory.set(addr, &value) };
    }

    fn mr_slice_without_prot(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();

        if self.tracing() {
            unsafe {
                self.trace_mem_access(&memory.mem_values(addr, len));

                // Bump the clk on the all current entries.
                memory.set_slice_clks(addr, len, self.clk);
            }
        }

        unsafe { memory.value_slice(addr, len) }
    }

    fn mr_slice_no_trace(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();
        unsafe { memory.value_slice(addr, len) }
    }

    fn mr_slice_unsafe(&mut self, addr: u64, len: usize) -> impl IntoIterator<Item = &u64> {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();

        if self.tracing() {
            unsafe {
                self.trace_mem_access(&memory.mem_values(addr, len));
            }
        }

        unsafe { memory.value_slice(addr, len) }
    }

    fn mw_slice_without_prot(&mut self, addr: u64, vals: &[u64]) {
        // unsafe { ContextMemory::new(self).mw_slice(addr, vals) };
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        let memory = self.unsafe_memory();

        // Trace the current entries.
        if self.tracing() {
            unsafe {
                let current_entries = memory.mem_values(addr, vals.len());
                for (curr, new_value) in current_entries.iter().zip(vals.iter()) {
                    self.trace_mem_access(&[*curr, MemValue { value: *new_value, clk: self.clk }]);
                }
            }
        }

        // Bump the clk and insert the new values.
        unsafe {
            memory.set_slice_clks(addr, vals.len(), self.clk);
            memory.set_slice_values(addr, vals);
        }
    }

    fn page_prot_write(&mut self, addr: u64, val: u8) {
        assert!(addr.is_multiple_of(PAGE_SIZE as u64), "addr must be page aligned");
        assert!(
            addr < self.function().max_memory_size as u64,
            "addr must be less than maximum possible value"
        );
        assert!(
            self.function().elf_info.untrusted_memory.is_some_and(|(s, e)| addr >= s && addr < e),
            "untrusted mode must be turned on, the requested page must be in untrusted memory region",
        );

        let page_idx = addr >> LOG_PAGE_SIZE;

        if self.tracing() && (!self.is_unconstrained()) {
            // Buffered page prot value takes precedence
            let page_prot_value = self
                .function()
                .buffered_mprotect_calls
                .get(&page_idx)
                .cloned()
                .or_else(|| self.function_mut().get_page_prot_record(page_idx))
                .unwrap_or_default();
            unsafe {
                self.trace_mem_access(&[page_prot_value.into()]);
            }
        }

        let value = PageProtValue { timestamp: self.clk, value: val };
        self.function_mut().buffered_mprotect_calls.insert(page_idx, value);
    }

    #[inline]
    fn page_prot_flush(&mut self) {
        self.function_mut().commit_buffered_prots()
    }

    fn prot_slice_check(
        &mut self,
        addr: u64,
        len: usize,
        prot_bitmap: u8,
    ) -> Result<(), Interrupt> {
        // While instruction level load / store relies on CPU's MMU & OS for
        // permission checking, this still needs implementation for precompiles.
        if !self.function().elf_info.enable_untrusted_program() {
            return Ok(());
        }

        let first_page_idx = addr >> LOG_PAGE_SIZE;
        let last_page_idx = (addr + (len - 1) as u64 * 8) >> LOG_PAGE_SIZE;

        for page_idx in first_page_idx..=last_page_idx {
            let mut page_prot_value =
                self.function_mut().get_page_prot_record(page_idx).unwrap_or_default();
            if self.tracing() && (!self.is_unconstrained()) {
                unsafe {
                    self.trace_mem_access(&[page_prot_value.into()]);
                }
            }

            // This is only fired from precompiles, there is no need to adjust
            // MemoryAccessPosition.
            page_prot_value.timestamp = self.clk;
            self.function_mut().set_page_prot_record(page_idx, &page_prot_value);

            // Check permissions
            if (prot_bitmap & PROT_EXEC) != 0 && (page_prot_value.value & PROT_EXEC) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_EXEC });
            }
            if (prot_bitmap & PROT_READ) != 0 && (page_prot_value.value & PROT_READ) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_READ });
            }
            if (prot_bitmap & PROT_WRITE) != 0 && (page_prot_value.value & PROT_WRITE) == 0 {
                return Err(Interrupt { code: PROT_FAILURE_WRITE });
            }
        }
        Ok(())
    }

    fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>> {
        unsafe { self.input_buffer() }
    }

    fn public_values_stream(&mut self) -> &mut Vec<u8> {
        unsafe { self.public_values_stream() }
    }

    fn enter_unconstrained(&mut self) -> io::Result<()> {
        self.enter_unconstrained()
    }

    fn exit_unconstrained(&mut self) {
        self.exit_unconstrained()
    }

    fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        if self.tracing() {
            unsafe { self.trace_hint(addr, value) };
        }
    }

    fn mw_hint(&mut self, addr: u64, val: u64) {
        let new_entry = MemValue { value: val, clk: 0 };
        unsafe { self.unsafe_memory().set(addr, &new_entry) };
    }

    fn set_exit_code(&mut self, exit_code: u32) {
        unsafe { self.function.as_mut() }.exit_code = exit_code;
    }

    fn is_unconstrained(&self) -> bool {
        self.is_unconstrained == 1
    }

    fn global_clk(&self) -> u64 {
        self.global_clk
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_start(&mut self, _name: &str) -> u32 {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        0
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_end(&mut self, _name: &str) -> Option<(u64, u32)> {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        None
    }

    #[cfg(feature = "profiling")]
    fn cycle_tracker_report_end(&mut self, _name: &str) -> Option<(u64, u32)> {
        // JitContext is not used when profiling is enabled (portable executor is used instead).
        // This is a no-op implementation for trait completeness.
        None
    }

    fn elf_info(&self) -> ElfInfo {
        unimplemented!()
    }

    fn init_addr_iter(&self) -> impl IntoIterator<Item = u64> {
        Vec::new()
    }

    fn page_prot_iter(&self) -> impl IntoIterator<Item = (&u64, &PageProtValue)> {
        Vec::new()
    }

    fn maybe_dump_profiler_data(&self) -> (Vec<(String, u64, u64)>, Vec<u64>) {
        unimplemented!()
    }

    fn maybe_insert_profiler_symbols<I: Iterator<Item = (String, u64, u64)>>(&mut self, _iter: I) {
        unimplemented!()
    }

    fn maybe_delete_profiler_symbols<I: Iterator<Item = u64>>(&mut self, _iter: I) {
        unimplemented!()
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct JitContext {
    /// The current program counter
    pub pc: u64,
    /// The number of cycles executed.
    pub clk: u64,
    /// The number of cycles executed.
    pub global_clk: u64,
    /// This context is in unconstrainted mode.
    /// 1 if unconstrained, 0 otherwise.
    pub is_unconstrained: u64,
    /// The pointer to the program memory.
    pub(crate) memory: NonNull<u8>,
    /// The pointer to the trace buffer.
    pub(crate) trace_buf: NonNull<u8>,
    /// The registers to start the execution with,
    /// these are loaded into real native registers at the start of execution.
    pub(crate) registers: [u64; 32],
    /// The unconstrained context, this is used to create the COW memory at runtime.
    pub(crate) maybe_unconstrained: Option<UnconstrainedCtx>,
    /// A reference to the JIT function being executed, so we can retrieve
    /// necessary data.
    pub(crate) function: NonNull<JitFunction>,
    /// Cached permission table, this is used by tracing & precompiles. Instruction-level
    /// permission checking is enforced by CPU's MMU w/ OS.
    pub(crate) permission: *mut LazyPageProtValue,
    /// Count of permission entries
    pub(crate) permission_count: u64,
    /// Memory start offset in the mmap
    pub(crate) memory_offset: u64,
    /// Maximum memory size, can be used to calculate clock address from memory address
    pub(crate) max_memory_size: u64,

    // The following data are tied to a specific JitRegion, when JitRegion is
    // swapped, they should be changed.
    /// Mapping from (pc - pc_base) / 4 => absolute address of the instruction.
    pub(crate) jump_table: NonNull<*const u8>,
    /// Exit label address
    pub(crate) exit_label: *const u8,
    /// Long jump label address
    pub(crate) long_jump_label: *const u8,
    /// PC base
    pub(crate) pc_base: u64,
    /// PC end
    pub(crate) pc_end: u64,
}

impl JitContext {
    /// # Safety
    /// - todo
    pub unsafe fn trace_mem_access(&self, reads: &[MemValue]) {
        // QUESTIONABLE: I think as long as Self is not `Sync` youre mostly fine, but its unclear,
        // how to actually call this method safe without taking a `&mut self`.

        // Read the current num reads from the trace buf.
        let raw = self.trace_buf.as_ptr();
        let num_reads_offset = std::mem::offset_of!(TraceChunkHeader, num_mem_reads);
        let num_reads_ptr = raw.add(num_reads_offset);
        let num_reads = std::ptr::read_unaligned(num_reads_ptr as *mut u64);

        // Write the new num reads to the trace buf.
        let new_num_reads = num_reads + reads.len() as u64;
        std::ptr::write_unaligned(num_reads_ptr as *mut u64, new_num_reads);

        // Write the new reads to the trace buf.
        let reads_start = std::mem::size_of::<TraceChunkHeader>();
        let tail_ptr = raw.add(reads_start) as *mut MemValue;
        let tail_ptr = tail_ptr.add(num_reads as usize);

        for (i, read) in reads.iter().enumerate() {
            std::ptr::write(tail_ptr.add(i), *read);
        }
    }

    /// Enter the unconstrained context, this will create a COW memory map of the memory file
    /// descriptor.
    pub fn enter_unconstrained(&mut self) -> io::Result<()> {
        // SAFETY: The memory is allocated by the [JitFunction] and is valid, not aliased, and has
        // enough space for the alignment.
        let mut cow_memory = unsafe {
            MmapOptions::new().no_reserve_swap().map_copy(&self.function.as_ref().mem_fd)?
        };
        let cow_memory_ptr = cow_memory.as_mut_ptr();

        // Mmap memory will be aligned to pages, so there is no need to adjust for alignment.
        let cow_memory_ptr = unsafe { cow_memory_ptr.add(self.memory_offset as usize) };

        // Preserve the current state of the JIT context.
        self.maybe_unconstrained = Some(UnconstrainedCtx {
            cow_memory,
            actual_memory_ptr: self.memory,
            pc: self.pc,
            clk: self.clk,
            global_clk: self.global_clk,
            registers: self.registers,
        });

        // Bump the PC to the next instruction.
        self.pc = self.pc.wrapping_add(4);

        // Set the memory pointer used by the JIT as the COW memory.
        //
        // SAFETY: [memmap2] does not return a null pointer.
        self.memory = unsafe { NonNull::new_unchecked(cow_memory_ptr) };

        // Set the is_unconstrained flag to 1.
        self.is_unconstrained = 1;

        Ok(())
    }

    /// Exit the unconstrained context, this will restore the original memory map.
    pub fn exit_unconstrained(&mut self) {
        let unconstrained = std::mem::take(&mut self.maybe_unconstrained)
            .expect("Exit unconstrained called but not context is present, this is a bug.");

        self.memory = unconstrained.actual_memory_ptr;
        self.pc = unconstrained.pc;
        self.registers = unconstrained.registers;
        self.clk = unconstrained.clk;
        self.is_unconstrained = 0;
    }

    /// Indicate that the program has read a hint.
    ///
    /// This is used to store the hints read by the program.
    ///
    /// # Safety
    /// - The address must be aligned to 8 bytes.
    /// - The hints pointer must not be mutably aliased.
    pub unsafe fn trace_hint(&mut self, addr: u64, value: Vec<u8>) {
        debug_assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");
        self.function_mut().hints.push((addr, value));
    }

    /// # Safety
    /// - The input buffer must be non null and valid to read from.
    pub const unsafe fn input_buffer(&mut self) -> &mut VecDeque<Vec<u8>> {
        &mut self.function_mut().input_buffer
    }

    /// # Safety
    /// - The public values stream must be non null and valid to read from.
    pub const unsafe fn public_values_stream(&mut self) -> &mut Vec<u8> {
        &mut self.function_mut().public_values_stream
    }

    /// Obtain a view of the registers.
    pub const fn registers(&self) -> &[u64; 32] {
        &self.registers
    }

    pub const fn rw(&mut self, reg: RiscRegister, val: u64) {
        self.registers[reg as usize] = val;
    }

    pub const fn rr(&self, reg: RiscRegister) -> u64 {
        self.registers[reg as usize]
    }

    #[inline]
    pub const fn function(&self) -> &JitFunction {
        unsafe { self.function.as_ref() }
    }

    #[inline]
    pub const fn function_mut(&mut self) -> &mut JitFunction {
        unsafe { self.function.as_mut() }
    }

    #[inline]
    pub const fn tracing(&self) -> bool {
        self.function().tracing()
    }

    #[inline]
    pub fn debug_sender(&self) -> Option<&mpsc::SyncSender<Option<debug::State>>> {
        self.function().debug_sender.as_ref()
    }

    #[inline]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        UnsafeMemory { ptr: self.memory, max_memory_size: self.max_memory_size as usize }
    }
}

/// The saved context of the JIT runtime, when entering the unconstrained context.
#[derive(Debug)]
pub struct UnconstrainedCtx {
    // An COW version of the memory.
    pub cow_memory: MmapMut,
    // The pointer to the actual memory.
    pub actual_memory_ptr: NonNull<u8>,
    // The program counter.
    pub pc: u64,
    // The clock.
    pub clk: u64,
    // The clock.
    pub global_clk: u64,
    // The registers.
    pub registers: [u64; 32],
}
