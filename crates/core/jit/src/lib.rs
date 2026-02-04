#![cfg_attr(not(target_os = "linux"), allow(unused))]

#[cfg(not(target_endian = "little"))]
compile_error!("This crate is only supported on little endian targets.");

pub mod backends;
pub mod context;
pub mod debug;
pub mod instructions;
mod macros;
pub mod risc;

use crash_handler::{CrashContext, CrashEvent, CrashEventResult, CrashHandler};
use dynasmrt::ExecutableBuffer;
use hashbrown::HashMap;
use memmap2::{MmapMut, MmapOptions};
use sp1_primitives::consts::{LOG_PAGE_SIZE, PAGE_SIZE, PROT_EXEC, PROT_READ, PROT_WRITE};
use std::{
    collections::{BTreeMap, VecDeque},
    ptr::NonNull,
    sync::{mpsc, Arc, Mutex},
};

pub use backends::*;
pub use context::*;
pub use instructions::*;
pub use risc::*;

/// A function that accepts the memory pointer.
pub type ExternFn = extern "C" fn(*mut JitContext);

pub type EcallHandler = extern "C" fn(*mut JitContext) -> u64;

/// A debugging utility to inspect registers
pub type DebugFn = extern "C" fn(u64);

/// A transpiler for risc32 instructions.
///
/// This trait is implemented for each target architecture supported by the JIT transpiler.
///
/// The transpiler is responsible for translating the risc32 instructions into the target
/// architecture's instruction set.
///
/// This transpiler should generate an entrypoint of the form: [`fn(*mut JitContext)`]
///
/// For each instruction, you will typically want to call [`SP1RiscvTranspiler::start_instr`]
/// before transpiling the instruction. This maps a "riscv instruction index" to some physical
/// native address, as there are multiple native instructions per riscv instruction.
///
/// You will also likely want to call [`SP1RiscvTranspiler::bump_clk`] to increment the clock
/// counter, and [`SP1RiscvTranspiler::set_pc`] to set the PC.
///
/// # Note
/// Some instructions will directly modify the PC, such as [`SP1RiscvTranspiler::jal`] and
/// [`SP1RiscvTranspiler::jalr`], and all the branch instructions, for these instructions, you would
/// not want to call [`SP1RiscvTranspiler::set_pc`] as it will be called for you.
///
///
/// ```rust,no_run,ignore
/// pub fn add_program() {
///     let mut transpiler = SP1RiscvTranspiler::new(program_size, memory_size, trace_buf_size, 100, 100).unwrap();
///      
///     // Transpile the first instruction.
///     transpiler.start_instr();
///     transpiler.add(RiscOperand::Reg(RiscRegister::A), RiscOperand::Reg(RiscRegister::B), RiscRegister::C);
///     transpiler.end_instr();
///     
///     // Transpile the second instruction.
///     transpiler.start_instr();
///
///     transpiler.add(RiscOperand::Reg(RiscRegister::A), RiscOperand::Reg(RiscRegister::B), RiscRegister::C);
///     transpiler.end_instr();
///     
///     let mut func = transpiler.finalize();
///
///     // Call the function.
///     let traces = func.call();
///
///     // do stuff with the traces.
/// }
/// ```
pub trait RiscvTranspiler:
    TraceCollector
    + ComputeInstructions
    + ControlFlowInstructions
    + MemoryInstructions
    + SystemInstructions
    + Sized
{
    /// Create a new transpiler.
    ///
    /// The program is used for the jump-table and is not a hard limit on the size of the program.
    /// The max memory size is the exact amount that can be used by SP1 program
    fn new(
        program_size: usize,
        max_memory_size: usize,
        max_trace_size: u64,
        pc_base: u64,
        clk_bump: u64,
        enable_untrusted_program: bool,
    ) -> Result<Self, std::io::Error>;

    /// Register a rust function of the form [`EcallHandler`] that will be used as the ECALL.
    fn register_ecall_handler(&mut self, handler: EcallHandler);

    /// Populates a jump table entry for the current instruction being transpiled.
    ///
    /// Effectively should create a mapping from RISCV PC -> absolute address of the instruction.
    ///
    /// This method should be called for "each pc" in the program.
    fn start_instr(&mut self);

    /// This method should be called for "each pc" in the program.
    /// Handle logics when finishing execution of an instruction such as bumping clk and jump to
    /// branch destination.
    fn end_instr(&mut self);

    /// Inspcet a [RiscRegister] using a function pointer.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn inspect_register(&mut self, reg: RiscRegister, handler: DebugFn);

    /// Print an immediate value.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn inspect_immediate(&mut self, imm: u64, handler: DebugFn);

    /// Call an [ExternFn] from the outputted assembly.
    ///
    /// Implementors should ensure that [`RiscvTranspiler::start_instr`] is called before this.
    fn call_extern_fn(&mut self, handler: ExternFn);

    /// Returns the function pointer to the generated code.
    ///
    /// This function is expected to be of the form: `fn(*mut JitContext)`.
    fn finalize(self) -> JitRegion;
}

/// A trait the collects traces, in the form [TraceChunk].
///
/// This type is expected to follow the conventions as described in the [TraceChunk] documentation.
pub trait TraceCollector {
    /// Write the current state of the registers into the trace buf.
    ///
    /// For SP1 this is only called once in the beginning of a "chunk".
    fn trace_registers(&mut self);

    /// Write the value located at rs1 + imm into the trace buf.
    fn trace_mem_value(&mut self, rs1: RiscRegister, imm: u64, is_write: bool, clk_bump: i32);

    /// Write the start pc of the trace chunk.
    fn trace_pc_start(&mut self);

    /// Write the start clk of the trace chunk.
    fn trace_clk_start(&mut self);

    /// Write the end clk of the trace chunk.
    fn trace_clk_end(&mut self);
}

/// This is only needed since sp1-jit and sp1-core-executor are separated. sp1-jit
/// has no access to Instruction definition.
pub trait TranspilerRunner {
    fn transpile(&self, programs: &[u32], pc_base: u64) -> Result<JitRegion, std::io::Error>;
}

pub trait Debuggable {
    fn print_ctx(&mut self);
}

impl<T: RiscvTranspiler> Debuggable for T {
    // Useful only for debugging.
    fn print_ctx(&mut self) {
        extern "C" fn print_ctx(ctx: *mut JitContext) {
            let ctx = unsafe { &mut *ctx };
            eprintln!("pc: {:x}", ctx.pc);
            eprintln!("clk: {}", ctx.clk);
            eprintln!("{:?}", *ctx.registers());
        }

        self.call_extern_fn(print_ctx);
    }
}

#[cfg(not(target_os = "linux"))]
/// Stub implementation for non-linux targets to compile.
pub struct JitRegion {}

/// The JIT compiled structure for a memory region.
/// Multiple JIT regions form a JitFunction
#[cfg(target_os = "linux")]
pub struct JitRegion {
    pub(crate) pc_base: u64,
    pub(crate) jump_table: Vec<*const u8>,
    pub(crate) exit_label: *const u8,
    pub(crate) long_jump_label: *const u8,
    pub(crate) code: ExecutableBuffer,
}

#[cfg(target_os = "linux")]
impl JitRegion {
    pub fn new(
        code: ExecutableBuffer,
        jump_table: Vec<usize>,
        exit_label_offset: usize,
        long_jump_label_offset: usize,
        pc_base: u64,
    ) -> Self {
        // Adjust the jump table to be absolute addresses.
        let buf_ptr = code.as_ptr();
        let jump_table =
            jump_table.into_iter().map(|offset| unsafe { buf_ptr.add(offset) }).collect();
        let exit_label = unsafe { buf_ptr.add(exit_label_offset) };
        let long_jump_label = unsafe { buf_ptr.add(long_jump_label_offset) };

        Self { code, jump_table, exit_label, long_jump_label, pc_base }
    }

    #[inline]
    pub(crate) fn size(&self) -> u64 {
        self.jump_table.len() as u64 * 4
    }

    #[inline]
    pub(crate) fn pc_end(&self) -> u64 {
        self.pc_base + self.size()
    }

    pub(crate) fn intersect(&self, other_base: u64, other_end: u64) -> bool {
        let intersect_start = std::cmp::max(other_base, self.pc_base);
        let intersect_end = std::cmp::min(other_end, self.pc_end());

        self.pc_base != other_base && intersect_start < intersect_end
    }
}

/// A type representing a JIT compiled function.
///
/// The underlying function should be of the form [`fn(*mut JitContext)`].
#[cfg(target_os = "linux")]
pub struct JitFunction {
    regions: Vec<JitRegion>,

    trace_buf_size: usize,

    transpiler: Box<dyn TranspilerRunner>,

    /// The initial memory image.
    initial_memory_image: Arc<HashMap<u64, u64>>,
    /// The initial prot image
    initial_prot_image: BTreeMap<u64, u8>,
    pc_start: u64,
    input_buffer: VecDeque<Vec<u8>>,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// VM memory. This holds permission buffer(for untrusted programs), clocks, and
    /// actual memory values
    /// Keep around the memfd, and pass it to the JIT context,
    /// we can use this to create the COW memory at runtime.
    mem_fd: memfd::Memfd,
    mmap: MmapMut,

    /// During execution, the hints are read by the program, and we store them here.
    /// This is effectively a mapping from start address to the value of the hint.
    pub hints: Vec<(u64, Vec<u8>)>,

    /// The JIT function may stop "in the middle" of an program,
    /// we want to be able to resume it, so this is the information needed to do so.
    pub pc: u64,
    pub registers: [u64; 32],
    pub clk: u64,
    pub global_clk: u64,
    pub exit_code: u32,

    pub debug_sender: Option<mpsc::SyncSender<Option<debug::State>>>,

    pub(crate) elf_info: ElfInfo,
    pub(crate) buffered_mprotect_calls: BTreeMap<u64, PageProtValue>,
    pub(crate) max_memory_size: usize,
    pub(crate) memory_offset: usize,
}

unsafe impl Send for JitFunction {}

#[cfg(target_os = "linux")]
impl JitFunction {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initial_region: JitRegion,
        max_memory_size: usize,
        trace_buf_size: usize,
        pc_start: u64,
        elf_info: ElfInfo,
        transpiler: Box<dyn TranspilerRunner>,
        initial_memory_image: Arc<HashMap<u64, u64>>,
        initial_prot_image: BTreeMap<u64, u8>,
    ) -> std::io::Result<Self> {
        let fd = memfd::MemfdOptions::default()
            .create(uuid::Uuid::new_v4().to_string())
            .expect("Failed to create jit memory");

        let permission_size = if elf_info.enable_untrusted_program() {
            assert_eq!(max_memory_size % PAGE_SIZE, 0);
            let count = max_memory_size / PAGE_SIZE;
            let size = count * std::mem::size_of::<LazyPageProtValue>();
            size.div_ceil(PAGE_SIZE) * PAGE_SIZE
        } else {
            0
        };

        // The mmap-based memory consists of 3 parts:
        // * permissions(for untrusted programs), one LazyPageProtValue entry per memory page
        // * Clocks, one u64 value for each u64 memory entry, so the same size as memory
        // * Actual memory
        // Mmap-based memory should already be aligned to Linux's page size.
        let memory_size = max_memory_size * 2 + permission_size;
        let memory_offset = max_memory_size + permission_size;
        fd.as_file().set_len(memory_size as u64)?;

        // Signal handler will be cleared when current instance is dropped
        setup_handler();

        let mut result = Self {
            regions: vec![initial_region],
            mmap: unsafe { MmapOptions::new().no_reserve_swap().map_mut(fd.as_file())? },
            mem_fd: fd,
            trace_buf_size,
            pc: pc_start,
            clk: 1,
            global_clk: 0,
            registers: [0; 32],
            initial_memory_image,
            initial_prot_image,
            pc_start,
            input_buffer: VecDeque::new(),
            hints: Vec::new(),
            public_values_stream: Vec::new(),
            debug_sender: None,
            exit_code: 0,
            elf_info,
            buffered_mprotect_calls: BTreeMap::new(),
            max_memory_size,
            memory_offset,
            transpiler,
        };
        result.insert_memory_image();
        result.insert_prot_image();

        Ok(result)
    }

    unsafe fn permission_ptr(&self) -> *mut LazyPageProtValue {
        if self.elf_info.enable_untrusted_program() {
            self.mmap.as_ptr() as *mut _
        } else {
            std::ptr::null_mut()
        }
    }

    unsafe fn memory_ptr(&self) -> *mut u8 {
        self.mmap.as_ptr().add(self.memory_offset) as *mut _
    }

    pub(crate) fn remove_region(&mut self, pc_base: u64, pc_end: u64) {
        // Ideally only trusted memory can execute ecalls to remove regions,
        // there is no chance of accidentally removing current region.
        self.regions.retain(|region| {
            assert!(
                !region.intersect(pc_base, pc_end),
                "Removing part of a region is not supported!"
            );
            !(region.pc_base == pc_base && region.pc_end() == pc_end)
        });
    }

    pub(crate) fn insert_region(&mut self, pc_base: u64, pc_end: u64) {
        for region in &self.regions {
            assert!(
                !region.intersect(pc_base, pc_end),
                "Executable region overlaps with existing one!"
            );
            if region.pc_base == pc_base && region.pc_end() == pc_end {
                // Executable region already exists
                return;
            }
        }
        // In fact we are setting exec permissions by pages, meaning they will be
        // aligned by page.
        assert_eq!((pc_end - pc_base) % 4, 0, "Exec region must be aligned by 4");
        // SAFETY: we know the pointer is aligned, and the instructions will
        // only be used within current method.
        let instructions = unsafe {
            let p = self.memory_view().unsafe_memory().ptr(pc_base);
            std::slice::from_raw_parts(p as *const u32, ((pc_end - pc_base) / 4) as usize)
        };

        let region = self
            .transpiler
            .transpile(instructions, pc_base)
            .expect("Failed to JIT new executable code");
        self.regions.push(region);
        self.regions.sort_by_key(|region| region.pc_base);
    }

    #[inline]
    pub fn get_page_prot_record(&self, page_idx: u64) -> Option<PageProtValue> {
        if !self.elf_info.enable_untrusted_program() {
            return None;
        }
        // TODO: figure out bound-checking logic
        unsafe { self.permission_ptr().add(page_idx as usize).read_unaligned() }.into()
    }

    #[inline]
    pub fn set_page_prot_record(&mut self, page_idx: u64, value: &PageProtValue) {
        if !self.elf_info.enable_untrusted_program() {
            return;
        }
        // TODO: figure out bound-checking logic
        let lazy_value = value.into();
        unsafe {
            self.permission_ptr().add(page_idx as usize).write_unaligned(lazy_value);
        }
    }

    pub fn commit_buffered_prots(&mut self) {
        let merge_pages = |page_idx: u64, os_prot: i32, pages: &mut Vec<(u64, u64, i32)>| {
            let mut processed = false;
            if let Some(last) = pages.last_mut() {
                if last.0 + last.1 == page_idx && last.2 == os_prot {
                    last.1 += 1;
                    processed = true;
                }
            }
            if !processed {
                pages.push((page_idx, 1, os_prot));
            }
        };

        // (start page idx, pages, OS prot)
        let mut rw_regions: Vec<(u64, u64, i32)> = Vec::new();
        let mut new_exec_regions: Vec<(u64, u64, i32)> = Vec::new();
        let mut removed_exec_regions: Vec<(u64, u64, i32)> = Vec::new();

        while let Some((page_idx, prot)) = self.buffered_mprotect_calls.pop_first() {
            // Update page prot records
            let old_value = self.get_page_prot_record(page_idx).unwrap_or_default();
            self.set_page_prot_record(page_idx, &prot);

            let old_executable = old_value.value & PROT_EXEC != 0;
            let new_executable = prot.value & PROT_EXEC != 0;

            // Exec pages require us to JIT new code or removed previous JIT code
            if old_executable && (!new_executable) {
                merge_pages(page_idx, 0, &mut removed_exec_regions);
            }
            if (!old_executable) && new_executable {
                merge_pages(page_idx, 0, &mut new_exec_regions);
            }

            // Read / write permissions are set to virtual memory so MMU / OS
            // can help us enforce them.
            let mut os_prot = libc::PROT_NONE;
            if prot.value & PROT_READ != 0 {
                os_prot |= libc::PROT_READ;
            }
            if prot.value & PROT_WRITE != 0 {
                os_prot |= libc::PROT_WRITE;
            }
            merge_pages(page_idx, os_prot, &mut rw_regions);
        }

        for (start_page, pages, _) in removed_exec_regions {
            let address = start_page << LOG_PAGE_SIZE;
            let len = pages << LOG_PAGE_SIZE;

            self.remove_region(address, address + len);
        }
        for (start_page, pages, _) in new_exec_regions {
            let address = start_page << LOG_PAGE_SIZE;
            let len = pages << LOG_PAGE_SIZE;

            self.insert_region(address, address + len);
        }

        // Update read / write permissions to OS virtual memory.
        // Only the actual memory region is updated with permissions.
        // Permission / clock regions are always READ / WRITE
        for (start_page, pages, prot) in rw_regions {
            let address = start_page << LOG_PAGE_SIZE;
            let len = pages << LOG_PAGE_SIZE;

            let ptr = unsafe { self.memory_ptr() };

            assert_eq!(
                unsafe { libc::mprotect(ptr.add(address as usize) as *mut _, len as usize, prot,) },
                0
            )
        }
    }

    /// Return a `MemoryView` structure of current compiled function
    pub fn memory_view(&self) -> MemoryView<'_> {
        MemoryView::new(&self.mmap[self.memory_offset..], self.max_memory_size)
    }

    /// Push an input to the input buffer.
    ///
    /// # Panics
    ///
    /// Panics if the PC is not the starting PC.
    pub fn push_input(&mut self, input: Vec<u8>) {
        assert!(
            self.pc == self.pc_start,
            "The input buffer should only be supplied before using the JIT function."
        );

        self.input_buffer.push_back(input);

        self.hints.reserve(1);
    }

    /// Set the entire input buffer.
    ///
    /// # Panics
    ///
    /// Panics if the PC is not the starting PC.
    pub fn set_input_buffer(&mut self, input: VecDeque<Vec<u8>>) {
        assert!(
            self.pc == self.pc_start,
            "The input buffer should only be supplied before using the JIT function."
        );

        // Reserve the space for the hints.
        self.hints.reserve(input.len());
        self.input_buffer = input;
    }

    #[inline]
    pub const fn tracing(&self) -> bool {
        self.trace_buf_size > 0
    }

    /// Call the function, returning the trace buffer, starting at the starting PC of the program.
    ///
    /// If the PC is 0, then the program has completed and we return None.
    ///
    /// # SAFETY
    /// Relies on the builder to emit valid assembly
    /// and that the pointer is valid for the duration of the function call.
    pub unsafe fn call(&mut self) -> Option<TraceChunkRaw> {
        if self.pc == 1 {
            return None;
        }

        let (jump_table, exit_label, long_jump_label, as_fn, pc_base, pc_end) = {
            let region = self
                .regions
                .iter_mut()
                .find(|region| self.pc >= region.pc_base && self.pc < region.pc_end())
                .unwrap_or_else(|| panic!("Failed to find region for pc=0x{:x}", self.pc));
            (
                NonNull::new_unchecked(region.jump_table.as_mut_ptr()),
                region.exit_label,
                region.long_jump_label,
                std::mem::transmute::<*const u8, fn(*mut JitContext)>(region.code.as_ptr()),
                region.pc_base,
                region.pc_end(),
            )
        };

        // Ensure the pointer is aligned to the alignment of the MemValue.
        let mut trace_buf =
            MmapMut::map_anon(self.trace_buf_size + std::mem::align_of::<MemValue>())
                .expect("Failed to create trace buf mmap");
        let trace_buf_offset = trace_buf.as_ptr().align_offset(std::mem::align_of::<MemValue>());
        let trace_buf_ptr = trace_buf.as_mut_ptr().add(trace_buf_offset);

        // Mmap memory should already be aligned to page size
        let mem_ptr = self.memory_ptr();
        assert_eq!(mem_ptr as usize % PAGE_SIZE, 0);

        // We want to skip any hints that the previous chunk read.
        let start_hint_lens = self.hints.len();

        let permission = self.permission_ptr();
        let permission_count = if self.elf_info.enable_untrusted_program() {
            self.max_memory_size / PAGE_SIZE
        } else {
            0
        } as u64;

        // SAFETY:
        // - The jump table is valid for the duration of the function call, its owned by self.
        // - The memory is valid for the duration of the function call, its owned by self.
        // - The permission is valid for the duration of the function call, its owned by self.
        // - The trace buf is valid for the duration of the function call, we just allocated it`
        let mut ctx = JitContext {
            jump_table,
            exit_label,
            long_jump_label,
            pc_base,
            pc_end,
            memory: NonNull::new_unchecked(mem_ptr),
            trace_buf: NonNull::new_unchecked(trace_buf_ptr),
            maybe_unconstrained: None,
            registers: self.registers,
            pc: self.pc,
            clk: self.clk,
            global_clk: self.global_clk,
            is_unconstrained: 0,
            function: NonNull::new_unchecked(self as *mut JitFunction),
            permission,
            permission_count,
            memory_offset: self.memory_offset as u64,
            max_memory_size: self.max_memory_size as u64,
        };

        tracing::debug_span!("JIT function", pc = ctx.pc, clk = ctx.clk).in_scope(|| {
            as_fn(&mut ctx);
        });

        // Update the values we want to preserve.
        self.pc = ctx.pc;
        self.registers = ctx.registers;
        self.clk = ctx.clk;
        self.global_clk = ctx.global_clk;

        self.tracing().then_some(TraceChunkRaw::new(
            trace_buf.make_read_only().expect("Failed to make trace buf read only"),
            // For each chunk, we only want to include the hints that the previous chunk did not
            // read. We also include any unread hints just in case we stopped in
            // between a hint_len and hint_read.
            self.hints
                .iter()
                .skip(start_hint_lens)
                .map(|(_, hint)| hint.len())
                .chain(self.input_buffer.iter().map(|input| input.len()))
                .collect(),
        ))
    }

    /// Reset the JIT function to the initial state.
    ///
    /// This will clear the registers, the program counter, the clock, and the memory, restoring the
    /// initial memory image.
    pub fn reset(&mut self) {
        self.pc = self.pc_start;
        self.registers = [0; 32];
        self.clk = 1;
        self.global_clk = 0;
        self.input_buffer = VecDeque::new();
        self.hints = Vec::new();
        self.public_values_stream = Vec::new();

        // Store the original size of the memory.
        let memory_size = self.mmap.len();

        // Create a new memfd for the backing memory.
        self.mem_fd = memfd::MemfdOptions::default()
            .create(uuid::Uuid::new_v4().to_string())
            .expect("Failed to create jit memory");

        self.mem_fd
            .as_file()
            .set_len(memory_size as u64)
            .expect("Failed to set memfd size for backing memory.");

        self.mmap = unsafe {
            MmapOptions::new()
                .no_reserve_swap()
                .map_mut(self.mem_fd.as_file())
                .expect("Failed to map memory")
        };

        self.insert_memory_image();
        self.insert_prot_image();
    }

    fn insert_memory_image(&mut self) {
        let memory = self.memory_view().unsafe_memory();

        for (addr, val) in self.initial_memory_image.iter() {
            #[cfg(debug_assertions)]
            if addr % 8 > 0 {
                panic!("Address {addr} is not aligned to 8");
            }

            unsafe {
                memory.set_slice_values(*addr, &[*val]);
            }
        }
    }

    fn insert_prot_image(&mut self) {
        for (page_idx, mut prot) in self.initial_prot_image.clone().into_iter() {
            let addr = page_idx << LOG_PAGE_SIZE;
            // Trusted instructions should already be JIT when creating JitFunction,
            // we can skip them.
            if prot & PROT_EXEC != 0
                && !(self
                    .elf_info
                    .untrusted_memory
                    .map(|(s, e)| addr >= s && addr < e)
                    .unwrap_or(false))
            {
                prot &= !PROT_EXEC;
            }
            self.buffered_mprotect_calls
                .insert(page_idx, PageProtValue { timestamp: 0, value: prot });
        }
        self.commit_buffered_prots();
    }
}

impl Drop for JitFunction {
    fn drop(&mut self) {
        clear_handler();
    }
}

pub struct MemoryView<'a> {
    memory: &'a [u8],
    max_memory_size: usize,
}

impl<'a> MemoryView<'a> {
    const fn new(memory: &'a [u8], max_memory_size: usize) -> Self {
        Self { memory, max_memory_size }
    }

    #[inline]
    pub fn unsafe_memory(&self) -> UnsafeMemory {
        UnsafeMemory {
            ptr: unsafe { NonNull::new_unchecked(self.memory.as_ptr() as *mut _) },
            max_memory_size: self.max_memory_size,
        }
    }

    /// Read a word from the memory at the address.
    ///
    /// # Panics
    ///
    /// Panics if the address is not aligned to 8 bytes.
    pub fn get(&self, addr: u64) -> MemValue {
        assert!(addr.is_multiple_of(8), "Address {addr} is not aligned to 8");

        // Implement get using UnsafeMemory so we don't need to
        // maintain the same logic twice. In the unlikely event that this
        // really becomes a performance bottleneck, we can re-implement the code.
        unsafe { self.unsafe_memory().get(addr) }
    }
}

/// An unsafe memory view
///
/// This allows reading without lifetime and mutability constraints.
pub struct UnsafeMemory {
    pub(crate) ptr: NonNull<u8>,
    pub(crate) max_memory_size: usize,
}

unsafe impl Send for UnsafeMemory {}
unsafe impl Sync for UnsafeMemory {}

impl UnsafeMemory {
    /// Get a value from the memory.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    #[must_use]
    pub unsafe fn get(&self, addr: u64) -> MemValue {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);
        let clk_ptr = value_ptr.sub(self.max_memory_size);

        MemValue {
            clk: std::ptr::read(clk_ptr as *const u64),
            value: std::ptr::read(value_ptr as *const u64),
        }
    }

    pub(crate) unsafe fn ptr(&self, addr: u64) -> *const u8 {
        self.ptr.as_ptr().add(addr as usize)
    }

    /// Set a MemValue to the memory.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    pub(crate) unsafe fn set(&self, addr: u64, value: &MemValue) {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);
        let clk_ptr = value_ptr.sub(self.max_memory_size);

        std::ptr::write(value_ptr as *mut u64, value.value);
        std::ptr::write(clk_ptr as *mut u64, value.clk);
    }

    /// Set clock for a slice of values.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    pub(crate) unsafe fn set_slice_clks(&self, addr: u64, len: usize, clk: u64) {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);
        let clk_ptr = value_ptr.sub(self.max_memory_size);

        for i in 0..len {
            std::ptr::write(clk_ptr.add(i * 8) as *mut u64, clk);
        }
    }

    /// Set a slice of values.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    pub(crate) unsafe fn set_slice_values(&self, addr: u64, vals: &[u64]) {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);

        for (i, val) in vals.iter().enumerate() {
            std::ptr::write(value_ptr.add(i * 8) as *mut u64, *val);
        }
    }

    /// Fetches a slice of memory value.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    /// Static lifetime is used so the generated slice has different lifetime from self,
    /// It is caller's reponsibility to ensure that the value slice is used properly
    pub(crate) unsafe fn value_slice(&self, addr: u64, len: usize) -> &'static [u64] {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);
        std::slice::from_raw_parts(value_ptr as *const u64, len)
    }

    /// Fetches a slice of memory clocks.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    /// Static lifetime is used so the generated slice has different lifetime from self,
    /// It is caller's reponsibility to ensure that the clk slice is used properly
    pub(crate) unsafe fn clk_slice(&self, addr: u64, len: usize) -> &'static [u64] {
        let value_ptr = self.ptr.as_ptr().add(addr as usize);
        let clk_ptr = value_ptr.sub(self.max_memory_size);

        std::slice::from_raw_parts(clk_ptr as *const u64, len)
    }

    /// Fetches a vector of MemValues.
    ///
    /// # Safety
    /// As the function strictly breaks the lifetime rules, it is unsafe and should only be used
    /// under strict guarantees that the memory is not being dropped or the same address being
    /// accessed is being modified.
    pub(crate) unsafe fn mem_values(&self, addr: u64, len: usize) -> Vec<MemValue> {
        self.value_slice(addr, len)
            .iter()
            .zip(self.clk_slice(addr, len))
            .map(|(value, clk)| MemValue { value: *value, clk: *clk })
            .collect()
    }

    /// Set a byte in the memory
    ///
    /// # Safety
    /// This function breaks both lifetime rule and mutability constraint. It is unsafe, and the
    /// caller should be responsible to ensure it is safe to call.
    #[cfg(test)]
    pub(crate) unsafe fn set_byte(&self, addr: u64, val: u8) {
        let entry_ptr = self.ptr.as_ptr();
        entry_ptr.add(addr as usize).write(val);
    }
}

/// A RISC-V interrupt, right now we are only doing trap with this
/// structure but it might be expanded later.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interrupt {
    /// Trap code
    pub code: u64,
}

// Linux signal handler to recover from SIGSEGV, which indicates a
// memory permission violation
struct SignalHandler;

unsafe impl CrashEvent for SignalHandler {
    fn on_crash(&self, _context: &CrashContext) -> CrashEventResult {
        CrashEventResult::Handled(false)
    }
}

struct SignalState {
    count: usize,
    handler: Option<CrashHandler>,
}

static SIGNAL_HANDLER_STATE: Mutex<SignalState> =
    Mutex::new(SignalState { count: 0, handler: None });

fn setup_handler() {
    let mut state = SIGNAL_HANDLER_STATE.lock().expect("lock");

    if state.count == 0 {
        state.handler =
            Some(CrashHandler::attach(Box::new(SignalHandler {})).expect("create handler"));
    }
    state.count += 1;
}

fn clear_handler() {
    let mut state = SIGNAL_HANDLER_STATE.lock().expect("lock");

    state.count -= 1;
    if state.count == 0 {
        state.handler = None;
    }
}
