#![allow(clippy::fn_to_numeric_cast)]

use crate::{
    EcallHandler, JitContext, RiscOperand, RiscRegister, RiscvTranspiler, TraceChunkHeader,
    TraceCollector,
};
use dynasmrt::{
    dynasm,
    x64::{Assembler, Rq},
    DynasmApi, DynasmLabelApi,
};
use sp1_primitives::consts::{DEFAULT_PAGE_PROT, LOG_PAGE_SIZE};
use std::{
    mem::offset_of,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};

mod instruction_impl;
#[cfg(test)]
mod tests;
mod transpiler;

// In addition to TEMP_A and TEMP_A, rax is also a free scratch register.

/// The first scratch register.
///
/// Callee-saved register.
const TEMP_A: u8 = Rq::RBX as u8;

/// The second scratch register.
///
/// Callee-saved register.
const TEMP_B: u8 = Rq::RBP as u8;

/// The JitContext pointer.
///
/// Callee-saved register.
const CONTEXT: u8 = Rq::R12 as u8;

/// The jump table pointer.
///
/// Callee-saved register.
const JUMP_TABLE: u8 = Rq::R13 as u8;

/// The trace buffer pointer.
///
/// Callee-saved register.
const TRACE_BUF: u8 = Rq::R14 as u8;

/// The saved stack pointer, used during external function calls.
///
/// Callee-saved register.
const SAVED_STACK_PTR: u8 = Rq::R15 as u8;

/// The offset of the pc in the JitContext.
const PC_OFFSET: i32 = offset_of!(JitContext, pc) as i32;

/// The offset of the clk in the JitContext.
const CLK_OFFSET: i32 = offset_of!(JitContext, clk) as i32;

/// The offset of the memory pointer in the JitContext.
const MEMORY_PTR_OFFSET: i32 = offset_of!(JitContext, memory) as i32;

/// The offset of the registers in the JitContext.
const REGISTERS_OFFSET: i32 = offset_of!(JitContext, registers) as i32;

/// The x86 backend for JIT transpipling RISC-V instructions to x86-64, according to the
/// [crate::SP1RiscvTranspiler] trait.
pub struct TranspilerBackend {
    inner: Assembler,
    /// A mapping of pc - pc_base => offset in the code buffer.
    jump_table: Vec<usize>,
    /// The size of the max memory for SP1 program.
    max_memory_size: usize,
    /// The maximum trace size.
    max_trace_size: u64,
    /// Has at least one instruction been inserted.
    has_instructions: bool,
    /// The pc base.
    pc_base: u64,
    /// The ecall handler.
    ecall_handler: EcallHandler,
    /// If a control flow instruction has been inserted.
    control_flow_instruction_inserted: bool,
    /// Indicate that we are "within" an instruction.
    instruction_started: bool,
    /// Indicate that instuction has been inserted that may cause us to early exit.
    may_early_exit: bool,
    /// The amount to bump the clk by each cycle.
    clk_bump: u64,
    /// Exit label offset
    exit_label_offset: usize,
    /// Long jump label offset, long jump means jumping to another JIT region.
    long_jump_label_offset: usize,
    /// Indicate if untrusted program is enabled
    enable_untrusted_program: bool,
}

impl TraceCollector for TranspilerBackend {
    fn trace_registers(&mut self) {
        for reg in RiscRegister::all_registers().iter() {
            let (xmm_index, xmm_offset) = Self::get_xmm_index(*reg);
            let value_byte_offset = *reg as u32 * 8;

            dynasm! {
                self;
                .arch x64;

                pextrq [Rq(TRACE_BUF) + value_byte_offset as i32], Rx(xmm_index), xmm_offset
            };
        }
    }

    /// Write the value at [rs1 + imm] into the trace buffer.
    fn trace_mem_value(&mut self, rs1: RiscRegister, imm: u64, is_write: bool, clk_bump: i32) {
        const TAIL_START_OFFSET: i32 = std::mem::size_of::<TraceChunkHeader>() as i32;
        const NUM_MEM_READS_OFFSET: i32 = offset_of!(TraceChunkHeader, num_mem_reads) as i32;
        const IS_UNCONSTRAINED_OFFSET: i32 = offset_of!(JitContext, is_unconstrained) as i32;
        let max_memory_size = self.max_memory_size as i64;

        dynasm! {
            self;
            .arch x64;

            // Check if were in unconstrained mode.
            cmp QWORD [Rq(CONTEXT) + IS_UNCONSTRAINED_OFFSET], 1;
            je >done
        }

        // Load the value, assumed to be of a memory read, into TEMP_A.
        self.emit_risc_operand_load(rs1.into(), TEMP_A);
        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Compute the address to load from.
            // ------------------------------------
            add Rq(TEMP_A), imm as i32;

            // ------------------------------------
            // Align to the start of the word.
            // ------------------------------------
            and Rq(TEMP_A), -8;

            // ------------------------------------
            // Compute the pointer to the tail
            // and store into `TEMP_B`.
            // ------------------------------------
            mov Rq(TEMP_B), QWORD [Rq(TRACE_BUF) + NUM_MEM_READS_OFFSET];
            shl Rq(TEMP_B), 4; // scale by the size of a `MemValue`.
            add Rq(TEMP_B), TAIL_START_OFFSET;
            add Rq(TEMP_B), Rq(TRACE_BUF)
        }

        if self.enable_untrusted_program {
            // TODO: for untrusted programs, trace page prot value
            let permission_offset = offset_of!(JitContext, permission) as i32;
            let value_n_inited: i16 = ((1u16 << 8) | (DEFAULT_PAGE_PROT as u16)) as i16;

            dynasm! {
                self;
                .arch x64;

                // ------------------------------------
                // Save TEMP_A as it will be used later.
                // ------------------------------------
                push Rq(TEMP_A);

                // ------------------------------------
                // Calculate page index, then permission offset.
                // ------------------------------------
                shr Rq(TEMP_A), LOG_PAGE_SIZE as _;
                shl Rq(TEMP_A), 4;

                // ------------------------------------
                // Locate the permission field to access.
                // ------------------------------------
                add Rq(TEMP_A), QWORD [Rq(CONTEXT) + permission_offset];

                // ------------------------------------
                // Load half-word first.
                // High byte is inited,
                // Low byte is value.
                // ------------------------------------
                mov ax, WORD [Rq(TEMP_A) + 8];

                // ------------------------------------
                // Test ah to see if prot is inited.
                // ------------------------------------
                cmp ah, 0;
                jne >prot_inited;

                // ------------------------------------
                // Initialize page prot;
                // ------------------------------------
                mov QWORD [Rq(TEMP_A)], 0;
                mov ax, value_n_inited;
                mov WORD [Rq(TEMP_A) + 8], ax;

                prot_inited:;
                // ------------------------------------
                // Copy page prot to trace tail.
                // ------------------------------------
                mov BYTE [Rq(TEMP_B) + 8], al;
                mov rax, QWORD [Rq(TEMP_A)];
                mov QWORD [Rq(TEMP_B)], rax;

                // ------------------------------------
                // Bump current clk in prot entry.
                // ------------------------------------
                mov rax, QWORD [Rq(CONTEXT) + CLK_OFFSET];
                add rax, clk_bump;
                mov [Rq(TEMP_A)], rax;

                // ------------------------------------
                // Increment the num mem reads, since weve pushed into it.
                // Increment TEMP_B for tracing mem value.
                // ------------------------------------
                add QWORD [Rq(TRACE_BUF) + NUM_MEM_READS_OFFSET], 1;
                add Rq(TEMP_B), 16;

                // ------------------------------------
                // Restore TEMP_A.
                // ------------------------------------
                pop Rq(TEMP_A)
            }
        }

        self.load_memory_ptr(Rq::RAX.into());
        dynasm! {
            self;
            .arch x64;
            // ------------------------------------
            // Add the physical memory pointer.
            // ------------------------------------
            add Rq(TEMP_A), rax;

            // ------------------------------------
            // Load the word into TEMP_B
            // and store it into the tail.
            //
            // UNTRUSTED: when tracing is enabled, memory READ
            // permission failure will be triggered here.
            // ------------------------------------
            mov rax, QWORD [Rq(TEMP_A)];
            mov [Rq(TEMP_B) + 8], rax
        }

        if is_write {
            dynasm! {
                self;
                .arch x64;
                // ------------------------------------
                // Dummy ops to test memory write permission
                //
                // UNTRUSTED: when tracing is enabled, memory WRITE
                // permission failure will be triggered here.
                // ------------------------------------
                mov QWORD [Rq(TEMP_A)], rax
            }
        }

        dynasm! {
            self;
            .arch x64;
            // ------------------------------------
            // Calculate clock address from memory address in TEMP_A
            // ------------------------------------
            mov rax, QWORD max_memory_size;
            sub Rq(TEMP_A), rax;

            // ------------------------------------
            // Load the clk from the memory entry into TEMP_B
            // and store it into the tail.
            // ------------------------------------
            mov rax, QWORD [Rq(TEMP_A)];
            mov [Rq(TEMP_B)], rax;

            // ------------------------------------
            // Bump the current clk in the memory entry.
            // ------------------------------------
            mov rax, QWORD [Rq(CONTEXT) + CLK_OFFSET];
            add rax, clk_bump;
            mov [Rq(TEMP_A)], rax;

            // ------------------------------------
            // Increment the num mem reads, since weve pushed into it.
            // ------------------------------------
            add QWORD [Rq(TRACE_BUF) + NUM_MEM_READS_OFFSET], 1;

            done:
        }
    }

    /// Write the start pc of the trace chunk.
    fn trace_pc_start(&mut self) {
        const PC_START_OFFSET: i32 = offset_of!(TraceChunkHeader, pc_start) as i32;

        self.load_pc_into_register(TEMP_A);

        dynasm! {
            self;
            .arch x64;

            mov [Rq(TRACE_BUF) + PC_START_OFFSET], Rq(TEMP_A)
        }
    }

    /// Write the start clk of the trace chunk.
    fn trace_clk_start(&mut self) {
        const CLK_START_OFFSET: i32 = offset_of!(TraceChunkHeader, clk_start) as i32;
        const CLK_OFFSET: i32 = offset_of!(JitContext, clk) as i32;

        dynasm! {
            self;
            .arch x64;

            mov Rq(TEMP_A), QWORD [Rq(CONTEXT) + CLK_OFFSET];
            mov [Rq(TRACE_BUF) + CLK_START_OFFSET], Rq(TEMP_A)
        }
    }

    fn trace_clk_end(&mut self) {
        const CLK_END_OFFSET: i32 = offset_of!(TraceChunkHeader, clk_end) as i32;
        const CLK_OFFSET: i32 = offset_of!(JitContext, clk) as i32;

        dynasm! {
            self;
            .arch x64;
            mov Rq(TEMP_A), [Rq(CONTEXT) + CLK_OFFSET];
            mov [Rq(TRACE_BUF) + CLK_END_OFFSET], Rq(TEMP_A)
        }
    }
}

impl TranspilerBackend {
    fn tracing(&self) -> bool {
        self.max_trace_size > 0
    }

    fn exit_if_trace_exceeds(&mut self, max_trace_size: u64) {
        let num_mem_reads_offset = offset_of!(TraceChunkHeader, num_mem_reads) as i32;
        let threshold_mem_reads = max_trace_size;
        let exit_label_offset = offset_of!(JitContext, exit_label) as i32;

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // 1. Load num_mem_reads from trace buffer
            // ------------------------------------
            mov Rq(TEMP_A), [Rq(TRACE_BUF) + num_mem_reads_offset];

            // ------------------------------------
            // 2. Check if num_mem_reads is 0 (skip exit at beginning)
            // ------------------------------------
            test Rq(TEMP_A), Rq(TEMP_A);
            jz >skip_exit;  // If num_mem_reads == 0, skip the exit check

            // ------------------------------------
            // 3. Check if num_mem_reads >= 90% of max_mem_reads
            // ------------------------------------
            mov Rq(TEMP_B), QWORD threshold_mem_reads as i64;  // Load threshold
            cmp Rq(TEMP_A), Rq(TEMP_B);  // Compare num_mem_reads with threshold

            // ------------------------------------
            // 4. If num_mem_reads >= threshold, return
            // ------------------------------------
            jb >skip_exit;  // Jump if below (unsigned comparison)
            jmp QWORD [Rq(CONTEXT) + exit_label_offset];
            skip_exit:
        }
    }

    /// Emit the prologue for the function.
    ///
    /// This is called before the first instruction is emitted.
    fn prologue(&mut self) {
        // Compute the offsets so we can store some pointers seperately.
        let jump_table_offset = offset_of!(JitContext, jump_table) as i32;
        let trace_buf_offset = offset_of!(JitContext, trace_buf) as i32;

        // Prologue
        //
        // Push all the callee-saved registers we clobber, to be restored when we exit.
        //
        // We also want to 0 out all the registers we use,
        // since were operting on the lower 32 bits of them, and upper zereos could pose problems.
        dynasm! {
            self;
            .arch x64;

            // Save the callee saved registers were gonna clobber.
            push Rq(TEMP_A);
            push Rq(TEMP_B);
            push Rq(CONTEXT);
            push Rq(JUMP_TABLE);
            push Rq(TRACE_BUF);
            push Rq(SAVED_STACK_PTR);

            // Save some useful pointers to non-volatile registers so we can use them in ASM easily.
            mov Rq(JUMP_TABLE), [rdi + jump_table_offset];
            mov Rq(TRACE_BUF), [rdi + trace_buf_offset];
            // Save the JitContext pointer to a non-volatile register.
            mov Rq(CONTEXT), rdi
        };

        // For each register from the context, lets load it into a phyiscal register.
        self.load_registers_from_context();

        if self.tracing() {
            self.trace_pc_start();
            self.trace_clk_start();
            self.trace_registers();
        }

        // Its possible that enter back into the function with a non-zero PC.
        self.jump_to_pc();
    }

    /// Restore all the registers callee-saved registers we clobbered
    ///
    /// To be called after the last instruction has been emitted.
    fn epilogue(&mut self) {
        if !self.has_instructions {
            panic!(
                "No instructions were emitted, 
                cannot finalize as this will break assumptions made in the jump table."
            );
        }

        if self.enable_untrusted_program {
            dynasm! {
                self;
                .arch x64;

                ->long_jump:
            }
            // Save long jump label offset, so we can do far jumps later
            self.long_jump_label_offset = self.inner.offset().0;

            self.call_extern_fn(sp1_jit_long_jump);
            // After long jump handler, we need to update JUMP_TABLE register
            let jump_table_offset = offset_of!(JitContext, jump_table) as i32;
            dynasm! {
                self;
                .arch x64;

                mov Rq(JUMP_TABLE), [Rq(CONTEXT) + jump_table_offset]
            }
            // Now jump_to_pc should work
            self.jump_to_pc();
        }

        // Start the global exit label.
        // Its possible that we need to hit this label due to reaching cycle limt.
        dynasm! {
            self;
            .arch x64;

            // Define the exit global label.
            ->exit:
        }
        // Save exit label offset, so we can do far jumps later
        self.exit_label_offset = self.inner.offset().0;

        if self.tracing() {
            self.trace_clk_end();
        }

        // Ensure the registers are saved to the context.
        self.save_registers_to_context();

        dynasm! {
            self;
            .arch x64;

            // Restore the callee saved registers.
            pop Rq(SAVED_STACK_PTR);
            pop Rq(TRACE_BUF);
            pop Rq(JUMP_TABLE);
            pop Rq(CONTEXT);
            pop Rq(TEMP_B);
            pop Rq(TEMP_A);

            ret
        };
    }

    fn save_registers_to_context(&mut self) {
        for reg in RiscRegister::all_registers().iter() {
            let (xmm_index, xmm_offset) = Self::get_xmm_index(*reg);
            let value_byte_offset = *reg as u32 * 8;

            dynasm! {
                self;
                .arch x64;

                pextrq [Rq(CONTEXT) + REGISTERS_OFFSET + value_byte_offset as i32], Rx(xmm_index), xmm_offset
            };
        }
    }

    fn load_registers_from_context(&mut self) {
        // For each register from the context, lets load it into a phyiscal register.
        for reg in RiscRegister::all_registers().iter() {
            let (xmm_index, xmm_offset) = Self::get_xmm_index(*reg);
            let value_byte_offset = *reg as u32 * 8;

            dynasm! {
                self;
                .arch x64;

                pinsrq Rx(xmm_index), [Rq(CONTEXT) + REGISTERS_OFFSET + value_byte_offset as i32], xmm_offset
            };
        }
    }

    /// RiscV registers are mapped to XMM registers.
    ///
    /// We load the value from the XMM register into the general purpose register for the backend to
    /// operate on. We do this to avoid accidently clobbering the XMM registers.
    ///
    /// NOTE: This aliases the full 64 bits of the register.
    fn emit_risc_operand_load(&mut self, op: RiscOperand, dst: u8) {
        match op {
            RiscOperand::Register(reg) => match reg {
                RiscRegister::X0 => {
                    dynasm! {
                        self;
                        .arch x64;

                        mov Rq(dst), 0_i32 // load 0 into dst
                    };
                }
                _ => {
                    let (xmm_index, xmm_offset) = Self::get_xmm_index(reg);

                    dynasm! {
                        self;
                        .arch x64;

                        pextrq Rq(dst), Rx(xmm_index), xmm_offset // load 64-bit value from XMM
                    };
                }
            },
            RiscOperand::Immediate(imm) => {
                dynasm! {
                    self;
                    .arch x64;

                    mov Rq(dst), imm
                };
            }
        }
    }

    /// Store the value from the general purpose register into the corresponding XMM register.
    ///
    /// Note: This stores the full 64 bits of the register.
    #[inline]
    fn emit_risc_register_store(&mut self, src: u8, dst: RiscRegister) {
        if dst == RiscRegister::X0 {
            // x0 is hardwired to 0 in RISC-V, ignore stores to it.
            return;
        }

        let (xmm_index, xmm_offset) = Self::get_xmm_index(dst);

        dynasm! {
            self;
            .arch x64;
            pinsrq Rx(xmm_index), Rq(src), xmm_offset
        };
    }

    /// Static lookup table for XMM register mapping.
    /// Maps RISC-V register index to (XMM index, XMM offset).
    /// Each XMM register holds 2 x 64-bit values, so we map registers 0-31 to XMM 0-15.
    const XMM_LOOKUP: [(u8, i8); 32] = [
        (0, 0),
        (0, 1),
        (1, 0),
        (1, 1),
        (2, 0),
        (2, 1),
        (3, 0),
        (3, 1),
        (4, 0),
        (4, 1),
        (5, 0),
        (5, 1),
        (6, 0),
        (6, 1),
        (7, 0),
        (7, 1),
        (8, 0),
        (8, 1),
        (9, 0),
        (9, 1),
        (10, 0),
        (10, 1),
        (11, 0),
        (11, 1),
        (12, 0),
        (12, 1),
        (13, 0),
        (13, 1),
        (14, 0),
        (14, 1),
        (15, 0),
        (15, 1),
    ];

    /// Get XMM index and offset for the given register using static lookup.
    ///
    /// We operate on the assumption there are 16 128 bit XMM registers we can use.
    /// Each XMM register can hold 2 x 64-bit values.
    /// We map a register to an index in the range `[0, 15]` and an offset in the range `[0, 1]`.
    #[inline]
    const fn get_xmm_index(reg: RiscRegister) -> (u8, i8) {
        Self::XMM_LOOKUP[reg as usize]
    }

    /// Call an external function, assumes that the arguments are already in the correct registers.
    #[inline]
    fn call_extern_fn_raw(&mut self, fn_ptr: usize) {
        // Before the call, save all the registers to the context.
        self.save_registers_to_context();

        // We need to save the caller-saved registers before we make any calls,
        // then restore them after the call.
        dynasm! {
            self;
            .arch x64;

            // Save the original stack pointer
            mov Rq(SAVED_STACK_PTR), rsp;

            // Align the stack to 16 bytes for the call
            lea rsp, [rsp - 8]; // sub 8 from the rsp
            mov rax, rsp; // copy
            and rax, 15; // compute rsp % 16
            sub rsp, rax; // sub that from the rsp to ensure 16 byte alignment

            // Call the external function
            mov rax, QWORD fn_ptr as _;
            call rax;

            // Restore the original stack pointer
            mov rsp, Rq(SAVED_STACK_PTR)
        }

        self.load_registers_from_context();
    }

    /// Load the pc from the context into the given register.
    #[inline]
    fn load_pc_into_register(&mut self, dst: u8) {
        let pc_offset = offset_of!(JitContext, pc) as i32;

        dynasm! {
            self;
            .arch x64;
            mov Rq(dst), QWORD [Rq(CONTEXT) + pc_offset]
        }
    }

    #[inline]
    fn load_memory_ptr(&mut self, src: u8) {
        dynasm! {
            self;
            .arch x64;
            mov Rq(src), QWORD [Rq(CONTEXT) + MEMORY_PTR_OFFSET]
        }
    }

    /// Bump the pc by the given amount.
    #[inline]
    fn bump_pc(&mut self, amt: u32) {
        let pc_offset = offset_of!(JitContext, pc) as i32;

        dynasm! {
            self;
            .arch x64;

            add QWORD [Rq(CONTEXT) + pc_offset], amt as i32
        }
    }

    /// Looks up into the jump table and executes a jump.
    #[inline]
    fn jump_to_pc(&mut self) {
        self.load_pc_into_register(TEMP_A);

        dynasm! {
            self;
            .arch x64;

            // If the PC we want to jump to is 1, jump to the exit label.
            cmp Rq(TEMP_A), 1;
            je >near_exit
        }

        if self.enable_untrusted_program {
            let pc_base_offset = offset_of!(JitContext, pc_base) as i32;
            let pc_end_offset = offset_of!(JitContext, pc_end) as i32;

            dynasm! {
                self;
                .arch x64;

                // Load pc_end to TEMP_B for comparison
                mov Rq(TEMP_B), QWORD [Rq(CONTEXT) + pc_end_offset];
                // // If the PC we want to jump is equal or greater than PC end, jump to long jump label
                cmp Rq(TEMP_A), Rq(TEMP_B);
                jae >near_long_jump;
                // Load pc_base to TEMP_B for comparison
                mov Rq(TEMP_B), QWORD [Rq(CONTEXT) + pc_base_offset];
                // Subtract the pc base to get the offset from the start of the program.
                sub Rq(TEMP_A), Rq(TEMP_B);
                // If the PC we want to jump to is lower than PC base, jump to long jump label
                jb >near_long_jump
            }
        } else {
            // In 64-bit RISC-V, some pc_base might not fit in 32-bit immediate value.
            if let Ok(pc_base) = TryInto::<i32>::try_into(self.pc_base) {
                dynasm! {
                    self;
                    .arch x64;
                    // Subtract the pc base to get the offset from the start of the program.
                    sub Rq(TEMP_A), pc_base
                }
            } else {
                let pc_base = self.pc_base as i64;
                dynasm! {
                    self;
                    .arch x64;
                    // Subtract the pc base to get the offset from the start of the program.
                    mov Rq(TEMP_B), QWORD pc_base;
                    sub Rq(TEMP_A), Rq(TEMP_B)
                }
            }
        }

        let exit_label_offset = offset_of!(JitContext, exit_label) as i32;
        dynasm! {
            self;
            .arch x64;
            // Divide by 4 to get the index (each instruction is 4 bytes).
            shr Rq(TEMP_A), 2;
            // Jump via the jump table, scaling by 8 since the pointers are 8 bytes.
            jmp QWORD [Rq(JUMP_TABLE) + Rq(TEMP_A) * 8];

            near_exit:;
            jmp QWORD [Rq(CONTEXT) + exit_label_offset]
        }

        if self.enable_untrusted_program {
            let long_jump_label_offset = offset_of!(JitContext, long_jump_label) as i32;
            dynasm! {
                self;
                .arch x64;

                near_long_jump:;
                jmp QWORD [Rq(CONTEXT) + long_jump_label_offset]
            }
        }
    }

    fn bump_clk(&mut self) {
        let clk_offset = offset_of!(JitContext, clk) as i32;
        let global_clk_offset = offset_of!(JitContext, global_clk) as i32;
        let is_unconstrained_offset = offset_of!(JitContext, is_unconstrained) as i32;
        let clk_bump = self.clk_bump as i32;

        dynasm! {
            self;
            .arch x64;

            // ------------------------------------
            // Add the amount to the clk field in the context.
            // ------------------------------------
            add QWORD [Rq(CONTEXT) + clk_offset], clk_bump;

            // ------------------------------------
            // Add to global_clk based on is_unconstrained:
            // - If is_unconstrained == 0, add 1
            // - If is_unconstrained == 1, add 0
            // ------------------------------------

            // Load is_unconstrained (8-bit) into TEMP_A with zero extension
            mov Rq(TEMP_A), QWORD [Rq(CONTEXT) + is_unconstrained_offset];

            // XOR with 1 to invert: 0 -> 1, 1 -> 0
            xor Rq(TEMP_A), 1;

            // Add the inverted value to global_clk
            add QWORD [Rq(CONTEXT) + global_clk_offset], Rq(TEMP_A)
        }
    }
}

impl Deref for TranspilerBackend {
    type Target = Assembler;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TranspilerBackend {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// The backend implicity relies on the exsitence of 16 128 bit XMM registers.
///
/// If this is not the case, we throw an error at compile time.
#[cfg(not(target_feature = "sse"))]
compile_error!("SSE is required for the x86 backend");

/// A dummy ecall handler that can be called by the JIT.
extern "C" fn ecallk(ctx: *mut JitContext) -> u64 {
    let ctx = unsafe { &mut *ctx };

    eprintln!("dummy ecall handler called with code: 0x{:x}", ctx.registers[5]);

    if ctx.registers[5] == 0 {
        ctx.pc = 0;
    } else {
        ctx.pc += 4;
    }

    ctx.clk += 256;

    0
}

/// Long jump handler. Long jump refers to jumps from one JIT region to
/// another. In this case, we will need to find the target JitRegion, and
/// use jump tables, labels from the target JitRegion to replace current
/// JitRegion.
extern "C" fn sp1_jit_long_jump(ctx: *mut JitContext) {
    // SAFETY: ctx will be dereferencable when calling long jump.
    let ctx = unsafe { &mut *ctx };

    let pc = ctx.pc;
    let (jump_table, exit_label, long_jump_label, pc_base, pc_end) = if let Some(region) = ctx
        .function_mut()
        .regions
        .iter_mut()
        .find(|region| pc >= region.pc_base && pc < region.pc_end())
    {
        (
            unsafe { NonNull::new_unchecked(region.jump_table.as_mut_ptr()) },
            region.exit_label,
            region.long_jump_label,
            region.pc_base,
            region.pc_end(),
        )
    } else {
        panic!("Long jump failed to find JitRegion for pc=0x{pc:x}!");
    };

    ctx.jump_table = jump_table;
    ctx.exit_label = exit_label;
    ctx.long_jump_label = long_jump_label;
    ctx.pc_base = pc_base;
    ctx.pc_end = pc_end;
}
