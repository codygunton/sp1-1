#![no_main]
sp1_zkvm::entrypoint!(main);

use rand::prelude::*;
use sp1_primitives::consts::{
    PAGE_SIZE, PROT_EXEC, PROT_FAILURE_EXEC, PROT_FAILURE_READ, PROT_FAILURE_WRITE, PROT_NONE,
    PROT_READ, PROT_WRITE,
};
use sp1_zkvm::{lib::mprotect::mprotect, syscalls};

// When the design of trap is complete, we would move TrapContext,
// __SUCCINCT_TRAP_CONTEXT and install_trap_handler to sp1-zkvm crate.
#[repr(C)]
pub struct TrapContext {
    handler: u64,
    code: u64,
    pc: u64,
}

#[no_mangle]
#[used]
pub static mut __SUCCINCT_TRAP_CONTEXT: TrapContext = TrapContext { handler: 1, code: 0, pc: 1 };

pub fn install_trap_handler(h: extern "C" fn()) {
    unsafe {
        __SUCCINCT_TRAP_CONTEXT.handler = h as *mut u8 as u64;
    }
}

pub static mut TRAP_COUNTER: u64 = 0;

// This is the actual trap function. It will merely return(returning
// from the function that traps, not the trap handler) with the trap code.
#[unsafe(naked)]
pub extern "C" fn sp1_trap_trap_trap() {
    // Note this is actually a trap handler, not a normal function.
    // SP1 would *jump* to the start of this function instead of calling
    // this function. All the registers will be exactly the same value
    // as they are when the trap happens. This means if we do `ret`, we
    // will effectively be returning from the function causing the trap.
    core::arch::naked_asm!(
        "la a1, {counter}",
        "ld a0, 0(a1)",
        "addi a0, a0, 1",
        "sd a0, 0(a1)",
        "la a0, {context}",
        "ld a0, 8(a0)",
        "ret",
        context = sym __SUCCINCT_TRAP_CONTEXT,
        counter = sym TRAP_COUNTER,
    )
}

pub fn main() {
    println!("Starting simple trap example");

    // If you comment this line out, trap will not take effect. SP1 will
    // simply terminate in case of permission violation.
    install_trap_handler(sp1_trap_trap_trap);

    // Heap allocated memory might not be page aligned, we are allocating
    // 6 pages(precompiles might need more), and find 5 aligned pages inside.
    let mut memory = vec![0u8; 6 * PAGE_SIZE];
    rand::thread_rng().fill(&mut memory[..]);

    // Get a pointer to the memory rounded up to the nearest page boundary
    let memory_ptr = memory.as_ptr() as *const u8;
    let aligned_ptr = (memory_ptr as usize + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aligned_ptr = aligned_ptr as *mut u8;

    println!("Memory aligned pointer: {:p}", aligned_ptr);

    // Violate read permission
    mprotect(aligned_ptr, PAGE_SIZE, PROT_WRITE | PROT_EXEC);
    assert_eq!(violating_read(aligned_ptr, rand::random()), PROT_FAILURE_READ);

    // Violate write permission
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_EXEC);
    assert_eq!(violating_write(aligned_ptr, rand::random()), PROT_FAILURE_WRITE);

    // Violate execute permission
    mprotect(aligned_ptr, PAGE_SIZE, PROT_READ | PROT_WRITE);
    assert_eq!(violating_execute(aligned_ptr), PROT_FAILURE_EXEC);
    mprotect(aligned_ptr, PAGE_SIZE, PROT_EXEC | PROT_WRITE);
    assert_eq!(violating_execute(aligned_ptr), PROT_FAILURE_READ);

    // Test precompiles
    let first_page = aligned_ptr;
    let second_page = (aligned_ptr as usize + PAGE_SIZE) as *mut u8;
    let third_page = (aligned_ptr as usize + PAGE_SIZE * 2) as *mut u8;
    let fourth_page = (aligned_ptr as usize + PAGE_SIZE * 3) as *mut u8;
    let fifth_page = (aligned_ptr as usize + PAGE_SIZE * 4) as *mut u8;

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_sha256_extend(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_sha256_extend(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_sha256_extend(first_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    run_sha256_extend(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_sha256_compress(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    run_sha256_compress(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_sha256_compress(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_WRITE);
    run_sha256_compress(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    run_sha256_compress(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_keccak_permute(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_keccak_permute(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_keccak_permute(first_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    run_keccak_permute(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_secp256k1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_secp256k1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_secp256k1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_secp256k1_add(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_secp256k1_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_secp256k1_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_secp256k1_double(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_secp256r1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_secp256r1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_secp256r1_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_secp256r1_add(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_secp256r1_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_secp256r1_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_secp256r1_double(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_add(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_bls12381_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_bls12381_double(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_add(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_bn254_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_bn254_double(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_bn254_double(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_ed_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_ed_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_ed_add(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_ed_add(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_ed_decompress(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_ed_decompress(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_ed_decompress(first_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_addmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_addmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_submod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_mulmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp_mulmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_addmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_addmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_submod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bls12381_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_mulmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bls12381_fp2_mulmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_addmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_addmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_submod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_mulmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp_mulmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_addmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_addmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_addmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_submod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_submod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_bn254_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_mulmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_bn254_fp2_mulmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_uint256_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    run_uint256_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_uint256_mulmod(first_page, second_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_uint256_mulmod(first_page, second_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    run_uint256_mulmod(first_page, second_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);
    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    run_u256x2048_mul(first_page, second_page, third_page, fourth_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    mprotect(fifth_page, PAGE_SIZE, PROT_NONE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_NONE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    mprotect(fifth_page, PAGE_SIZE, PROT_NONE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_NONE);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_NONE);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_NONE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_NONE);
    run_uint256_add_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    mprotect(second_page, PAGE_SIZE, PROT_READ);
    mprotect(third_page, PAGE_SIZE, PROT_READ);
    mprotect(fourth_page, PAGE_SIZE, PROT_WRITE);
    mprotect(fifth_page, PAGE_SIZE, PROT_WRITE);
    run_uint256_mul_with_carry(first_page, second_page, third_page, fourth_page, fifth_page);

    mprotect(first_page, PAGE_SIZE, PROT_NONE);
    run_poseidon2(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_READ);
    run_poseidon2(first_page);
    mprotect(first_page, PAGE_SIZE, PROT_WRITE);
    run_poseidon2(first_page);
    // This should not trap
    mprotect(first_page, PAGE_SIZE, PROT_READ | PROT_WRITE);
    run_poseidon2(first_page);

    assert_eq!(unsafe { TRAP_COUNTER }, 121);
    println!("Terminating! We have handled all traps!");
}

// The current example is a simplified one, while we do have the capability,
// we are not in fact doing a full context switch. In case of trapping, we simply
// return from the function causing the trap. This means the function causing
// traps must be in its own function. A more sophisticated setup does not
// have this limitation.
#[inline(never)]
pub extern "C" fn violating_read(page_addr: *mut u8, default_value: u64) -> u64 {
    #[allow(unused_assignments)]
    let mut value: u64 = default_value;

    unsafe {
        core::arch::asm!(
            "ld {value}, 8({ptr})",
            ptr = in(reg) page_addr,
            value = out(reg) value,
        );
    }

    value
}

#[unsafe(naked)]
pub extern "C" fn violating_write(page_addr: *mut u8, target_value: u64) -> u64 {
    core::arch::naked_asm!("sd a1, 16(a0)", "mv a0, a1", "ret",)
}

#[unsafe(naked)]
pub extern "C" fn violating_execute(page_addr: *mut u8) -> u64 {
    core::arch::naked_asm!("addi a0, a0, 24", "jr a0",)
}

#[inline(never)]
pub extern "C" fn run_sha256_extend(first_page_addr: *mut u8) {
    syscalls::syscall_sha256_extend(first_page_addr as *mut [u64; 64]);
}

#[inline(never)]
pub extern "C" fn run_sha256_compress(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_sha256_compress(
        first_page_addr as *mut [u64; 64],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_keccak_permute(first_page_addr: *mut u8) {
    syscalls::syscall_keccak_permute(first_page_addr as *mut [u64; 25]);
}

#[inline(never)]
pub extern "C" fn run_secp256k1_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_secp256k1_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_secp256k1_double(first_page_addr: *mut u8) {
    syscalls::syscall_secp256k1_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_secp256r1_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_secp256r1_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_secp256r1_double(first_page_addr: *mut u8) {
    syscalls::syscall_secp256r1_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_bls12381_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_add(
        first_page_addr as *mut [u64; 12],
        second_page_addr as *mut [u64; 12],
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_double(first_page_addr: *mut u8) {
    syscalls::syscall_bls12381_double(first_page_addr as *mut [u64; 12]);
}

#[inline(never)]
pub extern "C" fn run_bn254_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_add(
        first_page_addr as *mut [u64; 8],
        second_page_addr as *mut [u64; 8],
    );
}

#[inline(never)]
pub extern "C" fn run_bn254_double(first_page_addr: *mut u8) {
    syscalls::syscall_bn254_double(first_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_ed_add(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_ed_add(first_page_addr as *mut [u64; 8], second_page_addr as *mut [u64; 8]);
}

#[inline(never)]
pub extern "C" fn run_ed_decompress(first_page_addr: *mut u8) {
    syscalls::syscall_ed_decompress(unsafe {
        std::mem::transmute::<*mut u8, &mut [u64; 8]>(first_page_addr)
    });
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_addmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_submod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp_mulmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_addmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_submod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bls12381_fp2_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bls12381_fp2_mulmod(
        first_page_addr as *mut u64,
        second_page_addr as *const u64,
    );
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_addmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_submod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp_mulmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_addmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_addmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_submod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_submod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_bn254_fp2_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_bn254_fp2_mulmod(first_page_addr as *mut u64, second_page_addr as *const u64);
}

#[inline(never)]
pub extern "C" fn run_uint256_mulmod(first_page_addr: *mut u8, second_page_addr: *mut u8) {
    syscalls::syscall_uint256_mulmod(
        first_page_addr as *mut [u64; 4],
        second_page_addr as *const [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_u256x2048_mul(
    first_page_addr: *mut u8,
    second_page_addr: *mut u8,
    third_page_addr: *mut u8,
    fourth_page_addr: *mut u8,
) {
    syscalls::syscall_u256x2048_mul(
        first_page_addr as *const [u64; 4],
        second_page_addr as *const [u64; 32],
        third_page_addr as *mut [u64; 32],
        fourth_page_addr as *mut [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_uint256_add_with_carry(
    first_page_addr: *mut u8,
    second_page_addr: *mut u8,
    third_page_addr: *mut u8,
    fourth_page_addr: *mut u8,
    fifth_page_addr: *mut u8,
) {
    syscalls::syscall_uint256_add_with_carry(
        first_page_addr as *const [u64; 4],
        second_page_addr as *const [u64; 4],
        third_page_addr as *const [u64; 4],
        fourth_page_addr as *mut [u64; 4],
        fifth_page_addr as *mut [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_uint256_mul_with_carry(
    first_page_addr: *mut u8,
    second_page_addr: *mut u8,
    third_page_addr: *mut u8,
    fourth_page_addr: *mut u8,
    fifth_page_addr: *mut u8,
) {
    syscalls::syscall_uint256_mul_with_carry(
        first_page_addr as *const [u64; 4],
        second_page_addr as *const [u64; 4],
        third_page_addr as *const [u64; 4],
        fourth_page_addr as *mut [u64; 4],
        fifth_page_addr as *mut [u64; 4],
    );
}

#[inline(never)]
pub extern "C" fn run_poseidon2(first_page_addr: *mut u8) {
    syscalls::syscall_poseidon2(unsafe {
        std::mem::transmute::<*mut u8, &syscalls::Poseidon2State>(first_page_addr)
    });
}
