use num::{BigUint, Integer, One};

use sp1_jit::{
    Interrupt,
    RiscRegister::{X12, X13},
    SyscallContext,
};
use sp1_primitives::consts::{bytes_to_words_le, words_to_bytes_le_vec};

const U256_NUM_WORDS: usize = 4;
const U2048_NUM_WORDS: usize = 32;
const U256_NUM_BYTES: usize = U256_NUM_WORDS * 8;
const U2048_NUM_BYTES: usize = U2048_NUM_WORDS * 8;

pub(crate) unsafe fn u256x2048_mul(
    ctx: &mut impl SyscallContext,
    arg1: u64,
    arg2: u64,
) -> Result<Option<u64>, Interrupt> {
    let a_ptr = arg1;
    let b_ptr = arg2;

    let lo_ptr = ctx.rr(X12);
    let hi_ptr = ctx.rr(X13);

    ctx.read_slice_check(a_ptr, U256_NUM_WORDS)?;
    ctx.read_slice_check(b_ptr, U2048_NUM_WORDS)?;
    ctx.bump_memory_clk();
    ctx.write_slice_check(lo_ptr, U2048_NUM_WORDS)?;
    ctx.write_slice_check(hi_ptr, U256_NUM_WORDS)?;

    let a = words_to_bytes_le_vec(ctx.mr_slice_without_prot(a_ptr, U256_NUM_WORDS));
    ctx.bump_memory_clk();
    let b = words_to_bytes_le_vec(ctx.mr_slice_without_prot(b_ptr, U2048_NUM_WORDS));
    let uint256_a = BigUint::from_bytes_le(&a);
    let uint2048_b = BigUint::from_bytes_le(&b);

    let result = uint256_a * uint2048_b;

    let two_to_2048 = BigUint::one() << 2048;

    let (hi, lo) = result.div_rem(&two_to_2048);

    let mut lo_bytes = lo.to_bytes_le();
    lo_bytes.resize(U2048_NUM_BYTES, 0u8);
    let lo_words = bytes_to_words_le::<U2048_NUM_WORDS>(&lo_bytes);

    let mut hi_bytes = hi.to_bytes_le();
    hi_bytes.resize(U256_NUM_BYTES, 0u8);
    let hi_words = bytes_to_words_le::<U256_NUM_WORDS>(&hi_bytes);

    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(lo_ptr, &lo_words);
    ctx.bump_memory_clk();
    ctx.mw_slice_without_prot(hi_ptr, &hi_words);

    Ok(None)
}
