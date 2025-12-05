use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

use deepsize2::DeepSizeOf;
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};
use sp1_hypercube::shape::Shape;
use strum::{EnumIter, IntoEnumIterator, IntoStaticStr};
use subenum::subenum;

/// RV64IM AIR Identifiers.
///
/// These identifiers are for the various chips in the rv64im prover. We need them in the
/// executor to compute the memory cost of the current shard of execution.
///
/// The [`CoreAirId`]s are the AIRs that are not part of precompile shards and not the program or
/// byte AIR.
#[subenum(CoreAirId)]
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    EnumIter,
    IntoStaticStr,
    PartialOrd,
    Ord,
    Enum,
    DeepSizeOf,
)]
pub enum RiscvAirId {
    /// The cpu chip, which is a dummy for now, needed for shape loading.
    #[subenum(CoreAirId)]
    Cpu = 0,
    /// The program chip.
    Program = 1,
    /// The SHA-256 extend chip.
    ShaExtend = 2,
    /// The sha extend control chip.
    ShaExtendControl = 3,
    /// The sha extend control chip for user mode.
    ShaExtendControlUser = 4,
    /// The SHA-256 compress chip.
    ShaCompress = 5,
    /// The sha compress control chip.
    ShaCompressControl = 6,
    /// The sha compress control chip for user mode.
    ShaCompressControlUser = 7,
    /// The Edwards add assign chip.
    EdAddAssign = 8,
    /// The Edwards add assign chip for user mode.
    EdAddAssignUser = 9,
    /// The Edwards decompress chip.
    EdDecompress = 10,
    /// The Edwards decompress chip (user mode).
    EdDecompressUser = 11,
    /// The secp256k1 decompress chip.
    Secp256k1Decompress = 12,
    /// The secp256k1 decompress chip (user mode).
    Secp256k1DecompressUser = 13,
    /// The secp256k1 add assign chip.
    Secp256k1AddAssign = 14,
    /// The secp256k1 add assign chip for user mode.
    Secp256k1AddAssignUser = 15,
    /// The secp256k1 double assign chip.
    Secp256k1DoubleAssign = 16,
    /// The secp256k1 double assign chip for user mode.
    Secp256k1DoubleAssignUser = 17,
    /// The secp256r1 decompress chip.
    Secp256r1Decompress = 18,
    /// The secp256r1 decompress chip (user mode).
    Secp256r1DecompressUser = 19,
    /// The secp256r1 add assign chip.
    Secp256r1AddAssign = 20,
    /// The secp256r1 add assign chip for user mode.
    Secp256r1AddAssignUser = 21,
    /// The secp256r1 double assign chip.
    Secp256r1DoubleAssign = 22,
    /// The secp256r1 double assign chip for user mode.
    Secp256r1DoubleAssignUser = 23,
    /// The Keccak permute chip.
    KeccakPermute = 24,
    /// The keccak permute control chip.
    KeccakPermuteControl = 25,
    /// The keccak permute control chip for user mode.
    KeccakPermuteControlUser = 26,
    /// The bn254 add assign chip.
    Bn254AddAssign = 27,
    /// The bn254 add assign chip for user mode.
    Bn254AddAssignUser = 28,
    /// The bn254 double assign chip.
    Bn254DoubleAssign = 29,
    /// The bn254 double assign chip for user mode.
    Bn254DoubleAssignUser = 30,
    /// The bls12-381 add assign chip.
    Bls12381AddAssign = 31,
    /// The bls12-381 add assign chip for user mode.
    Bls12381AddAssignUser = 32,
    /// The bls12-381 double assign chip.
    Bls12381DoubleAssign = 33,
    /// The bls12-381 double assign chip for user mode.
    Bls12381DoubleAssignUser = 34,
    /// The uint256 mul mod chip.
    Uint256MulMod = 35,
    /// The uint256 mul mod chip (user mode).
    Uint256MulModUser = 36,
    /// The uint256 ops chip.
    Uint256Ops = 37,
    /// The uint256 ops chip (user mode).
    Uint256OpsUser = 38,
    /// The u256 xu2048 mul chip.
    U256XU2048Mul = 39,
    /// The u256 xu2048 mul chip (user mode).
    U256XU2048MulUser = 40,
    /// The bls12-381 fp op assign chip.
    Bls12381FpOpAssign = 41,
    /// The bls12-381 fp op assign chip for user mode.
    Bls12381FpOpAssignUser = 42,
    /// The bls12-831 fp2 add sub assign chip.
    Bls12381Fp2AddSubAssign = 43,
    /// The bls12-381 fp2 add sub assign chip for user mode.
    Bls12381Fp2AddSubAssignUser = 44,
    /// The bls12-831 fp2 mul assign chip.
    Bls12381Fp2MulAssign = 45,
    /// The bls12-381 fp2 mul assign chip for user mode.
    Bls12381Fp2MulAssignUser = 46,
    /// The bn254 fp op assign chip.
    Bn254FpOpAssign = 47,
    /// The bn254 fp op assign chip for user mode.
    Bn254FpOpAssignUser = 48,
    /// The bn254 fp2 add sub assign chip.
    Bn254Fp2AddSubAssign = 49,
    /// The bn254 fp2 add sub assign chip for user mode.
    Bn254Fp2AddSubAssignUser = 50,
    /// The bn254 fp2 mul assign chip.
    Bn254Fp2MulAssign = 51,
    /// The bn254 fp2 mul assign chip for user mode.
    Bn254Fp2MulAssignUser = 52,
    /// The bls12-381 decompress chip.
    Bls12381Decompress = 53,
    /// The bls12-381 decompress chip (user mode).
    Bls12381DecompressUser = 54,
    /// The poseidon2 chip.
    Poseidon2 = 55,
    /// The poseidon2 chip for user mode.
    Poseidon2User = 56,
    /// The syscall core chip.
    #[subenum(CoreAirId)]
    SyscallCore = 57,
    /// The syscall precompile chip.
    SyscallPrecompile = 58,
    /// The div rem chip.
    #[subenum(CoreAirId)]
    DivRem = 59,
    /// The div rem chip for user mode.
    #[subenum(CoreAirId)]
    DivRemUser = 60,
    /// The add chip for supervisor mode.
    #[subenum(CoreAirId)]
    Add = 61,
    /// The add chip for user mode.
    #[subenum(CoreAirId)]
    AddUser = 62,
    /// The addi chip.
    #[subenum(CoreAirId)]
    Addi = 63,
    /// The addi chip for user mode.
    #[subenum(CoreAirId)]
    AddiUser = 64,
    /// The addw chip.
    #[subenum(CoreAirId)]
    Addw = 65,
    /// The addw chip for user mode.
    #[subenum(CoreAirId)]
    AddwUser = 66,
    /// The sub chip.
    #[subenum(CoreAirId)]
    Sub = 67,
    /// The sub chip for user mode.
    #[subenum(CoreAirId)]
    SubUser = 68,
    /// The subw chip.
    #[subenum(CoreAirId)]
    Subw = 69,
    /// The subw chip for user mode.
    #[subenum(CoreAirId)]
    SubwUser = 70,
    /// The bitwise chip.
    #[subenum(CoreAirId)]
    Bitwise = 71,
    /// The bitwise chip for user mode.
    #[subenum(CoreAirId)]
    BitwiseUser = 72,
    /// The mul chip.
    #[subenum(CoreAirId)]
    Mul = 73,
    /// The mul chip for user mode.
    #[subenum(CoreAirId)]
    MulUser = 74,
    /// The shift right chip.
    #[subenum(CoreAirId)]
    ShiftRight = 75,
    /// The shift right chip for user mode.
    #[subenum(CoreAirId)]
    ShiftRightUser = 76,
    /// The shift left chip.
    #[subenum(CoreAirId)]
    ShiftLeft = 77,
    /// The shift left chip for user mode.
    #[subenum(CoreAirId)]
    ShiftLeftUser = 78,
    /// The lt chip.
    #[subenum(CoreAirId)]
    Lt = 79,
    /// The lt chip for user mode.
    #[subenum(CoreAirId)]
    LtUser = 80,
    /// The load byte chip.
    #[subenum(CoreAirId)]
    LoadByte = 81,
    /// The load byte chip for user mode.
    #[subenum(CoreAirId)]
    LoadByteUser = 82,
    /// The load half chip.
    #[subenum(CoreAirId)]
    LoadHalf = 83,
    /// The load half chip for user mode.
    #[subenum(CoreAirId)]
    LoadHalfUser = 84,
    /// The load word chip.
    #[subenum(CoreAirId)]
    LoadWord = 85,
    /// The load word chip for user mode.
    #[subenum(CoreAirId)]
    LoadWordUser = 86,
    /// The load x0 chip.
    #[subenum(CoreAirId)]
    LoadX0 = 87,
    /// The load x0 chip for user mode.
    #[subenum(CoreAirId)]
    LoadX0User = 88,
    /// The load double chip.
    #[subenum(CoreAirId)]
    LoadDouble = 89,
    /// The load double chip for user mode.
    #[subenum(CoreAirId)]
    LoadDoubleUser = 90,
    /// The store byte chip.
    #[subenum(CoreAirId)]
    StoreByte = 91,
    /// The store byte chip for user mode.
    #[subenum(CoreAirId)]
    StoreByteUser = 92,
    /// The store half chip.
    #[subenum(CoreAirId)]
    StoreHalf = 93,
    /// The store half chip for user mode.
    #[subenum(CoreAirId)]
    StoreHalfUser = 94,
    /// The store word chip.
    #[subenum(CoreAirId)]
    StoreWord = 95,
    /// The store word chip for user mode.
    #[subenum(CoreAirId)]
    StoreWordUser = 96,
    /// The store double chip.
    #[subenum(CoreAirId)]
    StoreDouble = 97,
    /// The store double chip for user mode.
    #[subenum(CoreAirId)]
    StoreDoubleUser = 98,
    /// The utype chip.
    #[subenum(CoreAirId)]
    UType = 99,
    /// The utype chip for user mode.
    #[subenum(CoreAirId)]
    UTypeUser = 100,
    /// The branch chip.
    #[subenum(CoreAirId)]
    Branch = 101,
    /// The branch chip for user mode.
    #[subenum(CoreAirId)]
    BranchUser = 102,
    /// The jal chip.
    #[subenum(CoreAirId)]
    Jal = 103,
    /// The jal chip for user mode.
    #[subenum(CoreAirId)]
    JalUser = 104,
    /// The jalr chip.
    #[subenum(CoreAirId)]
    Jalr = 105,
    /// The jalr chip for user mode.
    #[subenum(CoreAirId)]
    JalrUser = 106,
    /// The syscall instructions chip.
    #[subenum(CoreAirId)]
    SyscallInstrs = 107,
    /// The memory bump chip.
    #[subenum(CoreAirId)]
    MemoryBump = 108,
    /// The state bump chip.
    #[subenum(CoreAirId)]
    StateBump = 109,
    /// The memory global init chip.
    MemoryGlobalInit = 110,
    /// The memory global finalize chip.
    MemoryGlobalFinalize = 111,
    /// The memory local chip.
    #[subenum(CoreAirId)]
    MemoryLocal = 112,
    /// The global chip.
    #[subenum(CoreAirId)]
    Global = 113,
    /// The byte chip.
    Byte = 114,
    /// The range chip.
    Range = 115,
    /// The mprotect chip.
    #[subenum(CoreAirId)]
    Mprotect = 116,
    /// The instruction decode chip.
    #[subenum(CoreAirId)]
    InstructionDecode = 117,
    /// The instruction fetch chip.
    #[subenum(CoreAirId)]
    InstructionFetch = 118,
    /// The page prot chip.
    #[subenum(CoreAirId)]
    PageProt = 119,
    /// The page prot local chip.
    #[subenum(CoreAirId)]
    PageProtLocal = 120,
    /// The page prot global init chip.
    PageProtGlobalInit = 121,
    /// The page prot global finalize chip.
    PageProtGlobalFinalize = 122,
}

impl RiscvAirId {
    /// Returns the AIRs that are not part of precompile shards and not the program or byte AIR.
    #[must_use]
    pub fn core() -> Vec<RiscvAirId> {
        vec![
            RiscvAirId::Add,
            RiscvAirId::AddUser,
            RiscvAirId::Addi,
            RiscvAirId::AddiUser,
            RiscvAirId::Addw,
            RiscvAirId::AddwUser,
            RiscvAirId::Sub,
            RiscvAirId::SubUser,
            RiscvAirId::Subw,
            RiscvAirId::SubwUser,
            RiscvAirId::Mul,
            RiscvAirId::MulUser,
            RiscvAirId::Bitwise,
            RiscvAirId::BitwiseUser,
            RiscvAirId::ShiftLeft,
            RiscvAirId::ShiftLeftUser,
            RiscvAirId::ShiftRight,
            RiscvAirId::ShiftRightUser,
            RiscvAirId::DivRem,
            RiscvAirId::DivRemUser,
            RiscvAirId::Lt,
            RiscvAirId::LtUser,
            RiscvAirId::UType,
            RiscvAirId::UTypeUser,
            RiscvAirId::MemoryLocal,
            RiscvAirId::MemoryBump,
            RiscvAirId::StateBump,
            RiscvAirId::LoadByte,
            RiscvAirId::LoadByteUser,
            RiscvAirId::LoadHalf,
            RiscvAirId::LoadHalfUser,
            RiscvAirId::LoadWord,
            RiscvAirId::LoadWordUser,
            RiscvAirId::LoadDouble,
            RiscvAirId::LoadDoubleUser,
            RiscvAirId::LoadX0,
            RiscvAirId::LoadX0User,
            RiscvAirId::StoreByte,
            RiscvAirId::StoreByteUser,
            RiscvAirId::StoreHalf,
            RiscvAirId::StoreHalfUser,
            RiscvAirId::StoreWord,
            RiscvAirId::StoreWordUser,
            RiscvAirId::StoreDouble,
            RiscvAirId::StoreDoubleUser,
            RiscvAirId::Branch,
            RiscvAirId::BranchUser,
            RiscvAirId::Jal,
            RiscvAirId::JalUser,
            RiscvAirId::Jalr,
            RiscvAirId::JalrUser,
            RiscvAirId::PageProt,
            RiscvAirId::PageProtLocal,
            RiscvAirId::SyscallCore,
            RiscvAirId::SyscallInstrs,
            RiscvAirId::Global,
            RiscvAirId::Mprotect,
            RiscvAirId::InstructionDecode,
            RiscvAirId::InstructionFetch,
        ]
    }

    /// TODO replace these three with subenums or something
    /// Whether the ID represents a core AIR.
    #[must_use]
    pub fn is_core(self) -> bool {
        CoreAirId::try_from(self).is_ok()
    }

    /// Whether the ID represents a memory AIR.
    #[must_use]
    pub fn is_memory(self) -> bool {
        matches!(
            self,
            RiscvAirId::MemoryGlobalInit
                | RiscvAirId::MemoryGlobalFinalize
                | RiscvAirId::Global
                | RiscvAirId::PageProtGlobalInit
                | RiscvAirId::PageProtGlobalFinalize
        )
    }

    /// Whether the ID represents a precompile AIR.
    #[must_use]
    pub fn is_precompile(self) -> bool {
        matches!(
            self,
            RiscvAirId::ShaExtend
                | RiscvAirId::ShaCompress
                | RiscvAirId::EdAddAssign
                | RiscvAirId::EdDecompress
                | RiscvAirId::Secp256k1Decompress
                | RiscvAirId::Secp256k1AddAssign
                | RiscvAirId::Secp256k1DoubleAssign
                | RiscvAirId::Secp256r1Decompress
                | RiscvAirId::Secp256r1AddAssign
                | RiscvAirId::Secp256r1DoubleAssign
                | RiscvAirId::KeccakPermute
                | RiscvAirId::Bn254AddAssign
                | RiscvAirId::Bn254DoubleAssign
                | RiscvAirId::Bls12381AddAssign
                | RiscvAirId::Bls12381DoubleAssign
                | RiscvAirId::Uint256MulMod
                | RiscvAirId::Uint256Ops
                | RiscvAirId::U256XU2048Mul
                | RiscvAirId::Bls12381FpOpAssign
                | RiscvAirId::Bls12381Fp2AddSubAssign
                | RiscvAirId::Bls12381Fp2MulAssign
                | RiscvAirId::Bn254FpOpAssign
                | RiscvAirId::Bn254Fp2AddSubAssign
                | RiscvAirId::Bn254Fp2MulAssign
                | RiscvAirId::Bls12381Decompress
                | RiscvAirId::Poseidon2
        )
    }

    /// The number of rows in the AIR produced by each event.
    #[must_use]
    pub fn rows_per_event(&self) -> usize {
        match self {
            Self::ShaCompress => 80,
            Self::ShaExtend => 48,
            Self::KeccakPermute => 24,
            _ => 1,
        }
    }

    /// Get the ID of the AIR used in the syscall control implementation.
    #[must_use]
    pub fn control_air_id(self, page_protect_enabled: bool) -> Option<RiscvAirId> {
        if page_protect_enabled {
            return match self {
                RiscvAirId::ShaCompress => Some(RiscvAirId::ShaCompressControlUser),
                RiscvAirId::ShaExtend => Some(RiscvAirId::ShaExtendControlUser),
                RiscvAirId::KeccakPermute => Some(RiscvAirId::KeccakPermuteControlUser),
                _ => None,
            };
        }
        match self {
            RiscvAirId::ShaCompress => Some(RiscvAirId::ShaCompressControl),
            RiscvAirId::ShaExtend => Some(RiscvAirId::ShaExtendControl),
            RiscvAirId::KeccakPermute => Some(RiscvAirId::KeccakPermuteControl),
            _ => None,
        }
    }

    /// Returns the string representation of the AIR.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        self.into()
    }
}

impl FromStr for RiscvAirId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let air = Self::iter().find(|chip| chip.as_str() == s);
        match air {
            Some(air) => Ok(air),
            None => Err(format!("Invalid RV64IMAir: {s}")),
        }
    }
}

impl Display for RiscvAirId {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.as_str())
    }
}

/// Defines a set of maximal shapes for generating core proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaximalShapes {
    inner: Vec<EnumMap<CoreAirId, u32>>,
}

impl FromIterator<Shape<RiscvAirId>> for MaximalShapes {
    fn from_iter<T: IntoIterator<Item = Shape<RiscvAirId>>>(iter: T) -> Self {
        let mut maximal_shapes = Vec::new();
        for shape in iter {
            let mut maximal_shape = EnumMap::<CoreAirId, u32>::default();
            for (air, height) in shape {
                if let Ok(core_air) = CoreAirId::try_from(air) {
                    maximal_shape[core_air] = height as u32;
                } else if air != RiscvAirId::Program
                    && air != RiscvAirId::Byte
                    && air != RiscvAirId::Range
                {
                    tracing::warn!("Invalid core air: {air}");
                }
            }
            maximal_shapes.push(maximal_shape);
        }
        Self { inner: maximal_shapes }
    }
}

impl MaximalShapes {
    /// Returns an iterator over the maximal shapes.
    pub fn iter(&self) -> impl Iterator<Item = &EnumMap<CoreAirId, u32>> {
        self.inner.iter()
    }
}
