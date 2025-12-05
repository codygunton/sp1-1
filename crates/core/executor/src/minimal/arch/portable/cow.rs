use hashbrown::{
    hash_map::Entry::{Occupied as HBOccupied, Vacant as HBVacant},
    hash_map::{DefaultHashBuilder, Entry as HBEntry},
    HashMap,
};

use sp1_jit::PageProtValue;

use crate::memory::{Entry, PagedMemory};

/// A memory backed by [`PagedMemory`], which can be in either owned or COW mode.
pub enum MaybeCowMemory<T: Copy> {
    Cow { copy: PagedMemory<T>, original: PagedMemory<T> },
    Owned { memory: PagedMemory<T> },
}

impl<T: Copy> MaybeCowMemory<T> {
    /// Create a new owned memory.
    pub fn new_owned() -> Self {
        Self::Owned { memory: PagedMemory::default() }
    }

    /// Create a new cow memory.
    pub fn new_cow(original: PagedMemory<T>) -> Self {
        Self::Cow { copy: PagedMemory::default(), original }
    }

    /// Initialize the cow memory.
    ///
    /// If the memory is already in COW mode, this is a no-op.
    pub fn copy_on_write(&mut self) {
        match self {
            Self::Cow { .. } => {}
            Self::Owned { memory } => {
                *self = Self::new_cow(std::mem::take(memory));
            }
        }
    }

    /// Convert the memory to owned mode, discarding any of the memory in the COW.
    pub fn owned(&mut self) {
        match self {
            Self::Cow { copy: _, original } => {
                *self = Self::Owned { memory: std::mem::take(original) };
            }
            Self::Owned { .. } => {}
        }
    }

    /// Get a value from the memory.
    pub fn get(&self, addr: u64) -> Option<&T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original } => copy.get(addr).or_else(|| original.get(addr)),
            Self::Owned { memory } => memory.get(addr),
        }
    }

    /// Get a view of the keys of the memory.
    pub fn keys(&self) -> impl Iterator<Item = u64> + '_ {
        match self {
            Self::Cow { copy: _, original: _ } => unreachable!("Can't get keys of a cow memory"),
            Self::Owned { memory } => memory.keys(),
        }
    }

    /// Get an entry for the given address.
    pub fn entry(&mut self, addr: u64) -> Entry<'_, T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        // First we ensure that the copy has the value, if it exisits in the original.
        match self {
            Self::Cow { copy, original } => match copy.entry(addr) {
                Entry::Vacant(entry) => {
                    if let Some(value) = original.get(addr) {
                        entry.insert(*value);
                    }
                }
                Entry::Occupied(_) => {}
            },
            Self::Owned { .. } => {}
        }

        match self {
            Self::Cow { copy, original: _ } => copy.entry(addr),
            Self::Owned { memory } => memory.entry(addr),
        }
    }

    /// Insert a value into the memory.
    pub fn insert(&mut self, addr: u64, value: T) -> Option<T> {
        assert!(addr.is_multiple_of(8), "Address must be a multiple of 8");

        match self {
            Self::Cow { copy, original: _ } => copy.insert(addr, value),
            Self::Owned { memory } => memory.insert(addr, value),
        }
    }
}

/// A page prot, which can be in either owned or COW mode.
pub enum MaybeCowPageProt {
    /// `HashMap` for page protection in COW mode.
    Cow {
        /// The copy of the `HashMap`.
        copy: HashMap<u64, PageProtValue>,
        /// The original `HashMap`.
        original: HashMap<u64, PageProtValue>,
    },
    /// `HashMap` for page protection in owned mode.
    Owned {
        /// The page protection status for each page.
        page_prot: HashMap<u64, PageProtValue>,
    },
}

impl MaybeCowPageProt {
    /// Create a new cow page prot.
    #[must_use]
    pub fn new_cow(original: HashMap<u64, PageProtValue>) -> Self {
        Self::Cow { copy: HashMap::default(), original }
    }

    /// Initialize the cow page prot.
    ///
    /// If the page prot is already in COW mode, this is a no-op.
    pub fn copy_on_write(&mut self) {
        match self {
            Self::Cow { .. } => {}
            Self::Owned { page_prot } => {
                *self = Self::new_cow(std::mem::take(page_prot));
            }
        }
    }

    /// Convert the page prot to owned mode, discarding any of the page prot in the COW.
    pub fn owned(&mut self) {
        match self {
            Self::Cow { copy: _, original } => {
                *self = Self::Owned { page_prot: std::mem::take(original) };
            }
            Self::Owned { .. } => {}
        }
    }

    /// Get an entry for the given address.
    pub fn entry(&mut self, page_idx: u64) -> HBEntry<'_, u64, PageProtValue, DefaultHashBuilder> {
        // First we ensure that the copy has the value, if it exisits in the original.
        match self {
            Self::Cow { copy, original } => match copy.entry(page_idx) {
                HBVacant(entry) => {
                    if let Some(value) = original.get(&page_idx) {
                        entry.insert(*value);
                    }
                }
                HBOccupied(_) => {}
            },
            Self::Owned { .. } => {}
        }

        match self {
            Self::Cow { copy, original: _ } => copy.entry(page_idx),
            Self::Owned { page_prot } => page_prot.entry(page_idx),
        }
    }

    /// Get a value from the page prot.
    #[must_use]
    pub fn get(&self, page_idx: u64) -> Option<&PageProtValue> {
        match self {
            Self::Cow { copy, original } => copy.get(&page_idx).or_else(|| original.get(&page_idx)),
            Self::Owned { page_prot } => page_prot.get(&page_idx),
        }
    }

    /// Insert a value into the memory.
    pub fn insert(&mut self, page_idx: u64, value: PageProtValue) -> Option<PageProtValue> {
        match self {
            Self::Cow { copy, original: _ } => copy.insert(page_idx, value),
            Self::Owned { page_prot } => page_prot.insert(page_idx, value),
        }
    }

    /// Get a view of the keys of the page prot.
    pub fn keys(&self) -> impl Iterator<Item = &u64> {
        match self {
            Self::Cow { copy: _, original: _ } => unreachable!("Can't get keys of a cow page prot"),
            Self::Owned { page_prot } => page_prot.keys(),
        }
    }
}

impl From<HashMap<u64, PageProtValue>> for MaybeCowPageProt {
    fn from(page_prot: HashMap<u64, PageProtValue>) -> Self {
        Self::Owned { page_prot }
    }
}
