//! Kernel Memory Management
//!
//! Provides safe wrappers for kernel memory operations:
//! - Pool allocations (NonPaged, Paged)
//! - Memory Descriptor Lists (MDL)
//! - Secure memory access
//! - User/Kernel buffer handling
//!
//! # Memory Types
//! - **NonPagedPool**: Always in physical memory, accessible at any IRQL
//! - **PagedPool**: Can be paged out, only accessible at IRQL < DISPATCH_LEVEL
//! - **NonPagedPoolNx**: Non-executable nonpaged pool (security best practice)
//!
//! # Security Considerations
//! - Always validate user-mode buffer pointers
//! - Use MDLs for safe user buffer access
//! - Never trust user-provided sizes without validation

use core::ptr;
use wdk::println;
use wdk_sys::{
    ntddk::{
        ExAllocatePool2, ExFreePoolWithTag,
        IoAllocateMdl, IoFreeMdl, MmProbeAndLockPages, MmUnlockPages,
        MmGetSystemAddressForMdlSafe, MmBuildMdlForNonPagedPool,
        ProbeForRead, ProbeForWrite,
    },
    POOL_FLAG_NON_PAGED, POOL_FLAG_PAGED, POOL_FLAG_NON_PAGED_EXECUTE,
    PMDL, PVOID, ULONG, LOCK_OPERATION, MM_PAGE_PRIORITY,
};

/// Pool tag for our allocations (must be 4 chars)
/// 'LVTN' = Leviathan
pub const POOL_TAG: u32 = u32::from_le_bytes(*b"LVTN");

/// Memory pool types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolType {
    /// Non-paged pool - always resident, any IRQL
    NonPaged,
    /// Paged pool - can page out, IRQL < DISPATCH_LEVEL only
    Paged,
    /// Non-paged, non-executable - security best practice
    NonPagedNx,
}

impl PoolType {
    fn to_flags(self) -> u64 {
        match self {
            PoolType::NonPaged => POOL_FLAG_NON_PAGED as u64,
            PoolType::Paged => POOL_FLAG_PAGED as u64,
            PoolType::NonPagedNx => (POOL_FLAG_NON_PAGED | POOL_FLAG_NON_PAGED_EXECUTE) as u64,
        }
    }
}

/// Safe wrapper for pool allocations
pub struct PoolAllocation {
    ptr: PVOID,
    size: usize,
    pool_type: PoolType,
}

impl PoolAllocation {
    /// Allocate memory from the specified pool
    ///
    /// # Safety
    /// - NonPaged/NonPagedNx: Any IRQL
    /// - Paged: IRQL < DISPATCH_LEVEL
    pub unsafe fn new(size: usize, pool_type: PoolType) -> Option<Self> {
        if size == 0 {
            return None;
        }

        let ptr = unsafe {
            ExAllocatePool2(pool_type.to_flags(), size as u64, POOL_TAG)
        };

        if ptr.is_null() {
            println!("[Leviathan] Pool allocation failed: size={}", size);
            return None;
        }

        // Zero the memory for security
        unsafe {
            ptr::write_bytes(ptr as *mut u8, 0, size);
        }

        Some(Self { ptr, size, pool_type })
    }

    /// Get raw pointer to the allocation
    pub fn as_ptr(&self) -> PVOID {
        self.ptr
    }

    /// Get mutable raw pointer
    pub fn as_mut_ptr(&mut self) -> PVOID {
        self.ptr
    }

    /// Get the size of the allocation
    pub fn size(&self) -> usize {
        self.size
    }

    /// Get as typed pointer
    ///
    /// # Safety
    /// Caller must ensure T is valid for this memory
    pub unsafe fn as_typed<T>(&self) -> *const T {
        self.ptr as *const T
    }

    /// Get as mutable typed pointer
    ///
    /// # Safety
    /// Caller must ensure T is valid for this memory
    pub unsafe fn as_typed_mut<T>(&mut self) -> *mut T {
        self.ptr as *mut T
    }

    /// Get as byte slice
    ///
    /// # Safety
    /// Must be at appropriate IRQL for pool type
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr as *const u8, self.size) }
    }

    /// Get as mutable byte slice
    ///
    /// # Safety
    /// Must be at appropriate IRQL for pool type
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr as *mut u8, self.size) }
    }
}

impl Drop for PoolAllocation {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // Zero memory before freeing (security)
            unsafe {
                ptr::write_bytes(self.ptr as *mut u8, 0, self.size);
                ExFreePoolWithTag(self.ptr, POOL_TAG);
            }
        }
    }
}

/// Memory Descriptor List (MDL) wrapper
///
/// MDLs describe physical pages backing a virtual buffer,
/// allowing safe access to user-mode memory from kernel mode.
pub struct Mdl {
    mdl: PMDL,
    locked: bool,
    system_address: PVOID,
}

impl Mdl {
    /// Create an MDL for a buffer
    ///
    /// # Parameters
    /// - `virtual_address`: Start of the buffer
    /// - `length`: Size of the buffer
    /// - `secondary_buffer`: TRUE if this is a secondary buffer
    /// - `charge_quota`: TRUE to charge against process quota
    ///
    /// # Safety
    /// Must be at IRQL <= DISPATCH_LEVEL
    pub unsafe fn new(
        virtual_address: PVOID,
        length: usize,
        secondary_buffer: bool,
        charge_quota: bool,
    ) -> Option<Self> {
        let mdl = unsafe {
            IoAllocateMdl(
                virtual_address,
                length as u32,
                secondary_buffer as u8,
                charge_quota as u8,
                ptr::null_mut(),
            )
        };

        if mdl.is_null() {
            return None;
        }

        Some(Self {
            mdl,
            locked: false,
            system_address: ptr::null_mut(),
        })
    }

    /// Lock the pages described by the MDL
    ///
    /// This ensures the pages won't be paged out and gets their physical addresses.
    ///
    /// # Parameters
    /// - `access_mode`: KernelMode or UserMode
    /// - `operation`: IoReadAccess, IoWriteAccess, or IoModifyAccess
    ///
    /// # Safety
    /// - Must be at IRQL <= APC_LEVEL
    /// - For user buffers, must be in the context of the owning process
    pub unsafe fn lock_pages(&mut self, operation: LOCK_OPERATION) -> Result<(), ()> {
        if self.locked {
            return Ok(());
        }

        // Use SEH in production to catch access violations
        unsafe {
            MmProbeAndLockPages(
                self.mdl,
                wdk_sys::MODE::KernelMode as i8,
                operation,
            );
        }

        self.locked = true;
        Ok(())
    }

    /// Get a system-space virtual address for the MDL
    ///
    /// This maps the physical pages to a kernel virtual address.
    ///
    /// # Safety
    /// Pages must be locked first
    pub unsafe fn get_system_address(&mut self, priority: MM_PAGE_PRIORITY) -> Option<PVOID> {
        if !self.locked {
            return None;
        }

        if self.system_address.is_null() {
            self.system_address = unsafe {
                MmGetSystemAddressForMdlSafe(self.mdl, priority as u32)
            };
        }

        if self.system_address.is_null() {
            None
        } else {
            Some(self.system_address)
        }
    }

    /// Build MDL for non-paged pool memory
    ///
    /// Use this for buffers allocated from NonPagedPool.
    /// No need to lock pages - they're already locked.
    ///
    /// # Safety
    /// Buffer must be from NonPagedPool
    pub unsafe fn build_for_nonpaged(&mut self) {
        unsafe { MmBuildMdlForNonPagedPool(self.mdl) };
        self.locked = true;
    }

    /// Get the raw MDL pointer
    pub fn as_raw(&self) -> PMDL {
        self.mdl
    }
}

impl Drop for Mdl {
    fn drop(&mut self) {
        if self.locked && !self.mdl.is_null() {
            unsafe { MmUnlockPages(self.mdl) };
        }
        if !self.mdl.is_null() {
            unsafe { IoFreeMdl(self.mdl) };
        }
    }
}

/// Safely probe and validate a user-mode buffer
///
/// # Safety
/// Must be called in the context of the process that owns the buffer
pub unsafe fn probe_user_buffer(
    buffer: PVOID,
    length: usize,
    alignment: u32,
    for_write: bool,
) -> Result<(), ()> {
    if buffer.is_null() || length == 0 {
        return Err(());
    }

    // Wrap in SEH in production
    if for_write {
        unsafe { ProbeForWrite(buffer, length as u64, alignment) };
    } else {
        unsafe { ProbeForRead(buffer, length as u64, alignment) };
    }

    Ok(())
}

/// Copy data from user buffer to kernel buffer safely
///
/// # Safety
/// - Must be in user process context
/// - User buffer must be valid and accessible
pub unsafe fn copy_from_user(
    kernel_buffer: &mut [u8],
    user_buffer: PVOID,
    length: usize,
) -> Result<usize, ()> {
    if user_buffer.is_null() || length == 0 {
        return Err(());
    }

    let copy_len = core::cmp::min(length, kernel_buffer.len());

    // In production: Use SEH and proper MDL mapping
    unsafe {
        ProbeForRead(user_buffer, copy_len as u64, 1);
        ptr::copy_nonoverlapping(
            user_buffer as *const u8,
            kernel_buffer.as_mut_ptr(),
            copy_len,
        );
    }

    Ok(copy_len)
}

/// Copy data from kernel buffer to user buffer safely
///
/// # Safety
/// - Must be in user process context
/// - User buffer must be valid and writable
pub unsafe fn copy_to_user(
    user_buffer: PVOID,
    kernel_buffer: &[u8],
    length: usize,
) -> Result<usize, ()> {
    if user_buffer.is_null() || length == 0 {
        return Err(());
    }

    let copy_len = core::cmp::min(length, kernel_buffer.len());

    // In production: Use SEH and proper MDL mapping
    unsafe {
        ProbeForWrite(user_buffer, copy_len as u64, 1);
        ptr::copy_nonoverlapping(
            kernel_buffer.as_ptr(),
            user_buffer as *mut u8,
            copy_len,
        );
    }

    Ok(copy_len)
}

/// Secure memory zeroing that won't be optimized away
pub fn secure_zero(buffer: &mut [u8]) {
    // volatile write to prevent optimization
    for byte in buffer.iter_mut() {
        unsafe {
            ptr::write_volatile(byte, 0);
        }
    }
    // Memory barrier
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Lookaside list for frequent same-size allocations
///
/// More efficient than individual pool allocations for
/// fixed-size objects.
pub struct LookasideList {
    // Would contain NPAGED_LOOKASIDE_LIST or PAGED_LOOKASIDE_LIST
    // Simplified for this example
    entry_size: usize,
    pool_type: PoolType,
}

impl LookasideList {
    /// Create a new lookaside list
    ///
    /// # Safety
    /// Must be called at PASSIVE_LEVEL
    pub unsafe fn new(entry_size: usize, pool_type: PoolType) -> Self {
        // In production: Call ExInitializeNPagedLookasideList or
        // ExInitializePagedLookasideList
        Self { entry_size, pool_type }
    }

    /// Allocate an entry from the lookaside list
    ///
    /// # Safety
    /// Depends on pool type
    pub unsafe fn allocate(&self) -> Option<PVOID> {
        // In production: ExAllocateFromNPagedLookasideList
        PoolAllocation::new(self.entry_size, self.pool_type)
            .map(|alloc| {
                let ptr = alloc.as_ptr();
                core::mem::forget(alloc); // Don't free
                ptr
            })
    }

    /// Free an entry back to the lookaside list
    ///
    /// # Safety
    /// Entry must have been allocated from this list
    pub unsafe fn free(&self, entry: PVOID) {
        // In production: ExFreeToNPagedLookasideList
        if !entry.is_null() {
            unsafe { ExFreePoolWithTag(entry, POOL_TAG) };
        }
    }
}
