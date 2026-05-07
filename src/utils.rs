use crate::types::{LDR_DATA_TABLE_ENTRY, LIST_ENTRY, PEB, UNICODE_STRING};
use core::ffi::c_void;
use core::slice;

#[cfg(target_arch = "x86_64")]
use core::arch::asm;
#[cfg(target_arch = "x86")]
use core::arch::asm;

#[cfg(target_arch = "x86_64")]
#[inline(always)]
pub fn get_peb() -> *mut c_void {
    let peb: *mut c_void;
    unsafe {
        asm!("mov {}, gs:[0x60]", lateout(reg) peb, options(nostack, pure, readonly));
    }
    peb
}

#[cfg(target_arch = "x86")]
#[inline(always)]
pub fn get_peb() -> *mut c_void {
    let peb: *mut c_void;
    unsafe {
        asm!("mov {}, fs:[0x30]", lateout(reg) peb, options(nostack, pure, readonly));
    }
    peb
}

unsafe fn unicode_to_slice(u: &UNICODE_STRING) -> &[u16] {
    unsafe {
        if u.buffer.is_null() || u.length == 0 {
            return &[];
        }
        slice::from_raw_parts(u.buffer, (u.length / 2) as usize)
    }
}

pub fn hash_utf16_lower(s: &[u16]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &c in s {
        let b = match c {
            0x41..=0x5A => (c + 0x20) as u8,
            _ => c as u8,
        };
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

pub unsafe fn get_module_by_peb(peb: *mut c_void, name: &[u8]) -> *mut c_void {
    unsafe {
        let name = if name.last() == Some(&0) {
            &name[..name.len() - 1]
        } else {
            name
        };

        let peb = peb as *mut PEB;
        if peb.is_null() {
            return core::ptr::null_mut();
        }
        let ldr = (*peb).ldr;
        if ldr.is_null() {
            return core::ptr::null_mut();
        }

        let head = &mut (*ldr).in_memory_order_module_list as *mut LIST_ENTRY;
        let mut cur = (*head).flink;

        while !cur.is_null() && cur != head {
            let entry = (cur as usize
                - core::mem::offset_of!(LDR_DATA_TABLE_ENTRY, in_memory_order_links))
                as *mut LDR_DATA_TABLE_ENTRY;

            let mod_name = unicode_to_slice(&(*entry).base_dll_name);

            if mod_name.len() == name.len()
                && mod_name.iter().zip(name.iter()).all(|(&wc, &bc)| {
                    let a = if wc >= 0x41 && wc <= 0x5A {
                        wc + 0x20
                    } else {
                        wc
                    } as u8;
                    let b = if bc >= b'A' && bc <= b'Z' {
                        bc + 0x20
                    } else {
                        bc
                    };
                    a == b
                })
            {
                return (*entry).dll_base;
            }

            cur = (*cur).flink;
        }
        core::ptr::null_mut()
    }
}

pub unsafe fn get_module_by_hash(target: u32) -> Option<*mut c_void> {
    use crate::utils::hash_utf16_lower;
    use core::arch::asm;

    let peb: *mut u8;
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    if peb.is_null() {
        return None;
    }

    let ldr = *(peb.add(0x18) as *const *mut u8);
    if ldr.is_null() {
        return None;
    }

    let head = ldr.add(0x20) as *mut usize;
    let mut cur = *head as *mut u8;

    let mut count = 0usize;
    loop {
        let entry = cur.sub(0x10);

        let len = *(entry.add(0x58) as *const u16);
        let buf = *(entry.add(0x60) as *const *const u16);

        if len > 0 && len < 512 && !buf.is_null() {
            let slice = core::slice::from_raw_parts(buf, (len / 2) as usize);
            if hash_utf16_lower(slice) == target {
                let dll_base = *(entry.add(0x30) as *const *mut c_void);
                return Some(dll_base);
            }
        }

        let next = *(cur as *const *mut u8);
        if next as usize == head as usize || next.is_null() {
            break;
        }
        cur = next;

        count += 1;
        if count > 256 {
            break;
        }
    }
    None
}
