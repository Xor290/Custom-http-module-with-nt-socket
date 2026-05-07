use crate::types::*;
use crate::utils::{get_module_by_peb, get_peb, hash_utf16_lower};
use core::ffi::c_void;

pub const SECBUFFER_DATA: u32 = 0x0000_0001;
pub const HASH_NT_CREATE_FILE: u32 = hash_str("NtCreateFile");
pub const HASH_NT_DEVICE_IO: u32 = hash_str("NtDeviceIoControlFile");
pub const HASH_NTDLL: u32 = hash_str("ntdll.dll");
pub const HASH_SCHANNEL: u32 = hash_str("schannel.dll");
pub const HASH_INITIALIZE_SECURITY_CONTEXT: u32 = hash_str("InitializeSecurityContextW");
pub const HASH_ACQUIRE_CREDENTIALS: u32 = hash_str("AcquireCredentialsHandleW");
pub const HASH_FREE_CREDENTIALS: u32 = hash_str("FreeCredentialsHandle");
pub const HASH_DELETE_SECURITY_CONTEXT: u32 = hash_str("DeleteSecurityContext");
pub const HASH_ENCRYPT_MESSAGE: u32 = hash_str("EncryptMessage");
pub const HASH_DECRYPT_MESSAGE: u32 = hash_str("DecryptMessage");

pub type FnNtCreateFile = unsafe extern "system" fn(
    *mut *mut c_void,
    u64,
    *mut OBJECT_ATTRIBUTES,
    *mut IO_STATUS_BLOCK,
    *mut c_void,
    u32,
    u32,
    u32,
    u32,
    *mut c_void,
    u32,
) -> i32;

pub type FnNtDeviceIoControlFile = unsafe extern "system" fn(
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut IO_STATUS_BLOCK,
    u32,
    *mut c_void,
    u32,
    *mut c_void,
    u32,
) -> i32;

pub const fn hash_str(s: &str) -> u32 {
    let bytes = s.as_bytes();
    let mut hash: u32 = 0x811c9dc5;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u32;
        hash = hash.wrapping_mul(0x01000193);
        i += 1;
    }
    hash
}

pub unsafe fn get_proc_by_hash(module: *mut c_void, target: u32) -> Option<*mut c_void> {
    unsafe {
        let base = module as *const u8;

        let e_lfanew = (base.add(0x3C) as *const u32).read_unaligned() as usize;
        let nt = base.add(e_lfanew);

        let magic = (nt.add(0x18) as *const u16).read_unaligned();
        let (export_dir_rva_offset, export_dir_size_offset) = if magic == 0x020B {
            (0x88usize, 0x8Cusize)
        } else {
            (0x78usize, 0x7Cusize)
        };

        let export_rva = (nt.add(export_dir_rva_offset) as *const u32).read_unaligned() as usize;
        let export_size = (nt.add(export_dir_size_offset) as *const u32).read_unaligned() as usize;
        if export_rva == 0 {
            return None;
        }

        let exp = base.add(export_rva);
        let num_names = (exp.add(0x18) as *const u32).read_unaligned() as usize;
        let names_rva = (exp.add(0x20) as *const u32).read_unaligned() as usize;
        let ordinals_rva = (exp.add(0x24) as *const u32).read_unaligned() as usize;
        let functions_rva = (exp.add(0x1C) as *const u32).read_unaligned() as usize;

        for i in 0..num_names {
            let name_rva = (base.add(names_rva + i * 4) as *const u32).read_unaligned() as usize;
            let name_ptr = base.add(name_rva);

            let mut len = 0usize;
            while *name_ptr.add(len) != 0 {
                len += 1;
            }

            let name_slice = core::slice::from_raw_parts(name_ptr, len);
            let name_str = core::str::from_utf8_unchecked(name_slice);

            if hash_str(name_str) == target {
                let ord = (base.add(ordinals_rva + i * 2) as *const u16).read_unaligned() as usize;
                let fn_rva =
                    (base.add(functions_rva + ord * 4) as *const u32).read_unaligned() as usize;

                if fn_rva >= export_rva && fn_rva < export_rva + export_size {
                    return None;
                }

                return Some(base.add(fn_rva) as *mut c_void);
            }
        }

        None
    }
}
