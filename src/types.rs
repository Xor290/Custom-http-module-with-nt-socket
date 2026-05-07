use core::ffi::c_void;

#[repr(C)]
pub struct AfdCreatePacket {
    pub endpoint_flags: u32,
    pub group_id: u64,
    pub address_family: u16, // AF_INET = 2
    pub socket_type: u16,    // SOCK_STREAM = 1
    pub protocol: u16,       // IPPROTO_TCP = 6
    pub transport_name: [u16; 16],
}

#[repr(C)]
pub struct SockAddrIn {
    pub sin_family: u16,
    pub sin_port: u16,
    pub sin_addr: [u8; 4],
    pub sin_zero: [u8; 8],
}

impl SockAddrIn {
    pub fn new(ip: [u8; 4], port: u16) -> Self {
        SockAddrIn {
            sin_family: 2,
            sin_port: port.to_be(),
            sin_addr: ip,
            sin_zero: [0; 8],
        }
    }
}

#[repr(C)]
pub struct AfdBufX64 {
    pub len: u32,
    pub _pad: u32,
    pub buf: *mut u8,
}

#[repr(C)]
pub struct AfdRecvInfoX64 {
    pub buf_array: *mut AfdBufX64,
    pub buf_count: u32,
    pub afd_flags: u32,
    pub tdi_flags: u32,
    pub _pad: u32,
}

#[repr(C)]
pub struct PEB {
    pub inherited_address_space: u8,
    pub read_image_file_exec_options: u8,
    pub being_debugged: u8,
    pub _bit_field: u8,
    pub _pad1: [u8; 4],
    pub mutant: *mut c_void,
    pub image_base_address: *mut c_void,
    pub ldr: *mut PEB_LDR_DATA,
}

unsafe impl Send for PEB {}
unsafe impl Sync for PEB {}

#[repr(C)]
pub struct PEB_LDR_DATA {
    pub length: u32,
    pub initialized: u8,
    pub _pad: [u8; 3],
    pub ss_handle: *mut c_void,
    pub in_load_order_module_list: LIST_ENTRY,
    pub in_memory_order_module_list: LIST_ENTRY,
    pub in_initialization_order_module_list: LIST_ENTRY,
}

#[repr(C)]
pub struct LIST_ENTRY {
    pub flink: *mut LIST_ENTRY,
    pub blink: *mut LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub in_load_order_links: LIST_ENTRY,
    pub in_memory_order_links: LIST_ENTRY,
    pub in_initialization_order_links: LIST_ENTRY,
    pub dll_base: *mut c_void,
    pub entry_point: *mut c_void,
    pub size_of_image: u32,
    pub _pad: u32,
    pub full_dll_name: UNICODE_STRING,
    pub base_dll_name: UNICODE_STRING,
}

unsafe impl Send for LDR_DATA_TABLE_ENTRY {}
unsafe impl Sync for LDR_DATA_TABLE_ENTRY {}

#[repr(C)]
pub struct UNICODE_STRING {
    pub length: u16,
    pub maximum_length: u16,
    pub _padding: u32,
    pub buffer: *mut u16,
}

#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub length: u32,
    pub root_directory: *mut c_void,
    pub object_name: *mut UNICODE_STRING,
    pub attributes: u32,
    pub security_descriptor: *mut c_void,
    pub security_quality_of_service: *mut c_void,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
    pub status: i64,
    pub information: usize,
}

#[repr(C)]
pub struct SecBuffer {
    pub cb_buffer: u32,
    pub buffer_type: u32,
    pub pv_buffer: *mut c_void,
}

#[repr(C)]
pub struct SecBufferDesc {
    pub ul_version: u32,
    pub c_buffers: u32,
    pub p_buffers: *mut SecBuffer,
}

#[repr(C)]
pub struct WSABuffer {
    pub len: u32,
    pub buf: *mut u8,
}
