#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use aya_ebpf::cty::{c_int, c_uchar, c_uint, c_ulong, c_ulonglong, c_ushort, c_void};

pub type __u8 = c_uchar;
pub type __u16 = c_ushort;
pub type __u32 = c_uint;
pub type __u64 = c_ulonglong;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type __addrpair = __u64;
pub type __portpair = __u32;

#[repr(C)]
#[derive(Copy, Clone)]
pub union in6_addr__bindgen_ty_1 {
    pub u6_addr8: [__u8; 16usize],
    pub u6_addr16: [__be16; 8usize],
    pub u6_addr32: [__be32; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub in6_u: in6_addr__bindgen_ty_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_ty_1 {
    pub skc_addrpair: __addrpair,
    pub __bindgen_anon_1: sock_common__bindgen_ty_1__bindgen_ty_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common__bindgen_ty_1__bindgen_ty_1 {
    pub skc_daddr: __be32,
    pub skc_rcv_saddr: __be32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_ty_2 {
    pub skc_hash: c_uint,
    pub skc_u16hashes: [__u16; 2usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_ty_3 {
    pub skc_portpair: __portpair,
    pub __bindgen_anon_1: sock_common__bindgen_ty_3__bindgen_ty_1,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common__bindgen_ty_3__bindgen_ty_1 {
    pub skc_dport: __be16,
    pub skc_num: __u16,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct possible_net_t {
    pub net: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct atomic_t {
    pub counter: c_int,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct refcount_t {
    pub refs: atomic_t,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sk_buff_head {
    pub next: *mut c_void,
    pub prev: *mut c_void,
    pub qlen: __u32,
    pub lock: [u8; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_backlog {
    pub rmem_alloc: atomic_t,
    pub len: c_int,
    pub head: *mut c_void,
    pub tail: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common {
    pub __bindgen_anon_1: sock_common__bindgen_ty_1,
    pub __bindgen_anon_2: sock_common__bindgen_ty_2,
    pub __bindgen_anon_3: sock_common__bindgen_ty_3,
    pub skc_family: c_ushort,
    pub skc_state: c_uchar,
    pub _bitfield_1: c_uchar,
    pub skc_bound_dev_if: c_int,
    pub __bindgen_anon_4: [u64; 2usize],
    pub skc_prot: *mut c_void,
    pub skc_net: possible_net_t,
    pub skc_v6_daddr: in6_addr,
    pub skc_v6_rcv_saddr: in6_addr,
    pub __bindgen_padding_0: [u8; 48usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,
    pub sk_rx_dst: *mut c_void,
    pub sk_rx_dst_ifindex: c_int,
    pub sk_rx_dst_cookie: __u32,
    pub __bindgen_padding_0: [u8; 32usize],
    pub sk_drops: atomic_t,
    pub sk_rcvlowat: c_int,
    pub sk_error_queue: sk_buff_head,
    pub sk_receive_queue: sk_buff_head,
    pub sk_backlog: sock_backlog,
    pub sk_forward_alloc: c_int,
    pub sk_reserved_mem: __u32,
    pub sk_ll_usec: c_uint,
    pub sk_napi_id: c_uint,
    pub sk_rcvbuf: c_int,
    pub sk_disconnects: c_int,
    pub sk_filter: *mut c_void,
    pub sk_wq: *mut c_void,
    pub sk_policy: [*mut c_void; 2usize],
    pub sk_dst_cache: *mut c_void,
    pub sk_omem_alloc: atomic_t,
    pub sk_sndbuf: c_int,
    pub sk_wmem_queued: c_int,
    pub sk_wmem_alloc: refcount_t,
    pub sk_tsq_flags: c_ulong,
    pub sk_send_head: *mut c_void,
    pub sk_write_queue: sk_buff_head,
}
