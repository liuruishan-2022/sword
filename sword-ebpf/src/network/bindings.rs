#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use aya_ebpf::cty::{c_int, c_uchar, c_uint, c_ulonglong, c_ushort, c_void};

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
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,
}
