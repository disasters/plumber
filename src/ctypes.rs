extern crate libc;
use self::libc::{c_char, c_int};

#[derive(PartialEq,Debug,Clone)]
pub enum Type {
	// valid dnsRR_Header.Rrtype and dnsQuestion.qtype
	A     = 1,
	NS    = 2,
	MD    = 3,
	MF    = 4,
	CNAME = 5,
	SOA   = 6,
	MB    = 7,
	MG    = 8,
	MR    = 9,
	NULL  = 10,
	WKS   = 11,
	PTR   = 12,
	HINFO = 13,
	MINFO = 14,
	MX    = 15,
	TXT   = 16,
	AAAA  = 28,
	SRV   = 33,

	// valid dnsQuestion.qtype only
	AXFR  = 252,
	MAILB = 253,
	MAILA = 254,
	ALL   = 255,
}

#[derive(PartialEq,Debug,Clone)]
pub enum Class {
	// valid dnsQuestion.qclass
	INET   = 1,
	CSNET  = 2,
	CHAOS  = 3,
	HESIOD = 4,
	ANY    = 255,
}

#[derive(PartialEq,Debug,Clone)]
pub enum Rcode {
	// dnsMsg.rcode
	Success        = 0,
	FormatError    = 1,
	ServerFailure  = 2,
	NameError      = 3,
	NotImplemented = 4,
	Refused        = 5,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum ns_sect_q {
    ns_s_qd = 0,        /* Query: Question. */
    ns_s_an = 1,        /* Query: Answer. */
    ns_s_ns = 2,        /* Query: Name servers. */
    ns_s_ar = 3,        /* Query|Update: Additional records. */
    ns_s_max = 4
}

#[repr(C)]
pub struct ns_rr {
    pub name: [u8;1025],
    pub typef: u16,
    pub rr_class: u16,
    pub ttl: u32,
    pub rdlength: u16,
    pub rdata: *const u8,
}

impl Default for ns_rr {
    fn default() -> ns_rr {
        ns_rr {
            name: [0u8;1025],
            typef: 0,
            rr_class: 0,
            ttl: 0,
            rdlength: 0,
            rdata: 0 as *const u8,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ns_msg {
    pub msg: *const u8,
    pub eom: *const u8,
    pub id: u16,
    pub flags: u16,
    pub counts: [u16;4],
    pub sections: [*const u8;4],
    pub sect: ns_sect_q,
    pub rrnum: c_int,
    pub msg_ptr: *const u8,
}

impl Default for ns_msg {
    fn default() -> ns_msg {
        ns_msg {
            msg: 0 as *const u8,
            eom: 0 as *const u8,
            id: 0,
            flags: 0,
            counts: [0,0,0,0],
            sections: [0 as *const u8, 0 as *const u8, 0 as *const u8, 0 as *const u8],
            sect: ns_sect_q::ns_s_qd,
            rrnum: 0,
            msg_ptr: 0 as *const u8,
        }
    }
}
