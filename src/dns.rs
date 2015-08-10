extern crate libc;
use self::libc::{c_char, c_int};
use std::ffi::{CString, CStr};
use std::str::from_utf8;

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

#[link(name = "resolv")]
extern {
    pub fn __res_query(dname: *const c_char, class: c_int, typef: c_int,
               answer: *const u8, anslen: c_int) -> c_int;
}

fn query(dname: &str, class: Class, typef: Type) -> Result<&str, Rcode> {
    let dname = CString::new("_leader._tcp.mesos").unwrap();
    let ans: *const u8 = &[0u8;1024] as *const u8;
    println!("ans addr is {:?}", ans);
    unsafe {
        let r = __res_query(dname.as_ptr(), 1, 33,
                           ans, 1024);
        println!("res_query -> {:?}", r);
    }
    Err(Rcode::NotImplemented)
}

#[test]
fn test_query() {
    let r = query("_leader._tcp.mesos", Class::INET, Type::SRV);
    println!("result: {:?}", r);
}
