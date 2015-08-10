extern crate libc;
use self::libc::{c_char, c_int};
use std::ffi::{CString, CStr};
use std::str::from_utf8;

#[link(name = "resolv")]
extern {
    pub fn __res_query(dname: *const c_char, class: c_int, typef: c_int,
               answer: *const u8, anslen: c_int) -> c_int;
}

#[test]
fn query() {
    let dname = CString::new("_leader._tcp.mesos").unwrap();
    let ans: *const u8 = 0 as *const u8;
    let class: c_int = 33;
    let typef: c_int = 33;
    unsafe {
        let r = __res_query(dname.as_ptr(), class, typef,
                           ans, 1);
        println!("res_query -> {:?}", r);
    }
}
