#![feature(libc)]
extern crate libc;
use libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use libc::{c_char, c_int, c_void};
use std::mem;

#[link(name="dl")]
extern {
    fn dlsym(handle: *const c_void, symbol: *const c_char) -> *const c_void;
}
const RTLD_NEXT: *const c_void = -1isize as *const c_void;
pub unsafe fn dlsym_next(symbol: &'static str) -> *const u8 {
    let ptr = dlsym(RTLD_NEXT, symbol.as_ptr() as *const c_char);
    if ptr.is_null() {
        panic!("discotech: Unable to find underlying function for {}", symbol);
    }
    ptr as *const u8
}

#[no_mangle]
pub unsafe extern "C" fn connect(socket: c_int, address: *const sockaddr,
                           len: socklen_t) -> c_int {
    println!("HOOKING CONNECT!!!!!!!!!!!!!!!!!");
    let ptr = dlsym_next("connect");
    let f: fn(c_int, *const sockaddr, socklen_t) -> c_int = mem::transmute(ptr);
    f(socket, address, len)
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(node: *const c_char, service: *const c_char,
               hints: *const addrinfo, res: *const *const addrinfo) -> c_int {
    println!("HOOKING getaddrinfo!!!!!!!!!!!!!!!!!");
    let ptr = dlsym_next("getaddrinfo");
    let f: fn(*const c_char, *const c_char, *const addrinfo,
              *const *const addrinfo) -> c_int = mem::transmute(ptr);
    f(node, service, hints, res)
}
