extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int};
use std::mem;
use std::ffi::{CString, CStr};
use std::str::from_utf8;

use dynamic::dlsym_next;
use serverset::get_serverset;

fn sockaddr_to_port_ip(address: *mut sockaddr) -> (u16, [u8;4]) {
    let data = unsafe { (*address).sa_data };
    ((data[0] as u16) << 8 | (data[1] as u16),
     [data[2], data[3], data[4], data[5]])
}

fn port_ip_to_sa_data(port: u16, ip: [u8;4]) -> [u8; 14] {
    let mut sa_data: [u8; 14] = [0; 14];
    sa_data[0] = (port >> 8) as u8;
    sa_data[1] = port as u8;
    sa_data[2] = ip[0];
    sa_data[3] = ip[1];
    sa_data[4] = ip[2];
    sa_data[5] = ip[3];
    sa_data
}

#[no_mangle]
pub unsafe extern "C" fn connect(socket: c_int, address: *mut sockaddr,
                           len: socklen_t) -> c_int {
    println!("connect pre-hook: {:?}", sockaddr_to_port_ip(address));
    if (*address).sa_data[1] == 79 {
        (*address).sa_data[1] = 80;
    }
    println!("connect post-hook: {:?}", sockaddr_to_port_ip(address));
    //let ss = get_serverset();
    let ptr = dlsym_next("connect");
    let f: fn(c_int, *const sockaddr, socklen_t) -> c_int = mem::transmute(ptr);
    f(socket, address, len)
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(mut node: *const c_char, service: *const c_char,
               hints: *const addrinfo, res: *const *const addrinfo) -> c_int {
    let c_str = unsafe { CStr::from_ptr(node) };
    let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
    println!("getaddrinfo pre-hook: node: {:?} service: {:?}", s, service);

    let new_host = CString::new("google.com".as_bytes()).unwrap();
    node = new_host.as_ptr();
    //let ss = get_serverset();

    let ptr = dlsym_next("getaddrinfo");
    let f: fn(*const c_char, *const c_char, *const addrinfo,
              *const *const addrinfo) -> c_int = mem::transmute(ptr);
    f(node, service, hints, res)
}
