extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int};

use serverset::Serverset;

lazy_static! {
    static ref SS: Serverset = unsafe { Serverset::new() };
}

#[no_mangle]
pub unsafe fn connect(socket: c_int, address: *mut sockaddr,
                      len: socklen_t) -> c_int {
    SS.connect(socket, address, len)
}

#[no_mangle]
pub unsafe fn getaddrinfo(node: *const c_char, service: *const c_char,
                          hints: *const addrinfo,
                          res: *mut *const addrinfo) -> c_int {
    SS.getaddrinfo(node, service, hints, res)
}
