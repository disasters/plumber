extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int, size_t, ssize_t};
use std::collections::{BTreeMap};
use std::ffi::{CStr};
use std::mem;
use std::str::from_utf8;
use std::sync::{RwLock};

use dynamic::dlsym_next;
use util::{sockaddr_to_port_ip,port_ip_to_sa_data};
use dns::srv_mapper;

pub trait Hook {
    fn connect(&self, socket: c_int, address: *mut sockaddr,
               len: socklen_t) -> c_int;
    fn sendto(&self, socket: c_int, msg: *const c_char, msglen: size_t,
              flags: c_int, dest_addr: *mut sockaddr) -> ssize_t;
    fn getaddrinfo(&self, node: *const c_char, service: *const c_char,
                   hints: *const addrinfo, res: *mut *const addrinfo) -> c_int;
}

#[macro_export]
macro_rules! set_hook {
    ($t:ty : $c:expr) => (
        extern crate libc;
        use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
        use self::libc::{c_char, c_int, size_t, ssize_t};
        use hooks::Hook;

        lazy_static! {
            static ref HOOK : $t = unsafe { $c };
        }

        #[no_mangle]
        pub unsafe fn connect(socket: c_int, address: *mut sockaddr,
                              len: socklen_t) -> c_int {
            HOOK.connect(socket, address, len)
        }

        #[no_mangle]
        pub unsafe fn getaddrinfo(node: *const c_char, service: *const c_char,
                                  hints: *const addrinfo,
                                  res: *mut *const addrinfo) -> c_int {
            HOOK.getaddrinfo(node, service, hints, res)
        }

        #[no_mangle]
        pub unsafe fn sendto(socket: c_int, msg: *const c_char, msglen: size_t,
                             flags: c_int, dest_addr: *mut sockaddr) -> ssize_t {
            HOOK.sendto(socket, msg, msglen, flags, dest_addr)
        }
    )
}
