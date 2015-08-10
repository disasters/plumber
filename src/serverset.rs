extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int};
use std::collections::BTreeMap;
use std::ffi::{CString, CStr};
use std::mem;
use std::str::from_utf8;
use std::sync::{Arc, Mutex};

use chain::Chain;
use dynamic::dlsym_next;
use util::{sockaddr_to_port_ip,port_ip_to_sa_data};

pub struct ConnectArgs {
    socket: c_int,
    address: *mut sockaddr,
    len: socklen_t,
}

pub type ConnectRet = c_int;

pub struct GetaddrinfoArgs {
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *const *const addrinfo,
}

pub type GetaddrinfoRet = c_int;

fn host_mapper(host: String) -> Option<(u16, [u8;4])> {
    None
    //Some((8080, [127,127,127,127]))
}

fn ip_mapper(ip: [u8; 4]) -> (u16, [u8;4]) {
    (8080, [127,127,127,127])
}

pub struct Serverset {
    host_to_magic_ip: Arc<Mutex<BTreeMap<String, [u8;4]>>>,
    magic_ip_to_fetcher: Arc<Mutex<BTreeMap<[u8; 4], fn ([u8; 4]) -> (u16, [u8; 4])>>>,
    real_connect: unsafe extern "C" fn(c_int,
                                       *const sockaddr, socklen_t) -> c_int,
    real_getaddrinfo: unsafe extern "C" fn(node: *const c_char,
                              service: *const c_char,
                              hints: *const addrinfo,
                              res: *const *const addrinfo) -> c_int,
}

impl Serverset {
    pub unsafe fn new() -> Serverset {
        Serverset{
            host_to_magic_ip: Arc::new(Mutex::new(BTreeMap::new())),
            magic_ip_to_fetcher: Arc::new(Mutex::new(BTreeMap::new())),
            real_connect:
                mem::transmute(dlsym_next("connect\0").unwrap()),
            real_getaddrinfo:
                mem::transmute(dlsym_next("getaddrinfo\0").unwrap()),
        }
    }

    pub fn connect(&self, socket: c_int, address: *mut sockaddr,
                   len: socklen_t) -> c_int {
        Chain::Args(ConnectArgs{
            socket: socket,
            address: address,
            len: len,
        }).map( |a| {
            let (port, ip) = sockaddr_to_port_ip(a.address);
            self.magic_ip_to_fetcher.lock().unwrap().get(&ip).map( |f| {
                let (new_port, new_ip) = f(ip);
                unsafe {
                    (*a.address).sa_data = port_ip_to_sa_data(new_port, new_ip);
                }
            });
            Chain::Args(a)
        }).unwrap_or( |a| {
            unsafe {
                (self.real_connect)(a.socket, a.address, a.len)
            }
        })
    }

    pub fn getaddrinfo(&self, mut node: *const c_char, service: *const c_char,
                   hints: *const addrinfo, res: *const *const addrinfo) -> c_int {
        Chain::Args(GetaddrinfoArgs {
            node: node,
            service: service,
            hints: hints,
            res: res,
        }).map( |a| {
            let c_str = unsafe { CStr::from_ptr(node) };
            let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
            println!("getaddrinfo pre-hook: node: {:?} service: {:?}", s, service);
            host_mapper(s).map_or(Chain::Args(a), |port_ip| {
                self.magic_ip_to_fetcher.lock().unwrap().insert([127,0,0,1], ip_mapper);
                Chain::Ret(0)
            })
        }).unwrap_or( |a| {
            unsafe {
                let r = (self.real_getaddrinfo)(a.node, a.service, a.hints, a.res);
                println!("here");
                r
            }
        })
    }
}
