extern crate libc;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int, size_t};
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
    println!("mapping host {}", host);
    match host == "test.mesos" {
        true => Some((8080, [127,127,127,127])),
        false => None
    }
}

fn test_mapper(ip: [u8; 4]) -> (u16, [u8;4]) {
    println!("in test_mapper");
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
        println!("beginning connect dance");
        Chain::Args(ConnectArgs{
            socket: socket,
            address: address,
            len: len,
        }).map( |a| {
            let (port, ip) = sockaddr_to_port_ip(a.address);
            println!("connect trying to use ip {:?}", ip);
            self.magic_ip_to_fetcher.lock().unwrap().get(&ip).map( |f| {
                println!("got the fetcher!");
                let (new_port, new_ip) = f(ip);
                unsafe {
                    (*a.address).sa_data = port_ip_to_sa_data(new_port, new_ip);
                }
            });
            Chain::Args(a)
        }).unwrap_or( |a| {
            unsafe {
                let r = (self.real_connect)(a.socket, a.address, a.len);
                println!("connect returned {}", r);
                r
            }
        })
    }

    pub fn getaddrinfo(&self, mut node: *const c_char, service: *const c_char,
                   hints: *const addrinfo, res: *mut *const addrinfo) -> c_int {
        Chain::Args(GetaddrinfoArgs {
            node: node,
            service: service,
            hints: hints,
            res: res,
        }).map( |a| {
            let c_str = unsafe { CStr::from_ptr(node) };
            let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
            println!("getaddrinfo pre-hook: node: {:?} service: {:?}", s, service);
            host_mapper(s).map_or(Chain::Args(a), |(port, ip)| {
                self.magic_ip_to_fetcher.lock().unwrap().insert(ip, test_mapper);
                unsafe {
                    let sa_buf: *mut sockaddr =
                        mem::transmute(
                            libc::malloc(mem::size_of::<sockaddr>() as size_t)
                        );
                    *sa_buf = sockaddr{
                        sa_family: 1,
                        sa_data: port_ip_to_sa_data(port, ip),
                    };

                    let ai_buf: *mut addrinfo =
                        mem::transmute(
                            libc::malloc(mem::size_of::<addrinfo>() as size_t)
                        );
                    *ai_buf = addrinfo{
                        ai_flags: 0,
                        ai_family: 2,
                        ai_socktype: 1,
                        ai_protocol: 6,
                        ai_addrlen: 16,
                        ai_addr: sa_buf,
                        ai_canonname: 0 as *mut i8,
                        ai_next: 0 as *mut addrinfo,
                    };
                    *res = ai_buf;
                }
                Chain::Ret(0)
            })
        }).unwrap_or( |a| {
            unsafe {
                (self.real_getaddrinfo)(a.node, a.service, a.hints, a.res)
            }
        })
    }
}
