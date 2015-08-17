extern crate libc;
extern crate rand;
use self::libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use self::libc::{c_char, c_int, size_t, ssize_t};
use std::cmp::Ordering;
use std::collections::{BTreeMap};
use std::ffi::{CStr};
use std::mem;
use std::str::from_utf8;
use std::sync::{RwLock};

use self::rand::Rng;
use self::rand::distributions::{IndependentSample, Range};

use chain::Chain;
use dynamic::dlsym_next;
use util::{sockaddr_to_port_ip,port_ip_to_sa_data};
use dns::query_srv;

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

fn host_mapper(host: &String) -> Result<(u16, [u8;4]), String> {
    match host.starts_with("_") {
        true => Ok((8080, [127,127,127,127])),
        false => Err("doesn't begin with underscore".to_string())
    }
}

fn srv_mapper(host: &String) -> Result<(u16, [u8;4]), String> {
    let q = query_srv(host);
    if q.is_err() {
        return Err("srv lookup failed".to_string());
    }
    let mut results = q.unwrap();
    if results.len() == 0 {
        return Err("no records found".to_string());
    }
    results.sort();
    let mut high_prio = results.first().unwrap().priority;
    let mut weights = 0;
    let mut rng = rand::thread_rng();

    // scramble results so identical weights are chosen
    // with less bias
    results.sort_by(|a, b| {
        if rng.gen() {
            Ordering::Less
        } else {
            Ordering::Greater
        }
    });

    let mut choices = vec![];
    for r in results.iter() {
        if r.priority == high_prio {
            choices.push(r);
            weights += r.weight;
        }
    }
    if weights == 0 {
        let range = Range::new(0, choices.len());
        let weight = range.ind_sample(&mut rng);
        return Ok((choices[weight].port, choices[weight].ip));
    } else {
        let range = Range::new(0, weights);
        let weight = range.ind_sample(&mut rng);
        let mut sofar = 0;
        for rr in choices {
            sofar += rr.weight;
            if sofar >= weight {
                return Ok((rr.port, rr.ip));
            }
        }
    }
    Err("no srv picked!".to_string())
}

pub struct Serverset {
    magic_ip_to_host: RwLock<BTreeMap<[u8;4], String>>,
    magic_ip_to_fetcher: RwLock<BTreeMap<[u8; 4], fn (&String) -> Result<(u16, [u8; 4]),String>>>,
    real_connect: unsafe extern "C" fn(c_int,
                                       *const sockaddr, socklen_t) -> c_int,
    real_getaddrinfo: unsafe extern "C" fn(node: *const c_char,
                              service: *const c_char,
                              hints: *const addrinfo,
                              res: *const *const addrinfo) -> c_int,
    real_sendto: unsafe extern "C" fn(socket: c_int, msg: *const c_char,
                                      msglen: size_t, flags: c_int,
                                      dest_addr: *const sockaddr) -> ssize_t,
}

impl Serverset {
    pub unsafe fn new() -> Serverset {
        Serverset{
            magic_ip_to_host: RwLock::new(BTreeMap::new()),
            magic_ip_to_fetcher: RwLock::new(BTreeMap::new()),
            real_getaddrinfo:
                mem::transmute(dlsym_next("getaddrinfo\0").unwrap()),
            real_connect:
                mem::transmute(dlsym_next("connect\0").unwrap()),
            real_sendto:
                mem::transmute(dlsym_next("sendto\0").unwrap()),
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
            let ipf = self.magic_ip_to_fetcher.read().unwrap();
            ipf.get(&ip).map( |f| {
                let iph = self.magic_ip_to_host.read().unwrap();
                f(iph.get(&ip).unwrap()).map( |(new_port, new_ip)| {
                    unsafe {
                        (*a.address).sa_data = port_ip_to_sa_data(new_port, new_ip);
                    }
                });
            });
            Chain::Args(a)
        }).unwrap_or( |a| {
            unsafe {
                let (port, ip) = sockaddr_to_port_ip(a.address);
                (self.real_connect)(a.socket, a.address, a.len)
            }
        })
    }
    pub fn getaddrinfo(&self, node: *const c_char, service: *const c_char,
                   hints: *const addrinfo, res: *mut *const addrinfo) -> c_int {
        Chain::Args(GetaddrinfoArgs {
            node: node,
            service: service,
            hints: hints,
            res: res,
        }).map( |a| {
            let c_str = unsafe { CStr::from_ptr(node) };
            let s: String = from_utf8(c_str.to_bytes()).unwrap().to_owned();
            host_mapper(&s.clone()).map(|(port, ip)| {
                let mut ipf = self.magic_ip_to_fetcher.write().unwrap();
                ipf.insert(ip, srv_mapper);
                let mut iph = self.magic_ip_to_host.write().unwrap();
                iph.insert(ip, s);
                unsafe {
                    let sa_buf: *mut sockaddr =
                        mem::transmute(
                            libc::malloc(mem::size_of::<sockaddr>() as size_t)
                        );
                    *sa_buf = sockaddr{
                        sa_family: 2,
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
            }).or_else(|b: String| ->
                       Result<Chain<GetaddrinfoArgs, GetaddrinfoRet>, String> {
                           Ok(Chain::Args(a))
                       }).unwrap()
        }).unwrap_or( |a| {
            unsafe {
                (self.real_getaddrinfo)(a.node, a.service, a.hints, a.res)
            }
        })
    }

    pub fn sendto(&self, socket: c_int, msg: *const c_char, msglen: size_t,
                         flags: c_int, dest_addr: *const sockaddr) -> ssize_t {
        unsafe {
            (self.real_sendto)(socket, msg, msglen, flags, dest_addr)
        }
    }
}
