extern crate libc;
use self::libc::{c_char, c_int};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ffi::{CString, CStr};
use std::slice;
use std::str::from_utf8;

extern crate rand;
use self::rand::Rng;
use self::rand::distributions::{IndependentSample, Range};

use ctypes::*;

#[link(name = "resolv")]
extern {
    pub fn __res_query(dname: *const c_char, class: c_int, typef: c_int,
               answer: *const u8, anslen: c_int) -> c_int;
    pub fn ns_initparse(answer: *const u8, len: c_int, dst: *mut ns_msg);
    pub fn ns_parserr(msg: *mut ns_msg, sect: ns_sect_q, which: c_int, rr: *mut ns_rr);
    pub fn ns_sprintrr(msg: *mut ns_msg, rr: *mut ns_rr, b1: *const c_char,
                       b2: *const c_char, buf: *const c_char, buflen: c_int);
}

#[derive(PartialEq,Eq, PartialOrd, Ord, Debug, Clone)]
pub struct RR {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub ip: [u8;4],
    pub ttl: u32,
}

// query_srv uses res_query to attempt to look up SRV records.
pub fn query_srv(name: &str) -> Result<Vec<RR>, Rcode> {
    let dname = CString::new(name).unwrap();
    let ans_buf = [0u8;4096];
    let mut msg = ns_msg{..Default::default() };
    let mut res = vec![];
    unsafe {
        let len = __res_query(dname.as_ptr() as *const i8, Class::ANY as i32, Type::SRV as i32,
                           &ans_buf as *const u8, 4096);
        ns_initparse(&ans_buf as *const u8, len, &mut msg as *mut ns_msg);

        let mut host_to_ip: HashMap<String, [u8;4]> = HashMap::new();
        let nmsg_additional = msg.counts[3] as c_int;
        for i in 0..nmsg_additional {
            let dispbuf = [0u8;4096];
            let mut rr = ns_rr{..Default::default() };
            ns_parserr(&mut msg as *mut ns_msg, ns_sect_q::ns_s_ar, i, &mut rr as *mut ns_rr);
            ns_sprintrr(&mut msg as *mut ns_msg, &mut rr as *mut ns_rr,
                        0 as *const c_char, 0 as *const c_char,
                        dispbuf.as_ptr() as *const i8, 4096);
            let c_str = CStr::from_ptr(dispbuf.as_ptr() as *const i8);
            let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
            let host: &str = s.split_whitespace().nth(0).unwrap();
            let ip = s.split_whitespace().last().unwrap();
            let octets: Vec<u8> = ip.split(".").map( |o| {
                o.parse::<u8>().unwrap()
            }).collect();
            if octets.len() != 4 {
                continue;
            }
            let ip: [u8; 4] = [
                octets[0],
                octets[1],
                octets[2],
                octets[3],
            ];
            host_to_ip.insert(host.to_string(), ip);
        }

        let nmsg_answer = msg.counts[1] as c_int;
        for i in 0..nmsg_answer {
            let dispbuf = [0u8;4096];
            let mut rr = ns_rr{..Default::default() };
            ns_parserr(&mut msg as *mut ns_msg, ns_sect_q::ns_s_an, i, &mut rr as *mut ns_rr);
            ns_sprintrr(&mut msg as *mut ns_msg, &mut rr as *mut ns_rr,
                        0 as *const c_char, 0 as *const c_char,
                        dispbuf.as_ptr() as *const i8, 4096);
            let c_str = CStr::from_ptr(dispbuf.as_ptr() as *const i8);
            let s = from_utf8(c_str.to_bytes()).unwrap().to_owned();
            if rr.rdlength < 6 {
                return Err(Rcode::ServerFailure);
            }
            let rdata = slice::from_raw_parts(rr.rdata, rr.rdlength as usize);
            let prio: u16 = ((rdata[0] as u16) << 8) + rdata[1] as u16;
            let weight: u16 = ((rdata[2] as u16) << 8) + rdata[3] as u16;
            let port: u16 = ((rdata[4] as u16) << 8) + rdata[5] as u16;
            res.push(RR{
                ip: *host_to_ip.get(&s.split(" ").last().unwrap().to_string()).unwrap(),
                priority: prio,
                weight: weight,
                port: port,
                ttl: rr.ttl,
            });
        }
    }
    if res.len() == 0 {
        Err(Rcode::NameError)
    } else {
        Ok(res)
    }
}

// srv_mapper queries for SRV records and chooses
// one of the possible results based on the SRV
// priority and weight.
pub fn srv_mapper(host: &String) -> Result<RR, String> {
    let q = query_srv(host);
    if q.is_err() {
        return Err("srv lookup failed".to_string());
    }
    srv_chooser(q.unwrap())
}

pub fn srv_chooser(rrs: Vec<RR>) -> Result<RR, String> {
    let mut results = rrs.clone();
    if results.len() == 0 {
        return Err("no records found".to_string());
    }
    results.sort();
    let high_prio = results.first().unwrap().priority;
    let mut weights = 0;
    let mut rng = rand::thread_rng();

    // scramble results so identical weights are chosen
    // with less bias
    results.sort_by(|_, _| {
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
        return Ok(choices[weight].clone());
    } else {
        let range = Range::new(0, weights);
        let weight = range.ind_sample(&mut rng);
        let mut sofar = 0;
        for rr in choices {
            sofar += rr.weight;
            if sofar >= weight {
                return Ok(rr.clone());
            }
        }
    }
    Err("no srv picked!".to_string())
}

#[test]
fn test_query() {
    let r = query_srv("_etcd-server._tcp.etcd-t1.mesos");
    println!("result: {:?}", r);
}
