#![feature(libc)]
extern crate libc;
extern crate discotech;
use libc::types::os::common::bsd44::{addrinfo, socklen_t, sockaddr};
use libc::{c_char, c_int, c_void};
use std::env;
use std::mem;
use std::sync::{Once, ONCE_INIT, Arc, Mutex};

use discotech::*;

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

#[derive(Clone)]
struct SingletonServerset {
    inner: Arc<Mutex<Serverset>>
}

fn singleton() -> SingletonServerset {
    static mut SINGLETON: *const SingletonServerset = 0 as *const SingletonServerset;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            let conf_path = env::var("DISCO_CONF").unwrap();
            let conf = read_config(conf_path).unwrap();
            let s = Serverset::new(conf);

            let singleton = SingletonServerset {
                inner: Arc::new(Mutex::new(s))
            };

            // Put it in the heap so it can outlive this call
            SINGLETON = mem::transmute(Box::new(singleton));

            // Make sure to free heap memory at exit
            /* This doesn't exist in stable 1.0, so we will just leak it!
            rt::at_exit(|| {
                let singleton: Box<SingletonReader> = mem::transmute(SINGLETON);

                // Let's explictly free the memory for this example
                drop(singleton);

                // Set it to null again. I hope only one thread can call `at_exit`!
                SINGLETON = 0 as *const _;
            });
            */
        });

        // Now we give out a copy of the data that is safe to use concurrently.
        (*SINGLETON).clone()
    }
}

#[no_mangle]
pub unsafe extern "C" fn connect(socket: c_int, address: *const sockaddr,
                           len: socklen_t) -> c_int {
    println!("HOOKING CONNECT!!!!!!!!!!!!!!!!!");
    let ss = singleton();
    let ptr = dlsym_next("connect");
    let f: fn(c_int, *const sockaddr, socklen_t) -> c_int = mem::transmute(ptr);
    f(socket, address, len)
}

#[no_mangle]
pub unsafe extern "C" fn getaddrinfo(node: *const c_char, service: *const c_char,
               hints: *const addrinfo, res: *const *const addrinfo) -> c_int {
    println!("HOOKING getaddrinfo!!!!!!!!!!!!!!!!!");
    let ss = singleton();
    let ptr = dlsym_next("getaddrinfo");
    let f: fn(*const c_char, *const c_char, *const addrinfo,
              *const *const addrinfo) -> c_int = mem::transmute(ptr);
    f(node, service, hints, res)
}
