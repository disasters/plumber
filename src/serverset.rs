extern crate discotech;
use std::env;
use std::mem;
use std::sync::{Once, ONCE_INIT, Arc, Mutex};

use self::discotech::*;

#[derive(Clone)]
pub struct SingletonServerset {
    inner: Arc<Mutex<Serverset>>
}

// Please excuse this commando attempt to establish a base in a hostile address space.
pub fn get_serverset() -> SingletonServerset {
    static mut SINGLETON: *const SingletonServerset = 0 as *const SingletonServerset;
    static ONCE: Once = ONCE_INIT;

    unsafe {
        ONCE.call_once(|| {
            let conf_path = env::var("DISCO_CONF").unwrap();
            let conf = read_config(conf_path).unwrap();
            let s = Serverset::new(conf);

            let serverset = SingletonServerset {
                inner: Arc::new(Mutex::new(s))
            };

            SINGLETON = mem::transmute(Box::new(serverset));
        });

        (*SINGLETON).clone()
    }
}
