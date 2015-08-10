extern crate libc;
use self::libc::{c_char, c_int, c_void};

const RTLD_NEXT: *const c_void = -1isize as *const c_void;

#[link(name="dl")]
extern {
    fn dlsym(handle: *const c_void, symbol: *const c_char) -> *const c_void;
}

pub unsafe fn dlsym_next(symbol: &'static str) -> Result<*const u8, String> {
    let ptr = dlsym(RTLD_NEXT, symbol.as_ptr() as *const c_char);
    if ptr.is_null() {
        Err(format!("Unable to find underlying function for {}", symbol))
    } else {
        Ok(ptr as *const u8)
    }
}
