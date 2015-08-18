#[macro_use] extern crate lazy_static;
pub use dynamic::dlsym_next;
#[macro_use] pub mod hooks;
pub mod dynamic;
pub mod util;
pub mod ctypes;
pub mod dns;
