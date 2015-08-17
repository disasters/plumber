#[macro_use] extern crate lazy_static;
pub use dynamic::dlsym_next;
pub use srvhook::SRVHook;
#[macro_use] pub mod hooks;
pub mod dynamic;
pub mod srvhook;
pub mod util;
pub mod ctypes;
pub mod dns;

set_hook!(SRVHook : SRVHook::new());
