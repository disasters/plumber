extern crate libc;
use self::libc::types::os::common::bsd44::{sockaddr};

pub fn sockaddr_to_port_ip(address: *mut sockaddr) -> (u16, [u8;4]) {
    let data = unsafe { (*address).sa_data };
    ((data[0] as u16) << 8 | (data[1] as u16),
     [data[2], data[3], data[4], data[5]])
}

pub fn port_ip_to_sa_data(port: u16, ip: [u8;4]) -> [u8;14] {
    let mut sa_data: [u8; 14] = [0; 14];
    sa_data[0] = (port >> 8) as u8;
    sa_data[1] = port as u8;
    sa_data[2] = ip[0];
    sa_data[3] = ip[1];
    sa_data[4] = ip[2];
    sa_data[5] = ip[3];
    sa_data
}
