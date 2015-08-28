extern crate libc;
use self::libc::types::os::common::bsd44::{sockaddr};

pub fn usize_to_ip(u: usize) -> [u8;4] {
    [(u >> 24) as u8, (u >> 16) as u8, (u >> 8) as u8, u as u8]
}

pub fn ip_to_usize(ip: [u8;4]) -> usize {
    ((ip[0] as usize) << 24) as usize +
        ((ip[1] as usize) << 16) as usize +
        ((ip[2] as usize) << 8) as usize +
        (ip[3] as usize)
}

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

#[cfg(test)]
mod tests {
    extern crate quickcheck;

    use util;
    fn prop(u: usize) -> bool {
        util::ip_to_usize(util::usize_to_ip(u)) == u
    }

    #[test]
    fn test_usize_to_ip_to_usize() {
        quickcheck::quickcheck(prop as fn(usize)->bool);
        let ip = [250,1,2,3];
        assert!(util::usize_to_ip(util::ip_to_usize(ip)) == ip);
    }
}

