#[macro_use]
extern crate bitflags;
extern crate libc;

use std::io;
use std::default::Default;
use std::fs::{File,OpenOptions};
use std::os::unix::io::{RawFd,AsRawFd};

use libc::{c_ulong,c_short};

const IFF_UP: c_short = 0x0001;
/* ifr_flags */
const IFF_TUN: c_short = 0x0001;
const IFF_TAP: c_short = 0x0002;
const IFF_NO_PI: c_short = 0x1000;
const IFF_MULTI_QUEUE: c_short = 0x0100;

/* ioctls (x86_64) */
pub const TUNSETNOCSUM: c_ulong = 0x400454c8;
pub const TUNSETDEBUG: c_ulong = 0x400454c9;
pub const TUNSETIFF: c_ulong = 0x400454ca;
pub const TUNSETPERSIST: c_ulong = 0x400454cb;
pub const TUNSETOWNER: c_ulong = 0x400454cc;
pub const TUNSETLINK: c_ulong = 0x400454cd;
pub const TUNSETGROUP: c_ulong = 0x400454ce;
pub const TUNGETFEATURES: c_ulong = 0x800454cf;
pub const TUNSETOFFLOAD: c_ulong = 0x400454d0;
pub const TUNSETTXFILTER: c_ulong = 0x400454d1;
pub const TUNGETIFF: c_ulong = 0x800454d2;
pub const TUNGETSNDBUF: c_ulong = 0x800454d3;
pub const TUNSETSNDBUF: c_ulong = 0x400454d4;
pub const TUNATTACHFILTER: c_ulong = 0x401054d5;
pub const TUNDETACHFILTER: c_ulong = 0x401054d6;
pub const TUNGETVNETHDRSZ: c_ulong = 0x800454d7;
pub const TUNSETVNETHDRSZ: c_ulong = 0x400454d8;
pub const TUNSETQUEUE: c_ulong = 0x400454d9;
pub const TUNSETIFINDEX: c_ulong = 0x400454da;
pub const TUNGETFILTER: c_ulong = 0x801054db;

#[repr(C)]
#[derive(Debug,Default)]
struct ifreq_flags {
    ifr_name: [u8;libc::IF_NAMESIZE],
    ifr_ifru_flags: c_short,
    ifr_ifru: [u8;22], /* sizeof(ifreq) = 40 on my system */
}

#[derive(Debug)]
struct InternalTun {
    name: String,
    file: File,
    flags: c_short,
}

impl AsRawFd for InternalTun {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl io::Write for InternalTun {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl io::Read for InternalTun {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}

#[derive(Debug)]
pub struct Tun(InternalTun);
#[derive(Debug)]
pub struct MultiQueueTun(InternalTun);
#[derive(Debug)]
pub struct Tap(InternalTun);
#[derive(Debug)]
pub struct MultiQueueTap(InternalTun);
#[derive(Debug)]
pub struct Queue(InternalTun);

impl AsRef<InternalTun> for Tap {
    fn as_ref(&self) -> &InternalTun {
        &self.0
    }
}

impl AsMut<InternalTun> for Tap {
    fn as_mut(&mut self) -> &mut InternalTun {
        &mut self.0
    }
}

impl AsRef<InternalTun> for Queue {
    fn as_ref(&self) -> &InternalTun {
        &self.0
    }
}

impl AsMut<InternalTun> for Queue {
    fn as_mut(&mut self) -> &mut InternalTun {
        &mut self.0
    }
}

trait MultiQueue {
    fn open_queue(&self) -> io::Result<Queue>;
}

impl MultiQueue for MultiQueueTun {
    fn open_queue(&self) -> io::Result<Queue> {
        TunBuilder::open_int(Some(&self.0.name), self.0.flags, false).map(|tun| Queue(tun))
    }
}

impl MultiQueue for MultiQueueTap {
    fn open_queue(&self) -> io::Result<Queue> {
        TunBuilder::open_int(Some(&self.0.name), self.0.flags, false).map(|tun| Queue(tun))
    }
}

pub struct TunBuilder<'a,T> where T: AsRef<str> + AsRef<[u8]>, T: 'a {
    name: Option<&'a T>,
    persist: bool,
    packet_info: bool,
}

impl<'a, T> TunBuilder<'a,T> where T: AsRef<str> + AsRef<[u8]>  {
    pub fn new() -> Self {
        TunBuilder {
            name: None,
            packet_info: false,
            persist: false,
        }
    }

    pub fn with_name(name: &'a T) -> Self {
        TunBuilder {
            name: Some(name),
            packet_info: false,
            persist: false,
        }
    }

    pub fn persist(&mut self, v: bool) -> &mut Self {
        self.persist = v;
        self
    }

    pub fn with_packet_info(&mut self, v: bool) -> &mut Self {
        self.packet_info = v;
        self
    }

    pub fn open_tap(&mut self) -> io::Result<Tap> {
        let mut flags: c_short = IFF_TAP;

        if !self.packet_info {
            flags |= IFF_NO_PI;
        }

        Self::open_int(self.name, flags, self.persist).map(|tun| Tap(tun))
    }

    pub fn open_mq_tap(&mut self) -> io::Result<MultiQueueTap> {
        let mut flags: c_short = IFF_TAP;

        flags |= IFF_MULTI_QUEUE;

        if !self.packet_info {
            flags |= IFF_NO_PI;
        }

        Self::open_int(self.name, flags, self.persist).map(|tun| MultiQueueTap(tun))
    }

    pub fn open_tun(&mut self) -> io::Result<Tun> {
        let mut flags: c_short = IFF_TUN;

        if !self.packet_info {
            flags |= IFF_NO_PI;
        }

        Self::open_int(self.name, flags, self.persist).map(|tun| Tun(tun))
    }

    fn open_int(name: Option<&'a T>, flags: c_short, persist: bool) -> io::Result<InternalTun> {
        use std::ffi::CStr;

        let file = try!(OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/net/tun"));
        let mut ifreq = ifreq_flags::default();

        ifreq.ifr_ifru_flags = flags;

        if let Some(name) = name {
            use std::cmp::min;
            let bytes: &[u8] = name.as_ref();
            let len = min(bytes.len(), libc::IF_NAMESIZE - 1);
            &mut ifreq.ifr_name[0..len].copy_from_slice(bytes);
        }

        println!("IFREQ = {:?}", ifreq);

        let fd = file.as_raw_fd();
        let res = unsafe {
             libc::ioctl(fd, TUNSETIFF, &mut ifreq)
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        let res = unsafe {
             libc::ioctl(fd, TUNSETPERSIST, if persist { 1 } else { 0 })
        };
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        let c_name = unsafe { CStr::from_ptr(ifreq.ifr_name.as_ptr() as *const i8) };
        let name = c_name.to_owned().into_string().unwrap();
        Ok(InternalTun { file: file, name: name, flags: flags })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn builder() {
        use super::TunBuilder;
        let name = "pook";
        let tun = TunBuilder::with_name(&name)
            .with_packet_info(true)
            .persist(true)
            .open_tun();
        tun.unwrap();
    }

    #[test]
    fn queue() {
        use super::{Tun,TunBuilder};
        let name = "pook";
        let tun = TunBuilder::with_name(&name)
            .with_packet_info(false)
            .persist(false)
            .enable_multi_queue(true)
            .open_tun();
        let tun = tun.unwrap();
        let tun1 = tun.open_queue().unwrap();
        println!("TUN {:?}", &tun);
        println!("TUNQ {:?}", &tun1);
        println!("TUN {:?}", &tun);
    }
}
