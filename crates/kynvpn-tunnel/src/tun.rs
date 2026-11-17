//! A TUN device over a file descriptor someone else opened.

use crate::TunDevice;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::Duration;

/// A TUN device over an fd the platform handed us: Android's
/// `ParcelFileDescriptor.detachFd()` from `VpnService.Builder.establish()`,
/// or an iOS utun fd.
///
/// Waiting is `poll(2)` with a timeout rather than a wake pipe: simple, and
/// good enough until the engine stops polling on a timer at all (see
/// docs/PLAN.md, "Battery").
pub struct FdTun {
    fd: OwnedFd,
    /// utun (macOS, iOS) prefixes each packet with a 4-byte address family.
    af_header: bool,
}

impl FdTun {
    /// A plain TUN fd (Linux, Android): packets with no header.
    pub fn new(fd: OwnedFd) -> Self {
        Self {
            fd,
            af_header: false,
        }
    }

    /// A utun fd (Darwin): each packet starts with a big-endian
    /// `AF_INET`/`AF_INET6`.
    pub fn with_af_header(fd: OwnedFd) -> Self {
        Self {
            fd,
            af_header: true,
        }
    }
}

impl TunDevice for FdTun {
    fn read(&self, buf: &mut [u8], timeout: Duration) -> io::Result<Option<usize>> {
        let mut pfd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        match unsafe { libc::poll(&mut pfd, 1, ms) } {
            0 => return Ok(None),
            n if n < 0 => {
                let e = io::Error::last_os_error();
                return if e.kind() == io::ErrorKind::Interrupted {
                    Ok(None)
                } else {
                    Err(e)
                };
            }
            _ => {}
        }
        if self.af_header {
            let mut hdr = [0u8; 4];
            let mut iov = [
                libc::iovec {
                    iov_base: hdr.as_mut_ptr().cast(),
                    iov_len: 4,
                },
                libc::iovec {
                    iov_base: buf.as_mut_ptr().cast(),
                    iov_len: buf.len(),
                },
            ];
            let n = unsafe { libc::readv(self.fd.as_raw_fd(), iov.as_mut_ptr(), 2) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some((n as usize).saturating_sub(4)))
        } else {
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Some(n as usize))
        }
    }

    fn write(&self, packet: &[u8]) -> io::Result<()> {
        let n = if self.af_header {
            let af: u32 = match packet.first().map(|b| b >> 4) {
                Some(6) => libc::AF_INET6 as u32,
                _ => libc::AF_INET as u32,
            };
            let hdr = af.to_be_bytes();
            let iov = [
                libc::iovec {
                    iov_base: hdr.as_ptr() as *mut _,
                    iov_len: 4,
                },
                libc::iovec {
                    iov_base: packet.as_ptr() as *mut _,
                    iov_len: packet.len(),
                },
            ];
            unsafe { libc::writev(self.fd.as_raw_fd(), iov.as_ptr(), 2) }
        } else {
            unsafe { libc::write(self.fd.as_raw_fd(), packet.as_ptr().cast(), packet.len()) }
        };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
