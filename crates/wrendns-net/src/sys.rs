//! Linux syscall layer: batched `recvmmsg`/`sendmmsg` with `IP_PKTINFO`/`IPV6_PKTINFO`.
//!
//! REQ: DNS-001, NFR-003. This is the only module in WrenDNS that contains `unsafe`.
//! All buffers are allocated once per worker at startup; the pointer tables handed to the
//! kernel are rebuilt before every call, so nothing is self-referential across moves.

// FFI glue: casts convert small compile-time sizes (struct sizes, batch caps <= 1024) and
// AF_* constants into C types. Some casts look redundant on glibc but are required on musl,
// where msghdr/cmsghdr field types differ (u32 vs usize).
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::unnecessary_cast
)]

use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

use crate::udp::LocalAddr;

/// Max datagram size we accept from clients. Queries are small; anything larger is junk.
pub(crate) const RX_BUF: usize = 4096;
/// Max reply size we send over UDP (bounded by `udp_limit`, at most 4096 in practice).
pub(crate) const TX_BUF: usize = 4096;
/// Control-message buffer size: enough for one `in6_pktinfo` cmsg, 8-byte aligned.
const CTRL_WORDS: usize = 8;
type CtrlBuf = [u64; CTRL_WORDS];
const CTRL_LEN: usize = CTRL_WORDS * 8;

/// Raises the calling thread's nice value to at least `nice` (lower priority); a thread
/// that's already lower is left alone. On Linux, `setpriority(PRIO_PROCESS, tid)` applies to
/// that one thread, and threads it spawns inherit the value.
pub(crate) fn lower_thread_priority(nice: i32) -> io::Result<()> {
    // SAFETY: SYS_gettid takes no arguments and cannot fail.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    let tid = libc::id_t::try_from(tid).map_err(io::Error::other)?;
    // SAFETY: getpriority only reads its scalar arguments; `tid` is this thread's own ID.
    let cur = unsafe { libc::getpriority(libc::PRIO_PROCESS as _, tid) };
    let target = nice.clamp(-20, 19);
    if cur >= target {
        return Ok(());
    }
    // SAFETY: setpriority only reads its scalar arguments; `tid` is this thread's own ID.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, tid, target) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Moves the calling thread to `SCHED_IDLE`: it runs only when a CPU would otherwise be
/// idle and is preempted as soon as a normal thread (a DNS worker) wakes.
pub(crate) fn idle_thread() -> io::Result<()> {
    // SAFETY: `sched_param` is plain old data; zero is the only valid priority for SCHED_IDLE.
    let param: libc::sched_param = unsafe { mem::zeroed() };
    // SAFETY: pid 0 = the calling thread; `param` is valid for the duration of the call.
    let rc = unsafe { libc::sched_setscheduler(0, libc::SCHED_IDLE, &raw const param) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// REQ: DSC-002, DSC-003 (ADR-908, ADR-1001) - a UDP socket connected to `target`, made without a
/// `bind` call. A discovery worker's seccomp filter refuses `bind` (so it can't share the DNS port),
/// and `UdpSocket::bind` is the only way std makes a UDP socket; `connect(2)` on a datagram socket
/// binds it to an ephemeral port itself. The SNMP client takes this socket for its agent.
pub(crate) fn connect_udp(target: SocketAddr) -> io::Result<std::net::UdpSocket> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let family = match target {
        SocketAddr::V4(_) => libc::AF_INET,
        SocketAddr::V6(_) => libc::AF_INET6,
    };
    // SAFETY: plain socket(2) call with constant arguments; the result is checked below.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor that nothing else owns; the OwnedFd closes
    // it on the error paths below.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: all-zero is a valid sockaddr_storage.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let len = std_to_sockaddr(target, &mut storage);
    // SAFETY: `storage` holds a sockaddr of `len` bytes and lives through the call; the fd is a
    // valid datagram socket.
    let rc = unsafe {
        libc::connect(
            sock.as_raw_fd(),
            ptr::addr_of!(storage).cast::<libc::sockaddr>(),
            len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(std::net::UdpSocket::from(sock))
}

/// Reads every IPv4 address of every interface with `getifaddrs` (T24.32). Grouping and filtering
/// are safe code in `iface`.
pub(crate) fn interface_addrs() -> io::Result<Vec<crate::iface::RawAddr>> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer; on success the list it receives is freed below.
    if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list getifaddrs returned, valid until freeifaddrs.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_netmask.is_null() {
            continue;
        }
        // SAFETY: ifa_addr is non-null and points to a sockaddr whose family field is readable.
        let family = unsafe { (*ifa.ifa_addr).sa_family };
        if i32::from(family) != libc::AF_INET {
            continue;
        }
        // SAFETY: the family is AF_INET, so both pointers address a sockaddr_in (read unaligned,
        // to assume nothing about the allocation's alignment).
        let (addr, mask) = unsafe {
            (
                ptr::read_unaligned(ifa.ifa_addr.cast::<libc::sockaddr_in>()),
                ptr::read_unaligned(ifa.ifa_netmask.cast::<libc::sockaddr_in>()),
            )
        };
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: `ifa_name` is a valid C string; the call has no other preconditions.
        let ifindex = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        let flags = ifa.ifa_flags;
        out.push(crate::iface::RawAddr {
            name,
            ifindex,
            up: flags & libc::IFF_UP as u32 != 0,
            multicast: flags & libc::IFF_MULTICAST as u32 != 0,
            loopback: flags & libc::IFF_LOOPBACK as u32 != 0,
            addr: Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
            netmask: Ipv4Addr::from(u32::from_be(mask.sin_addr.s_addr)),
        });
    }
    // SAFETY: `head` came from a successful getifaddrs and is freed exactly once; nothing borrows
    // from the list after this (names were copied).
    unsafe { libc::freeifaddrs(head) };
    Ok(out)
}

/// Dumps the kernel neighbor table over rtnetlink (FLT-006). Parsing is safe code in
/// `neigh`; this function only owns the socket.
pub(crate) fn neighbor_dump() -> io::Result<Vec<crate::neigh::Neighbor>> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: plain socket(2) call with constant arguments; the result is checked below.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::NETLINK_ROUTE,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a freshly created, valid descriptor that nothing else owns.
    let sock = unsafe { OwnedFd::from_raw_fd(fd) };
    // A dump never takes long; don't let a wedged kernel reply hang the refresher.
    let tv = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    // SAFETY: `tv` is a valid timeval and the length matches its size.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            ptr::addr_of!(tv).cast(),
            mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: sockaddr_nl is plain old data; all-zero is a valid value (pid 0 = the kernel).
    let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
    addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let req = crate::neigh::dump_request(1);
    // SAFETY: `req` and `addr` outlive the call; the lengths match the buffers.
    let sent = unsafe {
        libc::sendto(
            sock.as_raw_fd(),
            req.as_ptr().cast(),
            req.len(),
            0,
            ptr::addr_of!(addr).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        // SAFETY: `buf` is a valid, writable buffer of the given length.
        let n = unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = usize::try_from(n).map_err(io::Error::other)?;
        if n == 0 {
            return Ok(out);
        }
        if crate::neigh::parse(&buf[..n], &mut out)? == crate::neigh::Chunk::Done {
            return Ok(out);
        }
    }
}

/// Enables destination-address reporting so replies can use the right source address.
pub(crate) fn enable_pktinfo(sock: &impl AsRawFd, v6: bool) -> io::Result<()> {
    let one: libc::c_int = 1;
    let (level, opt) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
    } else {
        (libc::IPPROTO_IP, libc::IP_PKTINFO)
    };
    // SAFETY: `one` is a valid c_int that outlives the call, and its exact size is passed.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            level,
            opt,
            ptr::from_ref(&one).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// One received datagram's metadata.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RxMeta {
    pub(crate) len: usize,
    pub(crate) peer: Option<SocketAddr>,
    pub(crate) local: Option<LocalAddr>,
    pub(crate) truncated: bool,
}

/// Per-worker batch buffers for `recvmmsg` and `sendmmsg`.
pub(crate) struct Batch {
    cap: usize,
    rx: Box<[[u8; RX_BUF]]>,
    rx_addr: Box<[libc::sockaddr_storage]>,
    rx_ctrl: Box<[CtrlBuf]>,
    rx_iov: Box<[libc::iovec]>,
    rx_hdr: Box<[libc::mmsghdr]>,
    tx: Box<[[u8; TX_BUF]]>,
    tx_len: Box<[usize]>,
    tx_addr: Box<[libc::sockaddr_storage]>,
    tx_addr_len: Box<[libc::socklen_t]>,
    tx_ctrl: Box<[CtrlBuf]>,
    tx_ctrl_len: Box<[usize]>,
    tx_iov: Box<[libc::iovec]>,
    tx_hdr: Box<[libc::mmsghdr]>,
    tx_count: usize,
}

impl std::fmt::Debug for Batch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Batch")
            .field("cap", &self.cap)
            .field("tx_count", &self.tx_count)
            .finish_non_exhaustive()
    }
}

fn zeroed_box<T: Copy>(n: usize) -> Box<[T]> {
    // SAFETY: only instantiated with plain-old-data libc structs (sockaddr_storage, iovec,
    // mmsghdr) for which the all-zero bit pattern is a valid value.
    vec![unsafe { MaybeUninit::<T>::zeroed().assume_init() }; n].into_boxed_slice()
}

impl Batch {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            cap,
            rx: vec![[0u8; RX_BUF]; cap].into_boxed_slice(),
            rx_addr: zeroed_box(cap),
            rx_ctrl: vec![[0u64; CTRL_WORDS]; cap].into_boxed_slice(),
            rx_iov: zeroed_box(cap),
            rx_hdr: zeroed_box(cap),
            tx: vec![[0u8; TX_BUF]; cap].into_boxed_slice(),
            tx_len: vec![0; cap].into_boxed_slice(),
            tx_addr: zeroed_box(cap),
            tx_addr_len: vec![0; cap].into_boxed_slice(),
            tx_ctrl: vec![[0u64; CTRL_WORDS]; cap].into_boxed_slice(),
            tx_ctrl_len: vec![0; cap].into_boxed_slice(),
            tx_iov: zeroed_box(cap),
            tx_hdr: zeroed_box(cap),
            tx_count: 0,
        }
    }

    /// Receives up to `capacity()` datagrams, blocking until at least one arrives (or the
    /// socket's read timeout fires, which surfaces as `WouldBlock`). Returns the count.
    pub(crate) fn recv(&mut self, fd: RawFd) -> io::Result<usize> {
        for i in 0..self.cap {
            self.rx_iov[i] = libc::iovec {
                iov_base: self.rx[i].as_mut_ptr().cast(),
                iov_len: RX_BUF,
            };
            let h = &mut self.rx_hdr[i];
            h.msg_len = 0;
            h.msg_hdr.msg_name = ptr::from_mut(&mut self.rx_addr[i]).cast();
            h.msg_hdr.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_hdr.msg_iov = ptr::from_mut(&mut self.rx_iov[i]);
            h.msg_hdr.msg_iovlen = 1;
            h.msg_hdr.msg_control = self.rx_ctrl[i].as_mut_ptr().cast();
            h.msg_hdr.msg_controllen = CTRL_LEN as _;
            h.msg_hdr.msg_flags = 0;
        }
        // SAFETY: every header points into buffers owned by `self` that stay alive and
        // unmoved for the duration of the call; lengths match the buffers; `cap` headers exist.
        let n = unsafe {
            libc::recvmmsg(
                fd,
                self.rx_hdr.as_mut_ptr(),
                self.cap as libc::c_uint,
                libc::MSG_WAITFORONE as _,
                ptr::null_mut(),
            )
        };
        usize::try_from(n).map_err(|_| io::Error::last_os_error())
    }

    /// Metadata for received datagram `i` (valid after `recv` returned more than `i`).
    pub(crate) fn rx_meta(&self, i: usize) -> RxMeta {
        let h = &self.rx_hdr[i];
        RxMeta {
            len: (h.msg_len as usize).min(RX_BUF),
            peer: sockaddr_to_std(&self.rx_addr[i], h.msg_hdr.msg_namelen),
            local: pktinfo_from_cmsgs(&h.msg_hdr),
            truncated: h.msg_hdr.msg_flags & libc::MSG_TRUNC != 0,
        }
    }

    /// Received datagram `i` (first `len` bytes) together with the next free send buffer.
    pub(crate) fn rx_and_next_tx(
        &mut self,
        i: usize,
        len: usize,
    ) -> (&[u8], Option<&mut [u8; TX_BUF]>) {
        (
            &self.rx[i][..len.min(RX_BUF)],
            self.tx.get_mut(self.tx_count),
        )
    }

    /// Queues the send buffer last returned by [`Batch::rx_and_next_tx`] (`len` bytes) for sending to
    /// `peer`, from `local` if known. Returns false if the send queue is full.
    pub(crate) fn queue_tx(
        &mut self,
        len: usize,
        peer: SocketAddr,
        local: Option<LocalAddr>,
    ) -> bool {
        let i = self.tx_count;
        if i >= self.cap {
            return false;
        }
        self.tx_len[i] = len.min(TX_BUF);
        self.tx_addr_len[i] = std_to_sockaddr(peer, &mut self.tx_addr[i]);
        self.tx_ctrl_len[i] = local.map_or(0, |l| write_pktinfo(&mut self.tx_ctrl[i], l));
        self.tx_count += 1;
        true
    }

    /// Sends all queued datagrams. Returns (sent, failed). Never blocks indefinitely on one
    /// bad destination: a failing message is skipped and counted.
    pub(crate) fn flush(&mut self, fd: RawFd) -> (usize, usize) {
        let count = self.tx_count;
        self.tx_count = 0;
        for i in 0..count {
            self.tx_iov[i] = libc::iovec {
                iov_base: self.tx[i].as_mut_ptr().cast(),
                iov_len: self.tx_len[i],
            };
            let h = &mut self.tx_hdr[i];
            h.msg_len = 0;
            h.msg_hdr.msg_name = ptr::from_mut(&mut self.tx_addr[i]).cast();
            h.msg_hdr.msg_namelen = self.tx_addr_len[i];
            h.msg_hdr.msg_iov = ptr::from_mut(&mut self.tx_iov[i]);
            h.msg_hdr.msg_iovlen = 1;
            h.msg_hdr.msg_control = if self.tx_ctrl_len[i] == 0 {
                ptr::null_mut()
            } else {
                self.tx_ctrl[i].as_mut_ptr().cast()
            };
            h.msg_hdr.msg_controllen = self.tx_ctrl_len[i] as _;
            h.msg_hdr.msg_flags = 0;
        }
        let (mut sent, mut failed, mut start) = (0, 0, 0);
        while start < count {
            // SAFETY: headers `start..count` point into buffers owned by `self`, alive and
            // unmoved for the call; `count - start` headers are initialized above.
            let n = unsafe {
                libc::sendmmsg(
                    fd,
                    self.tx_hdr[start..].as_mut_ptr(),
                    (count - start) as libc::c_uint,
                    0,
                )
            };
            match usize::try_from(n) {
                Ok(0) | Err(_) => {
                    let err = io::Error::last_os_error();
                    if n < 0 && err.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    failed += 1;
                    start += 1;
                }
                Ok(k) => {
                    sent += k;
                    start += k;
                }
            }
        }
        (sent, failed)
    }
}

/// Sends one datagram (deferred replies from async tasks), with source address control.
pub(crate) fn send_one(
    fd: RawFd,
    buf: &[u8],
    peer: SocketAddr,
    local: Option<LocalAddr>,
) -> io::Result<usize> {
    // SAFETY: all-zero is a valid sockaddr_storage.
    let mut addr: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let addr_len = std_to_sockaddr(peer, &mut addr);
    let mut ctrl: CtrlBuf = [0; CTRL_WORDS];
    let ctrl_len = local.map_or(0, |l| write_pktinfo(&mut ctrl, l));
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr().cast_mut().cast(),
        iov_len: buf.len(),
    };
    // SAFETY: all-zero is a valid msghdr; fields are set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = ptr::from_mut(&mut addr).cast();
    msg.msg_namelen = addr_len;
    msg.msg_iov = ptr::from_mut(&mut iov);
    msg.msg_iovlen = 1;
    if ctrl_len > 0 {
        msg.msg_control = ctrl.as_mut_ptr().cast();
        msg.msg_controllen = ctrl_len as _;
    }
    // SAFETY: `msg` points at stack values that outlive the call; the kernel only reads `buf`
    // (sendmsg never writes through iov_base).
    let n = unsafe { libc::sendmsg(fd, &raw const msg, 0) };
    usize::try_from(n).map_err(|_| io::Error::last_os_error())
}

fn sockaddr_to_std(s: &libc::sockaddr_storage, len: libc::socklen_t) -> Option<SocketAddr> {
    let len = len as usize;
    match libc::c_int::from(s.ss_family) {
        libc::AF_INET if len >= mem::size_of::<libc::sockaddr_in>() => {
            // SAFETY: family is AF_INET and the kernel wrote at least sizeof(sockaddr_in)
            // bytes; sockaddr_storage is suitably aligned for any sockaddr type.
            let a: libc::sockaddr_in = unsafe { ptr::read(ptr::from_ref(s).cast()) };
            Some(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr)),
                u16::from_be(a.sin_port),
            )))
        }
        libc::AF_INET6 if len >= mem::size_of::<libc::sockaddr_in6>() => {
            // SAFETY: as above, for AF_INET6 / sockaddr_in6.
            let a: libc::sockaddr_in6 = unsafe { ptr::read(ptr::from_ref(s).cast()) };
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(a.sin6_addr.s6_addr),
                u16::from_be(a.sin6_port),
                a.sin6_flowinfo,
                a.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

fn std_to_sockaddr(addr: SocketAddr, out: &mut libc::sockaddr_storage) -> libc::socklen_t {
    match addr {
        SocketAddr::V4(a) => {
            // SAFETY: all-zero is a valid sockaddr_in.
            let mut s: libc::sockaddr_in = unsafe { mem::zeroed() };
            s.sin_family = libc::AF_INET as libc::sa_family_t;
            s.sin_port = a.port().to_be();
            s.sin_addr.s_addr = u32::from(*a.ip()).to_be();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in.
            unsafe { ptr::write(ptr::from_mut(out).cast(), s) };
            mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(a) => {
            // SAFETY: all-zero is a valid sockaddr_in6.
            let mut s: libc::sockaddr_in6 = unsafe { mem::zeroed() };
            s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            s.sin6_port = a.port().to_be();
            s.sin6_addr.s6_addr = a.ip().octets();
            s.sin6_flowinfo = a.flowinfo();
            s.sin6_scope_id = a.scope_id();
            // SAFETY: sockaddr_storage is large and aligned enough for sockaddr_in6.
            unsafe { ptr::write(ptr::from_mut(out).cast(), s) };
            mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    }
}

/// Extracts the destination address/interface from IP(V6)_PKTINFO control messages.
fn pktinfo_from_cmsgs(msg: &libc::msghdr) -> Option<LocalAddr> {
    if msg.msg_control.is_null() || (msg.msg_controllen as usize) < mem::size_of::<libc::cmsghdr>()
    {
        return None;
    }
    // SAFETY: `msg` was filled in by recvmmsg; msg_control/msg_controllen describe a buffer
    // we own, and the CMSG_* macros only walk within that length.
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        // SAFETY: `cmsg` is non-null and within the control buffer (CMSG_FIRSTHDR/NXTHDR).
        let c = unsafe { &*cmsg };
        if c.cmsg_level == libc::IPPROTO_IP && c.cmsg_type == libc::IP_PKTINFO {
            // SAFETY: the kernel wrote an in_pktinfo payload for this cmsg type; it may be
            // unaligned, so read_unaligned.
            let info: libc::in_pktinfo =
                unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
            // `ipi_spec_dst` is the local address to answer from: the interface's own
            // address when the query came to a broadcast (or multicast) address, which
            // `ipi_addr` reports and the kernel refuses as a source (EINVAL).
            return Some(LocalAddr {
                ip: IpAddr::V4(Ipv4Addr::from(u32::from_be(info.ipi_spec_dst.s_addr))),
                ifindex: u32::try_from(info.ipi_ifindex).unwrap_or(0),
            });
        }
        if c.cmsg_level == libc::IPPROTO_IPV6 && c.cmsg_type == libc::IPV6_PKTINFO {
            // SAFETY: as above, for in6_pktinfo.
            let info: libc::in6_pktinfo =
                unsafe { ptr::read_unaligned(libc::CMSG_DATA(cmsg).cast()) };
            return Some(LocalAddr {
                ip: IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                ifindex: info.ipi6_ifindex,
            });
        }
        // SAFETY: `msg` and `cmsg` are valid as established above.
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    None
}

/// Writes a PKTINFO cmsg selecting the reply's source address. Returns the control length.
fn write_pktinfo(buf: &mut CtrlBuf, local: LocalAddr) -> usize {
    // A fake msghdr so CMSG_FIRSTHDR can locate the first header in `buf`.
    // SAFETY: all-zero is a valid msghdr.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_control = buf.as_mut_ptr().cast();
    msg.msg_controllen = CTRL_LEN as _;
    // SAFETY: `buf` is CTRL_LEN bytes, 8-byte aligned, and large enough for one cmsghdr plus
    // an in6_pktinfo (CMSG_SPACE(20) = 40 <= 64).
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&raw const msg);
        if cmsg.is_null() {
            return 0;
        }
        match local.ip {
            IpAddr::V4(ip) => {
                let mut info: libc::in_pktinfo = mem::zeroed();
                info.ipi_spec_dst.s_addr = u32::from(ip).to_be();
                (*cmsg).cmsg_level = libc::IPPROTO_IP;
                (*cmsg).cmsg_type = libc::IP_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as u32) as _;
                ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as u32) as usize
            }
            IpAddr::V6(ip) => {
                let mut info: libc::in6_pktinfo = mem::zeroed();
                info.ipi6_addr.s6_addr = ip.octets();
                info.ipi6_ifindex = local.ifindex;
                (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
                (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast(), info);
                libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) as usize
            }
        }
    }
}

/// `statvfs(2)`: `(total, available to unprivileged users)` in bytes (T6.11).
#[allow(clippy::useless_conversion)] // the field widths differ between targets (armv7 is 32-bit)
pub(crate) fn statvfs(path: &std::path::Path) -> io::Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: `statvfs` is plain old data; the kernel fills it in, and all-zero is a valid value.
    let mut st: libc::statvfs = unsafe { mem::zeroed() };
    // SAFETY: `c` is a NUL-terminated path that lives for the call; `st` is a valid, writable
    // `statvfs` the kernel writes into and nothing else aliases.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &raw mut st) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let frsize = u64::from(st.f_frsize);
    let (blocks, avail) = (u64::from(st.f_blocks), u64::from(st.f_bavail));
    Ok((blocks.saturating_mul(frsize), avail.saturating_mul(frsize)))
}

/// REQ: NFR-002 (T10.2) — a read-only, private memory map of a whole file: the filter's FST
/// snapshot files, so their pages are file-backed and can leave the process's resident set
/// (`release`) once the lookup index answers queries.
///
/// Only for files nothing modifies while they're mapped: snapshot files are written once into
/// a fresh directory and never rewritten or truncated in place (ADR-018). If another process
/// truncated one anyway, reading past the new end would raise SIGBUS; the files live in the
/// data directory, which only the service user can write.
#[derive(Debug)]
pub struct MappedFile {
    ptr: ptr::NonNull<u8>,
    len: usize,
}

// SAFETY: the mapping is read-only and private, and `MappedFile` hands out only shared
// slices of it, so sharing or sending it between threads is as safe as for a `Box<[u8]>`.
unsafe impl Send for MappedFile {}
// SAFETY: as above: no interior mutability; every access is a read.
unsafe impl Sync for MappedFile {}

impl MappedFile {
    /// Maps `path` (an empty file maps to an empty slice without a mapping).
    pub fn open(path: &std::path::Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let len = usize::try_from(file.metadata()?.len()).map_err(io::Error::other)?;
        if len == 0 {
            return Ok(Self {
                ptr: ptr::NonNull::dangling(),
                len: 0,
            });
        }
        // SAFETY: a fresh read-only private mapping of an open file descriptor, at an address
        // the kernel picks; the arguments are valid and the result is checked below. The
        // mapping stays valid after `file` closes.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let ptr = ptr::NonNull::new(p.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned null"))?;
        Ok(Self { ptr, len })
    }

    /// Drops this process's copies of the pages (`MADV_DONTNEED`). The data stays valid: the
    /// next read faults the page back in from the file (usually still in the page cache).
    pub fn release(&self) {
        if self.len == 0 {
            return;
        }
        // SAFETY: the range is exactly this mapping; for a private, unmodified file mapping
        // MADV_DONTNEED only discards resident pages, which reads restore from the file.
        // Failure is harmless (the pages just stay resident), so the result is ignored.
        unsafe {
            libc::madvise(self.ptr.as_ptr().cast(), self.len, libc::MADV_DONTNEED);
        }
    }
}

impl std::ops::Deref for MappedFile {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        // SAFETY: `ptr` is a live, readable mapping of `len` bytes (or dangling with `len` 0)
        // that stays mapped until `drop`, and nothing writes to it.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }
}

impl AsRef<[u8]> for MappedFile {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl Drop for MappedFile {
    fn drop(&mut self) {
        if self.len > 0 {
            // SAFETY: unmaps exactly the mapping `open` created; no slice of it outlives
            // `self` (they borrow it).
            unsafe {
                libc::munmap(self.ptr.as_ptr().cast(), self.len);
            }
        }
    }
}

// The allocator the binary links (`mimalloc`); this dependency makes sure its C library is
// linked here too (tests), whether or not it's the global allocator.
use libmimalloc_sys as _;

unsafe extern "C" {
    fn mi_option_set(option: libc::c_int, value: libc::c_long);
    fn mi_collect(force: bool);
}

/// `mi_option_purge_delay` in mimalloc's `mi_option_e` (the same in v2 and v3).
const MI_OPTION_PURGE_DELAY: libc::c_int = 15;

/// REQ: NFR-001 (T10.2) — mimalloc returns freed memory to the OS at once instead of after
/// its default 10 ms delay, which in practice kept a compile's peak and a cache fill's churn
/// resident (98 MiB instead of 170 MiB at a 1M-name compile's peak).
pub(crate) fn allocator_purge_at_once() {
    // SAFETY: mi_option_set only stores an integer option; 0 is a documented value for
    // purge_delay ("immediate purging"). Safe to call from any thread at any time.
    unsafe { mi_option_set(MI_OPTION_PURGE_DELAY, 0) }
}

/// REQ: NFR-001, OBS-902 (ADR-1008 (h)) — mimalloc frees what the calling thread's heap holds
/// empty and returns the arenas' free memory to the OS now, after work that runs rarely and
/// allocates a lot (the GeoIP build). Freed pages a thread keeps for reuse would otherwise stay
/// resident until that thread allocates again in the same size class, which a blocking-pool
/// thread may never do.
pub(crate) fn allocator_collect() {
    // SAFETY: mi_collect takes no pointers and only walks the calling thread's own heap and the
    // shared arenas under mimalloc's own locks; it is documented as callable from any thread at
    // any time (mimalloc makes the same call itself at thread exit).
    unsafe { mi_collect(true) }
}

/// REQ: NFR-001 (T10.2) — drops this process's resident pages of its own executable's
/// read-only mappings (code and constants) that hold no private copies, so code that ran once
/// (start-up, the API router and OpenAPI document, a compile) stops counting. Pages still in
/// use come back on their next access, from the page cache (a minor fault). Returns the bytes
/// that were resident in the mappings it trimmed.
pub(crate) fn trim_executable_pages() -> io::Result<u64> {
    let exe = std::fs::read_link("/proc/self/exe")?;
    let exe = exe.to_string_lossy();
    let smaps = std::fs::read_to_string("/proc/self/smaps")?;
    // (start, end, eligible, rss KiB, anonymous KiB) of the mapping being read.
    let mut cur: Option<(usize, usize, bool, u64, u64)> = None;
    let mut trimmed = 0u64;
    let mut finish = |m: Option<(usize, usize, bool, u64, u64)>| {
        if let Some((start, end, true, rss, 0)) = m
            && rss > 0
        {
            // SAFETY: `start..end` is one whole mapping of this process's executable that's
            // read-only and has no anonymous (copy-on-write) pages, so every page in it is
            // an unmodified copy of the file. For such a private file mapping MADV_DONTNEED
            // only drops resident pages; the next access maps the file's page again (code
            // keeps running, constants read the same). Failure is harmless (nothing changes).
            if unsafe {
                libc::madvise(start as *mut libc::c_void, end - start, libc::MADV_DONTNEED)
            } == 0
            {
                trimmed += rss * 1024;
            }
        }
    };
    for line in smaps.lines() {
        let mut parts = line.split_ascii_whitespace();
        let first = parts.next().unwrap_or_default();
        if let Some((a, b)) = first.split_once('-')
            && let (Ok(start), Ok(end)) =
                (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16))
        {
            finish(cur.take());
            let perms = parts.next().unwrap_or_default();
            let path = parts.skip(3).collect::<Vec<_>>().join(" ");
            let read_only = perms.as_bytes().get(1) == Some(&b'-');
            cur = Some((start, end, read_only && path == exe, 0, 0));
            continue;
        }
        let Some(m) = cur.as_mut() else { continue };
        let mut kib = || {
            parts
                .next()
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(0)
        };
        match first {
            "Rss:" => m.3 = kib(),
            "Anonymous:" => m.4 = kib(),
            _ => {}
        }
    }
    finish(cur.take());
    Ok(trimmed)
}

/// REQ: DSC-002 (ADR-908) — the discovery worker's `RLIMIT_DATA` at `data_bytes` (an allocation past
/// it aborts the worker alone) and `RLIMIT_CORE` 0, so an abort never writes a core file. `RLIMIT_AS`
/// is not used (ADR-908). Lowering both limits needs no privilege.
pub(crate) fn set_worker_rlimits(data_bytes: u64) -> io::Result<()> {
    let data = libc::rlimit {
        rlim_cur: data_bytes as libc::rlim_t,
        rlim_max: data_bytes as libc::rlim_t,
    };
    // SAFETY: setrlimit reads the struct it is given for the duration of the call; RLIMIT_DATA is
    // a valid resource.
    if unsafe { libc::setrlimit(libc::RLIMIT_DATA as _, &raw const data) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: as above, for RLIMIT_CORE: zero means no core file is ever written.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE as _, &raw const core) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Linux capability header for `capset` (`struct __user_cap_header_struct`).
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

/// One capability data word for `capset` (`struct __user_cap_data_struct`).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `_LINUX_CAPABILITY_VERSION_3`: two data words, so all 64 capability bits.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// REQ: DSC-002 (ADR-908, ADR-934) — the discovery worker holds no capability: the ambient set is cleared,
/// the permitted, effective and inheritable sets are emptied, and `no_new_privs` is set, so no exec
/// can gain one. Dropping a capability needs no privilege. The worker needs none: it reads stdin,
/// writes stdout, and lowers its own limits; its OOM score is raised before this runs.
///
/// `capset` is called only when the worker holds a permitted or effective capability. Under the
/// systemd unit the worker is a non-root process whose parent cleared the ambient set before exec
/// ([`clear_ambient_before_exec`]), so it holds none, and `capset` is in systemd's `@privileged` group:
/// a call there is a SIGSYS kill, not an error (N1). A root worker still drops its capabilities.
pub(crate) fn drop_worker_capabilities() -> io::Result<()> {
    // SAFETY: PR_CAP_AMBIENT with PR_CAP_AMBIENT_CLEAR_ALL takes no pointers.
    if unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if thread_holds_capabilities()? {
        let header = CapHeader {
            version: LINUX_CAPABILITY_VERSION_3,
            pid: 0,
        };
        let data = [CapData::default(); 2];
        // SAFETY: capset reads the header and the two data words, both of which live for the call. A
        // pid of 0 is the calling thread's process; empty sets are always a legal new value.
        if unsafe { libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS takes an integer flag and no pointers.
    if unsafe {
        libc::prctl(
            libc::PR_SET_NO_NEW_PRIVS,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Whether the calling thread has a non-empty permitted or effective capability set
/// (`CapPrm`/`CapEff` in `/proc/thread-self/status`). An inheritable bit alone grants nothing: no
/// exec file capability and no ambient capability can turn it into a permitted one.
fn thread_holds_capabilities() -> io::Result<bool> {
    let status = std::fs::read_to_string("/proc/thread-self/status")?;
    Ok(status
        .lines()
        .filter(|l| l.starts_with("CapPrm:") || l.starts_with("CapEff:"))
        .any(|l| l.split_whitespace().nth(1) != Some("0000000000000000")))
}

/// REQ: DSC-002 (ADR-934) — the child of a spawn clears its ambient capability set before it execs.
/// A child inherits the ambient set across exec, so a worker started by a unit that grants
/// `CAP_NET_BIND_SERVICE` (`AmbientCapabilities=`) would start holding it. The prctl runs in the
/// forked child, takes no pointers, and is async-signal-safe.
pub(crate) fn clear_ambient_before_exec(cmd: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: the closure runs in the child between fork and exec and calls only prctl, which is
    // async-signal-safe and allocates nothing. Its error (if any) aborts the spawn.
    unsafe {
        cmd.pre_exec(|| {
            // SAFETY: PR_CAP_AMBIENT with PR_CAP_AMBIENT_CLEAR_ALL takes no pointers.
            if libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// The architecture this build's syscall numbers and filter are for (`AUDIT_ARCH_*`). A 32-bit ARM
/// build uses the ARM EABI table, whose `bind`, `listen` and friends are direct calls (ADR-934).
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_NATIVE: u32 = 0xC000_00B7;
#[cfg(target_arch = "arm")]
const AUDIT_ARCH_NATIVE: u32 = 0x4000_0028;

/// The syscalls a discovery worker never makes: a listening socket (`bind`, `listen`), a tracer
/// (`ptrace`), another process's memory (`process_vm_readv`, `process_vm_writev`), and `io_uring`,
/// whose bind and listen operations skip the syscall filter on kernels 6.11 and later (ADR-934).
/// A compromised worker could otherwise take a share of the DNS port (`SO_REUSEPORT`) or read the
/// parent (ADR-908).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
const WORKER_DENIED_SYSCALLS: [libc::c_long; 8] = [
    libc::SYS_bind,
    libc::SYS_listen,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    libc::SYS_io_uring_setup,
    libc::SYS_io_uring_enter,
    libc::SYS_io_uring_register,
];

/// The first syscall number of the x32 ABI (`__X32_SYSCALL_BIT`). On `x86_64` a call with this bit set
/// (`nr | 0x40000000`) reaches the same handlers as the native call without matching the native
/// number, so the filter refuses the whole range (ADR-934). No other architecture uses it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// REQ: DSC-002 (ADR-908, ADR-934) — installs the worker's seccomp filter: the denied syscalls fail with
/// EPERM, every syscall in the x32 range fails with EPERM, every other syscall is allowed, and a call
/// from another architecture (a 32-bit syscall entry, say) kills the process. Needs `no_new_privs`
/// (set by [`drop_worker_capabilities`]). On an architecture with no filter the worker refuses to run
/// (fail closed, see the other definition).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm"))]
pub(crate) fn install_worker_seccomp() -> io::Result<()> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JMP_JEQ_K: u16 = 0x15;
    const BPF_JMP_JGE_K: u16 = 0x35;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0000 | 1;
    // Offsets into `struct seccomp_data`: `nr`, then `arch`.
    const OFFSET_NR: u32 = 0;
    const OFFSET_ARCH: u32 = 4;
    let stmt = |code: u16, k: u32| libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    };
    let denied = &WORKER_DENIED_SYSCALLS;
    let n = denied.len();
    // Layout: 0 arch, 1 (ours: skip 2), 2 kill, 3 nr, 4 x32 range -> EPERM, 5..5+n one test per denied
    // call (a match jumps to EPERM), 5+n allow, 6+n EPERM.
    let eperm_at = n + 6;
    let mut prog: Vec<libc::sock_filter> = Vec::with_capacity(n + 7);
    prog.push(stmt(BPF_LD_W_ABS, OFFSET_ARCH));
    prog.push(libc::sock_filter {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: AUDIT_ARCH_NATIVE,
    });
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    prog.push(stmt(BPF_LD_W_ABS, OFFSET_NR));
    prog.push(libc::sock_filter {
        code: BPF_JMP_JGE_K,
        jt: u8::try_from(eperm_at - 5).map_err(|_| io::Error::other("seccomp: filter too long"))?,
        jf: 0,
        k: X32_SYSCALL_BIT,
    });
    for (i, nr) in denied.iter().enumerate() {
        let jt = u8::try_from(n - i).map_err(|_| io::Error::other("seccomp: filter too long"))?;
        let k = u32::try_from(*nr).map_err(|_| io::Error::other("seccomp: bad syscall number"))?;
        prog.push(libc::sock_filter {
            code: BPF_JMP_JEQ_K,
            jt,
            jf: 0,
            k,
        });
    }
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    prog.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO_EPERM));
    debug_assert_eq!(prog.len(), eperm_at + 1);
    let len =
        u16::try_from(prog.len()).map_err(|_| io::Error::other("seccomp: filter too long"))?;
    let fprog = libc::sock_fprog {
        len,
        filter: prog.as_mut_ptr(),
    };
    // SAFETY: PR_SET_SECCOMP with SECCOMP_MODE_FILTER reads one `sock_fprog` whose filter points at
    // `prog`, which lives for the call; the kernel copies the program. No_new_privs was set first,
    // so this needs no privilege.
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            ptr::from_ref(&fprog) as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Fails: this architecture has no worker filter, so the worker refuses to run (ADR-908).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "arm")))]
pub(crate) fn install_worker_seccomp() -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no seccomp filter for this architecture",
    ))
}

/// REQ: DSC-002 (ADR-934) — `/proc/self/io`, opened while this process is still dumpable. Once it is
/// not dumpable the file belongs to root with mode 0400, so a non-root process can't open it again
/// (EACCES), and the host's write-rate metric would stop. A descriptor opened earlier keeps working:
/// `pread` at offset 0 regenerates the file. Set on the first call (`prepare_spawn` makes it before
/// the process becomes not dumpable); `None` when the kernel has no such file.
static SELF_IO: std::sync::OnceLock<Option<std::fs::File>> = std::sync::OnceLock::new();

/// Opens [`SELF_IO`] if it isn't open yet. Call before [`set_dumpable`] with `false`.
pub(crate) fn pin_self_io() {
    SELF_IO.get_or_init(|| std::fs::File::open("/proc/self/io").ok());
}

/// The text of `/proc/self/io` as the pinned descriptor reads it now (see [`SELF_IO`]).
pub(crate) fn self_io_text() -> Option<String> {
    use std::os::unix::fs::FileExt as _;
    let file = SELF_IO
        .get_or_init(|| std::fs::File::open("/proc/self/io").ok())
        .as_ref()?;
    let mut buf = [0u8; 4096];
    let n = file.read_at(&mut buf, 0).ok()?;
    String::from_utf8(buf[..n].to_vec()).ok()
}

/// Sets `PR_SET_DUMPABLE`. The worker becomes not dumpable last: a non-dumpable process's `/proc/self`
/// files belong to root, so anything that needs them is done first.
pub(crate) fn set_dumpable(on: bool) -> io::Result<()> {
    // SAFETY: PR_SET_DUMPABLE takes an integer flag and no pointers; 0 makes /proc/<pid> files and
    // core dumps owned by root only.
    if unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            libc::c_ulong::from(on),
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// A `ptrace(PTRACE_TRACEME)` probe, for the test that the filter refuses it (`EPERM`).
#[cfg(test)]
pub(crate) fn ptrace_probe() -> io::Result<()> {
    // SAFETY: PTRACE_TRACEME takes no pointers. The filter refuses it, so the call fails with EPERM
    // and nothing is traced.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_ptrace,
            0 as libc::c_long, // PTRACE_TRACEME
            0 as libc::c_long,
            0 as libc::c_long,
            0 as libc::c_long,
        )
    };
    if rc == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// REQ: DSC-002 (ADR-988) — the process's private writable address space (`VmData` in
/// `/proc/self/status`), in bytes: what `RLIMIT_DATA` counts. `None` when it can't be read.
pub(crate) fn vm_data_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let kib = status
        .lines()
        .find_map(|l| l.strip_prefix("VmData:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    Some(kib.saturating_mul(1024))
}

/// The process's current `RLIMIT_DATA` soft limit, in bytes (`RLIM_INFINITY` as `u64::MAX`).
pub(crate) fn data_limit() -> io::Result<u64> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we pass, which lives for the call.
    if unsafe { libc::getrlimit(libc::RLIMIT_DATA as _, &raw mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(if lim.rlim_cur == libc::RLIM_INFINITY {
        u64::MAX
    } else {
        lim.rlim_cur as u64
    })
}

/// Whether the process is dumpable (`PR_GET_DUMPABLE`).
pub(crate) fn dumpable() -> bool {
    // SAFETY: PR_GET_DUMPABLE takes no pointers and only reads the process's flag.
    unsafe {
        libc::prctl(
            libc::PR_GET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: NFR-001 (T10.2) — trimming the executable's pages leaves the process working:
    /// code and constants read back the same afterwards.
    #[test]
    fn nfr_001_trimming_code_pages_keeps_the_process_working() {
        static TABLE: [u64; 4] = [1, 2, 3, 0xdead_beef];
        let before: u64 = TABLE.iter().sum();
        let trimmed = trim_executable_pages().unwrap();
        assert!(trimmed > 0, "this test's own code was resident");
        assert_eq!(TABLE.iter().sum::<u64>(), before);
        assert_eq!(format!("{:?}", "still runs"), "\"still runs\"");
        allocator_purge_at_once();
        let v: Vec<u8> = vec![7; 1 << 20];
        drop(v);
        // REQ: OBS-902 (ADR-1008 (h)) - a collect after a large free leaves the allocator usable.
        allocator_collect();
        let w: Vec<u8> = vec![9; 1 << 20];
        assert_eq!(w.iter().map(|&b| u64::from(b)).sum::<u64>(), 9 << 20);
    }

    #[test]
    fn dns_001_sockaddr_roundtrip() {
        for addr in [
            "192.0.2.7:5353".parse::<SocketAddr>().unwrap(),
            "[2001:db8::1]:53".parse().unwrap(),
        ] {
            // SAFETY: all-zero is a valid sockaddr_storage.
            let mut s: libc::sockaddr_storage = unsafe { mem::zeroed() };
            let len = std_to_sockaddr(addr, &mut s);
            assert_eq!(sockaddr_to_std(&s, len), Some(addr));
        }
    }

    #[test]
    fn dns_001_pktinfo_cmsg_roundtrip() {
        for ip in [
            "10.1.2.3".parse::<IpAddr>().unwrap(),
            "fe80::1".parse().unwrap(),
        ] {
            let mut buf: CtrlBuf = [0; CTRL_WORDS];
            let local = LocalAddr { ip, ifindex: 3 };
            let len = write_pktinfo(&mut buf, local);
            assert!(len > 0 && len <= CTRL_LEN);
            // SAFETY: all-zero is a valid msghdr.
            let mut msg: libc::msghdr = unsafe { mem::zeroed() };
            msg.msg_control = buf.as_mut_ptr().cast();
            msg.msg_controllen = len as _;
            // Both directions use ipi_spec_dst for v4 (the address to answer from).
            let got = pktinfo_from_cmsgs(&msg);
            assert_eq!(got.map(|l| l.ip), Some(ip));
        }
    }
}
