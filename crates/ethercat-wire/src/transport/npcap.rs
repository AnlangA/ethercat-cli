use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr, CString};
use std::time::{Duration, Instant};

use libloading::Library;

use crate::error::{CliError, Result};
use crate::protocol::constants::{ECAT_FRAME_HEADER_LEN, ETH_HEADER_LEN, ETH_P_ECAT};
use crate::protocol::frame::{parse_dlpdu_datagram_refs, skip_ethernet_vlan_tags};
use crate::transport::{AdapterInfo, EthercatTransport};

const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_IF_LOOPBACK: u32 = 0x0000_0001;
const PCAP_IF_UP: u32 = 0x0000_0002;
const PCAP_IF_RUNNING: u32 = 0x0000_0004;

const PCAP_OPENFLAG_PROMISCUOUS: c_int = 1;
const PCAP_OPENFLAG_NOCAPTURE_LOCAL: c_int = 8;
const PCAP_OPENFLAG_MAX_RESPONSIVENESS: c_int = 16;

#[cfg(windows)]
type TimevalLong = i32;
#[cfg(not(windows))]
type TimevalLong = isize;

#[repr(C)]
struct PcapTimeval {
    tv_sec: TimevalLong,
    tv_usec: TimevalLong,
}

#[repr(C)]
struct PcapPkthdr {
    ts: PcapTimeval,
    caplen: c_uint,
    len: c_uint,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *const c_char,
    description: *const c_char,
    addresses: *const c_void,
    flags: c_uint,
}

type FnFindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FnFreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type FnPcapOpen = unsafe extern "C" fn(
    *const c_char,
    c_int,
    c_int,
    c_int,
    *const c_void,
    *mut c_char,
) -> *mut c_void;
type FnPcapCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut c_void;
type FnPcapSetInt = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type FnPcapActivate = unsafe extern "C" fn(*mut c_void) -> c_int;
type FnPcapClose = unsafe extern "C" fn(*mut c_void);
type FnPcapSendPacket = unsafe extern "C" fn(*mut c_void, *const c_uchar, c_int) -> c_int;
type FnPcapNextEx =
    unsafe extern "C" fn(*mut c_void, *mut *const PcapPkthdr, *mut *const c_uchar) -> c_int;
type FnPcapGetErr = unsafe extern "C" fn(*mut c_void) -> *const c_char;

struct PcapApi {
    _lib: Library,
    _packet_lib: Option<Library>,
    findalldevs: FnFindAllDevs,
    freealldevs: FnFreeAllDevs,
    pcap_open: Option<FnPcapOpen>,
    pcap_create: Option<FnPcapCreate>,
    pcap_set_snaplen: Option<FnPcapSetInt>,
    pcap_set_promisc: Option<FnPcapSetInt>,
    pcap_set_timeout: Option<FnPcapSetInt>,
    pcap_set_immediate_mode: Option<FnPcapSetInt>,
    pcap_setdirection: Option<FnPcapSetInt>,
    pcap_activate: Option<FnPcapActivate>,
    pcap_close: FnPcapClose,
    pcap_sendpacket: FnPcapSendPacket,
    pcap_next_ex: FnPcapNextEx,
    pcap_geterr: Option<FnPcapGetErr>,
}

impl PcapApi {
    fn load() -> Result<Self> {
        let candidates: &[&str] = if cfg!(windows) {
            &[r"C:\Windows\System32\Npcap\wpcap.dll", "wpcap.dll"]
        } else if cfg!(target_os = "macos") {
            &["libpcap.A.dylib", "libpcap.dylib"]
        } else {
            &["libpcap.so.1", "libpcap.so"]
        };

        let mut last_err = String::new();
        let mut loaded = None;

        #[cfg(windows)]
        let packet_lib = {
            // Keep Packet.dll loaded for the lifetime of PcapApi so non-WinPcap-compat installs resolve cleanly
            unsafe { Library::new(r"C:\Windows\System32\Npcap\Packet.dll") }.ok()
        };
        #[cfg(not(windows))]
        let packet_lib: Option<Library> = None;

        for path in candidates {
            match unsafe { Library::new(path) } {
                Ok(lib) => {
                    loaded = Some(lib);
                    break;
                }
                Err(e) => {
                    last_err = format!("{path}: {e}");
                }
            }
        }

        let lib = loaded.ok_or_else(|| {
            CliError::Interface(format!(
                "Cannot load Npcap/libpcap runtime library ({last_err}). Install Npcap (Windows) or libpcap (Linux) and run with sufficient privileges, or use `--iface sim` for local simulation."
            ))
        })?;

        unsafe {
            let findalldevs = *lib
                .get::<FnFindAllDevs>(b"pcap_findalldevs\0")
                .map_err(|e| CliError::Interface(format!("missing pcap_findalldevs: {e}")))?;
            let freealldevs = *lib
                .get::<FnFreeAllDevs>(b"pcap_freealldevs\0")
                .map_err(|e| CliError::Interface(format!("missing pcap_freealldevs: {e}")))?;
            let pcap_open = lib.get::<FnPcapOpen>(b"pcap_open\0").ok().map(|s| *s);
            let pcap_create = lib.get::<FnPcapCreate>(b"pcap_create\0").ok().map(|s| *s);
            let pcap_set_snaplen = lib
                .get::<FnPcapSetInt>(b"pcap_set_snaplen\0")
                .ok()
                .map(|s| *s);
            let pcap_set_promisc = lib
                .get::<FnPcapSetInt>(b"pcap_set_promisc\0")
                .ok()
                .map(|s| *s);
            let pcap_set_timeout = lib
                .get::<FnPcapSetInt>(b"pcap_set_timeout\0")
                .ok()
                .map(|s| *s);
            let pcap_set_immediate_mode = lib
                .get::<FnPcapSetInt>(b"pcap_set_immediate_mode\0")
                .ok()
                .map(|s| *s);
            let pcap_setdirection = lib
                .get::<FnPcapSetInt>(b"pcap_setdirection\0")
                .ok()
                .map(|s| *s);
            let pcap_activate = lib
                .get::<FnPcapActivate>(b"pcap_activate\0")
                .ok()
                .map(|s| *s);
            let pcap_close = *lib
                .get::<FnPcapClose>(b"pcap_close\0")
                .map_err(|e| CliError::Interface(format!("missing pcap_close: {e}")))?;
            let pcap_sendpacket = *lib
                .get::<FnPcapSendPacket>(b"pcap_sendpacket\0")
                .map_err(|e| CliError::Interface(format!("missing pcap_sendpacket: {e}")))?;
            let pcap_next_ex = *lib
                .get::<FnPcapNextEx>(b"pcap_next_ex\0")
                .map_err(|e| CliError::Interface(format!("missing pcap_next_ex: {e}")))?;
            let pcap_geterr = lib.get::<FnPcapGetErr>(b"pcap_geterr\0").ok().map(|s| *s);

            Ok(Self {
                _lib: lib,
                _packet_lib: packet_lib,
                findalldevs,
                freealldevs,
                pcap_open,
                pcap_create,
                pcap_set_snaplen,
                pcap_set_promisc,
                pcap_set_timeout,
                pcap_set_immediate_mode,
                pcap_setdirection,
                pcap_activate,
                pcap_close,
                pcap_sendpacket,
                pcap_next_ex,
                pcap_geterr,
            })
        }
    }
}

pub fn list_npcap_adapters() -> Result<Vec<AdapterInfo>> {
    let api = PcapApi::load()?;
    let mut alldevs: *mut PcapIf = std::ptr::null_mut();
    let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];

    let rc = unsafe { (api.findalldevs)(&mut alldevs, errbuf.as_mut_ptr()) };
    if rc == -1 {
        let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        return Err(CliError::Interface(format!(
            "pcap_findalldevs failed: {msg}"
        )));
    }

    let mut out = Vec::new();
    let mut cur = alldevs;
    while !cur.is_null() {
        let item = unsafe { &*cur };
        let name = if item.name.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(item.name) }
                .to_string_lossy()
                .into_owned()
        };
        let description = if item.description.is_null() {
            "(no description)".to_string()
        } else {
            unsafe { CStr::from_ptr(item.description) }
                .to_string_lossy()
                .into_owned()
        };
        let flags = item.flags;
        out.push(AdapterInfo {
            name,
            description,
            flags,
            is_loopback: (flags & PCAP_IF_LOOPBACK) != 0,
            is_up: (flags & PCAP_IF_UP) != 0,
            is_running: (flags & PCAP_IF_RUNNING) != 0,
            virtual_sim: false,
        });
        cur = item.next;
    }

    if !alldevs.is_null() {
        unsafe { (api.freealldevs)(alldevs) };
    }
    Ok(out)
}

pub struct NpcapTransport {
    api: PcapApi,
    handle: *mut c_void,
    iface_name: String,
    capture_local: bool,
    next_idx: u8,
}

impl NpcapTransport {
    pub fn open(iface: &str, capture_local: bool) -> Result<Self> {
        let api = PcapApi::load()?;
        let c_iface = CString::new(iface)
            .map_err(|_| CliError::Interface("interface name contains NUL byte".into()))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];

        let handle = if let Some(pcap_open_fn) = api.pcap_open {
            let mut flags = PCAP_OPENFLAG_PROMISCUOUS | PCAP_OPENFLAG_MAX_RESPONSIVENESS;
            if !capture_local {
                flags |= PCAP_OPENFLAG_NOCAPTURE_LOCAL;
            }
            // Note: SOEM uses read_timeout = -1 (non-blocking poll) with MAX_RESPONSIVENESS
            unsafe {
                pcap_open_fn(
                    c_iface.as_ptr(),
                    65536,
                    flags,
                    -1,
                    std::ptr::null(),
                    errbuf.as_mut_ptr(),
                )
            }
        } else if let (Some(create_fn), Some(activate_fn)) = (api.pcap_create, api.pcap_activate) {
            let h = unsafe { create_fn(c_iface.as_ptr(), errbuf.as_mut_ptr()) };
            if !h.is_null() {
                if let Some(f) = api.pcap_set_snaplen {
                    unsafe { f(h, 65536) };
                }
                if let Some(f) = api.pcap_set_promisc {
                    unsafe { f(h, 1) };
                }
                if let Some(f) = api.pcap_set_timeout {
                    unsafe { f(h, 1) };
                }
                if let Some(f) = api.pcap_set_immediate_mode {
                    unsafe { f(h, 1) };
                }
                let act = unsafe { activate_fn(h) };
                if act < 0 {
                    unsafe { (api.pcap_close)(h) };
                    std::ptr::null_mut()
                } else {
                    if !capture_local {
                        if let Some(setdir) = api.pcap_setdirection {
                            // PCAP_D_IN = 1: suppress outgoing host TX self-echo on Linux/libpcap
                            let _ = unsafe { setdir(h, 1) };
                        }
                    }
                    h
                }
            } else {
                std::ptr::null_mut()
            }
        } else {
            return Err(CliError::Interface(
                "libpcap has neither pcap_open nor pcap_create".into(),
            ));
        };

        if handle.is_null() {
            let err_msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            return Err(CliError::Interface(format!(
                "Cannot open adapter '{iface}' ({err_msg}). Run as Administrator/root and verify adapter name via `adapters`."
            )));
        }

        Ok(Self {
            api,
            handle,
            iface_name: iface.to_string(),
            capture_local,
            next_idx: 1,
        })
    }

    fn last_pcap_err(&self) -> String {
        if let Some(geterr) = self.api.pcap_geterr {
            let ptr = unsafe { geterr(self.handle) };
            if !ptr.is_null() {
                return unsafe { CStr::from_ptr(ptr) }
                    .to_string_lossy()
                    .into_owned();
            }
        }
        "pcap error".to_string()
    }
}

impl Drop for NpcapTransport {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.api.pcap_close)(self.handle) };
            self.handle = std::ptr::null_mut();
        }
    }
}

impl EthercatTransport for NpcapTransport {
    fn name(&self) -> &str {
        &self.iface_name
    }

    fn next_index(&mut self) -> u8 {
        let idx = self.next_idx;
        self.next_idx = self.next_idx.wrapping_add(1);
        idx
    }

    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<()> {
        let pkt_len = c_int::try_from(frame.len())
            .ok()
            .filter(|&n| (1..=65535).contains(&n))
            .ok_or_else(|| {
                CliError::Format(format!(
                    "invalid Ethernet frame length {} for pcap_sendpacket",
                    frame.len()
                ))
            })?;
        let rc = unsafe { (self.api.pcap_sendpacket)(self.handle, frame.as_ptr(), pkt_len) };
        if rc != 0 {
            return Err(CliError::Interface(format!(
                "pcap_sendpacket failed on '{}': {}",
                self.iface_name,
                self.last_pcap_err()
            )));
        }
        Ok(())
    }

    fn recv_raw_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();
        let deadline = now
            .checked_add(timeout)
            .unwrap_or_else(|| now + Duration::from_secs(3600));
        loop {
            let mut hdr_ptr: *const PcapPkthdr = std::ptr::null();
            let mut data_ptr: *const c_uchar = std::ptr::null();
            let res = unsafe { (self.api.pcap_next_ex)(self.handle, &mut hdr_ptr, &mut data_ptr) };
            if res > 0 && !hdr_ptr.is_null() && !data_ptr.is_null() {
                let caplen = unsafe { (*hdr_ptr).caplen } as usize;
                let slice = unsafe { std::slice::from_raw_parts(data_ptr, caplen) };
                return Ok(Some(slice.to_vec()));
            } else if res == -1 {
                return Err(CliError::Interface(format!(
                    "pcap_next_ex error on '{}': {}",
                    self.iface_name,
                    self.last_pcap_err()
                )));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    fn transact_frame(
        &mut self,
        tx_frame: &[u8],
        expected_idx: Option<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let start = Instant::now();
        let outer_deadline = start
            .checked_add(timeout)
            .unwrap_or_else(|| start + Duration::from_secs(3600));
        // Only retransmit pure read/NOP frames (`0x00`, `0x01`, `0x04`, `0x07`, `0x0A`) so slow slaves
        // never receive duplicate non-idempotent mailbox/EEPROM/register writes.
        let is_idempotent_read = parse_dlpdu_datagram_refs(tx_frame).is_ok_and(|dgs| {
            !dgs.is_empty() && dgs.iter().all(|d| matches!(d.cmd, 0 | 1 | 4 | 7 | 10))
        });
        let per_try = if is_idempotent_read {
            timeout
                .min(Duration::from_millis(25))
                .max(Duration::from_millis(2))
        } else {
            timeout.max(Duration::from_millis(2))
        };
        let filter_tx_echo =
            !self.capture_local && tx_frame.len() >= ETH_HEADER_LEN && (tx_frame[6] & 0x02) == 0;

        loop {
            self.send_raw_frame(tx_frame)?;
            let now = Instant::now();
            let inner_deadline = now
                .checked_add(per_try)
                .map(|d| d.min(outer_deadline))
                .unwrap_or(outer_deadline);
            while Instant::now() < inner_deadline {
                let mut hdr_ptr: *const PcapPkthdr = std::ptr::null();
                let mut data_ptr: *const c_uchar = std::ptr::null();
                let res =
                    unsafe { (self.api.pcap_next_ex)(self.handle, &mut hdr_ptr, &mut data_ptr) };
                if res > 0 && !hdr_ptr.is_null() && !data_ptr.is_null() {
                    let caplen = unsafe { (*hdr_ptr).caplen } as usize;
                    let rx = unsafe { std::slice::from_raw_parts(data_ptr, caplen) };
                    if rx.len() >= ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN + 2 {
                        // Reject unforwarded outgoing TX self-echo (ETG.1000.4 §4.2.2: Port 0 ESC sets src_mac[0] |= 0x02)
                        if filter_tx_echo && (rx[6] & 0x02) == 0 && rx[6..12] == tx_frame[6..12] {
                            continue;
                        }
                        if let Ok((etype, _vlan, off)) = skip_ethernet_vlan_tags(rx, 12) {
                            if etype == ETH_P_ECAT && rx.len() >= off + ECAT_FRAME_HEADER_LEN {
                                let ecat_hdr = u16::from_le_bytes([rx[off], rx[off + 1]]);
                                if (ecat_hdr & 0xF000) == 0x1000 {
                                    let idx_matches = match expected_idx {
                                        Some(exp) => rx.get(off + 3).copied() == Some(exp),
                                        None => true,
                                    };
                                    if idx_matches {
                                        return Ok(rx.to_vec());
                                    }
                                }
                            }
                        }
                    }
                    continue;
                } else if res == -1 {
                    return Err(CliError::Interface(format!(
                        "pcap_next_ex error on '{}': {}",
                        self.iface_name,
                        self.last_pcap_err()
                    )));
                }
                std::thread::sleep(Duration::from_micros(100));
            }
            if Instant::now() >= outer_deadline {
                return Err(CliError::Device(format!(
                    "timeout ({} ms) waiting for EtherCAT response frame on '{}'",
                    timeout.as_millis(),
                    self.iface_name
                )));
            }
        }
    }
}
