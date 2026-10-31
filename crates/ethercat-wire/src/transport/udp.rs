use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::error::{CliError, Result};
use crate::protocol::constants::{
    DEFAULT_MASTER_MAC, ECAT_FRAME_HEADER_LEN, ETH_HEADER_LEN, ETH_P_ECAT, UDP_PORT_ECAT,
};
use crate::protocol::frame::skip_ethernet_vlan_tags;
use crate::transport::EthercatTransport;

/// EtherCAT-over-UDP transport (`ETG.1000.4` / Beckhoff `ET9300Utilities.cEcatUdpMaster`,
/// UDP port `0x88A4 = 34980`, bare 2-byte EtherCAT header + DLPDU datagrams inside UDP).
pub struct UdpEcatTransport {
    uri: String,
    socket: UdpSocket,
    target: SocketAddr,
    is_broadcast_target: bool,
    local_port: u16,
    last_self_ip: Option<(IpAddr, bool)>,
    next_idx: u8,
}

fn parse_endpoint_with_default_port(raw: &str, default_port: u16) -> Result<SocketAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::Usage("empty UDP endpoint address".into()));
    }
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Ok(sa);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    if let Some(bracketed) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        if let Ok(ip) = bracketed.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, default_port));
        }
    }
    let with_port = if trimmed.contains(':') {
        trimmed.to_string()
    } else {
        format!("{trimmed}:{default_port}")
    };
    with_port
        .to_socket_addrs()
        .map_err(|e| CliError::Interface(format!("invalid UDP address '{trimmed}': {e}")))?
        .next()
        .ok_or_else(|| CliError::Interface(format!("could not resolve UDP address '{trimmed}'")))
}

fn is_ipv4_broadcast_like(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => v4.is_broadcast() || v4.octets()[3] == 255,
        IpAddr::V6(_) => false,
    }
}

fn is_local_interface_ip(ip: IpAddr) -> bool {
    ip.is_loopback() || UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

pub fn parse_udp_transport_uri(spec: &str) -> Result<(SocketAddr, SocketAddr, bool)> {
    let trimmed = spec.trim();
    let body = if trimmed
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("udp://"))
    {
        &trimmed[6..]
    } else if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("udp:"))
    {
        &trimmed[4..]
    } else {
        return Err(CliError::Usage(format!(
            "invalid UDP transport URI '{spec}'; expected udp://<target_ip>[:port] or udp://<bind_ip>[:port]@<target_ip>[:port]"
        )));
    };
    if body.trim().is_empty() {
        return Err(CliError::Usage(
            "UDP transport target missing; expected udp://<target_ip>[:34980]".into(),
        ));
    }

    let (bind_opt, target_str) = match body.split_once('@') {
        Some((b, t)) => (Some(b.trim()), t.trim()),
        None => (None, body.trim()),
    };

    let target = parse_endpoint_with_default_port(target_str, UDP_PORT_ECAT)?;
    let bind_addr = if let Some(b_str) = bind_opt.filter(|s| !s.is_empty()) {
        parse_endpoint_with_default_port(b_str, 0)?
    } else {
        match target {
            SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }
    };

    let bcast = is_ipv4_broadcast_like(&target);
    Ok((bind_addr, target, bcast))
}

fn slice_ecat_dlpdu(buf: &[u8]) -> Result<&[u8]> {
    if buf.len() < ECAT_FRAME_HEADER_LEN {
        return Err(CliError::Format(
            "frame too short for 2-byte EtherCAT header".into(),
        ));
    }
    let hdr = u16::from_le_bytes([buf[0], buf[1]]);
    if ((hdr >> 12) & 0x0F) != 0x01 {
        return Err(CliError::Format(format!(
            "unsupported EtherCAT frame header type 0x{:X} (expected DLPDU 0x1)",
            (hdr >> 12) & 0x0F
        )));
    }
    let body_len = (hdr & 0x07FF) as usize;
    let total_ecat = ECAT_FRAME_HEADER_LEN + body_len;
    if total_ecat > buf.len() {
        return Err(CliError::Format(format!(
            "EtherCAT header length ({body_len}) exceeds available payload ({})",
            buf.len() - ECAT_FRAME_HEADER_LEN
        )));
    }
    Ok(&buf[..total_ecat])
}

fn is_valid_bare_dlpdu(buf: &[u8]) -> bool {
    if buf.len() < ECAT_FRAME_HEADER_LEN {
        return false;
    }
    let hdr = u16::from_le_bytes([buf[0], buf[1]]);
    if (hdr & 0xF800) != 0x1000 {
        return false;
    }
    let body_len = (hdr & 0x07FF) as usize;
    if ECAT_FRAME_HEADER_LEN + body_len != buf.len() || body_len < 12 {
        return false;
    }
    let mut pos = ECAT_FRAME_HEADER_LEN;
    loop {
        if pos + 12 > buf.len() {
            return false;
        }
        let len_flags = u16::from_le_bytes([buf[pos + 6], buf[pos + 7]]);
        let dlen = (len_flags & 0x07FF) as usize;
        let more = (len_flags & 0x8000) != 0;
        let next = pos + 10 + dlen + 2;
        if next > buf.len() {
            return false;
        }
        if !more {
            return next == buf.len();
        }
        pos = next;
    }
}

/// Strip L2 Ethernet (`0x88A4`, VLAN-tagged `0x88A4`, or Ethernet+IPv4+UDP `34980`) header and
/// trailing Ethernet padding to produce the wire-level EtherCAT-over-UDP payload (`2B EcatHeader + DLPDU`).
pub fn extract_udp_ecat_payload(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() >= ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN {
        if let Ok((inner_type, _vlan, l3_off)) = skip_ethernet_vlan_tags(frame, 12) {
            if inner_type == ETH_P_ECAT && frame.len() >= l3_off + ECAT_FRAME_HEADER_LEN {
                return slice_ecat_dlpdu(&frame[l3_off..]);
            }

            // Also unwrap Ethernet + IPv4 + UDP (port 0x88A4 = 34980) frames
            if inner_type == 0x0800 && frame.len() >= l3_off + 20 + 8 + ECAT_FRAME_HEADER_LEN {
                let ver_ihl = frame[l3_off];
                let ihl = ((ver_ihl & 0x0F) as usize) * 4;
                if (ver_ihl >> 4) == 4
                    && ihl >= 20
                    && frame[l3_off + 9] == 17
                    && frame.len() >= l3_off + ihl + 8 + ECAT_FRAME_HEADER_LEN
                {
                    let udp_off = l3_off + ihl;
                    let src_port = u16::from_be_bytes([frame[udp_off], frame[udp_off + 1]]);
                    let dst_port = u16::from_be_bytes([frame[udp_off + 2], frame[udp_off + 3]]);
                    let udp_len =
                        u16::from_be_bytes([frame[udp_off + 4], eth_or_zero(frame, udp_off + 5)])
                            as usize;
                    if (src_port == UDP_PORT_ECAT || dst_port == UDP_PORT_ECAT)
                        && udp_len >= 8 + ECAT_FRAME_HEADER_LEN
                        && udp_off + udp_len <= frame.len()
                    {
                        return slice_ecat_dlpdu(&frame[udp_off + 8..udp_off + udp_len]);
                    }
                }
            }
        }
    }

    if is_valid_bare_dlpdu(frame) {
        return Ok(frame);
    }

    Err(CliError::Format(
        "frame is not a valid 0x88A4 EtherCAT frame or bare EtherCAT DLPDU".into(),
    ))
}

#[inline]
fn eth_or_zero(buf: &[u8], idx: usize) -> u8 {
    buf.get(idx).copied().unwrap_or(0)
}

/// Wrap a received UDP EtherCAT payload (`2B EcatHeader + DLPDU`) in a synthetic L2 `0x88A4`
/// Ethernet header so `parse_dlpdu_datagrams` and `dissect_frame` operate uniformly across all transports.
pub fn wrap_udp_ecat_payload(udp_payload: &[u8]) -> Result<Vec<u8>> {
    let valid_dlpdu = slice_ecat_dlpdu(udp_payload).map_err(|e| match e {
        CliError::Format(msg) => CliError::Protocol(format!("invalid UDP EtherCAT packet: {msg}")),
        other => other,
    })?;
    let mut eth = Vec::with_capacity(ETH_HEADER_LEN + valid_dlpdu.len());
    eth.extend_from_slice(&DEFAULT_MASTER_MAC);
    let mut slave_src = DEFAULT_MASTER_MAC;
    slave_src[0] |= 0x02; // Locally-administered bit indicating slave-processed return frame
    eth.extend_from_slice(&slave_src);
    eth.extend_from_slice(&ETH_P_ECAT.to_be_bytes());
    eth.extend_from_slice(valid_dlpdu);
    Ok(eth)
}

impl UdpEcatTransport {
    pub fn open(spec: &str) -> Result<Self> {
        let (bind_addr, target, is_broadcast_target) = parse_udp_transport_uri(spec)?;
        let socket = UdpSocket::bind(bind_addr).map_err(|e| {
            CliError::Interface(format!(
                "cannot bind UDP socket on {bind_addr} for '{spec}': {e}"
            ))
        })?;
        if is_broadcast_target {
            socket.set_broadcast(true).map_err(|e| {
                CliError::Interface(format!(
                    "cannot enable SO_BROADCAST on UDP socket for '{spec}': {e}"
                ))
            })?;
        }
        let local_port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
        Ok(Self {
            uri: spec.trim().to_string(),
            socket,
            target,
            is_broadcast_target,
            local_port,
            last_self_ip: None,
            next_idx: 1,
        })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket
            .local_addr()
            .map_err(|e| CliError::Interface(format!("cannot query UDP local_addr: {e}")))
    }
    pub fn target_addr(&self) -> SocketAddr {
        self.target
    }

    fn drain_stale_rx(&self) {
        if self.socket.set_nonblocking(true).is_ok() {
            let mut scratch = [0u8; 4096];
            while self.socket.recv_from(&mut scratch).is_ok() {}
            let _ = self.socket.set_nonblocking(false);
        }
    }

    fn recv_udp_datagram(&self, timeout: Duration) -> Result<Option<(Vec<u8>, SocketAddr)>> {
        let wait = timeout.max(Duration::from_millis(1));
        self.socket
            .set_read_timeout(Some(wait))
            .map_err(|e| CliError::Interface(format!("cannot set UDP read timeout: {e}")))?;
        let mut buf = [0u8; 4096];
        match self.socket.recv_from(&mut buf) {
            Ok((n, peer)) => Ok(Some((buf[..n].to_vec(), peer))),
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::ConnectionReset
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(CliError::Interface(format!("UDP recv_from error: {e}"))),
        }
    }
}

impl EthercatTransport for UdpEcatTransport {
    fn name(&self) -> &str {
        &self.uri
    }

    fn next_index(&mut self) -> u8 {
        let idx = self.next_idx;
        self.next_idx = self.next_idx.wrapping_add(1);
        idx
    }

    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<()> {
        let payload = extract_udp_ecat_payload(frame)?;
        let sent = self
            .socket
            .send_to(payload, self.target)
            .map_err(|e| CliError::Interface(format!("UDP send_to {} failed: {e}", self.target)))?;
        if sent != payload.len() {
            return Err(CliError::Interface(format!(
                "UDP partial send ({sent} of {} bytes)",
                payload.len()
            )));
        }
        Ok(())
    }

    fn recv_raw_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        let now = Instant::now();
        let wait = timeout.max(Duration::from_millis(1));
        let deadline = now
            .checked_add(wait)
            .unwrap_or_else(|| now + Duration::from_secs(3600));
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            let remaining = (deadline - now).max(Duration::from_millis(1));
            let Some((udp_bytes, _peer)) = self.recv_udp_datagram(remaining)? else {
                return Ok(None);
            };
            if let Ok(eth) = wrap_udp_ecat_payload(&udp_bytes) {
                return Ok(Some(eth));
            }
        }
    }

    fn transact_frame(
        &mut self,
        tx_frame: &[u8],
        expected_idx: Option<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let tx_payload = extract_udp_ecat_payload(tx_frame)?.to_vec();
        self.drain_stale_rx();
        let sent = self
            .socket
            .send_to(&tx_payload, self.target)
            .map_err(|e| CliError::Interface(format!("UDP send_to {} failed: {e}", self.target)))?;
        if sent != tx_payload.len() {
            return Err(CliError::Interface(format!(
                "UDP partial send ({sent} of {} bytes)",
                tx_payload.len()
            )));
        }

        let start = Instant::now();
        let wait = timeout.max(Duration::from_millis(1));
        let deadline = start
            .checked_add(wait)
            .unwrap_or_else(|| start + Duration::from_secs(3600));
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(CliError::Device(format!(
                    "timeout waiting for EtherCAT-over-UDP response from {} ({} ms)",
                    self.target,
                    timeout.as_millis()
                )));
            }
            let remaining = (deadline - now).max(Duration::from_millis(1));
            let Some((udp_rx, peer)) = self.recv_udp_datagram(remaining)? else {
                continue;
            };

            // Filter OS self-broadcast loopback echo when bound to the target UDP port (e.g. 34980 -> 255.255.255.255:34980)
            if self.is_broadcast_target && peer.port() == self.local_port && udp_rx == tx_payload {
                let peer_ip = peer.ip();
                let is_self = match self.last_self_ip {
                    Some((cached_ip, res)) if cached_ip == peer_ip => res,
                    _ => {
                        let res = is_local_interface_ip(peer_ip);
                        self.last_self_ip = Some((peer_ip, res));
                        res
                    }
                };
                if is_self {
                    continue;
                }
            }

            let Ok(rx_eth) = wrap_udp_ecat_payload(&udp_rx) else {
                // Ignore stray non-EtherCAT / truncated UDP packets on port 34980
                continue;
            };

            if let Some(exp_idx) = expected_idx {
                let min_single_dg_eth_len = ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN + 12;
                let idx_pos = ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN + 1;
                if rx_eth.len() < min_single_dg_eth_len || rx_eth[idx_pos] != exp_idx {
                    continue;
                }
            }
            return Ok(rx_eth);
        }
    }
}
