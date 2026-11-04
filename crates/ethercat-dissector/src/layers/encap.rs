use std::collections::BTreeMap;
use std::net::Ipv6Addr;

use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::{
    ECAT_FRAME_HEADER_LEN, ETH_HEADER_LEN, ETH_P_ECAT, UDP_PORT_ECAT,
};
use ethercat_wire::types::format_mac;
use serde_json::{json, Value};

use crate::layers::esl::{dissect_esl_tag, ESL_HEADER_LEN, ESL_SIGNATURE};
use crate::model::{DissectedEsl, DissectedEthernet};

/// Official EtherCAT-over-TCP port registered by Wireshark `packet-ecatf.c` (`0x88A4 = 34980`).
pub const TCP_PORT_ECAT: u16 = UDP_PORT_ECAT;
/// Official Beckhoff AMS/TCP port (`0xBF02 = 48898`).
pub const TCP_PORT_AMS: u16 = 48898;
/// Official Beckhoff AMS/UDP port (`0xBF03 = 48899`).
pub const UDP_PORT_AMS: u16 = 48899;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadProtocol {
    /// Standard 2-byte EtherCAT Frame Header (`ecatf`) at `[start..end)`.
    EthercatFrame,
    /// Standalone AMS/TCP payload (6-byte AMS/TCP header `[reserved:u16, length:u32_le]` + AMS PDU).
    AmsTcp,
    /// Standalone AMS/UDP payload (starts directly at 32-byte AMS header).
    AmsUdp,
}

pub struct ParsedEncapsulation {
    pub esl_prefix: Option<DissectedEsl>,
    pub ethernet: Option<DissectedEthernet>,
    pub payload_proto: PayloadProtocol,
    pub payload_start: usize,
    pub payload_end: usize,
}

/// Skips up to 2 IEEE 802.1Q / 802.1ad VLAN tags and returns `(ethertype, outer_vlan, inner_vlan, payload_offset)`.
pub fn skip_vlan_tags_ext(
    buf: &[u8],
    ethertype_off: usize,
) -> Result<(u16, Option<u16>, Option<u16>, usize)> {
    if buf.len() < ethertype_off + 2 {
        return Err(CliError::Format("truncated Ethernet EtherType".into()));
    }
    let mut pos = ethertype_off;
    let mut etype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    pos += 2;
    let mut outer_vlan = None;
    let mut inner_vlan = None;
    for tag_idx in 0..2 {
        if matches!(etype, 0x8100 | 0x88A8 | 0x9100) {
            if buf.len() < pos + 4 {
                return Err(CliError::Format("truncated 802.1Q/802.1ad VLAN tag".into()));
            }
            let tci = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
            let vid = tci & 0x0FFF;
            if tag_idx == 0 {
                inner_vlan = Some(vid);
            } else {
                outer_vlan = inner_vlan;
                inner_vlan = Some(vid);
            }
            etype = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
            pos += 4;
        } else {
            break;
        }
    }
    Ok((etype, outer_vlan, inner_vlan, pos))
}

struct ParsedL3Header {
    is_ipv6: bool,
    proto: u8,
    l4_off: usize,
    ip_end_in_eth: usize,
    src_ip: String,
    dst_ip: String,
}

fn parse_l3_ip_header(eth: &[u8], etype: u16, pos: usize) -> Option<ParsedL3Header> {
    if etype == 0x0800 && eth.len() >= pos + 20 {
        let ver = eth[pos] >> 4;
        let ihl = ((eth[pos] & 0x0F) as usize) * 4;
        if ver != 4 || ihl < 20 || eth.len() < pos + ihl + 8 {
            return None;
        }
        let frag_off = u16::from_be_bytes([eth[pos + 6], eth[pos + 7]]) & 0x1FFF;
        if frag_off != 0 {
            return None;
        }
        let ip_total_len = u16::from_be_bytes([eth[pos + 2], eth[pos + 3]]) as usize;
        let ip_end_in_eth = if ip_total_len >= ihl + 8 {
            (pos + ip_total_len).min(eth.len())
        } else {
            eth.len()
        };
        let src_ip = format!(
            "{}.{}.{}.{}",
            eth[pos + 12],
            eth[pos + 13],
            eth[pos + 14],
            eth[pos + 15]
        );
        let dst_ip = format!(
            "{}.{}.{}.{}",
            eth[pos + 16],
            eth[pos + 17],
            eth[pos + 18],
            eth[pos + 19]
        );
        return Some(ParsedL3Header {
            is_ipv6: false,
            proto: eth[pos + 9],
            l4_off: pos + ihl,
            ip_end_in_eth,
            src_ip,
            dst_ip,
        });
    }
    if etype == 0x86DD && eth.len() >= pos + 40 {
        let ver = eth[pos] >> 4;
        if ver != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([eth[pos + 4], eth[pos + 5]]) as usize;
        let ip_end_in_eth = if payload_len > 0 {
            (pos + 40 + payload_len).min(eth.len())
        } else {
            eth.len()
        };
        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&eth[pos + 8..pos + 24]);
        dst_octets.copy_from_slice(&eth[pos + 24..pos + 40]);
        let src_ip = Ipv6Addr::from(src_octets).to_string();
        let dst_ip = Ipv6Addr::from(dst_octets).to_string();

        let mut nh = eth[pos + 6];
        let mut ext_off = pos + 40;
        for _ in 0..6 {
            if matches!(nh, 0 | 43 | 60) {
                if ext_off + 2 > ip_end_in_eth {
                    return None;
                }
                let next = eth[ext_off];
                let hdr_len = (eth[ext_off + 1] as usize + 1) * 8;
                if ext_off + hdr_len > ip_end_in_eth {
                    return None;
                }
                ext_off += hdr_len;
                nh = next;
            } else if nh == 44 {
                if ext_off + 8 > ip_end_in_eth {
                    return None;
                }
                let frag_off_flags = u16::from_be_bytes([eth[ext_off + 2], eth[ext_off + 3]]);
                if (frag_off_flags & 0xFFF8) != 0 {
                    return None;
                }
                nh = eth[ext_off];
                ext_off += 8;
            } else {
                break;
            }
        }
        if ext_off + 8 > ip_end_in_eth {
            return None;
        }
        return Some(ParsedL3Header {
            is_ipv6: true,
            proto: nh,
            l4_off: ext_off,
            ip_end_in_eth,
            src_ip,
            dst_ip,
        });
    }
    None
}

fn has_supported_l2_header(eth: &[u8]) -> bool {
    if eth.len() < ETH_HEADER_LEN {
        return false;
    }
    let Ok((etype, _outer, _inner, pos)) = skip_vlan_tags_ext(eth, 12) else {
        return false;
    };
    if etype == ETH_P_ECAT {
        return true;
    }
    if let Some(l3) = parse_l3_ip_header(eth, etype, pos) {
        let l4_off = l3.l4_off;
        if l3.proto == 17 && eth.len() >= l4_off + 8 {
            let src_port = u16::from_be_bytes([eth[l4_off], eth[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[l4_off + 2], eth[l4_off + 3]]);
            let udp_len = u16::from_be_bytes([eth[l4_off + 4], eth[l4_off + 5]]) as usize;
            return udp_len >= 8
                && (src_port == UDP_PORT_ECAT
                    || dst_port == UDP_PORT_ECAT
                    || src_port == UDP_PORT_AMS
                    || dst_port == UDP_PORT_AMS);
        }
        if l3.proto == 6 && eth.len() >= l4_off + 20 {
            let src_port = u16::from_be_bytes([eth[l4_off], eth[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[l4_off + 2], eth[l4_off + 3]]);
            let data_off = ((eth[l4_off + 12] >> 4) as usize) * 4;
            return data_off >= 20
                && l3.ip_end_in_eth > l4_off + data_off
                && (src_port == TCP_PORT_AMS
                    || dst_port == TCP_PORT_AMS
                    || src_port == TCP_PORT_ECAT
                    || dst_port == TCP_PORT_ECAT);
        }
    }
    false
}

/// Fast zero-allocation pre-check whether `raw` carries an EtherCAT or AMS/ADS frame:
/// - Ethernet II `0x88A4`
/// - IEEE 802.1Q / 802.1ad VLAN + `0x88A4`
/// - Beckhoff ESL 16-byte prefix + Ethernet
/// - IPv4 or IPv6 + UDP port `34980` (`0x88A4` EtherCAT/UDP) or `48899` (`AMS/UDP`)
/// - IPv4 or IPv6 + TCP port `34980` (`0x88A4` EtherCAT/TCP) or `48898` (`AMS/TCP`) with payload
pub fn may_contain_ethercat(raw: &[u8], bare_ecat: bool) -> bool {
    if bare_ecat {
        return raw.len() >= ECAT_FRAME_HEADER_LEN;
    }
    if raw.len() >= ESL_HEADER_LEN + ETH_HEADER_LEN
        && raw[0..6] == ESL_SIGNATURE
        && has_supported_l2_header(&raw[ESL_HEADER_LEN..])
    {
        return true;
    }
    has_supported_l2_header(raw)
}

/// Parses outer L2/VLAN/IPv4/UDP/TCP/ESL encapsulation.
pub fn parse_l2_encapsulation(
    raw: &[u8],
    ws: &mut BTreeMap<String, Value>,
) -> Result<ParsedEncapsulation> {
    let (esl_prefix, l2_base) = if raw.len() >= ESL_HEADER_LEN + ETH_HEADER_LEN
        && raw[0..6] == ESL_SIGNATURE
        && has_supported_l2_header(&raw[ESL_HEADER_LEN..])
    {
        let esl = dissect_esl_tag(&raw[0..ESL_HEADER_LEN], "prefix", ws);
        (Some(esl), ESL_HEADER_LEN)
    } else {
        (None, 0usize)
    };

    let eth = &raw[l2_base..];
    if eth.len() < ETH_HEADER_LEN {
        return Err(CliError::Format(format!(
            "frame too short ({} bytes < 14-byte Ethernet header); use --bare for headerless EtherCAT frames",
            eth.len()
        )));
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&eth[0..6]);
    src.copy_from_slice(&eth[6..12]);
    let dst_str = format_mac(&dst);
    let src_str = format_mac(&src);
    let src_local_admin = (src[0] & 0x02) != 0;

    let (etype, outer_vlan, vlan_id, pos) = skip_vlan_tags_ext(eth, 12)?;

    ws.insert("eth.dst".into(), json!(dst_str.clone()));
    ws.insert("eth.src".into(), json!(src_str.clone()));
    ws.insert("eth.type".into(), json!(format!("0x{etype:04x}")));
    if let Some(ovid) = outer_vlan {
        ws.insert("vlan.outer_id".into(), json!(ovid));
    }
    if let Some(vid) = vlan_id {
        ws.insert("vlan.id".into(), json!(vid));
    }

    if etype == ETH_P_ECAT {
        let encap = match (esl_prefix.is_some(), vlan_id.is_some()) {
            (true, true) => "Beckhoff ESL + Ethernet + 802.1Q VLAN + EtherCAT (0x88A4)",
            (true, false) => "Beckhoff ESL + Ethernet II + EtherCAT (0x88A4)",
            (false, true) => "Ethernet + 802.1Q VLAN + EtherCAT (0x88A4)",
            (false, false) => "Ethernet II + EtherCAT (0x88A4)",
        };
        return Ok(ParsedEncapsulation {
            esl_prefix,
            ethernet: Some(DissectedEthernet {
                dst_mac: dst_str,
                src_mac: src_str,
                src_locally_administered: src_local_admin,
                vlan_id,
                outer_vlan_id: outer_vlan,
                ethertype: format!("0x{etype:04x}"),
                encapsulation: encap,
                src_ip: None,
                dst_ip: None,
                src_port: None,
                dst_port: None,
                tcp_seq: None,
                tcp_flags: None,
            }),
            payload_proto: PayloadProtocol::EthercatFrame,
            payload_start: l2_base + pos,
            payload_end: raw.len(),
        });
    }

    // IPv4 (0x0800) or IPv6 (0x86DD) + UDP (port 34980 / 48899) or TCP (port 34980 / 48898)
    if let Some(l3) = parse_l3_ip_header(eth, etype, pos) {
        let l4_off = l3.l4_off;
        if l3.proto == 17 && eth.len() >= l4_off + 8 {
            let src_port = u16::from_be_bytes([eth[l4_off], eth[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[l4_off + 2], eth[l4_off + 3]]);
            let udp_len = u16::from_be_bytes([eth[l4_off + 4], eth[l4_off + 5]]) as usize;
            if udp_len >= 8
                && (src_port == UDP_PORT_ECAT
                    || dst_port == UDP_PORT_ECAT
                    || src_port == UDP_PORT_AMS
                    || dst_port == UDP_PORT_AMS)
            {
                if l3.is_ipv6 {
                    ws.insert("ipv6.src".into(), json!(l3.src_ip.clone()));
                    ws.insert("ipv6.dst".into(), json!(l3.dst_ip.clone()));
                } else {
                    ws.insert("ip.src".into(), json!(l3.src_ip.clone()));
                    ws.insert("ip.dst".into(), json!(l3.dst_ip.clone()));
                }
                ws.insert("udp.srcport".into(), json!(src_port));
                ws.insert("udp.dstport".into(), json!(dst_port));
                let is_ecat = src_port == UDP_PORT_ECAT || dst_port == UDP_PORT_ECAT;
                let has_esl = esl_prefix.is_some();
                let udp_end = (l2_base + l4_off + udp_len)
                    .min(l2_base + l3.ip_end_in_eth)
                    .min(raw.len());
                let encap = match (l3.is_ipv6, is_ecat, has_esl) {
                    (false, true, true) => {
                        "Beckhoff ESL + Ethernet + IPv4 + UDP (port 34980 / 0x88A4)"
                    }
                    (false, true, false) => "Ethernet + IPv4 + UDP (port 34980 / 0x88A4)",
                    (false, false, true) => "Beckhoff ESL + Ethernet + IPv4 + UDP (AMS port 48899)",
                    (false, false, false) => "Ethernet + IPv4 + UDP (AMS port 48899)",
                    (true, true, true) => {
                        "Beckhoff ESL + Ethernet + IPv6 + UDP (port 34980 / 0x88A4)"
                    }
                    (true, true, false) => "Ethernet + IPv6 + UDP (port 34980 / 0x88A4)",
                    (true, false, true) => "Beckhoff ESL + Ethernet + IPv6 + UDP (AMS port 48899)",
                    (true, false, false) => "Ethernet + IPv6 + UDP (AMS port 48899)",
                };
                return Ok(ParsedEncapsulation {
                    esl_prefix,
                    ethernet: Some(DissectedEthernet {
                        dst_mac: dst_str,
                        src_mac: src_str,
                        src_locally_administered: src_local_admin,
                        vlan_id,
                        outer_vlan_id: outer_vlan,
                        ethertype: format!("0x{etype:04x}"),
                        encapsulation: encap,
                        src_ip: Some(l3.src_ip),
                        dst_ip: Some(l3.dst_ip),
                        src_port: Some(src_port),
                        dst_port: Some(dst_port),
                        tcp_seq: None,
                        tcp_flags: None,
                    }),
                    payload_proto: if is_ecat {
                        PayloadProtocol::EthercatFrame
                    } else {
                        PayloadProtocol::AmsUdp
                    },
                    payload_start: l2_base + l4_off + 8,
                    payload_end: udp_end,
                });
            }
        }

        if l3.proto == 6 && eth.len() >= l4_off + 20 {
            let src_port = u16::from_be_bytes([eth[l4_off], eth[l4_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[l4_off + 2], eth[l4_off + 3]]);
            let tcp_seq = u32::from_be_bytes([
                eth[l4_off + 4],
                eth[l4_off + 5],
                eth[l4_off + 6],
                eth[l4_off + 7],
            ]);
            let data_off = ((eth[l4_off + 12] >> 4) as usize) * 4;
            let tcp_flags = eth[l4_off + 13];
            let ip_end = (l2_base + l3.ip_end_in_eth).min(raw.len());
            let payload_start = l2_base + l4_off + data_off;
            let is_ams = src_port == TCP_PORT_AMS || dst_port == TCP_PORT_AMS;
            let is_ecat = !is_ams && (src_port == TCP_PORT_ECAT || dst_port == TCP_PORT_ECAT);
            if data_off >= 20 && ip_end > payload_start && (is_ams || is_ecat) {
                if l3.is_ipv6 {
                    ws.insert("ipv6.src".into(), json!(l3.src_ip.clone()));
                    ws.insert("ipv6.dst".into(), json!(l3.dst_ip.clone()));
                } else {
                    ws.insert("ip.src".into(), json!(l3.src_ip.clone()));
                    ws.insert("ip.dst".into(), json!(l3.dst_ip.clone()));
                }
                ws.insert("tcp.srcport".into(), json!(src_port));
                ws.insert("tcp.dstport".into(), json!(dst_port));
                let has_esl = esl_prefix.is_some();
                let encap = match (l3.is_ipv6, is_ecat, has_esl) {
                    (false, false, true) => "Beckhoff ESL + Ethernet + IPv4 + TCP (AMS port 48898)",
                    (false, false, false) => "Ethernet + IPv4 + TCP (AMS port 48898)",
                    (false, true, true) => {
                        "Beckhoff ESL + Ethernet + IPv4 + TCP (port 34980 / 0x88A4)"
                    }
                    (false, true, false) => "Ethernet + IPv4 + TCP (port 34980 / 0x88A4)",
                    (true, false, true) => "Beckhoff ESL + Ethernet + IPv6 + TCP (AMS port 48898)",
                    (true, false, false) => "Ethernet + IPv6 + TCP (AMS port 48898)",
                    (true, true, true) => {
                        "Beckhoff ESL + Ethernet + IPv6 + TCP (port 34980 / 0x88A4)"
                    }
                    (true, true, false) => "Ethernet + IPv6 + TCP (port 34980 / 0x88A4)",
                };
                return Ok(ParsedEncapsulation {
                    esl_prefix,
                    ethernet: Some(DissectedEthernet {
                        dst_mac: dst_str,
                        src_mac: src_str,
                        src_locally_administered: src_local_admin,
                        vlan_id,
                        outer_vlan_id: outer_vlan,
                        ethertype: format!("0x{etype:04x}"),
                        encapsulation: encap,
                        src_ip: Some(l3.src_ip),
                        dst_ip: Some(l3.dst_ip),
                        src_port: Some(src_port),
                        dst_port: Some(dst_port),
                        tcp_seq: Some(tcp_seq),
                        tcp_flags: Some(tcp_flags),
                    }),
                    payload_proto: if is_ecat {
                        PayloadProtocol::EthercatFrame
                    } else {
                        PayloadProtocol::AmsTcp
                    },
                    payload_start,
                    payload_end: ip_end,
                });
            }
        }
    }

    Err(CliError::Format(format!(
        "unsupported EtherType 0x{etype:04X} (expected 0x88A4 EtherCAT, IPv4/IPv6 UDP/TCP 34980, AMS TCP/48898, or AMS UDP/48899)"
    )))
}
