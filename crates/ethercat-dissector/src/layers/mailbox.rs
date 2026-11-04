use std::collections::BTreeMap;

use ethercat_wire::protocol::constants::{
    coe_service_name, ect_datatype_name, sdo_abort_description,
};
use ethercat_wire::types::{decode_typed_value, format_hex, format_mac, DataTypeSpec};
use serde_json::{json, Map, Value};

use crate::catalog::{foe_efw_cmd_name, mailbox_type_name};
use crate::layers::ams::dissect_ams_pdu;
use crate::model::{DissectedMailbox, EoeFragmentInfo, SdoEventKind, SdoInfoFragmentInfo};

/// Computes the standard CANopen CiA 301 / ETG.1000.6 CoE SDO Block Transfer 16-bit CRC
/// (`poly = 0x1021`, `init = 0x0000`, MSB-first, no reflection, `xorout = 0x0000`).
pub fn sdo_block_crc16(bytes: &[u8]) -> u16 {
    let mut crc: u16 = 0x0000;
    for &b in bytes {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Heuristic check whether a physical memory payload at `ado >= 0x1000` looks like a valid EtherCAT Mailbox PDU.
pub fn looks_like_mailbox(ado: u16, data: &[u8]) -> bool {
    if ado < 0x1000 || data.len() < 6 {
        return false;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if len == 0 || 6 + len > data.len() {
        return false;
    }
    let chan = data[4] & 0x3F;
    if chan != 0 {
        return false;
    }
    // Byte 5: bits 0..3 protocol type (or 0x81..0x85 error codes if bit 7 set in legacy error frames)
    let raw_type = data[5] & 0x8F;
    let body = &data[6..6 + len];
    match raw_type {
        0x00 => len == 4,
        0x01 => len >= 24,
        0x02 => len >= 4,
        0x03 => len >= 2 && matches!((body[1] >> 4) & 0x0F, 0x01..=0x08),
        0x04 => len >= 2 && matches!(body[0], 0x01..=0x06),
        0x05 => len >= 4 && matches!(body[0] & 0x07, 0x01..=0x07),
        0x0F => len >= 4,
        0x81..=0x85 => len >= 4 && (data[5] & 0x70) == 0,
        _ => false,
    }
}

pub fn mbx_error_detail_description(detail: u16) -> &'static str {
    match detail {
        0x01 => "Syntax of 6 octet Mailbox Header is wrong",
        0x02 => "The mailbox protocol is not supported",
        0x03 => "Invalid Channel Code",
        0x04 => "The service in the Mailbox protocol is not supported",
        0x05 => "Invalid mailbox protocol header",
        0x06 => "Length of received mailbox data is too short",
        0x07 => "No more memory in slave",
        0x08 => "The length of data is inconsistent",
        _ => "Unknown mailbox error detail",
    }
}

pub fn sdo_info_entry_name_offset(value_info: u8, bit_len: u16, total_len: usize) -> usize {
    let val_bytes = (bit_len as usize).div_ceil(8);
    let mut extra = 0usize;
    if (value_info & 0x08) != 0 {
        extra += 4; // Unit Type (UNSIGNED32)
    }
    if (value_info & 0x10) != 0 {
        extra += val_bytes; // Default value
    }
    if (value_info & 0x20) != 0 {
        extra += val_bytes; // Minimum value
    }
    if (value_info & 0x40) != 0 {
        extra += val_bytes; // Maximum value
    }
    (10 + extra).min(total_len)
}

/// Dissects an EtherCAT Mailbox PDU (`ecat_mailbox`), emitting both official Wireshark 4.6
/// fields and backward-compatible CLI selectors.
pub fn dissect_mailbox(
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> Option<DissectedMailbox> {
    dissect_mailbox_ext(data, ws, prefix, false)
}

pub fn dissect_mailbox_ext(
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
    force_efw: bool,
) -> Option<DissectedMailbox> {
    if data.len() < 6 {
        return None;
    }
    let length = u16::from_le_bytes([data[0], data[1]]);
    let address = u16::from_le_bytes([data[2], data[3]]);
    let channel = data[4] & 0x3F;
    let priority = (data[4] >> 6) & 0x03;
    let is_err_type = (data[5] & 0x80) != 0 && matches!(data[5] & 0x8F, 0x81..=0x85);
    let mbx_type = if is_err_type {
        data[5] & 0x8F
    } else {
        data[5] & 0x0F
    };
    let counter = if is_err_type {
        0
    } else {
        (data[5] >> 4) & 0x07
    };
    let mbx_type_str = mailbox_type_name(mbx_type);

    let malformed = (6 + length as usize) > data.len() || length == 0;
    let body_end = (6 + length as usize).min(data.len());
    let body = &data[6..body_end];

    ws.insert(format!("{prefix}.length"), json!(length));
    ws.insert(
        format!("{prefix}.address"),
        json!(format!("0x{address:04x}")),
    );
    ws.insert(format!("{prefix}.channel"), json!(channel));
    ws.insert(format!("{prefix}.priority"), json!(priority));
    ws.insert(format!("{prefix}.type"), json!(mbx_type));
    ws.insert(format!("{prefix}.type_name"), json!(mbx_type_str));
    ws.insert(format!("{prefix}.counter"), json!(counter));
    ws.insert(format!("{prefix}.cnt"), json!(counter));
    // Wireshark 4.6 `dissect_ecat_mailbox()`: `ecat_mailbox.data` covers the remaining bytes when the
    // mailbox is shorter than `6 + Length`, or the body when the type is not AoE/EoE/CoE/FoE/SoE.
    if data.len() < 6 + length as usize {
        ws.insert(format!("{prefix}.data"), json!(format_hex(&data[6..])));
    } else if !matches!(data[5] & 0x0F, 0x01..=0x05) {
        ws.insert(format!("{prefix}.data"), json!(format_hex(body)));
    }
    if malformed {
        ws.insert(format!("{prefix}.invalid"), json!(true));
    }

    let mut sdo_event = None;
    let mut sdo_info_fragment = None;
    let mut eoe_fragment = None;
    let mut foe_wrq_filename = None;

    let protocol = match mbx_type {
        0x00 | 0x81..=0x85 => dissect_mbx_err(body, ws, prefix),
        0x01 => {
            let (mut ams_v, sdo_ev) = dissect_ams_pdu(body, ws, Some(prefix));
            if let Some(obj) = ams_v.as_object_mut() {
                obj.insert("kind".into(), json!("AoE"));
            }
            sdo_event = sdo_ev;
            ams_v
        }
        0x02 => {
            let (eoe_v, eoe_frag) = dissect_eoe(body, ws, prefix);
            eoe_fragment = eoe_frag;
            eoe_v
        }
        0x03 => {
            let (coe_v, sdo_ev, sdo_info_frag) = dissect_coe(body, ws, prefix);
            sdo_event = sdo_ev;
            sdo_info_fragment = sdo_info_frag;
            coe_v
        }
        0x04 => {
            let (foe_v, wrq_fn) = dissect_foe(body, ws, prefix, force_efw);
            foe_wrq_filename = wrq_fn;
            foe_v
        }
        0x05 => dissect_soe(body, ws, prefix),
        0x0F => dissect_voe(body, ws, prefix),
        _ => json!({
            "kind": "Unknown",
            "raw_hex": format_hex(body),
        }),
    };

    Some(DissectedMailbox {
        length,
        address,
        channel,
        priority,
        mbx_type,
        mbx_type_name: mbx_type_str,
        counter,
        malformed,
        protocol,
        sdo_event,
        sdo_info_fragment,
        eoe_fragment,
        foe_wrq_filename,
        raw_bytes: data.to_vec(),
    })
}

fn dissect_voe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 6 {
        return json!({
            "kind": "VoE",
            "truncated": true,
            "raw_hex": format_hex(body),
        });
    }
    let vendor_id = u32::from_le_bytes([body[0], body[1], body[2], body[3]]);
    let vendor_type = u16::from_le_bytes([body[4], body[5]]);
    ws.insert(
        format!("{prefix}.voe.vendor_id"),
        json!(format!("0x{vendor_id:08x}")),
    );
    ws.insert(
        format!("{prefix}.voe.vendor_type"),
        json!(format!("0x{vendor_type:04x}")),
    );
    json!({
        "kind": "VoE",
        "vendor_id": format!("0x{vendor_id:08x}"),
        "vendor_type": format!("0x{vendor_type:04x}"),
        "data_hex": format_hex(&body[6..]),
    })
}

fn dissect_mbx_err(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 4 {
        ws.insert(format!("{prefix}.invalid"), json!(true));
        return json!({ "kind": "ERR", "truncated": true, "raw_hex": format_hex(body) });
    }
    let err_type = u16::from_le_bytes([body[0], body[1]]);
    let detail = u16::from_le_bytes([body[2], body[3]]);
    let detail_str = mbx_error_detail_description(detail);
    ws.insert(format!("{prefix}.err.type"), json!(err_type));
    ws.insert(format!("{prefix}.err.detail"), json!(detail));
    json!({
        "kind": "ERR",
        "type": err_type,
        "detail": detail,
        "detail_description": detail_str,
    })
}

fn format_eoe_le_ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0])
}

fn format_ipv4_be(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Dissects an inner Ethernet II frame carried inside EoE (single-fragment or reassembled multi-fragment):
/// - L2 Ethernet II + up to 2 IEEE 802.1Q / 802.1ad VLAN tags (`{prefix}.eoe.eth.*`, `{prefix}.eoe.vlan.*`)
/// - ARP `0x0806` (`{prefix}.eoe.arp.*`)
/// - IPv4 `0x0800` (`{prefix}.eoe.ip.*`) & IPv6 `0x86DD` (`{prefix}.eoe.ipv6.*`)
/// - ICMP (`1`) / ICMPv6 (`58`), TCP (`6`), UDP (`17`) (`{prefix}.eoe.icmp.*`, `.udp.*`, `.tcp.*`)
///
/// Returns `(inner_ethernet_json, inner_packet_json)`.
pub fn dissect_eoe_inner_frame(
    eth_frame: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
    dissect_l3_l4: bool,
) -> Option<(Value, Option<Value>)> {
    if eth_frame.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&eth_frame[0..6]);
    src.copy_from_slice(&eth_frame[6..12]);
    let dst_s = format_mac(&dst);
    let src_s = format_mac(&src);

    let mut pos = 12usize;
    let mut etype = u16::from_be_bytes([eth_frame[pos], eth_frame[pos + 1]]);
    pos += 2;
    let mut outer_vlan_id = None;
    let mut vlan_id = None;
    let mut vlan_prio = None;
    for tag_i in 0..2 {
        if matches!(etype, 0x8100 | 0x88A8 | 0x9100) && pos + 4 <= eth_frame.len() {
            let tci = u16::from_be_bytes([eth_frame[pos], eth_frame[pos + 1]]);
            let vid = tci & 0x0FFF;
            let prio = ((tci >> 13) & 0x07) as u8;
            if tag_i == 0 {
                vlan_id = Some(vid);
                vlan_prio = Some(prio);
            } else {
                outer_vlan_id = vlan_id;
                vlan_id = Some(vid);
                vlan_prio = Some(prio);
            }
            etype = u16::from_be_bytes([eth_frame[pos + 2], eth_frame[pos + 3]]);
            pos += 4;
        } else {
            break;
        }
    }

    let etype_s = format!("0x{etype:04x}");
    ws.insert(format!("{prefix}.eoe.eth.dst"), json!(dst_s.clone()));
    ws.insert(format!("{prefix}.eoe.eth.src"), json!(src_s.clone()));
    ws.insert(format!("{prefix}.eoe.eth.type"), json!(etype_s.clone()));
    if let Some(ovid) = outer_vlan_id {
        ws.insert(format!("{prefix}.eoe.vlan.outer_id"), json!(ovid));
    }
    if let Some(vid) = vlan_id {
        ws.insert(format!("{prefix}.eoe.vlan.id"), json!(vid));
    }
    if let Some(vp) = vlan_prio {
        ws.insert(format!("{prefix}.eoe.vlan.prio"), json!(vp));
    }

    let mut eth_obj = Map::new();
    eth_obj.insert("dst_mac".into(), json!(dst_s));
    eth_obj.insert("src_mac".into(), json!(src_s));
    eth_obj.insert("vlan_id".into(), json!(vlan_id));
    if let Some(ovid) = outer_vlan_id {
        eth_obj.insert("outer_vlan_id".into(), json!(ovid));
    }
    eth_obj.insert("ethertype".into(), json!(etype_s));
    let inner_eth = Value::Object(eth_obj);

    if !dissect_l3_l4 || pos >= eth_frame.len() {
        return Some((inner_eth, None));
    }

    let l3 = &eth_frame[pos..];
    let inner_pkt = match etype {
        // ARP (0x0806)
        0x0806 if l3.len() >= 8 => {
            let hw_type = u16::from_be_bytes([l3[0], l3[1]]);
            let proto_type = u16::from_be_bytes([l3[2], l3[3]]);
            let hw_size = l3[4];
            let proto_size = l3[5];
            let opcode = u16::from_be_bytes([l3[6], l3[7]]);
            let proto_s = format!("0x{proto_type:04x}");
            let op_name = match opcode {
                1 => "Request",
                2 => "Reply",
                _ => "Other",
            };
            ws.insert(format!("{prefix}.eoe.arp.hw.type"), json!(hw_type));
            ws.insert(
                format!("{prefix}.eoe.arp.proto.type"),
                json!(proto_s.clone()),
            );
            ws.insert(format!("{prefix}.eoe.arp.opcode"), json!(opcode));

            let mut pkt = Map::new();
            pkt.insert("network_protocol".into(), json!("ARP"));
            pkt.insert("hw_type".into(), json!(hw_type));
            pkt.insert("proto_type".into(), json!(proto_s));
            pkt.insert("opcode".into(), json!(opcode));
            pkt.insert("opcode_name".into(), json!(op_name));

            if hw_size == 6 && proto_size == 4 && l3.len() >= 28 {
                let mut sha_b = [0u8; 6];
                let mut tha_b = [0u8; 6];
                sha_b.copy_from_slice(&l3[8..14]);
                tha_b.copy_from_slice(&l3[18..24]);
                let sha = format_mac(&sha_b);
                let spa = format_ipv4_be(&l3[14..18]);
                let tha = format_mac(&tha_b);
                let tpa = format_ipv4_be(&l3[24..28]);

                ws.insert(format!("{prefix}.eoe.arp.src.hw_mac"), json!(sha.clone()));
                ws.insert(format!("{prefix}.eoe.arp.sha"), json!(sha.clone()));
                ws.insert(
                    format!("{prefix}.eoe.arp.src.proto_ipv4"),
                    json!(spa.clone()),
                );
                ws.insert(format!("{prefix}.eoe.arp.spa"), json!(spa.clone()));
                ws.insert(format!("{prefix}.eoe.arp.dst.hw_mac"), json!(tha.clone()));
                ws.insert(format!("{prefix}.eoe.arp.tha"), json!(tha.clone()));
                ws.insert(
                    format!("{prefix}.eoe.arp.dst.proto_ipv4"),
                    json!(tpa.clone()),
                );
                ws.insert(format!("{prefix}.eoe.arp.tpa"), json!(tpa.clone()));

                pkt.insert("sender_mac".into(), json!(sha));
                pkt.insert("sender_ip".into(), json!(spa));
                pkt.insert("target_mac".into(), json!(tha));
                pkt.insert("target_ip".into(), json!(tpa));
            }
            Some(Value::Object(pkt))
        }
        // IPv4 (0x0800)
        0x0800 if l3.len() >= 20 && (l3[0] >> 4) == 4 => {
            let ihl = ((l3[0] & 0x0F) as usize) * 4;
            if ihl >= 20 && l3.len() >= ihl {
                let total_len = u16::from_be_bytes([l3[2], l3[3]]) as usize;
                let ip_id = u16::from_be_bytes([l3[4], l3[5]]);
                let flags_frag = u16::from_be_bytes([l3[6], l3[7]]);
                let frag_offset = ((flags_frag & 0x1FFF) as usize) * 8;
                let ttl = l3[8];
                let proto = l3[9];
                let src_ip = format_ipv4_be(&l3[12..16]);
                let dst_ip = format_ipv4_be(&l3[16..20]);
                let id_s = format!("0x{ip_id:04x}");
                let ip_end = if total_len >= ihl {
                    total_len.min(l3.len())
                } else {
                    l3.len()
                };

                ws.insert(format!("{prefix}.eoe.ip.version"), json!(4));
                ws.insert(format!("{prefix}.eoe.ip.hdr_len"), json!(ihl));
                ws.insert(format!("{prefix}.eoe.ip.len"), json!(total_len));
                ws.insert(format!("{prefix}.eoe.ip.id"), json!(id_s.clone()));
                ws.insert(format!("{prefix}.eoe.ip.ttl"), json!(ttl));
                ws.insert(format!("{prefix}.eoe.ip.proto"), json!(proto));
                ws.insert(format!("{prefix}.eoe.ip.src"), json!(src_ip.clone()));
                ws.insert(format!("{prefix}.eoe.ip.dst"), json!(dst_ip.clone()));

                let mut pkt = Map::new();
                pkt.insert("network_protocol".into(), json!("IPv4"));
                pkt.insert("src_ip".into(), json!(src_ip));
                pkt.insert("dst_ip".into(), json!(dst_ip));
                pkt.insert("ip_proto".into(), json!(proto));
                pkt.insert("ttl".into(), json!(ttl));
                pkt.insert("total_length".into(), json!(total_len));
                pkt.insert("identification".into(), json!(id_s));
                if frag_offset > 0 {
                    pkt.insert("fragment_offset".into(), json!(frag_offset));
                } else {
                    dissect_eoe_l4(proto, &l3[ihl..ip_end], ws, prefix, false, &mut pkt);
                }
                Some(Value::Object(pkt))
            } else {
                None
            }
        }
        // IPv6 (0x86DD)
        0x86DD if l3.len() >= 40 && (l3[0] >> 4) == 6 => {
            let plen = u16::from_be_bytes([l3[4], l3[5]]) as usize;
            let mut nxt = l3[6];
            let hlim = l3[7];
            let mut src_b = [0u8; 16];
            let mut dst_b = [0u8; 16];
            src_b.copy_from_slice(&l3[8..24]);
            dst_b.copy_from_slice(&l3[24..40]);
            let src_ip6 = std::net::Ipv6Addr::from(src_b).to_string();
            let dst_ip6 = std::net::Ipv6Addr::from(dst_b).to_string();
            let ip6_end = (40usize.saturating_add(plen)).min(l3.len());

            ws.insert(format!("{prefix}.eoe.ipv6.plen"), json!(plen));
            ws.insert(format!("{prefix}.eoe.ipv6.nxt"), json!(nxt));
            ws.insert(format!("{prefix}.eoe.ipv6.hlim"), json!(hlim));
            ws.insert(format!("{prefix}.eoe.ipv6.src"), json!(src_ip6.clone()));
            ws.insert(format!("{prefix}.eoe.ipv6.dst"), json!(dst_ip6.clone()));

            let mut l4_off = 40usize;
            let mut non_zero_frag = false;
            for _ in 0..4 {
                match nxt {
                    // Hop-by-Hop (0), Routing (43), Destination Options (60)
                    0 | 43 | 60 if l4_off + 2 <= ip6_end => {
                        let ext_nxt = l3[l4_off];
                        let ext_len = ((l3[l4_off + 1] as usize) + 1) * 8;
                        if l4_off + ext_len > ip6_end {
                            break;
                        }
                        nxt = ext_nxt;
                        l4_off += ext_len;
                    }
                    // Fragment Header (44)
                    44 if l4_off + 8 <= ip6_end => {
                        let ext_nxt = l3[l4_off];
                        let frag_word = u16::from_be_bytes([l3[l4_off + 2], l3[l4_off + 3]]);
                        if (frag_word & 0xFFF8) != 0 {
                            non_zero_frag = true;
                        }
                        nxt = ext_nxt;
                        l4_off += 8;
                        break;
                    }
                    _ => break,
                }
            }

            let mut pkt = Map::new();
            pkt.insert("network_protocol".into(), json!("IPv6"));
            pkt.insert("src_ip".into(), json!(src_ip6));
            pkt.insert("dst_ip".into(), json!(dst_ip6));
            pkt.insert("next_header".into(), json!(nxt));
            pkt.insert("hop_limit".into(), json!(hlim));
            pkt.insert("payload_length".into(), json!(plen));
            if !non_zero_frag && l4_off <= ip6_end {
                dissect_eoe_l4(nxt, &l3[l4_off..ip6_end], ws, prefix, true, &mut pkt);
            }
            Some(Value::Object(pkt))
        }
        _ => None,
    };

    Some((inner_eth, inner_pkt))
}

fn dissect_eoe_l4(
    proto: u8,
    l4: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
    is_ipv6: bool,
    pkt: &mut Map<String, Value>,
) {
    match proto {
        // ICMPv4 (1) or ICMPv6 (58)
        1 | 58 if l4.len() >= 4 => {
            let icmp_type = l4[0];
            let icmp_code = l4[1];
            let checksum = u16::from_be_bytes([l4[2], l4[3]]);
            let csum_s = format!("0x{checksum:04x}");
            ws.insert(format!("{prefix}.eoe.icmp.type"), json!(icmp_type));
            ws.insert(format!("{prefix}.eoe.icmp.code"), json!(icmp_code));
            ws.insert(format!("{prefix}.eoe.icmp.checksum"), json!(csum_s.clone()));
            if is_ipv6 {
                ws.insert(format!("{prefix}.eoe.icmpv6.type"), json!(icmp_type));
                ws.insert(format!("{prefix}.eoe.icmpv6.code"), json!(icmp_code));
                ws.insert(
                    format!("{prefix}.eoe.icmpv6.checksum"),
                    json!(csum_s.clone()),
                );
            }
            pkt.insert(
                "transport_protocol".into(),
                json!(if is_ipv6 { "ICMPv6" } else { "ICMP" }),
            );
            pkt.insert("icmp_type".into(), json!(icmp_type));
            pkt.insert("icmp_code".into(), json!(icmp_code));
            pkt.insert("checksum".into(), json!(csum_s));

            let is_echo = (!is_ipv6 && matches!(icmp_type, 0 | 8))
                || (is_ipv6 && matches!(icmp_type, 128 | 129));
            if is_echo && l4.len() >= 8 {
                let ident = u16::from_be_bytes([l4[4], l4[5]]);
                let seq = u16::from_be_bytes([l4[6], l4[7]]);
                let dhex = format_hex(&l4[8..]);
                ws.insert(format!("{prefix}.eoe.icmp.ident"), json!(ident));
                ws.insert(format!("{prefix}.eoe.icmp.seq"), json!(seq));
                ws.insert(format!("{prefix}.eoe.icmp.data"), json!(dhex.clone()));
                pkt.insert("icmp_ident".into(), json!(ident));
                pkt.insert("icmp_seq".into(), json!(seq));
                pkt.insert("payload_hex".into(), json!(dhex));
            }
        }
        // TCP (6)
        6 if l4.len() >= 20 => {
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let seq = u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]]);
            let ack = u32::from_be_bytes([l4[8], l4[9], l4[10], l4[11]]);
            let data_off = (((l4[12] >> 4) & 0x0F) as usize) * 4;
            let flags = u16::from_be_bytes([l4[12] & 0x0F, l4[13]]) & 0x01FF;
            let window = u16::from_be_bytes([l4[14], l4[15]]);
            let flags_s = format!("0x{flags:03x}");
            let payload_hex = if data_off >= 20 && data_off <= l4.len() {
                format_hex(&l4[data_off..])
            } else {
                String::new()
            };

            ws.insert(format!("{prefix}.eoe.tcp.srcport"), json!(src_port));
            ws.insert(format!("{prefix}.eoe.tcp.dstport"), json!(dst_port));
            ws.insert(format!("{prefix}.eoe.tcp.seq"), json!(seq));
            ws.insert(format!("{prefix}.eoe.tcp.ack"), json!(ack));
            ws.insert(format!("{prefix}.eoe.tcp.hdr_len"), json!(data_off));
            ws.insert(format!("{prefix}.eoe.tcp.flags"), json!(flags_s.clone()));
            ws.insert(format!("{prefix}.eoe.tcp.window"), json!(window));
            ws.insert(
                format!("{prefix}.eoe.tcp.payload"),
                json!(payload_hex.clone()),
            );

            pkt.insert("transport_protocol".into(), json!("TCP"));
            pkt.insert("src_port".into(), json!(src_port));
            pkt.insert("dst_port".into(), json!(dst_port));
            pkt.insert("seq".into(), json!(seq));
            pkt.insert("ack".into(), json!(ack));
            pkt.insert("tcp_flags".into(), json!(flags_s));
            pkt.insert("window".into(), json!(window));
            pkt.insert("payload_hex".into(), json!(payload_hex));
        }
        // UDP (17)
        17 if l4.len() >= 8 => {
            let src_port = u16::from_be_bytes([l4[0], l4[1]]);
            let dst_port = u16::from_be_bytes([l4[2], l4[3]]);
            let udp_len = u16::from_be_bytes([l4[4], l4[5]]) as usize;
            let checksum = u16::from_be_bytes([l4[6], l4[7]]);
            let u_end = if udp_len >= 8 {
                udp_len.min(l4.len())
            } else {
                l4.len()
            };
            let payload_hex = format_hex(&l4[8..u_end]);
            let csum_s = format!("0x{checksum:04x}");

            ws.insert(format!("{prefix}.eoe.udp.srcport"), json!(src_port));
            ws.insert(format!("{prefix}.eoe.udp.dstport"), json!(dst_port));
            ws.insert(format!("{prefix}.eoe.udp.length"), json!(udp_len));
            ws.insert(format!("{prefix}.eoe.udp.checksum"), json!(csum_s.clone()));
            ws.insert(
                format!("{prefix}.eoe.udp.payload"),
                json!(payload_hex.clone()),
            );

            pkt.insert("transport_protocol".into(), json!("UDP"));
            pkt.insert("src_port".into(), json!(src_port));
            pkt.insert("dst_port".into(), json!(dst_port));
            pkt.insert("udp_length".into(), json!(udp_len));
            pkt.insert("checksum".into(), json!(csum_s));
            pkt.insert("payload_hex".into(), json!(payload_hex));
        }
        _ => {}
    }
}

fn dissect_eoe(
    body: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> (Value, Option<EoeFragmentInfo>) {
    if body.len() < 4 {
        ws.insert(format!("{prefix}.eoe.invalid"), json!(true));
        return (
            json!({ "kind": "EoE", "truncated": true, "raw_hex": format_hex(body) }),
            None,
        );
    }
    let info1 = u16::from_le_bytes([body[0], body[1]]);
    let info2 = u16::from_le_bytes([body[2], body[3]]);
    let frame_type = (info1 & 0x0F) as u8;
    let port = ((info1 >> 4) & 0x0F) as u8;
    let last_fragment = (info1 & 0x0100) != 0;
    let time_appended = (info1 & 0x0200) != 0;
    let time_request = (info1 & 0x0400) != 0;
    let frag_no = (info2 & 0x003F) as u8;
    let offset_or_size = ((info2 >> 6) & 0x003F) as u8;
    let frame_no = ((info2 >> 12) & 0x000F) as u8;
    let ftype_name = match frame_type {
        0x00 => "Fragment Data",
        0x01 => "Timestamp Response",
        0x02 => "Initiate EoE Request",
        0x03 => "Initiate EoE Response",
        0x04 => "Set Address Filter Request",
        0x05 => "Set Address Filter Response",
        0x06 => "Get IP Parameter Request",
        0x07 => "Get IP Parameter Response",
        0x08 => "Get Address Filter Request",
        0x09 => "Get Address Filter Response",
        _ => "Other EoE",
    };

    // Official Wireshark 4.6 EoE fields + legacy CLI aliases
    ws.insert(format!("{prefix}.eoe"), json!(format_hex(body)));
    ws.insert(
        format!("{prefix}.eoe.fraghead"),
        json!(format_hex(&body[0..4])),
    );
    ws.insert(format!("{prefix}.eoe.type"), json!(frame_type));
    ws.insert(format!("{prefix}.eoe.port"), json!(port));
    ws.insert(format!("{prefix}.eoe.frag_no"), json!(frag_no));
    ws.insert(format!("{prefix}.eoe.frame_no"), json!(frame_no));
    if frame_type == 0x00 {
        // Wireshark 4.6 only adds the fragment header fields for `EOE_TYPE_FRAME_FRAG`; the
        // offset/buffer-size field is shown in bytes (`32 * OffsetBuffer`).
        ws.insert(format!("{prefix}.eoe.fragno"), json!(frag_no));
        ws.insert(
            format!("{prefix}.eoe.offset"),
            json!(32 * offset_or_size as u32),
        );
        ws.insert(format!("{prefix}.eoe.frame"), json!(frame_no));
        ws.insert(format!("{prefix}.eoe.last"), json!(u8::from(last_fragment)));
        if time_request {
            ws.insert(format!("{prefix}.eoe.timestampreq"), json!(1u8));
        }
        if time_appended {
            ws.insert(format!("{prefix}.eoe.timestampapp"), json!(1u8));
        }
    }

    let payload = &body[4..];
    let mut out = Map::new();
    out.insert("kind".into(), json!("EoE"));
    out.insert("frame_type".into(), json!(frame_type));
    out.insert("frame_type_name".into(), json!(ftype_name));
    out.insert("port".into(), json!(port));
    out.insert("last_fragment".into(), json!(last_fragment));
    out.insert("time_appended".into(), json!(time_appended));
    out.insert("time_request".into(), json!(time_request));
    out.insert("fragment_no".into(), json!(frag_no));
    out.insert("offset_or_buffer_size".into(), json!(offset_or_size));
    out.insert("frame_no".into(), json!(frame_no));

    let mut eoe_frag_info = None;

    match frame_type {
        0x00 => {
            let (frag_bytes, ts_opt) = if time_appended && payload.len() >= 4 {
                let split = payload.len() - 4;
                let ts = u32::from_le_bytes([
                    payload[split],
                    payload[split + 1],
                    payload[split + 2],
                    payload[split + 3],
                ]);
                ws.insert(format!("{prefix}.eoe.timestamp"), json!(ts));
                (&payload[..split], Some(ts))
            } else {
                (payload, None)
            };
            ws.insert(format!("{prefix}.eoe.fragment"), json!(format_hex(payload)));
            if let Some(ts) = ts_opt {
                out.insert("timestamp_ns".into(), json!(ts));
            }
            if frag_no == 0 {
                if let Some((inner_eth, inner_pkt)) =
                    dissect_eoe_inner_frame(frag_bytes, ws, prefix, last_fragment)
                {
                    out.insert("inner_ethernet".into(), inner_eth);
                    if let Some(pkt) = inner_pkt {
                        out.insert("inner_packet".into(), pkt);
                    }
                }
            }
            eoe_frag_info = Some(EoeFragmentInfo {
                port,
                last_fragment,
                frame_no,
                frag_no,
                offset_or_size,
                data: frag_bytes.to_vec(),
            });
        }
        0x01 if payload.len() >= 4 => {
            let ts = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            ws.insert(format!("{prefix}.eoe.timestamp"), json!(ts));
            out.insert("timestamp_ns".into(), json!(ts));
        }
        // Set IP Parameter Request (0x02) / Get IP Parameter Response (0x07)
        // Fixed `ETHERCAT_EOE_INIT` layout (SSC `ecateoe.h`, Wireshark `ETHERCAT_EOE_INIT_LEN` = 58):
        // Flags(4) MAC(6) IP(4) Subnet(4) Gateway(4) DNS(4) DNSName(32); flags only mark validity.
        0x02 | 0x07 if payload.len() >= 4 => {
            const EOE_INIT_LEN: usize = 58;
            let flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            ws.insert(
                format!("{prefix}.eoe.init"),
                json!(format_hex(&payload[..payload.len().min(EOE_INIT_LEN)])),
            );
            let mut ip_params = Map::new();
            ip_params.insert("flags".into(), json!(format!("0x{flags:08x}")));
            let mac_at = |off: usize| -> Option<String> {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(payload.get(off..off + 6)?);
                Some(format_mac(&mac))
            };
            let ip_at = |off: usize| payload.get(off..off + 4).map(format_eoe_le_ipv4);
            let name_at = |off: usize| -> Option<String> {
                let raw = payload.get(off..)?;
                let raw = &raw[..raw.len().min(32)];
                (!raw.is_empty()).then(|| {
                    String::from_utf8_lossy(raw)
                        .trim_end_matches('\0')
                        .to_string()
                })
            };
            let fields = [
                (0x01u32, "macaddr", "mac", "mac", mac_at(4)),
                (0x02, "ipaddr", "ip", "ip", ip_at(10)),
                (0x04, "subnetmask", "subnet", "subnet_mask", ip_at(14)),
                (
                    0x08,
                    "defaultgateway",
                    "gateway",
                    "default_gateway",
                    ip_at(18),
                ),
                (0x10, "dnsserver", "dns_ip", "dns_server", ip_at(22)),
                (0x20, "dnsname", "dns_name", "dns_name", name_at(26)),
            ];
            if payload.len() < EOE_INIT_LEN {
                ws.insert(format!("{prefix}.eoe.init.invalid_length"), json!(true));
            } else {
                let flag_fields = [
                    ("contains_macaddr", 0x01u32),
                    ("contains_ipaddr", 0x02),
                    ("contains_subnetmask", 0x04),
                    ("contains_defaultgateway", 0x08),
                    ("contains_dnsserver", 0x10),
                    ("contains_dnsname", 0x20),
                    ("append_timestamp", 0x0001_0000),
                ];
                for (name, mask) in flag_fields {
                    ws.insert(
                        format!("{prefix}.eoe.init.{name}"),
                        json!((flags & mask) != 0),
                    );
                }
                for (_, official, _, _, val) in &fields {
                    if let Some(v) = val {
                        ws.insert(format!("{prefix}.eoe.init.{official}"), json!(v));
                    }
                }
            }
            // CLI aliases / structured output for parameters flagged as valid.
            for (mask, _, alias, key, val) in fields {
                if let (true, Some(v)) = ((flags & mask) != 0, val) {
                    ws.insert(format!("{prefix}.eoe.{alias}"), json!(v.clone()));
                    ip_params.insert(key.into(), json!(v));
                }
            }
            out.insert("ip_parameters".into(), Value::Object(ip_params));
        }
        // Set Address Filter Request (0x04) / Get Address Filter Response (0x09)
        0x04 | 0x09 => {
            if frame_type == 0x09 && payload.len() < 2 {
                ws.insert(format!("{prefix}.eoe.result"), json!(info2));
                out.insert("result_code".into(), json!(format!("0x{info2:04x}")));
            } else if payload.len() >= 2 {
                let opts = u16::from_le_bytes([payload[0], payload[1]]);
                // Support both ETG.1000.6 Table 45 (bits 0..3 filter_cnt, bits 4..6 mask_cnt, bit 8 nobcast)
                // and Wireshark MSB bitmask layout (0xF000 / 0x0C00 / 0x0100)
                let (f_cnt, m_cnt, no_bcast) = if (opts & 0x000F) != 0 || (opts & 0xF000) == 0 {
                    (
                        (opts & 0x000F) as usize,
                        ((opts >> 4) & 0x0007) as usize,
                        (opts & 0x0100) != 0 || (opts & 0x0080) != 0,
                    )
                } else {
                    (
                        ((opts >> 12) & 0x000F) as usize,
                        ((opts >> 10) & 0x0003) as usize,
                        (opts & 0x0100) != 0,
                    )
                };
                ws.insert(
                    format!("{prefix}.eoe.macfilter"),
                    json!(format_hex(payload)),
                );
                // Official Wireshark 4.6 fields: FT_UINT16 masks 0xF000 / 0x0C00, boolean 0x0100.
                ws.insert(
                    format!("{prefix}.eoe.macfilter.macfiltercount"),
                    json!((opts & 0xF000) >> 12),
                );
                ws.insert(
                    format!("{prefix}.eoe.macfilter.maskcount"),
                    json!((opts & 0x0C00) >> 10),
                );
                ws.insert(
                    format!("{prefix}.eoe.macfilter.nobroadcasts"),
                    json!((opts & 0x0100) != 0),
                );

                let mut off = 2usize;
                let mut filters = Vec::new();
                // Wireshark either stores fixed 16*6 filter slots or `f_cnt * 6` packed slots
                let fixed_16 = payload.len() >= 2 + 16 * 6 + 4 * 6;
                let slot_limit = if fixed_16 { 16 } else { f_cnt.min(16) };
                if off + slot_limit * 6 <= payload.len() {
                    ws.insert(
                        format!("{prefix}.eoe.macfilter.filter"),
                        json!(format_hex(&payload[off..off + slot_limit * 6])),
                    );
                }
                for idx in 0..slot_limit {
                    if off + 6 > payload.len() {
                        break;
                    }
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&payload[off..off + 6]);
                    let ms = format_mac(&mac);
                    ws.insert(
                        format!("{prefix}.eoe.macfilter.filter{idx}"),
                        json!(ms.clone()),
                    );
                    if idx < f_cnt {
                        filters.push(ms);
                    }
                    off += 6;
                }
                let mask_limit = if fixed_16 { 4 } else { m_cnt.min(4) };
                let mut masks = Vec::new();
                if fixed_16 {
                    // Wireshark 4.6 adds the filter-mask block with a length of 4*4 bytes.
                    ws.insert(
                        format!("{prefix}.eoe.macfilter.filtermask"),
                        json!(format_hex(&payload[off..off + 16])),
                    );
                } else if off + mask_limit * 6 <= payload.len() && mask_limit > 0 {
                    ws.insert(
                        format!("{prefix}.eoe.macfilter.filtermask"),
                        json!(format_hex(&payload[off..off + mask_limit * 6])),
                    );
                }
                for idx in 0..mask_limit {
                    if off + 6 > payload.len() {
                        break;
                    }
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&payload[off..off + 6]);
                    let ms = format_mac(&mac);
                    ws.insert(
                        format!("{prefix}.eoe.macfilter.filtermask{idx}"),
                        json!(ms.clone()),
                    );
                    if idx < m_cnt {
                        masks.push(ms);
                    }
                    off += 6;
                }
                out.insert(
                    "mac_filter".into(),
                    json!({
                        "filter_count": f_cnt,
                        "mask_count": m_cnt,
                        "no_broadcasts": no_bcast,
                        "filters": filters,
                        "masks": masks,
                    }),
                );
            }
        }
        0x03 | 0x05 => {
            ws.insert(format!("{prefix}.eoe.result"), json!(info2));
            out.insert("result_code".into(), json!(format!("0x{info2:04x}")));
        }
        _ => {}
    }

    out.insert("data_hex".into(), json!(format_hex(payload)));
    (Value::Object(out), eoe_frag_info)
}

fn dissect_coe(
    body: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> (Value, Option<SdoEventKind>, Option<SdoInfoFragmentInfo>) {
    if body.len() < 2 {
        ws.insert(format!("{prefix}.coe"), json!(format_hex(body)));
        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
        return (
            json!({ "kind": "CoE", "truncated": true, "raw_hex": format_hex(body) }),
            None,
            None,
        );
    }
    let coe_hdr = u16::from_le_bytes([body[0], body[1]]);
    let number = coe_hdr & 0x01FF;
    let service = ((coe_hdr >> 12) & 0x0F) as u8;
    let service_str = coe_service_name(service);
    ws.insert(format!("{prefix}.coe"), json!(format_hex(body)));
    ws.insert(format!("{prefix}.coe.number"), json!(number));
    ws.insert(format!("{prefix}.coe.type"), json!(service));
    ws.insert(format!("{prefix}.coe.service"), json!(service));
    ws.insert(format!("{prefix}.coe.service_name"), json!(service_str));

    let payload = &body[2..];
    match service {
        // Emergency
        0x01 => {
            if payload.len() < 8 {
                ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                return (
                    json!({ "kind": "CoE", "service": service_str, "truncated": true }),
                    None,
                    None,
                );
            }
            let err_code = u16::from_le_bytes([payload[0], payload[1]]);
            let err_reg = payload[2];
            let mfg_data = format_hex(&payload[3..8]);
            ws.insert(
                format!("{prefix}.coe.emcy.error_code"),
                json!(format!("0x{err_code:04x}")),
            );
            ws.insert(
                format!("{prefix}.coe.emcy.error_reg"),
                json!(format!("0x{err_reg:02x}")),
            );
            (
                json!({
                    "kind": "CoE",
                    "service": service_str,
                    "number": number,
                    "error_code": format!("0x{err_code:04x}"),
                    "error_register": format!("0x{err_reg:02x}"),
                    "manufacturer_data_hex": mfg_data,
                }),
                None,
                None,
            )
        }
        // SDO Request (0x02) & SDO Response (0x03)
        0x02 | 0x03 => {
            if payload.len() < 8 {
                // Wireshark 4.6: "Sdo Req/Res - invalid length" (CoE length < 2 + 8).
                ws.insert(format!("{prefix}.coe.invalid"), json!(true));
            }
            let (v, ev) = dissect_coe_sdo(service, number, payload, ws, prefix);
            (v, ev, None)
        }
        // SDO Information (0x08)
        0x08 => {
            let frag = if payload.len() >= 4 {
                let opcode = payload[0] & 0x7F;
                if matches!(opcode, 0x02 | 0x04 | 0x06) {
                    Some(SdoInfoFragmentInfo {
                        number,
                        opcode,
                        incomplete: (payload[0] & 0x80) != 0,
                        fragments_left: u16::from_le_bytes([payload[2], payload[3]]),
                        rest: payload[4..].to_vec(),
                    })
                } else {
                    None
                }
            } else {
                None
            };
            (
                dissect_coe_sdo_info(number, payload, ws, prefix),
                None,
                frag,
            )
        }
        // TxPDO (0x04), RxPDO (0x05), TxPDO_RTR (0x06), RxPDO_RTR (0x07)
        _ => (
            json!({
                "kind": "CoE",
                "service": service_str,
                "service_code": service,
                "number": number,
                "pdo_data_hex": format_hex(payload),
            }),
            None,
            None,
        ),
    }
}

fn dissect_coe_sdo(
    service: u8,
    number: u16,
    payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> (Value, Option<SdoEventKind>) {
    if payload.is_empty() {
        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
        return (
            json!({ "kind": "CoE", "service": coe_service_name(service), "truncated": true }),
            None,
        );
    }
    let cmd = payload[0];
    let ccs_scs = (cmd >> 5) & 0x07;
    ws.insert(
        format!("{prefix}.coe.sdo.cmd"),
        json!(format!("0x{cmd:02x}")),
    );
    if service == 0x02 {
        ws.insert(format!("{prefix}.coe.sdoreq"), json!(ccs_scs));
    } else {
        ws.insert(format!("{prefix}.coe.sdores"), json!(ccs_scs));
    }

    // Abort SDO Transfer (ccs_scs == 4)
    if ccs_scs == 4 {
        if payload.len() < 8 {
            ws.insert(format!("{prefix}.coe.invalid"), json!(true));
            return (
                json!({
                    "kind": "CoE",
                    "service": coe_service_name(service),
                    "number": number,
                    "sdo_op": "Abort Transfer",
                    "truncated": true,
                    "raw_hex": format_hex(payload),
                }),
                None,
            );
        }
        let index = u16::from_le_bytes([payload[1], payload[2]]);
        let subindex = payload[3];
        let abort_code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let abort_desc = sdo_abort_description(abort_code);
        let idx_s = format!("0x{index:04x}");
        let abt_s = format!("0x{abort_code:08x}");

        ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
        ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
        if service == 0x02 {
            ws.insert(format!("{prefix}.coe.abortcode"), json!(abt_s.clone()));
        }
        ws.insert(format!("{prefix}.coe.sdo.abort_code"), json!(abt_s.clone()));

        return (
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": "Abort Transfer",
                "index": idx_s,
                "subindex": subindex,
                "abort_code": abt_s,
                "abort_description": abort_desc,
            }),
            Some(SdoEventKind::Abort {
                index,
                subindex,
                abort_code,
            }),
        );
    }

    let is_seg_data_frame = (service == 0x02 && ccs_scs == 0) || (service == 0x03 && ccs_scs == 0);
    let is_dl_seg_res = service == 0x03 && ccs_scs == 1;
    let is_ul_seg_req = service == 0x02 && ccs_scs == 3;

    if is_seg_data_frame {
        let toggle = (cmd & 0x10) != 0;
        let last_seg = (cmd & 0x01) != 0;
        let unused = ((cmd >> 1) & 0x07) as usize;
        let seg_raw = &payload[1..];
        // Per ETG.1000.6, minimum SDO segment frame is 7 data bytes (padded if < 7);
        // in extended mailbox SDO segments (> 7 bytes), `unused` only applies when `seg_raw.len() == 7`.
        let valid_len = if seg_raw.len() == 7 {
            seg_raw.len().saturating_sub(unused)
        } else {
            seg_raw.len()
        };
        let seg_data = &seg_raw[..valid_len];
        let dhex = format_hex(seg_data);

        if service == 0x02 {
            ws.insert(
                format!("{prefix}.coe.sdoccsds"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoccsds.lastseg"), json!(last_seg));
            ws.insert(format!("{prefix}.coe.sdoccsds.size"), json!(unused));
            ws.insert(format!("{prefix}.coe.sdoccsds.toggle"), json!(toggle));
        } else {
            ws.insert(
                format!("{prefix}.coe.sdoscsus"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoscsus_lastseg"), json!(last_seg));
            ws.insert(format!("{prefix}.coe.sdoscsus_bytes"), json!(unused));
            ws.insert(format!("{prefix}.coe.sdoscsus_toggle"), json!(toggle));
        }
        ws.insert(format!("{prefix}.coe.dsoldata"), json!(dhex.clone()));
        ws.insert(format!("{prefix}.coe.sdo.toggle"), json!(toggle));
        ws.insert(format!("{prefix}.coe.sdo.last_segment"), json!(last_seg));
        ws.insert(format!("{prefix}.coe.sdo.data"), json!(dhex.clone()));

        let ev = if service == 0x02 {
            SdoEventKind::DownloadSegmentReq {
                toggle,
                last_segment: last_seg,
                seg_data: seg_data.to_vec(),
            }
        } else {
            SdoEventKind::UploadSegmentRes {
                toggle,
                last_segment: last_seg,
                seg_data: seg_data.to_vec(),
            }
        };

        return (
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": if service == 0x02 { "Download Segment Request" } else { "Upload Segment Response" },
                "toggle": toggle,
                "last_segment": last_seg,
                "data_hex": dhex,
            }),
            Some(ev),
        );
    }

    if is_dl_seg_res || is_ul_seg_req {
        let toggle = (cmd & 0x10) != 0;
        if is_dl_seg_res {
            ws.insert(
                format!("{prefix}.coe.sdoscsds"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoscsds_toggle"), json!(toggle));
        } else {
            ws.insert(
                format!("{prefix}.coe.sdoccsus"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoccsus_toggle"), json!(toggle));
        }
        ws.insert(format!("{prefix}.coe.sdo.toggle"), json!(toggle));
        let ev = if is_dl_seg_res {
            SdoEventKind::DownloadSegmentRes { toggle }
        } else {
            SdoEventKind::UploadSegmentReq { toggle }
        };
        return (
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": if is_dl_seg_res { "Download Segment Response" } else { "Upload Segment Request" },
                "toggle": toggle,
            }),
            Some(ev),
        );
    }

    // CoE SDO Block Download & Block Upload (ETG.1000.6 §5.6.2.6 / §5.6.2.7: ccs/scs == 5 | 6)
    if matches!((service, ccs_scs), (0x02, 5 | 6) | (0x03, 5 | 6)) {
        return dissect_coe_sdo_block_cmd(service, number, cmd, ccs_scs, payload, ws, prefix);
    }

    if payload.len() < 4 {
        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
        return (
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "truncated": true,
            }),
            None,
        );
    }
    let index = u16::from_le_bytes([payload[1], payload[2]]);
    let subindex = payload[3];
    let complete_access = (cmd & 0x10) != 0;
    let expedited = (cmd & 0x02) != 0;
    let size_indicated = (cmd & 0x01) != 0;
    let size0 = (cmd & 0x04) != 0;
    let size1 = (cmd & 0x08) != 0;
    let idx_s = format!("0x{index:04x}");

    ws.insert(format!("{prefix}.coe.sdoidx"), json!(idx_s.clone()));
    ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
    ws.insert(format!("{prefix}.coe.sdosub"), json!(subindex));
    ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
    ws.insert(format!("{prefix}.coe.sdo.ca"), json!(complete_access));
    ws.insert(format!("{prefix}.coe.sdo.expedited"), json!(expedited));

    match (service, ccs_scs) {
        (0x02, 1) => {
            ws.insert(
                format!("{prefix}.coe.sdoccsid"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(
                format!("{prefix}.coe.sdoccsid.sizeind"),
                json!(size_indicated),
            );
            ws.insert(format!("{prefix}.coe.sdoccsid.expedited"), json!(expedited));
            ws.insert(format!("{prefix}.coe.sdoccsid.size0"), json!(size0));
            ws.insert(format!("{prefix}.coe.sdoccsid.size1"), json!(size1));
            ws.insert(
                format!("{prefix}.coe.sdoccsid.complete"),
                json!(complete_access),
            );
        }
        (0x02, 2) => {
            ws.insert(
                format!("{prefix}.coe.sdoccsiu"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(
                format!("{prefix}.coe.sdoccsid.complete"),
                json!(complete_access),
            );
        }
        (0x03, 2) => {
            ws.insert(
                format!("{prefix}.coe.sdoscsiu"),
                json!(format!("0x{cmd:02x}")),
            );
            ws.insert(
                format!("{prefix}.coe.sdoscsiu_sizeind"),
                json!(size_indicated),
            );
            ws.insert(format!("{prefix}.coe.sdoscsiu_expedited"), json!(expedited));
            ws.insert(format!("{prefix}.coe.sdoscsiu_size0"), json!(size0));
            ws.insert(format!("{prefix}.coe.sdoscsiu_size1"), json!(size1));
            ws.insert(
                format!("{prefix}.coe.sdoscsiu_complete"),
                json!(complete_access),
            );
        }
        _ => {}
    }

    let op_name = match (service, ccs_scs) {
        (0x02, 1) => "Initiate Download Request",
        (0x02, 2) => "Initiate Upload Request",
        (0x03, 3) => "Initiate Download Response",
        (0x03, 2) => "Initiate Upload Response",
        _ => "SDO Message",
    };

    let carries_data = (service == 0x02 && ccs_scs == 1) || (service == 0x03 && ccs_scs == 2);
    let body_after_hdr = &payload[4..];
    if carries_data {
        if expedited {
            let unused = if size_indicated {
                ((cmd >> 2) & 0x03) as usize
            } else {
                0
            };
            let dlen = 4usize.saturating_sub(unused).min(body_after_hdr.len());
            let sdo_bytes = &body_after_hdr[..dlen];
            let auto_val =
                decode_typed_value(sdo_bytes, DataTypeSpec::Auto, None).unwrap_or(json!(null));
            let dhex = format_hex(sdo_bytes);

            // Wireshark 4.6: `n == 3` -> 1 byte, `n == 2` -> 2 bytes, otherwise the full 4 bytes
            // (upload responses only use the short widths when size-indicated + expedited).
            let n_field = (cmd >> 2) & 0x03;
            let ws_width = if service == 0x02 || size_indicated {
                match n_field {
                    3 => 1usize,
                    2 => 2,
                    _ => 4,
                }
            } else {
                4
            };
            let ws_bytes = &body_after_hdr[..ws_width.min(body_after_hdr.len())];
            let mut ws_raw = [0u8; 4];
            ws_raw[..ws_bytes.len()].copy_from_slice(ws_bytes);
            let ws_val = u32::from_le_bytes(ws_raw);
            let ws_hex = match ws_width {
                1 => format!("0x{ws_val:02x}"),
                2 => format!("0x{ws_val:04x}"),
                _ => format!("0x{ws_val:08x}"),
            };
            ws.insert(format!("{prefix}.coe.sdodata"), json!(ws_hex));
            ws.insert(format!("{prefix}.coe.sdo.data"), json!(dhex.clone()));
            ws.insert(format!("{prefix}.coe.sdo.value"), auto_val.clone());

            let ev = if service == 0x02 {
                SdoEventKind::InitiateDownload {
                    index,
                    subindex,
                    complete_access,
                    expedited: true,
                    indicated_size: Some(dlen),
                    inline_data: sdo_bytes.to_vec(),
                }
            } else {
                SdoEventKind::InitiateUploadRes {
                    index,
                    subindex,
                    complete_access,
                    expedited: true,
                    indicated_size: Some(dlen),
                    inline_data: sdo_bytes.to_vec(),
                }
            };

            (
                json!({
                    "kind": "CoE",
                    "service": coe_service_name(service),
                    "number": number,
                    "sdo_op": op_name,
                    "index": idx_s,
                    "subindex": subindex,
                    "complete_access": complete_access,
                    "expedited": true,
                    "size": dlen,
                    "data_hex": dhex,
                    "decoded_auto": auto_val,
                }),
                Some(ev),
            )
        } else if body_after_hdr.len() >= 4 {
            let total_size = u32::from_le_bytes([
                body_after_hdr[0],
                body_after_hdr[1],
                body_after_hdr[2],
                body_after_hdr[3],
            ]);
            let inline_data = &body_after_hdr[4..];
            let valid_len = if size_indicated {
                (total_size as usize).min(inline_data.len())
            } else {
                inline_data.len()
            };
            let sdo_bytes = &inline_data[..valid_len];
            let auto_val =
                decode_typed_value(sdo_bytes, DataTypeSpec::Auto, None).unwrap_or(json!(null));
            let dhex = format_hex(sdo_bytes);

            ws.insert(
                format!("{prefix}.coe.sdolength"),
                json!(format!("0x{total_size:08x}")),
            );
            ws.insert(format!("{prefix}.coe.sdo.total_size"), json!(total_size));
            ws.insert(format!("{prefix}.coe.dsoldata"), json!(dhex.clone()));
            ws.insert(format!("{prefix}.coe.sdo.data"), json!(dhex.clone()));
            ws.insert(format!("{prefix}.coe.sdo.value"), auto_val.clone());

            let ind_sz = size_indicated.then_some(total_size as usize);
            let ev = if service == 0x02 {
                SdoEventKind::InitiateDownload {
                    index,
                    subindex,
                    complete_access,
                    expedited: false,
                    indicated_size: ind_sz,
                    inline_data: sdo_bytes.to_vec(),
                }
            } else {
                SdoEventKind::InitiateUploadRes {
                    index,
                    subindex,
                    complete_access,
                    expedited: false,
                    indicated_size: ind_sz,
                    inline_data: sdo_bytes.to_vec(),
                }
            };

            (
                json!({
                    "kind": "CoE",
                    "service": coe_service_name(service),
                    "number": number,
                    "sdo_op": op_name,
                    "index": idx_s,
                    "subindex": subindex,
                    "complete_access": complete_access,
                    "expedited": false,
                    "total_size": total_size,
                    "frame_data_size": sdo_bytes.len(),
                    "data_hex": dhex,
                    "decoded_auto": auto_val,
                }),
                Some(ev),
            )
        } else {
            ws.insert(format!("{prefix}.coe.invalid"), json!(true));
            (
                json!({
                    "kind": "CoE",
                    "service": coe_service_name(service),
                    "number": number,
                    "sdo_op": op_name,
                    "index": idx_s,
                    "subindex": subindex,
                    "truncated": true,
                }),
                None,
            )
        }
    } else {
        let ev = if service == 0x02 && ccs_scs == 2 {
            Some(SdoEventKind::InitiateUploadReq {
                index,
                subindex,
                complete_access,
            })
        } else {
            None
        };
        (
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": op_name,
                "index": idx_s,
                "subindex": subindex,
                "complete_access": complete_access,
            }),
            ev,
        )
    }
}

pub fn dissect_coe_sdo_info(
    number: u16,
    payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> Value {
    if payload.len() < 4 {
        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
        return json!({
            "kind": "CoE",
            "service": "SDO Information",
            "number": number,
            "truncated": true,
        });
    }
    let opcode = payload[0] & 0x7F;
    let incomplete = (payload[0] & 0x80) != 0;
    let fragments_left = u16::from_le_bytes([payload[2], payload[3]]);
    let opcode_name = match opcode {
        0x01 => "Get OD List Request",
        0x02 => "Get OD List Response",
        0x03 => "Get Object Description Request",
        0x04 => "Get Object Description Response",
        0x05 => "Get Entry Description Request",
        0x06 => "Get Entry Description Response",
        0x07 => "SDO Info Error Request",
        _ => "Unknown SDO Info",
    };

    ws.insert(format!("{prefix}.coe.sdoinfoopcode"), json!(payload[0]));
    ws.insert(format!("{prefix}.coe.sdoinfo.opcode"), json!(opcode));
    ws.insert(
        format!("{prefix}.coe.sdoinfofrag"),
        json!(format!("0x{fragments_left:04x}")),
    );
    ws.insert(
        format!("{prefix}.coe.sdoinfo.fragments_left"),
        json!(fragments_left),
    );

    let rest = &payload[4..];
    match opcode {
        0x01 if rest.len() >= 2 => {
            let list_type = u16::from_le_bytes([rest[0], rest[1]]);
            ws.insert(
                format!("{prefix}.coe.sdoinfolisttype"),
                json!(format!("0x{list_type:04x}")),
            );
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "list_type": list_type,
            })
        }
        0x02 if rest.len() >= 2 => {
            let list_type = u16::from_le_bytes([rest[0], rest[1]]);
            let indices: Vec<String> = rest[2..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| format!("0x{:04x}", u16::from_le_bytes(c)))
                .collect();
            ws.insert(
                format!("{prefix}.coe.sdoinfolisttype"),
                json!(format!("0x{list_type:04x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfolist"), json!(indices.clone()));
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "incomplete": incomplete,
                "fragments_left": fragments_left,
                "list_type": list_type,
                "indices": indices,
            })
        }
        0x03 if rest.len() >= 2 => {
            let index = u16::from_le_bytes([rest[0], rest[1]]);
            let idx_s = format!("0x{index:04x}");
            ws.insert(format!("{prefix}.coe.sdoinfoindex"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.index"), json!(idx_s.clone()));
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "index": idx_s,
            })
        }
        0x04 if rest.len() >= 6 => {
            let index = u16::from_le_bytes([rest[0], rest[1]]);
            let dt = u16::from_le_bytes([rest[2], rest[3]]);
            let max_sub = rest[4];
            let obj_code = rest[5];
            let name = String::from_utf8_lossy(&rest[6..])
                .trim_end_matches('\0')
                .to_string();
            let idx_s = format!("0x{index:04x}");
            let dt_s = format!("0x{dt:04x}");

            ws.insert(format!("{prefix}.coe.sdoinfoindex"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.index"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfodatatype"), json!(dt_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfomaxsub"), json!(max_sub));
            ws.insert(format!("{prefix}.coe.sdoinfoobjcode"), json!(obj_code));
            ws.insert(format!("{prefix}.coe.sdoinfoname"), json!(name.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.name"), json!(name.clone()));

            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "incomplete": incomplete,
                "fragments_left": fragments_left,
                "index": idx_s,
                "datatype": dt_s,
                "datatype_name": ect_datatype_name(dt),
                "max_subindex": max_sub,
                "object_code": obj_code,
                "name": name,
            })
        }
        0x05 if rest.len() >= 4 => {
            let index = u16::from_le_bytes([rest[0], rest[1]]);
            let subindex = rest[2];
            let value_info = rest[3];
            let idx_s = format!("0x{index:04x}");

            ws.insert(format!("{prefix}.coe.sdoinfoindex"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.index"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfosubindex"), json!(subindex));
            ws.insert(format!("{prefix}.coe.sdoinfo.subindex"), json!(subindex));
            ws.insert(
                format!("{prefix}.coe.sdoinfovalueinfo"),
                json!(format!("0x{value_info:02x}")),
            );

            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "index": idx_s,
                "subindex": subindex,
                "value_info": value_info,
            })
        }
        0x06 if rest.len() >= 10 => {
            let index = u16::from_le_bytes([rest[0], rest[1]]);
            let subindex = rest[2];
            let value_info = rest[3];
            let dt = u16::from_le_bytes([rest[4], rest[5]]);
            let bit_len = u16::from_le_bytes([rest[6], rest[7]]);
            let obj_access = u16::from_le_bytes([rest[8], rest[9]]);
            let idx_s = format!("0x{index:04x}");
            let dt_s = format!("0x{dt:04x}");
            let acc_s = format!("0x{obj_access:04x}");

            let val_bytes = (bit_len as usize).div_ceil(8);
            let mut off = 10usize;
            if (value_info & 0x08) != 0 && off + 4 <= rest.len() {
                let ut =
                    u32::from_le_bytes([rest[off], rest[off + 1], rest[off + 2], rest[off + 3]]);
                ws.insert(
                    format!("{prefix}.coe.sdoinfounittype"),
                    json!(format!("0x{ut:08x}")),
                );
                off += 4;
            } else if (value_info & 0x08) != 0 && off + 2 <= rest.len() {
                let ut = u16::from_le_bytes([rest[off], rest[off + 1]]);
                ws.insert(
                    format!("{prefix}.coe.sdoinfounittype"),
                    json!(format!("0x{ut:04x}")),
                );
                off += 2;
            }
            if (value_info & 0x10) != 0 && off + val_bytes <= rest.len() {
                ws.insert(
                    format!("{prefix}.coe.sdoinfodefaultvalue"),
                    json!(format_hex(&rest[off..off + val_bytes])),
                );
                off += val_bytes;
            }
            if (value_info & 0x20) != 0 && off + val_bytes <= rest.len() {
                ws.insert(
                    format!("{prefix}.coe.sdoinfominvalue"),
                    json!(format_hex(&rest[off..off + val_bytes])),
                );
                off += val_bytes;
            }
            if (value_info & 0x40) != 0 && off + val_bytes <= rest.len() {
                ws.insert(
                    format!("{prefix}.coe.sdoinfomaxvalue"),
                    json!(format_hex(&rest[off..off + val_bytes])),
                );
            }

            let name_off = sdo_info_entry_name_offset(value_info, bit_len, rest.len());
            let name = String::from_utf8_lossy(&rest[name_off..])
                .trim_end_matches('\0')
                .to_string();

            ws.insert(format!("{prefix}.coe.sdoinfoindex"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.index"), json!(idx_s.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfosubindex"), json!(subindex));
            ws.insert(format!("{prefix}.coe.sdoinfo.subindex"), json!(subindex));
            ws.insert(
                format!("{prefix}.coe.sdoinfovalueinfo"),
                json!(format!("0x{value_info:02x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfodatatype"), json!(dt_s.clone()));
            ws.insert(
                format!("{prefix}.coe.sdoinfobitlen"),
                json!(format!("0x{bit_len:04x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfo.bit_length"), json!(bit_len));
            ws.insert(
                format!("{prefix}.coe.sdoinfoobjaccess"),
                json!(acc_s.clone()),
            );
            ws.insert(format!("{prefix}.coe.sdoinfoname"), json!(name.clone()));
            ws.insert(format!("{prefix}.coe.sdoinfo.name"), json!(name.clone()));

            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "incomplete": incomplete,
                "fragments_left": fragments_left,
                "index": idx_s,
                "subindex": subindex,
                "value_info": value_info,
                "datatype": dt_s,
                "datatype_name": ect_datatype_name(dt),
                "bit_length": bit_len,
                "obj_access": acc_s,
                "name": name,
            })
        }
        0x07 if rest.len() >= 4 => {
            let abort_code = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let abort_desc = sdo_abort_description(abort_code);
            let abt_s = format!("0x{abort_code:08x}");
            ws.insert(
                format!("{prefix}.coe.sdoinfoerrorcode"),
                json!(abt_s.clone()),
            );
            ws.insert(
                format!("{prefix}.coe.sdoinfo.abort_code"),
                json!(abt_s.clone()),
            );
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "abort_code": abt_s,
                "abort_description": abort_desc,
            })
        }
        _ => json!({
            "kind": "CoE",
            "service": "SDO Information",
            "number": number,
            "opcode": opcode,
            "opcode_name": opcode_name,
            "incomplete": incomplete,
            "fragments_left": fragments_left,
            "raw_hex": format_hex(rest),
        }),
    }
}

fn looks_like_efw_block(tail: &[u8]) -> bool {
    if tail.len() < 8 {
        return false;
    }
    let cmd = u16::from_le_bytes([tail[0], tail[1]]);
    let size = u16::from_le_bytes([tail[2], tail[3]]) as usize;
    matches!(cmd, 0x0001..=0x0004 | 0x0008..=0x000A) && 8 + size == tail.len()
}

fn dissect_foe(
    body: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
    force_efw: bool,
) -> (Value, Option<String>) {
    if body.len() < 6 {
        ws.insert(format!("{prefix}.foe.invalid"), json!(true));
        return (
            json!({ "kind": "FoE", "truncated": true, "raw_hex": format_hex(body) }),
            None,
        );
    }
    let opcode = body[0];
    let arg = u32::from_le_bytes([body[2], body[3], body[4], body[5]]);
    let tail = &body[6..];
    let op_name = match opcode {
        1 => "RRQ (Read Request)",
        2 => "WRQ (Write Request)",
        3 => "DATA",
        4 => "ACK",
        5 => "ERR",
        6 => "BUSY",
        _ => "Unknown FoE",
    };

    ws.insert(format!("{prefix}.foe"), json!(format_hex(body)));
    ws.insert(
        format!("{prefix}.foe_opmode"),
        json!(format!("0x{opcode:02x}")),
    );
    ws.insert(format!("{prefix}.foe.opcode"), json!(opcode));

    match opcode {
        1 | 2 => {
            let filename = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(format!("{prefix}.foe_filelength"), json!(arg));
            ws.insert(format!("{prefix}.foe_filename"), json!(filename.clone()));
            ws.insert(format!("{prefix}.foe.filename"), json!(filename.clone()));
            let wrq_fn = (opcode == 2).then(|| filename.clone());
            (
                json!({
                    "kind": "FoE",
                    "opcode": opcode,
                    "opcode_name": op_name,
                    "password": format!("0x{arg:08x}"),
                    "filename": filename,
                }),
                wrq_fn,
            )
        }
        3 => {
            ws.insert(format!("{prefix}.foe_packetno"), json!(arg));
            ws.insert(format!("{prefix}.foe.packet_no"), json!(arg));
            let mut obj = Map::new();
            obj.insert("kind".into(), json!("FoE"));
            obj.insert("opcode".into(), json!(opcode));
            obj.insert("opcode_name".into(), json!(op_name));
            obj.insert("packet_no".into(), json!(arg));
            obj.insert("data_len".into(), json!(tail.len()));
            obj.insert("data_hex".into(), json!(format_hex(tail)));

            if (force_efw && tail.len() >= 8) || looks_like_efw_block(tail) {
                let efw_cmd = u16::from_le_bytes([tail[0], tail[1]]);
                let efw_size = u16::from_le_bytes([tail[2], tail[3]]);
                let efw_addr_lw = u16::from_le_bytes([tail[4], tail[5]]);
                let efw_addr_hw = u16::from_le_bytes([tail[6], tail[7]]);
                let end = (8 + efw_size as usize).min(tail.len());
                let efw_data = format_hex(&tail[8..end]);

                ws.insert(format!("{prefix}.foe.efw"), json!(format_hex(tail)));
                ws.insert(
                    format!("{prefix}.foe.efw.cmd"),
                    json!(format!("0x{efw_cmd:04x}")),
                );
                ws.insert(format!("{prefix}.foe.efw.size"), json!(efw_size));
                ws.insert(
                    format!("{prefix}.foe.efw.addresslw"),
                    json!(format!("0x{efw_addr_lw:04x}")),
                );
                ws.insert(
                    format!("{prefix}.foe.efw.addresshw"),
                    json!(format!("0x{efw_addr_hw:04x}")),
                );
                ws.insert(format!("{prefix}.foe.efw.data"), json!(efw_data.clone()));

                obj.insert(
                    "efw_firmware".into(),
                    json!({
                        "cmd": format!("0x{efw_cmd:04x}"),
                        "cmd_name": foe_efw_cmd_name(efw_cmd),
                        "size": efw_size,
                        "address_lw": format!("0x{efw_addr_lw:04x}"),
                        "address_hw": format!("0x{efw_addr_hw:04x}"),
                        "address": format!("0x{:08x}", ((efw_addr_hw as u32) << 16) | efw_addr_lw as u32),
                        "data_hex": efw_data,
                    }),
                );
            }

            (Value::Object(obj), None)
        }
        4 => {
            ws.insert(format!("{prefix}.foe_packetno"), json!(arg));
            ws.insert(format!("{prefix}.foe.packet_no"), json!(arg));
            (
                json!({
                    "kind": "FoE",
                    "opcode": opcode,
                    "opcode_name": op_name,
                    "packet_no": arg,
                }),
                None,
            )
        }
        5 => {
            let err_text = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(format!("{prefix}.foe_errcode"), json!(arg));
            ws.insert(format!("{prefix}.foe_errtext"), json!(err_text.clone()));
            ws.insert(
                format!("{prefix}.foe.error_code"),
                json!(format!("0x{arg:08x}")),
            );
            (
                json!({
                    "kind": "FoE",
                    "opcode": opcode,
                    "opcode_name": op_name,
                    "error_code": format!("0x{arg:08x}"),
                    "error_text": err_text,
                }),
                None,
            )
        }
        6 => {
            let done = u16::from_le_bytes([body[2], body[3]]);
            let entire = u16::from_le_bytes([body[4], body[5]]);
            let busy_text = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(
                format!("{prefix}.foe_busydone"),
                json!(format!("0x{done:04x}")),
            );
            ws.insert(
                format!("{prefix}.foe_busyentire"),
                json!(format!("0x{entire:04x}")),
            );
            if !tail.is_empty() {
                ws.insert(format!("{prefix}.foe_busydata"), json!(format_hex(tail)));
            }
            ws.insert(format!("{prefix}.foe.busy_done"), json!(done));
            ws.insert(format!("{prefix}.foe.busy_entire"), json!(entire));
            (
                json!({
                    "kind": "FoE",
                    "opcode": opcode,
                    "opcode_name": op_name,
                    "done": done,
                    "entire": entire,
                    "busy_text": busy_text,
                }),
                None,
            )
        }
        _ => (
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "arg": arg,
                "raw_hex": format_hex(tail),
            }),
            None,
        ),
    }
}

fn dissect_soe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 4 {
        ws.insert(format!("{prefix}.soe.invalid"), json!(true));
        return json!({ "kind": "SoE", "truncated": true, "raw_hex": format_hex(body) });
    }
    let hdr16 = u16::from_le_bytes([body[0], body[1]]);
    let hdr0 = body[0];
    let opcode = hdr0 & 0x07;
    let incomplete = (hdr0 & 0x08) != 0;
    let error = (hdr0 & 0x10) != 0;
    let drive_no = (hdr0 >> 5) & 0x07;
    let element_flags = body[1];
    let idn_or_frag = u16::from_le_bytes([body[2], body[3]]);
    let idn_prefix = if (idn_or_frag & 0x8000) != 0 {
        'P'
    } else {
        'S'
    };
    let idn_set = (idn_or_frag >> 12) & 0x07;
    let idn_block = idn_or_frag & 0x0FFF;
    let idn_str = format!("{idn_prefix}-{idn_set}-{idn_block:04}");
    let op_name = match opcode {
        1 => "Read Request",
        2 => "Read Response",
        3 => "Write Request",
        4 => "Write Response",
        5 => "Notification",
        6 => "Emergency",
        7 => "Command",
        _ => "Unknown SoE",
    };

    let tail = &body[4..];
    // Official Wireshark 4.6 SoE fields
    ws.insert(format!("{prefix}.soe"), json!(format_hex(body)));
    ws.insert(
        format!("{prefix}.soe_header"),
        json!(format!("0x{hdr16:04x}")),
    );
    ws.insert(format!("{prefix}.soe_opcode"), json!(opcode));
    ws.insert(format!("{prefix}.soe_header_incomplete"), json!(incomplete));
    ws.insert(format!("{prefix}.soe_header_error"), json!(error));
    ws.insert(format!("{prefix}.soe_header_driveno"), json!(drive_no));
    ws.insert(
        format!("{prefix}.soe_header_datastate"),
        json!((element_flags & 0x01) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_name"),
        json!((element_flags & 0x02) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_attribute"),
        json!((element_flags & 0x04) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_unit"),
        json!((element_flags & 0x08) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_min"),
        json!((element_flags & 0x10) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_max"),
        json!((element_flags & 0x20) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_value"),
        json!((element_flags & 0x40) != 0),
    );
    ws.insert(
        format!("{prefix}.soe_header_reserved"),
        json!((element_flags & 0x80) != 0),
    );
    // Legacy CLI aliases
    ws.insert(format!("{prefix}.soe.opcode"), json!(opcode));
    ws.insert(format!("{prefix}.soe.incomplete"), json!(incomplete));
    ws.insert(format!("{prefix}.soe.error"), json!(error));
    ws.insert(format!("{prefix}.soe.drive_no"), json!(drive_no));

    // ETG.1000.6 error code (last 2 bytes of an error response) as a CLI extension field.
    let soe_err_code = if error && tail.len() >= 2 {
        let ec = u16::from_le_bytes([tail[tail.len() - 2], tail[tail.len() - 1]]);
        ws.insert(
            format!("{prefix}.soe.error_code"),
            json!(format!("0x{ec:04x}")),
        );
        Some(format!("0x{ec:04x}"))
    } else {
        None
    };

    // Official Wireshark 4.6 `dissect_ecat_soe()` presence rules.
    let idn_hex = json!(format!("0x{idn_or_frag:04x}"));
    if error {
        ws.insert(format!("{prefix}.soe_idn"), idn_hex.clone());
        // Wireshark reads `soe_error` at the same offset as the IDN.
        ws.insert(format!("{prefix}.soe_error"), idn_hex);
    } else if incomplete {
        ws.insert(format!("{prefix}.soe_frag"), idn_hex);
        ws.insert(format!("{prefix}.soe_data"), json!(format_hex(tail)));
    } else {
        match opcode {
            1 | 4 => {
                ws.insert(format!("{prefix}.soe_idn"), idn_hex);
            }
            2 | 3 | 5 => {
                ws.insert(format!("{prefix}.soe_idn"), idn_hex);
                ws.insert(format!("{prefix}.soe_data"), json!(format_hex(tail)));
            }
            _ => {}
        }
    }

    if incomplete {
        ws.insert(format!("{prefix}.soe.fragments_left"), json!(idn_or_frag));
    } else {
        ws.insert(format!("{prefix}.soe.idn"), json!(idn_str.clone()));
        ws.insert(format!("{prefix}.soe.fragments_left"), json!(0));
    }

    json!({
        "kind": "SoE",
        "opcode": opcode,
        "opcode_name": op_name,
        "incomplete": incomplete,
        "error": error,
        "soe_error_code": soe_err_code,
        "drive_no": drive_no,
        "element_flags": format!("0x{element_flags:02x}"),
        "idn": if incomplete { json!(null) } else { json!(idn_str) },
        "fragments_left": if incomplete { json!(idn_or_frag) } else { json!(0) },
        "data_hex": format_hex(tail),
    })
}

fn dissect_coe_sdo_block_cmd(
    service: u8,
    number: u16,
    cmd: u8,
    ccs_scs: u8,
    payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> (Value, Option<SdoEventKind>) {
    let svc_name = coe_service_name(service);
    match (service, ccs_scs) {
        // SDO Block Download Request (ccs == 6)
        (0x02, 6) => {
            let cs = cmd & 0x01;
            if cs == 0 {
                // Initiate Block Download Request
                if payload.len() < 8 {
                    ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                    return (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Initiate Block Download Request",
                            "truncated": true,
                        }),
                        None,
                    );
                }
                let index = u16::from_le_bytes([payload[1], payload[2]]);
                let subindex = payload[3];
                let total_size =
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let complete_access = (cmd & 0x10) != 0;
                let crc_support = (cmd & 0x04) != 0;
                let size_indicated = (cmd & 0x02) != 0;
                let idx_s = format!("0x{index:04x}");

                ws.insert(format!("{prefix}.coe.sdoidx"), json!(idx_s.clone()));
                ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
                ws.insert(format!("{prefix}.coe.sdosub"), json!(subindex));
                ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
                ws.insert(format!("{prefix}.coe.sdo.ca"), json!(complete_access));
                ws.insert(
                    format!("{prefix}.coe.sdolength"),
                    json!(format!("0x{total_size:08x}")),
                );
                ws.insert(format!("{prefix}.coe.sdo.total_size"), json!(total_size));
                ws.insert(
                    format!("{prefix}.coe.sdoblk.crc_support"),
                    json!(crc_support),
                );

                (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "Initiate Block Download Request",
                        "index": idx_s,
                        "subindex": subindex,
                        "complete_access": complete_access,
                        "crc_support": crc_support,
                        "size_indicated": size_indicated,
                        "total_size": total_size,
                    }),
                    Some(SdoEventKind::InitiateBlockDownload {
                        index,
                        subindex,
                        complete_access,
                        crc_support,
                        indicated_size: size_indicated.then_some(total_size as usize),
                    }),
                )
            } else {
                // End Block Download Request
                if payload.len() < 3 {
                    ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                    return (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "End Block Download Request",
                            "truncated": true,
                        }),
                        None,
                    );
                }
                let unused_bytes = (cmd >> 2) & 0x07;
                let crc = u16::from_le_bytes([payload[1], payload[2]]);
                let crc_s = format!("0x{crc:04x}");
                ws.insert(format!("{prefix}.coe.sdoblk.unused"), json!(unused_bytes));
                ws.insert(format!("{prefix}.coe.sdoblk.crc"), json!(crc_s.clone()));
                (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "End Block Download Request",
                        "unused_bytes": unused_bytes,
                        "crc": crc_s,
                    }),
                    Some(SdoEventKind::EndBlockDownload { unused_bytes, crc }),
                )
            }
        }
        // SDO Block Download Server Responses (scs == 5)
        (0x03, 5) => {
            let ss = cmd & 0x03;
            match ss {
                0 => {
                    if payload.len() < 5 {
                        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                        return (
                            json!({
                                "kind": "CoE",
                                "service": svc_name,
                                "number": number,
                                "sdo_op": "Initiate Block Download Response",
                                "truncated": true,
                            }),
                            None,
                        );
                    }
                    let index = u16::from_le_bytes([payload[1], payload[2]]);
                    let subindex = payload[3];
                    let blksize = payload[4];
                    let crc_support = (cmd & 0x04) != 0;
                    let idx_s = format!("0x{index:04x}");
                    ws.insert(format!("{prefix}.coe.sdoidx"), json!(idx_s.clone()));
                    ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
                    ws.insert(format!("{prefix}.coe.sdosub"), json!(subindex));
                    ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
                    ws.insert(format!("{prefix}.coe.sdoblk.blksize"), json!(blksize));
                    ws.insert(
                        format!("{prefix}.coe.sdoblk.crc_support"),
                        json!(crc_support),
                    );
                    (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Initiate Block Download Response",
                            "index": idx_s,
                            "subindex": subindex,
                            "crc_support": crc_support,
                            "blksize": blksize,
                        }),
                        Some(SdoEventKind::InitiateBlockDownloadRes {
                            index,
                            subindex,
                            crc_support,
                            blksize,
                        }),
                    )
                }
                2 => {
                    if payload.len() < 3 {
                        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                        return (
                            json!({
                                "kind": "CoE",
                                "service": svc_name,
                                "number": number,
                                "sdo_op": "Block Download Response",
                                "truncated": true,
                            }),
                            None,
                        );
                    }
                    let ackseq = payload[1];
                    let blksize = payload[2];
                    ws.insert(format!("{prefix}.coe.sdoblk.ackseq"), json!(ackseq));
                    ws.insert(format!("{prefix}.coe.sdoblk.blksize"), json!(blksize));
                    (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Block Download Response",
                            "ackseq": ackseq,
                            "blksize": blksize,
                        }),
                        Some(SdoEventKind::BlockDownloadAck { ackseq, blksize }),
                    )
                }
                _ => (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "End Block Download Response",
                    }),
                    Some(SdoEventKind::EndBlockDownloadRes),
                ),
            }
        }
        // SDO Block Upload Client Requests (ccs == 5)
        (0x02, 5) => {
            let cs = cmd & 0x03;
            match cs {
                0 => {
                    if payload.len() < 6 {
                        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                        return (
                            json!({
                                "kind": "CoE",
                                "service": svc_name,
                                "number": number,
                                "sdo_op": "Initiate Block Upload Request",
                                "truncated": true,
                            }),
                            None,
                        );
                    }
                    let index = u16::from_le_bytes([payload[1], payload[2]]);
                    let subindex = payload[3];
                    let blksize = payload[4];
                    let pst = payload[5];
                    let complete_access = (cmd & 0x10) != 0;
                    let crc_support = (cmd & 0x04) != 0;
                    let idx_s = format!("0x{index:04x}");
                    ws.insert(format!("{prefix}.coe.sdoidx"), json!(idx_s.clone()));
                    ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
                    ws.insert(format!("{prefix}.coe.sdosub"), json!(subindex));
                    ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
                    ws.insert(format!("{prefix}.coe.sdo.ca"), json!(complete_access));
                    ws.insert(format!("{prefix}.coe.sdoblk.blksize"), json!(blksize));
                    ws.insert(format!("{prefix}.coe.sdoblk.pst"), json!(pst));
                    ws.insert(
                        format!("{prefix}.coe.sdoblk.crc_support"),
                        json!(crc_support),
                    );
                    (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Initiate Block Upload Request",
                            "index": idx_s,
                            "subindex": subindex,
                            "complete_access": complete_access,
                            "crc_support": crc_support,
                            "blksize": blksize,
                            "pst": pst,
                        }),
                        Some(SdoEventKind::InitiateBlockUploadReq {
                            index,
                            subindex,
                            complete_access,
                            crc_support,
                            blksize,
                            pst,
                        }),
                    )
                }
                3 => (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "Start Block Upload Request",
                    }),
                    Some(SdoEventKind::StartBlockUpload),
                ),
                2 => {
                    if payload.len() < 3 {
                        ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                        return (
                            json!({
                                "kind": "CoE",
                                "service": svc_name,
                                "number": number,
                                "sdo_op": "Block Upload Response",
                                "truncated": true,
                            }),
                            None,
                        );
                    }
                    let ackseq = payload[1];
                    let blksize = payload[2];
                    ws.insert(format!("{prefix}.coe.sdoblk.ackseq"), json!(ackseq));
                    ws.insert(format!("{prefix}.coe.sdoblk.blksize"), json!(blksize));
                    (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Block Upload Response",
                            "ackseq": ackseq,
                            "blksize": blksize,
                        }),
                        Some(SdoEventKind::BlockUploadAck { ackseq, blksize }),
                    )
                }
                _ => (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "End Block Upload Response",
                    }),
                    Some(SdoEventKind::EndBlockUploadRes),
                ),
            }
        }
        // SDO Block Upload Server Responses (scs == 6)
        (0x03, 6) => {
            let ss = cmd & 0x01;
            if ss == 0 {
                if payload.len() < 8 {
                    ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                    return (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "Initiate Block Upload Response",
                            "truncated": true,
                        }),
                        None,
                    );
                }
                let index = u16::from_le_bytes([payload[1], payload[2]]);
                let subindex = payload[3];
                let total_size =
                    u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
                let crc_support = (cmd & 0x04) != 0;
                let size_indicated = (cmd & 0x02) != 0;
                let idx_s = format!("0x{index:04x}");
                ws.insert(format!("{prefix}.coe.sdoidx"), json!(idx_s.clone()));
                ws.insert(format!("{prefix}.coe.sdo.index"), json!(idx_s.clone()));
                ws.insert(format!("{prefix}.coe.sdosub"), json!(subindex));
                ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
                ws.insert(
                    format!("{prefix}.coe.sdolength"),
                    json!(format!("0x{total_size:08x}")),
                );
                ws.insert(format!("{prefix}.coe.sdo.total_size"), json!(total_size));
                ws.insert(
                    format!("{prefix}.coe.sdoblk.crc_support"),
                    json!(crc_support),
                );
                (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "Initiate Block Upload Response",
                        "index": idx_s,
                        "subindex": subindex,
                        "crc_support": crc_support,
                        "size_indicated": size_indicated,
                        "total_size": total_size,
                    }),
                    Some(SdoEventKind::InitiateBlockUploadRes {
                        index,
                        subindex,
                        crc_support,
                        indicated_size: size_indicated.then_some(total_size as usize),
                    }),
                )
            } else {
                if payload.len() < 3 {
                    ws.insert(format!("{prefix}.coe.invalid"), json!(true));
                    return (
                        json!({
                            "kind": "CoE",
                            "service": svc_name,
                            "number": number,
                            "sdo_op": "End Block Upload Request",
                            "truncated": true,
                        }),
                        None,
                    );
                }
                let unused_bytes = (cmd >> 2) & 0x07;
                let crc = u16::from_le_bytes([payload[1], payload[2]]);
                let crc_s = format!("0x{crc:04x}");
                ws.insert(format!("{prefix}.coe.sdoblk.unused"), json!(unused_bytes));
                ws.insert(format!("{prefix}.coe.sdoblk.crc"), json!(crc_s.clone()));
                (
                    json!({
                        "kind": "CoE",
                        "service": svc_name,
                        "number": number,
                        "sdo_op": "End Block Upload Request",
                        "unused_bytes": unused_bytes,
                        "crc": crc_s,
                    }),
                    Some(SdoEventKind::EndBlockUpload { unused_bytes, crc }),
                )
            }
        }
        _ => (
            json!({
                "kind": "CoE",
                "service": svc_name,
                "number": number,
                "sdo_op": "SDO Block Message",
            }),
            None,
        ),
    }
}

/// Re-dissects an active CoE SDO Block sub-block PDU (`seq_no = 1..=127`), purging any
/// stateless command/abort/index fields that may have been emitted prior to session state check.
pub fn dissect_mailbox_sdo_subblock(
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
    sub_idx: Option<usize>,
) -> Option<DissectedMailbox> {
    if data.len() < 9 {
        return None;
    }
    let length = u16::from_le_bytes([data[0], data[1]]);
    let address = u16::from_le_bytes([data[2], data[3]]);
    let channel = data[4] & 0x3F;
    let priority = (data[4] >> 6) & 0x03;
    let mbx_type = data[5] & 0x0F;
    if mbx_type != 0x03 {
        return None;
    }
    let counter = (data[5] >> 4) & 0x07;
    let body_end = (6 + length as usize).min(data.len());
    let body = &data[6..body_end];
    if body.len() < 3 {
        return None;
    }
    let coe_hdr = u16::from_le_bytes([body[0], body[1]]);
    let number = coe_hdr & 0x01FF;
    let service = ((coe_hdr >> 12) & 0x0F) as u8;
    if service != 0x02 && service != 0x03 {
        return None;
    }
    let seq_hdr = body[2];
    let seq_no = seq_hdr & 0x7F;
    // `seq_no == 0` (`0x80`) is a genuine SDO Abort Transfer, NOT a valid sub-block (1..=127)
    if seq_no == 0 {
        return None;
    }
    let last_subblock = (seq_hdr & 0x80) != 0;
    let sub_data = &body[3..];
    let dhex = format_hex(sub_data);
    let is_download = service == 0x02;

    // Purge any stateless CoE SDO command/index/abort keys produced before sub-block state detection
    let include_top = match sub_idx {
        None | Some(0) => true,
        Some(si) => !(0..si).any(|j| {
            let pfx = format!("ecat_mailbox[{j}].coe.");
            ws.keys().any(|k| k.starts_with(&pfx))
        }),
    };
    let mut prefixes = vec![prefix.to_string()];
    if include_top && prefix != "ecat_mailbox" {
        prefixes.push("ecat_mailbox".to_string());
    }
    if let Some(si) = sub_idx {
        prefixes.push(format!("ecat[{si}].mailbox"));
        let idx_pfx = format!("ecat_mailbox[{si}]");
        if !prefixes.contains(&idx_pfx) {
            prefixes.push(idx_pfx);
        }
    }
    ws.retain(|k, _| {
        !prefixes.iter().any(|p| {
            k.starts_with(&format!("{p}.coe.sdo"))
                || k.starts_with(&format!("{p}.coe.abortcode"))
                || k.starts_with(&format!("{p}.coe.dsoldata"))
                || k == &format!("{p}.coe.invalid")
        })
    });

    for p in &prefixes {
        ws.insert(format!("{p}.coe.sdoblk.seqno"), json!(seq_no));
        ws.insert(format!("{p}.coe.sdoblk.last"), json!(last_subblock));
        ws.insert(format!("{p}.coe.sdoblk.data"), json!(dhex.clone()));
        ws.insert(format!("{p}.coe.dsoldata"), json!(dhex.clone()));
        ws.insert(format!("{p}.coe.sdo.data"), json!(dhex.clone()));
    }

    let op_str = if is_download {
        "Block Download Sub-block"
    } else {
        "Block Upload Sub-block"
    };

    Some(DissectedMailbox {
        length,
        address,
        channel,
        priority,
        mbx_type,
        mbx_type_name: mailbox_type_name(mbx_type),
        counter,
        malformed: (6 + length as usize) > data.len() || length == 0,
        protocol: json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "sdo_op": op_str,
            "seq_no": seq_no,
            "last_subblock": last_subblock,
            "data_hex": dhex,
        }),
        sdo_event: Some(SdoEventKind::BlockSubblock {
            is_download,
            seq_no,
            last_subblock,
            data: sub_data.to_vec(),
        }),
        sdo_info_fragment: None,
        eoe_fragment: None,
        foe_wrq_filename: None,
        raw_bytes: data.to_vec(),
    })
}
