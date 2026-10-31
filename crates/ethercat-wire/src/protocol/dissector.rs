use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use crate::error::{CliError, Result};
use crate::pdo_codec::{decode_pdo_payload, PdoLayout};
use crate::protocol::constants::{
    al_state_name, al_status_code_description, ecat_frame_type_name, lookup_esc_register_by_addr,
    EcatCmd, ECAT_DATAGRAM_HEADER_LEN, ECAT_FRAME_HEADER_LEN, ECAT_FRAME_TYPE_DLPDU,
    ECAT_FRAME_TYPE_MAILBOX, ECAT_FRAME_TYPE_NV, ECAT_WKC_LEN, ETH_HEADER_LEN, ETH_P_ECAT,
    UDP_PORT_ECAT,
};
use crate::protocol::frame::skip_ethernet_vlan_tags;
use crate::protocol::mailbox::{dissect_mailbox, looks_like_mailbox, DissectedMailbox};
use crate::types::{format_hex, format_mac};

#[derive(Debug, Clone, Default)]
pub struct DissectOptions {
    pub bare_ecat: bool,
    pub force_mailbox: bool,
    pub pdo_layout: Option<PdoLayout>,
}

const ESL_SIGNATURE: [u8; 6] = [0x01, 0x01, 0x05, 0x10, 0x00, 0x00];
const ESL_HEADER_LEN: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct DissectedEsl {
    pub position: &'static str,
    pub flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u8>,
    pub crc_error: bool,
    pub align_error: bool,
    pub timestamp_enabled: bool,
    pub tlv_error: bool,
    pub timestamp_ns: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct DissectedEthernet {
    pub dst_mac: String,
    pub src_mac: String,
    pub src_locally_administered: bool,
    pub vlan_id: Option<u16>,
    pub ethertype: String,
    pub encapsulation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DissectedDatagram {
    pub subframe_index: usize,
    pub cmd: u8,
    pub cmd_mnemonic: String,
    pub cmd_description: String,
    pub idx: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adp: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adp_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_inc_slave_hint: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado_register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_addr: Option<String>,
    pub length: u16,
    pub reserved: u8,
    pub circulating: bool,
    pub more: bool,
    pub irq: String,
    pub irq_events: Vec<&'static str>,
    pub data_hex: String,
    pub wkc: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_decode: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<DissectedMailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdo_fields: Option<Vec<Value>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DissectedFrame {
    pub frame_wire_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esl: Option<DissectedEsl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ethernet: Option<DissectedEthernet>,
    pub ecat_header: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub datagrams: Vec<DissectedDatagram>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_mailbox: Option<DissectedMailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_variables: Option<Value>,
    pub padding_bytes: usize,
    pub wireshark_fields: BTreeMap<String, Value>,
}

/// Fast zero-allocation pre-check whether `raw` carries an EtherCAT frame (L2 `0x88A4`,
/// 802.1Q/802.1ad VLAN + `0x88A4`, Beckhoff ESL + Ethernet, or IPv4+UDP port `34980`).
pub fn may_contain_ethercat(raw: &[u8], bare_ecat: bool) -> bool {
    if bare_ecat {
        return raw.len() >= ECAT_FRAME_HEADER_LEN;
    }
    if raw.len() >= ESL_HEADER_LEN + ETH_HEADER_LEN
        && raw[0..6] == ESL_SIGNATURE
        && has_ecat_l2_header(&raw[ESL_HEADER_LEN..])
    {
        return true;
    }
    has_ecat_l2_header(raw)
}

pub fn dissect_frame(raw: &[u8], opts: &DissectOptions) -> Result<DissectedFrame> {
    let mut ws = BTreeMap::new();
    let (mut esl_info, eth_info, ecat_offset, payload_bound) = if opts.bare_ecat {
        (None, None, 0usize, raw.len())
    } else {
        parse_l2_encapsulation(raw, &mut ws)?
    };
    let bounded_raw = &raw[..payload_bound.min(raw.len())];

    if bounded_raw.len() < ecat_offset + ECAT_FRAME_HEADER_LEN {
        return Err(CliError::Format(
            "frame truncated before 2-byte EtherCAT header".into(),
        ));
    }

    let hdr_word = u16::from_le_bytes([bounded_raw[ecat_offset], bounded_raw[ecat_offset + 1]]);
    let ecat_len = (hdr_word & 0x07FF) as usize;
    let ecat_res = ((hdr_word >> 11) & 0x01) as u8;
    let ecat_type = ((hdr_word >> 12) & 0x0F) as u8;
    let ecat_type_str = ecat_frame_type_name(ecat_type);

    ws.insert("ecatf.length".into(), json!(ecat_len));
    ws.insert("ecatf.reserved".into(), json!(ecat_res));
    ws.insert("ecatf.type".into(), json!(ecat_type));
    ws.insert("ecatf.type_name".into(), json!(ecat_type_str));

    let body_start = ecat_offset + ECAT_FRAME_HEADER_LEN;
    if body_start + ecat_len > bounded_raw.len() {
        return Err(CliError::Format(format!(
            "EtherCAT frame header length ({ecat_len}) exceeds remaining bytes ({})",
            bounded_raw.len() - body_start
        )));
    }
    let body = &bounded_raw[body_start..body_start + ecat_len];
    let mut padding_bytes = raw.len() - (body_start + ecat_len);

    // Detect Beckhoff ET2000 16-byte ESL trailer (postfix mode, with or without 4-byte trailing FCS)
    if !opts.bare_ecat && esl_info.is_none() && padding_bytes >= ESL_HEADER_LEN {
        let trailer_ends: &[usize] = if padding_bytes >= ESL_HEADER_LEN + 4 {
            &[raw.len(), raw.len() - 4]
        } else {
            &[raw.len()]
        };
        for &end in trailer_ends {
            let start = end - ESL_HEADER_LEN;
            if raw[start..start + 6] == ESL_SIGNATURE {
                esl_info = Some(dissect_esl_tag(&raw[start..end], "trailer", &mut ws));
                padding_bytes -= ESL_HEADER_LEN;
                break;
            }
        }
    }

    let mut datagrams = Vec::new();
    let mut direct_mailbox = None;
    let mut network_variables = None;

    match ecat_type {
        ECAT_FRAME_TYPE_DLPDU => {
            let mut pos = 0usize;
            let mut sub_idx = 0usize;
            while pos < body.len() {
                if pos + ECAT_DATAGRAM_HEADER_LEN + ECAT_WKC_LEN > body.len() {
                    return Err(CliError::Format(format!(
                        "subframe {sub_idx} truncated at byte offset {pos}"
                    )));
                }
                let cmd_byte = body[pos];
                let cmd_enum = EcatCmd::from_code(cmd_byte);
                let idx = body[pos + 1];
                let word_a = u16::from_le_bytes([body[pos + 2], body[pos + 3]]);
                let word_b = u16::from_le_bytes([body[pos + 4], body[pos + 5]]);
                let lad = u32::from_le_bytes([
                    body[pos + 2],
                    body[pos + 3],
                    body[pos + 4],
                    body[pos + 5],
                ]);
                let len_flags = u16::from_le_bytes([body[pos + 6], body[pos + 7]]);
                let dlen = (len_flags & 0x07FF) as usize;
                let reserved = ((len_flags >> 11) & 0x07) as u8;
                let circulating = (len_flags & 0x4000) != 0;
                let more = (len_flags & 0x8000) != 0;
                let irq = u16::from_le_bytes([body[pos + 8], body[pos + 9]]);

                let data_start = pos + ECAT_DATAGRAM_HEADER_LEN;
                let data_end = data_start + dlen;
                if data_end + ECAT_WKC_LEN > body.len() {
                    return Err(CliError::Format(format!(
                        "subframe {sub_idx} payload ({dlen} bytes) overflows EtherCAT body"
                    )));
                }
                let data = &body[data_start..data_end];
                let wkc = u16::from_le_bytes([body[data_end], body[data_end + 1]]);

                let mnemonic = cmd_enum
                    .map(|c| c.mnemonic().to_string())
                    .unwrap_or_else(|| format!("CMD_0x{cmd_byte:02X}"));
                let cmd_desc = cmd_enum
                    .map(|c| c.description().to_string())
                    .unwrap_or_else(|| "Unknown/Reserved Command".to_string());

                let is_logical = cmd_enum.is_some_and(|c| c.is_logical());
                let is_auto_inc = cmd_enum.is_some_and(|c| c.is_auto_increment());

                let pfx = format!("ecat[{sub_idx}]");
                ws.insert(format!("{pfx}.cmd"), json!(mnemonic.clone()));
                ws.insert(format!("{pfx}.cmd_code"), json!(cmd_byte));
                ws.insert(format!("{pfx}.idx"), json!(idx));
                ws.insert(format!("{pfx}.len"), json!(dlen));
                ws.insert(format!("{pfx}.r"), json!(reserved));
                ws.insert(format!("{pfx}.res"), json!(reserved));
                ws.insert(format!("{pfx}.c"), json!(circulating));
                ws.insert(format!("{pfx}.circulating"), json!(circulating));
                ws.insert(format!("{pfx}.m"), json!(more));
                ws.insert(format!("{pfx}.next"), json!(more));
                ws.insert(format!("{pfx}.irq"), json!(format!("0x{irq:04x}")));
                ws.insert(format!("{pfx}.data"), json!(format_hex(data)));
                ws.insert(format!("{pfx}.wkc"), json!(wkc));

                if sub_idx == 0 {
                    ws.insert("ecat.cmd".into(), json!(mnemonic.clone()));
                    ws.insert("ecat.cmd_code".into(), json!(cmd_byte));
                    ws.insert("ecat.idx".into(), json!(idx));
                    ws.insert("ecat.len".into(), json!(dlen));
                    ws.insert("ecat.r".into(), json!(reserved));
                    ws.insert("ecat.res".into(), json!(reserved));
                    ws.insert("ecat.c".into(), json!(circulating));
                    ws.insert("ecat.circulating".into(), json!(circulating));
                    ws.insert("ecat.m".into(), json!(more));
                    ws.insert("ecat.next".into(), json!(more));
                    ws.insert("ecat.irq".into(), json!(format!("0x{irq:04x}")));
                    ws.insert("ecat.data".into(), json!(format_hex(data)));
                    ws.insert("ecat.wkc".into(), json!(wkc));
                }

                let (adp, adp_hex, auto_inc_hint, ado, ado_hex, ado_reg_name, logical_str) =
                    if is_logical {
                        let lhex = format!("0x{lad:08x}");
                        ws.insert(format!("{pfx}.lad"), json!(lhex.clone()));
                        if sub_idx == 0 {
                            ws.insert("ecat.lad".into(), json!(lhex.clone()));
                        }
                        (None, None, None, None, None, None, Some(lhex))
                    } else {
                        let adp_h = format!("0x{word_a:04x}");
                        let ado_h = format!("0x{word_b:04x}");
                        ws.insert(format!("{pfx}.adp"), json!(adp_h.clone()));
                        ws.insert(format!("{pfx}.ado"), json!(ado_h.clone()));
                        if sub_idx == 0 {
                            ws.insert("ecat.adp".into(), json!(adp_h.clone()));
                            ws.insert("ecat.ado".into(), json!(ado_h.clone()));
                        }
                        let reg_info = lookup_esc_register_by_addr(word_b);
                        let reg_str = reg_info.map(|r| format!("{} ({})", r.name, r.symbol));
                        if let Some(ri) = reg_info {
                            ws.insert(format!("{pfx}.ado_name"), json!(ri.name));
                            if sub_idx == 0 {
                                ws.insert("ecat.ado_name".into(), json!(ri.name));
                            }
                        }
                        let hint = if is_auto_inc {
                            Some(1i32 - (word_a as i16 as i32))
                        } else {
                            None
                        };
                        (
                            Some(word_a),
                            Some(adp_h),
                            hint,
                            Some(word_b),
                            Some(ado_h),
                            reg_str,
                            None,
                        )
                    };

                let register_decode = if !is_logical && word_b < 0x1000 && !data.is_empty() {
                    decode_esc_register_payload(word_b, data, &mut ws, Some(sub_idx))
                } else {
                    None
                };

                let prefer_pdo = !opts.force_mailbox
                    && opts
                        .pdo_layout
                        .as_ref()
                        .is_some_and(|l| l.total_bytes() == data.len() && data.len() < 32);

                let mailbox = if !is_logical
                    && !prefer_pdo
                    && (opts.force_mailbox || looks_like_mailbox(word_b, data))
                {
                    let mut mbx_ws = BTreeMap::new();
                    let decoded_mbx = dissect_mailbox(data, &mut mbx_ws, "ecat_mailbox");
                    if decoded_mbx.is_some() {
                        for (k, v) in mbx_ws {
                            let suffix = k.strip_prefix("ecat_mailbox.").unwrap_or(&k);
                            ws.insert(format!("ecat[{sub_idx}].mailbox.{suffix}"), v.clone());
                            ws.insert(format!("ecat_mailbox[{sub_idx}].{suffix}"), v.clone());
                            ws.entry(k).or_insert(v);
                        }
                    }
                    decoded_mbx
                } else {
                    None
                };

                let pdo_fields = if let Some(ref layout) = opts.pdo_layout {
                    if is_logical || (word_b >= 0x1000 && mailbox.is_none()) {
                        decode_pdo_payload(data, layout).ok().inspect(|entries| {
                            for e in entries {
                                if let Some(val) = e.get("value") {
                                    if let Some(name) = e.get("name").and_then(|v| v.as_str()) {
                                        ws.insert(format!("{pfx}.pdo.{name}"), val.clone());
                                        ws.entry(format!("ecat.pdo.{name}"))
                                            .or_insert_with(|| val.clone());
                                    }
                                    if let Some(ent) = e.get("entry").and_then(|v| v.as_str()) {
                                        ws.insert(format!("{pfx}.pdo.{ent}"), val.clone());
                                        ws.entry(format!("ecat.pdo.{ent}"))
                                            .or_insert_with(|| val.clone());
                                    }
                                }
                            }
                        })
                    } else {
                        None
                    }
                } else {
                    None
                };

                datagrams.push(DissectedDatagram {
                    subframe_index: sub_idx,
                    cmd: cmd_byte,
                    cmd_mnemonic: mnemonic,
                    cmd_description: cmd_desc,
                    idx,
                    adp,
                    adp_hex,
                    auto_inc_slave_hint: auto_inc_hint,
                    ado,
                    ado_hex,
                    ado_register: ado_reg_name,
                    logical_addr: logical_str,
                    length: dlen as u16,
                    reserved,
                    circulating,
                    more,
                    irq: format!("0x{irq:04x}"),
                    irq_events: decode_irq_bits(irq),
                    data_hex: format_hex(data),
                    wkc,
                    register_decode,
                    mailbox,
                    pdo_fields,
                });

                pos = data_end + ECAT_WKC_LEN;
                sub_idx += 1;
                if !more {
                    break;
                }
            }
        }
        ECAT_FRAME_TYPE_MAILBOX => {
            direct_mailbox = dissect_mailbox(body, &mut ws, "ecat_mailbox");
        }
        ECAT_FRAME_TYPE_NV => {
            network_variables = Some(dissect_nv(body, &mut ws));
        }
        _ => {}
    }

    Ok(DissectedFrame {
        frame_wire_len: raw.len(),
        esl: esl_info,
        ethernet: eth_info,
        ecat_header: json!({
            "length": ecat_len,
            "reserved": ecat_res,
            "type": ecat_type,
            "type_name": ecat_type_str,
        }),
        datagrams,
        direct_mailbox,
        network_variables,
        padding_bytes,
        wireshark_fields: ws,
    })
}

fn dissect_esl_tag(
    tag: &[u8],
    position: &'static str,
    ws: &mut BTreeMap<String, Value>,
) -> DissectedEsl {
    let flags = u16::from_le_bytes([tag[6], tag[7]]);
    // Wireshark packet-esl.c flags_to_port bitmasks
    const PORT_MASKS: [(u16, u8); 12] = [
        (0x0080, 0),
        (0x0040, 1),
        (0x0020, 2),
        (0x0010, 3),
        (0x0008, 4),
        (0x0004, 5),
        (0x0002, 6),
        (0x0001, 7),
        (0x8000, 8),
        (0x4000, 9),
        (0x0400, 10),
        (0x0200, 11),
    ];
    let port = PORT_MASKS
        .iter()
        .find_map(|&(mask, p)| ((flags & mask) != 0).then_some(p));
    let tlv_error = (flags & 0x0100) != 0;
    let crc_error = (flags & 0x0800) != 0;
    let align_error = (flags & 0x1000) != 0;
    let timestamp_enabled = (flags & 0x2000) != 0;
    let timestamp_ns = u64::from_le_bytes([
        tag[8], tag[9], tag[10], tag[11], tag[12], tag[13], tag[14], tag[15],
    ]);

    ws.insert("esl.flags".into(), json!(format!("0x{flags:04x}")));
    if let Some(p) = port {
        ws.insert("esl.port".into(), json!(p));
    }
    ws.insert("esl.crcerror".into(), json!(crc_error));
    ws.insert("esl.alignerror".into(), json!(align_error));
    ws.insert("esl.tsenable".into(), json!(timestamp_enabled));
    ws.insert("esl.tlverror".into(), json!(tlv_error));
    ws.insert("esl.timestamp".into(), json!(timestamp_ns));

    DissectedEsl {
        position,
        flags: format!("0x{flags:04x}"),
        port,
        crc_error,
        align_error,
        timestamp_enabled,
        tlv_error,
        timestamp_ns,
    }
}

fn has_ecat_l2_header(eth: &[u8]) -> bool {
    if eth.len() < ETH_HEADER_LEN {
        return false;
    }
    let Ok((etype, _vlan, pos)) = skip_ethernet_vlan_tags(eth, 12) else {
        return false;
    };
    if etype == ETH_P_ECAT {
        return true;
    }
    if etype == 0x0800 && eth.len() >= pos + 20 {
        let ver = eth[pos] >> 4;
        let ihl = ((eth[pos] & 0x0F) as usize) * 4;
        let proto = eth[pos + 9];
        if ver == 4 && ihl >= 20 && proto == 17 && eth.len() >= pos + ihl + 8 {
            let udp_off = pos + ihl;
            let src_port = u16::from_be_bytes([eth[udp_off], eth[udp_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[udp_off + 2], eth[udp_off + 3]]);
            let udp_len = u16::from_be_bytes([eth[udp_off + 4], eth[udp_off + 5]]) as usize;
            return udp_len >= 8 && (src_port == UDP_PORT_ECAT || dst_port == UDP_PORT_ECAT);
        }
    }
    false
}

fn parse_l2_encapsulation(
    raw: &[u8],
    ws: &mut BTreeMap<String, Value>,
) -> Result<(
    Option<DissectedEsl>,
    Option<DissectedEthernet>,
    usize,
    usize,
)> {
    let (esl_prefix, l2_base) = if raw.len() >= ESL_HEADER_LEN + ETH_HEADER_LEN
        && raw[0..6] == ESL_SIGNATURE
        && has_ecat_l2_header(&raw[ESL_HEADER_LEN..])
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

    let (etype, vlan_id, pos) = skip_ethernet_vlan_tags(eth, 12)?;

    ws.insert("eth.dst".into(), json!(dst_str.clone()));
    ws.insert("eth.src".into(), json!(src_str.clone()));
    ws.insert("eth.type".into(), json!(format!("0x{etype:04x}")));
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
        return Ok((
            esl_prefix,
            Some(DissectedEthernet {
                dst_mac: dst_str,
                src_mac: src_str,
                src_locally_administered: src_local_admin,
                vlan_id,
                ethertype: format!("0x{etype:04x}"),
                encapsulation: encap,
            }),
            l2_base + pos,
            raw.len(),
        ));
    }

    // Also support UDP/IP EtherCAT (EtherType 0x0800 IPv4 -> Proto 17 UDP -> port 0x88A4 = 34980)
    if etype == 0x0800 && eth.len() >= pos + 20 {
        let ver = eth[pos] >> 4;
        let ihl = ((eth[pos] & 0x0F) as usize) * 4;
        let proto = eth[pos + 9];
        if ver == 4 && ihl >= 20 && proto == 17 && eth.len() >= pos + ihl + 8 {
            let udp_off = pos + ihl;
            let src_port = u16::from_be_bytes([eth[udp_off], eth[udp_off + 1]]);
            let dst_port = u16::from_be_bytes([eth[udp_off + 2], eth[udp_off + 3]]);
            let udp_len = u16::from_be_bytes([eth[udp_off + 4], eth[udp_off + 5]]) as usize;
            if udp_len >= 8 && (src_port == UDP_PORT_ECAT || dst_port == UDP_PORT_ECAT) {
                ws.insert("udp.srcport".into(), json!(src_port));
                ws.insert("udp.dstport".into(), json!(dst_port));
                let has_esl = esl_prefix.is_some();
                let udp_end = (l2_base + udp_off + udp_len).min(raw.len());
                return Ok((
                    esl_prefix,
                    Some(DissectedEthernet {
                        dst_mac: dst_str,
                        src_mac: src_str,
                        src_locally_administered: src_local_admin,
                        vlan_id,
                        ethertype: format!("0x{etype:04x}"),
                        encapsulation: if has_esl {
                            "Beckhoff ESL + Ethernet + IPv4 + UDP (port 34980 / 0x88A4)"
                        } else {
                            "Ethernet + IPv4 + UDP (port 34980 / 0x88A4)"
                        },
                    }),
                    l2_base + udp_off + 8,
                    udp_end,
                ));
            }
        }
    }

    Err(CliError::Format(format!(
        "unsupported EtherType 0x{etype:04X} (expected 0x88A4 EtherCAT or UDP/34980)"
    )))
}

fn decode_irq_bits(irq: u16) -> Vec<&'static str> {
    let mut out = Vec::new();
    if (irq & 0x0001) != 0 {
        out.push("LATCH_EVT");
    }
    if (irq & 0x0004) != 0 {
        out.push("DL_STATUS_EVT");
    }
    if (irq & 0x0008) != 0 {
        out.push("AL_STATUS_EVT");
    }
    if (irq & 0x0010) != 0 {
        out.push("SM0_IRQ");
    }
    if (irq & 0x0020) != 0 {
        out.push("SM1_IRQ");
    }
    if (irq & 0x0040) != 0 {
        out.push("SM2_IRQ");
    }
    if (irq & 0x0080) != 0 {
        out.push("SM3_IRQ");
    }
    if (irq & 0x0100) != 0 {
        out.push("SM4_IRQ");
    }
    if (irq & 0x0200) != 0 {
        out.push("SM5_IRQ");
    }
    if (irq & 0x0400) != 0 {
        out.push("SM6_IRQ");
    }
    if (irq & 0x0800) != 0 {
        out.push("SM7_IRQ");
    }
    out
}

fn emit_reg_ws(ws: &mut BTreeMap<String, Value>, sub_idx: Option<usize>, key: &str, val: Value) {
    if let Some(i) = sub_idx {
        ws.insert(format!("ecat[{i}].reg.{key}"), val.clone());
        ws.entry(format!("ecat.reg.{key}")).or_insert(val);
    }
}

fn esc_port_type_name(bits: u8) -> &'static str {
    match bits & 0x03 {
        0 => "NotImplemented",
        1 => "NotConfigured",
        2 => "EBUS",
        _ => "MII",
    }
}

pub fn decode_esc_register_payload(
    ado: u16,
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    sub_idx: Option<usize>,
) -> Option<Value> {
    if data.is_empty() {
        return None;
    }

    let byte_at = |reg: u16| -> Option<u8> {
        let off = reg.checked_sub(ado)? as usize;
        data.get(off).copied()
    };
    let u16_at = |reg: u16| -> Option<u16> {
        let off = reg.checked_sub(ado)? as usize;
        if off + 2 <= data.len() {
            Some(u16::from_le_bytes([data[off], data[off + 1]]))
        } else {
            None
        }
    };
    let u32_at = |reg: u16| -> Option<u32> {
        let off = reg.checked_sub(ado)? as usize;
        if off + 4 <= data.len() {
            Some(u32::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
            ]))
        } else {
            None
        }
    };
    let u64_at = |reg: u16| -> Option<u64> {
        let off = reg.checked_sub(ado)? as usize;
        if off + 8 <= data.len() {
            Some(u64::from_le_bytes([
                data[off],
                data[off + 1],
                data[off + 2],
                data[off + 3],
                data[off + 4],
                data[off + 5],
                data[off + 6],
                data[off + 7],
            ]))
        } else {
            None
        }
    };

    match ado {
        0x0000..=0x0009 => {
            let mut m = serde_json::Map::new();
            m.insert("register".into(), json!("ESC Information"));
            if let Some(esc_type) = byte_at(0x0000) {
                let s = format!("0x{esc_type:02x}");
                emit_reg_ws(ws, sub_idx, "esc_type", json!(s.clone()));
                m.insert("esc_type".into(), json!(s));
            }
            if let Some(rev) = byte_at(0x0001) {
                emit_reg_ws(ws, sub_idx, "esc_revision", json!(rev));
                m.insert("revision".into(), json!(rev));
            }
            if let Some(build) = u16_at(0x0002) {
                emit_reg_ws(ws, sub_idx, "esc_build", json!(build));
                m.insert("build".into(), json!(build));
            }
            if let Some(fmmu_cnt) = byte_at(0x0004) {
                emit_reg_ws(ws, sub_idx, "fmmu_count", json!(fmmu_cnt));
                m.insert("fmmu_count".into(), json!(fmmu_cnt));
            }
            if let Some(sm_cnt) = byte_at(0x0005) {
                emit_reg_ws(ws, sub_idx, "sm_count", json!(sm_cnt));
                m.insert("sm_count".into(), json!(sm_cnt));
            }
            if let Some(ram_kb) = byte_at(0x0006) {
                emit_reg_ws(ws, sub_idx, "ram_size_kb", json!(ram_kb));
                m.insert("ram_size_kb".into(), json!(ram_kb));
            }
            if let Some(pdesc) = byte_at(0x0007) {
                let s = format!("0x{pdesc:02x}");
                emit_reg_ws(ws, sub_idx, "port_desc", json!(s.clone()));
                m.insert("port_descriptor".into(), json!(s));
                m.insert(
                    "ports".into(),
                    json!([
                        esc_port_type_name(pdesc),
                        esc_port_type_name(pdesc >> 2),
                        esc_port_type_name(pdesc >> 4),
                        esc_port_type_name(pdesc >> 6),
                    ]),
                );
            }
            if let Some(feat) = u16_at(0x0008) {
                let s = format!("0x{feat:04x}");
                let dc_sup = (feat & 0x0004) != 0;
                emit_reg_ws(ws, sub_idx, "esc_features", json!(s.clone()));
                emit_reg_ws(ws, sub_idx, "dc_supported", json!(dc_sup));
                m.insert("esc_features".into(), json!(s));
                m.insert(
                    "features_decoded".into(),
                    json!({
                        "fmmu_bit_operation_not_supported": (feat & 0x0001) != 0,
                        "distributed_clocks_available": dc_sup,
                        "dc_width_64bit": (feat & 0x0008) != 0,
                        "ebus_low_jitter": (feat & 0x0010) != 0,
                        "ebus_enhanced_link_detection": (feat & 0x0020) != 0,
                        "mii_enhanced_link_detection": (feat & 0x0040) != 0,
                        "fcs_error_separate_counter": (feat & 0x0080) != 0,
                    }),
                );
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0010 if data.len() >= 2 => {
            let stadr = u16::from_le_bytes([data[0], data[1]]);
            let alias = if data.len() >= 4 {
                Some(u16::from_le_bytes([data[2], data[3]]))
            } else {
                None
            };
            emit_reg_ws(ws, sub_idx, "station_addr", json!(format!("0x{stadr:04x}")));
            if let Some(al) = alias {
                emit_reg_ws(ws, sub_idx, "alias", json!(format!("0x{al:04x}")));
            }
            Some(json!({
                "register": "Configured Station Address",
                "station_addr": format!("0x{stadr:04x}"),
                "alias": alias.map(|a| format!("0x{a:04x}")),
            }))
        }
        0x0012 if data.len() >= 2 => {
            let al = u16::from_le_bytes([data[0], data[1]]);
            emit_reg_ws(ws, sub_idx, "alias", json!(format!("0x{al:04x}")));
            Some(json!({
                "register": "Configured Station Alias",
                "alias": format!("0x{al:04x}"),
            }))
        }
        0x0110 if data.len() >= 2 => {
            let dl = u16::from_le_bytes([data[0], data[1]]);
            emit_reg_ws(ws, sub_idx, "dl_status", json!(format!("0x{dl:04x}")));
            Some(json!({
                "register": "DL Status",
                "raw": format!("0x{dl:04x}"),
                "pdi_operational": (dl & 0x0001) != 0,
                "pdi_watchdog_ok": (dl & 0x0002) != 0,
                "extended_link_detection": (dl & 0x0004) != 0,
                "port0_link": (dl & 0x0010) != 0,
                "port1_link": (dl & 0x0020) != 0,
                "port2_link": (dl & 0x0040) != 0,
                "port3_link": (dl & 0x0080) != 0,
                "port0_signal": (dl & 0x0200) != 0,
                "port1_signal": (dl & 0x0800) != 0,
                "port2_signal": (dl & 0x2000) != 0,
                "port3_signal": (dl & 0x8000) != 0,
            }))
        }
        0x0120 | 0x0130 if data.len() >= 2 => {
            let st = u16::from_le_bytes([data[0], data[1]]);
            let state_name = al_state_name(st);
            let status_code = if ado == 0x0130 && data.len() >= 6 {
                Some(u16::from_le_bytes([data[4], data[5]]))
            } else {
                None
            };
            let raw_hex = format!("0x{st:04x}");
            emit_reg_ws(ws, sub_idx, "al_state", json!(state_name.clone()));
            if ado == 0x0120 {
                emit_reg_ws(ws, sub_idx, "al_control", json!(raw_hex.clone()));
            } else {
                emit_reg_ws(ws, sub_idx, "al_status", json!(raw_hex.clone()));
            }
            if let Some(sc) = status_code {
                emit_reg_ws(ws, sub_idx, "al_status_code", json!(format!("0x{sc:04x}")));
            }
            Some(json!({
                "register": if ado == 0x0120 { "AL Control" } else { "AL Status" },
                "raw": raw_hex,
                "state": st & 0x0F,
                "state_name": state_name,
                "error_or_ack_flag": (st & 0x0010) != 0,
                "id_request": (st & 0x0020) != 0,
                "al_status_code": status_code.map(|c| format!("0x{c:04x}")),
                "al_status_description": status_code.map(al_status_code_description),
            }))
        }
        0x0134 if data.len() >= 2 => {
            let sc = u16::from_le_bytes([data[0], data[1]]);
            emit_reg_ws(ws, sub_idx, "al_status_code", json!(format!("0x{sc:04x}")));
            Some(json!({
                "register": "AL Status Code",
                "code": format!("0x{sc:04x}"),
                "description": al_status_code_description(sc),
            }))
        }
        0x0300..=0x0313 => {
            let mut m = serde_json::Map::new();
            m.insert("register".into(), json!("ESC Error Counters"));
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0300 + p * 2) {
                    let k = format!("rx_err_frame_port{p}");
                    emit_reg_ws(ws, sub_idx, &k, json!(v));
                    m.insert(k, json!(v));
                }
                if let Some(v) = byte_at(0x0301 + p * 2) {
                    let k = format!("rx_err_phys_port{p}");
                    emit_reg_ws(ws, sub_idx, &k, json!(v));
                    m.insert(k, json!(v));
                }
            }
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0308 + p) {
                    let k = format!("fwd_rx_err_port{p}");
                    emit_reg_ws(ws, sub_idx, &k, json!(v));
                    m.insert(k, json!(v));
                }
            }
            if let Some(v) = byte_at(0x030C) {
                emit_reg_ws(ws, sub_idx, "epu_err_count", json!(v));
                m.insert("epu_err_count".into(), json!(v));
            }
            if let Some(v) = byte_at(0x030D) {
                emit_reg_ws(ws, sub_idx, "pdi_err_count", json!(v));
                m.insert("pdi_err_count".into(), json!(v));
            }
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0310 + p) {
                    let k = format!("lost_link_port{p}");
                    emit_reg_ws(ws, sub_idx, &k, json!(v));
                    m.insert(k, json!(v));
                }
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0400..=0x0443 => {
            let mut m = serde_json::Map::new();
            m.insert("register".into(), json!("Watchdog"));
            if let Some(div) = u16_at(0x0400) {
                emit_reg_ws(ws, sub_idx, "wd_divider", json!(div));
                m.insert("wd_divider".into(), json!(div));
            }
            if let Some(t_pdi) = u16_at(0x0410) {
                emit_reg_ws(ws, sub_idx, "wd_time_pdi", json!(t_pdi));
                m.insert("wd_time_pdi".into(), json!(t_pdi));
            }
            if let Some(t_pd) = u16_at(0x0420) {
                emit_reg_ws(ws, sub_idx, "wd_time_pdata", json!(t_pd));
                m.insert("wd_time_pdata".into(), json!(t_pd));
            }
            if let Some(st16) = u16_at(0x0440) {
                let s = format!("0x{st16:04x}");
                let ok = (st16 & 0x0001) != 0;
                emit_reg_ws(ws, sub_idx, "wd_status", json!(s.clone()));
                emit_reg_ws(ws, sub_idx, "wd_pdata_ok", json!(ok));
                m.insert("wd_status".into(), json!(s));
                m.insert("wd_pdata_ok".into(), json!(ok));
            } else if let Some(st8) = byte_at(0x0440) {
                let s = format!("0x{st8:02x}");
                let ok = (st8 & 0x01) != 0;
                emit_reg_ws(ws, sub_idx, "wd_status", json!(s.clone()));
                emit_reg_ws(ws, sub_idx, "wd_pdata_ok", json!(ok));
                m.insert("wd_status".into(), json!(s));
                m.insert("wd_pdata_ok".into(), json!(ok));
            }
            if let Some(c_pd) = byte_at(0x0442) {
                emit_reg_ws(ws, sub_idx, "wd_cnt_pdata", json!(c_pd));
                m.insert("wd_cnt_pdata".into(), json!(c_pd));
            }
            if let Some(c_pdi) = byte_at(0x0443) {
                emit_reg_ws(ws, sub_idx, "wd_cnt_pdi", json!(c_pdi));
                m.insert("wd_cnt_pdi".into(), json!(c_pdi));
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0500 => {
            let cfg = data[0];
            let pdi = data.get(1).copied();
            Some(json!({
                "register": "SII EEPROM Configuration",
                "assigned_to_pdi": (cfg & 0x01) != 0,
                "force_release_pdi": (cfg & 0x02) != 0,
                "pdi_has_access": pdi.map(|p| (p & 0x01) != 0),
            }))
        }
        0x0502 if data.len() >= 2 => {
            let ctl = u16::from_le_bytes([data[0], data[1]]);
            let word_addr = if data.len() >= 6 {
                Some(u32::from_le_bytes([data[2], data[3], data[4], data[5]]))
            } else if data.len() >= 4 {
                Some(u16::from_le_bytes([data[2], data[3]]) as u32)
            } else {
                None
            };
            let cmd_bits = (ctl >> 8) & 0x07;
            let op = match cmd_bits {
                0 => "NOP",
                1 => "READ",
                2 => "WRITE",
                4 => "RELOAD",
                _ => "OTHER",
            };
            emit_reg_ws(ws, sub_idx, "eep_busy", json!((ctl & 0x8000) != 0));
            emit_reg_ws(ws, sub_idx, "eep_op", json!(op));
            if let Some(wa) = word_addr {
                emit_reg_ws(ws, sub_idx, "eep_word_addr", json!(wa));
            }
            Some(json!({
                "register": "SII EEPROM Control/Status",
                "raw": format!("0x{ctl:04x}"),
                "write_enable": (ctl & 0x0001) != 0,
                "read_8bytes_supported": (ctl & 0x0040) != 0,
                "command": op,
                "checksum_error": (ctl & 0x0800) != 0,
                "device_info_loaded": (ctl & 0x1000) == 0,
                "ack_error_nack": (ctl & 0x2000) != 0,
                "write_error": (ctl & 0x4000) != 0,
                "busy": (ctl & 0x8000) != 0,
                "word_address": word_addr,
            }))
        }
        0x0508 => Some(json!({
            "register": "SII EEPROM Data",
            "bytes": data.len(),
            "hex": format_hex(data),
        })),
        0x0600..=0x06FF if (ado & 0x0F) == 0 && data.len() >= 16 => {
            let mut decoded_fmmus = Vec::new();
            let base_idx = ((ado - 0x0600) / 16) as usize;
            for (k, chunk) in data.as_chunks::<16>().0.iter().enumerate() {
                let fmmu_idx = base_idx + k;
                if fmmu_idx >= 16 {
                    break;
                }
                let log_start = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                let log_len = u16::from_le_bytes([chunk[4], chunk[5]]);
                let log_start_bit = chunk[6];
                let log_end_bit = chunk[7];
                let phys_start = u16::from_le_bytes([chunk[8], chunk[9]]);
                let phys_start_bit = chunk[10];
                let fmmu_type = chunk[11];
                let rd_en = (fmmu_type & 0x01) != 0;
                let wr_en = (fmmu_type & 0x02) != 0;
                let active = (chunk[12] & 0x01) != 0;

                let log_hex = format!("0x{log_start:08x}");
                let phys_hex = format!("0x{phys_start:04x}");
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("fmmu{fmmu_idx}.log_start"),
                    json!(log_hex.clone()),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("fmmu{fmmu_idx}.length"),
                    json!(log_len),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("fmmu{fmmu_idx}.phys_start"),
                    json!(phys_hex.clone()),
                );
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.read"), json!(rd_en));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.write"), json!(wr_en));
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("fmmu{fmmu_idx}.active"),
                    json!(active),
                );

                decoded_fmmus.push(json!({
                    "register": format!("FMMU {fmmu_idx}"),
                    "logical_start": log_hex,
                    "logical_length": log_len,
                    "logical_start_bit": log_start_bit,
                    "logical_end_bit": log_end_bit,
                    "physical_start": phys_hex,
                    "physical_start_bit": phys_start_bit,
                    "read_enable": rd_en,
                    "write_enable": wr_en,
                    "active": active,
                }));
            }
            if decoded_fmmus.len() == 1 {
                decoded_fmmus.into_iter().next()
            } else {
                Some(json!({
                    "register": "FMMU Table",
                    "entries": decoded_fmmus,
                }))
            }
        }
        0x0800..=0x087F => {
            if (ado & 0x07) == 0 && data.len() >= 8 {
                let mut decoded_sms = Vec::new();
                let base_idx = ((ado - 0x0800) / 8) as usize;
                for (k, chunk) in data.as_chunks::<8>().0.iter().enumerate() {
                    let sm_idx = base_idx + k;
                    if sm_idx >= 16 {
                        break;
                    }
                    let phys_start = u16::from_le_bytes([chunk[0], chunk[1]]);
                    let length = u16::from_le_bytes([chunk[2], chunk[3]]);
                    let ctrl = chunk[4];
                    let stat = chunk[5];
                    let activate = chunk[6];
                    let pdi_ctrl = chunk[7];
                    let mbx_full = (stat & 0x08) != 0;
                    let enabled = (activate & 0x01) != 0;
                    let phys_hex = format!("0x{phys_start:04x}");

                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("sm{sm_idx}.phys_start"),
                        json!(phys_hex.clone()),
                    );
                    emit_reg_ws(ws, sub_idx, &format!("sm{sm_idx}.length"), json!(length));
                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("sm{sm_idx}.ctrl"),
                        json!(format!("0x{ctrl:02x}")),
                    );
                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("sm{sm_idx}.status"),
                        json!(format!("0x{stat:02x}")),
                    );
                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("sm{sm_idx}.mbx_full"),
                        json!(mbx_full),
                    );
                    emit_reg_ws(ws, sub_idx, &format!("sm{sm_idx}.enabled"), json!(enabled));

                    decoded_sms.push(json!({
                        "register": format!("SyncManager {sm_idx}"),
                        "physical_start": phys_hex,
                        "length": length,
                        "buffer_mode": if (ctrl & 0x03) == 0x02 { "Mailbox (1-buffer)" } else { "3-Buffer (Process Data)" },
                        "direction": if ((ctrl >> 2) & 0x03) == 0x01 { "Write (Master->Slave)" } else { "Read (Slave->Master)" },
                        "mailbox_full": mbx_full,
                        "enabled": enabled,
                        "repeat_req": (activate & 0x02) != 0,
                        "pdi_control": format!("0x{pdi_ctrl:02x}"),
                    }));
                }
                if decoded_sms.len() == 1 {
                    decoded_sms.into_iter().next()
                } else {
                    Some(json!({
                        "register": "SyncManager Table",
                        "entries": decoded_sms,
                    }))
                }
            } else if (ado & 0x07) == 5 {
                let sm_idx = (ado - 0x0800) / 8;
                let stat = data[0];
                let mbx_full = (stat & 0x08) != 0;
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("sm{sm_idx}.status"),
                    json!(format!("0x{stat:02x}")),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("sm{sm_idx}.mbx_full"),
                    json!(mbx_full),
                );
                Some(json!({
                    "register": format!("SyncManager {sm_idx} Status"),
                    "status": format!("0x{stat:02x}"),
                    "mailbox_full": mbx_full,
                    "write_event": (stat & 0x01) != 0,
                    "read_event": (stat & 0x02) != 0,
                }))
            } else {
                None
            }
        }
        0x0900..=0x09AF => {
            let mut m = serde_json::Map::new();
            m.insert("register".into(), json!("Distributed Clocks"));
            for p in 0..4u16 {
                if let Some(rx_t) = u32_at(0x0900 + p * 4) {
                    let k = format!("dc_rx_time_port{p}");
                    emit_reg_ws(ws, sub_idx, &k, json!(rx_t));
                    m.insert(k, json!(rx_t));
                }
            }
            if let Some(sys64) = u64_at(0x0910) {
                emit_reg_ws(ws, sub_idx, "dc_systime", json!(sys64));
                m.insert("dc_systime_ns".into(), json!(sys64));
            } else if let Some(sys32) = u32_at(0x0910) {
                emit_reg_ws(ws, sub_idx, "dc_systime", json!(sys32));
                m.insert("dc_systime_ns".into(), json!(sys32));
            }
            if let Some(sof) = u64_at(0x0918) {
                emit_reg_ws(ws, sub_idx, "dc_sof", json!(sof));
                m.insert("dc_receive_time_ecat_ns".into(), json!(sof));
            }
            if let Some(off_ns) = u64_at(0x0920) {
                emit_reg_ws(ws, sub_idx, "dc_sys_offset", json!(off_ns));
                m.insert("dc_sys_offset_ns".into(), json!(off_ns));
            }
            if let Some(delay_ns) = u32_at(0x0928) {
                emit_reg_ws(ws, sub_idx, "dc_sys_delay", json!(delay_ns));
                m.insert("dc_sys_delay_ns".into(), json!(delay_ns));
            }
            if let Some(raw_diff) = u32_at(0x092C) {
                // ETG.1000.4 Table 61: bit 31 is sign (1 = negative, 0 = positive), bits 30:0 magnitude in ns
                let mag = (raw_diff & 0x7FFF_FFFF) as i64;
                let signed_diff = if (raw_diff & 0x8000_0000) != 0 {
                    -mag
                } else {
                    mag
                };
                emit_reg_ws(ws, sub_idx, "dc_sys_diff_ns", json!(signed_diff));
                m.insert("dc_sys_diff_ns".into(), json!(signed_diff));
            }
            if let Some(sp_start) = u16_at(0x0930) {
                m.insert("dc_speed_counter_start".into(), json!(sp_start));
            }
            if let Some(sp_diff) = u16_at(0x0932) {
                m.insert("dc_speed_counter_diff".into(), json!(sp_diff as i16));
            }
            if let Some(act_word) = u16_at(0x0980) {
                let act = (act_word >> 8) as u8;
                let s = format!("0x{act:02x}");
                emit_reg_ws(ws, sub_idx, "dc_sync_act", json!(s.clone()));
                m.insert("dc_sync_activation".into(), json!(s));
                m.insert("dc_cyclic_unit_active".into(), json!((act & 0x01) != 0));
                m.insert("dc_sync0_enabled".into(), json!((act & 0x02) != 0));
                m.insert("dc_sync1_enabled".into(), json!((act & 0x04) != 0));
            } else if let Some(act) = byte_at(0x0981) {
                let s = format!("0x{act:02x}");
                emit_reg_ws(ws, sub_idx, "dc_sync_act", json!(s.clone()));
                m.insert("dc_sync_activation".into(), json!(s));
                m.insert("dc_cyclic_unit_active".into(), json!((act & 0x01) != 0));
                m.insert("dc_sync0_enabled".into(), json!((act & 0x02) != 0));
                m.insert("dc_sync1_enabled".into(), json!((act & 0x04) != 0));
            }
            if let Some(st0_64) = u64_at(0x0990) {
                emit_reg_ws(ws, sub_idx, "dc_start0", json!(st0_64));
                m.insert("dc_sync0_start_time_ns".into(), json!(st0_64));
            } else if let Some(st0_32) = u32_at(0x0990) {
                emit_reg_ws(ws, sub_idx, "dc_start0", json!(st0_32));
                m.insert("dc_sync0_start_time_ns".into(), json!(st0_32));
            }
            if let Some(cyc0) = u32_at(0x09A0) {
                emit_reg_ws(ws, sub_idx, "dc_cycle0", json!(cyc0));
                m.insert("dc_sync0_cycle_ns".into(), json!(cyc0));
            }
            if let Some(cyc1) = u32_at(0x09A4) {
                emit_reg_ws(ws, sub_idx, "dc_cycle1", json!(cyc1));
                m.insert("dc_sync1_cycle_ns".into(), json!(cyc1));
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        _ => None,
    }
}

fn dissect_nv(body: &[u8], ws: &mut BTreeMap<String, Value>) -> Value {
    if body.len() < 6 {
        return json!({ "truncated": true, "raw_hex": format_hex(body) });
    }
    let publisher_id = u16::from_le_bytes([body[0], body[1]]);
    let nv_count = body[2];
    let cycle_nu = body[3];
    let quality = u16::from_le_bytes([body[4], body[5]]);
    ws.insert("nv.publisher_id".into(), json!(publisher_id));
    ws.insert("nv.count".into(), json!(nv_count));
    let mut vars = Vec::new();
    let mut pos = 6usize;
    for _ in 0..nv_count {
        if pos + 6 > body.len() {
            break;
        }
        let id = u16::from_le_bytes([body[pos], body[pos + 1]]);
        let hash = u16::from_le_bytes([body[pos + 2], body[pos + 3]]);
        let vlen = u16::from_le_bytes([body[pos + 4], body[pos + 5]]) as usize;
        pos += 6;
        if pos + vlen > body.len() {
            break;
        }
        vars.push(json!({
            "id": id,
            "hash": format!("0x{hash:04x}"),
            "length": vlen,
            "data_hex": format_hex(&body[pos..pos + vlen]),
        }));
        pos += vlen;
    }
    json!({
        "publisher_id": publisher_id,
        "count": nv_count,
        "cycle_number": cycle_nu,
        "quality": quality,
        "variables": vars,
    })
}
