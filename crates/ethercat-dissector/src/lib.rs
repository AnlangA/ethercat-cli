//! Standalone EtherCAT & Beckhoff TwinCAT protocol dissector (`ethercat-dissector`).
//!
//! Implements 100% of the official Wireshark 4.6 EtherCAT plugin protocol suite:
//! - `esl`: Beckhoff ET2000 EtherCAT Switch Link 16-byte hardware timestamp/port prefix & trailer
//! - `ecatf`: EtherCAT 2-byte Frame Header (`0x88A4`, VLAN/QinQ, IPv4/IPv6 UDP & TCP port `34980`) for types `1..5`
//! - `ecat`: Chained DLPDU subframes (`ecat[i].*`, `ecat.sub1..10.*`), ESC registers (`0x0000..0x09FF`),
//!   FMMU (`ecat.fmmu.*`), SyncManager (`ecat.syncman.*`), and DC propagation delays (`ecat.dc.dif.*`)
//! - `ecat_mailbox`: CoE (Emergency, SDO Expedited/Normal/Segmented/Abort, Complete Access, SDO Info OD,
//!   CoE PDO), EoE (IPv4/MAC params, `macfilter.*`, inner Ethernet fragments, timestamps),
//!   FoE (RRQ/WRQ/DATA/ACK/ERR/BUSY + Beckhoff `.efw` firmware blocks), SoE, AoE, VoE, ERR
//! - `ams`: Beckhoff AMS/ADS over EtherCAT (`ecatf.type == 2`), AoE (`mbx_type == 1`),
//!   `AMS/TCP` (port `48898`), and `AMS/UDP` (port `48899`), including CoE-over-AoE (`0xF302`)
//! - `tc_nv`: TwinCAT Network Variables (`ecatf.type == 4`)
//! - `ioraw`: TwinCAT RAW-IO (`ecatf.type == 3`)
//!
//! Plus XML-driven CoE Object Dictionary SDO decoding and **stateful temporal PDO dissection**
//! (`DissectSession`) from ETG.2000 ESI (`<EtherCATInfo>`), Offline OD (`<EtherCATDict>`), or
//! ETG.2100 ENI (`<EtherCATConfig>`) files.

pub mod catalog;
pub mod engine;
pub mod layers;
pub mod model;
pub mod xml;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use ethercat_wire::error::{CliError, Result};
use ethercat_wire::pdo_codec::decode_pdo_payload;
use ethercat_wire::protocol::constants::{
    lookup_esc_register_by_addr, EcatCmd, ECAT_DATAGRAM_HEADER_LEN, ECAT_FRAME_HEADER_LEN,
    ECAT_WKC_LEN,
};
use ethercat_wire::protocol::pcap_io::{
    for_each_frame_in_file, CapturedPacketRecord, FrameInputKind,
};
use ethercat_wire::types::format_hex;
use serde_json::json;

pub use catalog::{
    ecatf_type_name, WiresharkFieldMeta, WIRESHARK_FIELD_CATALOG, WIRESHARK_PROTOCOLS,
};
pub use engine::session::DissectSession;
pub use layers::ams::{
    dissect_ams_pdu, dissect_ams_pdu_indexed, dissect_ams_tcp, dissect_ams_tcp_multi,
    ADSIGRP_CANOPEN_SDO,
};
pub use layers::encap::{
    may_contain_ethercat, PayloadProtocol, TCP_PORT_AMS, TCP_PORT_ECAT, UDP_PORT_AMS,
};
pub use layers::esc_reg::{compute_dc_propagation_diffs, decode_esc_register_payload};
pub use layers::esl::{dissect_esl_tag, ESL_HEADER_LEN, ESL_SIGNATURE};
pub use layers::mailbox::{
    dissect_eoe_inner_frame, dissect_mailbox, dissect_mailbox_ext, looks_like_mailbox,
    mbx_error_detail_description, sdo_block_crc16, sdo_info_entry_name_offset,
};
pub use layers::nv_ioraw::{dissect_ioraw, dissect_tc_nv};
pub use layers::ws_registers::{
    is_official_register_field, ws_covered_registers, ws_register_cmd, ws_register_read_cmd,
};
pub use model::{
    DissectOptions, DissectedDatagram, DissectedEsl, DissectedEthernet, DissectedFrame,
    DissectedMailbox, EoeFragmentInfo, SdoEventKind, SdoXmlDecode,
};
pub use xml::{
    OdObject, OdSubEntry, PdoDirection, XmlCatalog, XmlDeviceProfile, XmlPdoDef, XmlPdoEntry,
};

pub use ethercat_wire::protocol::constants::{
    ECAT_FRAME_TYPE_DLPDU, ECAT_FRAME_TYPE_MAILBOX, ECAT_FRAME_TYPE_NV,
};
/// EtherCAT Frame Type `0x02`: Direct Beckhoff AMS/ADS frame.
pub const ECAT_FRAME_TYPE_ADS: u8 = 0x02;
/// EtherCAT Frame Type `0x03`: TwinCAT RAW-IO frame.
pub const ECAT_FRAME_TYPE_RAW_IO: u8 = 0x03;

/// Stateless single-frame EtherCAT / AMS dissector.
///
/// Decodes all Wireshark 4.6 protocol layers and (when `opts.xml_catalog` is provided) enriches
/// single-frame CoE SDO transactions with XML Object Dictionary names, types, units, and enums.
///
/// Note: Because single-frame stateless dissection has no preceding packet history, cyclic PDO
/// frames are NOT decoded from `opts.xml_catalog` here (only an explicit static `opts.pdo_layout`
/// override applies). Use [`DissectSession`] to dissect multi-packet sequences with temporal XML
/// PDO configuration tracking and multi-segment SDO reassembly.
pub fn dissect_frame(raw: &[u8], opts: &DissectOptions) -> Result<DissectedFrame> {
    dissect_frame_stateless_inner(raw, opts, true)
}

/// Streams a capture file (`.pcap`, `.pcapng`, PktMon `.txt`, `.txt`/`.hex`, `.bin`) in time order
/// through a stateful [`DissectSession`], invoking `on_frame(record, dissected_frame)` for each
/// valid EtherCAT / AMS packet. Return `Ok(false)` from `on_frame` to stop early.
pub fn dissect_capture_file<F>(
    path: &Path,
    input_kind: FrameInputKind,
    opts: DissectOptions,
    mut on_frame: F,
) -> Result<FrameInputKind>
where
    F: FnMut(&CapturedPacketRecord, DissectedFrame) -> Result<bool>,
{
    let bare = opts.bare_ecat;
    let mut session = DissectSession::new(opts);
    for_each_frame_in_file(path, input_kind, |rec| {
        if !may_contain_ethercat(&rec.data, bare) {
            return Ok(true);
        }
        match session.dissect_packet(rec.index, &rec.data) {
            Ok(df) => on_frame(&rec, df),
            Err(_) => Ok(true),
        }
    })
}

pub(crate) fn dissect_frame_stateless_inner(
    raw: &[u8],
    opts: &DissectOptions,
    apply_single_frame_xml: bool,
) -> Result<DissectedFrame> {
    let mut ws = BTreeMap::new();
    let (mut esl_info, eth_info, payload_proto, payload_start, payload_end) = if opts.bare_ecat {
        (
            None,
            None,
            PayloadProtocol::EthercatFrame,
            0usize,
            raw.len(),
        )
    } else {
        let enc = layers::encap::parse_l2_encapsulation(raw, &mut ws)?;
        (
            enc.esl_prefix,
            enc.ethernet,
            enc.payload_proto,
            enc.payload_start,
            enc.payload_end,
        )
    };

    let preferred_xml_dev = opts
        .xml_catalog
        .as_ref()
        .and_then(|cat| cat.match_slave(None, None, None, opts.xml_device.as_deref()));

    // Standalone AMS/TCP (port 48898) or AMS/UDP (port 48899) frame
    if matches!(
        payload_proto,
        PayloadProtocol::AmsTcp | PayloadProtocol::AmsUdp
    ) {
        let end = payload_end.min(raw.len());
        let ams_slice = &raw[payload_start.min(end)..end];
        let (mut ams_val, sdo_events, raw_tcp_seg) = if payload_proto == PayloadProtocol::AmsTcp {
            let (v, evs) = dissect_ams_tcp_multi(ams_slice, &mut ws);
            (v, evs, Some(ams_slice.to_vec()))
        } else {
            let (v, ev) = dissect_ams_pdu(ams_slice, &mut ws, None);
            let tp = v
                .get("target_port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0x1001) as u16;
            let evs = ev.into_iter().map(|e| (0usize, tp, e)).collect::<Vec<_>>();
            (v, evs, None)
        };
        let first_sdo_ev = sdo_events.first().map(|(_, _, e)| e.clone());
        if apply_single_frame_xml {
            if let Some(ref cat) = opts.xml_catalog {
                for (pdu_i, _, ev) in &sdo_events {
                    let pfx = if *pdu_i == 0 {
                        "ams".to_string()
                    } else {
                        format!("ams[{pdu_i}]")
                    };
                    if let Some(xd) = engine::sdo::enrich_single_frame_sdo(
                        ev,
                        cat,
                        preferred_xml_dev,
                        &mut ws,
                        &pfx,
                    ) {
                        let xd_val = serde_json::to_value(&xd).unwrap_or(json!(null));
                        if *pdu_i == 0 {
                            if let Some(obj) = ams_val.as_object_mut() {
                                obj.insert("sdo_xml".into(), xd_val.clone());
                            }
                        }
                        if let Some(arr) = ams_val
                            .as_object_mut()
                            .and_then(|o| o.get_mut("pdus"))
                            .and_then(serde_json::Value::as_array_mut)
                        {
                            if let Some(pdu_obj) = arr
                                .get_mut(*pdu_i)
                                .and_then(serde_json::Value::as_object_mut)
                            {
                                pdu_obj.insert("sdo_xml".into(), xd_val);
                            }
                        }
                    }
                }
            }
        }
        let proto_label = if payload_proto == PayloadProtocol::AmsTcp {
            "AMS/TCP"
        } else {
            "AMS/UDP"
        };
        return Ok(DissectedFrame {
            packet_index: None,
            frame_wire_len: raw.len(),
            esl: esl_info,
            ethernet: eth_info,
            ecat_header: json!({
                "length": ams_slice.len(),
                "reserved": 0,
                "type": ECAT_FRAME_TYPE_ADS,
                "type_name": proto_label,
            }),
            datagrams: Vec::new(),
            direct_mailbox: None,
            direct_ams: Some(ams_val),
            direct_ams_sdo_event: first_sdo_ev,
            direct_ams_sdo_events: sdo_events,
            raw_ams_tcp_segment: raw_tcp_seg,
            raw_io: None,
            network_variables: None,
            padding_bytes: raw.len().saturating_sub(end),
            wireshark_fields: ws,
        });
    }

    let bounded_raw = &raw[..payload_end.min(raw.len())];
    if bounded_raw.len() < payload_start + ECAT_FRAME_HEADER_LEN {
        return Err(CliError::Format(
            "frame truncated before 2-byte EtherCAT header".into(),
        ));
    }

    let hdr_word = u16::from_le_bytes([bounded_raw[payload_start], bounded_raw[payload_start + 1]]);
    let ecat_len = (hdr_word & 0x07FF) as usize;
    let ecat_res = ((hdr_word >> 11) & 0x01) as u8;
    let ecat_type = ((hdr_word >> 12) & 0x0F) as u8;
    let ecat_type_str = ecatf_type_name(ecat_type);

    ws.insert("ecatf.length".into(), json!(ecat_len));
    ws.insert("ecatf.reserved".into(), json!(ecat_res));
    ws.insert("ecatf.type".into(), json!(ecat_type));
    ws.insert("ecatf.type_name".into(), json!(ecat_type_str));

    let body_start = payload_start + ECAT_FRAME_HEADER_LEN;
    if body_start + ecat_len > bounded_raw.len() {
        return Err(CliError::Format(format!(
            "EtherCAT frame header length ({ecat_len}) exceeds remaining bytes ({})",
            bounded_raw.len() - body_start
        )));
    }
    let body = &bounded_raw[body_start..body_start + ecat_len];
    let body_end = body_start + ecat_len;
    let mut pad_end = bounded_raw.len();

    // Detect Beckhoff ET2000 16-byte ESL trailer (postfix mode, with or without 4-byte trailing FCS)
    let raw_tail_len = raw.len().saturating_sub(body_end);
    if !opts.bare_ecat && esl_info.is_none() && raw_tail_len >= ESL_HEADER_LEN {
        let trailer_ends: &[usize] = if raw_tail_len >= ESL_HEADER_LEN + 4 {
            &[raw.len(), raw.len() - 4]
        } else {
            &[raw.len()]
        };
        for &end in trailer_ends {
            let start = end - ESL_HEADER_LEN;
            if start >= body_end && raw[start..start + 6] == ESL_SIGNATURE {
                esl_info = Some(dissect_esl_tag(&raw[start..end], "trailer", &mut ws));
                pad_end = start.min(bounded_raw.len());
                break;
            }
        }
    }

    let padding_bytes = pad_end.saturating_sub(body_end);
    if padding_bytes > 0 {
        ws.insert(
            "ecat.subframe.pad_bytes".into(),
            json!(format_hex(&bounded_raw[body_end..pad_end])),
        );
    }

    let mut datagrams = Vec::new();
    let mut direct_mailbox = None;
    let mut direct_ams = None;
    let mut direct_ams_sdo_event = None;
    let mut direct_ams_sdo_events = Vec::new();
    let mut raw_io = None;
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
                let sub_raw_hex = format_hex(&body[pos..data_end + ECAT_WKC_LEN]);
                let data_hex = format_hex(data);
                let irq_hex = format!("0x{irq:04x}");

                let mnemonic = cmd_enum
                    .map(|c| c.mnemonic().to_string())
                    .unwrap_or_else(|| format!("CMD_0x{cmd_byte:02X}"));
                let cmd_desc = cmd_enum
                    .map(|c| c.description().to_string())
                    .unwrap_or_else(|| "Unknown/Reserved Command".to_string());

                let is_logical = cmd_enum.is_some_and(|c| c.is_logical());
                let is_auto_inc = cmd_enum.is_some_and(|c| c.is_auto_increment());

                let pfx = format!("ecat[{sub_idx}]");
                ws.insert(format!("{pfx}.sub"), json!(sub_raw_hex.clone()));
                ws.insert(format!("{pfx}.cmd"), json!(mnemonic.clone()));
                ws.insert(format!("{pfx}.cmd_code"), json!(cmd_byte));
                ws.insert(format!("{pfx}.idx"), json!(idx));
                ws.insert(format!("{pfx}.len"), json!(dlen));
                ws.insert(format!("{pfx}.subframe.length"), json!(dlen));
                ws.insert(format!("{pfx}.r"), json!(reserved));
                ws.insert(format!("{pfx}.res"), json!(reserved));
                ws.insert(format!("{pfx}.subframe.reserved"), json!(reserved));
                ws.insert(format!("{pfx}.c"), json!(circulating));
                ws.insert(format!("{pfx}.circulating"), json!(circulating));
                ws.insert(format!("{pfx}.subframe.circulating"), json!(circulating));
                ws.insert(format!("{pfx}.m"), json!(more));
                ws.insert(format!("{pfx}.next"), json!(more));
                ws.insert(format!("{pfx}.subframe.more"), json!(more));
                ws.insert(format!("{pfx}.irq"), json!(irq_hex.clone()));
                ws.insert(format!("{pfx}.int"), json!(irq_hex.clone()));
                ws.insert(format!("{pfx}.data"), json!(data_hex.clone()));
                ws.insert(format!("{pfx}.wkc"), json!(wkc));
                ws.insert(format!("{pfx}.cnt"), json!(wkc));

                // Official Wireshark 4.6 1-based `ecat.sub1..ecat.sub10.*` fields
                if sub_idx < 10 {
                    let s1 = sub_idx + 1;
                    ws.insert(format!("ecat.sub{s1}.cmd"), json!(mnemonic.clone()));
                    ws.insert(format!("ecat.sub{s1}.cmd_code"), json!(cmd_byte));
                    ws.insert(format!("ecat.sub{s1}.idx"), json!(idx));
                    ws.insert(format!("ecat.sub{s1}.len"), json!(dlen));
                    ws.insert(format!("ecat.sub{s1}.cnt"), json!(wkc));
                    ws.insert(format!("ecat.sub{s1}.wkc"), json!(wkc));
                }

                if sub_idx == 0 {
                    ws.insert("ecat.sub".into(), json!(sub_raw_hex));
                    ws.insert("ecat.cmd".into(), json!(mnemonic.clone()));
                    ws.insert("ecat.cmd_code".into(), json!(cmd_byte));
                    ws.insert("ecat.idx".into(), json!(idx));
                    ws.insert("ecat.len".into(), json!(dlen));
                    ws.insert("ecat.subframe.length".into(), json!(dlen));
                    ws.insert("ecat.r".into(), json!(reserved));
                    ws.insert("ecat.res".into(), json!(reserved));
                    ws.insert("ecat.subframe.reserved".into(), json!(reserved));
                    ws.insert("ecat.c".into(), json!(circulating));
                    ws.insert("ecat.circulating".into(), json!(circulating));
                    ws.insert("ecat.subframe.circulating".into(), json!(circulating));
                    ws.insert("ecat.m".into(), json!(more));
                    ws.insert("ecat.next".into(), json!(more));
                    ws.insert("ecat.subframe.more".into(), json!(more));
                    ws.insert("ecat.irq".into(), json!(irq_hex.clone()));
                    ws.insert("ecat.int".into(), json!(irq_hex.clone()));
                    ws.insert("ecat.wkc".into(), json!(wkc));
                    ws.insert("ecat.cnt".into(), json!(wkc));
                }

                let (adp, adp_hex, auto_inc_hint, ado, ado_hex, ado_reg_name, logical_str) =
                    if is_logical {
                        let lhex = format!("0x{lad:08x}");
                        ws.insert(format!("{pfx}.lad"), json!(lhex.clone()));
                        if sub_idx < 10 {
                            ws.insert(format!("ecat.sub{}.lad", sub_idx + 1), json!(lhex.clone()));
                        }
                        if sub_idx == 0 {
                            ws.insert("ecat.lad".into(), json!(lhex.clone()));
                        }
                        (None, None, None, None, None, None, Some(lhex))
                    } else {
                        let adp_h = format!("0x{word_a:04x}");
                        let ado_h = format!("0x{word_b:04x}");
                        ws.insert(format!("{pfx}.adp"), json!(adp_h.clone()));
                        ws.insert(format!("{pfx}.ado"), json!(ado_h.clone()));
                        if sub_idx < 10 {
                            let s1 = sub_idx + 1;
                            ws.insert(format!("ecat.sub{s1}.adp"), json!(adp_h.clone()));
                            ws.insert(format!("ecat.sub{s1}.ado"), json!(ado_h.clone()));
                        }
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

                // Wireshark 4.6 `dissect_ecat_datagram()` payload semantics:
                //  * DC branch: `(APRD|FPRD) && ado == 0x0900 && raw len field >= 16 && wkc > 0`
                //  * otherwise registers are dissected only when completely covered, and hidden
                //    for `APRD`/`FPRD`/`BRD` with `wkc == 0`
                //  * `ecat.data` / `ecat.subN.data` only when no register is covered, minus the
                //    mailbox span (`min(Length + 6, len)`) when a mailbox is recognized.
                let ws_dc_branch = !is_logical
                    && matches!(cmd_byte, 0x01 | 0x04)
                    && word_b == 0x0900
                    && len_flags >= 16
                    && wkc > 0;
                let covered_regs = if is_logical {
                    Vec::new()
                } else {
                    ws_covered_registers(cmd_byte, word_b, dlen)
                };
                let ws_show_regs = wkc > 0 || !ws_register_read_cmd(cmd_byte);

                // Official names follow Wireshark exactly; the indexed `ecat[i].*` extension namespace
                // keeps the full (also partial-register / WKC=0) decode for diagnostics.
                let dc_diff = if !is_logical && word_b < 0x1000 && !data.is_empty() {
                    let mut dc_ws = BTreeMap::new();
                    let v = compute_dc_propagation_diffs(word_b, data, &mut dc_ws, Some(sub_idx));
                    if !ws_dc_branch {
                        dc_ws.retain(|k, _| k.contains('['));
                    }
                    merge_ws_fields(&mut ws, dc_ws);
                    v
                } else {
                    None
                };

                let register_decode = if !is_logical && word_b < 0x1000 && !data.is_empty() {
                    let mut reg_ws = BTreeMap::new();
                    let decoded =
                        decode_esc_register_payload(word_b, data, &mut reg_ws, Some(sub_idx));
                    let mut allowed = BTreeSet::new();
                    if ws_show_regs {
                        for &(reg, rlen) in &covered_regs {
                            let off = (reg - word_b) as usize;
                            let mut one = BTreeMap::new();
                            decode_esc_register_payload(
                                reg,
                                &data[off..off + rlen as usize],
                                &mut one,
                                Some(sub_idx),
                            );
                            allowed.extend(one.into_keys());
                        }
                    }
                    reg_ws.retain(|k, _| {
                        k.contains('[') || !is_official_register_field(k) || allowed.contains(k)
                    });
                    merge_ws_fields(&mut ws, reg_ws);
                    decoded
                } else {
                    None
                };

                let prefer_pdo = !opts.force_mailbox
                    && opts
                        .pdo_layout
                        .as_ref()
                        .is_some_and(|l| l.total_bytes() == data.len() && data.len() < 32);

                let ws_mbx_span = if is_logical || ws_dc_branch || !covered_regs.is_empty() {
                    None
                } else {
                    ws_mailbox_span(cmd_byte, wkc, word_b, data)
                };
                // Extension beyond Wireshark 4.6: ERR (0x00) / VoE (0x0F) mailboxes are decoded when
                // the same command/WKC gating applies and the payload passes the strict heuristic.
                let ext_mbx = ws_mbx_span.is_none()
                    && !is_logical
                    && covered_regs.is_empty()
                    && ws_mailbox_cmd(cmd_byte, wkc)
                    && data.len() >= 6
                    && !matches!(data[5] & 0x0F, 0x01..=0x05)
                    && looks_like_mailbox(word_b, data);

                // Official `ecat.data` / `ecat.subN.data` with exact Wireshark presence/extent.
                if ws_dc_branch {
                    if sub_idx < 10 {
                        ws.insert(
                            format!("ecat.sub{}.data", sub_idx + 1),
                            json!(data_hex.clone()),
                        );
                    }
                } else if covered_regs.is_empty() {
                    let rest = &data[ws_mbx_span.unwrap_or(0)..];
                    if !rest.is_empty() {
                        let rest_hex = format_hex(rest);
                        ws.entry("ecat.data".to_string())
                            .or_insert_with(|| json!(rest_hex.clone()));
                        if sub_idx < 10 {
                            ws.insert(format!("ecat.sub{}.data", sub_idx + 1), json!(rest_hex));
                        }
                    }
                }

                let mut sdo_xml = None;
                let mailbox = if !is_logical
                    && !prefer_pdo
                    && (opts.force_mailbox || ws_mbx_span.is_some() || ext_mbx)
                {
                    let mut mbx_ws = BTreeMap::new();
                    let mut decoded_mbx = dissect_mailbox(data, &mut mbx_ws, "ecat_mailbox");
                    if let Some(ref mut mbx) = decoded_mbx {
                        for (k, v) in mbx_ws {
                            if let Some(suffix) = k.strip_prefix("ecat_mailbox.") {
                                ws.insert(format!("ecat[{sub_idx}].mailbox.{suffix}"), v.clone());
                                ws.insert(format!("ecat_mailbox[{sub_idx}].{suffix}"), v.clone());
                                ws.entry(k).or_insert(v);
                            } else {
                                ws.insert(format!("ecat[{sub_idx}].{k}"), v.clone());
                                ws.entry(k).or_insert(v);
                            }
                        }
                        if apply_single_frame_xml {
                            if let (Some(ref ev), Some(ref cat)) =
                                (&mbx.sdo_event, &opts.xml_catalog)
                            {
                                let mbx_pfx = format!("ecat_mailbox[{sub_idx}]");
                                if let Some(xd) = engine::sdo::enrich_single_frame_sdo(
                                    ev,
                                    cat,
                                    preferred_xml_dev,
                                    &mut ws,
                                    &mbx_pfx,
                                ) {
                                    if let Some(obj) = mbx.protocol.as_object_mut() {
                                        obj.insert(
                                            "sdo_xml".into(),
                                            serde_json::to_value(&xd).unwrap_or(json!(null)),
                                        );
                                    }
                                    sdo_xml = Some(xd);
                                }
                            }
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
                    resolved_slave: None,
                    ado,
                    ado_hex,
                    ado_register: ado_reg_name,
                    logical_addr: logical_str,
                    length: dlen as u16,
                    reserved,
                    circulating,
                    more,
                    irq: irq_hex,
                    irq_events: decode_irq_bits(irq),
                    data_hex,
                    raw_data: data.to_vec(),
                    wkc,
                    dc_diff,
                    register_decode,
                    mailbox,
                    sdo_xml,
                    pdo_fields,
                });

                pos = data_end + ECAT_WKC_LEN;
                sub_idx += 1;
                if !more {
                    break;
                }
            }
            ws.insert("ecat.subframe_count".into(), json!(datagrams.len()));
        }
        ECAT_FRAME_TYPE_ADS => {
            let (mut ams_v, sdo_ev) = dissect_ams_pdu(body, &mut ws, None);
            let tp = ams_v
                .get("target_port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0x1001) as u16;
            if apply_single_frame_xml {
                if let (Some(ref ev), Some(ref cat)) = (&sdo_ev, &opts.xml_catalog) {
                    if let Some(xd) = engine::sdo::enrich_single_frame_sdo(
                        ev,
                        cat,
                        preferred_xml_dev,
                        &mut ws,
                        "ams",
                    ) {
                        if let Some(obj) = ams_v.as_object_mut() {
                            obj.insert(
                                "sdo_xml".into(),
                                serde_json::to_value(&xd).unwrap_or(json!(null)),
                            );
                        }
                    }
                }
            }
            if let Some(ref ev) = sdo_ev {
                direct_ams_sdo_events.push((0usize, tp, ev.clone()));
            }
            direct_ams = Some(ams_v);
            direct_ams_sdo_event = sdo_ev;
        }
        ECAT_FRAME_TYPE_RAW_IO => {
            raw_io = Some(dissect_ioraw(body, &mut ws));
        }
        ECAT_FRAME_TYPE_NV => {
            network_variables = Some(dissect_tc_nv(body, &mut ws));
        }
        ECAT_FRAME_TYPE_MAILBOX => {
            let mut mbx_opt = dissect_mailbox(body, &mut ws, "ecat_mailbox");
            if apply_single_frame_xml {
                if let (Some(ref mut mbx), Some(ref cat)) = (&mut mbx_opt, &opts.xml_catalog) {
                    if let Some(ref ev) = mbx.sdo_event {
                        if let Some(xd) = engine::sdo::enrich_single_frame_sdo(
                            ev,
                            cat,
                            preferred_xml_dev,
                            &mut ws,
                            "ecat_mailbox",
                        ) {
                            if let Some(obj) = mbx.protocol.as_object_mut() {
                                obj.insert(
                                    "sdo_xml".into(),
                                    serde_json::to_value(&xd).unwrap_or(json!(null)),
                                );
                            }
                        }
                    }
                }
            }
            direct_mailbox = mbx_opt;
        }
        _ => {}
    }

    Ok(DissectedFrame {
        packet_index: None,
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
        direct_ams,
        direct_ams_sdo_event,
        direct_ams_sdo_events,
        raw_ams_tcp_segment: None,
        raw_io,
        network_variables,
        padding_bytes,
        wireshark_fields: ws,
    })
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
    if (irq & 0x0100) != 0 {
        out.push("SM0_IRQ");
    }
    if (irq & 0x0200) != 0 {
        out.push("SM1_IRQ");
    }
    if (irq & 0x0400) != 0 {
        out.push("SM2_IRQ");
    }
    if (irq & 0x0800) != 0 {
        out.push("SM3_IRQ");
    }
    if (irq & 0x1000) != 0 {
        out.push("SM4_IRQ");
    }
    if (irq & 0x2000) != 0 {
        out.push("SM5_IRQ");
    }
    if (irq & 0x4000) != 0 {
        out.push("SM6_IRQ");
    }
    if (irq & 0x8000) != 0 {
        out.push("SM7_IRQ");
    }
    out
}

/// Wireshark 4.6 mailbox command/WKC gate: `FPWR`/`APWR`/`APRW`/`FPRW` always, `FPRD`/`APRD`
/// only when the working counter is exactly `1`.
fn ws_mailbox_cmd(cmd: u8, wkc: u16) -> bool {
    matches!(cmd, 0x02 | 0x03 | 0x05 | 0x06) || (matches!(cmd, 0x01 | 0x04) && wkc == 1)
}

/// Exact port of Wireshark 4.6 `dissect_ecat_datagram()` mailbox recognition: returns the number of
/// datagram payload bytes handed to `ecat_mailbox` (`min(Length + 6, len)`), or `None`.
fn ws_mailbox_span(cmd: u8, wkc: u16, ado: u16, data: &[u8]) -> Option<usize> {
    if data.len() < 6 || ado < 0x1000 || !ws_mailbox_cmd(cmd, wkc) {
        return None;
    }
    let length = u16::from_le_bytes([data[0], data[1]]) as usize;
    let mbx_type = data[5] & 0x0F;
    if !matches!(mbx_type, 0x01..=0x05) || length > 1500 {
        return None;
    }
    Some((length + 6).min(data.len()))
}

/// Merges per-datagram fields: indexed keys (`ecat[i].*`) overwrite, unindexed official keys keep
/// the first occurrence in the frame (Wireshark's first-match field semantics).
fn merge_ws_fields(
    ws: &mut BTreeMap<String, serde_json::Value>,
    src: BTreeMap<String, serde_json::Value>,
) {
    for (k, v) in src {
        if k.contains('[') || k.starts_with("ecat.sub") {
            ws.insert(k, v);
        } else {
            ws.entry(k).or_insert(v);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dissect_frame, may_contain_ethercat, DissectOptions};
    use ethercat_wire::pdo_codec::{encode_pdo_assignments, PdoLayout};
    use ethercat_wire::protocol::constants::EcatCmd;
    use ethercat_wire::protocol::frame::{EcatFrameBuilder, RawDatagram};

    #[test]
    fn wire_frame_dissector_and_pdo_codec_roundtrip() {
        let layout = PdoLayout::parse_spec("ctrl:u16@0,target:i32@16").unwrap();
        let mut pdo_buf = vec![0u8; layout.total_bytes()];
        encode_pdo_assignments(
            &mut pdo_buf,
            &layout,
            &["ctrl=0x000F".into(), "target=-500".into()],
        )
        .unwrap();

        let mut dg = RawDatagram::new_logical(EcatCmd::Lrw, 0x07, 0x0001_0000, pdo_buf);
        dg.wkc = 3;
        let mut builder = EcatFrameBuilder::new();
        builder.add_datagram(dg);
        let raw = builder.build().unwrap();
        assert!(may_contain_ethercat(&raw, false));

        let df = dissect_frame(
            &raw,
            &DissectOptions {
                pdo_layout: Some(layout),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(df.datagrams.len(), 1);
        assert_eq!(df.datagrams[0].wkc, 3);
        assert_eq!(df.wireshark_fields["ecat.pdo.ctrl"], 15);
        assert_eq!(df.wireshark_fields["ecat.pdo.target"], -500);
    }
}
