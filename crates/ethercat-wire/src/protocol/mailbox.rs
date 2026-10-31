use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use crate::protocol::constants::{
    coe_service_name, ect_datatype_name, mailbox_type_name, sdo_abort_description,
};
use crate::types::{decode_typed_value, format_hex, format_mac, DataTypeSpec};

#[derive(Debug, Clone, Serialize)]
pub struct DissectedMailbox {
    pub length: u16,
    pub address: u16,
    pub channel: u8,
    pub priority: u8,
    pub mbx_type: u8,
    pub mbx_type_name: &'static str,
    pub counter: u8,
    pub protocol: Value,
}

/// Heuristic check whether a physical memory payload looks like a valid EtherCAT Mailbox frame.
pub fn looks_like_mailbox(ado: u16, data: &[u8]) -> bool {
    if ado < 0x1000 || data.len() < 6 {
        return false;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if len == 0 || 6 + len > data.len() {
        return false;
    }
    // Channel (bits 0..5 of byte 4) is normally 0; bit 7 of byte 5 is reserved (0).
    let chan = data[4] & 0x3F;
    if chan != 0 || (data[5] & 0x80) != 0 {
        return false;
    }
    let mtype = data[5] & 0x0F;
    let body = &data[6..6 + len];
    match mtype {
        0x00 => len == 4,
        0x01 => len >= 24, // AoE header = 24 bytes
        0x02 => len >= 4,  // EoE header = 4 bytes
        0x03 => len >= 2 && matches!((body[1] >> 4) & 0x0F, 0x01..=0x08), // CoE header + valid service
        0x04 => len >= 2 && matches!(body[0], 0x01..=0x06),               // FoE opcode 1..=6
        0x05 => len >= 4 && matches!(body[0] & 0x07, 0x01..=0x07),        // SoE opcode 1..=7
        0x0F => len >= 4,                                                 // VoE vendor header
        _ => false,
    }
}

pub fn dissect_mailbox(
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> Option<DissectedMailbox> {
    if data.len() < 6 {
        return None;
    }
    let length = u16::from_le_bytes([data[0], data[1]]);
    let address = u16::from_le_bytes([data[2], data[3]]);
    let channel = data[4] & 0x3F;
    let priority = (data[4] >> 6) & 0x03;
    let mbx_type = data[5] & 0x0F;
    let counter = (data[5] >> 4) & 0x07;
    let mbx_type_str = mailbox_type_name(mbx_type);

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
    ws.insert(format!("{prefix}.cnt"), json!(counter));

    let protocol = match mbx_type {
        0x00 => dissect_mbx_err(body, ws, prefix),
        0x01 => dissect_aoe(body, ws, prefix),
        0x02 => dissect_eoe(body, ws, prefix),
        0x03 => dissect_coe(body, ws, prefix),
        0x04 => dissect_foe(body, ws, prefix),
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
        protocol,
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

fn dissect_mbx_err(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 4 {
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

fn dissect_aoe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    // AoE header is 32 bytes: Target NetId (6) + Port (2) + Source NetId (6) + Port (2)
    // + CmdId (2) + StateFlags (2) + Length (4) + ErrorCode (4) + InvokeId (4)
    if body.len() < 32 {
        return json!({ "kind": "AoE", "truncated": true, "raw_hex": format_hex(body) });
    }
    let fmt_netid = |b: &[u8]| format!("{}.{}.{}.{}.{}.{}", b[0], b[1], b[2], b[3], b[4], b[5]);
    let target_netid = fmt_netid(&body[0..6]);
    let target_port = u16::from_le_bytes([body[6], body[7]]);
    let source_netid = fmt_netid(&body[8..14]);
    let source_port = u16::from_le_bytes([body[14], body[15]]);
    let cmd_id = u16::from_le_bytes([body[16], body[17]]);
    let state_flags = u16::from_le_bytes([body[18], body[19]]);
    let cb_len = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
    let error_code = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
    let invoke_id = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);
    let is_response = (state_flags & 0x0001) != 0;
    let cmd_name = match cmd_id {
        1 => "Read Device Info",
        2 => "Read",
        3 => "Write",
        4 => "Read State",
        5 => "Write Control",
        6 => "Add Device Notification",
        7 => "Delete Device Notification",
        8 => "Device Notification",
        9 => "Read Write",
        _ => "Other",
    };
    ws.insert(
        format!("{prefix}.aoe.target"),
        json!(format!("{target_netid}:{target_port}")),
    );
    ws.insert(
        format!("{prefix}.aoe.source"),
        json!(format!("{source_netid}:{source_port}")),
    );
    ws.insert(format!("{prefix}.aoe.cmd"), json!(cmd_id));
    ws.insert(format!("{prefix}.aoe.err"), json!(error_code));
    ws.insert(format!("{prefix}.aoe.invoke_id"), json!(invoke_id));

    let ads = &body[32..];
    let mut out = serde_json::Map::new();
    out.insert("kind".into(), json!("AoE"));
    out.insert("target_netid".into(), json!(target_netid));
    out.insert("target_port".into(), json!(target_port));
    out.insert("source_netid".into(), json!(source_netid));
    out.insert("source_port".into(), json!(source_port));
    out.insert("cmd_id".into(), json!(cmd_id));
    out.insert("cmd_name".into(), json!(cmd_name));
    out.insert("is_response".into(), json!(is_response));
    out.insert("state_flags".into(), json!(format!("0x{state_flags:04x}")));
    out.insert("length".into(), json!(cb_len));
    out.insert("error_code".into(), json!(error_code));
    out.insert("invoke_id".into(), json!(invoke_id));

    match (cmd_id, is_response) {
        (2, false) if ads.len() >= 12 => {
            let ig = u32::from_le_bytes([ads[0], ads[1], ads[2], ads[3]]);
            let io = u32::from_le_bytes([ads[4], ads[5], ads[6], ads[7]]);
            let rlen = u32::from_le_bytes([ads[8], ads[9], ads[10], ads[11]]);
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            ws.insert(format!("{prefix}.aoe.index_group"), json!(ig_s.clone()));
            ws.insert(format!("{prefix}.aoe.index_offset"), json!(io_s.clone()));
            out.insert("index_group".into(), json!(ig_s));
            out.insert("index_offset".into(), json!(io_s));
            out.insert("read_length".into(), json!(rlen));
        }
        (3, false) if ads.len() >= 12 => {
            let ig = u32::from_le_bytes([ads[0], ads[1], ads[2], ads[3]]);
            let io = u32::from_le_bytes([ads[4], ads[5], ads[6], ads[7]]);
            let wlen = u32::from_le_bytes([ads[8], ads[9], ads[10], ads[11]]);
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            ws.insert(format!("{prefix}.aoe.index_group"), json!(ig_s.clone()));
            ws.insert(format!("{prefix}.aoe.index_offset"), json!(io_s.clone()));
            out.insert("index_group".into(), json!(ig_s));
            out.insert("index_offset".into(), json!(io_s));
            out.insert("write_length".into(), json!(wlen));
            out.insert("payload_hex".into(), json!(format_hex(&ads[12..])));
        }
        (9, false) if ads.len() >= 16 => {
            let ig = u32::from_le_bytes([ads[0], ads[1], ads[2], ads[3]]);
            let io = u32::from_le_bytes([ads[4], ads[5], ads[6], ads[7]]);
            let rlen = u32::from_le_bytes([ads[8], ads[9], ads[10], ads[11]]);
            let wlen = u32::from_le_bytes([ads[12], ads[13], ads[14], ads[15]]);
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            ws.insert(format!("{prefix}.aoe.index_group"), json!(ig_s.clone()));
            ws.insert(format!("{prefix}.aoe.index_offset"), json!(io_s.clone()));
            out.insert("index_group".into(), json!(ig_s));
            out.insert("index_offset".into(), json!(io_s));
            out.insert("read_length".into(), json!(rlen));
            out.insert("write_length".into(), json!(wlen));
            out.insert("payload_hex".into(), json!(format_hex(&ads[16..])));
        }
        (2 | 9, true) if ads.len() >= 8 => {
            let res = u32::from_le_bytes([ads[0], ads[1], ads[2], ads[3]]);
            let dlen = u32::from_le_bytes([ads[4], ads[5], ads[6], ads[7]]);
            ws.insert(format!("{prefix}.aoe.result"), json!(res));
            out.insert("result".into(), json!(res));
            out.insert("data_length".into(), json!(dlen));
            out.insert("payload_hex".into(), json!(format_hex(&ads[8..])));
        }
        (3 | 5 | 7, true) if ads.len() >= 4 => {
            let res = u32::from_le_bytes([ads[0], ads[1], ads[2], ads[3]]);
            ws.insert(format!("{prefix}.aoe.result"), json!(res));
            out.insert("result".into(), json!(res));
        }
        _ => {}
    }

    out.insert("data_hex".into(), json!(format_hex(ads)));
    Value::Object(out)
}

fn format_eoe_le_ipv4(b: &[u8]) -> String {
    // ETG.1000.6 / SOEM ec_eoe.c: EoE IPv4 parameters are UNSIGNED32 LE ([octet4, octet3, octet2, octet1])
    format!("{}.{}.{}.{}", b[3], b[2], b[1], b[0])
}

fn dissect_eoe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 4 {
        return json!({ "kind": "EoE", "truncated": true, "raw_hex": format_hex(body) });
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
    ws.insert(format!("{prefix}.eoe.type"), json!(frame_type));
    ws.insert(format!("{prefix}.eoe.port"), json!(port));
    ws.insert(format!("{prefix}.eoe.frag_no"), json!(frag_no));
    ws.insert(format!("{prefix}.eoe.frame_no"), json!(frame_no));

    let payload = &body[4..];
    let mut out = serde_json::Map::new();
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

    match frame_type {
        // Fragment 0 of an Ethernet-over-EtherCAT frame carries the inner Ethernet II header
        0x00 if frag_no == 0 && payload.len() >= 14 => {
            let mut dst = [0u8; 6];
            let mut src = [0u8; 6];
            dst.copy_from_slice(&payload[0..6]);
            src.copy_from_slice(&payload[6..12]);
            let dst_s = format_mac(&dst);
            let src_s = format_mac(&src);
            let mut etype = u16::from_be_bytes([payload[12], payload[13]]);
            let mut vlan_id = None;
            if etype == 0x8100 && payload.len() >= 18 {
                vlan_id = Some(u16::from_be_bytes([payload[14], payload[15]]) & 0x0FFF);
                etype = u16::from_be_bytes([payload[16], payload[17]]);
            }
            let etype_s = format!("0x{etype:04x}");
            ws.insert(format!("{prefix}.eoe.eth.dst"), json!(dst_s.clone()));
            ws.insert(format!("{prefix}.eoe.eth.src"), json!(src_s.clone()));
            ws.insert(format!("{prefix}.eoe.eth.type"), json!(etype_s.clone()));
            if let Some(vid) = vlan_id {
                ws.insert(format!("{prefix}.eoe.vlan.id"), json!(vid));
            }
            out.insert(
                "inner_ethernet".into(),
                json!({
                    "dst_mac": dst_s,
                    "src_mac": src_s,
                    "vlan_id": vlan_id,
                    "ethertype": etype_s,
                }),
            );
        }
        // Set IP Parameter Request (0x02) / Get IP Parameter Response (0x07)
        0x02 | 0x07 if payload.len() >= 4 => {
            let flags = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let mut off = 4usize;
            let mut ip_params = serde_json::Map::new();
            ip_params.insert("flags".into(), json!(format!("0x{flags:08x}")));
            if (flags & 0x01) != 0 && off + 6 <= payload.len() {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&payload[off..off + 6]);
                let s = format_mac(&mac);
                ws.insert(format!("{prefix}.eoe.mac"), json!(s.clone()));
                ip_params.insert("mac".into(), json!(s));
                off += 6;
            }
            if (flags & 0x02) != 0 && off + 4 <= payload.len() {
                let s = format_eoe_le_ipv4(&payload[off..off + 4]);
                ws.insert(format!("{prefix}.eoe.ip"), json!(s.clone()));
                ip_params.insert("ip".into(), json!(s));
                off += 4;
            }
            if (flags & 0x04) != 0 && off + 4 <= payload.len() {
                let s = format_eoe_le_ipv4(&payload[off..off + 4]);
                ws.insert(format!("{prefix}.eoe.subnet"), json!(s.clone()));
                ip_params.insert("subnet_mask".into(), json!(s));
                off += 4;
            }
            if (flags & 0x08) != 0 && off + 4 <= payload.len() {
                let s = format_eoe_le_ipv4(&payload[off..off + 4]);
                ws.insert(format!("{prefix}.eoe.gateway"), json!(s.clone()));
                ip_params.insert("default_gateway".into(), json!(s));
                off += 4;
            }
            if (flags & 0x10) != 0 && off + 4 <= payload.len() {
                let s = format_eoe_le_ipv4(&payload[off..off + 4]);
                ws.insert(format!("{prefix}.eoe.dns_ip"), json!(s.clone()));
                ip_params.insert("dns_server".into(), json!(s));
                off += 4;
            }
            if (flags & 0x20) != 0 && off < payload.len() {
                let dns_len = (payload.len() - off).min(32);
                let s = String::from_utf8_lossy(&payload[off..off + dns_len])
                    .trim_end_matches('\0')
                    .to_string();
                ws.insert(format!("{prefix}.eoe.dns_name"), json!(s.clone()));
                ip_params.insert("dns_name".into(), json!(s));
            }
            out.insert("ip_parameters".into(), Value::Object(ip_params));
        }
        0x03 | 0x05 | 0x09 => {
            ws.insert(format!("{prefix}.eoe.result"), json!(info2));
            out.insert("result_code".into(), json!(format!("0x{info2:04x}")));
        }
        _ => {}
    }

    out.insert("data_hex".into(), json!(format_hex(payload)));
    Value::Object(out)
}

fn dissect_coe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 2 {
        return json!({ "kind": "CoE", "truncated": true, "raw_hex": format_hex(body) });
    }
    let coe_hdr = u16::from_le_bytes([body[0], body[1]]);
    let number = coe_hdr & 0x01FF;
    let service = ((coe_hdr >> 12) & 0x0F) as u8;
    let service_str = coe_service_name(service);
    ws.insert(format!("{prefix}.coe.number"), json!(number));
    ws.insert(format!("{prefix}.coe.service"), json!(service));
    ws.insert(format!("{prefix}.coe.service_name"), json!(service_str));

    let payload = &body[2..];
    match service {
        // Emergency
        0x01 => {
            if payload.len() < 8 {
                return json!({ "kind": "CoE", "service": service_str, "truncated": true });
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
            json!({
                "kind": "CoE",
                "service": service_str,
                "number": number,
                "error_code": format!("0x{err_code:04x}"),
                "error_register": format!("0x{err_reg:02x}"),
                "manufacturer_data_hex": mfg_data,
            })
        }
        // SDO Request (0x02) & SDO Response (0x03)
        0x02 | 0x03 => dissect_coe_sdo(service, number, payload, ws, prefix),
        // SDO Information (0x08)
        0x08 => dissect_coe_sdo_info(number, payload, ws, prefix),
        // TxPDO / RxPDO over CoE
        _ => json!({
            "kind": "CoE",
            "service": service_str,
            "number": number,
            "pdo_data_hex": format_hex(payload),
        }),
    }
}

fn dissect_coe_sdo(
    service: u8,
    number: u16,
    payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> Value {
    if payload.is_empty() {
        return json!({ "kind": "CoE", "service": coe_service_name(service), "truncated": true });
    }
    let cmd = payload[0];
    let ccs_scs = (cmd >> 5) & 0x07;
    ws.insert(
        format!("{prefix}.coe.sdo.cmd"),
        json!(format!("0x{cmd:02x}")),
    );

    // Abort SDO Transfer (0x80 => top 3 bits == 4)
    if ccs_scs == 4 {
        if payload.len() < 8 {
            return json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": "Abort Transfer",
                "truncated": true,
                "raw_hex": format_hex(payload),
            });
        }
        let index = u16::from_le_bytes([payload[1], payload[2]]);
        let subindex = payload[3];
        let abort_code = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
        let abort_desc = sdo_abort_description(abort_code);
        ws.insert(
            format!("{prefix}.coe.sdo.index"),
            json!(format!("0x{index:04x}")),
        );
        ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
        ws.insert(
            format!("{prefix}.coe.sdo.abort_code"),
            json!(format!("0x{abort_code:08x}")),
        );
        return json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "sdo_op": "Abort Transfer",
            "index": format!("0x{index:04x}"),
            "subindex": subindex,
            "abort_code": format!("0x{abort_code:08x}"),
            "abort_description": abort_desc,
        });
    }

    // Segment frames do NOT carry Index/Subindex at bytes 1..3:
    // - SDO Req: Download Segment Req (ccs=0), Upload Segment Req (ccs=3, Wait: Upload Seg Req DOES carry index/sub in SOEM, or reserved 7 bytes!)
    // - SDO Res: Upload Segment Res (scs=0), Download Segment Res (scs=1)
    let is_seg_data_frame = (service == 0x02 && ccs_scs == 0) || (service == 0x03 && ccs_scs == 0);
    let is_dl_seg_res = service == 0x03 && ccs_scs == 1;
    let is_ul_seg_req = service == 0x02 && ccs_scs == 3;

    if is_seg_data_frame {
        let toggle = (cmd & 0x10) != 0;
        let last_seg = (cmd & 0x01) != 0;
        let unused = ((cmd >> 1) & 0x07) as usize;
        let seg_raw = &payload[1..];
        let valid_len = if last_seg && seg_raw.len() == 7 {
            seg_raw.len().saturating_sub(unused)
        } else {
            seg_raw.len()
        };
        let seg_data = &seg_raw[..valid_len];
        ws.insert(format!("{prefix}.coe.sdo.toggle"), json!(toggle));
        ws.insert(format!("{prefix}.coe.sdo.last_segment"), json!(last_seg));
        ws.insert(
            format!("{prefix}.coe.sdo.data"),
            json!(format_hex(seg_data)),
        );
        return json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "sdo_op": if service == 0x02 { "Download Segment Request" } else { "Upload Segment Response" },
            "toggle": toggle,
            "last_segment": last_seg,
            "data_hex": format_hex(seg_data),
        });
    }

    if is_dl_seg_res || is_ul_seg_req {
        let toggle = (cmd & 0x10) != 0;
        ws.insert(format!("{prefix}.coe.sdo.toggle"), json!(toggle));
        return json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "sdo_op": if is_dl_seg_res { "Download Segment Response" } else { "Upload Segment Request" },
            "toggle": toggle,
        });
    }

    if payload.len() < 4 {
        return json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "truncated": true,
        });
    }
    let index = u16::from_le_bytes([payload[1], payload[2]]);
    let subindex = payload[3];
    let complete_access = (cmd & 0x10) != 0;
    let expedited = (cmd & 0x02) != 0;
    let size_indicated = (cmd & 0x01) != 0;

    ws.insert(
        format!("{prefix}.coe.sdo.index"),
        json!(format!("0x{index:04x}")),
    );
    ws.insert(format!("{prefix}.coe.sdo.subindex"), json!(subindex));
    ws.insert(format!("{prefix}.coe.sdo.ca"), json!(complete_access));
    ws.insert(format!("{prefix}.coe.sdo.expedited"), json!(expedited));

    let op_name = match (service, ccs_scs) {
        (0x02, 1) => "Initiate Download Request",
        (0x02, 2) => "Initiate Upload Request",
        (0x03, 3) => "Initiate Download Response",
        (0x03, 2) => "Initiate Upload Response",
        _ => "SDO Message",
    };

    // Data carrying initiate messages: Download Req (0x02, 1) or Upload Res (0x03, 2)
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
            ws.insert(
                format!("{prefix}.coe.sdo.data"),
                json!(format_hex(sdo_bytes)),
            );
            ws.insert(format!("{prefix}.coe.sdo.value"), auto_val.clone());
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": op_name,
                "index": format!("0x{index:04x}"),
                "subindex": subindex,
                "complete_access": complete_access,
                "expedited": true,
                "size": dlen,
                "data_hex": format_hex(sdo_bytes),
                "decoded_auto": auto_val,
            })
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
            ws.insert(format!("{prefix}.coe.sdo.total_size"), json!(total_size));
            ws.insert(
                format!("{prefix}.coe.sdo.data"),
                json!(format_hex(sdo_bytes)),
            );
            ws.insert(format!("{prefix}.coe.sdo.value"), auto_val.clone());
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": op_name,
                "index": format!("0x{index:04x}"),
                "subindex": subindex,
                "complete_access": complete_access,
                "expedited": false,
                "total_size": total_size,
                "frame_data_size": sdo_bytes.len(),
                "data_hex": format_hex(sdo_bytes),
                "decoded_auto": auto_val,
            })
        } else {
            json!({
                "kind": "CoE",
                "service": coe_service_name(service),
                "number": number,
                "sdo_op": op_name,
                "index": format!("0x{index:04x}"),
                "subindex": subindex,
                "truncated": true,
            })
        }
    } else {
        json!({
            "kind": "CoE",
            "service": coe_service_name(service),
            "number": number,
            "sdo_op": op_name,
            "index": format!("0x{index:04x}"),
            "subindex": subindex,
            "complete_access": complete_access,
        })
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

fn dissect_coe_sdo_info(
    number: u16,
    payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
    prefix: &str,
) -> Value {
    if payload.len() < 4 {
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
    ws.insert(format!("{prefix}.coe.sdoinfo.opcode"), json!(opcode));
    ws.insert(
        format!("{prefix}.coe.sdoinfo.fragments_left"),
        json!(fragments_left),
    );

    let rest = &payload[4..];
    match opcode {
        0x01 if rest.len() >= 2 => {
            let list_type = u16::from_le_bytes([rest[0], rest[1]]);
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
            ws.insert(
                format!("{prefix}.coe.sdoinfo.index"),
                json!(format!("0x{index:04x}")),
            );
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "index": format!("0x{index:04x}"),
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
            ws.insert(
                format!("{prefix}.coe.sdoinfo.index"),
                json!(format!("0x{index:04x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfo.name"), json!(name.clone()));
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "incomplete": incomplete,
                "fragments_left": fragments_left,
                "index": format!("0x{index:04x}"),
                "datatype": format!("0x{dt:04x}"),
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
            ws.insert(
                format!("{prefix}.coe.sdoinfo.index"),
                json!(format!("0x{index:04x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfo.subindex"), json!(subindex));
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "index": format!("0x{index:04x}"),
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
            let name_off = sdo_info_entry_name_offset(value_info, bit_len, rest.len());
            let name = String::from_utf8_lossy(&rest[name_off..])
                .trim_end_matches('\0')
                .to_string();
            ws.insert(
                format!("{prefix}.coe.sdoinfo.index"),
                json!(format!("0x{index:04x}")),
            );
            ws.insert(format!("{prefix}.coe.sdoinfo.subindex"), json!(subindex));
            ws.insert(format!("{prefix}.coe.sdoinfo.bit_length"), json!(bit_len));
            ws.insert(format!("{prefix}.coe.sdoinfo.name"), json!(name.clone()));
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "incomplete": incomplete,
                "fragments_left": fragments_left,
                "index": format!("0x{index:04x}"),
                "subindex": subindex,
                "value_info": value_info,
                "datatype": format!("0x{dt:04x}"),
                "datatype_name": ect_datatype_name(dt),
                "bit_length": bit_len,
                "obj_access": format!("0x{obj_access:04x}"),
                "name": name,
            })
        }
        0x07 if rest.len() >= 4 => {
            let abort_code = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
            let abort_desc = sdo_abort_description(abort_code);
            ws.insert(
                format!("{prefix}.coe.sdoinfo.abort_code"),
                json!(format!("0x{abort_code:08x}")),
            );
            json!({
                "kind": "CoE",
                "service": "SDO Information",
                "number": number,
                "opcode_name": opcode_name,
                "abort_code": format!("0x{abort_code:08x}"),
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

fn dissect_foe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 6 {
        return json!({ "kind": "FoE", "truncated": true, "raw_hex": format_hex(body) });
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
    ws.insert(format!("{prefix}.foe.opcode"), json!(opcode));
    match opcode {
        1 | 2 => {
            let filename = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(format!("{prefix}.foe.filename"), json!(filename.clone()));
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "password": format!("0x{arg:08x}"),
                "filename": filename,
            })
        }
        3 => {
            ws.insert(format!("{prefix}.foe.packet_no"), json!(arg));
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "packet_no": arg,
                "data_len": tail.len(),
                "data_hex": format_hex(tail),
            })
        }
        4 => {
            ws.insert(format!("{prefix}.foe.packet_no"), json!(arg));
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "packet_no": arg,
            })
        }
        5 => {
            let err_text = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(
                format!("{prefix}.foe.error_code"),
                json!(format!("0x{arg:08x}")),
            );
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "error_code": format!("0x{arg:08x}"),
                "error_text": err_text,
            })
        }
        6 => {
            let done = u16::from_le_bytes([body[2], body[3]]);
            let entire = u16::from_le_bytes([body[4], body[5]]);
            let busy_text = String::from_utf8_lossy(tail)
                .trim_end_matches('\0')
                .to_string();
            ws.insert(format!("{prefix}.foe.busy_done"), json!(done));
            ws.insert(format!("{prefix}.foe.busy_entire"), json!(entire));
            json!({
                "kind": "FoE",
                "opcode": opcode,
                "opcode_name": op_name,
                "done": done,
                "entire": entire,
                "busy_text": busy_text,
            })
        }
        _ => json!({
            "kind": "FoE",
            "opcode": opcode,
            "opcode_name": op_name,
            "arg": arg,
            "raw_hex": format_hex(tail),
        }),
    }
}

fn dissect_soe(body: &[u8], ws: &mut BTreeMap<String, Value>, prefix: &str) -> Value {
    if body.len() < 4 {
        return json!({ "kind": "SoE", "truncated": true, "raw_hex": format_hex(body) });
    }
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
        _ => "Unknown SoE",
    };
    ws.insert(format!("{prefix}.soe.opcode"), json!(opcode));
    ws.insert(format!("{prefix}.soe.incomplete"), json!(incomplete));
    ws.insert(format!("{prefix}.soe.error"), json!(error));
    ws.insert(format!("{prefix}.soe.drive_no"), json!(drive_no));
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
        "drive_no": drive_no,
        "element_flags": format!("0x{element_flags:02x}"),
        "idn": if incomplete { json!(null) } else { json!(idn_str) },
        "fragments_left": if incomplete { json!(idn_or_frag) } else { json!(0) },
        "data_hex": format_hex(&body[4..]),
    })
}
