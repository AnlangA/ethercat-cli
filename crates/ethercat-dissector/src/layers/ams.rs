use std::collections::BTreeMap;

use serde_json::{json, Map, Value};

use crate::catalog::{ads_cmd_name, ads_error_description, ads_state_name, ads_transmode_name};
use crate::model::SdoEventKind;

/// Beckhoff ADS IndexGroup for CANopen SDO over AoE (`ADSIGRP_CANOPEN_SDO`).
pub const ADSIGRP_CANOPEN_SDO: u32 = 0x0000_F302;

fn format_netid(b: &[u8]) -> String {
    format!("{}.{}.{}.{}.{}.{}", b[0], b[1], b[2], b[3], b[4], b[5])
}

/// Dissects an AMS/TCP payload starting with one or more back-to-back 6-byte AMS/TCP headers
/// (`[reserved:u16_le, len:u32_le]`).
pub fn dissect_ams_tcp(
    tcp_payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
) -> (Value, Option<SdoEventKind>) {
    let (val, mut evs) = dissect_ams_tcp_multi(tcp_payload, ws);
    let first_ev = evs.drain(..).next().map(|(_, _, ev)| ev);
    (val, first_ev)
}

/// Dissects one or more coalesced AMS/TCP PDUs in `tcp_payload`, emitting `ams[i].*` for every PDU
/// plus top-level `ams.*` for the first PDU, and returning all complete `(pdu_idx, target_port, SdoEventKind)` events.
pub fn dissect_ams_tcp_multi(
    tcp_payload: &[u8],
    ws: &mut BTreeMap<String, Value>,
) -> (Value, Vec<(usize, u16, SdoEventKind)>) {
    if tcp_payload.len() < 6 {
        return (
            json!({
                "protocol": "AMS/TCP",
                "truncated": true,
                "raw_hex": hex::encode(tcp_payload),
            }),
            Vec::new(),
        );
    }

    let mut off = 0usize;
    let mut pdu_idx = 0usize;
    let mut pdus = Vec::new();
    let mut sdo_events = Vec::new();
    let mut trailing_incomplete_hex = None;

    while off < tcp_payload.len() {
        if tcp_payload.len() - off < 6 {
            trailing_incomplete_hex = Some(hex::encode(&tcp_payload[off..]));
            break;
        }
        let tcp_reserved = u16::from_le_bytes([tcp_payload[off], tcp_payload[off + 1]]);
        let tcp_length = u32::from_le_bytes([
            tcp_payload[off + 2],
            tcp_payload[off + 3],
            tcp_payload[off + 4],
            tcp_payload[off + 5],
        ]);
        ws.insert(format!("ams[{pdu_idx}].tcp_length"), json!(tcp_length));
        ws.insert(format!("ams[{pdu_idx}].tcp_reserved"), json!(tcp_reserved));
        if pdu_idx == 0 {
            ws.insert("ams.tcp_length".into(), json!(tcp_length));
        }

        let expected_end = off.saturating_add(6).saturating_add(tcp_length as usize);
        let pdu_truncated = expected_end > tcp_payload.len() || (tcp_length as usize) < 32;
        let end = expected_end.min(tcp_payload.len());

        let (mut ams_val, sdo_ev) =
            dissect_ams_pdu_indexed(&tcp_payload[off + 6..end], ws, None, Some(pdu_idx));
        let target_port = ams_val
            .get("target_port")
            .and_then(Value::as_u64)
            .unwrap_or(0x1001) as u16;
        if let Some(obj) = ams_val.as_object_mut() {
            obj.insert("ams_tcp_reserved".into(), json!(tcp_reserved));
            obj.insert("ams_tcp_length".into(), json!(tcp_length));
            if pdu_truncated {
                obj.insert("truncated".into(), json!(true));
            }
        }
        if !pdu_truncated {
            if let Some(ev) = sdo_ev {
                sdo_events.push((pdu_idx, target_port, ev));
            }
        }
        pdus.push(ams_val);
        off = end;
        pdu_idx += 1;
    }

    ws.insert("ams.pdu_count".into(), json!(pdus.len()));
    let mut root = pdus.first().cloned().unwrap_or_else(|| json!({}));
    if let Some(obj) = root.as_object_mut() {
        obj.insert("pdu_count".into(), json!(pdus.len()));
        if pdus.len() > 1 {
            obj.insert("pdus".into(), Value::Array(pdus));
        }
        if let Some(th) = trailing_incomplete_hex {
            obj.insert("trailing_incomplete_hex".into(), json!(th));
        }
    }
    (root, sdo_events)
}

/// Dissects a 32-byte AMS header + ADS command payload (`ams.*`), optionally also emitting
/// `mbx_prefix` AoE mailbox compatibility selectors (`ecat_mailbox.aoe.*`).
pub fn dissect_ams_pdu(
    body: &[u8],
    ws: &mut BTreeMap<String, Value>,
    mbx_prefix: Option<&str>,
) -> (Value, Option<SdoEventKind>) {
    dissect_ams_pdu_indexed(body, ws, mbx_prefix, None)
}

pub fn dissect_ams_pdu_indexed(
    body: &[u8],
    ws: &mut BTreeMap<String, Value>,
    mbx_prefix: Option<&str>,
    pdu_idx: Option<usize>,
) -> (Value, Option<SdoEventKind>) {
    if body.len() < 32 {
        return (
            json!({
                "protocol": if mbx_prefix.is_some() { "AoE" } else { "AMS" },
                "truncated": true,
                "raw_hex": hex::encode(body),
            }),
            None,
        );
    }

    let target_net_id = format_netid(&body[0..6]);
    let target_port = u16::from_le_bytes([body[6], body[7]]);
    let sender_net_id = format_netid(&body[8..14]);
    let sender_port = u16::from_le_bytes([body[14], body[15]]);
    let cmd_id = u16::from_le_bytes([body[16], body[17]]);
    let state_flags = u16::from_le_bytes([body[18], body[19]]);
    let cb_data = u32::from_le_bytes([body[20], body[21], body[22], body[23]]);
    let error_code = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
    let invoke_id = u32::from_le_bytes([body[28], body[29], body[30], body[31]]);

    let is_response = (state_flags & 0x0001) != 0;
    let no_return = (state_flags & 0x0002) != 0;
    let ads_cmd = (state_flags & 0x0004) != 0;
    let sys_cmd = (state_flags & 0x0008) != 0;
    let high_prio = (state_flags & 0x0010) != 0;
    let ts_added = (state_flags & 0x0020) != 0;
    let udp_cmd = (state_flags & 0x0040) != 0;
    let init_cmd = (state_flags & 0x0080) != 0;
    let broadcast = (state_flags & 0x8000) != 0;

    macro_rules! insert_ams {
        ($k:expr, $v:expr) => {{
            let val: Value = $v;
            if let Some(pi) = pdu_idx {
                ws.insert(format!("ams[{pi}].{}", $k), val.clone());
            }
            if pdu_idx.is_none_or(|pi| pi == 0) {
                ws.entry(format!("ams.{}", $k))
                    .or_insert_with(|| val.clone());
            }
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.ams.{}", $k), val);
            }
        }};
    }

    insert_ams!("targetnetid", json!(target_net_id.clone()));
    insert_ams!("targetport", json!(target_port));
    insert_ams!("sendernetid", json!(sender_net_id.clone()));
    insert_ams!("senderport", json!(sender_port));
    insert_ams!("cmdid", json!(cmd_id));
    insert_ams!("stateflags", json!(format!("0x{state_flags:04x}")));
    insert_ams!("state_response", json!(is_response));
    insert_ams!("state_noreturn", json!(no_return));
    insert_ams!("state_adscmd", json!(ads_cmd));
    insert_ams!("state_syscmd", json!(sys_cmd));
    insert_ams!("state_highprio", json!(high_prio));
    insert_ams!("state_timestampadded", json!(ts_added));
    insert_ams!("state_udp", json!(udp_cmd));
    insert_ams!("state_initcmd", json!(init_cmd));
    insert_ams!("state_broadcast", json!(broadcast));
    insert_ams!("cbdata", json!(cb_data));
    insert_ams!("errorcode", json!(format!("0x{error_code:08x}")));
    insert_ams!("invokeid", json!(format!("0x{invoke_id:08x}")));

    if let Some(mp) = mbx_prefix {
        ws.insert(
            format!("{mp}.aoe.target"),
            json!(format!("{target_net_id}:{target_port}")),
        );
        ws.insert(format!("{mp}.aoe.targetport"), json!(target_port));
        ws.insert(
            format!("{mp}.aoe.source"),
            json!(format!("{sender_net_id}:{sender_port}")),
        );
        ws.insert(format!("{mp}.aoe.sender"), json!(sender_net_id.clone()));
        ws.insert(format!("{mp}.aoe.senderport"), json!(sender_port));
        ws.insert(format!("{mp}.aoe.cmd"), json!(cmd_id));
        ws.insert(format!("{mp}.aoe.err"), json!(error_code));
        ws.insert(format!("{mp}.aoe.errorcode"), json!(error_code));
        ws.insert(format!("{mp}.aoe.invoke_id"), json!(invoke_id));
        ws.insert(format!("{mp}.aoe.invokeid"), json!(invoke_id));
    }

    let ads_end = (32 + cb_data as usize).min(body.len());
    let ads_body = &body[32..ads_end];
    // Wireshark 4.6 `dissect_ams_pdu()`: `ams.data` only when the ADS command flag is clear,
    // `ams.ads_data` only after the fixed part of specific ADS services.
    if !ads_cmd && !ads_body.is_empty() {
        insert_ams!("data", json!(hex::encode(ads_body)));
    }
    let ws_ads_data_off = match (ads_cmd, cmd_id, is_response) {
        (true, 3, false) => Some(12),
        (true, 9, false) => Some(16),
        (true, 5, false) => Some(8),
        (true, 2, true) | (true, 9, true) => Some(8),
        _ => None,
    };
    if let Some(off) = ws_ads_data_off.filter(|&o| ads_body.len() >= o) {
        insert_ams!("ads_data", json!(hex::encode(&ads_body[off..])));
    }
    if ads_cmd && cmd_id == 4 && !is_response && cb_data != 0 && ads_body.len() >= 4 {
        let iid = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
        insert_ams!("ads_invokeid", json!(format!("0x{iid:08x}")));
    }

    let mut sdo_event = None;
    let mut ads_detail = Map::new();

    match (cmd_id, is_response) {
        // 1: ADS Read Device Info
        (1, false) => {
            insert_ams!("ads_readdinfo_req", json!(true));
        }
        (1, true) if ads_body.len() >= 24 => {
            insert_ams!("ads_readdinfo_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let major = ads_body[4];
            let minor = ads_body[5];
            let build = u16::from_le_bytes([ads_body[6], ads_body[7]]);
            let name_bytes = &ads_body[8..24];
            let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            let dev_name = String::from_utf8_lossy(&name_bytes[..nul]).to_string();
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            insert_ams!("ads_versionversion", json!(major));
            insert_ams!("ads_versionrevision", json!(minor));
            insert_ams!("ads_versionbuild", json!(build));
            insert_ams!("ads_devicename", json!(dev_name.clone()));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result_desc".into(), json!(ads_error_description(res)));
            ads_detail.insert("version".into(), json!(format!("{major}.{minor}.{build}")));
            ads_detail.insert("device_name".into(), json!(dev_name));
        }
        // 2: ADS Read
        (2, false) if ads_body.len() >= 12 => {
            insert_ams!("ads_read_req", json!(true));
            let ig = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let io = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let len = u32::from_le_bytes([ads_body[8], ads_body[9], ads_body[10], ads_body[11]]);
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            insert_ams!("ads_indexgroup", json!(ig_s.clone()));
            insert_ams!("ads_indexoffset", json!(io_s.clone()));
            insert_ams!("ads_cblength", json!(len));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.indexgroup"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.index_group"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.indexoffset"), json!(io_s.clone()));
                ws.insert(format!("{mp}.aoe.index_offset"), json!(io_s.clone()));
            }
            ads_detail.insert("index_group".into(), json!(ig_s));
            ads_detail.insert("index_offset".into(), json!(io_s));
            ads_detail.insert("read_length".into(), json!(len));
            if ig == ADSIGRP_CANOPEN_SDO {
                let sdo_idx = ((io >> 16) & 0xFFFF) as u16;
                let sdo_sub = (io & 0xFF) as u8;
                let ca = (io & 0x0100) != 0;
                ads_detail.insert(
                    "coe_over_aoe_index".into(),
                    json!(format!("0x{sdo_idx:04x}")),
                );
                ads_detail.insert("coe_over_aoe_subindex".into(), json!(sdo_sub));
                sdo_event = Some(SdoEventKind::AoeReadReq {
                    target_net_id: target_net_id.clone(),
                    target_port,
                    invoke_id,
                    index: sdo_idx,
                    subindex: sdo_sub,
                    complete_access: ca,
                });
            }
        }
        (2, true) if ads_body.len() >= 8 => {
            insert_ams!("ads_read_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let eff_res = if res != 0 { res } else { error_code };
            let len = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let end = (8 + len as usize).min(ads_body.len());
            let payload_slice = &ads_body[8..end];
            let dhex = hex::encode(payload_slice);
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            insert_ams!("ads_cblength", json!(len));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.result"), json!(res));
            }
            ads_detail.insert("result".into(), json!(res));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result_desc".into(), json!(ads_error_description(res)));
            ads_detail.insert("length".into(), json!(len));
            ads_detail.insert("data_hex".into(), json!(dhex));
            sdo_event = Some(SdoEventKind::AoeReadRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: eff_res,
                data: payload_slice.to_vec(),
            });
        }
        (2, true) if error_code != 0 => {
            insert_ams!("ads_read_res", json!(true));
            sdo_event = Some(SdoEventKind::AoeReadRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: error_code,
                data: Vec::new(),
            });
        }
        // 3: ADS Write
        (3, false) if ads_body.len() >= 12 => {
            insert_ams!("ads_write_req", json!(true));
            let ig = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let io = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let len = u32::from_le_bytes([ads_body[8], ads_body[9], ads_body[10], ads_body[11]]);
            let end = (12 + len as usize).min(ads_body.len());
            let wdata = &ads_body[12..end];
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            insert_ams!("ads_indexgroup", json!(ig_s.clone()));
            insert_ams!("ads_indexoffset", json!(io_s.clone()));
            insert_ams!("ads_cblength", json!(len));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.indexgroup"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.index_group"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.indexoffset"), json!(io_s.clone()));
                ws.insert(format!("{mp}.aoe.index_offset"), json!(io_s.clone()));
            }
            ads_detail.insert("index_group".into(), json!(ig_s));
            ads_detail.insert("index_offset".into(), json!(io_s));
            ads_detail.insert("write_length".into(), json!(len));
            ads_detail.insert("write_data_hex".into(), json!(hex::encode(wdata)));
            if ig == ADSIGRP_CANOPEN_SDO {
                let sdo_idx = ((io >> 16) & 0xFFFF) as u16;
                let sdo_sub = (io & 0xFF) as u8;
                let ca = (io & 0x0100) != 0;
                ads_detail.insert(
                    "coe_over_aoe_index".into(),
                    json!(format!("0x{sdo_idx:04x}")),
                );
                ads_detail.insert("coe_over_aoe_subindex".into(), json!(sdo_sub));
                sdo_event = Some(SdoEventKind::AoeWriteReq {
                    target_net_id: target_net_id.clone(),
                    target_port,
                    invoke_id,
                    index: sdo_idx,
                    subindex: sdo_sub,
                    complete_access: ca,
                    data: wdata.to_vec(),
                });
            }
        }
        (3, true) if ads_body.len() >= 4 => {
            insert_ams!("ads_write_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let eff_res = if res != 0 { res } else { error_code };
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.result"), json!(res));
            }
            ads_detail.insert("result".into(), json!(res));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result_desc".into(), json!(ads_error_description(res)));
            sdo_event = Some(SdoEventKind::AoeWriteRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: eff_res,
            });
        }
        (3, true) if error_code != 0 => {
            insert_ams!("ads_write_res", json!(true));
            sdo_event = Some(SdoEventKind::AoeWriteRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: error_code,
            });
        }
        // 4: ADS Read State
        (4, false) => {
            insert_ams!("ads_readstate_req", json!(true));
        }
        (4, true) if ads_body.len() >= 8 => {
            insert_ams!("ads_readstate_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let a_st = u16::from_le_bytes([ads_body[4], ads_body[5]]);
            let d_st = u16::from_le_bytes([ads_body[6], ads_body[7]]);
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            insert_ams!("ads_state", json!(format!("0x{a_st:04x}")));
            insert_ams!("ads_devicestate", json!(format!("0x{d_st:04x}")));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_state".into(), json!(a_st));
            ads_detail.insert("ads_state_name".into(), json!(ads_state_name(a_st)));
            ads_detail.insert("device_state".into(), json!(d_st));
        }
        // 5: ADS Write Control
        (5, false) if ads_body.len() >= 8 => {
            insert_ams!("ads_writectrl_req", json!(true));
            let a_st = u16::from_le_bytes([ads_body[0], ads_body[1]]);
            let d_st = u16::from_le_bytes([ads_body[2], ads_body[3]]);
            let len = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let end = (8 + len as usize).min(ads_body.len());
            insert_ams!("ads_state", json!(format!("0x{a_st:04x}")));
            insert_ams!("ads_devicestate", json!(format!("0x{d_st:04x}")));
            insert_ams!("ads_cblength", json!(len));
            ads_detail.insert("ads_state".into(), json!(a_st));
            ads_detail.insert("ads_state_name".into(), json!(ads_state_name(a_st)));
            ads_detail.insert("device_state".into(), json!(d_st));
            ads_detail.insert("length".into(), json!(len));
            ads_detail.insert("data_hex".into(), json!(hex::encode(&ads_body[8..end])));
        }
        (5, true) if ads_body.len() >= 4 => {
            insert_ams!("ads_writectrl_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result_desc".into(), json!(ads_error_description(res)));
        }
        // 6: ADS Add Device Notification
        (6, false) if ads_body.len() >= 24 => {
            insert_ams!("ads_adddn_req", json!(true));
            let ig = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let io = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let len = u32::from_le_bytes([ads_body[8], ads_body[9], ads_body[10], ads_body[11]]);
            let tmode =
                u32::from_le_bytes([ads_body[12], ads_body[13], ads_body[14], ads_body[15]]);
            let max_delay =
                u32::from_le_bytes([ads_body[16], ads_body[17], ads_body[18], ads_body[19]]);
            let cycle_time =
                u32::from_le_bytes([ads_body[20], ads_body[21], ads_body[22], ads_body[23]]);
            insert_ams!("ads_indexgroup", json!(format!("0x{ig:08x}")));
            insert_ams!("ads_indexoffset", json!(format!("0x{io:08x}")));
            insert_ams!("ads_cblength", json!(len));
            insert_ams!("ads_transmode", json!(tmode));
            insert_ams!("ads_maxdelay", json!(max_delay));
            insert_ams!("ads_cycletime", json!(cycle_time));
            ads_detail.insert("index_group".into(), json!(format!("0x{ig:08x}")));
            ads_detail.insert("index_offset".into(), json!(format!("0x{io:08x}")));
            ads_detail.insert("length".into(), json!(len));
            ads_detail.insert("trans_mode".into(), json!(tmode));
            ads_detail.insert("trans_mode_name".into(), json!(ads_transmode_name(tmode)));
            ads_detail.insert("max_delay".into(), json!(max_delay));
            ads_detail.insert("cycle_time".into(), json!(cycle_time));
        }
        (6, true) if ads_body.len() >= 8 => {
            insert_ams!("ads_adddn_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let hdl = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            insert_ams!("ads_notificationhandle", json!(format!("0x{hdl:08x}")));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("notification_handle".into(), json!(format!("0x{hdl:08x}")));
        }
        // 7: ADS Delete Device Notification
        (7, false) if ads_body.len() >= 4 => {
            insert_ams!("ads_deldn_req", json!(true));
            let hdl = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            insert_ams!("ads_notificationhandle", json!(format!("0x{hdl:08x}")));
            ads_detail.insert("notification_handle".into(), json!(format!("0x{hdl:08x}")));
        }
        (7, true) if ads_body.len() >= 4 => {
            insert_ams!("ads_deldn_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
        }
        // 8: ADS Device Notification (Stamp stream)
        (8, _) if ads_body.len() >= 8 => {
            insert_ams!("ads_dn_req", json!(true));
            let stream_len =
                u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let stamps_cnt =
                u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            insert_ams!("ads_cblength", json!(stream_len));
            insert_ams!("ads_noteblocksstamps", json!(stamps_cnt));
            let mut pos = 8usize;
            let mut stamps = Vec::new();
            for _ in 0..stamps_cnt.min(64) {
                if pos + 12 > ads_body.len() {
                    break;
                }
                let ts = u64::from_le_bytes([
                    ads_body[pos],
                    ads_body[pos + 1],
                    ads_body[pos + 2],
                    ads_body[pos + 3],
                    ads_body[pos + 4],
                    ads_body[pos + 5],
                    ads_body[pos + 6],
                    ads_body[pos + 7],
                ]);
                let sample_cnt = u32::from_le_bytes([
                    ads_body[pos + 8],
                    ads_body[pos + 9],
                    ads_body[pos + 10],
                    ads_body[pos + 11],
                ]);
                pos += 12;
                let mut samples = Vec::new();
                for _ in 0..sample_cnt.min(128) {
                    if pos + 8 > ads_body.len() {
                        break;
                    }
                    let hdl = u32::from_le_bytes([
                        ads_body[pos],
                        ads_body[pos + 1],
                        ads_body[pos + 2],
                        ads_body[pos + 3],
                    ]);
                    let sz = u32::from_le_bytes([
                        ads_body[pos + 4],
                        ads_body[pos + 5],
                        ads_body[pos + 6],
                        ads_body[pos + 7],
                    ]) as usize;
                    pos += 8;
                    let end = (pos + sz).min(ads_body.len());
                    if samples.is_empty() && stamps.is_empty() {
                        insert_ams!("ads_notificationhandle", json!(format!("0x{hdl:08x}")));
                    }
                    samples.push(json!({
                        "handle": format!("0x{hdl:08x}"),
                        "size": sz,
                        "data_hex": hex::encode(&ads_body[pos..end]),
                    }));
                    pos = end;
                }
                stamps.push(json!({
                    "timestamp_filetime": ts,
                    "sample_count": sample_cnt,
                    "samples": samples,
                }));
            }
            ads_detail.insert("stream_length".into(), json!(stream_len));
            ads_detail.insert("stamp_count".into(), json!(stamps_cnt));
            ads_detail.insert("stamps".into(), json!(stamps));
        }
        // 9: ADS Read Write
        (9, false) if ads_body.len() >= 16 => {
            insert_ams!("ads_readwrite_req", json!(true));
            let ig = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let io = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let rd_len = u32::from_le_bytes([ads_body[8], ads_body[9], ads_body[10], ads_body[11]]);
            let wr_len =
                u32::from_le_bytes([ads_body[12], ads_body[13], ads_body[14], ads_body[15]]);
            let end = (16 + wr_len as usize).min(ads_body.len());
            let ig_s = format!("0x{ig:08x}");
            let io_s = format!("0x{io:08x}");
            insert_ams!("ads_indexgroup", json!(ig_s.clone()));
            insert_ams!("ads_indexoffset", json!(io_s.clone()));
            insert_ams!("ads_cbreadlength", json!(rd_len));
            insert_ams!("ads_cbwritelength", json!(wr_len));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.indexgroup"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.index_group"), json!(ig_s.clone()));
                ws.insert(format!("{mp}.aoe.indexoffset"), json!(io_s.clone()));
                ws.insert(format!("{mp}.aoe.index_offset"), json!(io_s.clone()));
            }
            ads_detail.insert("index_group".into(), json!(ig_s));
            ads_detail.insert("index_offset".into(), json!(io_s));
            ads_detail.insert("read_length".into(), json!(rd_len));
            ads_detail.insert("write_length".into(), json!(wr_len));
            ads_detail.insert(
                "write_data_hex".into(),
                json!(hex::encode(&ads_body[16..end])),
            );
            if ig == ADSIGRP_CANOPEN_SDO {
                let sdo_idx = ((io >> 16) & 0xFFFF) as u16;
                let sdo_sub = (io & 0xFF) as u8;
                let ca = (io & 0x0100) != 0;
                ads_detail.insert(
                    "coe_over_aoe_index".into(),
                    json!(format!("0x{sdo_idx:04x}")),
                );
                ads_detail.insert("coe_over_aoe_subindex".into(), json!(sdo_sub));
                sdo_event = Some(SdoEventKind::AoeReadWriteReq {
                    target_net_id: target_net_id.clone(),
                    target_port,
                    invoke_id,
                    index: sdo_idx,
                    subindex: sdo_sub,
                    complete_access: ca,
                    read_length: rd_len as usize,
                    write_data: ads_body[16..end].to_vec(),
                });
            }
        }
        (9, true) if ads_body.len() >= 8 => {
            insert_ams!("ads_readwrite_res", json!(true));
            let res = u32::from_le_bytes([ads_body[0], ads_body[1], ads_body[2], ads_body[3]]);
            let eff_res = if res != 0 { res } else { error_code };
            let len = u32::from_le_bytes([ads_body[4], ads_body[5], ads_body[6], ads_body[7]]);
            let end = (8 + len as usize).min(ads_body.len());
            let payload_slice = &ads_body[8..end];
            insert_ams!("adsresult", json!(format!("0x{res:08x}")));
            insert_ams!("ads_cblength", json!(len));
            if let Some(mp) = mbx_prefix {
                ws.insert(format!("{mp}.aoe.result"), json!(res));
            }
            ads_detail.insert("result".into(), json!(res));
            ads_detail.insert("ads_result".into(), json!(format!("0x{res:08x}")));
            ads_detail.insert("ads_result_desc".into(), json!(ads_error_description(res)));
            ads_detail.insert("length".into(), json!(len));
            ads_detail.insert("data_hex".into(), json!(hex::encode(payload_slice)));
            sdo_event = Some(SdoEventKind::AoeReadRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: eff_res,
                data: payload_slice.to_vec(),
            });
        }
        (9, true) if error_code != 0 => {
            insert_ams!("ads_readwrite_res", json!(true));
            sdo_event = Some(SdoEventKind::AoeReadRes {
                sender_net_id: sender_net_id.clone(),
                sender_port,
                invoke_id,
                ads_result: error_code,
                data: Vec::new(),
            });
        }
        _ => {}
    }

    let mut out = Map::new();
    out.insert(
        "protocol".into(),
        json!(if mbx_prefix.is_some() { "AoE" } else { "AMS" }),
    );
    out.insert("target_net_id".into(), json!(target_net_id));
    out.insert("target_port".into(), json!(target_port));
    out.insert("sender_net_id".into(), json!(sender_net_id));
    out.insert("sender_port".into(), json!(sender_port));
    out.insert("cmd_id".into(), json!(cmd_id));
    out.insert("cmd_name".into(), json!(ads_cmd_name(cmd_id)));
    out.insert("state_flags".into(), json!(format!("0x{state_flags:04x}")));
    out.insert("is_response".into(), json!(is_response));
    out.insert("data_len".into(), json!(cb_data));
    out.insert("error_code".into(), json!(format!("0x{error_code:08x}")));
    out.insert(
        "error_description".into(),
        json!(ads_error_description(error_code)),
    );
    out.insert("invoke_id".into(), json!(invoke_id));
    out.insert("ads_payload_hex".into(), json!(hex::encode(ads_body)));
    for (k, v) in ads_detail {
        out.insert(k, v);
    }

    (Value::Object(out), sdo_event)
}
