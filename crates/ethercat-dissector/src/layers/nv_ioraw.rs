use std::collections::BTreeMap;

use ethercat_wire::types::format_mac;
use serde_json::{json, Value};

/// Dissects TwinCAT RAW-IO (`ecatf.type == 0x3`, Wireshark protocol `ioraw`).
/// Official Wireshark 4.6 layout (`packet-ioraw.c`):
/// - `[0..4]`: `ioraw.header` (4-byte RAW-IO header)
/// - `[4..]`:  `ioraw.data`   (variable process data)
pub fn dissect_ioraw(payload: &[u8], ws: &mut BTreeMap<String, Value>) -> Value {
    if payload.len() < 4 {
        let raw_hex = hex::encode(payload);
        ws.insert("ioraw.data".into(), json!(raw_hex.clone()));
        return json!({
            "protocol": "RAW-IO",
            "truncated": true,
            "data_hex": raw_hex,
        });
    }
    let hdr_hex = hex::encode(&payload[0..4]);
    let data_hex = hex::encode(&payload[4..]);
    ws.insert("ioraw.header".into(), json!(hdr_hex.clone()));
    ws.insert("ioraw.data".into(), json!(data_hex.clone()));
    json!({
        "protocol": "RAW-IO",
        "header_hex": hdr_hex,
        "data_len": payload.len() - 4,
        "data_hex": data_hex,
    })
}

/// Dissects TwinCAT Network Variables (`ecatf.type == 0x4`, Wireshark protocol `tc_nv`).
/// Verified against official Wireshark 4.6 (`packet-nv.c`):
/// - 12-byte `tc_nv.header`:
///   - `[0..6]`:   `tc_nv.publisher` (6-byte publisher MAC/ID)
///   - `[6..8]`:   `tc_nv.count` (`u16` LE variable count)
///   - `[8..10]`:  `tc_nv.cycleindex` (`u16` LE cycle index)
///   - `[10..12]`: 2 reserved bytes
/// - Repeated `count` variable blocks (`tc_nv.variable`):
///   - 8-byte `tc_nv.varheader`:
///     - `[0..2]`: `tc_nv.id` (`u16` LE)
///     - `[2..4]`: `tc_nv.hash` (`u16` LE)
///     - `[4..6]`: `tc_nv.length` (`u16` LE)
///     - `[6..8]`: `tc_nv.quality` (`u16` LE)
///   - `[8..8+length]`: `tc_nv.data`
pub fn dissect_tc_nv(payload: &[u8], ws: &mut BTreeMap<String, Value>) -> Value {
    if payload.len() < 12 {
        return json!({
            "protocol": "tc_nv",
            "truncated": true,
            "data_hex": hex::encode(payload),
        });
    }
    let mut pub_mac = [0u8; 6];
    pub_mac.copy_from_slice(&payload[0..6]);
    let publisher = format_mac(&pub_mac);
    let publisher_hex = hex::encode(&payload[0..6]);
    let var_count = u16::from_le_bytes([payload[6], payload[7]]);
    let cycle_index = u16::from_le_bytes([payload[8], payload[9]]);
    let reserved_hex = hex::encode(&payload[10..12]);

    ws.insert("tc_nv.header".into(), json!(hex::encode(&payload[0..12])));
    ws.insert("tc_nv.publisher".into(), json!(publisher.clone()));
    ws.insert("tc_nv.count".into(), json!(var_count));
    ws.insert("tc_nv.cycleindex".into(), json!(cycle_index));
    // Backward-compatible aliases
    ws.insert("nv.publisher_id".into(), json!(publisher_hex));
    ws.insert("nv.count".into(), json!(var_count));
    ws.insert("nv.cycle_index".into(), json!(cycle_index));

    let mut off = 12usize;
    let mut vars = Vec::new();
    for idx in 0..var_count as usize {
        if off + 8 > payload.len() {
            break;
        }
        let id = u16::from_le_bytes([payload[off], payload[off + 1]]);
        let hash = u16::from_le_bytes([payload[off + 2], payload[off + 3]]);
        let len = u16::from_le_bytes([payload[off + 4], payload[off + 5]]) as usize;
        let quality = u16::from_le_bytes([payload[off + 6], payload[off + 7]]);
        let var_hdr_hex = hex::encode(&payload[off..off + 8]);
        off += 8;
        let end = (off + len).min(payload.len());
        let data_hex = hex::encode(&payload[off..end]);
        let full_var_hex = format!("{var_hdr_hex}{data_hex}");
        off = end;

        if idx == 0 {
            ws.insert("tc_nv.variable".into(), json!(full_var_hex.clone()));
            ws.insert("tc_nv.varheader".into(), json!(var_hdr_hex.clone()));
            ws.insert("tc_nv.id".into(), json!(format!("0x{id:04x}")));
            ws.insert("tc_nv.hash".into(), json!(format!("0x{hash:04x}")));
            ws.insert("tc_nv.length".into(), json!(len));
            ws.insert("tc_nv.quality".into(), json!(format!("0x{quality:04x}")));
            ws.insert("tc_nv.data".into(), json!(data_hex.clone()));
        }
        ws.insert(format!("tc_nv.var[{idx}].id"), json!(format!("0x{id:04x}")));
        ws.insert(
            format!("tc_nv.var[{idx}].hash"),
            json!(format!("0x{hash:04x}")),
        );
        ws.insert(format!("tc_nv.var[{idx}].length"), json!(len));
        ws.insert(
            format!("tc_nv.var[{idx}].quality"),
            json!(format!("0x{quality:04x}")),
        );
        ws.insert(format!("tc_nv.var[{idx}].data"), json!(data_hex.clone()));

        vars.push(json!({
            "id": id,
            "id_hex": format!("0x{id:04x}"),
            "hash": format!("0x{hash:04x}"),
            "quality": format!("0x{quality:04x}"),
            "length": len,
            "data_hex": data_hex,
        }));
    }

    json!({
        "protocol": "tc_nv",
        "publisher": publisher,
        "count": var_count,
        "cycle_index": cycle_index,
        "reserved_hex": reserved_hex,
        "variables": vars,
    })
}
