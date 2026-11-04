use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::model::DissectedEsl;

/// Beckhoff ET2000 EtherCAT Switch Link 6-byte signature (`01:01:05:10:00:00`).
pub const ESL_SIGNATURE: [u8; 6] = [0x01, 0x01, 0x05, 0x10, 0x00, 0x00];
/// Length in bytes of a Beckhoff ET2000 ESL prefix or trailer tag.
pub const ESL_HEADER_LEN: usize = 16;

/// Dissects a 16-byte Beckhoff ET2000 EtherCAT Switch Link (`esl`) prefix or trailer tag.
pub fn dissect_esl_tag(
    tag: &[u8],
    position: &'static str,
    ws: &mut BTreeMap<String, Value>,
) -> DissectedEsl {
    let flags = u16::from_le_bytes([tag[6], tag[7]]);
    // Beckhoff ET2000 hardware port bitmask table
    const PORT_MASKS: &[(u16, u8)] = &[
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
    let align_error = (flags & 0x0800) != 0;
    let crc_error = (flags & 0x1000) != 0;
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
