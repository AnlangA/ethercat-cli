use std::collections::BTreeMap;

use ethercat_wire::protocol::constants::{al_state_name, al_status_code_description};
use ethercat_wire::types::format_hex;
use serde_json::{json, Map, Value};

fn emit_ws_key(
    ws: &mut BTreeMap<String, Value>,
    full_key: &str,
    indexed_key: Option<String>,
    val: Value,
) {
    ws.entry(full_key.to_string())
        .or_insert_with(|| val.clone());
    if let Some(ik) = indexed_key {
        ws.insert(ik, val);
    }
}

fn emit_reg_ws(ws: &mut BTreeMap<String, Value>, sub_idx: Option<usize>, suffix: &str, val: Value) {
    emit_ws_key(
        ws,
        &format!("ecat.reg.{suffix}"),
        sub_idx.map(|i| format!("ecat[{i}].reg.{suffix}")),
        val,
    );
}

fn emit_ecat_ws(
    ws: &mut BTreeMap<String, Value>,
    sub_idx: Option<usize>,
    suffix: &str,
    val: Value,
) {
    emit_ws_key(
        ws,
        &format!("ecat.{suffix}"),
        sub_idx.map(|i| format!("ecat[{i}].{suffix}")),
        val,
    );
}

fn esc_port_type_name(bits: u8) -> &'static str {
    match bits & 0x03 {
        0x00 => "Not implemented",
        0x01 => "Not configured (MII)",
        0x02 => "EBUS",
        0x03 => "MII / RMII / RGMII",
        _ => unreachable!(),
    }
}

/// Computes official Wireshark 4.6 Distributed Clocks port receive time differences
/// (`ecat.dc.dif.{da,bd,cb,cd,ba,ca}` and `ecat.sub{1..10}.dc.dif.*`) when `[0x0900..0x0910)` is present.
pub fn compute_dc_propagation_diffs(
    ado: u16,
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    sub_idx: Option<usize>,
) -> Option<Value> {
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
    let (Some(a), Some(b), Some(c), Some(d)) = (
        u32_at(0x0900),
        u32_at(0x0904),
        u32_at(0x0908),
        u32_at(0x090C),
    ) else {
        return None;
    };

    let mut diffs = Map::new();
    let mut record = |name: &str, v: u32| {
        diffs.insert(name.into(), json!(v));
        ws.entry(format!("ecat.dc.dif.{name}"))
            .or_insert_with(|| json!(v));
        if let Some(i) = sub_idx {
            ws.insert(format!("ecat[{i}].dc.dif.{name}"), json!(v));
            if i < 10 {
                let s1 = i + 1;
                ws.insert(format!("ecat.sub{s1}.dc.dif.{name}"), json!(v));
            }
        }
    };

    // Exact port of the Wireshark 4.6 `dissect_ecat_datagram()` DC branch (pDC[0..3] = A, B, C, D).
    if d != 0 {
        record("da", d.wrapping_sub(a));
        if b != 0 {
            record("bd", b.wrapping_sub(d));
        } else if c != 0 {
            record("cd", c.wrapping_sub(d));
        }
    }
    if b != 0 {
        record("ba", b.wrapping_sub(a));
        if c != 0 {
            record("cb", c.wrapping_sub(b));
        }
    } else if c != 0 {
        record("ca", c.wrapping_sub(a));
    }

    (!diffs.is_empty()).then_some(Value::Object(diffs))
}

/// Complete official Wireshark 4.6 ESC register, FMMU, SyncManager, and Distributed Clocks
/// register payload decoder (`0x0000..0x09FF`), preserving full backward compatibility with
/// existing `ethercat-cli` and `ethercat-master` selectors.
pub fn decode_esc_register_payload(
    ado: u16,
    data: &[u8],
    ws: &mut BTreeMap<String, Value>,
    sub_idx: Option<usize>,
) -> Option<Value> {
    if data.is_empty() || ado >= 0x1000 {
        return None;
    }

    let end_addr = ado.saturating_add(data.len() as u16);
    let overlaps = |lo: u16, hi: u16| -> bool { ado <= hi && end_addr > lo };

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

    // 1. Emit all official Wireshark 4.6 register fields overlapping `[ado..end_addr)`
    // 0x0000..0x0009 ESC Information
    if overlaps(0x0000, 0x0009) {
        if let Some(v) = byte_at(0x0000) {
            let hx = format!("0x{v:02x}");
            emit_reg_ws(ws, sub_idx, "type", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "esc_type", json!(hx));
        }
        if let Some(v) = byte_at(0x0001) {
            emit_reg_ws(ws, sub_idx, "revision", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "esc_revision", json!(v));
        }
        if let Some(v) = u16_at(0x0002) {
            emit_reg_ws(ws, sub_idx, "build", json!(format!("0x{v:04x}")));
            emit_reg_ws(ws, sub_idx, "esc_build", json!(v));
        }
        if let Some(v) = byte_at(0x0004) {
            emit_reg_ws(ws, sub_idx, "fmmucnt", json!(v));
            emit_reg_ws(ws, sub_idx, "fmmu_count", json!(v));
        }
        if let Some(v) = byte_at(0x0005) {
            emit_reg_ws(ws, sub_idx, "smcnt", json!(v));
            emit_reg_ws(ws, sub_idx, "sm_count", json!(v));
        }
        if let Some(v) = byte_at(0x0006) {
            emit_reg_ws(ws, sub_idx, "dpram", json!(v));
            emit_reg_ws(ws, sub_idx, "ram_size_kb", json!(v));
        }
        if let Some(v) = byte_at(0x0007) {
            let hx = format!("0x{v:02x}");
            emit_reg_ws(ws, sub_idx, "ports", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "port_desc", json!(hx));
        }
        if let Some(feat) = u16_at(0x0008) {
            let hx = format!("0x{feat:04x}");
            emit_reg_ws(ws, sub_idx, "features", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "esc_features", json!(hx));
            emit_reg_ws(
                ws,
                sub_idx,
                "features.fmmurestrict",
                json!((feat & 0x0001) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "features.smaddrrestrict",
                json!((feat & 0x0002) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "features.dcsupport",
                json!((feat & 0x0004) != 0),
            );
            emit_reg_ws(ws, sub_idx, "dc_supported", json!((feat & 0x0004) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "features.dc64support",
                json!((feat & 0x0008) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "features.ebuslowjitter",
                json!((feat & 0x0010) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "features.ebusextlinkdetect",
                json!((feat & 0x0020) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "features.miiextlinkdetect",
                json!((feat & 0x0040) != 0),
            );
            emit_reg_ws(ws, sub_idx, "features.crcext", json!((feat & 0x0080) != 0));
        }
    }

    // 0x0010..0x0041 Station Addresses, Protection & Reset
    if let Some(v) = u16_at(0x0010) {
        let hx = format!("0x{v:04x}");
        emit_reg_ws(ws, sub_idx, "physaddr", json!(hx.clone()));
        emit_reg_ws(ws, sub_idx, "station_addr", json!(hx));
    }
    if let Some(v) = u16_at(0x0012) {
        let hx = format!("0x{v:04x}");
        emit_reg_ws(ws, sub_idx, "physaddr2", json!(hx.clone()));
        emit_reg_ws(ws, sub_idx, "alias", json!(hx));
    }
    if let Some(v) = u16_at(0x0020) {
        emit_reg_ws(ws, sub_idx, "regprotect", json!(format!("0x{v:04x}")));
    }
    if let Some(v) = u16_at(0x0030) {
        emit_reg_ws(ws, sub_idx, "accessprotect", json!(format!("0x{v:04x}")));
    }
    if let Some(v) = byte_at(0x0040) {
        emit_reg_ws(ws, sub_idx, "resetecat", json!(format!("0x{v:02x}")));
    }
    if let Some(v) = byte_at(0x0041) {
        emit_reg_ws(ws, sub_idx, "resetpdi", json!(format!("0x{v:02x}")));
    }

    // 0x0100..0x0141 DL Control, Phys RW Offset, DL Status, AL Control/Status, PDI Control
    if overlaps(0x0100, 0x0141) {
        if let Some(v) = byte_at(0x0100) {
            emit_reg_ws(ws, sub_idx, "dlctrl1", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "dlctrl1.killnonecat", json!((v & 0x01) != 0));
            for p in 0..4u8 {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dlctrl1.port{p}extlinkdetect"),
                    json!((v & (0x10 << p)) != 0),
                );
            }
        }
        if let Some(v) = byte_at(0x0101) {
            // Note: official Wireshark 4.6 spells this `dlcrtl2` (plus clean alias `dlctrl2`)
            emit_reg_ws(ws, sub_idx, "dlcrtl2", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "dlctrl2", json!(format!("0x{v:02x}")));
            for p in 0..4u8 {
                let pv = (v >> (p * 2)) & 0x03;
                emit_reg_ws(ws, sub_idx, &format!("dlcrtl2.port{p}"), json!(pv));
                emit_reg_ws(ws, sub_idx, &format!("dlctrl2.port{p}"), json!(pv));
            }
        }
        if let Some(v) = byte_at(0x0102) {
            emit_reg_ws(ws, sub_idx, "dlctrl3", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "dlctrl3.fifosize", json!(v & 0x07));
            emit_reg_ws(ws, sub_idx, "dlctrl3.lowebusjit", json!((v & 0x08) != 0));
        }
        if let Some(v) = byte_at(0x0103) {
            emit_reg_ws(ws, sub_idx, "dlctrl4", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "dlctrl4.2ndaddress", json!((v & 0x01) != 0));
        }
        if let Some(v) = u16_at(0x0108) {
            emit_ecat_ws(ws, sub_idx, "regphysrwoffs", json!(format!("0x{v:04x}")));
        }
        if let Some(v) = byte_at(0x0110) {
            emit_reg_ws(ws, sub_idx, "dlstatus1", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "dlstatus1.operation", json!((v & 0x01) != 0));
            emit_reg_ws(ws, sub_idx, "dlstatus1.pdiwatchdog", json!((v & 0x02) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "dlstatus1.enhlinkdetect",
                json!((v & 0x04) != 0),
            );
            for p in 0..4u8 {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dlstatus1.physlink.port{p}"),
                    json!((v & (0x10 << p)) != 0),
                );
            }
        }
        if let Some(v) = byte_at(0x0111) {
            emit_reg_ws(ws, sub_idx, "dlstatus2", json!(format!("0x{v:02x}")));
            for p in 0..4u8 {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dlstatus2.port{p}"),
                    json!((v >> (p * 2)) & 0x03),
                );
            }
        }
        if let Some(dl) = u16_at(0x0110) {
            emit_reg_ws(ws, sub_idx, "dl_status", json!(format!("0x{dl:04x}")));
        }
        if let Some(ac) = u16_at(0x0120) {
            let hx = format!("0x{ac:04x}");
            emit_reg_ws(ws, sub_idx, "alctrl", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "al_control", json!(hx));
            emit_reg_ws(ws, sub_idx, "alctrl.ctrl", json!(ac & 0x000F));
            emit_reg_ws(ws, sub_idx, "alctrl.errack", json!((ac & 0x0010) != 0));
            emit_reg_ws(ws, sub_idx, "alctrl.id", json!((ac & 0x0020) != 0));
            if ado == 0x0120 {
                emit_reg_ws(ws, sub_idx, "al_state", json!(al_state_name(ac)));
            }
        }
        if let Some(st) = u16_at(0x0130) {
            let hx = format!("0x{st:04x}");
            emit_reg_ws(ws, sub_idx, "alstatus", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "al_status", json!(hx));
            emit_reg_ws(ws, sub_idx, "alstatus.status", json!(st & 0x000F));
            emit_reg_ws(ws, sub_idx, "alstatus.err", json!((st & 0x0010) != 0));
            emit_reg_ws(ws, sub_idx, "alstatus.id", json!((st & 0x0020) != 0));
            emit_reg_ws(ws, sub_idx, "al_state", json!(al_state_name(st)));
        }
        if let Some(sc) = u16_at(0x0134) {
            let hx = format!("0x{sc:04x}");
            emit_reg_ws(ws, sub_idx, "alstatuscode", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "al_status_code", json!(hx));
        }
        if let Some(v) = byte_at(0x0140) {
            let hx = format!("0x{v:02x}");
            emit_reg_ws(ws, sub_idx, "pdictrl1", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "pdictrl1.pdi", json!(hx));
        }
        if let Some(v) = byte_at(0x0141) {
            emit_reg_ws(ws, sub_idx, "pdictrl2", json!(format!("0x{v:02x}")));
            emit_reg_ws(ws, sub_idx, "pdictrl2.devemul", json!((v & 0x01) != 0));
            emit_reg_ws(ws, sub_idx, "pdictrl2.enhlnkdetect", json!((v & 0x02) != 0));
            emit_reg_ws(ws, sub_idx, "pdictrl2.dcsyncout", json!((v & 0x04) != 0));
            emit_reg_ws(ws, sub_idx, "pdictrl2.dcsyncin", json!((v & 0x08) != 0));
            for p in 0..4u8 {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("pdictrl2.enhlnkdetect{p}"),
                    json!((v & (0x10 << p)) != 0),
                );
            }
        }
    }

    // 0x0200..0x0223 Interrupt Masks & Event Requests
    if overlaps(0x0200, 0x0223) {
        for (reg, prefix) in [(0x0200u16, "irqmask.ecat_mask"), (0x0210u16, "irq.ecat")] {
            if let Some(v) = u16_at(reg) {
                emit_reg_ws(ws, sub_idx, prefix, json!(format!("0x{v:04x}")));
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.latchevt"),
                    json!((v & 0x0001) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.escstatevt"),
                    json!((v & 0x0004) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.alstatevt"),
                    json!((v & 0x0008) != 0),
                );
                for sm in 0..8u8 {
                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("{prefix}.sm{sm}irq"),
                        json!((v & (0x0100 << sm)) != 0),
                    );
                }
            }
        }
        for (reg, prefix) in [(0x0204u16, "irqmask.pdiL"), (0x0220u16, "irq.pdi1")] {
            if let Some(v) = u16_at(reg) {
                emit_reg_ws(ws, sub_idx, prefix, json!(format!("0x{v:04x}")));
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.alctrl"),
                    json!((v & 0x0001) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.latchin"),
                    json!((v & 0x0002) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.sync0"),
                    json!((v & 0x0004) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.sync1"),
                    json!((v & 0x0008) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.smchg"),
                    json!((v & 0x0010) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("{prefix}.eepromcmdpen"),
                    json!((v & 0x0020) != 0),
                );
                for sm in 0..8u8 {
                    emit_reg_ws(
                        ws,
                        sub_idx,
                        &format!("{prefix}.sm{sm}"),
                        json!((v & (0x0100 << sm)) != 0),
                    );
                }
            }
        }
        if let Some(v) = u16_at(0x0206) {
            emit_reg_ws(ws, sub_idx, "irqmask.pdiH", json!(format!("0x{v:04x}")));
        }
        if let Some(v) = u16_at(0x0222) {
            emit_reg_ws(ws, sub_idx, "irq.pdi2", json!(format!("0x{v:04x}")));
        }
    }

    // 0x0300..0x0313 Error Counters
    if overlaps(0x0300, 0x0313) {
        for p in 0..4u16 {
            if let Some(crc16) = u16_at(0x0300 + p * 2) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("crc{p}"),
                    json!(format!("0x{crc16:04x}")),
                );
            }
            if let Some(v) = byte_at(0x0300 + p * 2) {
                emit_reg_ws(ws, sub_idx, &format!("crc{p}.frame"), json!(v));
                emit_reg_ws(ws, sub_idx, &format!("rx_err_frame_port{p}"), json!(v));
            }
            if let Some(v) = byte_at(0x0301 + p * 2) {
                emit_reg_ws(ws, sub_idx, &format!("crc{p}.rx"), json!(v));
                emit_reg_ws(ws, sub_idx, &format!("rx_err_phys_port{p}"), json!(v));
            }
            if let Some(v) = byte_at(0x0308 + p) {
                emit_reg_ws(ws, sub_idx, &format!("crc.fwd{p}"), json!(v));
                emit_reg_ws(ws, sub_idx, &format!("fwd_rx_err_port{p}"), json!(v));
            }
            if let Some(v) = byte_at(0x0310 + p) {
                emit_reg_ws(ws, sub_idx, &format!("linklost{p}"), json!(v));
                emit_reg_ws(ws, sub_idx, &format!("lost_link_port{p}"), json!(v));
            }
        }
        if let Some(v) = byte_at(0x030C) {
            emit_reg_ws(ws, sub_idx, "processuniterr", json!(v));
            emit_reg_ws(ws, sub_idx, "epu_err_count", json!(v));
        }
        if let Some(v) = byte_at(0x030D) {
            emit_reg_ws(ws, sub_idx, "pdierr", json!(v));
            emit_reg_ws(ws, sub_idx, "pdi_err_count", json!(v));
        }
    }

    // 0x0400..0x0443 Watchdog
    if overlaps(0x0400, 0x0443) {
        if let Some(v) = u16_at(0x0400) {
            emit_reg_ws(ws, sub_idx, "wd.divisor", json!(v));
            emit_reg_ws(ws, sub_idx, "wd_divider", json!(v));
        }
        if let Some(v) = u16_at(0x0410) {
            emit_reg_ws(ws, sub_idx, "wd.timepdi", json!(v));
            emit_reg_ws(ws, sub_idx, "wd_time_pdi", json!(v));
        }
        if let Some(v) = u16_at(0x0420) {
            emit_reg_ws(ws, sub_idx, "wd.timesm", json!(v));
            emit_reg_ws(ws, sub_idx, "wd_time_pdata", json!(v));
        }
        if let Some(st8) = byte_at(0x0440) {
            let ok = (st8 & 0x01) != 0;
            emit_reg_ws(ws, sub_idx, "wd.status", json!(format!("0x{st8:02x}")));
            emit_reg_ws(ws, sub_idx, "wd.status.pdwatchdog", json!(ok));
            emit_reg_ws(ws, sub_idx, "wd_pdata_ok", json!(ok));
            if let Some(st16) = u16_at(0x0440) {
                emit_reg_ws(ws, sub_idx, "wd_status", json!(format!("0x{st16:04x}")));
            } else {
                emit_reg_ws(ws, sub_idx, "wd_status", json!(format!("0x{st8:02x}")));
            }
        }
        if let Some(v) = byte_at(0x0442) {
            emit_reg_ws(ws, sub_idx, "wd.cntsm", json!(v));
            emit_reg_ws(ws, sub_idx, "wd_cnt_pdata", json!(v));
        }
        if let Some(v) = byte_at(0x0443) {
            emit_reg_ws(ws, sub_idx, "wd.cntpdi", json!(v));
            emit_reg_ws(ws, sub_idx, "wd_cnt_pdi", json!(v));
        }
    }

    // 0x0500..0x051B SII EEPROM & MII Management
    if overlaps(0x0500, 0x051B) {
        if let Some(v16) = u16_at(0x0500) {
            emit_reg_ws(ws, sub_idx, "eeprom.assign", json!(format!("0x{v16:04x}")));
        }
        if let Some(b0) = byte_at(0x0500) {
            emit_reg_ws(ws, sub_idx, "eeprom.assign.ctrl", json!((b0 & 0x01) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "eeprom.assign.pdiaccess",
                json!((b0 & 0x02) != 0),
            );
            // Wireshark 4.6: `ecat.reg.eeprom.assign.status` = FT_BOOLEAN mask 0x10 of 0x0500.
            emit_reg_ws(ws, sub_idx, "eeprom.assign.status", json!((b0 & 0x10) != 0));
        }
        if let Some(ctl) = u16_at(0x0502) {
            emit_reg_ws(ws, sub_idx, "ctrlstat", json!(format!("0x{ctl:04x}")));
            emit_reg_ws(ws, sub_idx, "ctrlstat.wraccess", json!((ctl & 0x0001) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "ctrlstat.eepromemul",
                json!((ctl & 0x0020) != 0),
            );
            emit_reg_ws(ws, sub_idx, "ctrlstat.8bacc", json!((ctl & 0x0040) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.2bacc", json!((ctl & 0x0080) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.rdacc", json!((ctl & 0x0100) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.wracc", json!((ctl & 0x0200) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "ctrlstat.reloadacc",
                json!((ctl & 0x0400) != 0),
            );
            emit_reg_ws(ws, sub_idx, "ctrlstat.crcerr", json!((ctl & 0x0800) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.lderr", json!((ctl & 0x1000) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.cmderr", json!((ctl & 0x2000) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.wrerr", json!((ctl & 0x4000) != 0));
            emit_reg_ws(ws, sub_idx, "ctrlstat.busy", json!((ctl & 0x8000) != 0));
            emit_reg_ws(ws, sub_idx, "eep_busy", json!((ctl & 0x8000) != 0));
            let op = match (ctl >> 8) & 0x07 {
                0 => "NOP",
                1 => "READ",
                2 => "WRITE",
                4 => "RELOAD",
                _ => "OTHER",
            };
            emit_reg_ws(ws, sub_idx, "eep_op", json!(op));
        }
        if let Some(ah) = u16_at(0x0506) {
            emit_reg_ws(ws, sub_idx, "addrh", json!(format!("0x{ah:04x}")));
        }
        if let Some(al) = u16_at(0x0504) {
            emit_reg_ws(ws, sub_idx, "addrl", json!(format!("0x{al:04x}")));
            if let Some(ah) = u16_at(0x0506) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    "eep_word_addr",
                    json!(((ah as u32) << 16) | al as u32),
                );
            } else {
                emit_reg_ws(ws, sub_idx, "eep_word_addr", json!(al as u32));
            }
        }
        for d_idx in 0..4u16 {
            if let Some(dv) = u16_at(0x0508 + d_idx * 2) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("data{d_idx}"),
                    json!(format!("0x{dv:04x}")),
                );
            }
        }
        if let Some(mc) = u16_at(0x0510) {
            emit_reg_ws(ws, sub_idx, "mio.ctrlstat", json!(format!("0x{mc:04x}")));
            emit_reg_ws(
                ws,
                sub_idx,
                "mio.ctrlstat.wracc1",
                json!((mc & 0x0001) != 0),
            );
            emit_reg_ws(ws, sub_idx, "mio.ctrlstat.offsphy", json!(mc & 0x008F));
            emit_reg_ws(ws, sub_idx, "mio.ctrlstat.rdacc", json!((mc & 0x0100) != 0));
            emit_reg_ws(
                ws,
                sub_idx,
                "mio.ctrlstat.wracc2",
                json!((mc & 0x0200) != 0),
            );
            emit_reg_ws(ws, sub_idx, "mio.ctrlstat.wrerr", json!((mc & 0x4000) != 0));
            emit_reg_ws(ws, sub_idx, "mio.ctrlstat.busy", json!((mc & 0x8000) != 0));
        }
        if let Some(ma) = u16_at(0x0512) {
            emit_reg_ws(ws, sub_idx, "mio.addr", json!(format!("0x{ma:04x}")));
            emit_reg_ws(ws, sub_idx, "mio.addr.phyaddr", json!(ma & 0x001F));
            emit_reg_ws(ws, sub_idx, "mio.addr.mioaddr", json!((ma >> 8) & 0x001F));
        }
        if let Some(md) = u16_at(0x0514) {
            emit_reg_ws(ws, sub_idx, "mio.data", json!(format!("0x{md:04x}")));
        }
        if let Some(macc) = u16_at(0x0516) {
            emit_reg_ws(ws, sub_idx, "mio.access", json!(format!("0x{macc:04x}")));
            emit_reg_ws(
                ws,
                sub_idx,
                "mio.access.ecatacc",
                json!((macc & 0x0001) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "mio.access.pdiacc",
                json!((macc & 0x0100) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "mio.access.forcereset",
                json!((macc & 0x0200) != 0),
            );
        }
        for p in 0..4u16 {
            if let Some(ms) = byte_at(0x0518 + p) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}"),
                    json!(format!("0x{ms:02x}")),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.physlink"),
                    json!((ms & 0x01) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.link"),
                    json!((ms & 0x02) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.linkstatuserr"),
                    json!((ms & 0x04) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.readerr"),
                    json!((ms & 0x08) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.linkpartnererr"),
                    json!((ms & 0x10) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("mio.status{p}.phycfgupdated"),
                    json!((ms & 0x20) != 0),
                );
            }
        }
    }

    // 0x0600..0x06FF FMMU0..15 (official `ecat.fmmu.*` + compat `ecat.reg.fmmu{n}.*`)
    if overlaps(0x0600, 0x06FF) {
        for fmmu_idx in 0..16u16 {
            let base = 0x0600 + fmmu_idx * 16;
            if !overlaps(base, base + 15) {
                continue;
            }
            let slice_lo = (base.max(ado) - ado) as usize;
            let slice_hi = ((base + 16).min(end_addr) - ado) as usize;
            if slice_hi <= data.len() && slice_hi > slice_lo {
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "fmmu",
                    json!(format_hex(&data[slice_lo..slice_hi])),
                );
            }
            if let Some(lstart) = u32_at(base) {
                let hx = format!("0x{lstart:08x}");
                emit_ecat_ws(ws, sub_idx, "fmmu.lstart", json!(hx.clone()));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.log_start"), json!(hx));
            }
            if let Some(llen) = u16_at(base + 4) {
                emit_ecat_ws(ws, sub_idx, "fmmu.llen", json!(llen));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.length"), json!(llen));
            }
            if let Some(lsb) = byte_at(base + 6) {
                emit_ecat_ws(ws, sub_idx, "fmmu.lstartbit", json!(lsb));
            }
            if let Some(leb) = byte_at(base + 7) {
                emit_ecat_ws(ws, sub_idx, "fmmu.lendbit", json!(leb));
            }
            if let Some(pstart) = u16_at(base + 8) {
                let hx = format!("0x{pstart:04x}");
                emit_ecat_ws(ws, sub_idx, "fmmu.pstart", json!(hx.clone()));
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("fmmu{fmmu_idx}.phys_start"),
                    json!(hx),
                );
            }
            if let Some(psb) = byte_at(base + 10) {
                emit_ecat_ws(ws, sub_idx, "fmmu.pstartbit", json!(psb));
            }
            if let Some(ft) = byte_at(base + 11) {
                let rd = (ft & 0x01) != 0;
                let wr = (ft & 0x02) != 0;
                emit_ecat_ws(ws, sub_idx, "fmmu.type", json!(format!("0x{ft:02x}")));
                emit_ecat_ws(ws, sub_idx, "fmmu.typeread", json!(rd));
                emit_ecat_ws(ws, sub_idx, "fmmu.typewrite", json!(wr));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.read"), json!(rd));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.write"), json!(wr));
            }
            if let Some(act) = byte_at(base + 12) {
                let en = (act & 0x01) != 0;
                emit_ecat_ws(ws, sub_idx, "fmmu.activate", json!(format!("0x{act:02x}")));
                emit_ecat_ws(ws, sub_idx, "fmmu.activate0", json!(en));
                emit_reg_ws(ws, sub_idx, &format!("fmmu{fmmu_idx}.active"), json!(en));
            }
        }
    }

    // 0x0800..0x087F SyncManager0..15 (official `ecat.syncman.*` + compat `ecat.reg.sm{n}.*`)
    if overlaps(0x0800, 0x087F) {
        for sm_idx in 0..16u16 {
            let base = 0x0800 + sm_idx * 8;
            if !overlaps(base, base + 7) {
                continue;
            }
            let slice_lo = (base.max(ado) - ado) as usize;
            let slice_hi = ((base + 8).min(end_addr) - ado) as usize;
            if slice_hi <= data.len() && slice_hi > slice_lo {
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman",
                    json!(format_hex(&data[slice_lo..slice_hi])),
                );
            }
            if let Some(pstart) = u16_at(base) {
                let hx = format!("0x{pstart:04x}");
                emit_ecat_ws(ws, sub_idx, "syncman.start", json!(hx.clone()));
                emit_reg_ws(ws, sub_idx, &format!("sm{sm_idx}.phys_start"), json!(hx));
            }
            if let Some(slen) = u16_at(base + 2) {
                emit_ecat_ws(ws, sub_idx, "syncman.len", json!(slen));
                emit_reg_ws(ws, sub_idx, &format!("sm{sm_idx}.length"), json!(slen));
            }
            if let Some(cs16) = u16_at(base + 4) {
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.ctrlstatus",
                    json!(format!("0x{cs16:04x}")),
                );
            }
            if let Some(ctrl) = byte_at(base + 4) {
                emit_ecat_ws(ws, sub_idx, "syncman.opmode", json!(ctrl & 0x03));
                emit_ecat_ws(ws, sub_idx, "syncman.access", json!((ctrl >> 2) & 0x03));
                emit_ecat_ws(ws, sub_idx, "syncman.irq.ecat", json!((ctrl & 0x10) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.irq.pdi", json!((ctrl & 0x20) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.wdt", json!((ctrl & 0x40) != 0));
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("sm{sm_idx}.ctrl"),
                    json!(format!("0x{ctrl:02x}")),
                );
            }
            if let Some(stat) = byte_at(base + 5) {
                emit_ecat_ws(ws, sub_idx, "syncman.irq.write", json!((stat & 0x01) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.irq.read", json!((stat & 0x02) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.1bufstate", json!((stat & 0x08) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.3bufstate", json!((stat >> 4) & 0x03));
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
                    json!((stat & 0x08) != 0),
                );
            }
            if let Some(en16) = u16_at(base + 6) {
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.smenable",
                    json!(format!("0x{en16:04x}")),
                );
            }
            if let Some(act) = byte_at(base + 6) {
                emit_ecat_ws(ws, sub_idx, "syncman.enable", json!((act & 0x01) != 0));
                emit_ecat_ws(ws, sub_idx, "syncman.repeatreq", json!((act & 0x02) != 0));
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.latchsmchg.ecat",
                    json!((act & 0x40) != 0),
                );
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.latchsmchg.pdi",
                    json!((act & 0x80) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("sm{sm_idx}.enabled"),
                    json!((act & 0x01) != 0),
                );
            }
            if let Some(pdi_ctrl) = byte_at(base + 7) {
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.deactivate",
                    json!((pdi_ctrl & 0x01) != 0),
                );
                emit_ecat_ws(
                    ws,
                    sub_idx,
                    "syncman.repeatack",
                    json!((pdi_ctrl & 0x02) != 0),
                );
            }
        }
    }

    // 0x0900..0x09FF Distributed Clocks
    if overlaps(0x0900, 0x09FF) {
        for p in 0..4u16 {
            if let Some(rx_t) = u32_at(0x0900 + p * 4) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.recv{p}"),
                    json!(format!("0x{rx_t:08x}")),
                );
                emit_reg_ws(ws, sub_idx, &format!("dc_rx_time_port{p}"), json!(rx_t));
            }
        }
        if let Some(sys64) = u64_at(0x0910) {
            emit_reg_ws(ws, sub_idx, "dc.systime", json!(format!("0x{sys64:016x}")));
            emit_reg_ws(ws, sub_idx, "dc_systime", json!(sys64));
        } else if let Some(sys32) = u32_at(0x0910) {
            emit_reg_ws(ws, sub_idx, "dc_systime", json!(sys32));
        }
        if let Some(sys_l) = u32_at(0x0910) {
            emit_reg_ws(ws, sub_idx, "dc.systimeL", json!(format!("0x{sys_l:08x}")));
        }
        if let Some(sys_h) = u32_at(0x0914) {
            emit_reg_ws(ws, sub_idx, "dc.systimeH", json!(format!("0x{sys_h:08x}")));
        }
        if let Some(sof) = u64_at(0x0918) {
            emit_reg_ws(ws, sub_idx, "dc.recvtime64", json!(format!("0x{sof:016x}")));
            emit_reg_ws(ws, sub_idx, "dc_sof", json!(sof));
        }
        if let Some(off64) = u64_at(0x0920) {
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.systimeoffs",
                json!(format!("0x{off64:016x}")),
            );
            emit_reg_ws(ws, sub_idx, "dc_sys_offset", json!(off64));
        }
        if let Some(off_l) = u32_at(0x0920) {
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.systimeoffsl",
                json!(format!("0x{off_l:08x}")),
            );
        }
        if let Some(off_h) = u32_at(0x0924) {
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.systimeoffsh",
                json!(format!("0x{off_h:08x}")),
            );
        }
        if let Some(delay) = u32_at(0x0928) {
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.systimedelay",
                json!(format!("0x{delay:08x}")),
            );
            emit_reg_ws(ws, sub_idx, "dc_sys_delay", json!(delay));
        }
        if let Some(raw_diff) = u32_at(0x092C) {
            let mag = (raw_diff & 0x7FFF_FFFF) as i64;
            let signed_diff = if (raw_diff & 0x8000_0000) != 0 {
                -mag
            } else {
                mag
            };
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.ctrlerr",
                json!(format!("0x{raw_diff:08x}")),
            );
            emit_reg_ws(ws, sub_idx, "dc_sys_diff_ns", json!(signed_diff));
        }
        if let Some(v) = u16_at(0x0930) {
            emit_reg_ws(ws, sub_idx, "dc.speedstart", json!(format!("0x{v:04x}")));
        }
        if let Some(v) = u16_at(0x0932) {
            emit_reg_ws(ws, sub_idx, "dc.speeddiff", json!(format!("0x{v:04x}")));
        }
        if let Some(v) = byte_at(0x0934) {
            emit_reg_ws(ws, sub_idx, "dc.fltdepth.systimediff", json!(v));
        }
        if let Some(v) = byte_at(0x0935) {
            emit_reg_ws(ws, sub_idx, "dc.fltdepth.speedcnt", json!(v));
        }
        if let Some(cuc) = byte_at(0x0980) {
            emit_reg_ws(ws, sub_idx, "dc.cycunitctrl", json!(format!("0x{cuc:02x}")));
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.cycunitctrl.access_cyclic",
                json!((cuc & 0x01) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.cycunitctrl.access_latch0",
                json!((cuc & 0x10) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.cycunitctrl.access_latch1",
                json!((cuc & 0x20) != 0),
            );
        }
        if let Some(act) = byte_at(0x0981) {
            let hx = format!("0x{act:02x}");
            emit_reg_ws(ws, sub_idx, "dc.activation", json!(hx.clone()));
            emit_reg_ws(ws, sub_idx, "dc_sync_act", json!(hx));
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.enablecyclic",
                json!((act & 0x01) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.gen_sync0",
                json!((act & 0x02) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.gen_sync1",
                json!((act & 0x04) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.autoactivation",
                json!((act & 0x08) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.stimeext",
                json!((act & 0x10) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.stimecheck",
                json!((act & 0x20) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.hlfrange",
                json!((act & 0x40) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activation.dblrange",
                json!((act & 0x80) != 0),
            );
        }
        if let Some(v) = u16_at(0x0982) {
            emit_reg_ws(ws, sub_idx, "dc.cycimpuls", json!(format!("0x{v:04x}")));
        }
        if let Some(v) = byte_at(0x0984) {
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activationstat",
                json!(format!("0x{v:02x}")),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activationstat.sync0pend",
                json!((v & 0x01) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activationstat.sync1pend",
                json!((v & 0x02) != 0),
            );
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.activationstat.stimeoutofrange",
                json!((v & 0x04) != 0),
            );
        }
        if let Some(v) = byte_at(0x098E) {
            emit_reg_ws(ws, sub_idx, "dc.sync0.status", json!(format!("0x{v:02x}")));
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.sync0.status.triggered",
                json!((v & 0x01) != 0),
            );
        }
        if let Some(v) = byte_at(0x098F) {
            emit_reg_ws(ws, sub_idx, "dc.sync1.status", json!(format!("0x{v:02x}")));
            emit_reg_ws(
                ws,
                sub_idx,
                "dc.sync1.status.triggered",
                json!((v & 0x01) != 0),
            );
        }
        if let Some(st0) = u64_at(0x0990) {
            emit_reg_ws(ws, sub_idx, "dc.starttime0", json!(format!("0x{st0:016x}")));
            emit_reg_ws(ws, sub_idx, "dc_start0", json!(st0));
        } else if let Some(st0_32) = u32_at(0x0990) {
            emit_reg_ws(ws, sub_idx, "dc_start0", json!(st0_32));
        }
        if let Some(st1) = u64_at(0x0998) {
            emit_reg_ws(ws, sub_idx, "dc.starttime1", json!(format!("0x{st1:016x}")));
        }
        if let Some(cyc0) = u32_at(0x09A0) {
            emit_reg_ws(ws, sub_idx, "dc.cyctime0", json!(format!("0x{cyc0:08x}")));
            emit_reg_ws(ws, sub_idx, "dc_cycle0", json!(cyc0));
        }
        if let Some(cyc1) = u32_at(0x09A4) {
            emit_reg_ws(ws, sub_idx, "dc.cyctime1", json!(format!("0x{cyc1:08x}")));
            emit_reg_ws(ws, sub_idx, "dc_cycle1", json!(cyc1));
        }
        for l in 0..2u16 {
            if let Some(lc) = byte_at(0x09A8 + l) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.ctrl"),
                    json!(format!("0x{lc:02x}")),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.ctrl.pos"),
                    json!((lc & 0x01) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.ctrl.neg"),
                    json!((lc & 0x02) != 0),
                );
            }
            if let Some(ls) = byte_at(0x09AE + l) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.status"),
                    json!(format!("0x{ls:02x}")),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.status.eventpos"),
                    json!((ls & 0x01) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.status.eventneg"),
                    json!((ls & 0x02) != 0),
                );
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.status.pinstate"),
                    json!((ls & 0x04) != 0),
                );
            }
            if let Some(lp) = u64_at(0x09B0 + l * 16) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.pos"),
                    json!(format!("0x{lp:016x}")),
                );
            }
            if let Some(ln) = u64_at(0x09B8 + l * 16) {
                emit_reg_ws(
                    ws,
                    sub_idx,
                    &format!("dc.latch{l}.neg"),
                    json!(format!("0x{ln:016x}")),
                );
            }
        }
        if let Some(v) = u32_at(0x09F0) {
            emit_reg_ws(ws, sub_idx, "dc.rcvsyncmanchg", json!(format!("0x{v:08x}")));
        }
        if let Some(v) = u32_at(0x09F8) {
            emit_reg_ws(ws, sub_idx, "dc.pdismstart", json!(format!("0x{v:08x}")));
        }
        if let Some(v) = u32_at(0x09FC) {
            emit_reg_ws(ws, sub_idx, "dc.pdismchg", json!(format!("0x{v:08x}")));
        }
    }

    // 2. Build structured human/JSON `register_decode` object matching `ado` primary block
    match ado {
        0x0000..=0x0009 => {
            let mut m = Map::new();
            m.insert("register".into(), json!("ESC Information"));
            if let Some(esc_type) = byte_at(0x0000) {
                m.insert("esc_type".into(), json!(format!("0x{esc_type:02x}")));
            }
            if let Some(rev) = byte_at(0x0001) {
                m.insert("revision".into(), json!(rev));
            }
            if let Some(build) = u16_at(0x0002) {
                m.insert("build".into(), json!(build));
            }
            if let Some(fmmu_cnt) = byte_at(0x0004) {
                m.insert("fmmu_count".into(), json!(fmmu_cnt));
            }
            if let Some(sm_cnt) = byte_at(0x0005) {
                m.insert("sm_count".into(), json!(sm_cnt));
            }
            if let Some(ram_kb) = byte_at(0x0006) {
                m.insert("ram_size_kb".into(), json!(ram_kb));
            }
            if let Some(pdesc) = byte_at(0x0007) {
                m.insert("port_descriptor".into(), json!(format!("0x{pdesc:02x}")));
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
                m.insert("esc_features".into(), json!(format!("0x{feat:04x}")));
                m.insert(
                    "features_decoded".into(),
                    json!({
                        "fmmu_bit_operation_not_supported": (feat & 0x0001) != 0,
                        "sm_addressing_restriction": (feat & 0x0002) != 0,
                        "distributed_clocks_available": (feat & 0x0004) != 0,
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
            let alias = u16_at(0x0012);
            Some(json!({
                "register": "Configured Station Address",
                "station_addr": format!("0x{stadr:04x}"),
                "alias": alias.map(|a| format!("0x{a:04x}")),
            }))
        }
        0x0012 if data.len() >= 2 => {
            let al = u16::from_le_bytes([data[0], data[1]]);
            Some(json!({
                "register": "Configured Station Alias",
                "alias": format!("0x{al:04x}"),
            }))
        }
        0x0020 | 0x0030 if data.len() >= 2 => {
            let v = u16::from_le_bytes([data[0], data[1]]);
            Some(json!({
                "register": if ado == 0x0020 { "Write Register Protection" } else { "ESC Write Protection" },
                "raw": format!("0x{v:04x}"),
            }))
        }
        0x0040 | 0x0041 => Some(json!({
            "register": if ado == 0x0040 { "ESC Reset ECAT" } else { "ESC Reset PDI" },
            "raw": format!("0x{:02x}", data[0]),
        })),
        0x0100..=0x0103 => {
            let mut m = Map::new();
            m.insert("register".into(), json!("ESC DL Control"));
            if let Some(v) = byte_at(0x0100) {
                m.insert("dlctrl1".into(), json!(format!("0x{v:02x}")));
                m.insert("kill_non_ecat_frames".into(), json!((v & 0x01) != 0));
            }
            if let Some(v) = byte_at(0x0101) {
                m.insert("dlctrl2_port_loop".into(), json!(format!("0x{v:02x}")));
            }
            if let Some(v) = byte_at(0x0102) {
                m.insert("rx_fifo_size".into(), json!(v & 0x07));
                m.insert("low_ebus_jitter".into(), json!((v & 0x08) != 0));
            }
            if let Some(v) = byte_at(0x0103) {
                m.insert("station_alias_enabled".into(), json!((v & 0x01) != 0));
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0108 if data.len() >= 2 => Some(json!({
            "register": "Physical Read/Write Offset",
            "offset": format!("0x{:04x}", u16::from_le_bytes([data[0], data[1]])),
        })),
        0x0110 if data.len() >= 2 => {
            let dl = u16::from_le_bytes([data[0], data[1]]);
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
            Some(json!({
                "register": if ado == 0x0120 { "AL Control" } else { "AL Status" },
                "raw": format!("0x{st:04x}"),
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
            Some(json!({
                "register": "AL Status Code",
                "code": format!("0x{sc:04x}"),
                "description": al_status_code_description(sc),
            }))
        }
        0x0140..=0x0141 => Some(json!({
            "register": "PDI Control",
            "pdi_type": byte_at(0x0140).map(|v| format!("0x{v:02x}")),
            "pdi_config": byte_at(0x0141).map(|v| format!("0x{v:02x}")),
        })),
        0x0200..=0x0223 => {
            let mut m = Map::new();
            m.insert("register".into(), json!("ESC Interrupts"));
            if let Some(v) = u16_at(0x0200) {
                m.insert("ecat_irq_mask".into(), json!(format!("0x{v:04x}")));
            }
            if let Some(v) = u16_at(0x0204) {
                m.insert("pdi_irq_mask_low".into(), json!(format!("0x{v:04x}")));
            }
            if let Some(v) = u16_at(0x0210) {
                m.insert("ecat_irq_request".into(), json!(format!("0x{v:04x}")));
            }
            if let Some(v) = u16_at(0x0220) {
                m.insert("pdi_irq_request".into(), json!(format!("0x{v:04x}")));
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0300..=0x0313 => {
            let mut m = Map::new();
            m.insert("register".into(), json!("ESC Error Counters"));
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0300 + p * 2) {
                    m.insert(format!("rx_err_frame_port{p}"), json!(v));
                }
                if let Some(v) = byte_at(0x0301 + p * 2) {
                    m.insert(format!("rx_err_phys_port{p}"), json!(v));
                }
            }
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0308 + p) {
                    m.insert(format!("fwd_rx_err_port{p}"), json!(v));
                }
            }
            if let Some(v) = byte_at(0x030C) {
                m.insert("epu_err_count".into(), json!(v));
            }
            if let Some(v) = byte_at(0x030D) {
                m.insert("pdi_err_count".into(), json!(v));
            }
            for p in 0..4u16 {
                if let Some(v) = byte_at(0x0310 + p) {
                    m.insert(format!("lost_link_port{p}"), json!(v));
                }
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        0x0400..=0x0443 => {
            let mut m = Map::new();
            m.insert("register".into(), json!("Watchdog"));
            if let Some(div) = u16_at(0x0400) {
                m.insert("wd_divider".into(), json!(div));
            }
            if let Some(t_pdi) = u16_at(0x0410) {
                m.insert("wd_time_pdi".into(), json!(t_pdi));
            }
            if let Some(t_pd) = u16_at(0x0420) {
                m.insert("wd_time_pdata".into(), json!(t_pd));
            }
            if let Some(st16) = u16_at(0x0440) {
                m.insert("wd_status".into(), json!(format!("0x{st16:04x}")));
                m.insert("wd_pdata_ok".into(), json!((st16 & 0x0001) != 0));
            } else if let Some(st8) = byte_at(0x0440) {
                m.insert("wd_status".into(), json!(format!("0x{st8:02x}")));
                m.insert("wd_pdata_ok".into(), json!((st8 & 0x01) != 0));
            }
            if let Some(c_pd) = byte_at(0x0442) {
                m.insert("wd_cnt_pdata".into(), json!(c_pd));
            }
            if let Some(c_pdi) = byte_at(0x0443) {
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
            let op = match (ctl >> 8) & 0x07 {
                0 => "NOP",
                1 => "READ",
                2 => "WRITE",
                4 => "RELOAD",
                _ => "OTHER",
            };
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
        0x0508..=0x050F => Some(json!({
            "register": "SII EEPROM Data",
            "bytes": data.len(),
            "hex": format_hex(data),
        })),
        0x0510..=0x051B => Some(json!({
            "register": "MII Management Interface",
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

                decoded_fmmus.push(json!({
                    "register": format!("FMMU {fmmu_idx}"),
                    "logical_start": format!("0x{log_start:08x}"),
                    "logical_length": log_len,
                    "logical_start_bit": log_start_bit,
                    "logical_end_bit": log_end_bit,
                    "physical_start": format!("0x{phys_start:04x}"),
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

                    decoded_sms.push(json!({
                        "register": format!("SyncManager {sm_idx}"),
                        "physical_start": format!("0x{phys_start:04x}"),
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
                Some(json!({
                    "register": format!("SyncManager {sm_idx} Status"),
                    "status": format!("0x{stat:02x}"),
                    "mailbox_full": (stat & 0x08) != 0,
                    "write_event": (stat & 0x01) != 0,
                    "read_event": (stat & 0x02) != 0,
                }))
            } else {
                None
            }
        }
        0x0900..=0x09FF => {
            let mut m = Map::new();
            m.insert("register".into(), json!("Distributed Clocks"));
            for p in 0..4u16 {
                if let Some(rx_t) = u32_at(0x0900 + p * 4) {
                    m.insert(format!("dc_rx_time_port{p}"), json!(rx_t));
                }
            }
            if let Some(sys64) = u64_at(0x0910) {
                m.insert("dc_systime_ns".into(), json!(sys64));
            } else if let Some(sys32) = u32_at(0x0910) {
                m.insert("dc_systime_ns".into(), json!(sys32));
            }
            if let Some(sof) = u64_at(0x0918) {
                m.insert("dc_receive_time_ecat_ns".into(), json!(sof));
            }
            if let Some(off_ns) = u64_at(0x0920) {
                m.insert("dc_sys_offset_ns".into(), json!(off_ns));
            }
            if let Some(delay_ns) = u32_at(0x0928) {
                m.insert("dc_sys_delay_ns".into(), json!(delay_ns));
            }
            if let Some(raw_diff) = u32_at(0x092C) {
                let mag = (raw_diff & 0x7FFF_FFFF) as i64;
                let signed_diff = if (raw_diff & 0x8000_0000) != 0 {
                    -mag
                } else {
                    mag
                };
                m.insert("dc_sys_diff_ns".into(), json!(signed_diff));
            }
            if let Some(sp_start) = u16_at(0x0930) {
                m.insert("dc_speed_counter_start".into(), json!(sp_start));
            }
            if let Some(sp_diff) = u16_at(0x0932) {
                m.insert("dc_speed_counter_diff".into(), json!(sp_diff as i16));
            }
            if let Some(act) = byte_at(0x0981) {
                m.insert("dc_sync_activation".into(), json!(format!("0x{act:02x}")));
                m.insert("dc_cyclic_unit_active".into(), json!((act & 0x01) != 0));
                m.insert("dc_sync0_enabled".into(), json!((act & 0x02) != 0));
                m.insert("dc_sync1_enabled".into(), json!((act & 0x04) != 0));
            }
            if let Some(st0_64) = u64_at(0x0990) {
                m.insert("dc_sync0_start_time_ns".into(), json!(st0_64));
            } else if let Some(st0_32) = u32_at(0x0990) {
                m.insert("dc_sync0_start_time_ns".into(), json!(st0_32));
            }
            if let Some(cyc0) = u32_at(0x09A0) {
                m.insert("dc_sync0_cycle_ns".into(), json!(cyc0));
            }
            if let Some(cyc1) = u32_at(0x09A4) {
                m.insert("dc_sync1_cycle_ns".into(), json!(cyc1));
            }
            (m.len() > 1).then_some(Value::Object(m))
        }
        _ => None,
    }
}
