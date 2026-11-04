use std::collections::BTreeMap;

use ethercat_wire::types::{decode_typed_value, extract_bits_le, format_hex, DataTypeSpec};
use serde_json::{json, Value};

use crate::model::{SdoEventKind, SdoXmlDecode};
use crate::xml::{OdObject, OdSubEntry, XmlCatalog, XmlDeviceProfile};

fn decode_utf16le_str(bytes: &[u8]) -> String {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for &pair in bytes.as_chunks::<2>().0 {
        let u = u16::from_le_bytes(pair);
        if u == 0 {
            break;
        }
        units.push(u);
    }
    String::from_utf16_lossy(&units)
}

/// Decodes a scalar bit/byte slice using exact XML type + bit length + enum table.
pub fn decode_xml_scalar(
    raw_bytes: &[u8],
    bit_offset: usize,
    bit_length: u32,
    wire_type: DataTypeSpec,
    enum_values: &BTreeMap<i64, String>,
) -> Option<(Value, Option<String>)> {
    decode_xml_scalar_ext(
        raw_bytes,
        bit_offset,
        bit_length,
        wire_type,
        None,
        enum_values,
    )
}

/// Extended scalar decoder supporting explicit XML `type_name` (such as `UNICODE_STRING` UTF-16LE).
pub fn decode_xml_scalar_ext(
    raw_bytes: &[u8],
    bit_offset: usize,
    bit_length: u32,
    wire_type: DataTypeSpec,
    type_name: Option<&str>,
    enum_values: &BTreeMap<i64, String>,
) -> Option<(Value, Option<String>)> {
    if raw_bytes.is_empty() {
        return None;
    }
    let is_utf16 =
        type_name.is_some_and(|t| t.trim().to_ascii_uppercase().starts_with("UNICODE_STRING"));
    let effective_bits = if bit_length > 0 {
        bit_length as usize
    } else {
        raw_bytes.len() * 8
    };
    if bit_offset + effective_bits > raw_bytes.len() * 8 {
        // If SDO expedited/inline payload is shorter than nominal string max length, decode available bytes
        if matches!(wire_type, DataTypeSpec::String | DataTypeSpec::Hex) && bit_offset == 0 {
            if is_utf16 {
                return Some((json!(decode_utf16le_str(raw_bytes)), None));
            }
            let v = decode_typed_value(raw_bytes, wire_type, None).ok()?;
            return Some((v, None));
        }
        return None;
    }

    let extracted = extract_bits_le(raw_bytes, bit_offset, effective_bits).ok()?;

    let val = match wire_type {
        DataTypeSpec::Bool => json!((extracted.first().copied().unwrap_or(0) & 0x01) != 0),
        DataTypeSpec::U8
        | DataTypeSpec::U16
        | DataTypeSpec::U24
        | DataTypeSpec::U32
        | DataTypeSpec::U64 => {
            let mut buf = [0u8; 8];
            let n = extracted.len().min(8);
            buf[..n].copy_from_slice(&extracted[..n]);
            let u = u64::from_le_bytes(buf);
            json!(u)
        }
        DataTypeSpec::I8
        | DataTypeSpec::I16
        | DataTypeSpec::I24
        | DataTypeSpec::I32
        | DataTypeSpec::I64 => {
            let mut buf = [0u8; 8];
            let n = extracted.len().min(8);
            buf[..n].copy_from_slice(&extracted[..n]);
            let mut u = u64::from_le_bytes(buf);
            if effective_bits > 0 && effective_bits < 64 {
                let sign_bit = 1u64 << (effective_bits - 1);
                if (u & sign_bit) != 0 {
                    u |= !((1u64 << effective_bits) - 1);
                }
            }
            json!(u as i64)
        }
        DataTypeSpec::F32 if extracted.len() >= 4 => {
            decode_typed_value(&extracted[..4], DataTypeSpec::F32, None)
                .unwrap_or_else(|_| json!(format_hex(&extracted)))
        }
        DataTypeSpec::F64 if extracted.len() >= 8 => {
            decode_typed_value(&extracted[..8], DataTypeSpec::F64, None)
                .unwrap_or_else(|_| json!(format_hex(&extracted)))
        }
        DataTypeSpec::String => {
            if is_utf16 {
                json!(decode_utf16le_str(&extracted))
            } else {
                let nul = extracted
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(extracted.len());
                json!(String::from_utf8_lossy(&extracted[..nul]).to_string())
            }
        }
        _ => decode_typed_value(&extracted, wire_type, Some(effective_bits))
            .unwrap_or_else(|_| json!(format_hex(&extracted))),
    };

    let enum_text = if !enum_values.is_empty() {
        val.as_i64()
            .or_else(|| val.as_u64().map(|u| u as i64))
            .and_then(|iv| enum_values.get(&iv).cloned())
    } else {
        None
    };

    Some((val, enum_text))
}

/// Annotates CoE PDO Assignment (`0x1C12`/`0x1C13`) or CoE PDO Mapping (`0x1600..0x17FF`/`0x1A00..0x1BFF`)
/// SDO payloads with human-readable XML names!
fn build_pdo_config_annotations(
    dev: &XmlDeviceProfile,
    index: u16,
    subindex: u8,
    complete_access: bool,
    data: &[u8],
) -> Vec<String> {
    let mut notes = Vec::new();
    if matches!(index, 0x1C12 | 0x1C13) {
        if complete_access {
            let (cnt, start) = parse_ca_header(subindex, data, 2);
            if cnt == 0 {
                notes.push(format!(
                    "0x{index:04x}: clear SyncManager PDO assignment (count=0)"
                ));
            } else {
                for i in 0..cnt {
                    let off = start + i * 2;
                    if off + 2 <= data.len() {
                        let pdo_idx = u16::from_le_bytes([data[off], data[off + 1]]);
                        notes.push(describe_assigned_pdo(dev, pdo_idx));
                    }
                }
            }
        } else if subindex == 0 && !data.is_empty() {
            notes.push(format!("assigned PDO count = {}", data[0]));
        } else if subindex >= 1 && data.len() >= 2 {
            let pdo_idx = u16::from_le_bytes([data[0], data[1]]);
            notes.push(describe_assigned_pdo(dev, pdo_idx));
        }
    } else if (0x1600..=0x17FF).contains(&index) || (0x1A00..=0x1BFF).contains(&index) {
        if complete_access {
            let (cnt, start) = parse_ca_header(subindex, data, 4);
            if cnt == 0 {
                notes.push(format!(
                    "0x{index:04x}: clear PDO mapping entries (count=0)"
                ));
            } else {
                for i in 0..cnt {
                    let off = start + i * 4;
                    if off + 4 <= data.len() {
                        let raw = u32::from_le_bytes([
                            data[off],
                            data[off + 1],
                            data[off + 2],
                            data[off + 3],
                        ]);
                        notes.push(describe_mapped_entry(dev, raw));
                    }
                }
            }
        } else if subindex == 0 && !data.is_empty() {
            notes.push(format!("mapped entry count = {}", data[0]));
        } else if subindex >= 1 && data.len() >= 4 {
            let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            notes.push(describe_mapped_entry(dev, raw));
        }
    }
    notes
}

pub fn parse_ca_header(subindex: u8, data: &[u8], elem_bytes: usize) -> (usize, usize) {
    if subindex == 1 {
        return (data.len() / elem_bytes, 0);
    }
    if data.len() >= 2 {
        let cnt16 = u16::from_le_bytes([data[0], data[1]]) as usize;
        if 2 + cnt16 * elem_bytes <= data.len() {
            return (cnt16, 2);
        }
    }
    if !data.is_empty() {
        let cnt8 = data[0] as usize;
        if 1 + cnt8 * elem_bytes == data.len() {
            return (cnt8, 1);
        }
    }
    (0, 2.min(data.len()))
}

fn describe_assigned_pdo(dev: &XmlDeviceProfile, pdo_idx: u16) -> String {
    if let Some(p) = dev
        .rx_pdos
        .get(&pdo_idx)
        .or_else(|| dev.tx_pdos.get(&pdo_idx))
    {
        format!(
            "0x{pdo_idx:04x} ({}, {} bits, {} entries)",
            p.name,
            p.total_bits(),
            p.entries.len()
        )
    } else if let Some(obj) = dev.objects.get(&pdo_idx) {
        format!("0x{pdo_idx:04x} ({})", obj.name)
    } else {
        format!("0x{pdo_idx:04x}")
    }
}

fn describe_mapped_entry(dev: &XmlDeviceProfile, raw: u32) -> String {
    let bit_len = (raw & 0xFF) as u16;
    let esub = ((raw >> 8) & 0xFF) as u8;
    let eidx = ((raw >> 16) & 0xFFFF) as u16;
    let resolved = dev.resolve_pdo_entry(eidx, esub, bit_len);
    format!(
        "0x{eidx:04x}:{esub:02x} ({}, {}, {} bits)",
        resolved.name, resolved.data_type, bit_len
    )
}

fn standard_coe_fallback_object(
    dev: &XmlDeviceProfile,
    index: u16,
    subindex: u8,
) -> Option<(String, &'static str, OdSubEntry)> {
    match index {
        0x1C12 | 0x1C13 => {
            let obj_name = if index == 0x1C12 {
                "Sync Manager 2 RxPDO Assignment".to_string()
            } else {
                "Sync Manager 3 TxPDO Assignment".to_string()
            };
            let sub = if subindex == 0 {
                OdSubEntry {
                    subindex: 0,
                    name: "Number of assigned PDOs".into(),
                    type_name: "USINT".into(),
                    wire_type: DataTypeSpec::U8,
                    bit_length: 8,
                    bit_offset: Some(0),
                    access: Some("rw".into()),
                    pdo_mapping: None,
                    unit: None,
                    default_hex: None,
                    enum_values: BTreeMap::new(),
                }
            } else {
                OdSubEntry {
                    subindex,
                    name: format!("PDO Mapping {subindex}"),
                    type_name: "UINT".into(),
                    wire_type: DataTypeSpec::U16,
                    bit_length: 16,
                    bit_offset: Some(16 + (subindex as u32 - 1) * 16),
                    access: Some("rw".into()),
                    pdo_mapping: None,
                    unit: None,
                    default_hex: None,
                    enum_values: BTreeMap::new(),
                }
            };
            Some((obj_name, "ARRAY", sub))
        }
        0x1600..=0x17FF | 0x1A00..=0x1BFF => {
            let obj_name = dev
                .rx_pdos
                .get(&index)
                .or_else(|| dev.tx_pdos.get(&index))
                .map(|p| p.name.clone())
                .unwrap_or_else(|| {
                    if index < 0x1800 {
                        format!("RxPDO Mapping 0x{index:04x}")
                    } else {
                        format!("TxPDO Mapping 0x{index:04x}")
                    }
                });
            let sub = if subindex == 0 {
                OdSubEntry {
                    subindex: 0,
                    name: "Number of mapped objects".into(),
                    type_name: "USINT".into(),
                    wire_type: DataTypeSpec::U8,
                    bit_length: 8,
                    bit_offset: Some(0),
                    access: Some("rw".into()),
                    pdo_mapping: None,
                    unit: None,
                    default_hex: None,
                    enum_values: BTreeMap::new(),
                }
            } else {
                OdSubEntry {
                    subindex,
                    name: format!("Mapped Object {subindex}"),
                    type_name: "UDINT".into(),
                    wire_type: DataTypeSpec::U32,
                    bit_length: 32,
                    bit_offset: Some(16 + (subindex as u32 - 1) * 32),
                    access: Some("rw".into()),
                    pdo_mapping: None,
                    unit: None,
                    default_hex: None,
                    enum_values: BTreeMap::new(),
                }
            };
            Some((obj_name, "RECORD", sub))
        }
        _ => None,
    }
}

/// Decodes a Complete Access (`CA = 1`) SDO payload against `OdObject`.
fn decode_complete_access_subitems(obj: &OdObject, start_sub: u8, data: &[u8]) -> Vec<Value> {
    let mut items = Vec::new();
    if data.is_empty() {
        return items;
    }
    let base_shift_bits = if start_sub == 1 {
        obj.subentries
            .get(&1)
            .and_then(|s| s.bit_offset)
            .unwrap_or(16) as usize
    } else {
        0usize
    };
    let count_cap = (start_sub == 0
        && matches!(
            obj.index,
            0x1C12 | 0x1C13 | 0x1600..=0x17FF | 0x1A00..=0x1BFF | 0xF030 | 0xF050
        ))
    .then_some(data[0]);

    let mut running_bit = 0usize;
    for (&sidx, sub) in &obj.subentries {
        if sidx < start_sub {
            continue;
        }
        if let Some(max_sub) = count_cap {
            if sidx > max_sub {
                break;
            }
        }
        let bit_off = if let Some(explicit_off) = sub.bit_offset {
            let off = (explicit_off as usize).saturating_sub(base_shift_bits);
            if sidx == 0 && start_sub == 0 && off == 0 {
                running_bit = 16;
            } else {
                running_bit = off + (sub.bit_length as usize);
            }
            off
        } else if sidx == 0 && start_sub == 0 {
            running_bit = 16; // ETG.1000.6 pads subindex 0 to 16 bits in Complete Access
            0
        } else {
            let cur = running_bit;
            running_bit += sub.bit_length as usize;
            cur
        };
        let blen = if sub.bit_length > 0 {
            sub.bit_length
        } else {
            8
        };
        if bit_off + (blen as usize) > data.len() * 8 {
            break;
        }
        if let Some((val, enum_txt)) = decode_xml_scalar_ext(
            data,
            bit_off,
            blen,
            sub.wire_type,
            Some(&sub.type_name),
            &sub.enum_values,
        ) {
            let mut m = serde_json::Map::new();
            m.insert("subindex".into(), json!(sidx));
            m.insert("name".into(), json!(sub.name));
            m.insert("data_type".into(), json!(sub.type_name));
            m.insert("bit_offset".into(), json!(bit_off));
            m.insert("bit_length".into(), json!(sub.bit_length));
            m.insert("value".into(), val);
            if let Some(et) = enum_txt {
                m.insert("enum_text".into(), json!(et));
            }
            items.push(Value::Object(m));
        }
    }
    items
}

/// Enriches an SDO transaction (single-frame or reassembled multi-segment) with XML Object Dictionary metadata,
/// writing official/XML selectors into `ws` and returning `SdoXmlDecode`.
#[allow(clippy::too_many_arguments)]
pub fn decode_sdo_with_xml(
    catalog: &XmlCatalog,
    preferred_device: Option<&XmlDeviceProfile>,
    index: u16,
    subindex: u8,
    complete_access: bool,
    payload_bytes: Option<&[u8]>,
    reassembled_segments: Option<usize>,
    ws: &mut BTreeMap<String, Value>,
    mbx_prefix: &str,
) -> Option<SdoXmlDecode> {
    let idx_s = format!("0x{index:04x}");
    if let Some((dev, obj)) = catalog.find_object(index, preferred_device) {
        let pdo_annotations = payload_bytes
            .map(|b| build_pdo_config_annotations(dev, index, subindex, complete_access, b))
            .unwrap_or_default();

        if complete_access {
            let mut subitems = payload_bytes
                .map(|b| decode_complete_access_subitems(obj, subindex, b))
                .unwrap_or_default();
            if let Some(b) = payload_bytes {
                if matches!(index, 0x1C12 | 0x1C13 | 0x1600..=0x17FF | 0x1A00..=0x1BFF) {
                    let fb_items =
                        decode_fallback_complete_access_subitems(dev, index, subindex, b);
                    if fb_items.len() > subitems.len() {
                        let max_existing = subitems
                            .iter()
                            .filter_map(|v| v.get("subindex").and_then(Value::as_u64))
                            .max();
                        for fi in fb_items {
                            let fsub = fi.get("subindex").and_then(Value::as_u64).unwrap_or(0);
                            if max_existing.is_none_or(|m| fsub > m) {
                                subitems.push(fi);
                            }
                        }
                    }
                }
            }
            let summary_val = (!subitems.is_empty()).then(|| Value::Array(subitems.clone()));
            let out = SdoXmlDecode {
                index: idx_s,
                subindex,
                device_name: Some(dev.name.clone()),
                object_name: obj.name.clone(),
                object_code: Some(obj.object_code.into()),
                entry_name: Some("Complete Access".into()),
                data_type: Some(obj.type_name.clone()),
                bit_length: (obj.bit_size > 0).then_some(obj.bit_size),
                access: None,
                unit: None,
                value: summary_val,
                enum_text: None,
                subitems,
                pdo_annotations,
                reassembled_segments,
                reassembled_len: reassembled_segments.and(payload_bytes.map(|b| b.len())),
                abort_code: None,
            };
            emit_sdo_xml_ws(&out, ws, mbx_prefix);
            return Some(out);
        }

        let fb_sub = standard_coe_fallback_object(dev, index, subindex).map(|(_, _, fs)| fs);
        let sub = obj.subentries.get(&subindex).or(fb_sub.as_ref());
        let (val, enum_txt) = match (sub, payload_bytes) {
            (Some(s), Some(b)) if !b.is_empty() => decode_xml_scalar_ext(
                b,
                0,
                s.bit_length,
                s.wire_type,
                Some(&s.type_name),
                &s.enum_values,
            )
            .map(|(v, e)| (Some(v), e))
            .unwrap_or((None, None)),
            _ => (None, None),
        };

        let out = SdoXmlDecode {
            index: idx_s,
            subindex,
            device_name: Some(dev.name.clone()),
            object_name: obj.name.clone(),
            object_code: Some(obj.object_code.into()),
            entry_name: sub.map(|s| s.name.clone()),
            data_type: sub
                .map(|s| s.type_name.clone())
                .or_else(|| Some(obj.type_name.clone())),
            bit_length: sub.map(|s| s.bit_length).filter(|&b| b > 0),
            access: sub.and_then(|s| s.access.clone()),
            unit: sub.and_then(|s| s.unit.clone()),
            value: val,
            enum_text: enum_txt,
            subitems: Vec::new(),
            pdo_annotations,
            reassembled_segments,
            reassembled_len: reassembled_segments.and(payload_bytes.map(|b| b.len())),
            abort_code: None,
        };
        emit_sdo_xml_ws(&out, ws, mbx_prefix);
        return Some(out);
    }

    // Standard CoE PDO Assignment / Mapping fallback (`0x1C12`/`0x1C13`, `0x16xx`/`0x1Axx`)
    let dev = preferred_device.or_else(|| catalog.devices.first())?;
    let (obj_name, obj_code, sub) = standard_coe_fallback_object(dev, index, subindex)?;
    let pdo_annotations = payload_bytes
        .map(|b| build_pdo_config_annotations(dev, index, subindex, complete_access, b))
        .unwrap_or_default();
    let (val, enum_txt, subitems) = if !complete_access {
        let (v, e) = payload_bytes
            .filter(|b| !b.is_empty())
            .and_then(|b| decode_xml_scalar(b, 0, sub.bit_length, sub.wire_type, &sub.enum_values))
            .map(|(v, e)| (Some(v), e))
            .unwrap_or((None, None));
        (v, e, Vec::new())
    } else {
        let items = payload_bytes
            .map(|b| decode_fallback_complete_access_subitems(dev, index, subindex, b))
            .unwrap_or_default();
        let summary_val = (!items.is_empty()).then(|| Value::Array(items.clone()));
        (summary_val, None, items)
    };

    let out = SdoXmlDecode {
        index: idx_s,
        subindex,
        device_name: Some(dev.name.clone()),
        object_name: obj_name,
        object_code: Some(obj_code.into()),
        entry_name: Some(if complete_access {
            "Complete Access".into()
        } else {
            sub.name
        }),
        data_type: Some(sub.type_name),
        bit_length: Some(sub.bit_length),
        access: sub.access,
        unit: None,
        value: val,
        enum_text: enum_txt,
        subitems,
        pdo_annotations,
        reassembled_segments,
        reassembled_len: reassembled_segments.and(payload_bytes.map(|b| b.len())),
        abort_code: None,
    };
    emit_sdo_xml_ws(&out, ws, mbx_prefix);
    Some(out)
}

fn decode_fallback_complete_access_subitems(
    dev: &XmlDeviceProfile,
    index: u16,
    start_sub: u8,
    data: &[u8],
) -> Vec<Value> {
    let mut items = Vec::new();
    if data.is_empty() {
        return items;
    }
    let elem_bytes = match index {
        0x1C12 | 0x1C13 => 2usize,
        0x1600..=0x17FF | 0x1A00..=0x1BFF => 4usize,
        _ => return items,
    };
    let empty_enums = BTreeMap::new();
    let (count_limit, mut byte_off) = if start_sub == 0 {
        if let Some((_, _, sub0)) = standard_coe_fallback_object(dev, index, 0) {
            if let Some((v0, _)) = decode_xml_scalar(data, 0, 8, DataTypeSpec::U8, &empty_enums) {
                items.push(json!({
                    "subindex": 0,
                    "name": sub0.name,
                    "data_type": sub0.type_name,
                    "bit_offset": 0,
                    "bit_length": 8,
                    "value": v0,
                }));
            }
        }
        (Some(data[0] as usize), 2usize)
    } else if start_sub == 1 {
        (None, 0usize)
    } else {
        return items;
    };

    let mut sub_idx = 1u8;
    let mut decoded_elems = 0usize;
    while byte_off + elem_bytes <= data.len() {
        if let Some(lim) = count_limit {
            if decoded_elems >= lim {
                break;
            }
        }
        let Some((_, _, sub)) = standard_coe_fallback_object(dev, index, sub_idx) else {
            break;
        };
        let bit_off = byte_off * 8;
        if let Some((val, _)) =
            decode_xml_scalar(data, bit_off, sub.bit_length, sub.wire_type, &empty_enums)
        {
            items.push(json!({
                "subindex": sub_idx,
                "name": sub.name,
                "data_type": sub.type_name,
                "bit_offset": bit_off,
                "bit_length": sub.bit_length,
                "value": val,
            }));
        }
        byte_off += elem_bytes;
        decoded_elems += 1;
        let Some(next) = sub_idx.checked_add(1) else {
            break;
        };
        sub_idx = next;
    }
    items
}

/// Stateless helper to attach XML SDO metadata directly to a single-frame `SdoEventKind`.
pub fn enrich_single_frame_sdo(
    ev: &SdoEventKind,
    catalog: &XmlCatalog,
    preferred_device: Option<&XmlDeviceProfile>,
    ws: &mut BTreeMap<String, Value>,
    mbx_prefix: &str,
) -> Option<SdoXmlDecode> {
    match ev {
        SdoEventKind::InitiateDownload {
            index,
            subindex,
            complete_access,
            expedited,
            indicated_size,
            inline_data,
        }
        | SdoEventKind::InitiateUploadRes {
            index,
            subindex,
            complete_access,
            expedited,
            indicated_size,
            inline_data,
        } => {
            // Only decode payload immediately if it is complete in this frame (not waiting for segments)
            let is_complete = *expedited
                || match indicated_size {
                    Some(tot) => inline_data.len() >= *tot,
                    None => !inline_data.is_empty(),
                };
            let bytes = is_complete.then_some(inline_data.as_slice());
            decode_sdo_with_xml(
                catalog,
                preferred_device,
                *index,
                *subindex,
                *complete_access,
                bytes,
                None,
                ws,
                mbx_prefix,
            )
        }
        SdoEventKind::AoeWriteReq {
            index,
            subindex,
            complete_access,
            data,
            ..
        } => decode_sdo_with_xml(
            catalog,
            preferred_device,
            *index,
            *subindex,
            *complete_access,
            (!data.is_empty()).then_some(data.as_slice()),
            None,
            ws,
            mbx_prefix,
        ),
        SdoEventKind::AoeReadWriteReq {
            index,
            subindex,
            complete_access,
            write_data,
            ..
        } => decode_sdo_with_xml(
            catalog,
            preferred_device,
            *index,
            *subindex,
            *complete_access,
            (!write_data.is_empty()).then_some(write_data.as_slice()),
            None,
            ws,
            mbx_prefix,
        ),
        SdoEventKind::InitiateUploadReq {
            index,
            subindex,
            complete_access,
        }
        | SdoEventKind::AoeReadReq {
            index,
            subindex,
            complete_access,
            ..
        } => decode_sdo_with_xml(
            catalog,
            preferred_device,
            *index,
            *subindex,
            *complete_access,
            None,
            None,
            ws,
            mbx_prefix,
        ),
        SdoEventKind::Abort {
            index,
            subindex,
            abort_code,
        } => {
            let mut out = decode_sdo_with_xml(
                catalog,
                preferred_device,
                *index,
                *subindex,
                false,
                None,
                None,
                ws,
                mbx_prefix,
            )?;
            out.abort_code = Some(format!("0x{abort_code:08x}"));
            emit_sdo_xml_ws(&out, ws, mbx_prefix);
            Some(out)
        }
        SdoEventKind::InitiateBlockDownload {
            index,
            subindex,
            complete_access,
            ..
        }
        | SdoEventKind::InitiateBlockUploadReq {
            index,
            subindex,
            complete_access,
            ..
        } => decode_sdo_with_xml(
            catalog,
            preferred_device,
            *index,
            *subindex,
            *complete_access,
            None,
            None,
            ws,
            mbx_prefix,
        ),
        SdoEventKind::InitiateBlockDownloadRes {
            index, subindex, ..
        }
        | SdoEventKind::InitiateBlockUploadRes {
            index, subindex, ..
        } => decode_sdo_with_xml(
            catalog,
            preferred_device,
            *index,
            *subindex,
            false,
            None,
            None,
            ws,
            mbx_prefix,
        ),
        _ => None,
    }
}

fn insert_sdo_xml_field(
    ws: &mut BTreeMap<String, Value>,
    mbx_prefix: &str,
    sub_idx_alias: Option<&str>,
    mirror_aoe_ams: bool,
    suffix: &str,
    v: Value,
) {
    ws.insert(format!("{mbx_prefix}.coe.sdo.xml.{suffix}"), v.clone());
    if mbx_prefix == "ams" && ws.contains_key("ams[0].cmdid") {
        ws.insert(format!("ams[0].coe.sdo.xml.{suffix}"), v.clone());
    }
    if mirror_aoe_ams {
        ws.entry(format!("ams.coe.sdo.xml.{suffix}"))
            .or_insert_with(|| v.clone());
    }
    if let Some(alias) = sub_idx_alias {
        ws.insert(format!("{alias}.coe.sdo.xml.{suffix}"), v.clone());
    } else if mbx_prefix == "ecat_mailbox" {
        ws.insert(format!("ecat[0].mailbox.coe.sdo.xml.{suffix}"), v.clone());
        ws.insert(format!("ecat_mailbox[0].coe.sdo.xml.{suffix}"), v.clone());
    }
    if !mbx_prefix.starts_with("ams") {
        ws.entry(format!("ecat_mailbox.coe.sdo.xml.{suffix}"))
            .or_insert(v);
    }
}

pub fn emit_sdo_xml_ws(dec: &SdoXmlDecode, ws: &mut BTreeMap<String, Value>, mbx_prefix: &str) {
    let sub_idx_alias = mbx_prefix
        .strip_prefix("ecat_mailbox[")
        .and_then(|s| s.strip_suffix(']'))
        .map(|i| format!("ecat[{i}].mailbox"));
    let alias_ref = sub_idx_alias.as_deref();
    let mirror_aoe_ams = !mbx_prefix.starts_with("ams")
        && (ws.contains_key(&format!("{mbx_prefix}.aoe.cmdid")) || ws.contains_key("ams.cmdid"));
    let is_primary_mbx_sdo = !mbx_prefix.starts_with("ams")
        && (mbx_prefix == "ecat_mailbox"
            || mbx_prefix == "ecat_mailbox[0]"
            || !ws.contains_key("ecat_mailbox.coe.sdo.xml.index")
            || ws
                .get("ecat_mailbox.coe.sdo.xml.index")
                .and_then(Value::as_str)
                == Some(dec.index.as_str()));

    insert_sdo_xml_field(
        ws,
        mbx_prefix,
        alias_ref,
        mirror_aoe_ams,
        "index",
        json!(dec.index.clone()),
    );
    insert_sdo_xml_field(
        ws,
        mbx_prefix,
        alias_ref,
        mirror_aoe_ams,
        "subindex",
        json!(dec.subindex),
    );
    if let Some(dn) = &dec.device_name {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "device_name",
            json!(dn.clone()),
        );
    }
    insert_sdo_xml_field(
        ws,
        mbx_prefix,
        alias_ref,
        mirror_aoe_ams,
        "object_name",
        json!(dec.object_name.clone()),
    );
    if let Some(oc) = &dec.object_code {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "object_code",
            json!(oc.clone()),
        );
    }
    if let Some(en) = &dec.entry_name {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "entry_name",
            json!(en.clone()),
        );
    }
    if let Some(dt) = &dec.data_type {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "data_type",
            json!(dt.clone()),
        );
    }
    if let Some(bl) = dec.bit_length {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "bit_length",
            json!(bl),
        );
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "bit_size",
            json!(bl),
        );
    }
    if let Some(acc) = &dec.access {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "access",
            json!(acc.clone()),
        );
    }
    if let Some(u) = &dec.unit {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "unit",
            json!(u.clone()),
        );
    }
    if let Some(val) = &dec.value {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "value",
            val.clone(),
        );
        // Upgrade generic SDO value selector to exact XML-typed value!
        ws.insert(format!("{mbx_prefix}.coe.sdo.value"), val.clone());
        if mbx_prefix == "ams" && ws.contains_key("ams[0].cmdid") {
            ws.insert("ams[0].coe.sdo.value".into(), val.clone());
        }
        if mirror_aoe_ams {
            ws.entry("ams.coe.sdo.value".into())
                .or_insert_with(|| val.clone());
        }
        if let Some(alias) = alias_ref {
            ws.insert(format!("{alias}.coe.sdo.value"), val.clone());
        }
        if is_primary_mbx_sdo {
            ws.insert("ecat_mailbox.coe.sdo.value".into(), val.clone());
        }
        if mbx_prefix == "ecat_mailbox" || mbx_prefix == "ecat_mailbox[0]" {
            ws.insert("ecat[0].mailbox.coe.sdo.value".into(), val.clone());
            ws.insert("ecat_mailbox[0].coe.sdo.value".into(), val.clone());
        }
    }
    if let Some(et) = &dec.enum_text {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "enum_text",
            json!(et.clone()),
        );
    }
    if !dec.subitems.is_empty() {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "subitems",
            json!(dec.subitems.clone()),
        );
    }
    if !dec.pdo_annotations.is_empty() {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "pdo_annotations",
            json!(dec.pdo_annotations.clone()),
        );
    }
    if let Some(segs) = dec.reassembled_segments {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "reassembled_segments",
            json!(segs),
        );
    }
    if let Some(rlen) = dec.reassembled_len {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "reassembled_len",
            json!(rlen),
        );
    }
    if let Some(ac) = &dec.abort_code {
        insert_sdo_xml_field(
            ws,
            mbx_prefix,
            alias_ref,
            mirror_aoe_ams,
            "abort_code",
            json!(ac.clone()),
        );
    }
}
