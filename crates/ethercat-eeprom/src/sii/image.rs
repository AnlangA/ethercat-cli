use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::ect_datatype_name;

pub const SII_MIN_SIZE: usize = 128;
pub const SII_MAX_SIZE: usize = 524_288;
pub const SII_CATEGORY_OFFSET: usize = 0x80; // Word 0x0040

pub fn sii_le16(p: &[u8]) -> u16 {
    u16::from_le_bytes([
        p.first().copied().unwrap_or(0),
        p.get(1).copied().unwrap_or(0),
    ])
}

pub fn sii_le32(p: &[u8]) -> u32 {
    u32::from_le_bytes([
        p.first().copied().unwrap_or(0),
        p.get(1).copied().unwrap_or(0),
        p.get(2).copied().unwrap_or(0),
        p.get(3).copied().unwrap_or(0),
    ])
}

/// Compute EtherCAT SII Configuration CRC-8 (poly 0x07, init 0xFF) over the first 14 bytes (words 0..6).
pub fn sii_crc8(first_14_bytes: &[u8]) -> u8 {
    let mut crc: u8 = 0xFF;
    for &b in first_14_bytes.iter().take(14) {
        crc ^= b;
        for _ in 0..8 {
            crc = if (crc & 0x80) != 0 {
                (crc << 1) ^ 0x07
            } else {
                crc << 1
            };
        }
    }
    crc
}

/// Compute total declared EEPROM byte capacity from SII header word 0x003E (byte 0x7C):
/// `(u16_le(0x7c) + 1) * 128` bytes.
pub fn sii_declared_size(data: &[u8]) -> usize {
    if data.len() < SII_MIN_SIZE {
        return 0;
    }
    (sii_le16(&data[0x7C..0x7E]) as usize + 1) * 128
}

/// Validate an SII EEPROM binary image according to ETG.2010 and `esi-eeprom` safety rules.
pub fn sii_validate(data: &[u8]) -> Result<()> {
    if data.len() < SII_MIN_SIZE || data.len() > SII_MAX_SIZE || (data.len() & 1) != 0 {
        return Err(CliError::Format(format!(
            "SII image size ({}) must be even and between {SII_MIN_SIZE} and {SII_MAX_SIZE} bytes",
            data.len()
        )));
    }
    let declared = sii_declared_size(data);
    if declared != data.len() {
        return Err(CliError::Format(format!(
            "file length ({} bytes) does not match SII size field at byte 0x7c (declares {declared} bytes)",
            data.len()
        )));
    }
    let expected_crc = sii_crc8(&data[0..14]);
    let actual_crc = data[14];
    if expected_crc != actual_crc {
        return Err(CliError::Format(format!(
            "SII configuration CRC at byte 14 is invalid (actual=0x{actual_crc:02X}, expected=0x{expected_crc:02X})"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WordDiff {
    pub word_addr: usize,
    pub byte_offset: String,
    pub left_word: Option<String>,
    pub right_word: Option<String>,
}

pub fn sii_count_different_words(current: &[u8], proposed: &[u8]) -> usize {
    let max_words = current.len().max(proposed.len()).div_ceil(2);
    let mut diff = 0usize;
    for word_addr in 0..max_words {
        let i = word_addr * 2;
        let ls = current
            .get(i..current.len().min(i + 2))
            .filter(|s| !s.is_empty());
        let rs = proposed
            .get(i..proposed.len().min(i + 2))
            .filter(|s| !s.is_empty());
        if ls != rs {
            diff += 1;
        }
    }
    diff
}

pub fn sii_diff_words(left: &[u8], right: &[u8], max_details: usize) -> (usize, Vec<WordDiff>) {
    let max_words = left.len().max(right.len()).div_ceil(2);
    let mut total = 0usize;
    let mut details = Vec::new();
    for word_addr in 0..max_words {
        let i = word_addr * 2;
        let ls = left.get(i..left.len().min(i + 2)).filter(|s| !s.is_empty());
        let rs = right
            .get(i..right.len().min(i + 2))
            .filter(|s| !s.is_empty());
        if ls != rs {
            total += 1;
            if details.len() < max_details {
                details.push(WordDiff {
                    word_addr,
                    byte_offset: format!("0x{i:04x}"),
                    left_word: ls.map(|s| format!("0x{:04x}", sii_le16(s))),
                    right_word: rs.map(|s| format!("0x{:04x}", sii_le16(s))),
                });
            }
        }
    }
    (total, details)
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiHeaderDecoded {
    pub pdi_control: String,
    pub pdi_configuration: String,
    pub sync_impulse_len_ns: u32,
    pub pdi_configuration_2: String,
    pub configured_station_alias: u16,
    pub configured_station_alias_hex: String,
    pub crc_byte: String,
    pub crc_expected: String,
    pub crc_ok: bool,
    pub vendor_id: u32,
    pub vendor_id_hex: String,
    pub product_code: u32,
    pub product_code_hex: String,
    pub revision_number: u32,
    pub revision_number_hex: String,
    pub serial_number: u32,
    pub serial_number_hex: String,
    pub bootstrap_rx_mbx_offset: String,
    pub bootstrap_rx_mbx_size: u16,
    pub bootstrap_tx_mbx_offset: String,
    pub bootstrap_tx_mbx_size: u16,
    pub std_rx_mbx_offset: String,
    pub std_rx_mbx_size: u16,
    pub std_tx_mbx_offset: String,
    pub std_tx_mbx_size: u16,
    pub mbx_protocol_flags: String,
    pub mbx_protocols: Vec<&'static str>,
    pub size_kbit_minus_1: u16,
    pub declared_size_bytes: usize,
    pub version: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiCategoryHeaderInfo {
    pub category_code: u16,
    pub category_hex: String,
    pub category_name: &'static str,
    pub byte_offset: usize,
    pub word_length: u16,
    pub byte_length: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiGeneralDecoded {
    pub group_idx: u8,
    pub group_name: Option<String>,
    pub image_idx: u8,
    pub image_name: Option<String>,
    pub order_idx: u8,
    pub order_name: Option<String>,
    pub name_idx: u8,
    pub device_name: Option<String>,
    pub coe_details: SiiCoeDetails,
    pub foe_enabled: bool,
    pub eoe_enabled: bool,
    pub soe_channels: u8,
    pub ds402_channels: u8,
    pub sysman_class: u8,
    pub flags: u8,
    pub current_on_ebus_ma: i16,
    pub physical_ports: [String; 4],
    pub physical_memory_addr: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiCoeDetails {
    pub raw: String,
    pub enable_sdo: bool,
    pub enable_sdo_info: bool,
    pub enable_pdo_assign: bool,
    pub enable_pdo_configuration: bool,
    pub enable_upload_at_startup: bool,
    pub enable_sdo_complete_access: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiSyncManagerDecoded {
    pub index: usize,
    pub physical_start_address: String,
    pub physical_start_u16: u16,
    pub length: u16,
    pub control_register: String,
    pub status_register: String,
    pub enable_byte: String,
    pub enabled: bool,
    pub sm_type: u8,
    pub sm_type_name: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiPdoEntryDecoded {
    pub index: String,
    pub index_u16: u16,
    pub subindex: u8,
    pub name_idx: u8,
    pub name: Option<String>,
    pub data_type: u16,
    pub data_type_name: &'static str,
    pub bit_length: u8,
    pub bit_offset: usize,
    pub flags: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiPdoDecoded {
    pub direction: &'static str,
    pub pdo_index: String,
    pub pdo_index_u16: u16,
    pub entry_count: u8,
    pub sync_manager: i16,
    pub dc_sync: u8,
    pub name_idx: u8,
    pub name: Option<String>,
    pub flags: u16,
    pub total_bits: usize,
    pub entries: Vec<SiiPdoEntryDecoded>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiDcModeDecoded {
    pub cycle_time_0_ns: u32,
    pub shift_time_0_ns: i32,
    pub shift_time_1_ns: i32,
    pub sync1_cycle_factor: i16,
    pub assign_activate: String,
    pub sync0_cycle_factor: i16,
    pub name_idx: u8,
    pub name: Option<String>,
    pub desc_idx: u8,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SiiCategoriesDecoded {
    pub category_headers: Vec<SiiCategoryHeaderInfo>,
    pub strings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub general: Option<SiiGeneralDecoded>,
    pub fmmus: Vec<String>,
    pub sync_managers: Vec<SiiSyncManagerDecoded>,
    pub tx_pdos: Vec<SiiPdoDecoded>,
    pub rx_pdos: Vec<SiiPdoDecoded>,
    pub dc_modes: Vec<SiiDcModeDecoded>,
    pub terminator_found: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiDecodedImage {
    pub actual_size_bytes: usize,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_error: Option<String>,
    pub header: SiiHeaderDecoded,
    pub categories: SiiCategoriesDecoded,
}

pub fn sii_category_name(code: u16) -> &'static str {
    match code & 0x7FFF {
        0 => "NOP",
        10 => "Strings",
        20 => "DataTypes",
        30 => "General",
        40 => "FMMU",
        41 => "SyncM",
        42 => "FMMUx",
        43 => "SyncUnit",
        50 => "TxPDO",
        51 => "RxPDO",
        60 => "DC",
        0x7FFF => "End",
        _ => "Vendor/Custom",
    }
}

pub fn parse_sii_image(data: &[u8]) -> Result<SiiDecodedImage> {
    if data.len() < SII_MIN_SIZE {
        return Err(CliError::Format(format!(
            "SII buffer too short ({} bytes < {SII_MIN_SIZE} minimum)",
            data.len()
        )));
    }
    let validation_error = sii_validate(data).err().map(|e| e.to_string());
    let expected_crc = sii_crc8(&data[0..14]);
    let actual_crc = data[14];
    let mbx_proto_word = sii_le16(&data[0x38..0x3A]);
    let mut mbx_protocols = Vec::new();
    if (mbx_proto_word & 0x0001) != 0 {
        mbx_protocols.push("AoE");
    }
    if (mbx_proto_word & 0x0002) != 0 {
        mbx_protocols.push("EoE");
    }
    if (mbx_proto_word & 0x0004) != 0 {
        mbx_protocols.push("CoE");
    }
    if (mbx_proto_word & 0x0008) != 0 {
        mbx_protocols.push("FoE");
    }
    if (mbx_proto_word & 0x0010) != 0 {
        mbx_protocols.push("SoE");
    }
    if (mbx_proto_word & 0x0020) != 0 {
        mbx_protocols.push("VoE");
    }

    let alias = sii_le16(&data[0x08..0x0A]);
    let vendor_id = sii_le32(&data[0x10..0x14]);
    let product_code = sii_le32(&data[0x14..0x18]);
    let revision = sii_le32(&data[0x18..0x1C]);
    let serial = sii_le32(&data[0x1C..0x20]);
    let size_kbit = sii_le16(&data[0x7C..0x7E]);

    let header = SiiHeaderDecoded {
        pdi_control: format!("0x{:04x}", sii_le16(&data[0x00..0x02])),
        pdi_configuration: format!("0x{:04x}", sii_le16(&data[0x02..0x04])),
        sync_impulse_len_ns: (sii_le16(&data[0x04..0x06]) as u32) * 10,
        pdi_configuration_2: format!("0x{:04x}", sii_le16(&data[0x06..0x08])),
        configured_station_alias: alias,
        configured_station_alias_hex: format!("0x{alias:04x}"),
        crc_byte: format!("0x{actual_crc:02x}"),
        crc_expected: format!("0x{expected_crc:02x}"),
        crc_ok: actual_crc == expected_crc,
        vendor_id,
        vendor_id_hex: format!("0x{vendor_id:08x}"),
        product_code,
        product_code_hex: format!("0x{product_code:08x}"),
        revision_number: revision,
        revision_number_hex: format!("0x{revision:08x}"),
        serial_number: serial,
        serial_number_hex: format!("0x{serial:08x}"),
        bootstrap_rx_mbx_offset: format!("0x{:04x}", sii_le16(&data[0x28..0x2A])),
        bootstrap_rx_mbx_size: sii_le16(&data[0x2A..0x2C]),
        bootstrap_tx_mbx_offset: format!("0x{:04x}", sii_le16(&data[0x2C..0x2E])),
        bootstrap_tx_mbx_size: sii_le16(&data[0x2E..0x30]),
        std_rx_mbx_offset: format!("0x{:04x}", sii_le16(&data[0x30..0x32])),
        std_rx_mbx_size: sii_le16(&data[0x32..0x34]),
        std_tx_mbx_offset: format!("0x{:04x}", sii_le16(&data[0x34..0x36])),
        std_tx_mbx_size: sii_le16(&data[0x36..0x38]),
        mbx_protocol_flags: format!("0x{mbx_proto_word:04x}"),
        mbx_protocols,
        size_kbit_minus_1: size_kbit,
        declared_size_bytes: sii_declared_size(data),
        version: sii_le16(&data[0x7E..0x80]),
    };

    let categories = parse_sii_categories(data);

    Ok(SiiDecodedImage {
        actual_size_bytes: data.len(),
        valid: validation_error.is_none(),
        validation_error,
        header,
        categories,
    })
}

fn parse_sii_categories(data: &[u8]) -> SiiCategoriesDecoded {
    let mut out = SiiCategoriesDecoded::default();
    if data.len() <= SII_CATEGORY_OFFSET {
        return out;
    }

    // First pass: collect raw category slices so Strings (cat 10) is available even if ordered later
    let mut raw_slices: Vec<(u16, usize, &[u8])> = Vec::new();
    let mut pos = SII_CATEGORY_OFFSET;
    while pos + 2 <= data.len() {
        let cat_type = sii_le16(&data[pos..pos + 2]);
        if cat_type == 0xFFFF {
            out.terminator_found = true;
            break;
        }
        if pos + 4 > data.len() {
            break;
        }
        let word_len = sii_le16(&data[pos + 2..pos + 4]);
        let byte_len = (word_len as usize) * 2;
        let body_start = pos + 4;
        let body_end = (body_start + byte_len).min(data.len());
        out.category_headers.push(SiiCategoryHeaderInfo {
            category_code: cat_type & 0x7FFF,
            category_hex: format!("0x{cat_type:04x}"),
            category_name: sii_category_name(cat_type),
            byte_offset: pos,
            word_length: word_len,
            byte_length: byte_len,
        });
        raw_slices.push((cat_type & 0x7FFF, pos, &data[body_start..body_end]));
        if body_start + byte_len > data.len() {
            break;
        }
        pos = body_start + byte_len;
    }

    // Parse Strings (10) first
    for &(cat, _, body) in &raw_slices {
        if cat == 10 && !body.is_empty() {
            let count = body[0] as usize;
            let mut idx = 1usize;
            for _ in 0..count {
                if idx >= body.len() {
                    break;
                }
                let slen = body[idx] as usize;
                idx += 1;
                let end = (idx + slen).min(body.len());
                let raw_str = &body[idx..end];
                let decoded = match std::str::from_utf8(raw_str) {
                    Ok(utf8) => utf8.to_string(),
                    Err(_) => crate::esi::xml::decode_cp1252_latin1(raw_str),
                };
                let s = decoded.trim_end_matches('\0').to_string();
                out.strings.push(s);
                idx = end;
            }
        }
    }

    let resolve_str = |idx: u8, strings: &[String]| -> Option<String> {
        if idx == 0 {
            None
        } else {
            strings.get((idx as usize) - 1).cloned()
        }
    };

    // Parse remaining categories
    for &(cat, _, body) in &raw_slices {
        match cat {
            30 if body.len() >= 16 => {
                let group_idx = body[0];
                let image_idx = body[1];
                let order_idx = body[2];
                let name_idx = body[3];
                let coe = body.get(5).copied().unwrap_or(0);
                let foe = body.get(6).copied().unwrap_or(0);
                let eoe = body.get(7).copied().unwrap_or(0);
                let soe = body.get(8).copied().unwrap_or(0);
                let ds402 = body.get(9).copied().unwrap_or(0);
                let sysman = body.get(10).copied().unwrap_or(0);
                let flags = body.get(11).copied().unwrap_or(0);
                let current_ma = if body.len() >= 14 {
                    i16::from_le_bytes([body[12], body[13]])
                } else {
                    0
                };
                let port_word = if body.len() >= 18 {
                    sii_le16(&body[16..18])
                } else {
                    0
                };
                let port_type_str = |nibble: u16| -> String {
                    match nibble & 0x0F {
                        0x00 => "NotImplemented".into(),
                        0x01 => "MII".into(),
                        0x02 => "Reserved".into(),
                        0x03 => "EBUS".into(),
                        0x04 => "FastHotConnect".into(),
                        other => format!("0x{other:x}"),
                    }
                };
                let phys_mem = if body.len() >= 20 {
                    sii_le16(&body[18..20])
                } else {
                    0
                };
                out.general = Some(SiiGeneralDecoded {
                    group_idx,
                    group_name: resolve_str(group_idx, &out.strings),
                    image_idx,
                    image_name: resolve_str(image_idx, &out.strings),
                    order_idx,
                    order_name: resolve_str(order_idx, &out.strings),
                    name_idx,
                    device_name: resolve_str(name_idx, &out.strings),
                    coe_details: SiiCoeDetails {
                        raw: format!("0x{coe:02x}"),
                        enable_sdo: (coe & 0x01) != 0,
                        enable_sdo_info: (coe & 0x02) != 0,
                        enable_pdo_assign: (coe & 0x04) != 0,
                        enable_pdo_configuration: (coe & 0x08) != 0,
                        enable_upload_at_startup: (coe & 0x10) != 0,
                        enable_sdo_complete_access: (coe & 0x20) != 0,
                    },
                    foe_enabled: (foe & 0x01) != 0,
                    eoe_enabled: (eoe & 0x01) != 0,
                    soe_channels: soe,
                    ds402_channels: ds402,
                    sysman_class: sysman,
                    flags,
                    current_on_ebus_ma: current_ma,
                    physical_ports: [
                        port_type_str(port_word),
                        port_type_str(port_word >> 4),
                        port_type_str(port_word >> 8),
                        port_type_str(port_word >> 12),
                    ],
                    physical_memory_addr: format!("0x{phys_mem:04x}"),
                });
            }
            40 => {
                for &b in body {
                    if b == 0xFF {
                        break;
                    }
                    let usage = match b {
                        0x00 => "Unused",
                        0x01 => "Outputs",
                        0x02 => "Inputs",
                        0x03 => "SyncMStatus",
                        _ => "Reserved",
                    };
                    out.fmmus.push(usage.to_string());
                }
            }
            41 => {
                for (i, chunk) in body.as_chunks::<8>().0.iter().enumerate() {
                    let phys = sii_le16(&chunk[0..2]);
                    let len = sii_le16(&chunk[2..4]);
                    let creg = chunk[4];
                    let sreg = chunk[5];
                    let enable = chunk[6];
                    let sm_type = chunk[7];
                    let sm_type_name = match sm_type {
                        0 => "Unused",
                        1 => "MbxOut (Master->Slave)",
                        2 => "MbxIn (Slave->Master)",
                        3 => "Outputs (RxPDO)",
                        4 => "Inputs (TxPDO)",
                        _ => "Other",
                    };
                    out.sync_managers.push(SiiSyncManagerDecoded {
                        index: i,
                        physical_start_address: format!("0x{phys:04x}"),
                        physical_start_u16: phys,
                        length: len,
                        control_register: format!("0x{creg:02x}"),
                        status_register: format!("0x{sreg:02x}"),
                        enable_byte: format!("0x{enable:02x}"),
                        enabled: (enable & 0x01) != 0,
                        sm_type,
                        sm_type_name,
                    });
                }
            }
            50 | 51 => {
                let direction = if cat == 50 { "TxPDO" } else { "RxPDO" };
                let pdos = parse_pdo_category(body, direction, &out.strings);
                if cat == 50 {
                    out.tx_pdos.extend(pdos);
                } else {
                    out.rx_pdos.extend(pdos);
                }
            }
            60 => {
                for chunk in body.chunks(24) {
                    if chunk.len() < 24 {
                        break;
                    }
                    let cycle0 = sii_le32(&chunk[0..4]);
                    let shift0 = sii_le32(&chunk[4..8]) as i32;
                    let shift1 = sii_le32(&chunk[8..12]) as i32;
                    let sync1_fac = sii_le16(&chunk[12..14]) as i16;
                    let assign_act = sii_le16(&chunk[14..16]);
                    let sync0_fac = sii_le16(&chunk[16..18]) as i16;
                    let name_idx = chunk[18];
                    let desc_idx = chunk[19];
                    out.dc_modes.push(SiiDcModeDecoded {
                        cycle_time_0_ns: cycle0,
                        shift_time_0_ns: shift0,
                        shift_time_1_ns: shift1,
                        sync1_cycle_factor: sync1_fac,
                        assign_activate: format!("0x{assign_act:04x}"),
                        sync0_cycle_factor: sync0_fac,
                        name_idx,
                        name: resolve_str(name_idx, &out.strings),
                        desc_idx,
                        description: resolve_str(desc_idx, &out.strings),
                    });
                }
            }
            _ => {}
        }
    }

    out
}

fn parse_pdo_category(
    body: &[u8],
    direction: &'static str,
    strings: &[String],
) -> Vec<SiiPdoDecoded> {
    let mut pdos = Vec::new();
    let mut pos = 0usize;
    let mut sm_bit_offsets: std::collections::BTreeMap<i16, usize> =
        std::collections::BTreeMap::new();

    while pos + 8 <= body.len() {
        let pdo_index = sii_le16(&body[pos..pos + 2]);
        let entry_count = body[pos + 2];
        let sync_m = body[pos + 3] as i8 as i16;
        let dc_sync = body[pos + 4];
        let name_idx = body[pos + 5];
        let flags = sii_le16(&body[pos + 6..pos + 8]);
        pos += 8;

        let mut entries = Vec::new();
        let mut pdo_bits = 0usize;
        for _ in 0..entry_count {
            if pos + 8 > body.len() {
                break;
            }
            let e_idx = sii_le16(&body[pos..pos + 2]);
            let e_sub = body[pos + 2];
            let e_name_idx = body[pos + 3];
            let e_dt = body[pos + 4];
            let e_bit_len = body[pos + 5];
            let e_flags = sii_le16(&body[pos + 6..pos + 8]);
            pos += 8;

            let bit_off = if sync_m >= 0 {
                let slot = sm_bit_offsets.entry(sync_m).or_insert(0);
                let cur = *slot;
                *slot += e_bit_len as usize;
                cur
            } else {
                pdo_bits
            };
            pdo_bits += e_bit_len as usize;

            entries.push(SiiPdoEntryDecoded {
                index: format!("0x{e_idx:04x}"),
                index_u16: e_idx,
                subindex: e_sub,
                name_idx: e_name_idx,
                name: if e_name_idx == 0 {
                    None
                } else {
                    strings.get((e_name_idx as usize) - 1).cloned()
                },
                data_type: e_dt as u16,
                data_type_name: ect_datatype_name(e_dt as u16),
                bit_length: e_bit_len,
                bit_offset: bit_off,
                flags: e_flags,
            });
        }

        pdos.push(SiiPdoDecoded {
            direction,
            pdo_index: format!("0x{pdo_index:04x}"),
            pdo_index_u16: pdo_index,
            entry_count,
            sync_manager: sync_m,
            dc_sync,
            name_idx,
            name: if name_idx == 0 {
                None
            } else {
                strings.get((name_idx as usize) - 1).cloned()
            },
            flags,
            total_bits: pdo_bits,
            entries,
        });
    }
    pdos
}

#[derive(Debug, Clone)]
pub struct SiiPatchSpec {
    pub alias: Option<u16>,
    pub vendor_id: Option<u32>,
    pub product_code: Option<u32>,
    pub revision_number: Option<u32>,
    pub serial_number: Option<u32>,
    pub word_writes: Vec<(usize, u16)>,
    pub recalculate_crc: bool,
}

impl Default for SiiPatchSpec {
    fn default() -> Self {
        Self {
            alias: None,
            vendor_id: None,
            product_code: None,
            revision_number: None,
            serial_number: None,
            word_writes: Vec::new(),
            recalculate_crc: true,
        }
    }
}

pub fn patch_sii_image(input: &[u8], spec: &SiiPatchSpec) -> Result<Vec<u8>> {
    if input.len() < SII_MIN_SIZE || input.len() > SII_MAX_SIZE || (input.len() & 1) != 0 {
        return Err(CliError::Format(format!(
            "cannot patch SII image of invalid size {} bytes",
            input.len()
        )));
    }
    let mut buf = input.to_vec();
    if let Some(alias) = spec.alias {
        buf[0x08..0x0A].copy_from_slice(&alias.to_le_bytes());
    }
    if let Some(vendor) = spec.vendor_id {
        buf[0x10..0x14].copy_from_slice(&vendor.to_le_bytes());
    }
    if let Some(product) = spec.product_code {
        buf[0x14..0x18].copy_from_slice(&product.to_le_bytes());
    }
    if let Some(rev) = spec.revision_number {
        buf[0x18..0x1C].copy_from_slice(&rev.to_le_bytes());
    }
    if let Some(serial) = spec.serial_number {
        buf[0x1C..0x20].copy_from_slice(&serial.to_le_bytes());
    }
    let mut touched_crc_header = spec.alias.is_some();
    let mut explicit_word7 = false;
    for &(word_addr, val) in &spec.word_writes {
        let byte_off = word_addr
            .checked_mul(2)
            .ok_or_else(|| CliError::Format("word address overflow".into()))?;
        if byte_off + 2 > buf.len() {
            return Err(CliError::Format(format!(
                "word address 0x{word_addr:04x} (byte 0x{byte_off:04x}) exceeds image size ({} bytes)",
                buf.len()
            )));
        }
        if word_addr <= 6 {
            touched_crc_header = true;
        } else if word_addr == 7 {
            explicit_word7 = true;
        }
        buf[byte_off..byte_off + 2].copy_from_slice(&val.to_le_bytes());
    }
    if (spec.recalculate_crc || touched_crc_header) && !(explicit_word7 && !spec.recalculate_crc) {
        buf[14] = sii_crc8(&buf[0..14]);
    }
    sii_validate(&buf)?;
    Ok(buf)
}

/// SII binary compilation profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiiBuildProfile {
    /// Beckhoff SSC Tool / `ET9300Utilities.EsiSiiHandler` compatible layout:
    /// General string order `[GroupType, Image, Type, Name]`, includes assigned PDO categories,
    /// and emits a 24-byte zero DC category when no `<OpMode>` is defined.
    #[default]
    Ssc,
    /// Compact ETG.2010 layout:
    /// General string order `[Type, Name, GroupType, Image]`, omits TxPDO/RxPDO categories when
    /// CoE (`0x0004`) is enabled, and omits DC category when no `<OpMode>` is defined.
    Minimal,
}

/// Deduplicated 1-based ETG.2010 SII `Strings` (Category 10) table with byte-budget enforcement.
#[derive(Debug, Clone, Default)]
pub struct SiiStringTable {
    encoded: Vec<Vec<u8>>,
}

impl SiiStringTable {
    pub fn new() -> Self {
        Self {
            encoded: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }

    pub fn len(&self) -> usize {
        self.encoded.len()
    }

    pub fn intern(&mut self, value: &str) -> u8 {
        self.intern_batch_within_budget(&[value], 0, None)[0]
    }

    /// Total encoded TLV byte size (including 4-byte category header and even-byte padding)
    /// when emitted as Category 10 (`Strings`), or `0` if empty.
    pub fn tlv_byte_len(&self) -> usize {
        if self.encoded.is_empty() {
            return 0;
        }
        let raw_body_len = 1usize + self.encoded.iter().map(|b| 1 + b.len()).sum::<usize>();
        let padded_body_len = (raw_body_len + 1) & !1;
        4 + padded_body_len
    }

    /// Encode Category 10 (`Strings`) body bytes (padded with `0x00` to an even byte count).
    pub fn encode_body(&self) -> Vec<u8> {
        if self.encoded.is_empty() {
            return Vec::new();
        }
        let mut body = Vec::new();
        body.push(self.encoded.len() as u8);
        for bytes in &self.encoded {
            let slen = bytes.len().min(255);
            body.push(slen as u8);
            body.extend_from_slice(&bytes[..slen]);
        }
        if (body.len() & 1) != 0 {
            body.push(0x00);
        }
        body
    }

    /// Atomically intern a batch of category strings only if the resulting total SII image
    /// size stays within `max_total_bytes` (given `base_non_string_bytes`).
    /// If the batch would overflow `max_total_bytes` or exceed 255 strings, `self` is unchanged
    /// and all returned indices are `0`.
    pub fn intern_batch_within_budget(
        &mut self,
        candidates: &[&str],
        base_non_string_bytes: usize,
        max_total_bytes: Option<usize>,
    ) -> Vec<u8> {
        let saved_len = self.encoded.len();
        let mut indices = Vec::with_capacity(candidates.len());
        for &s in candidates {
            let bytes = crate::esi::xml::encode_cp1252_latin1_trunc255(s);
            if bytes.is_empty() {
                indices.push(0);
                continue;
            }
            if let Some(pos) = self.encoded.iter().position(|existing| existing == &bytes) {
                indices.push((pos + 1) as u8);
            } else if self.encoded.len() >= 255 {
                if max_total_bytes.is_some() {
                    self.encoded.truncate(saved_len);
                    return vec![0u8; candidates.len()];
                }
                indices.push(0);
            } else {
                self.encoded.push(bytes);
                indices.push(self.encoded.len() as u8);
            }
        }
        if let Some(budget) = max_total_bytes {
            if base_non_string_bytes + self.tlv_byte_len() > budget {
                self.encoded.truncate(saved_len);
                return vec![0u8; candidates.len()];
            }
        }
        indices
    }
}

/// Input specification for SII Category 30 (`General`, 32 bytes / 16 words).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiiGeneralSpec {
    pub group_type: String,
    pub image_name: String,
    pub order_code: String,
    pub device_name: String,
    pub coe_details: u8,
    pub foe_details: u8,
    pub eoe_details: u8,
    pub soe_channels: u8,
    pub ds402_channels: u8,
    pub sysman_class: u8,
    pub flags: u8,
    pub current_on_ebus_ma: i16,
    pub physical_ports_word: u16,
    pub physical_memory_address: u16,
}

/// Input specification for an entry in SII Category 41 (`SyncM`, 8 bytes per SM).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct SiiSyncMInput {
    pub physical_start_address: u16,
    pub length: u16,
    pub control_register: u8,
    pub status_register: u8,
    pub enable_byte: u8,
    pub sm_type: u8,
}

/// Input specification for a PDO entry inside SII Category 50 (`TxPDO`) or 51 (`RxPDO`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiiPdoEntrySpec {
    pub index: u16,
    pub subindex: u8,
    pub name: String,
    pub data_type: u8,
    pub bit_len: u8,
    pub flags: u16,
}

/// Input specification for a PDO mapping inside SII Category 50 (`TxPDO`) or 51 (`RxPDO`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiiPdoSpec {
    pub index: u16,
    pub sync_manager: i8,
    pub dc_sync: u8,
    pub name: String,
    pub flags: u16,
    pub entries: Vec<SiiPdoEntrySpec>,
}

/// Input specification for a Distributed Clocks mode inside SII Category 60 (`DC`, 24 bytes).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SiiDcOpModeSpec {
    pub name: String,
    pub description: String,
    pub cycle_time_0_ns: u32,
    pub shift_time_0_ns: i32,
    pub shift_time_1_ns: i32,
    pub sync1_cycle_factor: i16,
    pub assign_activate: u16,
    pub sync0_cycle_factor: i16,
}

/// Complete specification to encode a valid ETG.2010 SII EEPROM binary image.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiiBuildSpec {
    /// First 14 bytes of ESC configuration area (`0x00..0x0E`, words `0..6`).
    pub config_data_14: [u8; 14],
    pub configured_station_alias: Option<u16>,
    pub vendor_id: u32,
    pub product_code: u32,
    pub revision_number: u32,
    pub serial_number: u32,
    /// `[rx_offset, rx_size, tx_offset, tx_size]` at `0x28..0x30`.
    pub bootstrap_mailbox: [u16; 4],
    /// `[rx_offset, rx_size, tx_offset, tx_size]` at `0x30..0x38`.
    pub std_mailbox: [u16; 4],
    /// Mailbox protocol bitmask at `0x38..0x3A` (`0x01=AoE, 0x02=EoE, 0x04=CoE, 0x08=FoE, 0x10=SoE, 0x20=VoE`).
    pub mbx_protocols: u16,
    /// Declared EEPROM size in bytes (e.g. `2048` from `<Eeprom><ByteSize>`).
    pub declared_byte_size: usize,
    /// Enforce string-table category priority byte budget (`General -> DC -> TxPDO -> RxPDO`).
    pub respect_byte_size_budget: bool,
    /// Automatically grow EEPROM size (rounded up to 128-byte boundary) so all categories and strings fit.
    pub auto_grow_size: bool,
    pub profile: SiiBuildProfile,
    pub general: Option<SiiGeneralSpec>,
    /// FMMU usage codes (`1=Outputs`, `2=Inputs`, `3=MBoxState`).
    pub fmmus: Vec<u8>,
    pub sync_managers: Vec<SiiSyncMInput>,
    pub tx_pdos: Vec<SiiPdoSpec>,
    pub rx_pdos: Vec<SiiPdoSpec>,
    pub dc_modes: Vec<SiiDcOpModeSpec>,
}

impl Default for SiiBuildSpec {
    fn default() -> Self {
        Self {
            config_data_14: [0u8; 14],
            configured_station_alias: None,
            vendor_id: 0,
            product_code: 0,
            revision_number: 0,
            serial_number: 0,
            bootstrap_mailbox: [0u16; 4],
            std_mailbox: [0u16; 4],
            mbx_protocols: 0,
            declared_byte_size: 2048,
            respect_byte_size_budget: true,
            auto_grow_size: false,
            profile: SiiBuildProfile::Ssc,
            general: None,
            fmmus: Vec::new(),
            sync_managers: Vec::new(),
            tx_pdos: Vec::new(),
            rx_pdos: Vec::new(),
            dc_modes: Vec::new(),
        }
    }
}

fn push_sii_tlv(out: &mut Vec<u8>, cat_code: u16, body: &[u8], pad_byte: u8) -> Result<()> {
    let padded_len = (body.len() + 1) & !1;
    let word_len = u16::try_from(padded_len / 2).map_err(|_| {
        CliError::Format(format!(
            "SII category {cat_code} body ({padded_len} bytes) exceeds 65535 words"
        ))
    })?;
    out.extend_from_slice(&cat_code.to_le_bytes());
    out.extend_from_slice(&word_len.to_le_bytes());
    out.extend_from_slice(body);
    if padded_len > body.len() {
        out.push(pad_byte);
    }
    Ok(())
}

fn encode_pdo_list(pdos: &[SiiPdoSpec], string_indices: &[u8]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    let mut str_cursor = 0usize;
    for pdo in pdos {
        let entry_cnt = u8::try_from(pdo.entries.len()).map_err(|_| {
            CliError::Format(format!(
                "PDO 0x{:04X} has {} entries (exceeds SII u8 limit 255)",
                pdo.index,
                pdo.entries.len()
            ))
        })?;
        let pdo_name_idx = string_indices.get(str_cursor).copied().unwrap_or(0);
        str_cursor += 1;

        body.extend_from_slice(&pdo.index.to_le_bytes());
        body.push(entry_cnt);
        body.push(pdo.sync_manager as u8);
        body.push(pdo.dc_sync);
        body.push(pdo_name_idx);
        body.extend_from_slice(&pdo.flags.to_le_bytes());

        for entry in &pdo.entries {
            let entry_name_idx = string_indices.get(str_cursor).copied().unwrap_or(0);
            str_cursor += 1;
            body.extend_from_slice(&entry.index.to_le_bytes());
            body.push(entry.subindex);
            body.push(entry_name_idx);
            body.push(entry.data_type);
            body.push(entry.bit_len);
            body.extend_from_slice(&entry.flags.to_le_bytes());
        }
    }
    Ok(body)
}

fn compute_non_string_bytes(
    spec: &SiiBuildSpec,
    active_tx_pdos: &[SiiPdoSpec],
    active_rx_pdos: &[SiiPdoSpec],
    emit_zero_dc: bool,
) -> usize {
    let mut bytes = SII_CATEGORY_OFFSET + 2; // 128B header + 2B 0xFFFF
    if spec.general.is_some() {
        bytes += 4 + 32;
    }
    let emit_empty_fmmu_sm = spec.profile == SiiBuildProfile::Ssc;
    if !spec.fmmus.is_empty() || emit_empty_fmmu_sm {
        bytes += 4 + ((spec.fmmus.len() + 1) & !1);
    }
    if !spec.sync_managers.is_empty() || emit_empty_fmmu_sm {
        bytes += 4 + 8 * spec.sync_managers.len();
    }
    if !active_tx_pdos.is_empty() {
        let tx_body: usize = active_tx_pdos.iter().map(|p| 8 + 8 * p.entries.len()).sum();
        bytes += 4 + tx_body;
    }
    if !active_rx_pdos.is_empty() {
        let rx_body: usize = active_rx_pdos.iter().map(|p| 8 + 8 * p.entries.len()).sum();
        bytes += 4 + rx_body;
    }
    if !spec.dc_modes.is_empty() {
        bytes += 4 + 24 * spec.dc_modes.len();
    } else if emit_zero_dc {
        bytes += 4 + 24;
    }
    bytes
}

pub(crate) fn sii_spec_omits_coe_pdos(spec: &SiiBuildSpec) -> bool {
    let has_coe = (spec.mbx_protocols & 0x0004) != 0;
    if !has_coe {
        return false;
    }
    if spec.profile == SiiBuildProfile::Minimal {
        return true;
    }
    if !spec.auto_grow_size && spec.respect_byte_size_budget {
        let declared_aligned = spec
            .declared_byte_size
            .max(SII_MIN_SIZE)
            .next_multiple_of(128);
        let emit_zero_dc = spec.profile == SiiBuildProfile::Ssc && spec.dc_modes.is_empty();
        let with_pdos = compute_non_string_bytes(spec, &spec.tx_pdos, &spec.rx_pdos, emit_zero_dc);
        if with_pdos > declared_aligned {
            return true;
        }
    }
    false
}

/// Encode a complete, CRC-validated ETG.2010 SII EEPROM binary image from `SiiBuildSpec`.
pub fn encode_sii_image(spec: &SiiBuildSpec) -> Result<Vec<u8>> {
    let declared_aligned = spec
        .declared_byte_size
        .max(SII_MIN_SIZE)
        .next_multiple_of(128);
    if !spec.auto_grow_size && declared_aligned > SII_MAX_SIZE {
        return Err(CliError::Format(format!(
            "declared SII EEPROM size ({declared_aligned} bytes) exceeds SII_MAX_SIZE ({SII_MAX_SIZE} bytes)"
        )));
    }

    let omit_coe_pdos = sii_spec_omits_coe_pdos(spec);
    let active_tx_pdos: &[SiiPdoSpec] = if omit_coe_pdos { &[] } else { &spec.tx_pdos };
    let active_rx_pdos: &[SiiPdoSpec] = if omit_coe_pdos { &[] } else { &spec.rx_pdos };
    let emit_zero_dc = spec.profile == SiiBuildProfile::Ssc && spec.dc_modes.is_empty();
    let base_non_string_bytes =
        compute_non_string_bytes(spec, active_tx_pdos, active_rx_pdos, emit_zero_dc);

    if !spec.auto_grow_size && base_non_string_bytes > declared_aligned {
        return Err(CliError::Format(format!(
            "required SII category data ({base_non_string_bytes} bytes even without strings) exceeds declared EEPROM ByteSize ({declared_aligned} bytes); pass --ignore-eeprom-size or increase --eeprom-size"
        )));
    }

    let string_budget = if !spec.auto_grow_size && spec.respect_byte_size_budget {
        Some(declared_aligned)
    } else {
        None
    };

    // Intern strings in Beckhoff ET9300Utilities category priority order:
    // 1. General -> 2. DC -> 3. TxPDO -> 4. RxPDO.
    // Note: ET9300Utilities.EsiSiiHandler.GetEEPROMContent checks each category's unmerged
    // `GetRequiredStringCatBytes()` against `availableBytes` (`byteSize - 2 - nonStringBytes`)
    // before calling `AddStringReferences`, dropping an entire category's strings (e.g.
    // Beckhoff EP3048-0002's 8 repeated TxPDO channels) when its unmerged byte count exceeds
    // `availableBytes`, even if deduplication would have made them fit.
    let mut str_table = SiiStringTable::new();
    let mut ssc_unmerged_avail = string_budget.map(|b| b.saturating_sub(base_non_string_bytes));
    let raw_req_sum = |items: &[&str]| -> usize {
        items
            .iter()
            .map(|s| {
                let enc = crate::esi::xml::encode_cp1252_latin1_trunc255(s);
                if enc.is_empty() {
                    0
                } else {
                    enc.len() + 1
                }
            })
            .sum()
    };

    let (gen_group_idx, gen_img_idx, gen_order_idx, gen_name_idx) = if let Some(g) = &spec.general {
        match spec.profile {
            SiiBuildProfile::Ssc => {
                let candidates = [
                    g.group_type.as_str(),
                    g.image_name.as_str(),
                    g.order_code.as_str(),
                    g.device_name.as_str(),
                ];
                let raw_req = raw_req_sum(&candidates);
                let idxs = if ssc_unmerged_avail.is_some_and(|avail| raw_req > avail) {
                    vec![0u8; candidates.len()]
                } else {
                    let res = str_table.intern_batch_within_budget(
                        &candidates,
                        base_non_string_bytes,
                        string_budget,
                    );
                    if res.iter().any(|&idx| idx != 0) {
                        if let Some(ref mut avail) = ssc_unmerged_avail {
                            *avail = avail.saturating_sub(raw_req);
                        }
                    }
                    res
                };
                (idxs[0], idxs[1], idxs[2], idxs[3])
            }
            SiiBuildProfile::Minimal => {
                let candidates = [
                    g.order_code.as_str(),
                    g.device_name.as_str(),
                    g.group_type.as_str(),
                    g.image_name.as_str(),
                ];
                let idxs = str_table.intern_batch_within_budget(
                    &candidates,
                    base_non_string_bytes,
                    string_budget,
                );
                (idxs[2], idxs[3], idxs[0], idxs[1])
            }
        }
    } else {
        (0, 0, 0, 0)
    };

    let dc_str_indices = if !spec.dc_modes.is_empty() {
        let mut dc_candidates = Vec::with_capacity(spec.dc_modes.len() * 2);
        let mut dc_raw_req = 0usize;
        for m in &spec.dc_modes {
            dc_candidates.push(m.name.as_str());
            dc_candidates.push(m.description.as_str());
            let name_enc = crate::esi::xml::encode_cp1252_latin1_trunc255(&m.name);
            let desc_enc = crate::esi::xml::encode_cp1252_latin1_trunc255(&m.description);
            if !name_enc.is_empty() {
                dc_raw_req += name_enc.len() + 1;
            }
            dc_raw_req += desc_enc.len() + 1;
        }
        if spec.profile == SiiBuildProfile::Ssc
            && ssc_unmerged_avail.is_some_and(|avail| dc_raw_req > avail)
        {
            vec![0u8; dc_candidates.len()]
        } else {
            let res = str_table.intern_batch_within_budget(
                &dc_candidates,
                base_non_string_bytes,
                string_budget,
            );
            if spec.profile == SiiBuildProfile::Ssc
                && (res.iter().any(|&idx| idx != 0) || dc_candidates.iter().all(|s| s.is_empty()))
            {
                if let Some(ref mut avail) = ssc_unmerged_avail {
                    *avail = avail.saturating_sub(dc_raw_req);
                }
            }
            res
        }
    } else {
        let dc_empty_req = usize::from(spec.profile == SiiBuildProfile::Ssc);
        if let Some(ref mut avail) = ssc_unmerged_avail {
            *avail = avail.saturating_sub(dc_empty_req);
        }
        Vec::new()
    };

    let tx_str_indices = if !active_tx_pdos.is_empty() {
        let mut tx_candidates = Vec::new();
        for p in active_tx_pdos {
            tx_candidates.push(p.name.as_str());
            for e in &p.entries {
                tx_candidates.push(e.name.as_str());
            }
        }
        let raw_req = raw_req_sum(&tx_candidates);
        if spec.profile == SiiBuildProfile::Ssc
            && ssc_unmerged_avail.is_some_and(|avail| raw_req > avail)
        {
            vec![0u8; tx_candidates.len()]
        } else {
            let res = str_table.intern_batch_within_budget(
                &tx_candidates,
                base_non_string_bytes,
                string_budget,
            );
            if spec.profile == SiiBuildProfile::Ssc && res.iter().any(|&idx| idx != 0) {
                if let Some(ref mut avail) = ssc_unmerged_avail {
                    *avail = avail.saturating_sub(raw_req);
                }
            }
            res
        }
    } else {
        Vec::new()
    };

    let rx_str_indices = if !active_rx_pdos.is_empty() {
        let mut rx_candidates = Vec::new();
        for p in active_rx_pdos {
            rx_candidates.push(p.name.as_str());
            for e in &p.entries {
                rx_candidates.push(e.name.as_str());
            }
        }
        let raw_req = raw_req_sum(&rx_candidates);
        if spec.profile == SiiBuildProfile::Ssc
            && ssc_unmerged_avail.is_some_and(|avail| raw_req > avail)
        {
            vec![0u8; rx_candidates.len()]
        } else {
            str_table.intern_batch_within_budget(
                &rx_candidates,
                base_non_string_bytes,
                string_budget,
            )
        }
    } else {
        Vec::new()
    };

    let required_bytes = base_non_string_bytes + str_table.tlv_byte_len();
    let total_bytes = if spec.auto_grow_size {
        required_bytes
            .max(declared_aligned)
            .max(SII_MIN_SIZE)
            .next_multiple_of(128)
    } else {
        if required_bytes > declared_aligned {
            return Err(CliError::Format(format!(
                "encoded SII image ({required_bytes} bytes) exceeds declared EEPROM ByteSize ({declared_aligned} bytes); pass --ignore-eeprom-size or increase --eeprom-size"
            )));
        }
        declared_aligned
    };

    if total_bytes > SII_MAX_SIZE {
        return Err(CliError::Format(format!(
            "encoded SII image ({total_bytes} bytes) exceeds SII_MAX_SIZE ({SII_MAX_SIZE} bytes)"
        )));
    }
    let size_kbit_minus_1 = u16::try_from((total_bytes / 128) - 1).map_err(|_| {
        CliError::Format(format!(
            "encoded SII image ({total_bytes} bytes) overflows 16-bit SII size field"
        ))
    })?;

    // Build 128-byte header (0x00..0x80)
    let mut out = Vec::with_capacity(total_bytes);
    out.resize(SII_CATEGORY_OFFSET, 0u8);
    out[0..14].copy_from_slice(&spec.config_data_14);
    if let Some(alias) = spec.configured_station_alias {
        out[0x08..0x0A].copy_from_slice(&alias.to_le_bytes());
    }
    out[0x0E] = sii_crc8(&out[0..14]);
    out[0x0F] = 0x00;

    out[0x10..0x14].copy_from_slice(&spec.vendor_id.to_le_bytes());
    out[0x14..0x18].copy_from_slice(&spec.product_code.to_le_bytes());
    out[0x18..0x1C].copy_from_slice(&spec.revision_number.to_le_bytes());
    out[0x1C..0x20].copy_from_slice(&spec.serial_number.to_le_bytes());

    for (i, &w) in spec.bootstrap_mailbox.iter().enumerate() {
        let off = 0x28 + i * 2;
        out[off..off + 2].copy_from_slice(&w.to_le_bytes());
    }
    for (i, &w) in spec.std_mailbox.iter().enumerate() {
        let off = 0x30 + i * 2;
        out[off..off + 2].copy_from_slice(&w.to_le_bytes());
    }
    out[0x38..0x3A].copy_from_slice(&spec.mbx_protocols.to_le_bytes());
    out[0x7C..0x7E].copy_from_slice(&size_kbit_minus_1.to_le_bytes());
    out[0x7E..0x80].copy_from_slice(&1u16.to_le_bytes());

    // Category 10: Strings
    if !str_table.is_empty() {
        let str_body = str_table.encode_body();
        push_sii_tlv(&mut out, 10, &str_body, 0x00)?;
    }

    // Category 30: General (32 bytes = 16 words)
    if let Some(g) = &spec.general {
        let mut gen_body = [0u8; 32];
        gen_body[0] = gen_group_idx;
        gen_body[1] = gen_img_idx;
        gen_body[2] = gen_order_idx;
        gen_body[3] = gen_name_idx;
        gen_body[4] = 0x00;
        gen_body[5] = g.coe_details;
        gen_body[6] = g.foe_details;
        gen_body[7] = g.eoe_details;
        gen_body[8] = g.soe_channels;
        gen_body[9] = g.ds402_channels;
        gen_body[10] = g.sysman_class;
        gen_body[11] = g.flags;
        gen_body[12..14].copy_from_slice(&g.current_on_ebus_ma.to_le_bytes());
        if spec.profile == SiiBuildProfile::Ssc {
            gen_body[14] = gen_group_idx;
        }
        gen_body[16..18].copy_from_slice(&g.physical_ports_word.to_le_bytes());
        gen_body[18..20].copy_from_slice(&g.physical_memory_address.to_le_bytes());
        push_sii_tlv(&mut out, 30, &gen_body, 0x00)?;
    }

    // Category 40: FMMU (pad odd length with 0xFF per ETG.2010 / ET9300Utilities;
    // ET9300Utilities always emits FMMU/SyncM TLV headers in SSC profile even when empty)
    let emit_empty_fmmu_sm = spec.profile == SiiBuildProfile::Ssc;
    if !spec.fmmus.is_empty() || emit_empty_fmmu_sm {
        push_sii_tlv(&mut out, 40, &spec.fmmus, 0xFF)?;
    }

    // Category 41: SyncM (8 bytes per SM)
    if !spec.sync_managers.is_empty() || emit_empty_fmmu_sm {
        let mut sm_body = Vec::with_capacity(spec.sync_managers.len() * 8);
        for sm in &spec.sync_managers {
            sm_body.extend_from_slice(&sm.physical_start_address.to_le_bytes());
            sm_body.extend_from_slice(&sm.length.to_le_bytes());
            sm_body.push(sm.control_register);
            sm_body.push(sm.status_register);
            sm_body.push(sm.enable_byte);
            sm_body.push(sm.sm_type);
        }
        push_sii_tlv(&mut out, 41, &sm_body, 0x00)?;
    }

    // Category 50: TxPDO
    if !active_tx_pdos.is_empty() {
        let tx_body = encode_pdo_list(active_tx_pdos, &tx_str_indices)?;
        push_sii_tlv(&mut out, 50, &tx_body, 0x00)?;
    }

    // Category 51: RxPDO
    if !active_rx_pdos.is_empty() {
        let rx_body = encode_pdo_list(active_rx_pdos, &rx_str_indices)?;
        push_sii_tlv(&mut out, 51, &rx_body, 0x00)?;
    }

    // Category 60: DC (24 bytes per OpMode, or 24-byte zero block in SSC profile)
    if !spec.dc_modes.is_empty() {
        let mut dc_body = Vec::with_capacity(spec.dc_modes.len() * 24);
        for (i, m) in spec.dc_modes.iter().enumerate() {
            let name_idx = dc_str_indices.get(i * 2).copied().unwrap_or(0);
            let desc_idx = dc_str_indices.get(i * 2 + 1).copied().unwrap_or(0);
            dc_body.extend_from_slice(&m.cycle_time_0_ns.to_le_bytes());
            dc_body.extend_from_slice(&m.shift_time_0_ns.to_le_bytes());
            dc_body.extend_from_slice(&m.shift_time_1_ns.to_le_bytes());
            dc_body.extend_from_slice(&m.sync1_cycle_factor.to_le_bytes());
            dc_body.extend_from_slice(&m.assign_activate.to_le_bytes());
            dc_body.extend_from_slice(&m.sync0_cycle_factor.to_le_bytes());
            dc_body.push(name_idx);
            dc_body.push(desc_idx);
            dc_body.extend_from_slice(&[0u8; 4]);
        }
        push_sii_tlv(&mut out, 60, &dc_body, 0x00)?;
    } else if emit_zero_dc {
        push_sii_tlv(&mut out, 60, &[0u8; 24], 0x00)?;
    }

    // End-of-categories marker (0xFFFF) + fill remaining EEPROM capacity with 0xFF
    out.extend_from_slice(&[0xFF, 0xFF]);
    debug_assert_eq!(out.len(), required_bytes);
    if out.len() < total_bytes {
        out.resize(total_bytes, 0xFF);
    }

    sii_validate(&out)?;
    Ok(out)
}

/// Format an SII binary image as a Beckhoff Slave Stack Code (SSC) compatible C header
/// defining `unsigned char aEepromData[] = { ... };` (16 bytes per line).
pub fn format_ssc_eeprom_header(data: &[u8], info_comment: Option<&str>) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(256 + data.len().saturating_mul(6));
    if let Some(comment) = info_comment {
        for line in comment.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                s.push_str("//\n");
            } else {
                s.push_str("// ");
                s.push_str(trimmed);
                s.push('\n');
            }
        }
    } else {
        s.push_str("// Generated by ethercat-cli (Beckhoff SSC compatible SII EEPROM image)\n");
    }
    if data.len() >= SII_MIN_SIZE {
        let _ = writeln!(
            s,
            "// Size: {} bytes | VendorId: 0x{:08X} | ProductCode: 0x{:08X} | RevisionNo: 0x{:08X} | CRC8: 0x{:02X}",
            data.len(),
            sii_le32(&data[0x10..0x14]),
            sii_le32(&data[0x14..0x18]),
            sii_le32(&data[0x18..0x1C]),
            data[0x0E],
        );
    }
    s.push_str("unsigned char aEepromData[] = {\n");
    let total = data.len();
    for (chunk_idx, chunk) in data.chunks(16).enumerate() {
        for (i, &b) in chunk.iter().enumerate() {
            let global_idx = chunk_idx * 16 + i;
            if global_idx + 1 < total {
                let _ = write!(s, "0x{b:02X},");
            } else {
                let _ = write!(s, "0x{b:02X}");
            }
        }
        s.push('\n');
    }
    s.push_str("};\n");
    s
}

/// Convert decoded SII PDO categories (50/51) into a wire-level `PdoLayout` for dissection and cyclic I/O.
pub fn sii_pdos_to_layout(pdos: &[SiiPdoDecoded]) -> ethercat_wire::pdo_codec::PdoLayout {
    use ethercat_wire::pdo_codec::{PdoFieldDef, PdoLayout};
    use ethercat_wire::types::DataTypeSpec;

    let mut fields = Vec::new();
    let mut max_bit_end = 0usize;
    for pdo in pdos {
        if pdo.sync_manager < 0 {
            continue;
        }
        for entry in &pdo.entries {
            if entry.bit_length == 0 {
                continue;
            }
            let end_bit = entry.bit_offset + entry.bit_length as usize;
            if end_bit > max_bit_end {
                max_bit_end = end_bit;
            }
            // 0x0000:00 is standard ETG PDO alignment padding
            if entry.index_u16 == 0x0000 {
                continue;
            }
            let entry_id = format!("0x{:04x}:{:02x}", entry.index_u16, entry.subindex);
            let name = entry
                .name
                .clone()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| entry_id.clone());
            let ty = DataTypeSpec::from_coe_datatype(entry.data_type, entry.bit_length as u16)
                .unwrap_or_else(|| DataTypeSpec::from_ect_code(entry.data_type));
            fields.push(PdoFieldDef {
                name,
                entry_id: Some(entry_id),
                ty,
                bit_offset: entry.bit_offset,
                bit_length: entry.bit_length as usize,
            });
        }
    }
    PdoLayout {
        fields,
        min_total_bits: max_bit_end,
    }
}
