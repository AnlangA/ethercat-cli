pub mod compiler;
pub mod xml;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::esi::xml::{parse_xml_file, XmlElement};
use ethercat_wire::error::{CliError, Result};

pub use compiler::{compile_esi_device_to_sii, EsiCompileOptions, EsiCompiledSii};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiVendor {
    pub id: u32,
    pub id_hex: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiGroup {
    pub group_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_group: Option<String>,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiDataTypeDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiSm {
    pub index: usize,
    pub sm_type_name: String,
    pub sm_type_code: u8,
    pub start_address: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_size: Option<u16>,
    pub default_size: u16,
    pub control_byte: u8,
    pub enable: bool,
    pub virtual_sm: bool,
    pub op_only: bool,
    pub pdi_ctrl: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiPdoEntry {
    pub index: u16,
    pub subindex: u8,
    pub bit_len: u16,
    pub name: String,
    pub data_type: String,
    pub data_type_code: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiPdo {
    pub direction: String,
    pub index: u16,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sm: Option<i8>,
    pub su: u8,
    pub fixed: bool,
    pub mandatory: bool,
    pub virtual_pdo: bool,
    pub entries: Vec<EsiPdoEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiCoeConfig {
    pub enable_sdo: bool,
    pub sdo_info: bool,
    pub pdo_assign: bool,
    pub pdo_config: bool,
    pub pdo_upload: bool,
    pub complete_access: bool,
    pub segmented_sdo: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiMailbox {
    pub data_link_layer: bool,
    pub aoe: bool,
    pub eoe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coe: Option<EsiCoeConfig>,
    pub foe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soe_channels: Option<u8>,
    pub voe: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<[u16; 4]>,
}

impl EsiMailbox {
    pub fn protocol_mask(&self) -> u16 {
        let mut mask = 0u16;
        if self.aoe {
            mask |= 0x0001;
        }
        if self.eoe {
            mask |= 0x0002;
        }
        if self.coe.is_some() {
            mask |= 0x0004;
        }
        if self.foe {
            mask |= 0x0008;
        }
        if self.soe_channels.is_some() {
            mask |= 0x0010;
        }
        if self.voe {
            mask |= 0x0020;
        }
        mask
    }

    pub fn protocol_names(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.aoe {
            out.push("AoE".into());
        }
        if self.eoe {
            out.push("EoE".into());
        }
        if self.coe.is_some() {
            out.push("CoE".into());
        }
        if self.foe {
            out.push("FoE".into());
        }
        if self.soe_channels.is_some() {
            out.push("SoE".into());
        }
        if self.voe {
            out.push("VoE".into());
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiDcOpMode {
    pub name: String,
    pub description: String,
    pub assign_activate: u16,
    pub cycle_time_sync0_ns: u32,
    pub factor_sync0: i16,
    pub shift_time_sync0_ns: i32,
    pub cycle_time_sync1_ns: u32,
    pub factor_sync1: i16,
    pub shift_time_sync1_ns: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiEepromSpec {
    pub byte_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_data: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<[u16; 4]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<Vec<u8>>,
    pub assign_to_pdi: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiDevice {
    pub index: usize,
    pub source_file: String,
    pub vendor_id: u32,
    pub vendor_name: String,
    pub order_code: String,
    pub device_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub group_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    pub image_name: String,
    pub product_code: u32,
    pub revision_number: u32,
    pub serial_number: u32,
    pub enable_safeop: bool,
    pub enable_not_lrw: bool,
    pub physics: String,
    pub physical_ports_word: u16,
    pub identification_reg134: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identification_ado: Option<u16>,
    pub current_on_ebus_ma: i16,
    pub ds402_channels: u8,
    pub profile_numbers: Vec<u32>,
    pub fmmus: Vec<String>,
    pub fmmu_codes: Vec<u8>,
    pub sync_managers: Vec<EsiSm>,
    pub tx_pdos: Vec<EsiPdo>,
    pub rx_pdos: Vec<EsiPdo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<EsiMailbox>,
    pub dc_modes: Vec<EsiDcOpMode>,
    pub eeprom: EsiEepromSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiDeviceSummary {
    pub index: usize,
    pub source_file: String,
    pub vendor_id: String,
    pub vendor_name: String,
    pub order_code: String,
    pub device_name: String,
    pub group_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_name: Option<String>,
    pub product_code: String,
    pub revision_number: String,
    pub physics: String,
    pub eeprom_byte_size: usize,
    pub sm_count: usize,
    pub assigned_tx_pdo_count: usize,
    pub assigned_rx_pdo_count: usize,
    pub total_tx_pdo_count: usize,
    pub total_rx_pdo_count: usize,
    pub dc_mode_count: usize,
    pub mailbox_protocols: Vec<String>,
}

impl EsiDevice {
    pub fn summary(&self) -> EsiDeviceSummary {
        EsiDeviceSummary {
            index: self.index,
            source_file: self.source_file.clone(),
            vendor_id: format!("0x{:08X}", self.vendor_id),
            vendor_name: self.vendor_name.clone(),
            order_code: self.order_code.clone(),
            device_name: self.device_name.clone(),
            group_type: self.group_type.clone(),
            group_name: self.group_name.clone(),
            product_code: format!("0x{:08X}", self.product_code),
            revision_number: format!("0x{:08X}", self.revision_number),
            physics: self.physics.clone(),
            eeprom_byte_size: self.eeprom.byte_size,
            sm_count: self.sync_managers.len(),
            assigned_tx_pdo_count: self.tx_pdos.iter().filter(|p| p.sm.is_some()).count(),
            assigned_rx_pdo_count: self.rx_pdos.iter().filter(|p| p.sm.is_some()).count(),
            total_tx_pdo_count: self.tx_pdos.len(),
            total_rx_pdo_count: self.rx_pdos.len(),
            dc_mode_count: self.dc_modes.len(),
            mailbox_protocols: self
                .mailbox
                .as_ref()
                .map(|m| m.protocol_names())
                .unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiCatalog {
    pub root_path: String,
    pub files_loaded: Vec<String>,
    pub vendors: Vec<EsiVendor>,
    pub groups: Vec<EsiGroup>,
    pub devices: Vec<EsiDevice>,
}

/// Parse an unsigned ETG.2000 integer supporting `#x...`, `0x...`, or decimal.
pub fn parse_esi_u64(raw: &str) -> Result<u64> {
    let s = raw.trim().replace('_', "");
    if s.is_empty() {
        return Err(CliError::Format("empty ESI numeric value".into()));
    }
    let s = s.strip_prefix('+').unwrap_or(&s);
    if let Some(hex_str) = s
        .strip_prefix("#x")
        .or_else(|| s.strip_prefix("#X"))
        .or_else(|| s.strip_prefix("0x"))
        .or_else(|| s.strip_prefix("0X"))
    {
        u64::from_str_radix(hex_str, 16)
            .map_err(|e| CliError::Format(format!("invalid ESI hex '{raw}': {e}")))
    } else {
        s.parse::<u64>()
            .map_err(|e| CliError::Format(format!("invalid ESI integer '{raw}': {e}")))
    }
}

/// Parse a signed ETG.2000 integer supporting optional sign with `#x...`, `0x...`, or decimal.
pub fn parse_esi_i64(raw: &str) -> Result<i64> {
    let s = raw.trim().replace('_', "");
    if s.is_empty() {
        return Err(CliError::Format("empty ESI signed numeric value".into()));
    }
    if let Some(neg) = s.strip_prefix('-') {
        let mag = parse_esi_u64(neg)?;
        if mag == (i64::MAX as u64) + 1 {
            Ok(i64::MIN)
        } else {
            let pos = i64::try_from(mag)
                .map_err(|_| CliError::Format(format!("ESI signed value '{raw}' out of range")))?;
            Ok(-pos)
        }
    } else {
        let mag = parse_esi_u64(&s)?;
        i64::try_from(mag)
            .map_err(|_| CliError::Format(format!("ESI signed value '{raw}' out of range")))
    }
}

pub fn parse_esi_bool(raw: &str) -> bool {
    let s = raw.trim();
    s == "1" || s.eq_ignore_ascii_case("true")
}

pub fn parse_esi_hex_bytes(raw: &str) -> Result<Vec<u8>> {
    let trimmed = raw.trim();
    let without_prefix = trimmed
        .strip_prefix("#x")
        .or_else(|| trimmed.strip_prefix("#X"))
        .or_else(|| trimmed.strip_prefix("0x"))
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let cleaned: String = without_prefix
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    if (cleaned.len() & 1) != 0 {
        return Err(CliError::Format(format!(
            "ESI hex binary string has odd nibble length ({} chars)",
            cleaned.len()
        )));
    }
    hex::decode(&cleaned).map_err(|e| CliError::Format(format!("invalid ESI hex byte string: {e}")))
}

/// Select localized element text per ETG.2000 `LcId` rules (default `1033` = English).
/// When `lcid == 0`, selects the first matching element in document order.
pub fn pick_localized_text(parent: &XmlElement, tag: &str, lcid: u32) -> Option<String> {
    let trim_ctl = |s: &str| s.trim_matches(['\r', '\n', '\t']).to_string();
    let matches: Vec<&XmlElement> = parent.children_named(tag).collect();
    if matches.is_empty() {
        return None;
    }
    if lcid == 0 {
        return Some(trim_ctl(&matches[0].text));
    }
    for el in &matches {
        if let Some(attr) = el.attr("LcId") {
            if parse_esi_u64(attr).ok() == Some(lcid as u64) {
                return Some(trim_ctl(&el.text));
            }
        }
    }
    for el in &matches {
        if el.attr("LcId").is_none() {
            return Some(trim_ctl(&el.text));
        }
    }
    if lcid != 1033 {
        for el in &matches {
            if let Some(attr) = el.attr("LcId") {
                if parse_esi_u64(attr).ok() == Some(1033) {
                    return Some(trim_ctl(&el.text));
                }
            }
        }
    }
    Some(trim_ctl(&matches[0].text))
}

pub fn encode_physics_ports(physics: &str) -> u16 {
    let mut word = 0u16;
    for (port_idx, ch) in physics.chars().take(4).enumerate() {
        let code: u16 = match ch {
            'Y' | 'y' => 0x01, // MII
            'K' | 'k' => 0x03, // EBUS
            'H' | 'h' => 0x04, // FastHotConnect
            _ => 0x00,         // NotImplemented / space
        };
        word |= code << (port_idx * 4);
    }
    word
}

pub fn resolve_coe_datatype_code(
    dt_name: &str,
    entry_index: u16,
    bit_len: u16,
    custom_types: &BTreeMap<String, EsiDataTypeDef>,
) -> u8 {
    if entry_index == 0 && dt_name.trim().is_empty() {
        return 0x00;
    }
    let mut current = dt_name.trim().to_ascii_uppercase();
    for _ in 0..8 {
        if let Some(code) = match_builtin_coe_datatype(&current) {
            return code;
        }
        if let Some(def) = custom_types.get(&current) {
            if let Some(ref base) = def.base_type {
                let next = base.trim().to_ascii_uppercase();
                if !next.is_empty() && next != current {
                    current = next;
                    continue;
                }
            }
        }
        break;
    }
    if entry_index == 0 {
        return 0x00;
    }
    match bit_len {
        1 => 0x01,
        2..=7 => 0x30 + (bit_len as u8 - 1),
        8 => 0x05,
        16 => 0x06,
        24 => 0x16,
        32 => 0x07,
        40 => 0x18,
        48 => 0x19,
        56 => 0x1A,
        64 => 0x1B,
        _ => 0x00,
    }
}

fn match_builtin_coe_datatype(upper: &str) -> Option<u8> {
    match upper {
        "" | "NONE" => Some(0x00),
        "BOOL" | "BOOLEAN" | "BIT" => Some(0x01),
        "SINT" | "INTEGER8" | "INT8" => Some(0x02),
        "INT" | "INTEGER16" | "INT16" => Some(0x03),
        "DINT" | "INTEGER32" | "INT32" => Some(0x04),
        "USINT" | "UNSIGNED8" | "UINT8" => Some(0x05),
        "UINT" | "UNSIGNED16" | "UINT16" => Some(0x06),
        "UDINT" | "UNSIGNED32" | "UINT32" => Some(0x07),
        "REAL" | "REAL32" | "FLOAT" => Some(0x08),
        "VISIBLE_STRING" => Some(0x09),
        "OCTET_STRING" => Some(0x0A),
        "UNICODE_STRING" => Some(0x0B),
        "TIME_OF_DAY" => Some(0x0C),
        "TIME_DIFFERENCE" => Some(0x0D),
        "INT24" | "INTEGER24" => Some(0x10),
        "LREAL" | "REAL64" | "DOUBLE" => Some(0x11),
        "INT40" | "INTEGER40" => Some(0x12),
        "INT48" | "INTEGER48" => Some(0x13),
        "INT56" | "INTEGER56" => Some(0x14),
        "LINT" | "INTEGER64" | "INT64" => Some(0x15),
        "UINT24" | "UNSIGNED24" => Some(0x16),
        "UINT40" | "UNSIGNED40" => Some(0x18),
        "UINT48" | "UNSIGNED48" => Some(0x19),
        "UINT56" | "UNSIGNED56" => Some(0x1A),
        "ULINT" | "UNSIGNED64" | "UINT64" | "LWORD" => Some(0x1B),
        "GUID" => Some(0x1D),
        "BYTE" => Some(0x1E),
        "WORD" => Some(0x1F),
        "DWORD" => Some(0x20),
        "BITARR8" => Some(0x2D),
        "BITARR16" => Some(0x2E),
        "BITARR32" => Some(0x2F),
        "BIT1" => Some(0x30),
        "BIT2" => Some(0x31),
        "BIT3" => Some(0x32),
        "BIT4" => Some(0x33),
        "BIT5" => Some(0x34),
        "BIT6" => Some(0x35),
        "BIT7" => Some(0x36),
        "BIT8" => Some(0x37),
        _ if upper.starts_with("STRING") => Some(0x09),
        _ if upper.starts_with("ARRAY") && upper.ends_with("OF UINT") => Some(0x0B),
        _ if upper.starts_with("ARRAY") && upper.ends_with("OF INT") => Some(0x60),
        _ if upper.starts_with("ARRAY") && upper.ends_with("OF SINT") => Some(0x61),
        _ if upper.starts_with("ARRAY") && upper.ends_with("OF DINT") => Some(0x62),
        _ if upper.starts_with("ARRAY") && upper.ends_with("OF UDINT") => Some(0x63),
        _ if upper.starts_with("ARRAY") => Some(0x0A),
        _ => None,
    }
}

fn parse_vendor_elem(vendor_el: &XmlElement, lcid: u32) -> Result<EsiVendor> {
    let id_str = vendor_el.child_text("Id").unwrap_or("0");
    let id = u32::try_from(parse_esi_u64(id_str)?)
        .map_err(|_| CliError::Format(format!("Vendor <Id> '{id_str}' overflows u32")))?;
    let name = pick_localized_text(vendor_el, "Name", lcid).unwrap_or_default();
    Ok(EsiVendor {
        id,
        id_hex: format!("0x{id:08X}"),
        name,
    })
}

fn parse_groups_elem(groups_el: &XmlElement, lcid: u32, out: &mut Vec<EsiGroup>) {
    for g in groups_el.children_named("Group") {
        let group_type = g.child_text("Type").unwrap_or("").to_string();
        if group_type.is_empty() {
            continue;
        }
        let parent_group = g
            .attr("ParentGroup")
            .or_else(|| g.child_text("ParentGroup"))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());
        let name = pick_localized_text(g, "Name", lcid).unwrap_or_else(|| group_type.clone());
        if !out.iter().any(|existing| existing.group_type == group_type) {
            out.push(EsiGroup {
                group_type,
                parent_group,
                name,
            });
        }
    }
}

fn parse_pdo_elem(
    pdo_el: &XmlElement,
    direction: &str,
    lcid: u32,
    custom_types: &BTreeMap<String, EsiDataTypeDef>,
) -> Result<EsiPdo> {
    let idx_str = pdo_el.child_text("Index").unwrap_or("0");
    let index = u16::try_from(parse_esi_u64(idx_str)?)
        .map_err(|_| CliError::Format(format!("{direction} <Index> '{idx_str}' overflows u16")))?;
    let name = pick_localized_text(pdo_el, "Name", lcid).unwrap_or_default();
    let sm = match pdo_el.attr("Sm") {
        Some(s) if !s.trim().is_empty() => {
            let v = parse_esi_i64(s)?;
            Some(i8::try_from(v).map_err(|_| {
                CliError::Format(format!("{direction} Sm attribute '{s}' overflows i8"))
            })?)
        }
        _ => None,
    };
    let su = match pdo_el.attr("Su") {
        Some(s) if !s.trim().is_empty() => u8::try_from(parse_esi_u64(s)?).unwrap_or(0),
        _ => 0,
    };
    let fixed = pdo_el.attr("Fixed").is_some_and(parse_esi_bool);
    let mandatory = pdo_el.attr("Mandatory").is_some_and(parse_esi_bool);
    let virtual_pdo = pdo_el.attr("Virtual").is_some_and(parse_esi_bool);

    let mut entries = Vec::new();
    for entry_el in pdo_el.children_named("Entry") {
        let e_idx_str = entry_el.child_text("Index").unwrap_or("0");
        let e_index = u16::try_from(parse_esi_u64(e_idx_str)?).map_err(|_| {
            CliError::Format(format!("PDO Entry <Index> '{e_idx_str}' overflows u16"))
        })?;
        let e_sub = match entry_el.child_text("SubIndex") {
            Some(s) if !s.is_empty() => u8::try_from(parse_esi_u64(s)?).unwrap_or(0),
            _ => 0,
        };
        let bit_len = match entry_el.child_text("BitLen") {
            Some(s) if !s.is_empty() => u16::try_from(parse_esi_u64(s)?).map_err(|_| {
                CliError::Format(format!(
                    "PDO Entry 0x{e_index:04X}:{e_sub} <BitLen> '{s}' exceeds u16 (65535)"
                ))
            })?,
            _ => 0,
        };
        let e_name = pick_localized_text(entry_el, "Name", lcid).unwrap_or_default();
        let dt_str = entry_el
            .child_text("DataType")
            .unwrap_or("")
            .trim()
            .to_string();
        let data_type_code = resolve_coe_datatype_code(&dt_str, e_index, bit_len, custom_types);
        entries.push(EsiPdoEntry {
            index: e_index,
            subindex: e_sub,
            bit_len,
            name: e_name,
            data_type: dt_str,
            data_type_code,
        });
    }

    Ok(EsiPdo {
        direction: direction.to_string(),
        index,
        name,
        sm,
        su,
        fixed,
        mandatory,
        virtual_pdo,
        entries,
    })
}

fn parse_mailbox_bootstrap_elem(boot_el: &XmlElement) -> Option<[u16; 4]> {
    if let (Some(rx_start), Some(rx_len), Some(tx_start), Some(tx_len)) = (
        boot_el
            .child("Send")
            .and_then(|s| s.child_text("Start").or_else(|| s.attr("StartAddress"))),
        boot_el
            .child("Send")
            .and_then(|s| s.child_text("Length").or_else(|| s.attr("Length"))),
        boot_el
            .child("Receive")
            .and_then(|r| r.child_text("Start").or_else(|| r.attr("StartAddress"))),
        boot_el
            .child("Receive")
            .and_then(|r| r.child_text("Length").or_else(|| r.attr("Length"))),
    ) {
        let r_off = u16::try_from(parse_esi_u64(rx_start).ok()?).ok()?;
        let r_sz = u16::try_from(parse_esi_u64(rx_len).ok()?).ok()?;
        let t_off = u16::try_from(parse_esi_u64(tx_start).ok()?).ok()?;
        let t_sz = u16::try_from(parse_esi_u64(tx_len).ok()?).ok()?;
        return Some([r_off, r_sz, t_off, t_sz]);
    }
    if !boot_el.text.trim().is_empty() {
        if let Ok(bytes) = parse_esi_hex_bytes(&boot_el.text) {
            if bytes.len() >= 8 {
                return Some([
                    u16::from_le_bytes([bytes[0], bytes[1]]),
                    u16::from_le_bytes([bytes[2], bytes[3]]),
                    u16::from_le_bytes([bytes[4], bytes[5]]),
                    u16::from_le_bytes([bytes[6], bytes[7]]),
                ]);
            }
        }
    }
    None
}

fn parse_device_elem(
    dev_el: &XmlElement,
    vendor: &EsiVendor,
    groups: &[EsiGroup],
    source_file: &str,
    device_index: usize,
    lcid: u32,
) -> Result<EsiDevice> {
    let physics = dev_el
        .attr("Physics")
        .or_else(|| dev_el.child_text("Physics"))
        .unwrap_or("")
        .to_string();
    let physical_ports_word = encode_physics_ports(&physics);

    let (order_code, product_code, revision_number, serial_number, enable_safeop, enable_not_lrw) =
        if let Some(type_el) = dev_el.child("Type") {
            let code_str = type_el.text.trim().to_string();
            let prod = match type_el.attr("ProductCode") {
                Some(s) => u32::try_from(parse_esi_u64(s)?)
                    .map_err(|_| CliError::Format(format!("ProductCode '{s}' overflows u32")))?,
                None => 0,
            };
            let rev = match type_el.attr("RevisionNo") {
                Some(s) => u32::try_from(parse_esi_u64(s)?)
                    .map_err(|_| CliError::Format(format!("RevisionNo '{s}' overflows u32")))?,
                None => 0,
            };
            let ser = match type_el.attr("SerialNo") {
                Some(s) => u32::try_from(parse_esi_u64(s)?)
                    .map_err(|_| CliError::Format(format!("SerialNo '{s}' overflows u32")))?,
                None => 0,
            };
            let safe_op = type_el.attr("EnableSafeOp").is_some_and(parse_esi_bool);
            let not_lrw = type_el
                .attr("UseLrdLwr")
                .or_else(|| type_el.attr("EnableNotLrw"))
                .is_some_and(parse_esi_bool);
            (code_str, prod, rev, ser, safe_op, not_lrw)
        } else {
            (String::new(), 0, 0, 0, false, false)
        };

    let device_name =
        pick_localized_text(dev_el, "Name", lcid).unwrap_or_else(|| order_code.clone());
    let url = pick_localized_text(dev_el, "URL", lcid).filter(|s| !s.is_empty());
    let group_type = dev_el.child_text("GroupType").unwrap_or("").to_string();
    let group_name = groups
        .iter()
        .find(|g| g.group_type == group_type)
        .map(|g| g.name.clone());
    let image_name = dev_el.child_text("ImageName").unwrap_or("").to_string();

    let mut identification_reg134 = false;
    let mut identification_ado = None;
    let mut current_on_ebus_ma: Option<i16> = None;

    if let Some(info_el) = dev_el.child("Info") {
        if let Some(reg134) = info_el.child_text("IdentificationReg134") {
            identification_reg134 = parse_esi_bool(reg134);
        }
        if let Some(ado_el) = info_el.child("IdentificationAdo") {
            let val_str = ado_el.attr("Value").unwrap_or_else(|| ado_el.text.trim());
            if !val_str.is_empty() {
                if let Ok(v) = parse_esi_u64(val_str) {
                    if let Ok(v16) = u16::try_from(v) {
                        identification_ado = Some(v16);
                    }
                }
            }
        }
        if let Some(elec_el) = info_el.child("Electrical") {
            if let Some(cur_str) = elec_el.child_text("EBusCurrent") {
                if !cur_str.is_empty() {
                    if let Ok(v) = parse_esi_i64(cur_str) {
                        current_on_ebus_ma = Some(v.clamp(i16::MIN as i64, i16::MAX as i64) as i16);
                    }
                }
            }
        }
    }

    // Parse <Profile> ChannelInfo + Dictionary DataTypes
    let mut custom_types = BTreeMap::new();
    let mut profile_numbers = Vec::new();
    let mut ds402_channels = 0u8;
    for prof_el in dev_el.children_named("Profile") {
        for ch_el in prof_el.children_named("ChannelInfo") {
            if let Some(pno_str) = ch_el.child_text("ProfileNo") {
                if let Ok(pno) = parse_esi_u64(pno_str) {
                    if let Ok(p32) = u32::try_from(pno) {
                        profile_numbers.push(p32);
                        if p32 == 402 {
                            ds402_channels = ds402_channels.saturating_add(1);
                        }
                    }
                }
            }
        }
        if let Some(pno_str) = prof_el.child_text("ProfileNo") {
            if let Ok(pno) = parse_esi_u64(pno_str) {
                if let Ok(p32) = u32::try_from(pno) {
                    profile_numbers.push(p32);
                    if p32 == 402 {
                        ds402_channels = ds402_channels.saturating_add(1);
                    }
                }
            }
        }
        if let Some(dict_el) = prof_el.child("Dictionary") {
            if let Some(dts_el) = dict_el.child("DataTypes") {
                for dt_el in dts_el.children_named("DataType") {
                    if let Some(dt_name) = dt_el.child_text("Name") {
                        if dt_name.is_empty() {
                            continue;
                        }
                        let base_type = dt_el
                            .child_text("BaseType")
                            .map(|s| s.to_string())
                            .filter(|s| !s.is_empty());
                        let bit_size = dt_el
                            .child_text("BitSize")
                            .and_then(|s| parse_esi_u64(s).ok())
                            .and_then(|v| u32::try_from(v).ok());
                        custom_types.insert(
                            dt_name.to_ascii_uppercase(),
                            EsiDataTypeDef {
                                name: dt_name.to_string(),
                                base_type,
                                bit_size,
                            },
                        );
                    }
                }
            }
        }
    }

    // Parse <Fmmu>
    let mut fmmus = Vec::new();
    let mut fmmu_codes = Vec::new();
    for fmmu_el in dev_el.children_named("Fmmu") {
        let kind = fmmu_el.text.trim();
        if !kind.is_empty() {
            fmmus.push(kind.to_string());
        }
        match kind {
            "Outputs" => fmmu_codes.push(0x01),
            "Inputs" => fmmu_codes.push(0x02),
            "MBoxState" => fmmu_codes.push(0x03),
            // TwinCAT-only dynamic FMMU tags (`DynamicInputs`, `DynamicOutputs`) have no
            // ETG.2010 SII Category 40 representation and are omitted by Beckhoff SSC.
            _ => {}
        }
    }

    // Parse <Sm>
    let mut sync_managers = Vec::new();
    for (sm_idx, sm_el) in dev_el.children_named("Sm").enumerate() {
        let sm_type_name = sm_el.text.trim().to_string();
        let sm_type_code = match sm_type_name.as_str() {
            "MBoxOut" => 1,
            "MBoxIn" => 2,
            "Outputs" => 3,
            "Inputs" => 4,
            _ => 0,
        };
        let start_address = sm_el
            .attr("StartAddress")
            .map(parse_esi_u64)
            .transpose()?
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(0);
        let min_size = sm_el
            .attr("MinSize")
            .map(parse_esi_u64)
            .transpose()?
            .and_then(|v| u16::try_from(v).ok());
        let max_size = sm_el
            .attr("MaxSize")
            .map(parse_esi_u64)
            .transpose()?
            .and_then(|v| u16::try_from(v).ok());
        let default_size = sm_el
            .attr("DefaultSize")
            .map(parse_esi_u64)
            .transpose()?
            .and_then(|v| u16::try_from(v).ok())
            .or(min_size)
            .unwrap_or(0);
        let control_byte = sm_el
            .attr("ControlByte")
            .map(parse_esi_u64)
            .transpose()?
            .and_then(|v| u8::try_from(v).ok())
            .unwrap_or(0);
        let enable = sm_el.attr("Enable").is_some_and(parse_esi_bool);
        let virtual_sm = sm_el.attr("Virtual").is_some_and(parse_esi_bool);
        let op_only = sm_el.attr("OpOnly").is_some_and(parse_esi_bool);
        let pdi_ctrl = sm_el.attr("PdiCtrl").is_some_and(parse_esi_bool);

        sync_managers.push(EsiSm {
            index: sm_idx,
            sm_type_name,
            sm_type_code,
            start_address,
            min_size,
            max_size,
            default_size,
            control_byte,
            enable,
            virtual_sm,
            op_only,
            pdi_ctrl,
        });
    }

    // Parse <TxPdo> & <RxPdo>
    let mut tx_pdos = Vec::new();
    for tx_el in dev_el.children_named("TxPdo") {
        tx_pdos.push(parse_pdo_elem(tx_el, "TxPDO", lcid, &custom_types)?);
    }
    let mut rx_pdos = Vec::new();
    for rx_el in dev_el.children_named("RxPdo") {
        rx_pdos.push(parse_pdo_elem(rx_el, "RxPDO", lcid, &custom_types)?);
    }

    // Parse <Mailbox>
    let mailbox = dev_el.child("Mailbox").map(|mbx_el| {
        let data_link_layer = mbx_el.attr("DataLinkLayer").is_some_and(parse_esi_bool);
        let aoe = mbx_el.child("AoE").is_some();
        let eoe = mbx_el.child("EoE").is_some();
        let foe = mbx_el.child("FoE").is_some();
        let voe = mbx_el.child("VoE").is_some();
        let soe_channels = mbx_el.child("SoE").map(|soe_el| {
            soe_el
                .attr("ChannelCount")
                .and_then(|s| parse_esi_u64(s).ok())
                .and_then(|v| u8::try_from(v).ok())
                .unwrap_or(1)
        });
        let coe = mbx_el.child("CoE").map(|coe_el| {
            let enable_sdo = coe_el
                .attr("Sdo")
                .or_else(|| coe_el.attr("EnableSdo"))
                .map(parse_esi_bool)
                .unwrap_or(true);
            EsiCoeConfig {
                enable_sdo,
                sdo_info: coe_el.attr("SdoInfo").is_some_and(parse_esi_bool),
                pdo_assign: coe_el.attr("PdoAssign").is_some_and(parse_esi_bool),
                pdo_config: coe_el.attr("PdoConfig").is_some_and(parse_esi_bool),
                pdo_upload: coe_el.attr("PdoUpload").is_some_and(parse_esi_bool),
                complete_access: coe_el.attr("CompleteAccess").is_some_and(parse_esi_bool),
                segmented_sdo: coe_el.attr("SegmentedSdo").is_some_and(parse_esi_bool),
            }
        });
        let bootstrap = mbx_el
            .child("Bootstrap")
            .and_then(parse_mailbox_bootstrap_elem);
        EsiMailbox {
            data_link_layer,
            aoe,
            eoe,
            coe,
            foe,
            soe_channels,
            voe,
            bootstrap,
        }
    });

    // Parse <Dc><OpMode>
    let mut dc_modes = Vec::new();
    if let Some(dc_el) = dev_el.child("Dc") {
        for op_el in dc_el.children_named("OpMode") {
            let name = pick_localized_text(op_el, "Name", lcid).unwrap_or_default();
            let description = pick_localized_text(op_el, "Desc", lcid).unwrap_or_default();
            let assign_activate = op_el
                .child_text("AssignActivate")
                .and_then(|s| parse_esi_u64(s).ok())
                .and_then(|v| u16::try_from(v).ok())
                .unwrap_or(0);
            let (cycle_time_sync0_ns, factor_sync0) =
                if let Some(c0_el) = op_el.child("CycleTimeSync0") {
                    let cyc = parse_esi_u64(c0_el.text.trim())
                        .ok()
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    let fac = c0_el
                        .attr("Factor")
                        .and_then(|s| parse_esi_i64(s).ok())
                        .and_then(|v| i16::try_from(v).ok())
                        .unwrap_or(0);
                    (cyc, fac)
                } else {
                    (0, 0)
                };
            let shift_time_sync0_ns = op_el
                .child_text("ShiftTimeSync0")
                .and_then(|s| parse_esi_i64(s).ok())
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(0);
            let (cycle_time_sync1_ns, factor_sync1) =
                if let Some(c1_el) = op_el.child("CycleTimeSync1") {
                    let cyc = parse_esi_u64(c1_el.text.trim())
                        .ok()
                        .and_then(|v| u32::try_from(v).ok())
                        .unwrap_or(0);
                    let fac = if let Some(fac_attr) = c1_el.attr("Factor") {
                        parse_esi_i64(fac_attr)
                            .ok()
                            .and_then(|v| i16::try_from(v).ok())
                            .unwrap_or(0)
                    } else if cyc > 0 && cycle_time_sync0_ns > 0 && cyc >= cycle_time_sync0_ns {
                        i16::try_from(cyc / cycle_time_sync0_ns).unwrap_or(0)
                    } else {
                        0
                    };
                    (cyc, fac)
                } else {
                    (0, 0)
                };
            let shift_time_sync1_ns = op_el
                .child_text("ShiftTimeSync1")
                .and_then(|s| parse_esi_i64(s).ok())
                .and_then(|v| i32::try_from(v).ok())
                .unwrap_or(0);

            dc_modes.push(EsiDcOpMode {
                name,
                description,
                assign_activate,
                cycle_time_sync0_ns,
                factor_sync0,
                shift_time_sync0_ns,
                cycle_time_sync1_ns,
                factor_sync1,
                shift_time_sync1_ns,
            });
        }
    }

    // Parse <Eeprom>
    let mut eeprom_spec = EsiEepromSpec {
        byte_size: 2048,
        config_data: None,
        bootstrap: None,
        raw_data: None,
        assign_to_pdi: false,
    };
    if let Some(eep_el) = dev_el.child("Eeprom") {
        eeprom_spec.assign_to_pdi = eep_el.attr("AssignToPdi").is_some_and(parse_esi_bool)
            || eep_el.child_text("AssignToPdi").is_some_and(parse_esi_bool);
        if let Some(bs_str) = eep_el.child_text("ByteSize") {
            if !bs_str.is_empty() {
                eeprom_spec.byte_size = usize::try_from(parse_esi_u64(bs_str)?).map_err(|_| {
                    CliError::Format(format!("Eeprom <ByteSize> '{bs_str}' overflows usize"))
                })?;
            }
        }
        if let Some(cfg_str) = eep_el.child_text("ConfigData") {
            if !cfg_str.is_empty() {
                eeprom_spec.config_data = Some(parse_esi_hex_bytes(cfg_str)?);
            }
        }
        if let Some(boot_str) = eep_el.child_text("BootStrap") {
            if !boot_str.is_empty() {
                let b = parse_esi_hex_bytes(boot_str)?;
                if b.len() >= 8 {
                    eeprom_spec.bootstrap = Some([
                        u16::from_le_bytes([b[0], b[1]]),
                        u16::from_le_bytes([b[2], b[3]]),
                        u16::from_le_bytes([b[4], b[5]]),
                        u16::from_le_bytes([b[6], b[7]]),
                    ]);
                }
            }
        }
        if let Some(data_str) = eep_el.child_text("Data") {
            if !data_str.is_empty() {
                let raw = parse_esi_hex_bytes(data_str)?;
                if eep_el.child("ByteSize").is_none() && raw.len() >= 128 {
                    eeprom_spec.byte_size = raw.len();
                }
                eeprom_spec.raw_data = Some(raw);
            }
        }
        if current_on_ebus_ma.is_none() {
            if let Some(cur_str) = eep_el.child_text("CurrentOnEBus") {
                if !cur_str.is_empty() {
                    if let Ok(v) = parse_esi_i64(cur_str) {
                        current_on_ebus_ma = Some(v.clamp(i16::MIN as i64, i16::MAX as i64) as i16);
                    }
                }
            }
        }
    }

    Ok(EsiDevice {
        index: device_index,
        source_file: source_file.to_string(),
        vendor_id: vendor.id,
        vendor_name: vendor.name.clone(),
        order_code,
        device_name,
        url,
        group_type,
        group_name,
        image_name,
        product_code,
        revision_number,
        serial_number,
        enable_safeop,
        enable_not_lrw,
        physics,
        physical_ports_word,
        identification_reg134,
        identification_ado,
        current_on_ebus_ma: current_on_ebus_ma.unwrap_or(0),
        ds402_channels,
        profile_numbers,
        fmmus,
        fmmu_codes,
        sync_managers,
        tx_pdos,
        rx_pdos,
        mailbox,
        dc_modes,
        eeprom: eeprom_spec,
    })
}

fn normalize_path_key(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

fn resolve_info_ref_path(parent_file: &Path, ref_text: &str) -> PathBuf {
    let normalized = ref_text
        .trim()
        .replace(['\\', '/'], std::path::MAIN_SEPARATOR_STR);
    let rel = Path::new(&normalized);
    if rel.is_absolute() {
        rel.to_path_buf()
    } else if let Some(dir) = parent_file.parent() {
        dir.join(rel)
    } else {
        rel.to_path_buf()
    }
}

#[allow(clippy::too_many_arguments)]
fn load_esi_xml_recursive(
    xml_path: &Path,
    lcid: u32,
    inherited_vendor: Option<&EsiVendor>,
    strict_root: bool,
    visited: &mut HashSet<PathBuf>,
    files_loaded: &mut Vec<String>,
    vendors: &mut Vec<EsiVendor>,
    groups: &mut Vec<EsiGroup>,
    devices: &mut Vec<EsiDevice>,
) -> Result<()> {
    let key = normalize_path_key(xml_path);
    if !visited.insert(key) {
        return Ok(());
    }

    let root = parse_xml_file(xml_path)?;
    if !root.name.eq_ignore_ascii_case("EtherCATInfo") {
        if strict_root {
            return Err(CliError::Format(format!(
                "file '{}' root element is '<{}>', expected '<EtherCATInfo>'",
                xml_path.display(),
                root.name
            )));
        }
        return Ok(());
    }

    let display_path = xml_path.display().to_string();
    files_loaded.push(display_path.clone());

    let local_vendor = if let Some(v_el) = root.child("Vendor") {
        let v = parse_vendor_elem(v_el, lcid)?;
        if !vendors.iter().any(|existing| existing.id == v.id) {
            vendors.push(v.clone());
        }
        v
    } else if let Some(inherited) = inherited_vendor {
        inherited.clone()
    } else {
        EsiVendor {
            id: 0,
            id_hex: "0x00000000".into(),
            name: String::new(),
        }
    };

    // Parse <Descriptions><Groups> and <Descriptions><Devices> before/alongside <InfoReference>
    if let Some(desc_el) = root.child("Descriptions") {
        if let Some(groups_el) = desc_el.child("Groups") {
            parse_groups_elem(groups_el, lcid, groups);
        }
    }

    // Collect <InfoReference> from both <EtherCATInfo> and <Descriptions>
    let mut info_refs = Vec::new();
    for ir in root.children_named("InfoReference") {
        let t = ir.text.trim();
        if !t.is_empty() {
            info_refs.push(t.to_string());
        }
    }
    if let Some(desc_el) = root.child("Descriptions") {
        for ir in desc_el.children_named("InfoReference") {
            let t = ir.text.trim();
            if !t.is_empty() {
                info_refs.push(t.to_string());
            }
        }
    }

    if let Some(desc_el) = root.child("Descriptions") {
        if let Some(devs_el) = desc_el.child("Devices") {
            for dev_el in devs_el.children_named("Device") {
                let idx = devices.len();
                let parsed =
                    parse_device_elem(dev_el, &local_vendor, groups, &display_path, idx, lcid)?;
                devices.push(parsed);
            }
        }
    }

    for ref_str in info_refs {
        let ref_path = resolve_info_ref_path(xml_path, &ref_str);
        if !ref_path.exists() {
            if strict_root {
                return Err(CliError::Usage(format!(
                    "ESI <InfoReference> file '{}' referenced from '{}' does not exist",
                    ref_path.display(),
                    xml_path.display()
                )));
            }
            continue;
        }
        load_esi_xml_recursive(
            &ref_path,
            lcid,
            Some(&local_vendor),
            false,
            visited,
            files_loaded,
            vendors,
            groups,
            devices,
        )?;
    }

    Ok(())
}

/// Load an ETG.2000 ESI catalog directly from in-memory XML bytes (resolving optional
/// `<InfoReference>` includes relative to `base_dir` if provided).
pub fn load_esi_catalog_from_bytes(
    raw: &[u8],
    display_source: &str,
    base_dir: Option<&Path>,
    lcid: u32,
) -> Result<EsiCatalog> {
    let root = crate::esi::xml::parse_xml_bytes(raw)?;
    if !root.name.eq_ignore_ascii_case("EtherCATInfo") {
        return Err(CliError::Format(format!(
            "ESI XML '{}' root element is '<{}>', expected '<EtherCATInfo>'",
            display_source, root.name
        )));
    }
    let mut visited = HashSet::new();
    let mut files_loaded = vec![display_source.to_string()];
    let mut vendors = Vec::new();
    let mut groups = Vec::new();
    let mut devices = Vec::new();

    let local_vendor = if let Some(v_el) = root.child("Vendor") {
        let v = parse_vendor_elem(v_el, lcid)?;
        vendors.push(v.clone());
        v
    } else {
        EsiVendor {
            id: 0,
            id_hex: "0x00000000".into(),
            name: String::new(),
        }
    };

    if let Some(desc_el) = root.child("Descriptions") {
        if let Some(groups_el) = desc_el.child("Groups") {
            parse_groups_elem(groups_el, lcid, &mut groups);
        }
    }

    let mut info_refs = Vec::new();
    for ir in root.children_named("InfoReference") {
        let t = ir.text.trim();
        if !t.is_empty() {
            info_refs.push(t.to_string());
        }
    }
    if let Some(desc_el) = root.child("Descriptions") {
        for ir in desc_el.children_named("InfoReference") {
            let t = ir.text.trim();
            if !t.is_empty() {
                info_refs.push(t.to_string());
            }
        }
        if let Some(devs_el) = desc_el.child("Devices") {
            for dev_el in devs_el.children_named("Device") {
                let idx = devices.len();
                let parsed =
                    parse_device_elem(dev_el, &local_vendor, &groups, display_source, idx, lcid)?;
                devices.push(parsed);
            }
        }
    }

    if let Some(dir) = base_dir {
        let dummy_parent = dir.join("__in_memory__.xml");
        for ref_str in info_refs {
            let ref_path = resolve_info_ref_path(&dummy_parent, &ref_str);
            if ref_path.exists() {
                load_esi_xml_recursive(
                    &ref_path,
                    lcid,
                    Some(&local_vendor),
                    false,
                    &mut visited,
                    &mut files_loaded,
                    &mut vendors,
                    &mut groups,
                    &mut devices,
                )?;
            }
        }
    }

    for dev in &mut devices {
        if dev.group_name.is_none() && !dev.group_type.is_empty() {
            dev.group_name = groups
                .iter()
                .find(|g| g.group_type == dev.group_type)
                .map(|g| g.name.clone());
        }
    }

    Ok(EsiCatalog {
        root_path: display_source.to_string(),
        files_loaded,
        vendors,
        groups,
        devices,
    })
}

/// Load an ETG.2000 ESI catalog from either a single `.xml` file (resolving `<InfoReference>`
/// includes recursively) or a directory of `.xml` files.
pub fn load_esi_catalog(path: &Path, lcid: u32) -> Result<EsiCatalog> {
    if !path.exists() {
        return Err(CliError::Usage(format!(
            "ESI path '{}' does not exist",
            path.display()
        )));
    }

    let mut visited = HashSet::new();
    let mut files_loaded = Vec::new();
    let mut vendors = Vec::new();
    let mut groups = Vec::new();
    let mut devices = Vec::new();

    if path.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|e| {
                CliError::Usage(format!(
                    "cannot read ESI directory '{}': {e}",
                    path.display()
                ))
            })?
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| {
                p.is_file()
                    && p.extension()
                        .and_then(|ext| ext.to_str())
                        .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
            })
            .collect();
        entries.sort();
        let mut first_xml_err: Option<CliError> = None;
        for xml_file in entries {
            if let Err(e) = load_esi_xml_recursive(
                &xml_file,
                lcid,
                None,
                false,
                &mut visited,
                &mut files_loaded,
                &mut vendors,
                &mut groups,
                &mut devices,
            ) {
                if first_xml_err.is_none() {
                    first_xml_err = Some(e);
                }
            }
        }
        if devices.is_empty() {
            if let Some(err) = first_xml_err {
                return Err(err);
            }
        }
    } else {
        load_esi_xml_recursive(
            path,
            lcid,
            None,
            true,
            &mut visited,
            &mut files_loaded,
            &mut vendors,
            &mut groups,
            &mut devices,
        )?;
    }

    // Back-fill group_name if a referenced file defined <Group> after a <Device>
    for dev in &mut devices {
        if dev.group_name.is_none() && !dev.group_type.is_empty() {
            dev.group_name = groups
                .iter()
                .find(|g| g.group_type == dev.group_type)
                .map(|g| g.name.clone());
        }
    }

    Ok(EsiCatalog {
        root_path: path.display().to_string(),
        files_loaded,
        vendors,
        groups,
        devices,
    })
}

fn format_device_choices<'a, I>(devices: I, total: usize, max_items: usize) -> String
where
    I: IntoIterator<Item = &'a EsiDevice>,
{
    let mut lines = Vec::new();
    for dev in devices.into_iter().take(max_items) {
        lines.push(format!(
            "  [{}] {} | \"{}\" | ProductCode=0x{:08X} | RevisionNo=0x{:08X}",
            dev.index, dev.order_code, dev.device_name, dev.product_code, dev.revision_number
        ));
    }
    if total > max_items {
        lines.push(format!("  ... ({} more devices)", total - max_items));
    }
    lines.join("\n")
}

/// Select a single `<Device>` from a catalog using optional `--device` (`index`, `<Type>` code,
/// `<Name>`, `ProductCode`, or `type@rev` / `product_code:rev`) and optional `--revision`.
pub fn select_esi_device<'a>(
    devices: &'a [EsiDevice],
    selector: Option<&str>,
    revision: Option<u32>,
) -> Result<&'a EsiDevice> {
    if devices.is_empty() {
        return Err(CliError::Format(
            "no <Device> descriptions found in ESI XML".into(),
        ));
    }

    let trimmed_sel = selector.map(str::trim).filter(|s| !s.is_empty());
    if trimmed_sel.is_none() && revision.is_none() {
        if devices.len() == 1 {
            return Ok(&devices[0]);
        }
        return Err(CliError::Usage(format!(
            "ESI catalog contains {} <Device> entries; specify --device <index|type|product_code> (and optional --revision <rev>):\n{}",
            devices.len(),
            format_device_choices(devices.iter(), devices.len(), 20)
        )));
    }

    let mut effective_rev = revision;
    let base_sel = if let Some(sel) = trimmed_sel {
        if effective_rev.is_none() {
            if let Some((lhs, rhs)) = sel.split_once('@').or_else(|| sel.split_once(':')) {
                if let Ok(parsed_rev) = parse_esi_u64(rhs) {
                    if let Ok(rev32) = u32::try_from(parsed_rev) {
                        effective_rev = Some(rev32);
                        let lhs_trimmed = lhs.trim();
                        (!lhs_trimmed.is_empty()).then_some(lhs_trimmed)
                    } else {
                        Some(sel)
                    }
                } else {
                    Some(sel)
                }
            } else {
                Some(sel)
            }
        } else {
            Some(sel)
        }
    } else {
        None
    };

    if let Some(sel) = base_sel {
        // Pure decimal 0-based index check
        let is_hex_prefixed = sel.starts_with("0x")
            || sel.starts_with("0X")
            || sel.starts_with("#x")
            || sel.starts_with("#X");
        if !is_hex_prefixed {
            if let Ok(idx) = sel.parse::<usize>() {
                if let Some(dev) = devices.get(idx) {
                    if effective_rev.is_none_or(|r| dev.revision_number == r) {
                        return Ok(dev);
                    }
                }
            }
        }

        let parsed_code = parse_esi_u64(sel).ok().and_then(|v| u32::try_from(v).ok());
        let candidates: Vec<&EsiDevice> = devices
            .iter()
            .filter(|d| {
                let name_or_code_match = d.order_code.eq_ignore_ascii_case(sel)
                    || d.device_name.eq_ignore_ascii_case(sel)
                    || parsed_code.is_some_and(|pc| d.product_code == pc);
                name_or_code_match && effective_rev.is_none_or(|r| d.revision_number == r)
            })
            .collect();

        match candidates.len() {
            1 => return Ok(candidates[0]),
            0 => {
                return Err(CliError::Usage(format!(
                    "no ESI <Device> matched selector '{}'{} (available: {}):\n{}",
                    sel,
                    effective_rev
                        .map(|r| format!(" with revision 0x{r:08X}"))
                        .unwrap_or_default(),
                    devices.len(),
                    format_device_choices(devices.iter(), devices.len(), 20)
                )));
            }
            n => {
                return Err(CliError::Usage(format!(
                    "selector '{}' matched {n} revisions/devices; disambiguate with --revision <u32> or --device <index>:\n{}",
                    sel,
                    format_device_choices(candidates.iter().copied(), n, 20)
                )));
            }
        }
    }

    // Only `--revision` (or `@rev` / `:rev`) was provided
    let Some(rev) = effective_rev else {
        return Err(CliError::Usage(
            "neither --device nor --revision specified".into(),
        ));
    };
    let candidates: Vec<&EsiDevice> = devices
        .iter()
        .filter(|d| d.revision_number == rev)
        .collect();
    match candidates.len() {
        1 => Ok(candidates[0]),
        0 => Err(CliError::Usage(format!(
            "no ESI <Device> matched revision 0x{rev:08X}:\n{}",
            format_device_choices(devices.iter(), devices.len(), 20)
        ))),
        n => Err(CliError::Usage(format!(
            "revision 0x{rev:08X} matched {n} devices; add --device <index|type|product_code>:\n{}",
            format_device_choices(candidates.iter().copied(), n, 20)
        ))),
    }
}

/// Match a live slave's `(VendorId, ProductCode, RevisionNo)` against a loaded ESI catalog.
pub fn match_esi_device_by_identity(
    devices: &[EsiDevice],
    vendor_id: u32,
    product_code: u32,
    revision_number: u32,
) -> Option<(&EsiDevice, &'static str)> {
    if let Some(exact) = devices.iter().find(|d| {
        d.vendor_id == vendor_id
            && d.product_code == product_code
            && d.revision_number == revision_number
    }) {
        return Some((exact, "exact"));
    }

    // Fallback: compatible revision (same VendorId & ProductCode, highest revision <= slave revision, else closest)
    let same_product: Vec<&EsiDevice> = devices
        .iter()
        .filter(|d| d.vendor_id == vendor_id && d.product_code == product_code)
        .collect();
    if same_product.is_empty() {
        return None;
    }
    if let Some(compatible) = same_product
        .iter()
        .copied()
        .filter(|d| d.revision_number <= revision_number)
        .max_by_key(|d| d.revision_number)
    {
        return Some((compatible, "compatible_revision"));
    }
    same_product
        .into_iter()
        .min_by_key(|d| d.revision_number.abs_diff(revision_number))
        .map(|d| (d, "nearest_revision"))
}
