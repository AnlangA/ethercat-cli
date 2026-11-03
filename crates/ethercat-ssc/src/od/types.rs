use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::xml_dom::{DomElement, DomNode};
use ethercat_wire::error::{CliError, Result};

/// Single entry in Beckhoff's 61-row `BaseDataTypeHandler::DataTypes` table.
#[derive(Debug, Clone, Copy)]
pub struct BaseDataTypeInfo {
    pub id: u16,
    pub coe_name: &'static str,
    pub esi_syntax: &'static str,
    pub ssc_entry_info_syntax: &'static str,
    pub ssc_variable_type: &'static str,
    pub bit_length: i32,
}

/// Complete 61-entry `BaseDataTypeHandler::DataTypes` table in exact array order
/// (exact order matters for `get_data_type_id_by_bitlen`).
pub const DATA_TYPES: &[BaseDataTypeInfo] = &[
    BaseDataTypeInfo {
        id: 0,
        coe_name: "NOT_DEFINED",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_NULL",
        ssc_variable_type: "",
        bit_length: 0,
    },
    BaseDataTypeInfo {
        id: 1,
        coe_name: "BOOLEAN",
        esi_syntax: "BOOL",
        ssc_entry_info_syntax: "DEFTYPE_BOOLEAN",
        ssc_variable_type: "BOOLEAN",
        bit_length: 1,
    },
    BaseDataTypeInfo {
        id: 2,
        coe_name: "INTEGER8",
        esi_syntax: "SINT",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER8",
        ssc_variable_type: "INT8",
        bit_length: 8,
    },
    BaseDataTypeInfo {
        id: 3,
        coe_name: "INTEGER16",
        esi_syntax: "INT",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER16",
        ssc_variable_type: "INT16",
        bit_length: 16,
    },
    BaseDataTypeInfo {
        id: 4,
        coe_name: "INTEGER32",
        esi_syntax: "DINT",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER32",
        ssc_variable_type: "INT32",
        bit_length: 32,
    },
    BaseDataTypeInfo {
        id: 5,
        coe_name: "UNSIGNED8",
        esi_syntax: "USINT",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED8",
        ssc_variable_type: "UINT8",
        bit_length: 8,
    },
    BaseDataTypeInfo {
        id: 6,
        coe_name: "UNSIGNED16",
        esi_syntax: "UINT",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED16",
        ssc_variable_type: "UINT16",
        bit_length: 16,
    },
    BaseDataTypeInfo {
        id: 7,
        coe_name: "UNSIGNED32",
        esi_syntax: "UDINT",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED32",
        ssc_variable_type: "UINT32",
        bit_length: 32,
    },
    BaseDataTypeInfo {
        id: 8,
        coe_name: "REAL32",
        esi_syntax: "REAL",
        ssc_entry_info_syntax: "DEFTYPE_REAL32",
        ssc_variable_type: "REAL32",
        bit_length: 32,
    },
    BaseDataTypeInfo {
        id: 9,
        coe_name: "VISIBLE_STRING",
        esi_syntax: "STRING(n)",
        ssc_entry_info_syntax: "DEFTYPE_VISIBLESTRING",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 10,
        coe_name: "OCTET_STRING",
        esi_syntax: "ARRAY [0..n] OF BYTE",
        ssc_entry_info_syntax: "DEFTYPE_OCTETSTRING",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 11,
        coe_name: "UNICODE_STRING",
        esi_syntax: "ARRAY [0..n] OF UINT",
        ssc_entry_info_syntax: "DEFTYPE_UNICODE_STRING",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 16,
        coe_name: "INTEGER24",
        esi_syntax: "INT24",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER24",
        ssc_variable_type: "",
        bit_length: 24,
    },
    BaseDataTypeInfo {
        id: 17,
        coe_name: "REAL64",
        esi_syntax: "LREAL",
        ssc_entry_info_syntax: "DEFTYPE_REAL64",
        ssc_variable_type: "REAL64",
        bit_length: 64,
    },
    BaseDataTypeInfo {
        id: 18,
        coe_name: "INTEGER40",
        esi_syntax: "INT40",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER40",
        ssc_variable_type: "",
        bit_length: 40,
    },
    BaseDataTypeInfo {
        id: 19,
        coe_name: "INTEGER48",
        esi_syntax: "INT48",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER48",
        ssc_variable_type: "",
        bit_length: 48,
    },
    BaseDataTypeInfo {
        id: 20,
        coe_name: "INTEGER56",
        esi_syntax: "INT56",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER56",
        ssc_variable_type: "",
        bit_length: 56,
    },
    BaseDataTypeInfo {
        id: 21,
        coe_name: "INTEGER64",
        esi_syntax: "LINT",
        ssc_entry_info_syntax: "DEFTYPE_INTEGER64",
        ssc_variable_type: "INT64",
        bit_length: 64,
    },
    BaseDataTypeInfo {
        id: 22,
        coe_name: "UNSIGNED24",
        esi_syntax: "UINT24",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED24",
        ssc_variable_type: "",
        bit_length: 24,
    },
    BaseDataTypeInfo {
        id: 24,
        coe_name: "UNSIGNED40",
        esi_syntax: "UINT40",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED40",
        ssc_variable_type: "",
        bit_length: 40,
    },
    BaseDataTypeInfo {
        id: 25,
        coe_name: "UNSIGNED48",
        esi_syntax: "UINT48",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED48",
        ssc_variable_type: "",
        bit_length: 48,
    },
    BaseDataTypeInfo {
        id: 26,
        coe_name: "UNSIGNED56",
        esi_syntax: "UINT56",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED56",
        ssc_variable_type: "",
        bit_length: 56,
    },
    BaseDataTypeInfo {
        id: 27,
        coe_name: "UNSIGNED64",
        esi_syntax: "ULINT",
        ssc_entry_info_syntax: "DEFTYPE_UNSIGNED64",
        ssc_variable_type: "UINT64",
        bit_length: 64,
    },
    BaseDataTypeInfo {
        id: 30,
        coe_name: "BYTE",
        esi_syntax: "BYTE",
        ssc_entry_info_syntax: "DEFTYPE_BYTE",
        ssc_variable_type: "UINT8",
        bit_length: 8,
    },
    BaseDataTypeInfo {
        id: 31,
        coe_name: "WORD",
        esi_syntax: "WORD",
        ssc_entry_info_syntax: "DEFTYPE_WORD",
        ssc_variable_type: "UINT16",
        bit_length: 16,
    },
    BaseDataTypeInfo {
        id: 32,
        coe_name: "DWORD",
        esi_syntax: "DWORD",
        ssc_entry_info_syntax: "DEFTYPE_DWORD",
        ssc_variable_type: "UINT32",
        bit_length: 32,
    },
    BaseDataTypeInfo {
        id: 33,
        coe_name: "PDO_MAPPING",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_PDOMAPPING",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 35,
        coe_name: "IDENTITY",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_IDENTITY",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 37,
        coe_name: "COMMAND_PAR",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_COMMAND",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 39,
        coe_name: "PDO_PARAMETER",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_PDOCOMPAR",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 40,
        coe_name: "ENUM",
        esi_syntax: "DTxxxxENnn",
        ssc_entry_info_syntax: "DEFTYPE_ENUM",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 41,
        coe_name: "SM_SYNCHRONISATION",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_SMPAR",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 42,
        coe_name: "RECORD",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_RECORD",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 43,
        coe_name: "BACKUP_PARAMETER",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_BACKUP",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 44,
        coe_name: "MODULAR_DEVICE_PROFILE",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_MDP",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 45,
        coe_name: "BITARR8",
        esi_syntax: "BITARR8",
        ssc_entry_info_syntax: "DEFTYPE_BITARR8",
        ssc_variable_type: "UINT8",
        bit_length: 8,
    },
    BaseDataTypeInfo {
        id: 46,
        coe_name: "BITARR16",
        esi_syntax: "BITARR16",
        ssc_entry_info_syntax: "DEFTYPE_BITARR16",
        ssc_variable_type: "UINT16",
        bit_length: 16,
    },
    BaseDataTypeInfo {
        id: 47,
        coe_name: "BITARR32",
        esi_syntax: "BITARR32",
        ssc_entry_info_syntax: "DEFTYPE_BITARR32",
        ssc_variable_type: "UINT32",
        bit_length: 32,
    },
    BaseDataTypeInfo {
        id: 48,
        coe_name: "BIT1",
        esi_syntax: "BIT1",
        ssc_entry_info_syntax: "DEFTYPE_BIT1",
        ssc_variable_type: "BIT1",
        bit_length: 1,
    },
    BaseDataTypeInfo {
        id: 49,
        coe_name: "BIT2",
        esi_syntax: "BIT2",
        ssc_entry_info_syntax: "DEFTYPE_BIT2",
        ssc_variable_type: "BIT2",
        bit_length: 2,
    },
    BaseDataTypeInfo {
        id: 50,
        coe_name: "BIT3",
        esi_syntax: "BIT3",
        ssc_entry_info_syntax: "DEFTYPE_BIT3",
        ssc_variable_type: "BIT3",
        bit_length: 3,
    },
    BaseDataTypeInfo {
        id: 51,
        coe_name: "BIT4",
        esi_syntax: "BIT4",
        ssc_entry_info_syntax: "DEFTYPE_BIT4",
        ssc_variable_type: "BIT4",
        bit_length: 4,
    },
    BaseDataTypeInfo {
        id: 52,
        coe_name: "BIT5",
        esi_syntax: "BIT5",
        ssc_entry_info_syntax: "DEFTYPE_BIT5",
        ssc_variable_type: "BIT5",
        bit_length: 5,
    },
    BaseDataTypeInfo {
        id: 53,
        coe_name: "BIT6",
        esi_syntax: "BIT6",
        ssc_entry_info_syntax: "DEFTYPE_BIT6",
        ssc_variable_type: "BIT6",
        bit_length: 6,
    },
    BaseDataTypeInfo {
        id: 54,
        coe_name: "BIT7",
        esi_syntax: "BIT7",
        ssc_entry_info_syntax: "DEFTYPE_BIT7",
        ssc_variable_type: "BIT7",
        bit_length: 7,
    },
    BaseDataTypeInfo {
        id: 55,
        coe_name: "BIT8",
        esi_syntax: "BIT8",
        ssc_entry_info_syntax: "DEFTYPE_BIT8",
        ssc_variable_type: "BIT8",
        bit_length: 8,
    },
    BaseDataTypeInfo {
        id: 56,
        coe_name: "BIT9",
        esi_syntax: "BIT9",
        ssc_entry_info_syntax: "0x0038",
        ssc_variable_type: "",
        bit_length: 9,
    },
    BaseDataTypeInfo {
        id: 57,
        coe_name: "BIT10",
        esi_syntax: "BIT10",
        ssc_entry_info_syntax: "0x0039",
        ssc_variable_type: "",
        bit_length: 10,
    },
    BaseDataTypeInfo {
        id: 58,
        coe_name: "BIT11",
        esi_syntax: "BIT11",
        ssc_entry_info_syntax: "0x003A",
        ssc_variable_type: "",
        bit_length: 11,
    },
    BaseDataTypeInfo {
        id: 59,
        coe_name: "BIT12",
        esi_syntax: "BIT12",
        ssc_entry_info_syntax: "0x003B",
        ssc_variable_type: "",
        bit_length: 12,
    },
    BaseDataTypeInfo {
        id: 60,
        coe_name: "BIT13",
        esi_syntax: "BIT13",
        ssc_entry_info_syntax: "0x003C",
        ssc_variable_type: "",
        bit_length: 13,
    },
    BaseDataTypeInfo {
        id: 61,
        coe_name: "BIT14",
        esi_syntax: "BIT14",
        ssc_entry_info_syntax: "0x003D",
        ssc_variable_type: "",
        bit_length: 14,
    },
    BaseDataTypeInfo {
        id: 62,
        coe_name: "BIT15",
        esi_syntax: "BIT15",
        ssc_entry_info_syntax: "0x003E",
        ssc_variable_type: "",
        bit_length: 15,
    },
    BaseDataTypeInfo {
        id: 63,
        coe_name: "BIT16",
        esi_syntax: "BIT16",
        ssc_entry_info_syntax: "0x003F",
        ssc_variable_type: "",
        bit_length: 16,
    },
    BaseDataTypeInfo {
        id: 608,
        coe_name: "ARRAY_OF_INT",
        esi_syntax: "ARRAY [0..n] OF INT",
        ssc_entry_info_syntax: "DEFTYPE_ARRAY_OF_INT",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 609,
        coe_name: "ARRAY_OF_SINT",
        esi_syntax: "ARRAY [0..n] OF SINT",
        ssc_entry_info_syntax: "DEFTYPE_ARRAY_OF_SINT",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 610,
        coe_name: "ARRAY_OF_DINT",
        esi_syntax: "ARRAY [0..n] OF DINT",
        ssc_entry_info_syntax: "DEFTYPE_ARRAY_OF_DINT",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 611,
        coe_name: "ARRAY_OF_UDINT",
        esi_syntax: "ARRAY [0..n] OF UDINT",
        ssc_entry_info_syntax: "DEFTYPE_ARRAY_OF_UDINT",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 641,
        coe_name: "ERROR_SETTING",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_ERRORHANDLING",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 642,
        coe_name: "DIAGNOSIS_HISTORY",
        esi_syntax: "",
        ssc_entry_info_syntax: "DEFTYPE_DIAGHISTORY",
        ssc_variable_type: "",
        bit_length: -1,
    },
    BaseDataTypeInfo {
        id: 65535,
        coe_name: "ANY_DATA_TYPE",
        esi_syntax: "",
        ssc_entry_info_syntax: "",
        ssc_variable_type: "",
        bit_length: -1,
    },
];

/// Parse `STRING(n)` returning `Some(n)` (or `Some(0)` for template `STRING(n)`).
fn parse_string_type_len(name: &str) -> Option<i32> {
    let trimmed = name.trim();
    let prefix = trimmed.get(..7)?;
    if !prefix.eq_ignore_ascii_case("STRING(") || !trimmed.ends_with(')') {
        return None;
    }
    let inner = trimmed.get(7..trimmed.len() - 1)?.trim();
    if inner.eq_ignore_ascii_case("n") || inner == "-1" {
        return Some(0);
    }
    inner.parse::<i32>().ok().filter(|&n| n >= 0)
}

/// Parse `ARRAY [0..n] OF <ELEM>` returning `Some((elem_upper, count))` where `count = n + 1`.
fn parse_array_type(name: &str) -> Option<(String, i32)> {
    let trimmed = name.trim();
    let upper = trimmed.to_ascii_uppercase();
    if !upper.starts_with("ARRAY") {
        return None;
    }
    let lb = upper.find('[')?;
    let rb = upper.find(']')?;
    if rb <= lb {
        return None;
    }
    let range = upper[lb + 1..rb].trim();
    let dots = range.find("..")?;
    let lo_str = range[..dots].trim();
    let hi_str = range[dots + 2..].trim();
    let lo: i32 = lo_str.parse().ok()?;
    let count = if hi_str == "N" || hi_str == "-1" {
        0
    } else {
        let hi: i32 = hi_str.parse().ok()?;
        (hi - lo + 1).max(0)
    };
    let rest = upper[rb + 1..].trim();
    let elem = rest.strip_prefix("OF")?.trim().to_string();
    Some((elem, count))
}

/// Parse `DT<xxxx>EN<nn>` returning `Some((enum_id, bit_len))`.
pub fn parse_enum_type_syntax(name: &str) -> Option<(u16, i32)> {
    let trimmed = name.trim();
    if trimmed.eq_ignore_ascii_case("DTxxxxENnn") {
        return Some((40, 0));
    }
    if !trimmed.to_ascii_uppercase().starts_with("DT") {
        return None;
    }
    let upper = trimmed.to_ascii_uppercase();
    let en_pos = upper.find("EN")?;
    if en_pos < 3 {
        return None;
    }
    let hex_part = &upper[2..en_pos];
    let bit_part = &upper[en_pos + 2..];
    let id = u16::from_str_radix(hex_part, 16).ok()?;
    let bits = bit_part.parse::<i32>().ok()?;
    Some((id, bits))
}

/// Check if an entry name is a default placeholder like `"SubIndex 001"` or empty.
pub fn is_default_subindex_name(name: &str) -> bool {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed
        .get(..8)
        .is_some_and(|p| p.eq_ignore_ascii_case("subindex"))
    {
        let digits = trimmed[8..].trim();
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
    } else {
        false
    }
}

pub fn get_data_type(id: u16) -> Option<&'static BaseDataTypeInfo> {
    let lookup = if (0x0800..=0x0FFF).contains(&id) {
        40
    } else {
        id
    };
    DATA_TYPES.iter().find(|dt| dt.id == lookup)
}

/// Look up `DataTypeId` and bit length from a type string (`UINT16`, `USINT`, `STRING(12)`, `DT0800EN08`, `pad_5`, etc.).
pub fn resolve_data_type_name(name: &str) -> Result<(u16, i32)> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Ok((0, 0));
    }
    if trimmed
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("pad_"))
    {
        let bits = trimmed[4..].trim().parse::<i32>().map_err(|_| {
            CliError::SscInvalidData(format!("Data type \"{trimmed}\" not supported"))
        })?;
        if bits < 0 {
            return Err(CliError::SscInvalidData(format!(
                "Data type \"{trimmed}\" not supported"
            )));
        }
        return Ok((0, bits));
    }
    if let Some(char_len) = parse_string_type_len(trimmed) {
        return Ok((9, char_len * 8));
    }
    if let Some((elem, count)) = parse_array_type(trimmed) {
        return match elem.as_str() {
            "BYTE" | "USINT" => Ok((10, count * 8)),
            "UINT" | "WORD" => Ok((11, count * 16)),
            "INT" => Ok((608, count * 16)),
            "SINT" => Ok((609, count * 8)),
            "DINT" => Ok((610, count * 32)),
            "UDINT" | "DWORD" => Ok((611, count * 32)),
            _ => Err(CliError::SscInvalidData(format!(
                "Data type \"{trimmed}\" not supported"
            ))),
        };
    }
    if let Some((enum_id, bits)) = parse_enum_type_syntax(trimmed) {
        return Ok((enum_id, bits));
    }
    if let Some(hex_str) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .or_else(|| trimmed.strip_prefix("#x"))
        .or_else(|| trimmed.strip_prefix("#X"))
    {
        if let Ok(id) = u16::from_str_radix(hex_str, 16) {
            if let Some(dt) = get_data_type(id) {
                return Ok((id, dt.bit_length.max(0)));
            }
        }
    }
    if trimmed.eq_ignore_ascii_case("BOOL") {
        return Ok((1, 1));
    }
    for dt in DATA_TYPES {
        if (!dt.coe_name.is_empty() && dt.coe_name.eq_ignore_ascii_case(trimmed))
            || (!dt.esi_syntax.is_empty() && dt.esi_syntax.eq_ignore_ascii_case(trimmed))
            || (!dt.ssc_entry_info_syntax.is_empty()
                && dt.ssc_entry_info_syntax.eq_ignore_ascii_case(trimmed))
            || (!dt.ssc_variable_type.is_empty()
                && dt.ssc_variable_type.eq_ignore_ascii_case(trimmed))
        {
            return Ok((dt.id, dt.bit_length.max(0)));
        }
    }
    Err(CliError::SscInvalidData(format!(
        "Data type \"{trimmed}\" not supported"
    )))
}

/// Exact parity with `BaseDataTypeHandler::GetDataTypeID(Int32 bitlen)` (first matching entry in `DATA_TYPES`).
pub fn get_data_type_id_by_bitlen(bitlen: i32) -> Result<u16> {
    if bitlen <= 0 {
        return Ok(0);
    }
    for dt in DATA_TYPES {
        if dt.bit_length == bitlen {
            return Ok(dt.id);
        }
    }
    Err(CliError::SscInvalidData(format!(
        "No data type for bitsize {bitlen} defined"
    )))
}

pub fn is_bit_type(id: u16) -> bool {
    id == 1 || (48..=63).contains(&id)
}

/// Format ESI `<Type>` name for an entry (`STRING(12)`, `ARRAY [0..3] OF BYTE`, `DT0800`, `UINT`, etc.).
pub fn create_esi_syntax_for_entry(entry: &EntryInfo) -> String {
    let id = entry.data_type_id;
    if id == 0 {
        return String::new();
    }
    if (0x0800..=0x0FFF).contains(&id) {
        return format!("DT{id:04X}EN{:02}", entry.bit_length);
    }
    match id {
        9 => {
            let chars = (entry.bit_length / 8).max(0);
            format!("STRING({chars})")
        }
        10 => {
            let hi = ((entry.bit_length / 8) - 1).max(0);
            format!("ARRAY [0..{hi}] OF BYTE")
        }
        11 => {
            let hi = ((entry.bit_length / 16) - 1).max(0);
            format!("ARRAY [0..{hi}] OF UINT")
        }
        608 => {
            let hi = ((entry.bit_length / 16) - 1).max(0);
            format!("ARRAY [0..{hi}] OF INT")
        }
        609 => {
            let hi = ((entry.bit_length / 8) - 1).max(0);
            format!("ARRAY [0..{hi}] OF SINT")
        }
        610 => {
            let hi = ((entry.bit_length / 32) - 1).max(0);
            format!("ARRAY [0..{hi}] OF DINT")
        }
        611 => {
            let hi = ((entry.bit_length / 32) - 1).max(0);
            format!("ARRAY [0..{hi}] OF UDINT")
        }
        _ => get_data_type(id)
            .map(|dt| dt.esi_syntax.to_string())
            .unwrap_or_default(),
    }
}

/// Reverse 2-hex-char byte pairs (`"0x12345678"` or `"12345678"` -> `"78563412"`), matching `DataTable::GetHexString`.
pub fn reverse_hex_byte_pairs(hex_str: &str) -> String {
    let trimmed = hex_str.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return String::new();
    }
    let mut digits: Vec<u8> = stripped
        .bytes()
        .filter(|b| b.is_ascii_hexdigit())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if digits.is_empty() {
        return String::new();
    }
    if digits.len() % 2 == 1 {
        digits.insert(0, b'0');
    }
    let mut out = String::with_capacity(digits.len());
    for pair in digits.as_chunks::<2>().0.iter().rev() {
        out.push(pair[0] as char);
        out.push(pair[1] as char);
    }
    out
}

/// Convert a CSV/XLSX string value (`"0x12345678"`, `"100"`, `"25.5"`, `"ECAT-AI"`) into `EntryInfo.default_data`
/// with exact parity to `ConvertStringValueToObject` -> `ConvertObjectToHexDataString` -> `DataTable::GetHexString`.
pub fn convert_table_value_to_default_data(
    data_type_id: u16,
    bit_length: i32,
    raw_value: &str,
) -> Result<String> {
    let val = raw_value.trim();
    if val.is_empty() {
        return Ok(String::new());
    }

    let id = if (0x0800..=0x0FFF).contains(&data_type_id) || data_type_id == 40 {
        get_data_type_id_by_bitlen(bit_length).unwrap_or(5)
    } else {
        data_type_id
    };

    // VISIBLE_STRING (id == 9): note that `0x...` hex input is decoded to string, else literal string bytes,
    // then `ConvertObjectToHexDataString` emits `"0x" + forward_ascii_hex`, and `DataTable::GetHexString` reverses byte pairs!
    if id == 9 {
        let bytes: Vec<u8> =
            if let Some(hex_part) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
                let padded = if hex_part.len() % 2 == 1 {
                    format!("0{hex_part}")
                } else {
                    hex_part.to_string()
                };
                let mut decoded = Vec::with_capacity(padded.len() / 2);
                for chunk in padded.as_bytes().chunks(2) {
                    let s = std::str::from_utf8(chunk).unwrap_or("00");
                    decoded.push(u8::from_str_radix(s, 16).map_err(|_| {
                        CliError::SscInvalidData(format!("Invalid hex string default '{val}'"))
                    })?);
                }
                decoded
            } else {
                val.as_bytes().to_vec()
            };
        let mut forward_hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            forward_hex.push_str(&format!("{b:02X}"));
        }
        return Ok(reverse_hex_byte_pairs(&forward_hex));
    }

    // Byte / integer arrays (10, 11, 608..611)
    if matches!(id, 10 | 11 | 608 | 609 | 610 | 611) {
        let elem_hex_chars = match id {
            10 | 609 => 2usize,
            11 | 608 => 4usize,
            610 | 611 => 8usize,
            _ => 2usize,
        };
        if let Some(hex_part) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            if !hex_part.contains(',') && !hex_part.contains('-') {
                if !hex_part
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
                {
                    return Err(CliError::SscInvalidData(format!(
                        "Invalid hex array value '{val}'"
                    )));
                }
                return Ok(reverse_hex_byte_pairs(hex_part));
            }
        }
        let mut forward_hex = String::new();
        for token in val.split([',', '-']) {
            let t = token.trim();
            if t.is_empty() {
                continue;
            }
            let num: i64 = if let Some(hx) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                i64::from_str_radix(hx, 16)
                    .map_err(|_| CliError::SscInvalidData(format!("Invalid array element '{t}'")))?
            } else {
                t.parse::<i64>()
                    .map_err(|_| CliError::SscInvalidData(format!("Invalid array element '{t}'")))?
            };
            let mask: u64 = match elem_hex_chars {
                2 => 0xFF,
                4 => 0xFFFF,
                8 => 0xFFFF_FFFF,
                _ => u64::MAX,
            };
            let u = (num as u64) & mask;
            forward_hex.push_str(&format!("{u:0width$X}", width = elem_hex_chars));
        }
        return Ok(reverse_hex_byte_pairs(&forward_hex));
    }

    // REAL32 (id == 8)
    if id == 8 {
        let bits: u32 = if let Some(hx) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X"))
        {
            u32::from_str_radix(hx, 16)
                .map_err(|_| CliError::SscInvalidData(format!("Invalid REAL32 hex '{val}'")))?
        } else {
            let f: f32 = val
                .parse()
                .map_err(|_| CliError::SscInvalidData(format!("Invalid REAL32 '{val}'")))?;
            f.to_bits()
        };
        let be_hex = format!("{bits:08X}");
        return Ok(reverse_hex_byte_pairs(&be_hex));
    }

    // REAL64 (id == 17)
    if id == 17 {
        let bits: u64 = if let Some(hx) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X"))
        {
            u64::from_str_radix(hx, 16)
                .map_err(|_| CliError::SscInvalidData(format!("Invalid REAL64 hex '{val}'")))?
        } else {
            let d: f64 = val
                .parse()
                .map_err(|_| CliError::SscInvalidData(format!("Invalid REAL64 '{val}'")))?;
            d.to_bits()
        };
        let be_hex = format!("{bits:016X}");
        return Ok(reverse_hex_byte_pairs(&be_hex));
    }

    // BOOLEAN (id == 1)
    if id == 1 {
        let b = if let Some(hx) = val.strip_prefix("0x").or_else(|| val.strip_prefix("0X")) {
            let v = u64::from_str_radix(hx, 16)
                .map_err(|_| CliError::SscInvalidData(format!("Invalid BOOL '{val}'")))?;
            v != 0
        } else if val == "1" || val == "01" || val.eq_ignore_ascii_case("true") {
            true
        } else if val == "0" || val == "00" || val.eq_ignore_ascii_case("false") {
            false
        } else {
            return Err(CliError::SscInvalidData(format!(
                "Failed to convert '{val}' to bool"
            )));
        };
        return Ok(if b {
            "01".to_string()
        } else {
            "00".to_string()
        });
    }

    // Scalar signed / unsigned / bit integers
    let byte_width = (((bit_length.max(8) + 7) / 8) as usize).max(1);
    let hex_digits = byte_width * 2;
    let unsigned_bits: u64 = if let Some(hx) = val
        .strip_prefix("0x")
        .or_else(|| val.strip_prefix("0X"))
        .or_else(|| val.strip_prefix("#x"))
        .or_else(|| val.strip_prefix("#X"))
    {
        u64::from_str_radix(hx, 16)
            .map_err(|_| CliError::SscInvalidData(format!("Invalid hex integer '{val}'")))?
    } else if val.starts_with('-') {
        let signed: i64 = val
            .parse()
            .map_err(|_| CliError::SscInvalidData(format!("Invalid signed integer '{val}'")))?;
        signed as u64
    } else {
        val.parse::<u64>()
            .map_err(|_| CliError::SscInvalidData(format!("Invalid integer '{val}'")))?
    };
    let mask = if hex_digits >= 16 {
        u64::MAX
    } else {
        (1u64 << (hex_digits * 4)) - 1
    };
    let be_hex = format!("{:0width$X}", unsigned_bits & mask, width = hex_digits);
    Ok(reverse_hex_byte_pairs(&be_hex))
}

/// Encode an ASCII string into forward uppercase hex (`"SSC-Device"` -> `"5353432D446576696365"`),
/// matching `SlaveProject::GetAsciiString`.
pub fn encode_ascii_hex_forward(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// CoE SDO Read/Write access flags matching `ET9300Utilities.ApplicationHandler.EntryFlags`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessFlags {
    pub read_preop: bool,
    pub read_safeop: bool,
    pub read_op: bool,
    pub write_preop: bool,
    pub write_safeop: bool,
    pub write_op: bool,
}

impl Default for AccessFlags {
    fn default() -> Self {
        Self::RO
    }
}

impl AccessFlags {
    pub const RO: Self = Self {
        read_preop: true,
        read_safeop: true,
        read_op: true,
        write_preop: false,
        write_safeop: false,
        write_op: false,
    };

    pub const RW: Self = Self {
        read_preop: true,
        read_safeop: true,
        read_op: true,
        write_preop: true,
        write_safeop: true,
        write_op: true,
    };

    pub const WO: Self = Self {
        read_preop: false,
        read_safeop: false,
        read_op: false,
        write_preop: true,
        write_safeop: true,
        write_op: true,
    };

    pub const RW_PREOP_RO_OTHER: Self = Self {
        read_preop: true,
        read_safeop: true,
        read_op: true,
        write_preop: true,
        write_safeop: false,
        write_op: false,
    };

    pub fn any_read(self) -> bool {
        self.read_preop || self.read_safeop || self.read_op
    }

    pub fn all_read(self) -> bool {
        self.read_preop && self.read_safeop && self.read_op
    }

    pub fn any_write(self) -> bool {
        self.write_preop || self.write_safeop || self.write_op
    }

    pub fn all_write(self) -> bool {
        self.write_preop && self.write_safeop && self.write_op
    }

    /// Parse CSV/XLSX/ESI access specification such as `"ro"`, `"rw"`, `"wo"`, `"rw-p"`, `"ro/preop"`, etc.,
    /// plus optional ESI `ReadRestrictions` / `WriteRestrictions` attributes.
    pub fn parse_str(raw: &str, read_restr: Option<&str>, write_restr: Option<&str>) -> Self {
        let norm = raw.trim().to_ascii_lowercase();
        let mut flags = match norm.as_str() {
            "" | "ro" => Self::RO,
            "rw" => Self::RW,
            "wo" => Self::WO,
            "rw_preop" | "rwp" | "rw-p" | "rw (preop)" => Self::RW_PREOP_RO_OTHER,
            "rw_safeop" | "rws" | "rw-s" => Self {
                read_preop: true,
                read_safeop: true,
                read_op: true,
                write_preop: false,
                write_safeop: true,
                write_op: false,
            },
            "rw_op" | "rwo" | "rw-o" => Self {
                read_preop: true,
                read_safeop: true,
                read_op: true,
                write_preop: false,
                write_safeop: false,
                write_op: true,
            },
            "rw_preop_safeop" | "rwps" => Self {
                read_preop: true,
                read_safeop: true,
                read_op: true,
                write_preop: true,
                write_safeop: true,
                write_op: false,
            },
            "rw_preop_op" | "rwpo" => Self {
                read_preop: true,
                read_safeop: true,
                read_op: true,
                write_preop: true,
                write_safeop: false,
                write_op: true,
            },
            "rw_safeop_op" | "rwso" => Self {
                read_preop: true,
                read_safeop: true,
                read_op: true,
                write_preop: false,
                write_safeop: true,
                write_op: true,
            },
            _ => {
                // Underscore-delimited state tokens like `r_p_s_o_w_p`
                if norm.contains('w') && norm.contains("preop") && !norm.contains("op_") {
                    Self::RW_PREOP_RO_OTHER
                } else if norm.starts_with("rw") {
                    Self::RW
                } else if norm.starts_with("wo") {
                    Self::WO
                } else {
                    Self::RO
                }
            }
        };

        if let Some(rr) = read_restr {
            if !rr.trim().is_empty() {
                let rlow = rr.to_ascii_lowercase();
                flags.read_preop = rlow.contains("preop");
                flags.read_safeop = rlow.contains("safeop");
                flags.read_op = rlow
                    .split('_')
                    .any(|tok| tok.trim() == "op" || tok.trim() == "operational");
            }
        }
        if let Some(wr) = write_restr {
            if !wr.trim().is_empty() {
                let wlow = wr.to_ascii_lowercase();
                flags.write_preop = wlow.contains("preop");
                flags.write_safeop = wlow.contains("safeop");
                flags.write_op = wlow
                    .split('_')
                    .any(|tok| tok.trim() == "op" || tok.trim() == "operational");
            }
        }
        flags
    }

    /// Return `(access_text, read_restrictions_attr, write_restrictions_attr)` for ESI `<Access>`.
    pub fn to_esi_access(self) -> (&'static str, Option<String>, Option<String>) {
        let text = if self.any_read() && self.any_write() {
            "rw"
        } else if self.any_write() {
            "wo"
        } else {
            "ro"
        };

        let read_restr = if self.any_read() && !self.all_read() {
            let mut parts = Vec::new();
            if self.read_preop {
                parts.push("PreOP");
            }
            if self.read_safeop {
                parts.push("SafeOP");
            }
            if self.read_op {
                parts.push("OP");
            }
            Some(parts.join("_"))
        } else {
            None
        };

        let write_restr = if self.any_write() && !self.all_write() {
            let mut parts = Vec::new();
            if self.write_preop {
                parts.push("PreOP");
            }
            if self.write_safeop {
                parts.push("SafeOP");
            }
            if self.write_op {
                parts.push("OP");
            }
            Some(parts.join("_"))
        } else {
            None
        };

        (text, read_restr, write_restr)
    }

    /// Format SSC C access macro expression (e.g. `ACCESS_READ`, `ACCESS_READWRITE`, `ACCESS_READ | ACCESS_WRITE_PREOP`).
    pub fn to_ssc_c_syntax(self) -> String {
        if self == Self::RW {
            return "ACCESS_READWRITE".to_string();
        }
        if self == Self::RO {
            return "ACCESS_READ".to_string();
        }
        if self == Self::WO {
            return "ACCESS_WRITE".to_string();
        }
        let mut parts = Vec::new();
        if self.all_read() {
            parts.push("ACCESS_READ");
        } else {
            if self.read_preop {
                parts.push("ACCESS_READ_PREOP");
            }
            if self.read_safeop {
                parts.push("ACCESS_READ_SAFEOP");
            }
            if self.read_op {
                parts.push("ACCESS_READ_OP");
            }
        }
        if self.all_write() {
            parts.push("ACCESS_WRITE");
        } else {
            if self.write_preop {
                parts.push("ACCESS_WRITE_PREOP");
            }
            if self.write_safeop {
                parts.push("ACCESS_WRITE_SAFEOP");
            }
            if self.write_op {
                parts.push("ACCESS_WRITE_OP");
            }
        }
        if parts.is_empty() {
            "ACCESS_READ".to_string()
        } else {
            parts.join(" | ")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum PdoMappingMode {
    #[default]
    None,
    Rx,
    Tx,
    RxOrTx,
    TxAndRx,
}

impl PdoMappingMode {
    pub fn parse_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "rx" | "r" => Self::Rx,
            "tx" | "t" => Self::Tx,
            "rxtx" | "rt" => Self::RxOrTx,
            "txrx" | "tr" => Self::TxAndRx,
            _ => Self::None,
        }
    }

    pub fn to_esi_str(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Rx => Some("r"),
            Self::Tx => Some("t"),
            Self::RxOrTx => Some("rt"),
            Self::TxAndRx => Some("tr"),
        }
    }

    pub fn allows_rx(self) -> bool {
        matches!(self, Self::Rx | Self::RxOrTx | Self::TxAndRx)
    }

    pub fn allows_tx(self) -> bool {
        matches!(self, Self::Tx | Self::RxOrTx | Self::TxAndRx)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EntryFlags {
    pub access: AccessFlags,
    pub pdo_mapping: PdoMappingMode,
    pub backup: bool,
    pub setting: bool,
}

impl EntryFlags {
    pub const RO: Self = Self {
        access: AccessFlags::RO,
        pdo_mapping: PdoMappingMode::None,
        backup: false,
        setting: false,
    };

    pub const RW: Self = Self {
        access: AccessFlags::RW,
        pdo_mapping: PdoMappingMode::None,
        backup: false,
        setting: false,
    };

    pub fn to_ssc_c_syntax(self) -> String {
        let mut s = self.access.to_ssc_c_syntax();
        match self.pdo_mapping {
            PdoMappingMode::None => {}
            PdoMappingMode::Rx => s.push_str(" | OBJACCESS_RXPDOMAPPING"),
            PdoMappingMode::Tx => s.push_str(" | OBJACCESS_TXPDOMAPPING"),
            PdoMappingMode::RxOrTx | PdoMappingMode::TxAndRx => {
                s.push_str(" | OBJACCESS_RXPDOMAPPING | OBJACCESS_TXPDOMAPPING");
            }
        }
        if self.backup {
            s.push_str(" | OBJACCESS_BACKUP");
        }
        if self.setting {
            s.push_str(" | OBJACCESS_SETTINGS");
        }
        s
    }

    pub fn to_esi_flags_element(self, include_category: Option<ObjectCategory>) -> DomElement {
        let mut flags_el = DomElement::new("Flags");
        let (acc_txt, r_restr, w_restr) = self.access.to_esi_access();
        let mut acc_el = DomElement::with_text("Access", acc_txt);
        if let Some(rr) = r_restr {
            acc_el.set_attr("ReadRestrictions", rr);
        }
        if let Some(wr) = w_restr {
            acc_el.set_attr("WriteRestrictions", wr);
        }
        flags_el.push_child(DomNode::Element(acc_el));
        if let Some(cat) = include_category {
            if let Some(cat_str) = cat.to_esi_str() {
                flags_el.push_child(DomNode::Element(DomElement::with_text("Category", cat_str)));
            }
        }
        if let Some(pdo_str) = self.pdo_mapping.to_esi_str() {
            flags_el.push_child(DomNode::Element(DomElement::with_text(
                "PdoMapping",
                pdo_str,
            )));
        }
        if self.backup {
            flags_el.push_child(DomNode::Element(DomElement::with_text("Backup", "1")));
        }
        if self.setting {
            flags_el.push_child(DomNode::Element(DomElement::with_text("Setting", "1")));
        }
        flags_el
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ObjectCategory {
    #[default]
    Optional,
    Mandatory,
    Conditional,
}

impl ObjectCategory {
    pub fn parse_str(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "m" | "mandatory" => Self::Mandatory,
            "c" | "conditional" => Self::Conditional,
            _ => Self::Optional,
        }
    }

    pub fn to_esi_str(self) -> Option<&'static str> {
        match self {
            Self::Optional => Some("o"),
            Self::Mandatory => Some("m"),
            Self::Conditional => Some("c"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ObjectCode {
    #[default]
    None = 0,
    Domain = 2,
    Deftype = 5,
    Defstruct = 6,
    Variable = 7,
    Array = 8,
    Record = 9,
}

impl ObjectCode {
    pub fn parse_str(s: &str) -> Self {
        match s.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" | "2" => Self::Domain,
            "DEFTYPE" | "5" => Self::Deftype,
            "DEFSTRUCT" | "6" => Self::Defstruct,
            "VAR" | "VARIABLE" | "7" => Self::Variable,
            "ARRAY" | "ARR" | "8" => Self::Array,
            "RECORD" | "REC" | "9" => Self::Record,
            _ => Self::None,
        }
    }
}

/// Single subindex / entry of an `ObjectInfo`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntryInfo {
    pub sub_index: u8,
    pub name: String,
    pub data_type_id: u16,
    pub bit_length: i32,
    pub bit_offset: i32,
    pub flags: EntryFlags,
    /// Little-endian hex string (`"78563412"`, `"0000CC41"`, etc.) or forward ASCII hex on `0x1008`..`0x100A`.
    pub default_data: String,
    pub min_data: String,
    pub max_data: String,
    pub unit: Option<u32>,
    pub description: String,
    pub coe_read_callback: String,
    pub coe_write_callback: String,
    /// For `ENUM` (`0x0800..0x0FFF`) entries: integer enum value (`<Value>` in `<EnumInfo>`).
    pub enum_value: Option<i32>,
    /// Optional per-entry category (`m` / `o` / `c`) emitted in enhanced `.esp` `<Application>` dictionaries.
    #[serde(default)]
    pub category: Option<ObjectCategory>,
}

impl EntryInfo {
    pub fn effective_name(&self) -> String {
        if self.name.is_empty() {
            format!("SubIndex {:03}", self.sub_index)
        } else {
            self.name.clone()
        }
    }

    /// Inherit missing fields from a referenced base `EntryInfo` (`EntryInfo::InheritFrom` parity).
    pub fn inherit_from(&mut self, base: &Self) {
        if self.name.trim().is_empty() {
            self.name = base.name.clone();
        }
        if self.data_type_id == 0 {
            self.data_type_id = base.data_type_id;
        }
        if self.bit_length <= 0 {
            self.bit_length = base.bit_length;
        }
        if self.default_data.is_empty() {
            self.default_data = base.default_data.clone();
        }
        if self.min_data.is_empty() {
            self.min_data = base.min_data.clone();
        }
        if self.max_data.is_empty() {
            self.max_data = base.max_data.clone();
        }
        if self.unit.is_none() {
            self.unit = base.unit;
        }
        if self.description.is_empty() {
            self.description = base.description.clone();
        }
        if self.coe_read_callback.is_empty() {
            self.coe_read_callback = base.coe_read_callback.clone();
        }
        if self.coe_write_callback.is_empty() {
            self.coe_write_callback = base.coe_write_callback.clone();
        }
        if self.category.is_none() {
            self.category = base.category;
        }
    }
}

/// CoE Object Dictionary object (`0x0000..=0xFFFF`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectInfo {
    pub index: u16,
    pub name: String,
    pub object_code: ObjectCode,
    /// Optional explicit object-level `DEFTYPE_*` (`33` `PDO_MAPPING`, `35` `IDENTITY`, `42` `RECORD`, etc.).
    pub data_type_id: u16,
    pub category: ObjectCategory,
    #[serde(default)]
    pub has_explicit_category: bool,
    pub entries: Vec<EntryInfo>,
    pub depend_on_slot: bool,
    pub depend_on_slot_group: bool,
    pub coe_read_callback: String,
    pub coe_write_callback: String,
    pub variable_name_override: Option<String>,
    pub description: String,
    /// Preserves raw XML `<Object>` / `<DataType>` nodes for passthrough built-in / preserved ESI objects when needed.
    #[serde(skip)]
    pub raw_esi_object: Option<DomElement>,
    #[serde(skip)]
    pub raw_esi_datatypes: Vec<DomElement>,
}

impl ObjectInfo {
    pub fn new(index: u16, name: impl Into<String>, object_code: ObjectCode) -> Self {
        Self {
            index,
            name: name.into(),
            object_code,
            data_type_id: 0,
            category: ObjectCategory::Optional,
            has_explicit_category: false,
            entries: Vec::new(),
            depend_on_slot: false,
            depend_on_slot_group: false,
            coe_read_callback: String::new(),
            coe_write_callback: String::new(),
            variable_name_override: None,
            description: String::new(),
            raw_esi_object: None,
            raw_esi_datatypes: Vec::new(),
        }
    }

    pub fn is_enum_object(&self) -> bool {
        (0x0800..=0x0FFF).contains(&self.index)
    }

    pub fn is_rx_pdo_mapping(&self) -> bool {
        (0x1600..=0x17FF).contains(&self.index)
    }

    pub fn is_tx_pdo_mapping(&self) -> bool {
        (0x1A00..=0x1BFF).contains(&self.index)
    }

    pub fn is_pdo_mapping_object(&self) -> bool {
        self.is_rx_pdo_mapping() || self.is_tx_pdo_mapping()
    }

    pub fn is_sm_assign_object(&self) -> bool {
        (0x1C10..=0x1C2F).contains(&self.index)
    }

    pub fn entry(&self, sub_index: u8) -> Option<&EntryInfo> {
        self.entries.iter().find(|e| e.sub_index == sub_index)
    }

    pub fn entry_mut(&mut self, sub_index: u8) -> Option<&mut EntryInfo> {
        self.entries.iter_mut().find(|e| e.sub_index == sub_index)
    }

    /// Number of subindex entries excluding SubIndex 0 (or 0 for `VAR`).
    pub fn max_sub_index(&self) -> u8 {
        self.entries
            .iter()
            .filter(|e| e.data_type_id != 0 || e.sub_index > 0)
            .map(|e| e.sub_index)
            .max()
            .unwrap_or(0)
    }

    /// Number of declared entries excluding SI0 for `ARRAY`/`RECORD`.
    pub fn num_sub_entries(&self) -> usize {
        self.entries.iter().filter(|e| e.sub_index > 0).count()
    }

    /// Promote/normalize `object_code` and `data_type_id`, and recalculate bit offsets!
    /// Note the critical Beckhoff rule: if `object_code == Array` AND any subindex > 0 has a custom
    /// non-default name (e.g. `"Gain 1"` instead of `"SubIndex 001"` / `""`) AND `!is_sm_assign_object()`
    /// AND `!is_enum_object()`, SSC C codegen treats it as `Record` (`DEFTYPE_RECORD` / `OBJCODE_REC`)
    /// so custom subindex names are emitted in `aName0xXXXX`!
    pub fn finalize_layout(&mut self) {
        if self.is_enum_object() {
            self.data_type_id = 40;
            if self.object_code == ObjectCode::None {
                self.object_code = ObjectCode::Array;
            }
            return;
        }

        // Sort entries by sub_index while preserving padding order if sub_index == 0 for VAR vs SI0
        self.entries.sort_by_key(|e| e.sub_index);

        if self.object_code == ObjectCode::None {
            if self.entries.len() == 1
                && self.entries.first().map(|e| e.sub_index).unwrap_or(0) == 0
            {
                self.object_code = ObjectCode::Variable;
            } else {
                let all_same_type = {
                    let mut types = self
                        .entries
                        .iter()
                        .filter(|e| e.sub_index > 0)
                        .map(|e| (e.data_type_id, e.bit_length));
                    if let Some(first) = types.next() {
                        types.all(|t| t == first)
                    } else {
                        false
                    }
                };
                let has_custom_names = self
                    .entries
                    .iter()
                    .filter(|e| e.sub_index > 0)
                    .any(|e| !is_default_subindex_name(&e.name));
                if all_same_type && !has_custom_names {
                    self.object_code = ObjectCode::Array;
                } else {
                    self.object_code = ObjectCode::Record;
                }
            }
        } else if self.object_code == ObjectCode::Array && !self.is_sm_assign_object() {
            // `ObjectInfo::UpdateObjectCode`: promote `ARRAY` to `RECORD` when subentries have custom names
            // or heterogeneous types/bit-lengths (e.g. `0x2001` `GainTable` with `"Gain 1"`, `"Gain 2"`).
            let all_same_type = {
                let mut types = self
                    .entries
                    .iter()
                    .filter(|e| e.sub_index > 0)
                    .map(|e| (e.data_type_id, e.bit_length));
                if let Some(first) = types.next() {
                    types.all(|t| t == first)
                } else {
                    true
                }
            };
            let has_custom_names = self
                .entries
                .iter()
                .filter(|e| e.sub_index > 0)
                .any(|e| !is_default_subindex_name(&e.name));
            if !all_same_type || has_custom_names {
                self.object_code = ObjectCode::Record;
            }
        }

        // Ensure SI0 exists for ARRAY / RECORD objects
        let si0_cat = if self.has_explicit_category {
            Some(self.category)
        } else {
            None
        };
        if matches!(self.object_code, ObjectCode::Array | ObjectCode::Record)
            && !self.entries.iter().any(|e| e.sub_index == 0)
        {
            let max_si = self.max_sub_index();
            let si0 = EntryInfo {
                sub_index: 0,
                name: "SubIndex 000".to_string(),
                data_type_id: 5, // UNSIGNED8
                bit_length: 8,
                bit_offset: 0,
                flags: EntryFlags::RO,
                default_data: format!("{max_si:02X}"),
                category: si0_cat,
                ..Default::default()
            };
            self.entries.insert(0, si0);
        } else if matches!(self.object_code, ObjectCode::Array | ObjectCode::Record) {
            let max_si = self.max_sub_index();
            if let Some(si0) = self.entry_mut(0) {
                if si0.default_data.is_empty() {
                    si0.default_data = format!("{max_si:02X}");
                }
                if si0.name.is_empty() {
                    si0.name = "SubIndex 000".to_string();
                }
                if si0.category.is_none() && si0_cat.is_some() {
                    si0.category = si0_cat;
                }
            }
        }

        // Fill missing subentry names as `"SubIndex XXX"` when empty? Keep empty in `entry.name` if needed,
        // or remember `is_default_subindex_name` matches both `""` and `"SubIndex 003"`!
        if self.data_type_id == 0 {
            if self.is_pdo_mapping_object() {
                self.data_type_id = 33; // PDO_MAPPING
            } else if self.index == 0x1018 {
                self.data_type_id = 35; // IDENTITY
            } else if self.index == 0x1C32 || self.index == 0x1C33 {
                self.data_type_id = 41; // SM_SYNCHRONISATION
            } else if self.object_code == ObjectCode::Variable {
                self.data_type_id = self.entries.first().map(|e| e.data_type_id).unwrap_or(0);
            } else if self.object_code == ObjectCode::Array {
                let has_custom_names = self
                    .entries
                    .iter()
                    .filter(|e| e.sub_index > 0)
                    .any(|e| !is_default_subindex_name(&e.name));
                if has_custom_names && !self.is_sm_assign_object() {
                    self.data_type_id = 42; // RECORD in SSC when custom subindex names exist!
                } else {
                    self.data_type_id = self
                        .entries
                        .iter()
                        .find(|e| e.sub_index > 0)
                        .or_else(|| self.entries.first())
                        .map(|e| e.data_type_id)
                        .unwrap_or(5);
                }
            } else {
                self.data_type_id = 42; // RECORD
            }
        }

        // Propagate CoE callbacks from subentries if object-level callback is empty
        if self.coe_read_callback.is_empty() {
            if let Some(cb) = self
                .entries
                .iter()
                .find(|e| !e.coe_read_callback.is_empty())
                .map(|e| e.coe_read_callback.clone())
            {
                self.coe_read_callback = cb;
            }
        }
        if self.coe_write_callback.is_empty() {
            if let Some(cb) = self
                .entries
                .iter()
                .find(|e| !e.coe_write_callback.is_empty())
                .map(|e| e.coe_write_callback.clone())
            {
                self.coe_write_callback = cb;
            }
        }

        self.recalculate_bit_offsets();
    }

    /// Effective `ObjectCode` for SSC C codegen (`ARRAY` with custom subentry names -> `Record`).
    pub fn effective_ssc_object_code(&self) -> ObjectCode {
        if self.is_enum_object() {
            return ObjectCode::Record;
        }
        if self.is_pdo_mapping_object() {
            return ObjectCode::Record;
        }
        if self.object_code == ObjectCode::Array
            && !self.is_sm_assign_object()
            && self
                .entries
                .iter()
                .filter(|e| e.sub_index > 0)
                .any(|e| !is_default_subindex_name(&e.name))
        {
            return ObjectCode::Record;
        }
        self.object_code
    }

    /// Compute ETG.2000 bit offsets for `VAR` / `ARRAY` / `RECORD`:
    /// - SI0 starts at bit 0 (8 bits), followed by 8-bit pad so SI1 starts at bit 16!
    /// - Entries with `bit_length >= 16` align up to a 16-bit word boundary (`(offs + 15) & !15`).
    /// - Entries with `bit_length == 8` (and not bit-type `BIT1..BIT8`) align up to an 8-bit byte boundary (`(offs + 7) & !7`).
    /// - Total struct bit size for `ARRAY` / `RECORD` aligns up to an 8-bit byte boundary (`(end + 7) & !7`),
    ///   preserving any explicit `BitOffset` set on sparse subindices (such as `0x1C32:32` at bit 480 -> `BitSize = 488`).
    pub fn recalculate_bit_offsets(&mut self) {
        if self.object_code == ObjectCode::Variable {
            if let Some(first) = self.entries.first_mut() {
                first.bit_offset = 0;
            }
            return;
        }
        // Preserve pre-computed sparse offsets (e.g., 0x1C32/0x1C33 where SI8 is at 208 after skipped SI7 and SI32 is at 480)
        let has_explicit_offsets = self
            .entries
            .iter()
            .any(|e| e.sub_index > 0 && e.bit_offset > 0);
        if has_explicit_offsets {
            return;
        }
        let mut offset = 0i32;
        for entry in &mut self.entries {
            if entry.sub_index == 0 && entry.bit_offset == 0 && offset == 0 {
                entry.bit_offset = 0;
                offset = 16; // SI0 occupies 16-bit aligned slot (0..8 + 8 pad -> SI1 at 16)
                continue;
            }
            if entry.bit_length >= 16 && !is_bit_type(entry.data_type_id) {
                offset = (offset + 15) & !15;
            } else if entry.bit_length == 8
                && !is_bit_type(entry.data_type_id)
                && entry.data_type_id != 0
            {
                offset = (offset + 7) & !7;
            }
            entry.bit_offset = offset;
            offset += entry.bit_length.max(0);
        }
    }

    pub fn total_bit_size(&self) -> i32 {
        if self.is_enum_object() {
            let bits = self
                .entries
                .iter()
                .find(|e| e.sub_index > 0)
                .map(|e| e.bit_length)
                .unwrap_or(8);
            return bits.max(1);
        }
        if self.object_code == ObjectCode::Variable {
            return self.entries.first().map(|e| e.bit_length).unwrap_or(0);
        }
        let end = self
            .entries
            .last()
            .map(|e| e.bit_offset + e.bit_length.max(0))
            .unwrap_or(0);
        (end + 7) & !7
    }

    /// Exact parity with `ObjectInfo::GetSourceCodeFriendlyName(String name)`.
    pub fn get_source_code_friendly_name(name: &str) -> String {
        if name.is_empty() {
            return String::new();
        }
        let is_sep = |c: char| -> bool {
            c.is_whitespace()
                || c == '\u{00A0}'
                || matches!(
                    c,
                    '-' | '.'
                        | ','
                        | ';'
                        | ':'
                        | '/'
                        | '\\'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '+'
                        | '*'
                        | '&'
                        | '%'
                        | '$'
                        | '#'
                        | '!'
                        | '?'
                        | '\''
                        | '"'
                        | '<'
                        | '>'
                        | '|'
                        | '='
                        | '~'
                        | '^'
                        | '@'
                )
        };
        let mut out = String::new();
        for token in name.split(is_sep).filter(|s| !s.is_empty()) {
            let mut chars = token.chars();
            if let Some(first) = chars.next() {
                for up in first.to_uppercase() {
                    out.push(up);
                }
                out.extend(chars);
            }
        }
        if out
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            format!("_{out}")
        } else {
            out
        }
    }

    pub fn esi_type_name(&self) -> String {
        if self.object_code == ObjectCode::Variable {
            self.entries
                .first()
                .map(create_esi_syntax_for_entry)
                .unwrap_or_default()
        } else {
            format!("DT{:X}", self.index)
        }
    }

    pub fn build_esi_datatype_nodes_ex(&self, enhanced_info: bool) -> Vec<DomElement> {
        if !self.raw_esi_datatypes.is_empty() {
            return self.raw_esi_datatypes.clone();
        }

        if self.is_enum_object() {
            if self.object_code == ObjectCode::Defstruct {
                // Built-in or XML-imported ENUM (`ObjectCode == 6`): `<Name>DT0800EN03</Name><BaseType>USINT</BaseType><BitSize>3</BitSize><EnumInfo>...`
                let (_, parsed_bits) =
                    parse_enum_type_syntax(&self.name).unwrap_or((self.index, 8));
                let elem_bits = if parsed_bits > 0 {
                    parsed_bits
                } else {
                    self.entries
                        .iter()
                        .find(|e| e.sub_index > 0)
                        .map(|e| e.bit_length)
                        .unwrap_or(8)
                        .max(1)
                };
                let base_esi = if elem_bits <= 8 {
                    "USINT"
                } else if elem_bits <= 16 {
                    "UINT"
                } else {
                    "UDINT"
                };
                let dt_name = if self.name.to_ascii_uppercase().starts_with("DT") {
                    self.name.clone()
                } else {
                    format!("DT{:04X}EN{:02}", self.index, elem_bits)
                };
                let mut dt = DomElement::new("DataType");
                dt.push_child(DomNode::Element(DomElement::with_text("Name", dt_name)));
                dt.push_child(DomNode::Element(DomElement::with_text(
                    "BaseType", base_esi,
                )));
                dt.push_child(DomNode::Element(DomElement::with_text(
                    "BitSize",
                    elem_bits.to_string(),
                )));
                for entry in self.entries.iter().filter(|e| e.sub_index > 0) {
                    let val = entry.enum_value.unwrap_or_else(|| {
                        let be = reverse_hex_byte_pairs(&entry.default_data);
                        i32::from_str_radix(&be, 16).unwrap_or(0)
                    });
                    let mut ei = DomElement::new("EnumInfo");
                    ei.push_child(DomNode::Element(DomElement::with_text("Text", &entry.name)));
                    ei.push_child(DomNode::Element(DomElement::with_text(
                        "Enum",
                        val.to_string(),
                    )));
                    dt.push_child(DomNode::Element(ei));
                }
                return vec![dt];
            } else {
                // CSV/XLSX `0x0800;ARRAY` enum (`DT800ARR` + `DT800`)
                let count = self.entries.iter().filter(|e| e.sub_index > 0).count() as i32;
                let elem_bits = self
                    .entries
                    .iter()
                    .find(|e| e.sub_index > 0)
                    .map(|e| e.bit_length)
                    .unwrap_or(8)
                    .max(8);
                let base_esi = if elem_bits <= 8 {
                    "USINT"
                } else if elem_bits <= 16 {
                    "UINT"
                } else {
                    "UDINT"
                };
                let arr_name = format!("DT{:X}ARR", self.index);
                let dt_name = format!("DT{:X}", self.index);

                let mut arr_dt = DomElement::new("DataType");
                arr_dt.push_child(DomNode::Element(DomElement::with_text("Name", &arr_name)));
                arr_dt.push_child(DomNode::Element(DomElement::with_text(
                    "BaseType", base_esi,
                )));
                arr_dt.push_child(DomNode::Element(DomElement::with_text(
                    "BitSize",
                    (count * elem_bits).to_string(),
                )));
                let mut ai = DomElement::new("ArrayInfo");
                ai.push_child(DomNode::Element(DomElement::with_text("LBound", "1")));
                ai.push_child(DomNode::Element(DomElement::with_text(
                    "Elements",
                    count.to_string(),
                )));
                arr_dt.push_child(DomNode::Element(ai));

                let mut rec_dt = DomElement::new("DataType");
                rec_dt.push_child(DomNode::Element(DomElement::with_text("Name", &dt_name)));
                rec_dt.push_child(DomNode::Element(DomElement::with_text(
                    "BitSize",
                    (16 + ((count * elem_bits + 7) & !7)).to_string(),
                )));
                let si0_cat = if enhanced_info && self.has_explicit_category {
                    Some(self.category)
                } else {
                    None
                };
                let mut si0 = DomElement::new("SubItem");
                si0.push_child(DomNode::Element(DomElement::with_text("SubIdx", "0")));
                si0.push_child(DomNode::Element(DomElement::with_text(
                    "Name",
                    "SubIndex 000",
                )));
                si0.push_child(DomNode::Element(DomElement::with_text("Type", "USINT")));
                si0.push_child(DomNode::Element(DomElement::with_text("BitSize", "8")));
                si0.push_child(DomNode::Element(DomElement::with_text("BitOffs", "0")));
                si0.push_child(DomNode::Element(
                    EntryFlags::RO.to_esi_flags_element(si0_cat),
                ));
                rec_dt.push_child(DomNode::Element(si0));

                let elem_cat = if enhanced_info {
                    self.entries
                        .iter()
                        .find(|e| e.sub_index > 0)
                        .and_then(|e| e.category)
                } else {
                    None
                };
                let mut si_el = DomElement::new("SubItem");
                si_el.push_child(DomNode::Element(DomElement::with_text("Name", "Elements")));
                si_el.push_child(DomNode::Element(DomElement::with_text("Type", &arr_name)));
                si_el.push_child(DomNode::Element(DomElement::with_text(
                    "BitSize",
                    (count * elem_bits).to_string(),
                )));
                si_el.push_child(DomNode::Element(DomElement::with_text("BitOffs", "16")));
                si_el.push_child(DomNode::Element(
                    EntryFlags::RO.to_esi_flags_element(elem_cat),
                ));
                rec_dt.push_child(DomNode::Element(si_el));

                return vec![arr_dt, rec_dt];
            }
        }

        if self.object_code == ObjectCode::Variable {
            return Vec::new();
        }

        let dt_name = format!("DT{:X}", self.index);
        let sub_entries: Vec<&EntryInfo> =
            self.entries.iter().filter(|e| e.sub_index > 0).collect();
        let uniform_unnamed_array = self.object_code == ObjectCode::Array
            && !sub_entries.is_empty()
            && sub_entries
                .iter()
                .all(|e| is_default_subindex_name(&e.name) && e.description.is_empty())
            && sub_entries.iter().all(|e| {
                e.data_type_id == sub_entries[0].data_type_id
                    && e.bit_length == sub_entries[0].bit_length
                    && e.flags == sub_entries[0].flags
            });

        let mut out = Vec::new();
        if uniform_unnamed_array {
            let elem = sub_entries[0];
            let elem_type = create_esi_syntax_for_entry(elem);
            let count = sub_entries.len() as i32;
            let arr_bits = count * elem.bit_length;
            let arr_name = format!("{dt_name}ARR");

            let mut arr_dt = DomElement::new("DataType");
            arr_dt.push_child(DomNode::Element(DomElement::with_text("Name", &arr_name)));
            arr_dt.push_child(DomNode::Element(DomElement::with_text(
                "BaseType", &elem_type,
            )));
            arr_dt.push_child(DomNode::Element(DomElement::with_text(
                "BitSize",
                arr_bits.to_string(),
            )));
            let mut ai = DomElement::new("ArrayInfo");
            ai.push_child(DomNode::Element(DomElement::with_text("LBound", "1")));
            ai.push_child(DomNode::Element(DomElement::with_text(
                "Elements",
                count.to_string(),
            )));
            arr_dt.push_child(DomNode::Element(ai));
            out.push(arr_dt);

            let mut rec_dt = DomElement::new("DataType");
            rec_dt.push_child(DomNode::Element(DomElement::with_text("Name", &dt_name)));
            rec_dt.push_child(DomNode::Element(DomElement::with_text(
                "BitSize",
                self.total_bit_size().to_string(),
            )));
            if let Some(si0) = self.entry(0) {
                rec_dt.push_child(DomNode::Element(Self::build_subitem_element_ex(
                    si0,
                    enhanced_info,
                )));
            }
            let elem_cat = if enhanced_info { elem.category } else { None };
            let mut el_sub = DomElement::new("SubItem");
            el_sub.push_child(DomNode::Element(DomElement::with_text("Name", "Elements")));
            el_sub.push_child(DomNode::Element(DomElement::with_text("Type", &arr_name)));
            el_sub.push_child(DomNode::Element(DomElement::with_text(
                "BitSize",
                arr_bits.to_string(),
            )));
            el_sub.push_child(DomNode::Element(DomElement::with_text("BitOffs", "16")));
            el_sub.push_child(DomNode::Element(elem.flags.to_esi_flags_element(elem_cat)));
            rec_dt.push_child(DomNode::Element(el_sub));
            out.push(rec_dt);
        } else {
            let mut rec_dt = DomElement::new("DataType");
            rec_dt.push_child(DomNode::Element(DomElement::with_text("Name", &dt_name)));
            if enhanced_info {
                rec_dt.push_child(DomNode::Element(DomElement::with_text(
                    "BaseType",
                    "NOT_DEFINED",
                )));
            }
            rec_dt.push_child(DomNode::Element(DomElement::with_text(
                "BitSize",
                self.total_bit_size().to_string(),
            )));
            for entry in &self.entries {
                if entry.data_type_id == 0 {
                    continue;
                }
                rec_dt.push_child(DomNode::Element(Self::build_subitem_element_ex(
                    entry,
                    enhanced_info,
                )));
            }
            out.push(rec_dt);
        }

        out
    }

    fn build_subitem_element_ex(entry: &EntryInfo, enhanced_info: bool) -> DomElement {
        let mut sub = DomElement::new("SubItem");
        sub.push_child(DomNode::Element(DomElement::with_text(
            "SubIdx",
            entry.sub_index.to_string(),
        )));
        sub.push_child(DomNode::Element(DomElement::with_text(
            "Name",
            entry.effective_name(),
        )));
        let type_str = create_esi_syntax_for_entry(entry);
        sub.push_child(DomNode::Element(DomElement::with_text("Type", type_str)));
        if !enhanced_info && !entry.description.is_empty() {
            sub.push_child(DomNode::Element(DomElement::with_text(
                "Comment",
                &entry.description,
            )));
        }
        sub.push_child(DomNode::Element(DomElement::with_text(
            "BitSize",
            entry.bit_length.to_string(),
        )));
        if let Some(u) = entry.unit {
            sub.push_child(DomNode::Element(DomElement::with_text(
                "Unit",
                u.to_string(),
            )));
        }
        sub.push_child(DomNode::Element(DomElement::with_text(
            "BitOffs",
            entry.bit_offset.to_string(),
        )));
        let cat = if enhanced_info { entry.category } else { None };
        sub.push_child(DomNode::Element(entry.flags.to_esi_flags_element(cat)));
        sub
    }

    /// Build ESI `<Object>` node for `<Dictionary><Objects>`.
    pub fn build_esi_object_node_ex(&self, enhanced_info: bool) -> DomElement {
        if let Some(ref raw) = self.raw_esi_object {
            return raw.clone();
        }

        let mut obj = DomElement::new("Object");
        let idx_str = format!("#x{:X}", self.index);
        let mut idx_el = DomElement::with_text("Index", idx_str);
        if self.depend_on_slot {
            idx_el.set_attr("DependOnSlot", "true");
        }
        if self.depend_on_slot_group {
            idx_el.set_attr("DependOnSlotGroup", "true");
        }
        obj.push_child(DomNode::Element(idx_el));
        obj.push_child(DomNode::Element(DomElement::with_text("Name", &self.name)));

        let type_name = self.esi_type_name();
        obj.push_child(DomNode::Element(DomElement::with_text("Type", type_name)));
        obj.push_child(DomNode::Element(DomElement::with_text(
            "BitSize",
            self.total_bit_size().to_string(),
        )));

        // `<Info>` block (DefaultData / MinData / MaxData / SubItem Info)
        if let Some(info_el) = self.build_esi_info_element_ex(enhanced_info) {
            obj.push_child(DomNode::Element(info_el));
        }

        // `<Flags>` block on `<Object>` is emitted ONLY for `VAR` objects (without `<Category>`)
        if self.object_code == ObjectCode::Variable {
            if let Some(first) = self.entries.first() {
                obj.push_child(DomNode::Element(first.flags.to_esi_flags_element(None)));
            }
            if enhanced_info {
                if !self.coe_read_callback.is_empty() {
                    obj.push_child(DomNode::Element(DomElement::with_text(
                        "CoeRead",
                        &self.coe_read_callback,
                    )));
                }
                if !self.coe_write_callback.is_empty() {
                    obj.push_child(DomNode::Element(DomElement::with_text(
                        "CoeWrite",
                        &self.coe_write_callback,
                    )));
                }
            }
        }

        obj
    }

    fn pad_var_hex_data(raw: &str, bit_length: i32) -> String {
        if raw.is_empty() {
            return String::new();
        }
        let mut s = raw.to_ascii_uppercase();
        if !s.len().is_multiple_of(2) {
            s.insert(0, '0');
        }
        if bit_length > 8 {
            let target_len = (bit_length / 4) as usize;
            while s.len() < target_len {
                s.push('0');
            }
        }
        s
    }

    fn pad_subentry_hex_data(raw: &str, bit_length: i32, pad_right: bool) -> String {
        if raw.is_empty() {
            return String::new();
        }
        let mut s = raw.to_ascii_uppercase();
        if !s.len().is_multiple_of(2) {
            s.insert(0, '0');
        }
        if bit_length > 8 {
            let target_len = (bit_length / 4) as usize;
            if pad_right {
                while s.len() < target_len {
                    s.push('0');
                }
            } else if s.len() < target_len {
                let mut padded = "0".repeat(target_len - s.len());
                padded.push_str(&s);
                s = padded;
            }
        }
        s
    }

    fn build_esi_info_element_ex(&self, enhanced_info: bool) -> Option<DomElement> {
        if self.object_code == ObjectCode::Variable {
            let first = self.entries.first()?;
            if first.default_data.is_empty()
                && first.min_data.is_empty()
                && first.max_data.is_empty()
                && first.description.is_empty()
            {
                return None;
            }
            let mut info = DomElement::new("Info");
            if !first.description.is_empty() {
                info.push_child(DomNode::Element(DomElement::with_text(
                    "Description",
                    &first.description,
                )));
            }
            if !first.min_data.is_empty() {
                info.push_child(DomNode::Element(DomElement::with_text(
                    "MinData",
                    Self::pad_var_hex_data(&first.min_data, first.bit_length),
                )));
            }
            if !first.max_data.is_empty() {
                info.push_child(DomNode::Element(DomElement::with_text(
                    "MaxData",
                    Self::pad_var_hex_data(&first.max_data, first.bit_length),
                )));
            }
            if !first.default_data.is_empty() {
                info.push_child(DomNode::Element(DomElement::with_text(
                    "DefaultData",
                    Self::pad_var_hex_data(&first.default_data, first.bit_length),
                )));
            }
            return Some(info);
        }

        // ARRAY / RECORD: emit `<SubItem>` inside `<Info>` for entries with DefaultData / MinData / MaxData (or enhanced description comment)
        let any_data = self.entries.iter().any(|e| {
            e.data_type_id != 0
                && (!e.default_data.is_empty()
                    || !e.min_data.is_empty()
                    || !e.max_data.is_empty()
                    || (enhanced_info && !e.description.is_empty()))
        });
        if !any_data && self.description.is_empty() {
            return None;
        }
        let mut info = DomElement::new("Info");
        if !self.description.is_empty() {
            info.push_child(DomNode::Element(DomElement::with_text(
                "Description",
                &self.description,
            )));
        }
        for entry in &self.entries {
            if entry.data_type_id == 0 {
                continue;
            }
            let has_hex = !entry.default_data.is_empty()
                || !entry.min_data.is_empty()
                || !entry.max_data.is_empty();
            let has_enh_comment = enhanced_info && !entry.description.is_empty();
            if !has_hex && !has_enh_comment {
                continue;
            }
            let mut si = DomElement::new("SubItem");
            si.push_child(DomNode::Element(DomElement::with_text(
                "Name",
                entry.effective_name(),
            )));
            if has_hex {
                let mut sub_info = DomElement::new("Info");
                if !entry.min_data.is_empty() {
                    sub_info.push_child(DomNode::Element(DomElement::with_text(
                        "MinData",
                        Self::pad_subentry_hex_data(&entry.min_data, entry.bit_length, true),
                    )));
                }
                if !entry.max_data.is_empty() {
                    sub_info.push_child(DomNode::Element(DomElement::with_text(
                        "MaxData",
                        Self::pad_subentry_hex_data(&entry.max_data, entry.bit_length, true),
                    )));
                }
                if !entry.default_data.is_empty() {
                    let pad_right = entry.data_type_id == 9;
                    sub_info.push_child(DomNode::Element(DomElement::with_text(
                        "DefaultData",
                        Self::pad_subentry_hex_data(
                            &entry.default_data,
                            entry.bit_length,
                            pad_right,
                        ),
                    )));
                }
                si.push_child(DomNode::Element(sub_info));
            }
            if has_enh_comment {
                si.push_comment(entry.description.replace("--", "- -"));
            }
            info.push_child(DomNode::Element(si));
        }
        Some(info)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OdValidationReport {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub skipped_objects: Vec<u16>,
}

/// Ordered CoE Object Dictionary (`BTreeMap<u16, ObjectInfo>` sorted by object index).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObjectInfoCollection {
    pub name: String,
    pub device_profile: u16,
    pub module_profile: u16,
    pub index_increment: u16,
    pub pdo_index_increment: u16,
    pub source_code_prefix: String,
    pub objects: BTreeMap<u16, ObjectInfo>,
}

impl ObjectInfoCollection {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            device_profile: 0,
            module_profile: 0,
            index_increment: 0,
            pdo_index_increment: 0,
            source_code_prefix: String::new(),
            objects: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, mut obj: ObjectInfo) {
        obj.finalize_layout();
        self.objects.insert(obj.index, obj);
    }

    pub fn contains(&self, index: u16) -> bool {
        self.objects.contains_key(&index)
    }

    pub fn get(&self, index: u16) -> Option<&ObjectInfo> {
        self.objects.get(&index)
    }

    pub fn remove(&mut self, index: u16) -> Option<ObjectInfo> {
        self.objects.remove(&index)
    }

    pub fn rx_pdos(&self) -> Vec<&ObjectInfo> {
        self.objects
            .range(0x1600..=0x17FF)
            .map(|(_, o)| o)
            .collect()
    }

    pub fn tx_pdos(&self) -> Vec<&ObjectInfo> {
        self.objects
            .range(0x1A00..=0x1BFF)
            .map(|(_, o)| o)
            .collect()
    }

    /// True when any `0x1C12` or `0x1C13` entry (including SI0) has write access enabled (`PdoAssign`).
    pub fn pdo_assign_required(&self) -> bool {
        for idx in [0x1C12u16, 0x1C13u16] {
            if let Some(obj) = self.objects.get(&idx) {
                if obj.entries.iter().any(|e| e.flags.access.any_write()) {
                    return true;
                }
            }
        }
        false
    }

    /// True when any `0x1600..0x17FF` or `0x1A00..0x1BFF` PDO mapping entry has write access enabled (`PdoConfig`).
    pub fn pdo_config_required(&self) -> bool {
        self.rx_pdos()
            .into_iter()
            .chain(self.tx_pdos())
            .any(|o| o.entries.iter().any(|e| e.flags.access.any_write()))
    }

    /// Auto-create `0x1600..` RxPDO and `0x1A00..` TxPDO mapping objects from mappable `0x6000..0x9FFF` objects
    /// when no explicit PDO mapping objects were defined!
    /// Matches `PdoMappingObjectHandler::CreatePdoMappingObjects`.
    pub fn auto_create_pdo_mapping_objects(&mut self, overwrite_existing: bool, align_bytes: u16) {
        if !overwrite_existing && (!self.rx_pdos().is_empty() || !self.tx_pdos().is_empty()) {
            return;
        }
        if overwrite_existing {
            let rx_keys: Vec<u16> = self
                .objects
                .range(0x1600..=0x17FF)
                .map(|(&k, _)| k)
                .collect();
            for k in rx_keys {
                self.objects.remove(&k);
            }
            let tx_keys: Vec<u16> = self
                .objects
                .range(0x1A00..=0x1BFF)
                .map(|(&k, _)| k)
                .collect();
            for k in tx_keys {
                self.objects.remove(&k);
            }
        }

        let align_bits = (align_bytes.max(1) as i32) * 8;
        let mut new_pdos = Vec::new();
        let mut rx_pdo_idx = 0x1600u16;
        let mut tx_pdo_idx = 0x1A00u16;

        // Scan objects in index order (`0x6000..0xFFFF` or any object with rx/tx mappable entries)
        let candidate_indices: Vec<u16> = self.objects.keys().copied().collect();
        for idx in candidate_indices {
            if (0x1600..=0x1BFF).contains(&idx) || (0x1C00..=0x1CFF).contains(&idx) {
                continue;
            }
            let obj = &self.objects[&idx];
            // Check Rx-mappable entries on this object
            let rx_entries: Vec<&EntryInfo> = obj
                .entries
                .iter()
                .filter(|e| {
                    (obj.object_code == ObjectCode::Variable || e.sub_index > 0)
                        && e.flags.pdo_mapping.allows_rx()
                })
                .collect();
            if !rx_entries.is_empty() && rx_pdo_idx <= 0x17FF {
                let pdo =
                    Self::build_single_pdo_mapping_object(rx_pdo_idx, obj, &rx_entries, align_bits);
                new_pdos.push(pdo);
                rx_pdo_idx += 1;
            }

            // Check Tx-mappable entries on this object
            let tx_entries: Vec<&EntryInfo> = obj
                .entries
                .iter()
                .filter(|e| {
                    (obj.object_code == ObjectCode::Variable || e.sub_index > 0)
                        && e.flags.pdo_mapping.allows_tx()
                })
                .collect();
            if !tx_entries.is_empty() && tx_pdo_idx <= 0x1BFF {
                let pdo =
                    Self::build_single_pdo_mapping_object(tx_pdo_idx, obj, &tx_entries, align_bits);
                new_pdos.push(pdo);
                tx_pdo_idx += 1;
            }
        }

        for pdo in new_pdos {
            self.insert(pdo);
        }
    }

    fn build_single_pdo_mapping_object(
        pdo_index: u16,
        target_obj: &ObjectInfo,
        mapped_entries: &[&EntryInfo],
        align_bits: i32,
    ) -> ObjectInfo {
        let pdo_name = format!("{} process data mapping", target_obj.name);
        let mut pdo = ObjectInfo::new(pdo_index, pdo_name, ObjectCode::Record);
        pdo.data_type_id = 33; // DEFTYPE_PDOMAPPING
        pdo.category = ObjectCategory::Mandatory;
        pdo.depend_on_slot = target_obj.depend_on_slot;
        pdo.depend_on_slot_group = target_obj.depend_on_slot_group;

        let mut si = 1u8;
        let mut total_bits = 0i32;
        for target_entry in mapped_entries {
            let map_val: u32 = ((target_obj.index as u32) << 16)
                | ((target_entry.sub_index as u32) << 8)
                | ((target_entry.bit_length.max(0) as u32) & 0xFF);
            let default_le = reverse_hex_byte_pairs(&format!("{map_val:08X}"));
            pdo.entries.push(EntryInfo {
                sub_index: si,
                name: format!("SubIndex {si:03}"),
                data_type_id: 7, // UNSIGNED32
                bit_length: 32,
                bit_offset: 16 + ((si as i32 - 1) * 32),
                flags: EntryFlags::RO,
                default_data: default_le,
                description: format!(
                    "Reference to 0x{:04X}.{}",
                    target_obj.index, target_entry.sub_index
                ),
                ..Default::default()
            });
            total_bits += target_entry.bit_length.max(0);
            si = si.saturating_add(1);
        }

        // Pad to `align_bits` boundary if unaligned
        let rem = total_bits % align_bits;
        if rem != 0 {
            let mut pad_bits = align_bits - rem;
            while pad_bits > 0 {
                let chunk = pad_bits.min(32);
                let map_val: u32 = chunk as u32; // 0x0000_00xx padding entry
                let default_le = reverse_hex_byte_pairs(&format!("{map_val:08X}"));
                pdo.entries.push(EntryInfo {
                    sub_index: si,
                    name: format!("SubIndex {si:03}"),
                    data_type_id: 7,
                    bit_length: 32,
                    bit_offset: 16 + ((si as i32 - 1) * 32),
                    flags: EntryFlags::RO,
                    default_data: default_le,
                    description: "Padding entry".to_string(),
                    ..Default::default()
                });
                pad_bits -= chunk;
                si = si.saturating_add(1);
            }
        }

        pdo.finalize_layout();
        pdo
    }

    /// Auto-create `0x1C12` ("SyncManager 2 assignment") and `0x1C13` ("SyncManager 3 assignment")
    /// matching `ObjectInfoCollection::AutoCreateSmAssignObjects`.
    pub fn auto_create_sm_assign_objects(&mut self, overwrite_existing: bool) {
        let entry_flags = if self.pdo_assign_required() {
            EntryFlags {
                access: AccessFlags::RW_PREOP_RO_OTHER,
                ..EntryFlags::RO
            }
        } else {
            EntryFlags::RO
        };

        let mut extra_slot_entries = self
            .objects
            .get(&0xF030)
            .map(|o| o.num_sub_entries() as u16)
            .unwrap_or(0);
        if extra_slot_entries > 0 && self.pdo_index_increment > 0 {
            extra_slot_entries = extra_slot_entries.saturating_mul(self.pdo_index_increment);
        }

        // 0x1C12 (RxPDO -> SM2)
        if overwrite_existing || !self.contains(0x1C12) {
            if overwrite_existing {
                self.remove(0x1C12);
            }
            let has_sm2_in_1c00 = self.objects.get(&0x1C00).and_then(|o| o.entry(3)).is_some();
            let rx_indices: Vec<u16> = self.rx_pdos().into_iter().map(|o| o.index).collect();
            if has_sm2_in_1c00 || !rx_indices.is_empty() || extra_slot_entries > 0 {
                let mut sm2 =
                    ObjectInfo::new(0x1C12, "SyncManager 2 assignment", ObjectCode::Array);
                sm2.data_type_id = 6; // UNSIGNED16
                sm2.entries.push(EntryInfo {
                    sub_index: 0,
                    name: "SubIndex 000".to_string(),
                    data_type_id: 5,
                    bit_length: 8,
                    bit_offset: 0,
                    flags: entry_flags,
                    default_data: format!("{:02X}", rx_indices.len() + extra_slot_entries as usize),
                    ..Default::default()
                });
                let mut si = 1u8;
                for pdo_idx in rx_indices {
                    sm2.entries.push(EntryInfo {
                        sub_index: si,
                        name: format!("SubIndex {si:03}"),
                        data_type_id: 6,
                        bit_length: 16,
                        bit_offset: 16 + ((si as i32 - 1) * 16),
                        flags: entry_flags,
                        default_data: format!("{:04X}", pdo_idx.swap_bytes()),
                        ..Default::default()
                    });
                    si = si.saturating_add(1);
                }
                for _ in 0..extra_slot_entries {
                    sm2.entries.push(EntryInfo {
                        sub_index: si,
                        name: format!("SubIndex {si:03}"),
                        data_type_id: 6,
                        bit_length: 16,
                        bit_offset: 16 + ((si as i32 - 1) * 16),
                        flags: entry_flags,
                        default_data: "0000".to_string(),
                        ..Default::default()
                    });
                    si = si.saturating_add(1);
                }
                self.insert(sm2);
            }
        }

        // 0x1C13 (TxPDO -> SM3)
        if overwrite_existing || !self.contains(0x1C13) {
            if overwrite_existing {
                self.remove(0x1C13);
            }
            let has_sm3_in_1c00 = self.objects.get(&0x1C00).and_then(|o| o.entry(4)).is_some();
            let tx_indices: Vec<u16> = self.tx_pdos().into_iter().map(|o| o.index).collect();
            if has_sm3_in_1c00 || !tx_indices.is_empty() || extra_slot_entries > 0 {
                let mut sm3 =
                    ObjectInfo::new(0x1C13, "SyncManager 3 assignment", ObjectCode::Array);
                sm3.data_type_id = 6; // UNSIGNED16
                sm3.entries.push(EntryInfo {
                    sub_index: 0,
                    name: "SubIndex 000".to_string(),
                    data_type_id: 5,
                    bit_length: 8,
                    bit_offset: 0,
                    flags: entry_flags,
                    default_data: format!("{:02X}", tx_indices.len() + extra_slot_entries as usize),
                    ..Default::default()
                });
                let mut si = 1u8;
                for pdo_idx in tx_indices {
                    sm3.entries.push(EntryInfo {
                        sub_index: si,
                        name: format!("SubIndex {si:03}"),
                        data_type_id: 6,
                        bit_length: 16,
                        bit_offset: 16 + ((si as i32 - 1) * 16),
                        flags: entry_flags,
                        default_data: format!("{:04X}", pdo_idx.swap_bytes()),
                        ..Default::default()
                    });
                    si = si.saturating_add(1);
                }
                for _ in 0..extra_slot_entries {
                    sm3.entries.push(EntryInfo {
                        sub_index: si,
                        name: format!("SubIndex {si:03}"),
                        data_type_id: 6,
                        bit_length: 16,
                        bit_offset: 16 + ((si as i32 - 1) * 16),
                        flags: entry_flags,
                        default_data: "0000".to_string(),
                        ..Default::default()
                    });
                    si = si.saturating_add(1);
                }
                self.insert(sm3);
            }
        }
    }

    /// Calculate total mapped process data byte length for `sm_assign_index` (`0x1C12` RxPDO or `0x1C13` TxPDO).
    pub fn get_process_data_length_bytes(&self, sm_assign_index: u16) -> u16 {
        let Some(sm_obj) = self.objects.get(&sm_assign_index) else {
            return 0;
        };
        let mut total_bits = 0u32;
        for assign_entry in sm_obj.entries.iter().filter(|e| e.sub_index > 0) {
            let be = reverse_hex_byte_pairs(&assign_entry.default_data);
            let Ok(pdo_idx) = u16::from_str_radix(&be, 16) else {
                continue;
            };
            if pdo_idx == 0 {
                continue;
            }
            if let Some(pdo_obj) = self.objects.get(&pdo_idx) {
                for pdo_entry in pdo_obj.entries.iter().filter(|e| e.sub_index > 0) {
                    let map_be = reverse_hex_byte_pairs(&pdo_entry.default_data);
                    if let Ok(map_u32) = u32::from_str_radix(&map_be, 16) {
                        total_bits += map_u32 & 0xFF;
                    }
                }
            }
        }
        total_bits.div_ceil(8) as u16
    }

    /// Finalize all objects, auto-create missing PDO mapping & SM assign objects when needed, and verify basic rules.
    pub fn finalize_and_validate(&mut self, auto_create_pdos_and_sm: bool) {
        let keys: Vec<u16> = self.objects.keys().copied().collect();
        for k in keys {
            if let Some(obj) = self.objects.get_mut(&k) {
                obj.finalize_layout();
            }
        }
        if auto_create_pdos_and_sm {
            self.auto_create_pdo_mapping_objects(false, 1);
            self.auto_create_sm_assign_objects(false);
        }
    }

    /// Inherit objects and missing subentries from a referenced base `ObjectInfoCollection`
    /// (`ObjectInfoCollection::InheritObjects` / `ObjectInfo::InheritFrom` parity).
    pub fn inherit_objects(&mut self, base: &Self) {
        if self.device_profile == 0 && base.device_profile != 0 {
            self.device_profile = base.device_profile;
        }
        if self.module_profile == 0 && base.module_profile != 0 {
            self.module_profile = base.module_profile;
        }
        if self.index_increment == 0 && base.index_increment != 0 {
            self.index_increment = base.index_increment;
        }
        if self.pdo_index_increment == 0 && base.pdo_index_increment != 0 {
            self.pdo_index_increment = base.pdo_index_increment;
        }

        for (&idx, base_obj) in &base.objects {
            if let Some(cur_obj) = self.objects.get_mut(&idx) {
                if cur_obj.name.trim().is_empty() {
                    cur_obj.name = base_obj.name.clone();
                }
                if cur_obj.object_code == ObjectCode::None {
                    cur_obj.object_code = base_obj.object_code;
                }
                if !cur_obj.has_explicit_category && base_obj.has_explicit_category {
                    cur_obj.category = base_obj.category;
                    cur_obj.has_explicit_category = true;
                }
                if cur_obj.description.is_empty() {
                    cur_obj.description = base_obj.description.clone();
                }
                if cur_obj.coe_read_callback.is_empty() {
                    cur_obj.coe_read_callback = base_obj.coe_read_callback.clone();
                }
                if cur_obj.coe_write_callback.is_empty() {
                    cur_obj.coe_write_callback = base_obj.coe_write_callback.clone();
                }
                for base_entry in &base_obj.entries {
                    if let Some(cur_entry) = cur_obj.entry_mut(base_entry.sub_index) {
                        cur_entry.inherit_from(base_entry);
                    } else if cur_obj.object_code != ObjectCode::Variable {
                        cur_obj.entries.push(base_entry.clone());
                    }
                }
                cur_obj.finalize_layout();
            } else {
                self.objects.insert(idx, base_obj.clone());
            }
        }
    }

    /// Validate CoE Object Dictionary rules (`ObjectInfoCollection::ValidateObjects` parity).
    /// When `remove_invalid_objects` is true (`SSC OD Tool /f` force mode), objects with validation
    /// errors are removed and listed in `skipped_objects`.
    pub fn validate_objects(
        &mut self,
        check_ssc_alignment_rules: bool,
        remove_invalid_objects: bool,
    ) -> OdValidationReport {
        const RESERVED_C_WORDS: &[&str] = &[
            "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
            "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
            "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct",
            "switch", "typedef", "union", "unsigned", "void", "volatile", "while",
        ];

        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut invalid_indices: Vec<u16> = Vec::new();
        let is_mdp = self.device_profile == 5001;

        for (&idx, obj) in &self.objects {
            let mut obj_has_error = false;
            if idx >= 0x1000 && obj.object_code == ObjectCode::None && obj.entries.is_empty() {
                errors.push(format!(
                    "Object 0x{idx:04X} ('{}') has no ObjectCode and no subentries",
                    obj.name
                ));
                obj_has_error = true;
            }

            let trimmed_obj_name = obj.name.trim();
            if !trimmed_obj_name.is_empty()
                && RESERVED_C_WORDS
                    .iter()
                    .any(|w| w.eq_ignore_ascii_case(trimmed_obj_name))
            {
                warnings.push(format!(
                    "Object 0x{idx:04X} name '{}' is a reserved C keyword",
                    obj.name
                ));
            }

            let has_coe_cb = !obj.coe_read_callback.trim().is_empty()
                || !obj.coe_write_callback.trim().is_empty();

            for e in &obj.entries {
                let si = e.sub_index;
                let trimmed_ename = e.name.trim();
                if !trimmed_ename.is_empty()
                    && RESERVED_C_WORDS
                        .iter()
                        .any(|w| w.eq_ignore_ascii_case(trimmed_ename))
                {
                    warnings.push(format!(
                        "Entry 0x{idx:04X}.{si} name '{}' is a reserved C keyword",
                        e.name
                    ));
                }

                if matches!(
                    e.flags.pdo_mapping,
                    PdoMappingMode::RxOrTx | PdoMappingMode::TxAndRx
                ) {
                    warnings.push(format!(
                        "Entry 0x{idx:04X}.{si} ('{}') allows both RxPDO and TxPDO mapping",
                        e.effective_name()
                    ));
                }

                if is_mdp && (obj.object_code == ObjectCode::Variable || si > 0) {
                    if (0x6000..=0x6FFF).contains(&idx) && e.flags.pdo_mapping == PdoMappingMode::Rx
                    {
                        errors.push(format!(
                            "MDP input entry 0x{idx:04X}.{si} ('{}') cannot be mapped to RxPDO",
                            e.effective_name()
                        ));
                        obj_has_error = true;
                    } else if (0x7000..=0x7FFF).contains(&idx)
                        && e.flags.pdo_mapping == PdoMappingMode::Tx
                    {
                        errors.push(format!(
                            "MDP output entry 0x{idx:04X}.{si} ('{}') cannot be mapped to TxPDO",
                            e.effective_name()
                        ));
                        obj_has_error = true;
                    }
                }

                if check_ssc_alignment_rules
                    && !obj.is_enum_object()
                    && obj.object_code != ObjectCode::Variable
                    && !has_coe_cb
                    && e.coe_read_callback.trim().is_empty()
                    && e.coe_write_callback.trim().is_empty()
                    && si > 0
                    && e.data_type_id != 0
                    && e.bit_length > 0
                {
                    if e.bit_length <= 8 {
                        let start_byte = e.bit_offset / 8;
                        let end_byte = (e.bit_offset + e.bit_length - 1) / 8;
                        if start_byte != end_byte {
                            errors.push(format!(
                                "Entry 0x{idx:04X}.{si} ({} bits at bit offset {}) overlaps a byte border without CoE callback",
                                e.bit_length, e.bit_offset
                            ));
                            obj_has_error = true;
                        }
                    } else if e.bit_offset % 16 != 0 {
                        errors.push(format!(
                            "Entry 0x{idx:04X}.{si} ({} bits at bit offset {}) does not start at a 16-bit word border without CoE callback",
                            e.bit_length, e.bit_offset
                        ));
                        obj_has_error = true;
                    }
                }
            }

            if obj_has_error {
                invalid_indices.push(idx);
            }
        }

        let mut skipped_objects = Vec::new();
        if remove_invalid_objects {
            for idx in invalid_indices {
                self.objects.remove(&idx);
                skipped_objects.push(idx);
            }
        }

        OdValidationReport {
            errors,
            warnings,
            skipped_objects,
        }
    }

    /// Build `<Dictionary>` (`<UnitTypes>` + `<DataTypes>` + `<Objects>`) for ESI or `<EtherCATDict>`,
    /// reproducing the exact `firstDtIdx = 0` `InsertBefore` ordering of `ObjectInfoCollection::CreateOfflineDictionary`.
    pub fn build_dictionary_element(&self, _is_offline_dict: bool) -> DomElement {
        self.build_dictionary_element_ex(false, None)
    }

    pub fn build_dictionary_element_ex(
        &self,
        enhanced_info: bool,
        module_ident: Option<u32>,
    ) -> DomElement {
        let mut dict = DomElement::new("Dictionary");
        if enhanced_info {
            let mut info_el = DomElement::new("Information");
            info_el.push_attr("Name", &self.name);
            if self.device_profile != 0 {
                info_el.push_attr("DeviceProfile", self.device_profile.to_string());
            }
            if self.module_profile != 0 {
                info_el.push_attr("ModuleProfile", self.module_profile.to_string());
            }
            if self.index_increment != 0 {
                info_el.push_attr("ObjectIndexIncrement", self.index_increment.to_string());
            }
            if self.pdo_index_increment != 0 {
                info_el.push_attr(
                    "PdoMappingObjectIndexIncrement",
                    self.pdo_index_increment.to_string(),
                );
            }
            if let Some(mid) = module_ident {
                info_el.push_attr("ModuleIdent", mid.to_string());
            }
            dict.push_child(info_el);
        }

        let mut unit_list: Vec<DomElement> = Vec::new();
        let mut dt_list: Vec<DomElement> = Vec::new();
        let mut obj_container = DomElement::new("Objects");

        for obj in self.objects.values() {
            if (0x0400..=0x04FF).contains(&obj.index) {
                if let Some(raw) = &obj.raw_esi_object {
                    unit_list.push(raw.clone());
                }
                continue;
            }

            let mut candidate_dts: Vec<DomElement> = Vec::new();
            if obj.raw_esi_object.is_some() && !obj.raw_esi_datatypes.is_empty() {
                candidate_dts.extend(obj.raw_esi_datatypes.iter().cloned());
            } else if obj.is_enum_object() && obj.object_code == ObjectCode::Defstruct {
                let bit_size = obj
                    .entries
                    .iter()
                    .find(|e| e.sub_index > 0)
                    .map(|e| e.bit_length)
                    .unwrap_or(8);
                let (base_name, base_bits) = if bit_size <= 8 {
                    ("USINT", 8)
                } else if bit_size <= 16 {
                    ("UINT", 16)
                } else {
                    ("UDINT", 32)
                };
                let mut base_dt = DomElement::new("DataType");
                base_dt.push_child(DomElement::with_text("Name", base_name));
                base_dt.push_child(DomElement::with_text("BitSize", base_bits.to_string()));
                candidate_dts.push(base_dt);
                candidate_dts.extend(obj.build_esi_datatype_nodes_ex(enhanced_info));
            } else {
                for entry in &obj.entries {
                    if entry.data_type_id == 0 {
                        continue;
                    }
                    let esi_type = create_esi_syntax_for_entry(entry);
                    if !esi_type.is_empty() {
                        candidate_dts.push(build_scalar_or_array_datatype_node(entry, &esi_type));
                    }
                }
                candidate_dts.extend(obj.build_esi_datatype_nodes_ex(enhanced_info));
            }

            for node in candidate_dts {
                let node_name = node.child_text("Name").unwrap_or_default();
                if node_name.is_empty() {
                    continue;
                }
                let mut first_dt_idx = 0usize;
                let mut found = false;
                for (i, existing) in dt_list.iter().enumerate() {
                    let ex_name = existing.child_text("Name").unwrap_or_default();
                    if ex_name == node_name {
                        found = true;
                    } else if first_dt_idx == 0 && ex_name.starts_with("DT") {
                        first_dt_idx = i;
                    }
                }
                if !found {
                    if !node_name.starts_with("DT") {
                        if dt_list.is_empty() {
                            dt_list.push(node);
                        } else {
                            dt_list.insert(first_dt_idx, node);
                        }
                    } else {
                        dt_list.push(node);
                    }
                }
            }

            if !obj.is_enum_object() {
                obj_container.push_child(obj.build_esi_object_node_ex(enhanced_info));
            }
        }

        if !unit_list.is_empty() {
            let mut ut_container = DomElement::new("UnitTypes");
            for ut in unit_list {
                ut_container.push_child(ut);
            }
            dict.push_child(ut_container);
        }

        let mut dt_container = DomElement::new("DataTypes");
        for dt in dt_list {
            dt_container.push_child(dt);
        }
        dict.push_child(dt_container);
        dict.push_child(obj_container);
        dict
    }
}

fn build_scalar_or_array_datatype_node(entry: &EntryInfo, esi_type: &str) -> DomElement {
    let mut dt = DomElement::new("DataType");
    dt.push_child(DomNode::Element(DomElement::with_text("Name", esi_type)));
    if matches!(entry.data_type_id, 10 | 11 | 608 | 609 | 610 | 611) {
        let (base_type, elem_bits) = match entry.data_type_id {
            10 => ("BYTE", 8),
            11 => ("UINT", 16),
            608 => ("INT", 16),
            609 => ("SINT", 8),
            610 => ("DINT", 32),
            611 => ("UDINT", 32),
            _ => ("BYTE", 8),
        };
        let elems = (entry.bit_length / elem_bits).max(1);
        dt.push_child(DomNode::Element(DomElement::with_text(
            "BaseType", base_type,
        )));
        dt.push_child(DomNode::Element(DomElement::with_text(
            "BitSize",
            entry.bit_length.to_string(),
        )));
        let mut ai = DomElement::new("ArrayInfo");
        ai.push_child(DomNode::Element(DomElement::with_text("LBound", "0")));
        ai.push_child(DomNode::Element(DomElement::with_text(
            "Elements",
            elems.to_string(),
        )));
        dt.push_child(DomNode::Element(ai));
    } else {
        dt.push_child(DomNode::Element(DomElement::with_text(
            "BitSize",
            entry.bit_length.to_string(),
        )));
    }
    dt
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleCoEInitCmd {
    pub transition: String,
    pub index: u16,
    pub sub_index: u8,
    pub depend_on_slot: bool,
    pub depend_on_slot_group: bool,
    pub data_hex: String,
    pub comment: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleObjectInfoCollection {
    pub name: String,
    pub type_name: String,
    pub module_ident: u32,
    pub module_class: Option<String>,
    pub fixed_pdos: bool,
    pub od: ObjectInfoCollection,
    pub init_cmds: Vec<ModuleCoEInitCmd>,
}

/// Complete imported application (`<Application>` in `.esp`, or parsed from `.xlsx`/`.csv`/`.xml`/`.eds`/`.tmc`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SlaveApplication {
    pub name: String,
    pub application_file_name: String,
    pub original_file_path: String,
    pub od: ObjectInfoCollection,
    pub modules: Vec<ModuleObjectInfoCollection>,
    pub max_slots: u16,
    pub slot_index_increment: u16,
    pub slot_pdo_increment: u16,
}

impl SlaveApplication {
    pub fn new(name: impl Into<String>) -> Self {
        let n = name.into();
        let file_stem = ObjectInfo::get_source_code_friendly_name(&n);
        let app_file = if file_stem.is_empty() {
            "Application".to_string()
        } else {
            file_stem
        };
        Self {
            name: n.clone(),
            application_file_name: app_file,
            original_file_path: String::new(),
            od: ObjectInfoCollection::new(n),
            modules: Vec::new(),
            max_slots: 0,
            slot_index_increment: 0,
            slot_pdo_increment: 0,
        }
    }

    /// Total RxPDO or TxPDO byte size including worst-case module PDO contributions across `max_slots`.
    pub fn get_process_data_length_bytes(&self, sm_assign_index: u16) -> u16 {
        let mut base = self.od.get_process_data_length_bytes(sm_assign_index);
        if !self.modules.is_empty() && self.max_slots > 0 {
            let max_mod = self
                .modules
                .iter()
                .map(|m| {
                    let pdos = if sm_assign_index == 0x1C12 {
                        m.od.rx_pdos()
                    } else {
                        m.od.tx_pdos()
                    };
                    let mut bits = 0u32;
                    for pdo in pdos {
                        for entry in pdo.entries.iter().filter(|e| e.sub_index > 0) {
                            let be = reverse_hex_byte_pairs(&entry.default_data);
                            if let Ok(v) = u32::from_str_radix(&be, 16) {
                                bits += v & 0xFF;
                            }
                        }
                    }
                    bits.div_ceil(8) as u16
                })
                .max()
                .unwrap_or(0);
            base = base.saturating_add(max_mod.saturating_mul(self.max_slots));
        }
        base
    }

    /// Serialize to `<Application>` DOM element for `.esp` project persistence
    /// (`SlaveApplication::ToXmlNode` / `EsiGenerator::CreateOfflineDictionary(false, true)` parity).
    pub fn to_esp_xml_element(&self) -> DomElement {
        let mut app_el = DomElement::new("Application");
        app_el.push_child(DomNode::Element(
            self.od.build_dictionary_element_ex(true, None),
        ));
        for m in &self.modules {
            let mut mod_el = DomElement::new("Module");
            mod_el.push_child(DomNode::Element(
                m.od.build_dictionary_element_ex(true, Some(m.module_ident)),
            ));
            app_el.push_child(DomNode::Element(mod_el));
        }
        app_el
    }
}
