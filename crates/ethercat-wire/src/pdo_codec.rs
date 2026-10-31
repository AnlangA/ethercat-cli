use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{CliError, Result};
use crate::types::{
    decode_typed_value, encode_typed_value, extract_bits_le, format_hex, insert_bits_le, parse_u16,
    parse_usize, DataTypeSpec,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PdoFieldDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_id: Option<String>,
    pub ty: DataTypeSpec,
    pub bit_offset: usize,
    pub bit_length: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PdoLayout {
    pub fields: Vec<PdoFieldDef>,
    #[serde(default, skip_serializing_if = "is_zero_usize")]
    pub min_total_bits: usize,
}

fn is_zero_usize(v: &usize) -> bool {
    *v == 0
}

impl PdoLayout {
    /// Parse a compact PDO layout specification string:
    /// `"statusword:u16@0,actual_pos:i32@16,ready:bool@0"` or `"flag:u8@16:4"` (explicit bit length `:4`).
    pub fn parse_spec(spec: &str) -> Result<Self> {
        let mut fields = Vec::new();
        for raw_item in spec.split(',') {
            let item = raw_item.trim();
            if item.is_empty() {
                continue;
            }
            let (name_ty, off_part) = item.rsplit_once('@').ok_or_else(|| {
                CliError::Format(format!(
                    "invalid PDO field spec '{item}'; expected `<name>:<type>@<bit_offset>[:<bit_len>]`"
                ))
            })?;
            let (name, ty_str) = name_ty.rsplit_once(':').ok_or_else(|| {
                CliError::Format(format!(
                    "invalid PDO field '{item}'; missing `:<type>` before `@`"
                ))
            })?;
            let ty = DataTypeSpec::parse_name(ty_str)?;
            let (bit_offset, bit_length) = if let Some((off_s, len_s)) = off_part.split_once(':') {
                (
                    parse_usize(off_s).map_err(CliError::Format)?,
                    parse_usize(len_s).map_err(CliError::Format)?,
                )
            } else {
                let off = parse_usize(off_part).map_err(CliError::Format)?;
                let len = ty.default_bit_len().ok_or_else(|| {
                    CliError::Format(format!(
                        "type '{ty_str}' requires explicit `:<bit_len>` in '{item}'"
                    ))
                })?;
                (off, len)
            };
            let trimmed_name = name.trim().to_string();
            let entry_id = if trimmed_name.contains(':') && trimmed_name.starts_with("0x") {
                Some(normalize_entry_key(&trimmed_name))
            } else {
                None
            };
            fields.push(PdoFieldDef {
                name: trimmed_name,
                entry_id,
                ty,
                bit_offset,
                bit_length,
            });
        }
        if fields.is_empty() {
            return Err(CliError::Format(
                "PDO layout spec contains no fields".into(),
            ));
        }
        Ok(Self {
            fields,
            min_total_bits: 0,
        })
    }

    pub fn to_spec_string(&self) -> String {
        self.fields
            .iter()
            .map(|f| {
                let ty_str = serde_json::to_value(f.ty)
                    .ok()
                    .and_then(|v| v.as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "hex".into());
                let safe_name = f.name.replace([',', '@'], "_");
                format!("{safe_name}:{ty_str}@{}:{}", f.bit_offset, f.bit_length)
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn total_bits(&self) -> usize {
        self.fields
            .iter()
            .map(|f| f.bit_offset.saturating_add(f.bit_length))
            .max()
            .unwrap_or(0)
            .max(self.min_total_bits)
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bits().div_ceil(8)
    }
}

pub fn decode_pdo_payload(data: &[u8], layout: &PdoLayout) -> Result<Vec<Value>> {
    let mut out = Vec::with_capacity(layout.fields.len());
    let data_bits = data.len().saturating_mul(8);
    for f in &layout.fields {
        let Some(end_bit) = f.bit_offset.checked_add(f.bit_length) else {
            continue;
        };
        if end_bit > data_bits {
            continue;
        }
        let raw_bits = extract_bits_le(data, f.bit_offset, f.bit_length)?;
        let val = decode_typed_value(&raw_bits, f.ty, Some(f.bit_length))?;
        out.push(json!({
            "name": f.name,
            "entry": f.entry_id,
            "type": f.ty,
            "bit_offset": f.bit_offset,
            "bit_length": f.bit_length,
            "raw_hex": format_hex(&raw_bits),
            "value": val,
        }));
    }
    Ok(out)
}

/// Apply `key=value` assignments (where `key` matches field `name` or `0xXXXX:XX` `entry_id`) into a PDO byte buffer.
pub fn encode_pdo_assignments(
    base_buf: &mut [u8],
    layout: &PdoLayout,
    assignments: &[String],
) -> Result<()> {
    for assign in assignments {
        let (k, v) = assign.split_once('=').ok_or_else(|| {
            CliError::Format(format!(
                "invalid PDO assignment '{assign}'; expected `<field_or_0xXXXX:XX>=<value>`"
            ))
        })?;
        let key = k.trim();
        let norm_entry = normalize_entry_key(key);
        let field = layout
            .fields
            .iter()
            .find(|f| {
                f.name.eq_ignore_ascii_case(key)
                    || f.entry_id
                        .as_deref()
                        .is_some_and(|eid| eid.eq_ignore_ascii_case(&norm_entry))
            })
            .ok_or_else(|| {
                CliError::Format(format!(
                    "PDO field '{key}' not found in layout; available fields: {}",
                    layout
                        .fields
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            })?;
        let encoded = encode_typed_value(v.trim(), field.ty)?;
        insert_bits_le(base_buf, field.bit_offset, field.bit_length, &encoded)?;
    }
    Ok(())
}

pub fn normalize_entry_key(k: &str) -> String {
    if let Some((idx_s, sub_s)) = k.split_once(':') {
        if let (Ok(idx), Ok(sub)) = (
            parse_u16(idx_s),
            u8::from_str_radix(sub_s.trim_start_matches("0x"), 16).or_else(|_| sub_s.parse::<u8>()),
        ) {
            return format!("0x{idx:04x}:{sub:02x}");
        }
    }
    k.to_ascii_lowercase()
}
