use std::borrow::Cow;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{CliError, Result};

fn strip_underscores(input: &str) -> Cow<'_, str> {
    let trimmed = input.trim();
    if trimmed.contains('_') {
        Cow::Owned(trimmed.replace('_', ""))
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// Parse unsigned u64 supporting `0x` / `#x` hex, `0b` binary, `0o` octal, or decimal (with optional `_`).
pub fn parse_u64(input: &str) -> std::result::Result<u64, String> {
    let s = strip_underscores(input);
    if s.is_empty() {
        return Err("empty numeric string".to_string());
    }
    if let Some(rest) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .or_else(|| s.strip_prefix("#x"))
        .or_else(|| s.strip_prefix("#X"))
    {
        u64::from_str_radix(rest, 16).map_err(|e| format!("invalid hex '{input}': {e}"))
    } else if let Some(rest) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        u64::from_str_radix(rest, 2).map_err(|e| format!("invalid binary '{input}': {e}"))
    } else if let Some(rest) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
        u64::from_str_radix(rest, 8).map_err(|e| format!("invalid octal '{input}': {e}"))
    } else {
        s.parse::<u64>()
            .map_err(|e| format!("invalid integer '{input}': {e}"))
    }
}

pub fn parse_u32(input: &str) -> std::result::Result<u32, String> {
    let v = parse_u64(input)?;
    u32::try_from(v).map_err(|_| format!("value '{input}' out of range for u32"))
}

pub fn parse_u16(input: &str) -> std::result::Result<u16, String> {
    let v = parse_u64(input)?;
    u16::try_from(v).map_err(|_| format!("value '{input}' out of range for u16"))
}

pub fn parse_u8(input: &str) -> std::result::Result<u8, String> {
    let v = parse_u64(input)?;
    u8::try_from(v).map_err(|_| format!("value '{input}' out of range for u8"))
}

pub fn parse_usize(input: &str) -> std::result::Result<usize, String> {
    let v = parse_u64(input)?;
    usize::try_from(v).map_err(|_| format!("value '{input}' out of range for usize"))
}

pub fn parse_i64(input: &str) -> std::result::Result<i64, String> {
    let s = strip_underscores(input);
    if let Some(neg) = s.strip_prefix('-') {
        let mag = parse_u64(neg)?;
        if mag == (i64::MAX as u64) + 1 {
            Ok(i64::MIN)
        } else if mag <= i64::MAX as u64 {
            Ok(-(mag as i64))
        } else {
            Err(format!("value '{input}' out of range for i64"))
        }
    } else {
        let mag = parse_u64(&s)?;
        i64::try_from(mag).map_err(|_| format!("value '{input}' out of range for i64"))
    }
}

/// Parse byte sequence from hex string (`"01 02 ff"`, `"0x0102ff"`, `"01:02:ff"`, `"01-02-ff"`)
/// or from a binary file if prefixed with `@` (e.g. `@payload.bin`).
pub fn parse_bytes_arg(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if let Some(path) = trimmed.strip_prefix('@') {
        return std::fs::read(path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot read payload file '{path}': {e}"),
            ))
        });
    }
    parse_hex_bytes(trimmed)
}

/// Parse arbitrary hex text into bytes, tolerating spaces, commas, newlines, `0x` prefixes,
/// and byte-pair `:` / `-` / `_` separators (rejecting leading, trailing, or consecutive `-` / `:`).
pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.starts_with('-')
        || trimmed.starts_with(':')
        || trimmed.ends_with('-')
        || trimmed.ends_with(':')
    {
        return Err(CliError::Format(format!(
            "invalid leading or trailing separator in hex byte string '{trimmed}'"
        )));
    }
    let mut cleaned = String::with_capacity(trimmed.len());
    let mut chars = trimmed.chars().peekable();
    let mut prev_was_delim = false;
    while let Some(c) = chars.next() {
        if c == '0' && matches!(chars.peek(), Some('x' | 'X')) {
            chars.next();
            prev_was_delim = false;
            continue;
        }
        if c.is_ascii_hexdigit() {
            cleaned.push(c);
            prev_was_delim = false;
        } else if matches!(c, ':' | '-') {
            if prev_was_delim || cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
                return Err(CliError::Format(format!(
                    "misplaced '{c}' delimiter in hex byte string '{trimmed}'"
                )));
            }
            prev_was_delim = true;
        } else if matches!(c, ' ' | '\t' | '\r' | '\n' | ',' | '_') {
            prev_was_delim = false;
        } else {
            return Err(CliError::Format(format!(
                "unexpected character '{c}' in hex byte string"
            )));
        }
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err(CliError::Format(format!(
            "hex byte string has odd number of nibbles ({})",
            cleaned.len()
        )));
    }
    hex::decode(&cleaned).map_err(|e| CliError::Format(format!("invalid hex bytes: {e}")))
}

pub fn format_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

#[allow(dead_code)]
pub fn format_hex_spaced(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let bytes = parse_hex_bytes(s)?;
    if bytes.len() != 6 {
        return Err(CliError::Format(format!(
            "MAC address must be 6 bytes, got {} bytes from '{s}'",
            bytes.len()
        )));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Supported EtherCAT / CoE / PDO value data types for decoding and encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataTypeSpec {
    /// Automatically infer representation from byte/bit length (u8/u16/u32/u64 or hex+ascii).
    Auto,
    /// Boolean (1 bit or 1 byte: 0 = false, non-zero = true).
    Bool,
    /// Unsigned 8-bit integer (ECT_UNSIGNED8).
    U8,
    /// Unsigned 16-bit little-endian integer (ECT_UNSIGNED16).
    U16,
    /// Unsigned 24-bit little-endian integer (ECT_UNSIGNED24).
    U24,
    /// Unsigned 32-bit little-endian integer (ECT_UNSIGNED32).
    U32,
    /// Unsigned 64-bit little-endian integer (ECT_UNSIGNED64).
    U64,
    /// Signed 8-bit integer (ECT_INTEGER8).
    I8,
    /// Signed 16-bit little-endian integer (ECT_INTEGER16).
    I16,
    /// Signed 24-bit little-endian integer (ECT_INTEGER24).
    I24,
    /// Signed 32-bit little-endian integer (ECT_INTEGER32).
    I32,
    /// Signed 64-bit little-endian integer (ECT_INTEGER64).
    I64,
    /// IEEE-754 32-bit little-endian float (ECT_REAL32).
    F32,
    /// IEEE-754 64-bit little-endian float (ECT_REAL64).
    F64,
    /// UTF-8 / ASCII visible string, trimming trailing NUL bytes (ECT_VISIBLE_STRING).
    String,
    /// Raw hexadecimal byte string (ECT_OCTET_STRING).
    Hex,
}

impl DataTypeSpec {
    pub fn from_ect_code(code: u16) -> Self {
        match code {
            0x0001 | 0x0030 => DataTypeSpec::Bool,
            0x0002 => DataTypeSpec::I8,
            0x0003 => DataTypeSpec::I16,
            0x0004 => DataTypeSpec::I32,
            0x0005 | 0x001E | 0x002D | 0x0031..=0x0037 => DataTypeSpec::U8,
            0x0006 | 0x001F | 0x002E => DataTypeSpec::U16,
            0x0007 | 0x0020 | 0x002F => DataTypeSpec::U32,
            0x0008 => DataTypeSpec::F32,
            0x0009 => DataTypeSpec::String,
            0x000A => DataTypeSpec::Hex,
            0x0010 => DataTypeSpec::I24,
            0x0011 => DataTypeSpec::F64,
            0x0015 => DataTypeSpec::I64,
            0x0016 => DataTypeSpec::U24,
            0x001B => DataTypeSpec::U64,
            _ => DataTypeSpec::Auto,
        }
    }

    pub fn parse_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "bool" | "boolean" | "bit" | "bit1" => Ok(Self::Bool),
            "u8" | "uint8" | "usint" | "byte" | "bit2" | "bit3" | "bit4" | "bit5" | "bit6"
            | "bit7" | "bit8" => Ok(Self::U8),
            "u16" | "uint16" | "uint" | "word" => Ok(Self::U16),
            "u24" | "uint24" => Ok(Self::U24),
            "u32" | "uint32" | "udint" | "dword" => Ok(Self::U32),
            "u64" | "uint64" | "ulint" | "lword" => Ok(Self::U64),
            "i8" | "int8" | "sint" => Ok(Self::I8),
            "i16" | "int16" | "int" => Ok(Self::I16),
            "i24" | "int24" => Ok(Self::I24),
            "i32" | "int32" | "dint" => Ok(Self::I32),
            "i64" | "int64" | "lint" => Ok(Self::I64),
            "f32" | "float" | "real" | "real32" => Ok(Self::F32),
            "f64" | "double" | "lreal" | "real64" => Ok(Self::F64),
            "string" | "str" | "visible_string" => Ok(Self::String),
            "hex" | "bytes" | "octets" | "octet_string" => Ok(Self::Hex),
            other => Err(CliError::Format(format!("unknown data type '{other}'"))),
        }
    }

    pub fn default_bit_len(self) -> Option<usize> {
        match self {
            Self::Bool => Some(1),
            Self::U8 | Self::I8 => Some(8),
            Self::U16 | Self::I16 => Some(16),
            Self::U24 | Self::I24 => Some(24),
            Self::U32 | Self::I32 | Self::F32 => Some(32),
            Self::U64 | Self::I64 | Self::F64 => Some(64),
            Self::Auto | Self::String | Self::Hex => None,
        }
    }

    pub fn from_coe_datatype(dt: u16, bit_len: u16) -> Option<Self> {
        match dt {
            0x0001 => Some(Self::Bool),
            0x0002 => Some(Self::I8),
            0x0003 => Some(Self::I16),
            0x0004 => Some(Self::I32),
            0x0005 | 0x001E | 0x002D => Some(Self::U8),
            0x0006 | 0x001F | 0x002E => Some(Self::U16),
            0x0007 | 0x0020 | 0x002F => Some(Self::U32),
            0x0008 => Some(Self::F32),
            0x0009 => Some(Self::String),
            0x000A => Some(Self::Hex),
            0x0010 => Some(Self::I24),
            0x0011 => Some(Self::F64),
            0x0015 => Some(Self::I64),
            0x0016 => Some(Self::U24),
            0x001B => Some(Self::U64),
            0x0030..=0x003F => match bit_len {
                1 => Some(Self::Bool),
                2..=8 => Some(Self::U8),
                9..=16 => Some(Self::U16),
                17..=32 => Some(Self::U32),
                _ => Some(Self::Hex),
            },
            _ => None,
        }
    }
}

/// Extract `bit_len` bits starting at `bit_offset` (EtherCAT little-endian bit numbering:
/// bit 0 is LSB of byte 0; bit 7 is MSB of byte 0; bit 8 is LSB of byte 1).
pub fn extract_bits_le(buf: &[u8], bit_offset: usize, bit_len: usize) -> Result<Vec<u8>> {
    let total_bits = buf
        .len()
        .checked_mul(8)
        .ok_or_else(|| CliError::Format("payload bit length overflow".into()))?;
    let end_bit = bit_offset
        .checked_add(bit_len)
        .ok_or_else(|| CliError::Format("bit slice offset + length overflow".into()))?;
    if end_bit > total_bits {
        return Err(CliError::Format(format!(
            "bit slice [{bit_offset}..{end_bit}) exceeds payload size ({total_bits} bits / {} bytes)",
            buf.len()
        )));
    }
    if bit_len == 0 {
        return Ok(Vec::new());
    }
    let out_bytes = bit_len.div_ceil(8);
    let mut out = vec![0u8; out_bytes];
    if bit_offset.is_multiple_of(8) {
        let byte_start = bit_offset / 8;
        let full_bytes = bit_len / 8;
        let rem_bits = bit_len % 8;
        out[..full_bytes].copy_from_slice(&buf[byte_start..byte_start + full_bytes]);
        if rem_bits > 0 {
            out[full_bytes] = buf[byte_start + full_bytes] & ((1u8 << rem_bits) - 1);
        }
        return Ok(out);
    }
    for i in 0..bit_len {
        let src_bit = bit_offset + i;
        let bit_val = (buf[src_bit / 8] >> (src_bit % 8)) & 1;
        out[i / 8] |= bit_val << (i % 8);
    }
    Ok(out)
}

/// Insert `bit_len` bits from `src` (LSB-first) into `dst` starting at `bit_offset`.
pub fn insert_bits_le(dst: &mut [u8], bit_offset: usize, bit_len: usize, src: &[u8]) -> Result<()> {
    let total_bits = dst
        .len()
        .checked_mul(8)
        .ok_or_else(|| CliError::Format("destination buffer bit length overflow".into()))?;
    let end_bit = bit_offset
        .checked_add(bit_len)
        .ok_or_else(|| CliError::Format("bit write offset + length overflow".into()))?;
    if end_bit > total_bits {
        return Err(CliError::Format(format!(
            "bit write [{bit_offset}..{end_bit}) exceeds buffer size ({total_bits} bits)"
        )));
    }
    if bit_len == 0 {
        return Ok(());
    }
    if bit_offset.is_multiple_of(8) {
        let byte_start = bit_offset / 8;
        let full_bytes = bit_len / 8;
        let rem_bits = bit_len % 8;
        let copy_bytes = full_bytes.min(src.len());
        dst[byte_start..byte_start + copy_bytes].copy_from_slice(&src[..copy_bytes]);
        if copy_bytes < full_bytes {
            dst[byte_start + copy_bytes..byte_start + full_bytes].fill(0);
        }
        if rem_bits > 0 {
            let mask = (1u8 << rem_bits) - 1;
            let src_part = src.get(full_bytes).copied().unwrap_or(0) & mask;
            let slot = &mut dst[byte_start + full_bytes];
            *slot = (*slot & !mask) | src_part;
        }
        return Ok(());
    }
    for i in 0..bit_len {
        let src_bit = if i / 8 < src.len() {
            (src[i / 8] >> (i % 8)) & 1
        } else {
            0
        };
        let dst_idx = (bit_offset + i) / 8;
        let dst_shift = (bit_offset + i) % 8;
        if src_bit == 1 {
            dst[dst_idx] |= 1 << dst_shift;
        } else {
            dst[dst_idx] &= !(1 << dst_shift);
        }
    }
    Ok(())
}

/// Sign-extend an integer of `bit_len` bits stored in a u64.
fn sign_extend(raw: u64, bit_len: usize) -> i64 {
    if bit_len == 0 || bit_len >= 64 {
        return raw as i64;
    }
    let shift = 64 - bit_len;
    ((raw << shift) as i64) >> shift
}

fn read_le_u64_padded(bytes: &[u8]) -> u64 {
    let mut tmp = [0u8; 8];
    let n = bytes.len().min(8);
    tmp[..n].copy_from_slice(&bytes[..n]);
    u64::from_le_bytes(tmp)
}

/// Decode raw little-endian bytes (optionally with an exact bit length) into a JSON Value.
pub fn decode_typed_value(
    bytes: &[u8],
    ty: DataTypeSpec,
    bit_len_hint: Option<usize>,
) -> Result<Value> {
    let bit_len = bit_len_hint.unwrap_or_else(|| bytes.len().saturating_mul(8));
    match ty {
        DataTypeSpec::Auto => {
            if bit_len == 0 || bytes.is_empty() {
                return Ok(json!(null));
            }
            match bit_len {
                1 => Ok(json!((bytes[0] & 1) != 0)),
                2..=8 => {
                    let mask = if bit_len < 8 {
                        ((1u16 << bit_len) - 1) as u8
                    } else {
                        0xFF
                    };
                    Ok(json!(bytes[0] & mask))
                }
                9..=16 => {
                    let mask = if bit_len < 16 {
                        (1u64 << bit_len) - 1
                    } else {
                        0xFFFF
                    };
                    Ok(json!((read_le_u64_padded(bytes) & mask) as u16))
                }
                17..=32 => {
                    let mask = if bit_len < 32 {
                        (1u64 << bit_len) - 1
                    } else {
                        0xFFFF_FFFF
                    };
                    Ok(json!((read_le_u64_padded(bytes) & mask) as u32))
                }
                33..=64 => {
                    let mask = if bit_len < 64 {
                        (1u64 << bit_len) - 1
                    } else {
                        u64::MAX
                    };
                    Ok(json!(read_le_u64_padded(bytes) & mask))
                }
                _ => {
                    // Check if printable ASCII string without intermediate Vec allocation
                    let nul_end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    let trimmed = &bytes[..nul_end];
                    if !trimmed.is_empty()
                        && trimmed
                            .iter()
                            .all(|&b| (0x20..=0x7E).contains(&b) || b == b'\t')
                    {
                        Ok(json!({
                            "hex": format_hex(bytes),
                            "ascii": String::from_utf8_lossy(trimmed).into_owned()
                        }))
                    } else {
                        Ok(json!(format_hex(bytes)))
                    }
                }
            }
        }
        DataTypeSpec::Bool => {
            let any = bytes.iter().any(|&b| b != 0);
            Ok(json!(any))
        }
        DataTypeSpec::U8 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for u8".into()));
            }
            let mask = if bit_len < 8 {
                (1u16 << bit_len) - 1
            } else {
                0xFF
            } as u8;
            Ok(json!(bytes[0] & mask))
        }
        DataTypeSpec::U16 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for u16".into()));
            }
            let bits = bit_len.clamp(1, 16);
            let mask = if bits < 16 {
                (1u64 << bits) - 1
            } else {
                0xFFFF
            };
            Ok(json!((read_le_u64_padded(bytes) & mask) as u16))
        }
        DataTypeSpec::U24 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for u24".into()));
            }
            let bits = bit_len.clamp(1, 24);
            let mask = if bits < 24 {
                (1u64 << bits) - 1
            } else {
                0x00FF_FFFF
            };
            Ok(json!((read_le_u64_padded(bytes) & mask) as u32))
        }
        DataTypeSpec::U32 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for u32".into()));
            }
            let bits = bit_len.clamp(1, 32);
            let mask = if bits < 32 {
                (1u64 << bits) - 1
            } else {
                0xFFFF_FFFF
            };
            Ok(json!((read_le_u64_padded(bytes) & mask) as u32))
        }
        DataTypeSpec::U64 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for u64".into()));
            }
            let bits = bit_len.clamp(1, 64);
            let mask = if bits < 64 {
                (1u64 << bits) - 1
            } else {
                u64::MAX
            };
            Ok(json!(read_le_u64_padded(bytes) & mask))
        }
        DataTypeSpec::I8 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for i8".into()));
            }
            let bits = bit_len.clamp(1, 8);
            Ok(json!(sign_extend(bytes[0] as u64, bits) as i8))
        }
        DataTypeSpec::I16 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for i16".into()));
            }
            let bits = bit_len.clamp(1, 16);
            Ok(json!(sign_extend(read_le_u64_padded(bytes), bits) as i16))
        }
        DataTypeSpec::I24 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for i24".into()));
            }
            let bits = bit_len.clamp(1, 24);
            Ok(json!(sign_extend(read_le_u64_padded(bytes), bits) as i32))
        }
        DataTypeSpec::I32 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for i32".into()));
            }
            let bits = bit_len.clamp(1, 32);
            Ok(json!(sign_extend(read_le_u64_padded(bytes), bits) as i32))
        }
        DataTypeSpec::I64 => {
            if bytes.is_empty() {
                return Err(CliError::Format("need >=1 byte for i64".into()));
            }
            let bits = bit_len.clamp(1, 64);
            Ok(json!(sign_extend(read_le_u64_padded(bytes), bits)))
        }
        DataTypeSpec::F32 => {
            if bytes.len() < 4 {
                return Err(CliError::Format(format!(
                    "need 4 bytes for f32, got {}",
                    bytes.len()
                )));
            }
            let v = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            Ok(json_float32(v))
        }
        DataTypeSpec::F64 => {
            if bytes.len() < 8 {
                return Err(CliError::Format(format!(
                    "need 8 bytes for f64, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&bytes[..8]);
            Ok(json_float64(f64::from_le_bytes(arr)))
        }
        DataTypeSpec::String => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            Ok(json!(String::from_utf8_lossy(&bytes[..end]).into_owned()))
        }
        DataTypeSpec::Hex => Ok(json!(format_hex(bytes))),
    }
}

fn json_float32(v: f32) -> Value {
    if v.is_nan() {
        json!("NaN")
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            json!("-Infinity")
        } else {
            json!("Infinity")
        }
    } else {
        json!(v)
    }
}

fn json_float64(v: f64) -> Value {
    if v.is_nan() {
        json!("NaN")
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            json!("-Infinity")
        } else {
            json!("Infinity")
        }
    } else {
        json!(v)
    }
}

/// Check whether a trimmed CLI scalar string looks like a decimal floating-point literal.
pub fn is_decimal_float_literal(s: &str) -> bool {
    if s.starts_with('@') || !s.contains('.') {
        return false;
    }
    let unsigned = s
        .strip_prefix('-')
        .or_else(|| s.strip_prefix('+'))
        .unwrap_or(s);
    !(unsigned.starts_with("0x")
        || unsigned.starts_with("0X")
        || unsigned.starts_with("#x")
        || unsigned.starts_with("#X")
        || unsigned.starts_with("0b")
        || unsigned.starts_with("0B")
        || unsigned.starts_with("0o")
        || unsigned.starts_with("0O"))
}

/// Encode a CLI string value into little-endian bytes according to `ty`.
pub fn encode_typed_value(value_str: &str, ty: DataTypeSpec) -> Result<Vec<u8>> {
    let s = value_str.trim();
    match ty {
        DataTypeSpec::Auto => {
            if s.starts_with('@') {
                parse_bytes_arg(s)
            } else if s.eq_ignore_ascii_case("true") {
                Ok(vec![1])
            } else if s.eq_ignore_ascii_case("false") {
                Ok(vec![0])
            } else if is_decimal_float_literal(s) {
                let cleaned = s.replace('_', "");
                let v64: f64 = cleaned
                    .parse()
                    .map_err(|e| CliError::Format(format!("invalid float literal '{s}': {e}")))?;
                if !v64.is_finite() {
                    return Err(CliError::Format(format!(
                        "non-finite float literal '{s}' requires explicit --type f32 or f64"
                    )));
                }
                let v32 = v64 as f32;
                if v32.is_finite() {
                    Ok(v32.to_le_bytes().to_vec())
                } else {
                    Ok(v64.to_le_bytes().to_vec())
                }
            } else if s.starts_with('-') {
                let v = parse_i64(s).map_err(CliError::Format)?;
                if (i8::MIN as i64..=i8::MAX as i64).contains(&v) {
                    Ok(vec![(v as i8) as u8])
                } else if (i16::MIN as i64..=i16::MAX as i64).contains(&v) {
                    Ok((v as i16).to_le_bytes().to_vec())
                } else if (i32::MIN as i64..=i32::MAX as i64).contains(&v) {
                    Ok((v as i32).to_le_bytes().to_vec())
                } else {
                    Ok(v.to_le_bytes().to_vec())
                }
            } else if let Ok(v) = parse_u64(s) {
                if v <= u8::MAX as u64 {
                    Ok(vec![v as u8])
                } else if v <= u16::MAX as u64 {
                    Ok((v as u16).to_le_bytes().to_vec())
                } else if v <= u32::MAX as u64 {
                    Ok((v as u32).to_le_bytes().to_vec())
                } else {
                    Ok(v.to_le_bytes().to_vec())
                }
            } else {
                parse_hex_bytes(s)
            }
        }
        DataTypeSpec::Bool => match s.to_ascii_lowercase().as_str() {
            "1" | "true" | "on" | "yes" => Ok(vec![1]),
            "0" | "false" | "off" | "no" => Ok(vec![0]),
            _ => Err(CliError::Format(format!("invalid bool value '{s}'"))),
        },
        DataTypeSpec::U8 => {
            let v = parse_u8(s).map_err(CliError::Format)?;
            Ok(vec![v])
        }
        DataTypeSpec::U16 => {
            let v = parse_u16(s).map_err(CliError::Format)?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::U24 => {
            let v = parse_u32(s).map_err(CliError::Format)?;
            if v > 0x00FF_FFFF {
                return Err(CliError::Format(format!("value '{s}' exceeds u24 max")));
            }
            let b = v.to_le_bytes();
            Ok(vec![b[0], b[1], b[2]])
        }
        DataTypeSpec::U32 => {
            let v = parse_u32(s).map_err(CliError::Format)?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::U64 => {
            let v = parse_u64(s).map_err(CliError::Format)?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::I8 => {
            let v = parse_i64(s).map_err(CliError::Format)?;
            let v8 = i8::try_from(v)
                .map_err(|_| CliError::Format(format!("value '{s}' out of range for i8")))?;
            Ok(vec![v8 as u8])
        }
        DataTypeSpec::I16 => {
            let v = parse_i64(s).map_err(CliError::Format)?;
            let v16 = i16::try_from(v)
                .map_err(|_| CliError::Format(format!("value '{s}' out of range for i16")))?;
            Ok(v16.to_le_bytes().to_vec())
        }
        DataTypeSpec::I24 => {
            let v = parse_i64(s).map_err(CliError::Format)?;
            if !(-0x80_0000..=0x7F_FFFF).contains(&v) {
                return Err(CliError::Format(format!(
                    "value '{s}' out of range for i24"
                )));
            }
            let b = (v as i32).to_le_bytes();
            Ok(vec![b[0], b[1], b[2]])
        }
        DataTypeSpec::I32 => {
            let v = parse_i64(s).map_err(CliError::Format)?;
            let v32 = i32::try_from(v)
                .map_err(|_| CliError::Format(format!("value '{s}' out of range for i32")))?;
            Ok(v32.to_le_bytes().to_vec())
        }
        DataTypeSpec::I64 => {
            let v = parse_i64(s).map_err(CliError::Format)?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::F32 => {
            let v: f32 = strip_underscores(s)
                .parse()
                .map_err(|e| CliError::Format(format!("invalid f32 '{s}': {e}")))?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::F64 => {
            let v: f64 = strip_underscores(s)
                .parse()
                .map_err(|e| CliError::Format(format!("invalid f64 '{s}': {e}")))?;
            Ok(v.to_le_bytes().to_vec())
        }
        DataTypeSpec::String => Ok(s.as_bytes().to_vec()),
        DataTypeSpec::Hex => parse_bytes_arg(s),
    }
}
