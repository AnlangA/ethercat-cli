use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

use flate2::read::{DeflateDecoder, GzDecoder};
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;

use ethercat_wire::error::{CliError, Result};

/// Read a file that may be GZIP-compressed (`.escfg`, `.esp`) or plain XML/text.
pub fn read_gzip_or_plain(path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read(path).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read '{}': {e}", path.display()),
        ))
    })?;
    decode_gzip_or_plain(&raw, &path.display().to_string())
}

const MAX_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

/// Decompress bytes if GZIP magic (`1F 8B`) is present, otherwise return as-is.
pub fn decode_gzip_or_plain(raw: &[u8], label: &str) -> Result<Vec<u8>> {
    if raw.len() >= 2 && raw[0] == 0x1F && raw[1] == 0x8B {
        let decoder = GzDecoder::new(raw);
        let mut out = Vec::with_capacity(raw.len().saturating_mul(2).min(1024 * 1024));
        decoder
            .take(MAX_DECOMPRESSED_BYTES + 1)
            .read_to_end(&mut out)
            .map_err(|e| CliError::Format(format!("failed to gunzip '{label}': {e}")))?;
        if out.len() as u64 > MAX_DECOMPRESSED_BYTES {
            return Err(CliError::Format(format!(
                "gunzip output for '{label}' exceeds maximum allowed size ({} MiB)",
                MAX_DECOMPRESSED_BYTES / (1024 * 1024)
            )));
        }
        Ok(out)
    } else {
        Ok(raw.to_vec())
    }
}

/// Convert raw bytes to String (stripping UTF-8 BOM if present, with Latin-1 fallback for C comments).
pub fn bytes_to_text(bytes: &[u8]) -> String {
    let slice = if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        &bytes[3..]
    } else {
        bytes
    };
    match std::str::from_utf8(slice) {
        Ok(s) => s.to_string(),
        Err(_) => slice.iter().map(|&b| b as char).collect(),
    }
}

/// Compress `plain` with GZIP and write to `path` (creating parent directories if needed).
pub fn write_gzip_file(path: &Path, plain: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let encoded = encode_gzip_bytes(plain)?;
    fs::write(path, encoded)?;
    Ok(())
}

/// Compress `plain` into a GZIP byte buffer.
pub fn encode_gzip_bytes(plain: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(plain)
        .map_err(|e| CliError::Format(format!("failed to gzip compress buffer: {e}")))?;
    encoder
        .finish()
        .map_err(|e| CliError::Format(format!("failed to finish gzip stream: {e}")))
}

/// Minimal pure-Rust PKZIP archive reader for OpenXML `.xlsx` packages.
#[derive(Debug, Clone)]
pub struct ZipArchiveReader {
    entries: BTreeMap<String, Vec<u8>>,
}

impl ZipArchiveReader {
    pub fn open(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read zip/xlsx file '{}': {e}", path.display()),
            ))
        })?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        const EOCD_SIG: u32 = 0x0605_4B50;
        const CD_SIG: u32 = 0x0201_4B50;
        const LFH_SIG: u32 = 0x0403_4B50;

        if data.len() < 22 {
            return Err(CliError::Format(
                "invalid ZIP/XLSX archive: file shorter than 22 bytes".into(),
            ));
        }

        let min_pos = data.len().saturating_sub(22 + 65_535);
        let mut eocd_pos = None;
        let mut pos = data.len() - 22;
        loop {
            if le_u32(data, pos) == EOCD_SIG {
                let comment_len = le_u16(data, pos + 20) as usize;
                if pos + 22 + comment_len <= data.len() {
                    eocd_pos = Some(pos);
                    break;
                }
            }
            if pos == min_pos {
                break;
            }
            pos -= 1;
        }

        let eocd = eocd_pos.ok_or_else(|| {
            CliError::Format("invalid ZIP/XLSX archive: End of Central Directory not found".into())
        })?;

        let total_entries = le_u16(data, eocd + 10) as usize;
        let cd_size = le_u32(data, eocd + 12) as usize;
        let cd_offset = le_u32(data, eocd + 16) as usize;

        if cd_offset
            .checked_add(cd_size)
            .is_none_or(|end| end > data.len())
        {
            return Err(CliError::Format(
                "invalid ZIP/XLSX archive: Central Directory out of bounds".into(),
            ));
        }

        let mut entries = BTreeMap::new();
        let mut cursor = cd_offset;

        for _ in 0..total_entries {
            if cursor + 46 > data.len() || le_u32(data, cursor) != CD_SIG {
                return Err(CliError::Format(
                    "invalid ZIP/XLSX archive: malformed Central Directory entry".into(),
                ));
            }
            let method = le_u16(data, cursor + 10);
            let expected_crc = le_u32(data, cursor + 16);
            let comp_size = le_u32(data, cursor + 20) as usize;
            let uncomp_size = le_u32(data, cursor + 24) as usize;
            let name_len = le_u16(data, cursor + 28) as usize;
            let extra_len = le_u16(data, cursor + 30) as usize;
            let comment_len = le_u16(data, cursor + 32) as usize;
            let lfh_offset = le_u32(data, cursor + 42) as usize;

            let name_end = cursor
                .checked_add(46)
                .and_then(|v| v.checked_add(name_len))
                .ok_or_else(|| {
                    CliError::Format(
                        "invalid ZIP/XLSX archive: Central Directory offset overflow".into(),
                    )
                })?;
            let next_cursor = name_end
                .checked_add(extra_len)
                .and_then(|v| v.checked_add(comment_len))
                .ok_or_else(|| {
                    CliError::Format(
                        "invalid ZIP/XLSX archive: Central Directory entry length overflow".into(),
                    )
                })?;
            if next_cursor > data.len() {
                return Err(CliError::Format(
                    "invalid ZIP/XLSX archive: Central Directory filename exceeds EOF".into(),
                ));
            }

            let raw_name = String::from_utf8_lossy(&data[cursor + 46..name_end]).replace('\\', "/");
            cursor = next_cursor;

            if raw_name.ends_with('/') {
                continue;
            }

            if uncomp_size as u64 > MAX_DECOMPRESSED_BYTES {
                return Err(CliError::Format(format!(
                    "ZIP entry '{raw_name}' uncompressed size ({uncomp_size} bytes) exceeds safety limit"
                )));
            }

            if lfh_offset
                .checked_add(30)
                .is_none_or(|end| end > data.len())
                || le_u32(data, lfh_offset) != LFH_SIG
            {
                return Err(CliError::Format(format!(
                    "invalid ZIP/XLSX archive: malformed Local File Header for '{raw_name}'"
                )));
            }
            let lfh_name_len = le_u16(data, lfh_offset + 26) as usize;
            let lfh_extra_len = le_u16(data, lfh_offset + 28) as usize;
            let payload_start = lfh_offset
                .checked_add(30)
                .and_then(|v| v.checked_add(lfh_name_len))
                .and_then(|v| v.checked_add(lfh_extra_len))
                .ok_or_else(|| {
                    CliError::Format(format!(
                        "ZIP entry '{raw_name}' local header offset overflow"
                    ))
                })?;
            let payload_end = payload_start
                .checked_add(comp_size)
                .ok_or_else(|| CliError::Format(format!("ZIP entry '{raw_name}' size overflow")))?;
            if payload_end > data.len() {
                return Err(CliError::Format(format!(
                    "ZIP entry '{raw_name}' compressed payload exceeds EOF"
                )));
            }
            let comp_slice = &data[payload_start..payload_end];

            let decoded = match method {
                0 => comp_slice.to_vec(),
                8 => {
                    let dec = DeflateDecoder::new(comp_slice);
                    let mut buf = Vec::with_capacity(uncomp_size.min(1024 * 1024));
                    dec.take(MAX_DECOMPRESSED_BYTES + 1)
                        .read_to_end(&mut buf)
                        .map_err(|e| {
                            CliError::Format(format!(
                                "failed to deflate ZIP entry '{raw_name}': {e}"
                            ))
                        })?;
                    if buf.len() as u64 > MAX_DECOMPRESSED_BYTES {
                        return Err(CliError::Format(format!(
                            "ZIP entry '{raw_name}' decompressed size exceeds safety limit"
                        )));
                    }
                    buf
                }
                other => {
                    return Err(CliError::Format(format!(
                        "unsupported ZIP compression method {other} for entry '{raw_name}'"
                    )));
                }
            };

            if decoded.len() != uncomp_size {
                return Err(CliError::Format(format!(
                    "ZIP entry '{raw_name}' uncompressed size mismatch (got {}, expected {uncomp_size})",
                    decoded.len()
                )));
            }
            let actual_crc = crc32fast::hash(&decoded);
            if actual_crc != expected_crc {
                return Err(CliError::Format(format!(
                    "ZIP entry '{raw_name}' CRC32 mismatch (got 0x{actual_crc:08X}, expected 0x{expected_crc:08X})"
                )));
            }

            entries.insert(raw_name, decoded);
        }

        Ok(Self { entries })
    }

    pub fn get(&self, name: &str) -> Option<&[u8]> {
        let normalized = name.trim_start_matches('/').replace('\\', "/");
        if let Some(v) = self.entries.get(&normalized) {
            return Some(v.as_slice());
        }
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(&normalized))
            .map(|(_, v)| v.as_slice())
    }
}

/// Write a standard Deflate PKZIP archive (used to generate valid OpenXML `.xlsx` templates).
pub fn encode_zip_archive(files: &[(&str, &[u8])]) -> Result<Vec<u8>> {
    struct CdRecord {
        name: Vec<u8>,
        crc: u32,
        comp_len: u32,
        uncomp_len: u32,
        lfh_offset: u32,
    }

    let mut out = Vec::new();
    let mut cd_records = Vec::with_capacity(files.len());

    // Fixed DOS timestamp: 2025-01-01 00:00:00 for deterministic output
    let dos_time: u16 = 0;
    let dos_date: u16 = ((2025 - 1980) << 9) | (1 << 5) | 1;

    for &(raw_name, content) in files {
        let clean_name = raw_name.trim_start_matches('/').replace('\\', "/");
        let name_bytes = clean_name.into_bytes();
        let crc = crc32fast::hash(content);

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(content)
            .map_err(|e| CliError::Format(format!("ZIP deflate error: {e}")))?;
        let compressed = enc
            .finish()
            .map_err(|e| CliError::Format(format!("ZIP deflate finish error: {e}")))?;

        let lfh_offset = out.len() as u32;
        let comp_len = compressed.len() as u32;
        let uncomp_len = content.len() as u32;

        // Local File Header (0x04034b50)
        out.extend_from_slice(&0x0403_4B50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed (2.0)
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&8u16.to_le_bytes()); // method = Deflate
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&comp_len.to_le_bytes());
        out.extend_from_slice(&uncomp_len.to_le_bytes());
        out.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&name_bytes);
        out.extend_from_slice(&compressed);

        cd_records.push(CdRecord {
            name: name_bytes,
            crc,
            comp_len,
            uncomp_len,
            lfh_offset,
        });
    }

    let cd_offset = out.len() as u32;
    for rec in &cd_records {
        out.extend_from_slice(&0x0201_4B50u32.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version made by
        out.extend_from_slice(&20u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&8u16.to_le_bytes()); // method = Deflate
        out.extend_from_slice(&dos_time.to_le_bytes());
        out.extend_from_slice(&dos_date.to_le_bytes());
        out.extend_from_slice(&rec.crc.to_le_bytes());
        out.extend_from_slice(&rec.comp_len.to_le_bytes());
        out.extend_from_slice(&rec.uncomp_len.to_le_bytes());
        out.extend_from_slice(&(rec.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(&0u16.to_le_bytes()); // comment len
        out.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        out.extend_from_slice(&rec.lfh_offset.to_le_bytes());
        out.extend_from_slice(&rec.name);
    }
    let cd_size = (out.len() as u32) - cd_offset;
    let count = cd_records.len() as u16;

    // End of Central Directory (0x06054b50)
    out.extend_from_slice(&0x0605_4B50u32.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk num
    out.extend_from_slice(&0u16.to_le_bytes()); // cd start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len

    Ok(out)
}

/// Convert a 16x14 `.bmp` (or `.png`/`.gif`) image file into an EtherCAT ESI `ImageData16x14`
/// uppercase hex string, matching `SSC Tool.exe -> GetImageData`.
pub fn encode_image_data_16x14(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("failed to read image '{}': {e}", path.display()),
        ))
    })?;
    let (width, height) = read_image_dimensions(&bytes).ok_or_else(|| {
        CliError::Format(format!(
            "unsupported or corrupt image header in '{}' (expected 16x14 BMP/PNG/GIF)",
            path.display()
        ))
    })?;
    if width != 16 || height != 14 {
        return Err(CliError::Validation(format!(
            "The Image size shall be 16x14 (current image size {width}x{height})"
        )));
    }
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &b in &bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02X}");
    }
    Ok(hex)
}

fn read_image_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    // BMP ('BM')
    if bytes.len() >= 26 && &bytes[0..2] == b"BM" {
        let dib_size = le_u32(bytes, 14);
        if dib_size == 12 {
            let w = le_u16(bytes, 18) as u32;
            let h = le_u16(bytes, 20) as u32;
            return Some((w, h));
        } else if dib_size >= 40 && bytes.len() >= 26 {
            let w = i32::from_le_bytes(bytes[18..22].try_into().ok()?).unsigned_abs();
            let h = i32::from_le_bytes(bytes[22..26].try_into().ok()?).unsigned_abs();
            return Some((w, h));
        }
    }
    // PNG
    if bytes.len() >= 24 && &bytes[0..8] == b"\x89PNG\r\n\x1a\n" && &bytes[12..16] == b"IHDR" {
        let w = u32::from_be_bytes(bytes[16..20].try_into().ok()?);
        let h = u32::from_be_bytes(bytes[20..24].try_into().ok()?);
        return Some((w, h));
    }
    // GIF ('GIF87a' / 'GIF89a')
    if bytes.len() >= 10 && (&bytes[0..6] == b"GIF87a" || &bytes[0..6] == b"GIF89a") {
        let w = le_u16(bytes, 6) as u32;
        let h = le_u16(bytes, 8) as u32;
        return Some((w, h));
    }
    None
}

#[inline]
fn le_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn le_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
