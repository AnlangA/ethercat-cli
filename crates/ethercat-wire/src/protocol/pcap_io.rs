use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::types::parse_hex_bytes;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameInputKind {
    /// Automatically detect format from file magic/BOM/extension (.pcap, .pcapng, PktMon .txt, hex text, or raw .bin).
    Auto,
    /// Raw binary frame bytes (.bin).
    Bin,
    /// Hexadecimal text dump (plain hex or offset-prefixed lines).
    Hex,
    /// Standard libpcap capture file (.pcap, microsecond or nanosecond magic).
    Pcap,
    /// Wireshark / IETF next-generation capture file (.pcapng, LE or BE, multi-section).
    Pcapng,
    /// Microsoft-Windows-PktMon text log containing `0x0000: ffff ...` packet dumps.
    Pktmon,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacketRecord {
    pub index: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub data: Vec<u8>,
}

/// Stream packet records from `path`, invoking `on_packet` for each packet (`Ok(true)` = continue,
/// `Ok(false)` = stop early). Returns the resolved `FrameInputKind`.
///
/// Standard `.pcap` and `.pcapng` files are streamed incrementally from disk via `BufReader<File>`
/// so `--limit` stops immediately without reading multi-gigabyte captures into memory.
pub fn for_each_frame_in_file<F>(
    path: &Path,
    kind: FrameInputKind,
    mut on_packet: F,
) -> Result<FrameInputKind>
where
    F: FnMut(CapturedPacketRecord) -> Result<bool>,
{
    let mut file = File::open(path)
        .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
    let mut peek = [0u8; 4096];
    let peek_len = file
        .read(&mut peek)
        .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
    if peek_len == 0 {
        return Err(CliError::Format(format!(
            "file '{}' is empty",
            path.display()
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| CliError::Format(format!("cannot seek '{}': {e}", path.display())))?;

    let is_compressed_archive = (peek_len >= 2 && peek[0..2] == [0x1F, 0x8B])
        || (peek_len >= 4 && peek[0..4] == [0x28, 0xB5, 0x2F, 0xFD])
        || (peek_len >= 6 && peek[0..6] == [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
    let has_compressed_ext = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| {
            matches!(
                ext.to_ascii_lowercase().as_str(),
                "gz" | "tgz" | "zst" | "xz"
            )
        });
    if is_compressed_archive
        && (matches!(kind, FrameInputKind::Pcap | FrameInputKind::Pcapng)
            || (kind == FrameInputKind::Auto && has_compressed_ext))
    {
        return Err(CliError::Format(format!(
            "compressed capture archive '{}' (.gz/.zst/.xz) is not supported directly; decompress to .pcap or .pcapng first",
            path.display()
        )));
    }

    let resolved = match kind {
        FrameInputKind::Auto => detect_input_kind(path, &peek[..peek_len]),
        other => other,
    };

    match resolved {
        FrameInputKind::Pcap => {
            stream_pcap_reader(BufReader::new(file), &mut on_packet)?;
            Ok(FrameInputKind::Pcap)
        }
        FrameInputKind::Pcapng => {
            stream_pcapng_reader(BufReader::new(file), &mut on_packet)?;
            Ok(FrameInputKind::Pcapng)
        }
        FrameInputKind::Pktmon => {
            let mut raw = Vec::new();
            file.read_to_end(&mut raw)
                .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
            let text = decode_text_auto_bom(&raw)?;
            stream_pktmon_or_hexdump(&text, &mut on_packet)?;
            Ok(FrameInputKind::Pktmon)
        }
        FrameInputKind::Hex => {
            let mut raw = Vec::new();
            file.read_to_end(&mut raw)
                .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
            let text = decode_text_auto_bom(&raw)?;
            if text
                .lines()
                .any(|l| l.trim_start().starts_with("0x") && l.contains(':'))
            {
                stream_pktmon_or_hexdump(&text, &mut on_packet)?;
            } else {
                let bytes = parse_hex_bytes(&text)?;
                let _ = on_packet(CapturedPacketRecord {
                    index: 0,
                    timestamp: None,
                    note: None,
                    data: bytes,
                })?;
            }
            Ok(FrameInputKind::Hex)
        }
        FrameInputKind::Bin | FrameInputKind::Auto => {
            let mut raw = Vec::new();
            file.read_to_end(&mut raw)
                .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
            let _ = on_packet(CapturedPacketRecord {
                index: 0,
                timestamp: None,
                note: None,
                data: raw,
            })?;
            Ok(FrameInputKind::Bin)
        }
    }
}
pub fn load_frames_from_file(
    path: &Path,
    kind: FrameInputKind,
    limit: usize,
) -> Result<Vec<CapturedPacketRecord>> {
    let max_items = if limit == 0 { usize::MAX } else { limit };
    let mut out = Vec::new();
    for_each_frame_in_file(path, kind, |rec| {
        out.push(rec);
        Ok(out.len() < max_items)
    })?;
    Ok(out)
}

fn detect_input_kind(path: &Path, raw: &[u8]) -> FrameInputKind {
    if raw.len() >= 12 && raw[0..4] == [0x0A, 0x0D, 0x0D, 0x0A] {
        let bom_le = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
        if matches!(bom_le, 0x1A2B_3C4D | 0x4D3C_2B1A) {
            return FrameInputKind::Pcapng;
        }
    }
    if raw.len() >= 4 {
        let magic_le = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
        if matches!(
            magic_le,
            0xA1B2_C3D4 | 0xD4C3_B2A1 | 0xA1B2_3C4D | 0x4D3C_B2A1
        ) {
            return FrameInputKind::Pcap;
        }
    }
    // UTF-16LE BOM or UTF-16BE BOM -> text log (such as Windows PktMon .txt)
    if raw.starts_with(&[0xFF, 0xFE]) || raw.starts_with(&[0xFE, 0xFF]) {
        return FrameInputKind::Pktmon;
    }
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        match ext.to_ascii_lowercase().as_str() {
            "pcap" => return FrameInputKind::Pcap,
            "pcapng" | "ntar" => return FrameInputKind::Pcapng,
            "txt" | "log" => {
                if let Ok(text) = std::str::from_utf8(&raw[..raw.len().min(4096)]) {
                    if text.contains("0x0000:") {
                        return FrameInputKind::Pktmon;
                    }
                    return FrameInputKind::Hex;
                }
            }
            "hex" => return FrameInputKind::Hex,
            _ => {}
        }
    }
    if let Ok(text) = std::str::from_utf8(&raw[..raw.len().min(4096)]) {
        if text.contains("0x0000:") {
            return FrameInputKind::Pktmon;
        }
        if text.chars().all(|c| {
            c.is_ascii_hexdigit() || c.is_ascii_whitespace() || matches!(c, 'x' | 'X' | ':' | '-')
        }) {
            return FrameInputKind::Hex;
        }
    }
    FrameInputKind::Bin
}

fn decode_text_auto_bom(raw: &[u8]) -> Result<String> {
    if let Some(body) = raw.strip_prefix(&[0xFF, 0xFE]) {
        if !body.len().is_multiple_of(2) {
            return Err(CliError::Format(
                "truncated UTF-16LE text (odd byte length)".into(),
            ));
        }
        let u16s: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        return Ok(String::from_utf16_lossy(&u16s));
    }
    if let Some(body) = raw.strip_prefix(&[0xFE, 0xFF]) {
        if !body.len().is_multiple_of(2) {
            return Err(CliError::Format(
                "truncated UTF-16BE text (odd byte length)".into(),
            ));
        }
        let u16s: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_be_bytes(c))
            .collect();
        return Ok(String::from_utf16_lossy(&u16s));
    }
    let body = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw);
    std::str::from_utf8(body)
        .map(|s| s.to_string())
        .map_err(|e| CliError::Format(format!("invalid UTF-8 text: {e}")))
}

fn read_exact_or_eof<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

fn stream_pcap_reader<R, F>(mut reader: R, on_packet: &mut F) -> Result<()>
where
    R: Read,
    F: FnMut(CapturedPacketRecord) -> Result<bool>,
{
    let mut ghdr = [0u8; 24];
    let ghdr_read = read_exact_or_eof(&mut reader, &mut ghdr)
        .map_err(|e| CliError::Format(format!("pcap read error: {e}")))?;
    if ghdr_read < 24 {
        return Err(CliError::Format(
            "pcap file shorter than 24-byte global header".into(),
        ));
    }
    let magic_le = u32::from_le_bytes([ghdr[0], ghdr[1], ghdr[2], ghdr[3]]);
    let (little_endian, nano) = match magic_le {
        0xA1B2_C3D4 => (true, false),
        0xA1B2_3C4D => (true, true),
        0xD4C3_B2A1 => (false, false),
        0x4D3C_B2A1 => (false, true),
        _ => {
            return Err(CliError::Format(format!(
                "unsupported pcap magic 0x{magic_le:08x}"
            )));
        }
    };
    let read_u32 = |slice: &[u8]| -> u32 {
        if little_endian {
            u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
        } else {
            u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
        }
    };
    let network = read_u32(&ghdr[20..24]);
    if network != 1 {
        return Err(CliError::Format(format!(
            "unsupported pcap link-layer type {network} (expected LINKTYPE_ETHERNET = 1)"
        )));
    }

    let mut index = 0usize;
    let mut phdr = [0u8; 16];
    loop {
        let n = read_exact_or_eof(&mut reader, &mut phdr)
            .map_err(|e| CliError::Format(format!("pcap packet header read error: {e}")))?;
        if n == 0 {
            break;
        }
        if n < 16 {
            return Err(CliError::Format(format!(
                "truncated pcap packet header at packet #{index} (got {n}/16 bytes)"
            )));
        }
        let ts_sec = read_u32(&phdr[0..4]);
        let ts_sub = read_u32(&phdr[4..8]);
        let incl_len = read_u32(&phdr[8..12]) as usize;
        if incl_len > 16 * 1024 * 1024 {
            return Err(CliError::Format(format!(
                "corrupt pcap packet #{index}: incl_len={incl_len} exceeds 16 MiB"
            )));
        }
        let mut data = vec![0u8; incl_len];
        let body_read = read_exact_or_eof(&mut reader, &mut data)
            .map_err(|e| CliError::Format(format!("pcap packet body read error: {e}")))?;
        if body_read < incl_len {
            return Err(CliError::Format(format!(
                "truncated pcap packet #{index} payload (expected {incl_len} bytes, got {body_read})"
            )));
        }
        let ts = if nano {
            format!("{ts_sec}.{ts_sub:09}")
        } else {
            format!("{ts_sec}.{ts_sub:06}")
        };
        let keep_going = on_packet(CapturedPacketRecord {
            index,
            timestamp: Some(ts),
            note: None,
            data,
        })?;
        index += 1;
        if !keep_going {
            break;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
enum PcapngTsResol {
    DecimalPow10(u8),
    BinaryPow2(u8),
}

impl Default for PcapngTsResol {
    fn default() -> Self {
        Self::DecimalPow10(6)
    }
}

impl PcapngTsResol {
    fn from_option_byte(b: u8) -> Self {
        if (b & 0x80) == 0 {
            Self::DecimalPow10(b & 0x7F)
        } else {
            Self::BinaryPow2(b & 0x7F)
        }
    }

    fn format_timestamp(self, ts_high: u32, ts_low: u32) -> String {
        let raw = ((ts_high as u128) << 32) | (ts_low as u128);
        match self {
            Self::DecimalPow10(0) => format!("{raw}.000000"),
            Self::DecimalPow10(exp) if exp <= 18 => {
                let scale = 10u128.pow(exp as u32);
                let secs = raw / scale;
                let frac = raw % scale;
                let width = exp as usize;
                format!("{secs}.{frac:0width$}")
            }
            Self::DecimalPow10(exp) => {
                // Unusually high exponent: scale down to nanoseconds
                let shift = (exp - 9).min(27) as u32;
                let ns_total = raw / 10u128.pow(shift);
                let secs = ns_total / 1_000_000_000;
                let frac = ns_total % 1_000_000_000;
                format!("{secs}.{frac:09}")
            }
            Self::BinaryPow2(0) => format!("{raw}.000000"),
            Self::BinaryPow2(exp) if exp <= 64 => {
                let secs = raw >> exp;
                let mask = (1u128 << exp) - 1;
                let frac_ticks = raw & mask;
                let ns = (frac_ticks * 1_000_000_000) >> exp;
                format!("{secs}.{ns:09}")
            }
            Self::BinaryPow2(_) => format!("{raw}.000000"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PcapngIface {
    link_type: u16,
    snap_len: u32,
    ts_resol: PcapngTsResol,
}

fn rd_u16(slice: &[u8], le: bool) -> u16 {
    if le {
        u16::from_le_bytes([slice[0], slice[1]])
    } else {
        u16::from_be_bytes([slice[0], slice[1]])
    }
}

fn rd_u32(slice: &[u8], le: bool) -> u32 {
    if le {
        u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
    } else {
        u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])
    }
}

fn stream_pcapng_reader<R, F>(mut reader: R, on_packet: &mut F) -> Result<()>
where
    R: Read,
    F: FnMut(CapturedPacketRecord) -> Result<bool>,
{
    const MAX_BLOCK_LEN: usize = 16 * 1024 * 1024;
    let mut seen_shb = false;
    let mut saw_ethernet_iface = false;
    let mut first_non_eth_linktype: Option<u16> = None;
    let mut le = true;
    let mut ifaces: Vec<PcapngIface> = Vec::new();
    let mut index = 0usize;
    let mut hdr = [0u8; 8];
    let mut rem: Vec<u8> = Vec::new();

    loop {
        let n = read_exact_or_eof(&mut reader, &mut hdr)
            .map_err(|e| CliError::Format(format!("pcapng block header read error: {e}")))?;
        if n == 0 {
            break;
        }
        if n < 8 {
            return Err(CliError::Format(
                "truncated pcapng block header before EOF".into(),
            ));
        }

        // Section Header Block (0x0A0D0D0A is palindrome across LE and BE!)
        if hdr[0..4] == [0x0A, 0x0D, 0x0D, 0x0A] {
            let mut bom_bytes = [0u8; 4];
            let bom_n = read_exact_or_eof(&mut reader, &mut bom_bytes)
                .map_err(|e| CliError::Format(format!("pcapng SHB magic read error: {e}")))?;
            if bom_n < 4 {
                return Err(CliError::Format(
                    "truncated pcapng Section Header Block".into(),
                ));
            }
            let bom_le = u32::from_le_bytes(bom_bytes);
            le = match bom_le {
                0x1A2B_3C4D => true,
                0x4D3C_2B1A => false,
                _ => {
                    return Err(CliError::Format(format!(
                        "invalid pcapng byte-order magic 0x{bom_le:08x}"
                    )));
                }
            };
            let total_len = rd_u32(&hdr[4..8], le) as usize;
            if !(28..=MAX_BLOCK_LEN).contains(&total_len) || !total_len.is_multiple_of(4) {
                return Err(CliError::Format(format!(
                    "invalid pcapng SHB total_length {total_len}"
                )));
            }
            let rem_len = total_len - 12;
            rem.resize(rem_len, 0);
            let rem_n = read_exact_or_eof(&mut reader, &mut rem)
                .map_err(|e| CliError::Format(format!("pcapng SHB body read error: {e}")))?;
            if rem_n < rem_len {
                return Err(CliError::Format(
                    "truncated pcapng Section Header Block body".into(),
                ));
            }
            let trailer = rd_u32(&rem[rem_len - 4..rem_len], le) as usize;
            if trailer != total_len {
                return Err(CliError::Format(format!(
                    "pcapng SHB trailing length mismatch ({trailer} != {total_len})"
                )));
            }
            seen_shb = true;
            ifaces.clear();
            continue;
        }

        if !seen_shb {
            return Err(CliError::Format(
                "pcapng file does not start with a Section Header Block (0x0A0D0D0A)".into(),
            ));
        }

        let block_type = rd_u32(&hdr[0..4], le);
        let total_len = rd_u32(&hdr[4..8], le) as usize;
        if !(12..=MAX_BLOCK_LEN).contains(&total_len) || !total_len.is_multiple_of(4) {
            return Err(CliError::Format(format!(
                "corrupt pcapng block (type=0x{block_type:08x}, total_length={total_len})"
            )));
        }

        let rem_len = total_len - 8;
        rem.resize(rem_len, 0);
        let rem_n = read_exact_or_eof(&mut reader, &mut rem)
            .map_err(|e| CliError::Format(format!("pcapng block body read error: {e}")))?;
        if rem_n < rem_len {
            return Err(CliError::Format(format!(
                "truncated pcapng block (type=0x{block_type:08x}): expected {rem_len} bytes, got {rem_n}"
            )));
        }
        let trailer = rd_u32(&rem[rem_len - 4..rem_len], le) as usize;
        if trailer != total_len {
            return Err(CliError::Format(format!(
                "pcapng block (type=0x{block_type:08x}) trailing length mismatch ({trailer} != {total_len})"
            )));
        }
        let body = &rem[..rem_len - 4];

        match block_type {
            // Interface Description Block (IDB)
            0x0000_0001 => {
                if body.len() < 8 {
                    return Err(CliError::Format(
                        "pcapng IDB shorter than 8-byte header".into(),
                    ));
                }
                let link_type = rd_u16(&body[0..2], le);
                if link_type == 1 {
                    saw_ethernet_iface = true;
                } else if first_non_eth_linktype.is_none() {
                    first_non_eth_linktype = Some(link_type);
                }
                let snap_len = rd_u32(&body[4..8], le);
                let mut ts_resol = PcapngTsResol::default();
                let opts = &body[8..];
                let mut opt_off = 0usize;
                while opt_off + 4 <= opts.len() {
                    let opt_code = rd_u16(&opts[opt_off..opt_off + 2], le);
                    let opt_len = rd_u16(&opts[opt_off + 2..opt_off + 4], le) as usize;
                    opt_off += 4;
                    if opt_code == 0 {
                        break;
                    }
                    if opt_off + opt_len > opts.len() {
                        break;
                    }
                    if opt_code == 9 && opt_len >= 1 {
                        ts_resol = PcapngTsResol::from_option_byte(opts[opt_off]);
                    }
                    opt_off += (opt_len + 3) & !3;
                }
                ifaces.push(PcapngIface {
                    link_type,
                    snap_len,
                    ts_resol,
                });
            }
            // Enhanced Packet Block (EPB)
            0x0000_0006 => {
                if body.len() < 20 {
                    return Err(CliError::Format(
                        "pcapng EPB shorter than 20-byte header".into(),
                    ));
                }
                let iface_id = rd_u32(&body[0..4], le) as usize;
                let iface = ifaces.get(iface_id).copied().ok_or_else(|| {
                    CliError::Format(format!(
                        "pcapng EPB #{index} references undefined interface_id {iface_id} (have {} IDB(s))",
                        ifaces.len()
                    ))
                })?;
                let ts_high = rd_u32(&body[4..8], le);
                let ts_low = rd_u32(&body[8..12], le);
                let cap_len = rd_u32(&body[12..16], le) as usize;
                if 20 + cap_len > body.len() {
                    return Err(CliError::Format(format!(
                        "pcapng EPB #{index} cap_len ({cap_len}) exceeds block body ({})",
                        body.len() - 20
                    )));
                }
                if iface.link_type != 1 {
                    index += 1;
                    continue;
                }
                let keep_going = on_packet(CapturedPacketRecord {
                    index,
                    timestamp: Some(iface.ts_resol.format_timestamp(ts_high, ts_low)),
                    note: None,
                    data: body[20..20 + cap_len].to_vec(),
                })?;
                index += 1;
                if !keep_going {
                    return Ok(());
                }
            }
            // Simple Packet Block (SPB)
            0x0000_0003 => {
                if body.len() < 4 {
                    return Err(CliError::Format(
                        "pcapng SPB shorter than 4-byte header".into(),
                    ));
                }
                let iface = ifaces.first().copied().ok_or_else(|| {
                    CliError::Format(
                        "pcapng SPB appears before any Interface Description Block (IDB)".into(),
                    )
                })?;
                let orig_len = rd_u32(&body[0..4], le) as usize;
                let snap = if iface.snap_len > 0 {
                    iface.snap_len as usize
                } else {
                    usize::MAX
                };
                let cap_len = orig_len.min(snap).min(body.len() - 4);
                if iface.link_type != 1 {
                    index += 1;
                    continue;
                }
                let keep_going = on_packet(CapturedPacketRecord {
                    index,
                    timestamp: None,
                    note: None,
                    data: body[4..4 + cap_len].to_vec(),
                })?;
                index += 1;
                if !keep_going {
                    return Ok(());
                }
            }
            // Obsolete Packet Block (0x00000002)
            0x0000_0002 => {
                if body.len() < 20 {
                    return Err(CliError::Format(
                        "pcapng Packet Block shorter than 20-byte header".into(),
                    ));
                }
                let iface_id = rd_u16(&body[0..2], le) as usize;
                let iface = ifaces.get(iface_id).copied().ok_or_else(|| {
                    CliError::Format(format!(
                        "pcapng Packet Block #{index} references undefined interface_id {iface_id}"
                    ))
                })?;
                let ts_high = rd_u32(&body[4..8], le);
                let ts_low = rd_u32(&body[8..12], le);
                let cap_len = rd_u32(&body[12..16], le) as usize;
                if 20 + cap_len > body.len() {
                    return Err(CliError::Format(format!(
                        "pcapng Packet Block #{index} cap_len ({cap_len}) exceeds block body"
                    )));
                }
                if iface.link_type != 1 {
                    index += 1;
                    continue;
                }
                let keep_going = on_packet(CapturedPacketRecord {
                    index,
                    timestamp: Some(iface.ts_resol.format_timestamp(ts_high, ts_low)),
                    note: None,
                    data: body[20..20 + cap_len].to_vec(),
                })?;
                index += 1;
                if !keep_going {
                    return Ok(());
                }
            }
            // Metadata / statistics / name resolution / custom blocks: skip
            _ => {}
        }
    }
    if !seen_shb {
        return Err(CliError::Format(
            "pcapng file contains no Section Header Block".into(),
        ));
    }
    if !saw_ethernet_iface {
        if let Some(lt) = first_non_eth_linktype {
            return Err(CliError::Format(format!(
                "unsupported pcapng link-layer type {lt} (expected LINKTYPE_ETHERNET = 1)"
            )));
        }
    }
    Ok(())
}

fn stream_pktmon_or_hexdump<F>(text: &str, on_packet: &mut F) -> Result<()>
where
    F: FnMut(CapturedPacketRecord) -> Result<bool>,
{
    let mut index = 0usize;
    let mut current_bytes: Vec<u8> = Vec::new();
    let mut current_meta: Option<String> = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("0x") {
            if let Some((offset_hex, hex_part)) = rest.split_once(':') {
                if let Ok(off) = usize::from_str_radix(offset_hex.trim(), 16) {
                    if off == 0 && !current_bytes.is_empty() {
                        let keep = on_packet(CapturedPacketRecord {
                            index,
                            timestamp: None,
                            note: current_meta.take(),
                            data: std::mem::take(&mut current_bytes),
                        })?;
                        index += 1;
                        if !keep {
                            return Ok(());
                        }
                    }
                    // Parse hex tokens while excluding trailing ASCII column (e.g. `EC`, `dead`, `0000`)
                    if off > 0 && current_bytes.len() > off {
                        current_bytes.truncate(off);
                    }
                    let hex_body = hex_part.trim_start();
                    // Strip trailing padding + ASCII column separated by 3+ spaces
                    let hex_col = hex_body
                        .split_once("   ")
                        .map(|(lhs, _)| lhs)
                        .unwrap_or(hex_body);
                    let mut line_bytes = 0usize;
                    let mut expected_tok_len: Option<usize> = None;
                    let mut cursor = hex_col;
                    while !cursor.is_empty() {
                        let trimmed_cur = cursor.trim_start_matches([' ', '\t']);
                        let ws_gap = cursor.len() - trimmed_cur.len();
                        if trimmed_cur.is_empty() {
                            break;
                        }
                        // A 2+ space/tab gap (except the optional 8-byte midpoint split in `hexdump -C`)
                        // introduces the trailing ASCII column.
                        if line_bytes > 0
                            && ((ws_gap >= 2 && line_bytes != 8) || cursor.starts_with('\t'))
                        {
                            break;
                        }
                        let tok_end = trimmed_cur.find([' ', '\t']).unwrap_or(trimmed_cur.len());
                        let tok = &trimmed_cur[..tok_end];
                        cursor = &trimmed_cur[tok_end..];
                        if !tok.chars().all(|c| c.is_ascii_hexdigit())
                            || !tok.len().is_multiple_of(2)
                        {
                            break;
                        }
                        if let Some(exp_len) = expected_tok_len {
                            // Allow a shorter final hex word only on 4-nibble `tcpdump -x` lines (`0001 ... 02`)
                            if tok.len() != exp_len && !(exp_len == 4 && tok.len() == 2) {
                                break;
                            }
                        } else {
                            expected_tok_len = Some(tok.len());
                        }
                        if let Ok(mut b) = hex::decode(tok) {
                            line_bytes += b.len();
                            current_bytes.append(&mut b);
                        } else {
                            break;
                        }
                    }
                    continue;
                }
            }
        }
        if !current_bytes.is_empty() {
            let keep = on_packet(CapturedPacketRecord {
                index,
                timestamp: None,
                note: current_meta.take(),
                data: std::mem::take(&mut current_bytes),
            })?;
            index += 1;
            if !keep {
                return Ok(());
            }
        }
        if trimmed.contains("[Microsoft-Windows-PktMon]") {
            current_meta = Some(trimmed.to_string());
        }
    }

    if !current_bytes.is_empty() {
        let _ = on_packet(CapturedPacketRecord {
            index,
            timestamp: None,
            note: current_meta.take(),
            data: current_bytes,
        })?;
        index += 1;
    }

    if index == 0 {
        return Err(CliError::Format(
            "no packet hex blocks (`0x0000: ...`) found in text file".into(),
        ));
    }
    Ok(())
}

/// Write captured Ethernet frames to a `.pcap` or `.pcapng` file (selected by extension; defaults
/// to standard little-endian microsecond `.pcap`, `LINKTYPE_ETHERNET = 1`).
pub fn write_pcap_file(path: &Path, packets: &[(u64, Vec<u8>)]) -> Result<()> {
    if path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|ext| matches!(ext.to_ascii_lowercase().as_str(), "pcapng" | "ntar"))
    {
        return write_pcapng_file(path, packets);
    }
    let snaplen = packets
        .iter()
        .map(|(_, d)| u32::try_from(d.len()).unwrap_or(u32::MAX))
        .max()
        .unwrap_or(0)
        .max(65535);
    let mut buf = Vec::with_capacity(24 + packets.len() * 80);
    buf.extend_from_slice(&0xA1B2_C3D4u32.to_le_bytes()); // magic (microsecond LE)
    buf.extend_from_slice(&2u16.to_le_bytes()); // major
    buf.extend_from_slice(&4u16.to_le_bytes()); // minor
    buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf.extend_from_slice(&snaplen.to_le_bytes()); // snaplen
    buf.extend_from_slice(&1u32.to_le_bytes()); // network = LINKTYPE_ETHERNET (1)

    for (ts_us, data) in packets {
        let sec = (*ts_us / 1_000_000) as u32;
        let usec = (*ts_us % 1_000_000) as u32;
        let len = data.len() as u32;
        buf.extend_from_slice(&sec.to_le_bytes());
        buf.extend_from_slice(&usec.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(data);
    }

    std::fs::write(path, buf).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot write pcap '{}': {e}", path.display()),
        ))
    })
}

/// Write captured Ethernet frames (timestamps in microseconds) to a Wireshark `.pcapng` file.
pub fn write_pcapng_file(path: &Path, packets: &[(u64, Vec<u8>)]) -> Result<()> {
    let snaplen = packets
        .iter()
        .map(|(_, d)| u32::try_from(d.len()).unwrap_or(u32::MAX))
        .max()
        .unwrap_or(0)
        .max(65535);
    let mut buf = Vec::with_capacity(48 + packets.len() * 96);
    // Section Header Block (28 bytes)
    buf.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    buf.extend_from_slice(&28u32.to_le_bytes());
    buf.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // major = 1
    buf.extend_from_slice(&0u16.to_le_bytes()); // minor = 0
    buf.extend_from_slice(&(-1i64).to_le_bytes()); // section length = unspecified (-1)
    buf.extend_from_slice(&28u32.to_le_bytes());

    // Interface Description Block (20 bytes, LINKTYPE_ETHERNET = 1, default microsecond resolution)
    buf.extend_from_slice(&0x0000_0001u32.to_le_bytes());
    buf.extend_from_slice(&20u32.to_le_bytes());
    buf.extend_from_slice(&1u16.to_le_bytes()); // LINKTYPE_ETHERNET
    buf.extend_from_slice(&0u16.to_le_bytes()); // reserved
    buf.extend_from_slice(&snaplen.to_le_bytes()); // snaplen
    buf.extend_from_slice(&20u32.to_le_bytes());

    for (ts_us, data) in packets {
        let cap_len = data.len() as u32;
        let padded_len = (data.len() + 3) & !3;
        let total_len = (32 + padded_len) as u32;
        let ts_high = (*ts_us >> 32) as u32;
        let ts_low = (*ts_us & 0xFFFF_FFFF) as u32;
        buf.extend_from_slice(&0x0000_0006u32.to_le_bytes());
        buf.extend_from_slice(&total_len.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // interface_id = 0
        buf.extend_from_slice(&ts_high.to_le_bytes());
        buf.extend_from_slice(&ts_low.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(&cap_len.to_le_bytes());
        buf.extend_from_slice(data);
        buf.resize(buf.len() + (padded_len - data.len()), 0);
        buf.extend_from_slice(&total_len.to_le_bytes());
    }

    std::fs::write(path, buf).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot write pcapng '{}': {e}", path.display()),
        ))
    })
}
