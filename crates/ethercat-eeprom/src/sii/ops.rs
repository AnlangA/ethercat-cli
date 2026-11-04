use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::sii::image::{
    parse_sii_image, sii_count_different_words, sii_crc8, sii_declared_size, sii_diff_words,
    sii_le16, sii_le32, sii_validate, SiiDecodedImage, WordDiff, SII_MAX_SIZE, SII_MIN_SIZE,
};
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::EcatCmd;
use ethercat_wire::transport::EthercatTransport;

const ECT_REG_EEPCFG: u16 = 0x0500;
const ECT_REG_EEPCTL: u16 = 0x0502;
const ECT_REG_EEPSTAT: u16 = 0x0502;
const ECT_REG_EEPDAT: u16 = 0x0508;

const EC_ECMD_NOP: u16 = 0x0000;
const EC_ECMD_READ: u16 = 0x0100;
const EC_ECMD_WRITE: u16 = 0x0201;
const EC_ECMD_RELOAD: u16 = 0x0400;

const EC_ESTAT_R64: u16 = 0x0040;
const EC_ESTAT_BUSY: u16 = 0x8000;
const EC_ESTAT_EMASK: u16 = 0x7800;
const EC_ESTAT_NACK: u16 = 0x2000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlaveSiiSummary {
    pub slave: u16,
    pub vendor_id: String,
    pub product_code: String,
    pub revision_number: String,
    pub serial_number: String,
    pub alias: String,
    pub name: Option<String>,
    pub size_bytes: usize,
    pub crc_ok: bool,
}

impl SlaveSiiSummary {
    pub fn from_image(slave: u16, raw: &[u8]) -> Self {
        let parsed = parse_sii_image(raw).ok();
        let name = parsed.as_ref().and_then(|p| {
            p.categories
                .general
                .as_ref()
                .and_then(|g| g.device_name.clone())
                .or_else(|| p.categories.strings.first().cloned())
        });
        let slice_or_empty = |start: usize, end: usize| -> &[u8] {
            raw.get(start..end.min(raw.len())).unwrap_or(&[])
        };
        let crc_ok = raw.len() >= 15 && sii_crc8(&raw[0..14]) == raw[14];
        Self {
            slave,
            vendor_id: format!("0x{:08X}", sii_le32(slice_or_empty(0x10, 0x14))),
            product_code: format!("0x{:08X}", sii_le32(slice_or_empty(0x14, 0x18))),
            revision_number: format!("0x{:08X}", sii_le32(slice_or_empty(0x18, 0x1C))),
            serial_number: format!("0x{:08X}", sii_le32(slice_or_empty(0x1C, 0x20))),
            alias: format!("0x{:04X}", sii_le16(slice_or_empty(0x08, 0x0A))),
            name,
            size_bytes: raw.len(),
            crc_ok,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscConfigCheck {
    pub slave: u16,
    pub esc_pdi_control: String,
    pub proposed_pdi_control: String,
    pub pdi_control_matches: bool,
    pub esc_pdi_config: String,
    pub proposed_pdi_config: String,
    pub pdi_config_matches: bool,
    pub esc_pdi_config_ext: String,
    pub matches: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiiWriteReport {
    pub slave: u16,
    pub dry_run: bool,
    pub executed: bool,
    pub current_size_bytes: usize,
    pub proposed_size_bytes: usize,
    pub differing_words: usize,
    pub written_words: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
    pub verified: bool,
    pub proposed_identity: SlaveSiiSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esc_config_check: Option<EscConfigCheck>,
    pub sample_diffs: Vec<WordDiff>,
}

fn slave_aiadr(slave: u16) -> u16 {
    (1i32 - slave as i32) as u16
}

fn claim_eeprom(bus: &mut dyn EthercatTransport, slave: u16, timeout: Duration) -> Result<bool> {
    let aiadr = slave_aiadr(slave);
    let (wkc, state_bytes) =
        bus.send_datagram(EcatCmd::Aprd, aiadr, ECT_REG_EEPCFG, vec![0u8; 2], timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "slave {slave} did not respond when reading ECT_REG_EEPCFG (0x0500)"
        )));
    }
    let access_state = u16::from_le_bytes([state_bytes[0], state_bytes[1]]);
    let was_pdi = (access_state & 0x0101) != 0;
    if was_pdi {
        let (wkc1, _) =
            bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCFG, vec![2u8], timeout)?;
        if wkc1 == 0 {
            return Err(CliError::Device(format!(
                "slave {slave} rejected EEPROM force-release from PDI"
            )));
        }
        let (wkc2, _) =
            bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCFG, vec![0u8], timeout)?;
        if wkc2 == 0 {
            // Best-effort restore to PDI after partial handover, matching esi-eeprom main.c
            let _ = bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCFG, vec![1u8], timeout);
            return Err(CliError::Device(format!(
                "slave {slave} rejected assigning EEPROM control to master"
            )));
        }
    }
    Ok(was_pdi)
}

fn release_eeprom(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    was_pdi: bool,
    timeout: Duration,
) -> Result<()> {
    if !was_pdi {
        return Ok(());
    }
    let aiadr = slave_aiadr(slave);
    let (wkc, _) = bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCFG, vec![1u8], timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "could not return EEPROM control to PDI on slave {slave}"
        )));
    }
    Ok(())
}

fn eeprom_wait_not_busy(
    bus: &mut dyn EthercatTransport,
    aiadr: u16,
    timeout: Duration,
) -> Result<u16> {
    let start = Instant::now();
    let deadline = start
        .checked_add(timeout)
        .unwrap_or_else(|| start + Duration::from_secs(3600));
    let mut first = true;
    loop {
        if !first {
            std::thread::sleep(Duration::from_micros(200));
        }
        first = false;
        let step_timeout = timeout
            .min(deadline.saturating_duration_since(Instant::now()))
            .max(Duration::from_millis(1));
        let (wkc, buf) = bus.send_datagram(
            EcatCmd::Aprd,
            aiadr,
            ECT_REG_EEPSTAT,
            vec![0u8; 2],
            step_timeout,
        )?;
        if wkc > 0 {
            let estat = u16::from_le_bytes([buf[0], buf[1]]);
            if (estat & EC_ESTAT_BUSY) == 0 {
                return Ok(estat);
            }
        }
        if Instant::now() >= deadline {
            return Err(CliError::Device(
                "timeout waiting for SII EEPROM busy flag to clear".into(),
            ));
        }
    }
}

fn read_eeprom_word_ap(
    bus: &mut dyn EthercatTransport,
    aiadr: u16,
    word_addr: u32,
    timeout: Duration,
) -> Result<(u64, bool)> {
    let estat = eeprom_wait_not_busy(bus, aiadr, timeout)?;
    if (estat & EC_ESTAT_EMASK) != 0 {
        let _ = bus.send_datagram(
            EcatCmd::Apwr,
            aiadr,
            ECT_REG_EEPCTL,
            EC_ECMD_NOP.to_le_bytes().to_vec(),
            timeout,
        );
    }

    let mut nack_cnt = 0;
    loop {
        let mut req = Vec::with_capacity(6);
        req.extend_from_slice(&EC_ECMD_READ.to_le_bytes());
        req.extend_from_slice(&word_addr.to_le_bytes());

        let (wkc, _) = bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCTL, req, timeout)?;
        if wkc == 0 {
            return Err(CliError::Device(format!(
                "EEPROM read command failed at word 0x{word_addr:06x} (WKC=0)"
            )));
        }
        let estat2 = eeprom_wait_not_busy(bus, aiadr, timeout)?;
        if (estat2 & EC_ESTAT_NACK) != 0 {
            nack_cnt += 1;
            if nack_cnt >= 3 {
                return Err(CliError::Device(format!(
                    "EEPROM NACK persisted at word 0x{word_addr:06x}"
                )));
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        let r64 = (estat2 & EC_ESTAT_R64) != 0;
        let read_len = if r64 { 8 } else { 4 };
        let (wkc_d, data) = bus.send_datagram(
            EcatCmd::Aprd,
            aiadr,
            ECT_REG_EEPDAT,
            vec![0u8; read_len],
            timeout,
        )?;
        if wkc_d == 0 {
            return Err(CliError::Device(format!(
                "failed reading ECT_REG_EEPDAT at word 0x{word_addr:06x}"
            )));
        }
        let mut padded = [0u8; 8];
        padded[..read_len].copy_from_slice(&data[..read_len]);
        return Ok((u64::from_le_bytes(padded), r64));
    }
}

fn write_eeprom_word_ap(
    bus: &mut dyn EthercatTransport,
    aiadr: u16,
    word_addr: u32,
    word: u16,
    timeout: Duration,
) -> Result<()> {
    let estat = eeprom_wait_not_busy(bus, aiadr, timeout)?;
    if (estat & EC_ESTAT_EMASK) != 0 {
        let _ = bus.send_datagram(
            EcatCmd::Apwr,
            aiadr,
            ECT_REG_EEPCTL,
            EC_ECMD_NOP.to_le_bytes().to_vec(),
            timeout,
        );
    }

    let mut nack_cnt = 0;
    loop {
        let (wkc_d, _) = bus.send_datagram(
            EcatCmd::Apwr,
            aiadr,
            ECT_REG_EEPDAT,
            word.to_le_bytes().to_vec(),
            timeout,
        )?;
        if wkc_d == 0 {
            return Err(CliError::Device(format!(
                "EEPROM write data failed at word 0x{word_addr:06x}"
            )));
        }

        let mut req = Vec::with_capacity(6);
        req.extend_from_slice(&EC_ECMD_WRITE.to_le_bytes());
        req.extend_from_slice(&word_addr.to_le_bytes());
        let (wkc_c, _) = bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCTL, req, timeout)?;
        if wkc_c == 0 {
            return Err(CliError::Device(format!(
                "EEPROM write command failed at word 0x{word_addr:06x}"
            )));
        }

        let estat2 = eeprom_wait_not_busy(bus, aiadr, timeout)?;
        if (estat2 & EC_ESTAT_NACK) != 0 {
            nack_cnt += 1;
            if nack_cnt >= 3 {
                return Err(CliError::Device(format!(
                    "EEPROM write NACK at word 0x{word_addr:06x}"
                )));
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        return Ok(());
    }
}

fn reload_eeprom_ap(bus: &mut dyn EthercatTransport, aiadr: u16, timeout: Duration) -> Result<()> {
    let estat = eeprom_wait_not_busy(bus, aiadr, timeout)?;
    if (estat & EC_ESTAT_EMASK) != 0 {
        let _ = bus.send_datagram(
            EcatCmd::Apwr,
            aiadr,
            ECT_REG_EEPCTL,
            EC_ECMD_NOP.to_le_bytes().to_vec(),
            timeout,
        );
    }
    let mut req = Vec::with_capacity(6);
    req.extend_from_slice(&EC_ECMD_RELOAD.to_le_bytes());
    req.extend_from_slice(&0u32.to_le_bytes());
    let (wkc, _) = bus.send_datagram(EcatCmd::Apwr, aiadr, ECT_REG_EEPCTL, req, timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(
            "EEPROM RELOAD command returned WKC=0".into(),
        ));
    }
    let st = eeprom_wait_not_busy(bus, aiadr, timeout)?;
    if (st & EC_ESTAT_EMASK) != 0 {
        return Err(CliError::Device(format!(
            "EEPROM RELOAD reported status error 0x{st:04x}"
        )));
    }
    Ok(())
}

fn read_claimed_bytes(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    start_byte: usize,
    length: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let aiadr = slave_aiadr(slave);
    let mut out = vec![0u8; length];
    let mut offset = 0usize;
    while offset < length {
        let word_addr = ((start_byte + offset) >> 1) as u32;
        let (val, r64) = read_eeprom_word_ap(bus, aiadr, word_addr, timeout)?;
        let chunk = if r64 { 8usize } else { 4usize };
        let copy_count = (length - offset).min(chunk);
        for i in 0..copy_count {
            out[offset + i] = ((val >> (8 * i)) & 0xFF) as u8;
        }
        offset += copy_count;
    }
    Ok(out)
}

fn read_device_sii_for_backup(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    fallback_len: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let was_pdi = claim_eeprom(bus, slave, timeout)?;
    let read_res = (|| -> Result<Vec<u8>> {
        let header = read_claimed_bytes(bus, slave, 0, SII_MIN_SIZE, timeout)?;
        let declared = sii_declared_size(&header);
        let target_len = if (SII_MIN_SIZE..=SII_MAX_SIZE).contains(&declared) && (declared & 1) == 0
        {
            declared
        } else {
            // Allow backing up & programming factory-blank (`0xFF`) or corrupt-header EEPROMs
            fallback_len.clamp(SII_MIN_SIZE, SII_MAX_SIZE)
        };
        let mut full = Vec::with_capacity(target_len);
        full.extend_from_slice(&header);
        if target_len > SII_MIN_SIZE {
            let tail =
                read_claimed_bytes(bus, slave, SII_MIN_SIZE, target_len - SII_MIN_SIZE, timeout)?;
            full.extend_from_slice(&tail);
        }
        Ok(full)
    })();
    let _ = release_eeprom(bus, slave, was_pdi, timeout);
    read_res
}

/// Read the complete SII EEPROM binary image of `slave` (1-based), automatically sizing from byte 0x7C
/// and guaranteeing restoration of PDI EEPROM ownership.
pub fn read_device_sii_image(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let was_pdi = claim_eeprom(bus, slave, timeout)?;
    let read_res = (|| -> Result<Vec<u8>> {
        let header = read_claimed_bytes(bus, slave, 0, SII_MIN_SIZE, timeout)?;
        let declared = sii_declared_size(&header);
        if !(SII_MIN_SIZE..=SII_MAX_SIZE).contains(&declared) || (declared & 1) != 0 {
            return Err(CliError::Device(format!(
                "slave {slave} EEPROM declares invalid size {declared} bytes at 0x7c"
            )));
        }
        let mut full = Vec::with_capacity(declared);
        full.extend_from_slice(&header);
        if declared > SII_MIN_SIZE {
            let tail =
                read_claimed_bytes(bus, slave, SII_MIN_SIZE, declared - SII_MIN_SIZE, timeout)?;
            full.extend_from_slice(&tail);
        }
        Ok(full)
    })();

    let release_res = release_eeprom(bus, slave, was_pdi, timeout);
    let data = read_res?;
    release_res?;
    Ok(data)
}

/// Read an explicit byte range `[offset .. offset + length)` from slave SII EEPROM (read-only).
pub fn read_device_sii_slice(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    offset: usize,
    length: usize,
    timeout: Duration,
) -> Result<Vec<u8>> {
    if slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    if (offset & 1) != 0 {
        return Err(CliError::Usage(
            "SII byte offset must be even (16-bit word aligned)".into(),
        ));
    }
    if length == 0 || length > SII_MAX_SIZE {
        return Err(CliError::Usage(format!(
            "SII read length must be 1..={SII_MAX_SIZE} bytes"
        )));
    }
    if offset
        .checked_add(length)
        .is_none_or(|end| end > SII_MAX_SIZE)
    {
        return Err(CliError::Usage(format!(
            "SII slice [0x{offset:x}..0x{offset:x}+{length}) exceeds SII_MAX_SIZE ({SII_MAX_SIZE} bytes)"
        )));
    }
    let was_pdi = claim_eeprom(bus, slave, timeout)?;
    let res = read_claimed_bytes(bus, slave, offset, length, timeout);
    let rel = release_eeprom(bus, slave, was_pdi, timeout);
    let data = res?;
    rel?;
    Ok(data)
}

pub fn inspect_sii_data(raw: &[u8]) -> Result<SiiDecodedImage> {
    parse_sii_image(raw)
}

/// Issue ESC EEPROM `RELOAD` (`0x0502` command `0x0400`) on `slave` (1-based), claiming
/// EEPROM control from PDI if needed and restoring PDI ownership afterward.
pub fn reload_device_sii(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    timeout: Duration,
) -> Result<()> {
    if slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let was_pdi = claim_eeprom(bus, slave, timeout)?;
    let aiadr = slave_aiadr(slave);
    let rel_cmd = reload_eeprom_ap(bus, aiadr, timeout);
    let release_res = release_eeprom(bus, slave, was_pdi, timeout);
    rel_cmd?;
    release_res?;
    Ok(())
}

/// Compare active ESC PDI Control (`0x0140..0x0142`) and PDI Configuration (`0x0150..0x0154`)
/// registers on `slave` against `proposed_sii[0..4]` (matching Beckhoff `EEPROM Programmer.exe`
/// `CheckEscConfigData`).
pub fn check_slave_esc_config(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    proposed_sii: &[u8],
    timeout: Duration,
) -> Result<EscConfigCheck> {
    if slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    if proposed_sii.len() < 8 {
        return Err(CliError::Format(
            "proposed SII image too short to inspect PDI config words".into(),
        ));
    }
    let aiadr = slave_aiadr(slave);
    let (wkc_ctrl, ctrl_bytes) =
        bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0140, vec![0u8; 2], timeout)?;
    if wkc_ctrl == 0 {
        return Err(CliError::Device(format!(
            "slave {slave} did not respond when reading ESC PDI Control (0x0140)"
        )));
    }
    let (wkc_cfg, cfg_bytes) =
        bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0150, vec![0u8; 4], timeout)?;
    if wkc_cfg == 0 {
        return Err(CliError::Device(format!(
            "slave {slave} did not respond when reading ESC PDI Configuration (0x0150)"
        )));
    }

    let esc_pdi_ctrl = sii_le16(&ctrl_bytes[0..2]);
    let esc_pdi_cfg = sii_le16(&cfg_bytes[0..2]);
    let esc_pdi_cfg_ext = sii_le16(&cfg_bytes[2..4]);
    let prop_pdi_ctrl = sii_le16(&proposed_sii[0..2]);
    let prop_pdi_cfg = sii_le16(&proposed_sii[2..4]);

    let pdi_control_matches = esc_pdi_ctrl == prop_pdi_ctrl;
    let pdi_config_matches = esc_pdi_cfg == prop_pdi_cfg;
    let matches = pdi_control_matches && pdi_config_matches;
    let warning = if matches {
        None
    } else {
        Some(format!(
            "ESC active PDI config (0x0140=0x{esc_pdi_ctrl:04X}, 0x0150=0x{esc_pdi_cfg:04X}) differs from proposed SII ConfigData (word0=0x{prop_pdi_ctrl:04X}, word1=0x{prop_pdi_cfg:04X})"
        ))
    };

    Ok(EscConfigCheck {
        slave,
        esc_pdi_control: format!("0x{esc_pdi_ctrl:04X}"),
        proposed_pdi_control: format!("0x{prop_pdi_ctrl:04X}"),
        pdi_control_matches,
        esc_pdi_config: format!("0x{esc_pdi_cfg:04X}"),
        proposed_pdi_config: format!("0x{prop_pdi_cfg:04X}"),
        pdi_config_matches,
        esc_pdi_config_ext: format!("0x{esc_pdi_cfg_ext:04X}"),
        matches,
        warning,
    })
}

#[derive(Debug, Clone)]
pub struct GuardedSiiWriteOptions<'a> {
    pub slave: u16,
    pub proposed: &'a [u8],
    pub execute: bool,
    pub backup_path: Option<&'a Path>,
    pub confirm_token: Option<&'a str>,
    pub reload: bool,
    pub timeout: Duration,
}

/// Guarded SII EEPROM write implementing all safety invariants of `esi-eeprom`:
/// 1. Validates proposed image (size, alignment, 0x7c capacity, CRC-8).
/// 2. Reads current device EEPROM (read-only) and computes word differences.
/// 3. If `execute == false`, stops immediately (zero EEPROM write commands sent).
/// 4. Requires non-existing `--backup` path AND exact `--confirm WRITE-SLAVE-<n>` token.
/// 5. Saves full backup before writing any word.
/// 6. Writes only differing 16-bit words: body words (`size..16`) first, header words (`0..16`) last.
/// 7. Releases PDI control and reads back full EEPROM to verify byte-for-byte match.
pub fn write_device_sii_guarded(
    bus: &mut dyn EthercatTransport,
    opts: &GuardedSiiWriteOptions<'_>,
) -> Result<SiiWriteReport> {
    write_device_sii_guarded_checked(bus, opts, false)
}

/// Same as [`write_device_sii_guarded`], with optional active ESC PDI Control/Configuration
/// verification (`0x0140`/`0x0150` vs `proposed[0..4]`) before executing writes.
pub fn write_device_sii_guarded_checked(
    bus: &mut dyn EthercatTransport,
    opts: &GuardedSiiWriteOptions<'_>,
    check_esc_config: bool,
) -> Result<SiiWriteReport> {
    if opts.slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    sii_validate(opts.proposed)?;

    let esc_config_check = if check_esc_config {
        Some(check_slave_esc_config(
            bus,
            opts.slave,
            opts.proposed,
            opts.timeout,
        )?)
    } else {
        None
    };

    let current = read_device_sii_for_backup(bus, opts.slave, opts.proposed.len(), opts.timeout)?;
    let differences = sii_count_different_words(&current, opts.proposed);
    let (_, sample_diffs) = sii_diff_words(&current, opts.proposed, 32);
    let proposed_identity = SlaveSiiSummary::from_image(opts.slave, opts.proposed);

    if !opts.execute {
        return Ok(SiiWriteReport {
            slave: opts.slave,
            dry_run: true,
            executed: false,
            current_size_bytes: current.len(),
            proposed_size_bytes: opts.proposed.len(),
            differing_words: differences,
            written_words: 0,
            backup_path: None,
            verified: false,
            proposed_identity,
            esc_config_check,
            sample_diffs,
        });
    }

    if let Some(ref chk) = esc_config_check {
        if !chk.matches {
            return Err(CliError::Mismatch(format!(
                "{}. Refusing to overwrite slave {} EEPROM with --check-esc-config enabled; no data was written.",
                chk.warning
                    .as_deref()
                    .unwrap_or("ESC PDI configuration mismatch"),
                opts.slave
            )));
        }
    }

    let expected_token = format!("WRITE-SLAVE-{}", opts.slave);
    let backup = opts.backup_path.ok_or_else(|| {
        CliError::WriteLocked(format!(
            "--backup <new-file.bin> and exact --confirm {expected_token} are required. No data was written."
        ))
    })?;
    let confirm = opts.confirm_token.unwrap_or("");
    if confirm != expected_token {
        return Err(CliError::WriteLocked(format!(
            "confirmation token mismatch: expected '{expected_token}', got '{confirm}'. No data was written."
        )));
    }
    if backup.exists() {
        return Err(CliError::WriteLocked(format!(
            "backup file already exists: '{}'. Refusing to overwrite backup; no data was written.",
            backup.display()
        )));
    }
    std::fs::write(backup, &current).map_err(|e| {
        CliError::WriteLocked(format!(
            "could not create backup '{}': {e}. No data was written.",
            backup.display()
        ))
    })?;

    if differences == 0 && current.len() == opts.proposed.len() {
        if opts.reload {
            reload_device_sii(bus, opts.slave, opts.timeout)?;
        }
        return Ok(SiiWriteReport {
            slave: opts.slave,
            dry_run: false,
            executed: true,
            current_size_bytes: current.len(),
            proposed_size_bytes: opts.proposed.len(),
            differing_words: 0,
            written_words: 0,
            backup_path: Some(backup.display().to_string()),
            verified: true,
            proposed_identity,
            esc_config_check,
            sample_diffs,
        });
    }

    let was_pdi = claim_eeprom(bus, opts.slave, opts.timeout)?;
    let aiadr = slave_aiadr(opts.slave);
    let mut written_words = 0usize;

    let write_res = (|| -> Result<()> {
        // 1. Write body words from end down to byte 16 first
        let mut pos = opts.proposed.len();
        while pos > 16 {
            let offset = pos - 2;
            let same = offset + 1 < current.len()
                && current[offset] == opts.proposed[offset]
                && current[offset + 1] == opts.proposed[offset + 1];
            if !same {
                let word = sii_le16(&opts.proposed[offset..offset + 2]);
                write_eeprom_word_ap(bus, aiadr, (offset >> 1) as u32, word, opts.timeout)?;
                written_words += 1;
            }
            pos -= 2;
        }
        // 2. Write configuration header words (bytes 0..16) last
        let mut hdr_off = 0usize;
        while hdr_off < 16 {
            let same = hdr_off + 1 < current.len()
                && current[hdr_off] == opts.proposed[hdr_off]
                && current[hdr_off + 1] == opts.proposed[hdr_off + 1];
            if !same {
                let word = sii_le16(&opts.proposed[hdr_off..hdr_off + 2]);
                write_eeprom_word_ap(bus, aiadr, (hdr_off >> 1) as u32, word, opts.timeout)?;
                written_words += 1;
            }
            hdr_off += 2;
        }
        if opts.reload {
            reload_eeprom_ap(bus, aiadr, opts.timeout)?;
        }
        Ok(())
    })();

    let release_res = release_eeprom(bus, opts.slave, was_pdi, opts.timeout);
    if let Err(e) = write_res {
        return Err(CliError::Device(format!(
            "EEPROM write failed after {written_words} changed word(s) ({e}). Backup preserved at '{}'.",
            backup.display()
        )));
    }
    release_res?;

    let verified_img = read_device_sii_image(bus, opts.slave, opts.timeout)?;
    if verified_img != opts.proposed {
        return Err(CliError::Mismatch(format!(
            "POST-WRITE VERIFY FAILED on slave {}. Backup preserved at '{}'.",
            opts.slave,
            backup.display()
        )));
    }

    Ok(SiiWriteReport {
        slave: opts.slave,
        dry_run: false,
        executed: true,
        current_size_bytes: current.len(),
        proposed_size_bytes: opts.proposed.len(),
        differing_words: differences,
        written_words,
        backup_path: Some(backup.display().to_string()),
        verified: true,
        proposed_identity,
        esc_config_check,
        sample_diffs,
    })
}
