use serde::{Deserialize, Serialize};

use crate::esi::{EsiDevice, EsiPdo};
use crate::sii::image::{
    encode_sii_image, parse_sii_image, sii_crc8, sii_le16, sii_spec_omits_coe_pdos,
    SiiBuildProfile, SiiBuildSpec, SiiDcOpModeSpec, SiiGeneralSpec, SiiPdoEntrySpec, SiiPdoSpec,
    SiiSyncMInput, SII_CATEGORY_OFFSET, SII_MAX_SIZE, SII_MIN_SIZE,
};
use ethercat_wire::error::{CliError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EsiCompileOptions {
    pub profile: SiiBuildProfile,
    pub eeprom_size_override: Option<usize>,
    pub ignore_eeprom_size: bool,
    pub include_unassigned_pdos: bool,
    pub alias_override: Option<u16>,
    pub serial_override: Option<u32>,
    pub revision_override: Option<u32>,
}

impl Default for EsiCompileOptions {
    fn default() -> Self {
        Self {
            profile: SiiBuildProfile::Ssc,
            eeprom_size_override: None,
            ignore_eeprom_size: false,
            include_unassigned_pdos: false,
            alias_override: None,
            serial_override: None,
            revision_override: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EsiCompiledSii {
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
    pub mode: &'static str,
    pub profile: SiiBuildProfile,
    pub declared_byte_size: usize,
    pub final_byte_size: usize,
    pub used_bytes: usize,
    pub free_bytes: usize,
    pub crc8_hex: String,
    pub strings_interned: usize,
    pub total_unique_candidate_strings: usize,
    pub strings_dropped_by_budget: usize,
}

fn measure_sii_used_bytes(data: &[u8]) -> usize {
    if data.len() < SII_CATEGORY_OFFSET {
        return data.len();
    }
    let mut pos = SII_CATEGORY_OFFSET;
    while pos + 2 <= data.len() {
        let cat = sii_le16(&data[pos..pos + 2]);
        if cat == 0xFFFF {
            return pos + 2;
        }
        if pos + 4 > data.len() {
            return data.len();
        }
        let word_len = sii_le16(&data[pos + 2..pos + 4]) as usize;
        pos = (pos + 4 + word_len * 2).min(data.len());
    }
    data.len()
}

fn map_esi_pdos(
    pdos: &[EsiPdo],
    include_unassigned: bool,
    has_coe: bool,
    profile: SiiBuildProfile,
) -> Result<Vec<SiiPdoSpec>> {
    let mut out = Vec::new();
    for p in pdos.iter().filter(|p| p.sm.is_some() || include_unassigned) {
        if p.entries.len() > u8::MAX as usize {
            if profile == SiiBuildProfile::Ssc || has_coe {
                continue;
            }
            return Err(CliError::Format(format!(
                "PDO 0x{:04X} has {} entries (exceeds SII u8 limit 255 on non-CoE Minimal profile)",
                p.index,
                p.entries.len()
            )));
        }
        if let Some(oversized) = p.entries.iter().find(|e| e.bit_len > u8::MAX as u16) {
            // ETG.2010 SII Category 50/51 stores Entry.BitLen as u8 (max 255 bits).
            // Beckhoff ET9300Utilities.Sii.PDOCategory catches the byte overflow per PDO and
            // omits that PDO from SII (e.g. non-CoE Beckhoff ATH2000-5250 with 512-bit TxPDO
            // 0x1A00 keeps its valid 16-bit RxPDO 0x1600). Under Minimal profile on non-CoE
            // devices, reject explicitly rather than silently dropping a fixed PDO.
            if profile == SiiBuildProfile::Ssc || has_coe {
                continue;
            }
            return Err(CliError::Format(format!(
                "PDO 0x{:04X} Entry 0x{:04X}:{} <BitLen> {} exceeds SII u8 limit (255) on non-CoE Minimal profile",
                p.index, oversized.index, oversized.subindex, oversized.bit_len
            )));
        }
        out.push(SiiPdoSpec {
            index: p.index,
            sync_manager: p.sm.unwrap_or(-1),
            dc_sync: match profile {
                SiiBuildProfile::Ssc => 0,
                SiiBuildProfile::Minimal => p.su,
            },
            name: p.name.clone(),
            flags: 0,
            entries: p
                .entries
                .iter()
                .map(|e| SiiPdoEntrySpec {
                    index: e.index,
                    subindex: e.subindex,
                    name: e.name.clone(),
                    data_type: e.data_type_code,
                    bit_len: e.bit_len as u8,
                    flags: 0,
                })
                .collect(),
        });
    }
    Ok(out)
}

fn count_unique_candidate_strings(spec: &SiiBuildSpec) -> usize {
    let mut unique: Vec<Vec<u8>> = Vec::new();
    let mut push_uniq = |s: &str| {
        let bytes = crate::esi::xml::encode_cp1252_latin1_trunc255(s);
        if !bytes.is_empty() && !unique.contains(&bytes) {
            unique.push(bytes);
        }
    };
    if let Some(ref g) = spec.general {
        push_uniq(&g.group_type);
        push_uniq(&g.image_name);
        push_uniq(&g.order_code);
        push_uniq(&g.device_name);
    }
    for dc in &spec.dc_modes {
        push_uniq(&dc.name);
        push_uniq(&dc.description);
    }
    if !sii_spec_omits_coe_pdos(spec) {
        for p in &spec.tx_pdos {
            push_uniq(&p.name);
            for e in &p.entries {
                push_uniq(&e.name);
            }
        }
        for p in &spec.rx_pdos {
            push_uniq(&p.name);
            for e in &p.entries {
                push_uniq(&e.name);
            }
        }
    }
    unique.len().min(255)
}

/// Compile a parsed `EsiDevice` into a validated ETG.2010 SII binary image.
pub fn compile_esi_device_to_sii(
    device: &EsiDevice,
    opts: &EsiCompileOptions,
) -> Result<EsiCompiledSii> {
    let declared_size = opts
        .eeprom_size_override
        .unwrap_or(device.eeprom.byte_size)
        .max(SII_MIN_SIZE);

    let effective_rev = opts.revision_override.unwrap_or(device.revision_number);
    let effective_serial = opts.serial_override.unwrap_or(device.serial_number);

    // Pre-encoded <Eeprom><Data> mode when <ConfigData> is absent
    if device.eeprom.config_data.is_none() {
        if let Some(ref raw_blob) = device.eeprom.raw_data {
            if raw_blob.len() < SII_MIN_SIZE {
                return Err(CliError::Format(format!(
                    "ESI <Eeprom><Data> on device '{}' is only {} bytes (< 128 bytes)",
                    device.order_code,
                    raw_blob.len()
                )));
            }
            let target_len = if opts.ignore_eeprom_size {
                raw_blob
                    .len()
                    .max(declared_size)
                    .max(SII_MIN_SIZE)
                    .next_multiple_of(128)
            } else {
                let aligned = declared_size.next_multiple_of(128);
                if raw_blob.len() > aligned {
                    return Err(CliError::Format(format!(
                        "ESI <Eeprom><Data> ({} bytes) exceeds declared EEPROM size ({aligned} bytes)",
                        raw_blob.len()
                    )));
                }
                aligned
            };
            if target_len > SII_MAX_SIZE {
                return Err(CliError::Format(format!(
                    "target SII size ({target_len} bytes) exceeds SII_MAX_SIZE ({SII_MAX_SIZE} bytes)"
                )));
            }

            let mut buf = raw_blob.clone();
            if buf.len() < target_len {
                buf.resize(target_len, 0xFF);
            }
            if let Some(alias) = opts.alias_override {
                buf[0x08..0x0A].copy_from_slice(&alias.to_le_bytes());
            }
            if device.vendor_id != 0 {
                buf[0x10..0x14].copy_from_slice(&device.vendor_id.to_le_bytes());
            }
            if device.product_code != 0 {
                buf[0x14..0x18].copy_from_slice(&device.product_code.to_le_bytes());
            }
            if opts.revision_override.is_some() || buf[0x18..0x1C] == [0, 0, 0, 0] {
                buf[0x18..0x1C].copy_from_slice(&effective_rev.to_le_bytes());
            }
            if opts.serial_override.is_some() || effective_serial != 0 {
                buf[0x1C..0x20].copy_from_slice(&effective_serial.to_le_bytes());
            }
            let size_kbit_minus_1 = ((target_len / 128) - 1) as u16;
            buf[0x7C..0x7E].copy_from_slice(&size_kbit_minus_1.to_le_bytes());
            if buf[0x7E..0x80] == [0, 0] {
                buf[0x7E..0x80].copy_from_slice(&1u16.to_le_bytes());
            }
            buf[0x0E] = sii_crc8(&buf[0..14]);

            let decoded = parse_sii_image(&buf)?;
            let used = measure_sii_used_bytes(&buf);
            let strings_cnt = decoded.categories.strings.len();
            return Ok(EsiCompiledSii {
                crc8_hex: format!("0x{:02X}", buf[0x0E]),
                final_byte_size: buf.len(),
                used_bytes: used,
                free_bytes: buf.len().saturating_sub(used),
                bytes: buf,
                mode: "raw_data",
                profile: opts.profile,
                declared_byte_size: declared_size,
                strings_interned: strings_cnt,
                total_unique_candidate_strings: strings_cnt,
                strings_dropped_by_budget: 0,
            });
        }
    }

    // Standard <ConfigData> + ETG.2000 Device model -> ETG.2010 SII compilation
    let mut config_data_14 = [0u8; 14];
    if let Some(ref cfg) = device.eeprom.config_data {
        let copy_len = cfg.len().min(14);
        config_data_14[..copy_len].copy_from_slice(&cfg[..copy_len]);
    }

    let bootstrap_mailbox = device
        .eeprom
        .bootstrap
        .or_else(|| device.mailbox.as_ref().and_then(|m| m.bootstrap))
        .unwrap_or([0u16; 4]);

    let std_mailbox = if device.mailbox.is_some() {
        let rx = device
            .sync_managers
            .iter()
            .find(|sm| sm.sm_type_code == 1)
            .map(|sm| (sm.start_address, sm.default_size))
            .unwrap_or((0, 0));
        let tx = device
            .sync_managers
            .iter()
            .find(|sm| sm.sm_type_code == 2)
            .map(|sm| (sm.start_address, sm.default_size))
            .unwrap_or((0, 0));
        [rx.0, rx.1, tx.0, tx.1]
    } else {
        [0u16; 4]
    };

    let mbx_protocols = device
        .mailbox
        .as_ref()
        .map(|m| m.protocol_mask())
        .unwrap_or(0);

    let coe_details = if let Some(coe) = device.mailbox.as_ref().and_then(|m| m.coe.as_ref()) {
        let mut c = 0u8;
        if coe.enable_sdo {
            c |= 0x01;
        }
        if coe.sdo_info {
            c |= 0x02;
        }
        if coe.pdo_assign {
            c |= 0x04;
        }
        if coe.pdo_config {
            c |= 0x08;
        }
        if coe.pdo_upload {
            c |= 0x10;
        }
        if coe.complete_access {
            c |= 0x20;
        }
        c
    } else {
        0
    };

    let foe_details = u8::from(device.mailbox.as_ref().is_some_and(|m| m.foe));
    let eoe_details = u8::from(device.mailbox.as_ref().is_some_and(|m| m.eoe));
    let soe_channels = match opts.profile {
        SiiBuildProfile::Ssc => 0,
        SiiBuildProfile::Minimal => device
            .mailbox
            .as_ref()
            .and_then(|m| m.soe_channels)
            .unwrap_or(0),
    };
    let ds402_channels = match opts.profile {
        SiiBuildProfile::Ssc => 0,
        SiiBuildProfile::Minimal => device.ds402_channels,
    };

    let mut gen_flags = 0u8;
    if opts.profile == SiiBuildProfile::Minimal && device.enable_safeop {
        gen_flags |= 0x01;
    }
    if device.enable_not_lrw {
        gen_flags |= 0x02;
    }
    let mbx_flag = match opts.profile {
        // ET9300Utilities GeneralCategory checks `SelectSingleNode("Mailbox") != null`
        SiiBuildProfile::Ssc => device.mailbox.is_some(),
        SiiBuildProfile::Minimal => device.mailbox.as_ref().is_some_and(|m| m.data_link_layer),
    };
    if mbx_flag {
        gen_flags |= 0x04;
    }
    if device.identification_reg134 {
        gen_flags |= 0x08;
    }
    if device.identification_ado.is_some() {
        gen_flags |= 0x10;
    }

    let general = SiiGeneralSpec {
        group_type: device.group_type.clone(),
        image_name: match opts.profile {
            SiiBuildProfile::Ssc => String::new(),
            SiiBuildProfile::Minimal => device.image_name.clone(),
        },
        order_code: device.order_code.clone(),
        device_name: device.device_name.clone(),
        coe_details,
        foe_details,
        eoe_details,
        soe_channels,
        ds402_channels,
        sysman_class: 0,
        flags: gen_flags,
        // ET9300Utilities GeneralCategory(DeviceDescription) leaves _CurrentOnEbus = 0;
        // preserve parsed <EBusCurrent> under Minimal profile.
        current_on_ebus_ma: match opts.profile {
            SiiBuildProfile::Ssc => 0,
            SiiBuildProfile::Minimal => device.current_on_ebus_ma,
        },
        physical_ports_word: device.physical_ports_word,
        physical_memory_address: device.identification_ado.unwrap_or(0),
    };

    let sync_managers: Vec<SiiSyncMInput> = device
        .sync_managers
        .iter()
        .map(|sm| {
            let mut enable_byte = 0u8;
            if sm.enable {
                enable_byte |= 0x01;
            }
            if sm.virtual_sm {
                enable_byte |= 0x04;
            }
            if sm.op_only {
                enable_byte |= 0x08;
            }
            SiiSyncMInput {
                physical_start_address: sm.start_address,
                length: sm.default_size,
                control_register: sm.control_byte,
                status_register: 0x00,
                enable_byte,
                sm_type: sm.sm_type_code,
            }
        })
        .collect();

    let has_coe = (mbx_protocols & 0x0004) != 0;
    let tx_pdos = map_esi_pdos(
        &device.tx_pdos,
        opts.include_unassigned_pdos,
        has_coe,
        opts.profile,
    )?;
    let rx_pdos = map_esi_pdos(
        &device.rx_pdos,
        opts.include_unassigned_pdos,
        has_coe,
        opts.profile,
    )?;

    // ET9300Utilities.Sii.DCCategory uses SelectSingleNode("Dc/OpMode") (at most 1 OpMode)
    // and UInt32.TryParse for ShiftTimeSync0 / ShiftTimeSync1 (negative values stay 0).
    let dc_limit = match opts.profile {
        SiiBuildProfile::Ssc => 1,
        SiiBuildProfile::Minimal => usize::MAX,
    };
    let dc_modes: Vec<SiiDcOpModeSpec> = device
        .dc_modes
        .iter()
        .take(dc_limit)
        .map(|m| SiiDcOpModeSpec {
            name: m.name.clone(),
            description: m.description.clone(),
            cycle_time_0_ns: m.cycle_time_sync0_ns,
            shift_time_0_ns: match opts.profile {
                SiiBuildProfile::Ssc => m.shift_time_sync0_ns.max(0),
                SiiBuildProfile::Minimal => m.shift_time_sync0_ns,
            },
            shift_time_1_ns: match opts.profile {
                SiiBuildProfile::Ssc => m.shift_time_sync1_ns.max(0),
                SiiBuildProfile::Minimal => m.shift_time_sync1_ns,
            },
            sync1_cycle_factor: m.factor_sync1,
            assign_activate: m.assign_activate,
            sync0_cycle_factor: m.factor_sync0,
        })
        .collect();

    let build_spec = SiiBuildSpec {
        config_data_14,
        configured_station_alias: opts.alias_override,
        vendor_id: device.vendor_id,
        product_code: device.product_code,
        revision_number: effective_rev,
        serial_number: effective_serial,
        bootstrap_mailbox,
        std_mailbox,
        mbx_protocols,
        declared_byte_size: declared_size,
        respect_byte_size_budget: !opts.ignore_eeprom_size,
        auto_grow_size: opts.ignore_eeprom_size,
        profile: opts.profile,
        general: Some(general),
        fmmus: device.fmmu_codes.clone(),
        sync_managers,
        tx_pdos,
        rx_pdos,
        dc_modes,
    };

    let candidate_strings = count_unique_candidate_strings(&build_spec);
    let bytes = encode_sii_image(&build_spec)?;
    let decoded = parse_sii_image(&bytes)?;
    let used = measure_sii_used_bytes(&bytes);
    let interned = decoded.categories.strings.len();

    Ok(EsiCompiledSii {
        crc8_hex: format!("0x{:02X}", bytes[0x0E]),
        final_byte_size: bytes.len(),
        used_bytes: used,
        free_bytes: bytes.len().saturating_sub(used),
        bytes,
        mode: "config_data",
        profile: opts.profile,
        declared_byte_size: declared_size,
        strings_interned: interned,
        total_unique_candidate_strings: candidate_strings,
        strings_dropped_by_budget: candidate_strings.saturating_sub(interned),
    })
}
