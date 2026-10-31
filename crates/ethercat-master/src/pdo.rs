use std::path::Path;
use std::time::Duration;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::coe::{prepare_slave_mailbox, query_single_entry_description, sdo_read_raw};
use crate::slave_aiadr;
use ethercat_eeprom::sii::image::{parse_sii_image, sii_le16, sii_pdos_to_layout, SiiPdoDecoded};
use ethercat_eeprom::sii::ops::read_device_sii_image;
use ethercat_wire::error::{CliError, Result};
pub use ethercat_wire::pdo_codec::{
    decode_pdo_payload, encode_pdo_assignments, normalize_entry_key, PdoFieldDef, PdoLayout,
};
use ethercat_wire::protocol::constants::{ect_datatype_name, EcatCmd};
use ethercat_wire::transport::EthercatTransport;
use ethercat_wire::types::{decode_typed_value, extract_bits_le, format_hex, DataTypeSpec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PdoSource {
    /// Try CoE 0x1C12/0x1C13 if slave is >= PRE-OP, falling back to SII EEPROM categories 50/51.
    Auto,
    /// Read PDO mapping from SII EEPROM categories 50 (TxPDO) & 51 (RxPDO) (works even in INIT).
    Sii,
    /// Read live CoE PDO assignment objects 0x1C12 (RxPDO) & 0x1C13 (TxPDO) via SDO.
    Coe,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlavePdoMapReport {
    pub source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slave: Option<u16>,
    pub rx_total_bits: usize,
    pub rx_total_bytes: usize,
    pub tx_total_bits: usize,
    pub tx_total_bytes: usize,
    pub rx_layout_spec: String,
    pub tx_layout_spec: String,
    pub rx_pdos: Vec<SiiPdoDecoded>,
    pub tx_pdos: Vec<SiiPdoDecoded>,
}

pub fn load_pdo_map_from_sii_bytes(
    sii_bytes: &[u8],
    slave: Option<u16>,
) -> Result<SlavePdoMapReport> {
    let parsed = parse_sii_image(sii_bytes)?;
    let rx_layout = sii_pdos_to_layout(&parsed.categories.rx_pdos);
    let tx_layout = sii_pdos_to_layout(&parsed.categories.tx_pdos);
    let rx_bits = rx_layout.total_bits();
    let tx_bits = tx_layout.total_bits();
    Ok(SlavePdoMapReport {
        source: "sii",
        slave,
        rx_total_bits: rx_bits,
        rx_total_bytes: rx_bits.div_ceil(8),
        tx_total_bits: tx_bits,
        tx_total_bytes: tx_bits.div_ceil(8),
        rx_layout_spec: rx_layout.to_spec_string(),
        tx_layout_spec: tx_layout.to_spec_string(),
        rx_pdos: parsed.categories.rx_pdos,
        tx_pdos: parsed.categories.tx_pdos,
    })
}

pub fn read_pdo_map_coe(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    auto_preop: bool,
    timeout: Duration,
) -> Result<SlavePdoMapReport> {
    let mut cfg = prepare_slave_mailbox(bus, slave, auto_preop, timeout)?;

    let mut read_assign =
        |assign_idx: u16, dir: &'static str, sm_num: i16| -> Result<Vec<SiiPdoDecoded>> {
            let (cnt_b, _) = sdo_read_raw(bus, &mut cfg, assign_idx, 0, false, timeout)?;
            let pdo_cnt = cnt_b.first().copied().unwrap_or(0);
            let mut pdos = Vec::new();
            let mut cum_bit_off = 0usize;

            for sub in 1..=pdo_cnt {
                let (pidx_b, _) = sdo_read_raw(bus, &mut cfg, assign_idx, sub, false, timeout)?;
                if pidx_b.len() < 2 {
                    continue;
                }
                let pdo_idx = sii_le16(&pidx_b[0..2]);
                let (ecnt_b, _) = sdo_read_raw(bus, &mut cfg, pdo_idx, 0, false, timeout)?;
                let entry_cnt = ecnt_b.first().copied().unwrap_or(0);
                let mut entries = Vec::new();
                let mut pdo_bits = 0usize;

                for esub in 1..=entry_cnt {
                    let (map_b, _) = sdo_read_raw(bus, &mut cfg, pdo_idx, esub, false, timeout)?;
                    if map_b.len() < 4 {
                        continue;
                    }
                    let raw_map = u32::from_le_bytes([map_b[0], map_b[1], map_b[2], map_b[3]]);
                    let bit_len = (raw_map & 0xFF) as u8;
                    let obj_sub = ((raw_map >> 8) & 0xFF) as u8;
                    let obj_idx = ((raw_map >> 16) & 0xFFFF) as u16;
                    if obj_idx == 0x0000 {
                        entries.push(ethercat_eeprom::sii::image::SiiPdoEntryDecoded {
                            index: "0x0000".into(),
                            index_u16: 0,
                            subindex: 0,
                            name_idx: 0,
                            name: None,
                            data_type: 0,
                            data_type_name: "PADDING",
                            bit_length: bit_len,
                            bit_offset: cum_bit_off,
                            flags: 0,
                        });
                        cum_bit_off += bit_len as usize;
                        pdo_bits += bit_len as usize;
                        continue;
                    }
                    let fallback_dt: u16 = match bit_len {
                        1 => 0x0001,
                        8 => 0x0005,
                        16 => 0x0006,
                        32 => 0x0004,
                        64 => 0x001B,
                        _ => 0x0000,
                    };
                    let (resolved_dt, resolved_name) = if let Some((edt, _, ename)) =
                        query_single_entry_description(bus, &mut cfg, obj_idx, obj_sub, timeout)
                    {
                        let label = if ename.is_empty() {
                            format!("0x{obj_idx:04x}:{obj_sub:02x}")
                        } else {
                            ename
                        };
                        (edt, label)
                    } else {
                        (fallback_dt, format!("0x{obj_idx:04x}:{obj_sub:02x}"))
                    };
                    entries.push(ethercat_eeprom::sii::image::SiiPdoEntryDecoded {
                        index: format!("0x{obj_idx:04x}"),
                        index_u16: obj_idx,
                        subindex: obj_sub,
                        name_idx: 0,
                        name: Some(resolved_name),
                        data_type: u8::try_from(resolved_dt).unwrap_or(0),
                        data_type_name: ect_datatype_name(resolved_dt),
                        bit_length: bit_len,
                        bit_offset: cum_bit_off,
                        flags: 0,
                    });
                    cum_bit_off += bit_len as usize;
                    pdo_bits += bit_len as usize;
                }

                pdos.push(SiiPdoDecoded {
                    direction: dir,
                    pdo_index: format!("0x{pdo_idx:04x}"),
                    pdo_index_u16: pdo_idx,
                    entry_count: entry_cnt,
                    sync_manager: sm_num,
                    dc_sync: 0,
                    name_idx: 0,
                    name: None,
                    flags: 0,
                    total_bits: pdo_bits,
                    entries,
                });
            }
            Ok(pdos)
        };

    let rx_pdos = read_assign(0x1C12, "RxPDO", 2)?;
    let tx_pdos = read_assign(0x1C13, "TxPDO", 3)?;
    let rx_layout = sii_pdos_to_layout(&rx_pdos);
    let tx_layout = sii_pdos_to_layout(&tx_pdos);
    let rx_bits = rx_layout.total_bits();
    let tx_bits = tx_layout.total_bits();

    Ok(SlavePdoMapReport {
        source: "coe",
        slave: Some(slave),
        rx_total_bits: rx_bits,
        rx_total_bytes: rx_bits.div_ceil(8),
        tx_total_bits: tx_bits,
        tx_total_bytes: tx_bits.div_ceil(8),
        rx_layout_spec: rx_layout.to_spec_string(),
        tx_layout_spec: tx_layout.to_spec_string(),
        rx_pdos,
        tx_pdos,
    })
}

pub fn read_slave_pdo_map(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    source: PdoSource,
    sii_file: Option<&Path>,
    auto_preop: bool,
    timeout: Duration,
) -> Result<SlavePdoMapReport> {
    if let Some(path) = sii_file {
        let bytes = std::fs::read(path)
            .map_err(|e| CliError::Format(format!("cannot read '{}': {e}", path.display())))?;
        return load_pdo_map_from_sii_bytes(&bytes, Some(slave));
    }
    if slave == 0 {
        return Err(CliError::Usage(
            "PDO mapping requires a 1-based slave index (>= 1)".into(),
        ));
    }
    match source {
        PdoSource::Sii => {
            let img = read_device_sii_image(bus, slave, timeout)?;
            load_pdo_map_from_sii_bytes(&img, Some(slave))
        }
        PdoSource::Coe => read_pdo_map_coe(bus, slave, auto_preop, timeout),
        PdoSource::Auto => match read_pdo_map_coe(bus, slave, auto_preop, timeout) {
            Ok(rep) if !rep.rx_pdos.is_empty() || !rep.tx_pdos.is_empty() => Ok(rep),
            _ => {
                let img = read_device_sii_image(bus, slave, timeout)?;
                load_pdo_map_from_sii_bytes(&img, Some(slave))
            }
        },
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PdoIoReport {
    pub operation: &'static str,
    pub dry_run: bool,
    pub slave: u16,
    pub mechanism: &'static str,
    pub wkc: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_outputs_hex: Option<String>,
    pub rx_inputs_hex: String,
    pub decoded_inputs: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_slice: Option<Value>,
}

pub struct PdoReadParams<'a> {
    pub slave: u16,
    pub logical_addr: Option<u32>,
    pub auto_map_fmmu: bool,
    pub entry_filter: Option<&'a str>,
    pub bit_offset: Option<usize>,
    pub bit_length: Option<usize>,
    pub ty: DataTypeSpec,
    pub layout_override: Option<&'a str>,
    pub sii_file: Option<&'a Path>,
    pub timeout: Duration,
}

fn configure_slave_fmmu_for_pdo(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    logical_addr: u32,
    rx_bytes: u16,
    tx_bytes: u16,
    timeout: Duration,
) -> Result<()> {
    let aiadr = slave_aiadr(slave);
    let (_, sm_regs) = bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0810, vec![0u8; 16], timeout)?;
    let sm2_start = sii_le16(&sm_regs[0..2]);
    let sm3_start = sii_le16(&sm_regs[8..10]);

    // FMMU0 -> Outputs (SM2, write_enable = 0x02)
    if rx_bytes > 0 && sm2_start > 0 {
        let mut fmmu0 = vec![0u8; 16];
        fmmu0[0..4].copy_from_slice(&logical_addr.to_le_bytes());
        fmmu0[4..6].copy_from_slice(&rx_bytes.to_le_bytes());
        fmmu0[6] = 0;
        fmmu0[7] = 7;
        fmmu0[8..10].copy_from_slice(&sm2_start.to_le_bytes());
        fmmu0[10] = 0;
        fmmu0[11] = 0x02;
        fmmu0[12] = 0x01;
        bus.send_datagram(EcatCmd::Apwr, aiadr, 0x0600, fmmu0, timeout)?;
    }

    // FMMU1 -> Inputs (SM3, read_enable = 0x01)
    if tx_bytes > 0 && sm3_start > 0 {
        let mut fmmu1 = vec![0u8; 16];
        fmmu1[0..4].copy_from_slice(&logical_addr.to_le_bytes());
        fmmu1[4..6].copy_from_slice(&tx_bytes.to_le_bytes());
        fmmu1[6] = 0;
        fmmu1[7] = 7;
        fmmu1[8..10].copy_from_slice(&sm3_start.to_le_bytes());
        fmmu1[10] = 0;
        fmmu1[11] = 0x01;
        fmmu1[12] = 0x01;
        bus.send_datagram(EcatCmd::Apwr, aiadr, 0x0610, fmmu1, timeout)?;
    }
    Ok(())
}

pub fn pdo_read_live(
    bus: &mut dyn EthercatTransport,
    params: &PdoReadParams<'_>,
) -> Result<PdoIoReport> {
    if params.slave == 0 {
        return Err(CliError::Usage(
            "PDO read requires a 1-based slave position (`--slave 1..N`)".into(),
        ));
    }
    let aiadr = slave_aiadr(params.slave);
    let (sm_wkc, sm_regs) =
        bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0810, vec![0u8; 16], params.timeout)?;
    if sm_wkc == 0 {
        return Err(CliError::Device(format!(
            "slave {} did not respond to SyncManager read (WKC=0)",
            params.slave
        )));
    }
    let sm2_len = sii_le16(&sm_regs[2..4]);
    let sm3_addr = sii_le16(&sm_regs[8..10]);
    let sm3_len = sii_le16(&sm_regs[10..12]) as usize;

    let (tx_layout, rx_bytes_for_fmmu) = if let Some(spec) = params.layout_override {
        (PdoLayout::parse_spec(spec)?, sm2_len)
    } else if let Some(sii_path) = params.sii_file {
        let raw = std::fs::read(sii_path).map_err(|e| {
            CliError::Format(format!(
                "cannot read SII file '{}': {e}",
                sii_path.display()
            ))
        })?;
        let img = parse_sii_image(&raw)?;
        let rx_l = sii_pdos_to_layout(&img.categories.rx_pdos);
        let tx_l = sii_pdos_to_layout(&img.categories.tx_pdos);
        (tx_l, (rx_l.total_bytes() as u16).max(sm2_len))
    } else {
        let map = read_slave_pdo_map(
            bus,
            params.slave,
            PdoSource::Auto,
            None,
            false,
            params.timeout,
        )?;
        (sii_pdos_to_layout(&map.tx_pdos), map.rx_total_bytes as u16)
    };
    let read_len = if params.logical_addr.is_some()
        && !params.auto_map_fmmu
        && params.layout_override.is_some()
    {
        tx_layout.total_bytes().max(1)
    } else {
        tx_layout.total_bytes().max(sm3_len).max(1)
    };

    let (mechanism, wkc, rx_bytes) = if let Some(lad) = params.logical_addr {
        if params.auto_map_fmmu {
            configure_slave_fmmu_for_pdo(
                bus,
                params.slave,
                lad,
                rx_bytes_for_fmmu,
                read_len as u16,
                params.timeout,
            )?;
        }
        let (w, b) =
            bus.send_logical_datagram(EcatCmd::Lrd, lad, vec![0u8; read_len], params.timeout)?;
        ("logical_lrd", w, b)
    } else {
        let phys = if sm3_addr > 0 { sm3_addr } else { 0x1400 };
        let (w, b) = bus.send_datagram(
            EcatCmd::Aprd,
            aiadr,
            phys,
            vec![0u8; read_len],
            params.timeout,
        )?;
        ("sm3_physical_aprd", w, b)
    };

    if wkc == 0 {
        return Err(CliError::Device(format!(
            "PDO read ({mechanism}) returned WKC=0 on slave {}",
            params.slave
        )));
    }

    let mut decoded_inputs = decode_pdo_payload(&rx_bytes, &tx_layout)?;
    if let Some(ef) = params.entry_filter {
        let norm = normalize_entry_key(ef);
        decoded_inputs.retain(|item| {
            item.get("name")
                .and_then(|v| v.as_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(ef))
                || item
                    .get("entry")
                    .and_then(|v| v.as_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case(&norm))
        });
        if decoded_inputs.is_empty() {
            return Err(CliError::Mismatch(format!(
                "PDO entry '{ef}' not found in slave {} TxPDO mapping; run `pdo map --slave {}` to inspect mapped entries.",
                params.slave, params.slave
            )));
        }
    }

    let selected_slice = if let Some(boff) = params.bit_offset {
        let blen = params
            .bit_length
            .or_else(|| params.ty.default_bit_len())
            .unwrap_or(8);
        let sliced = extract_bits_le(&rx_bytes, boff, blen)?;
        let val = decode_typed_value(&sliced, params.ty, Some(blen))?;
        Some(json!({
            "bit_offset": boff,
            "bit_length": blen,
            "raw_hex": format_hex(&sliced),
            "value": val,
        }))
    } else {
        None
    };

    Ok(PdoIoReport {
        operation: "read",
        dry_run: false,
        slave: params.slave,
        mechanism,
        wkc,
        tx_outputs_hex: None,
        rx_inputs_hex: format_hex(&rx_bytes),
        decoded_inputs,
        selected_slice,
    })
}

pub struct PdoExchangeParams<'a> {
    pub slave: u16,
    pub logical_addr: u32,
    pub auto_map_fmmu: bool,
    pub set_fields: &'a [String],
    pub raw_tx_bytes: Option<Vec<u8>>,
    pub rx_layout_override: Option<&'a str>,
    pub tx_layout_override: Option<&'a str>,
    pub sii_file: Option<&'a Path>,
    pub dry_run: bool,
    pub timeout: Duration,
}

pub fn pdo_exchange_live(
    mut bus: Option<&mut dyn EthercatTransport>,
    params: &PdoExchangeParams<'_>,
) -> Result<PdoIoReport> {
    if params.slave == 0 {
        return Err(CliError::Usage(
            "PDO exchange requires a 1-based slave position (`--slave 1..N`)".into(),
        ));
    }
    let rx_override = params
        .rx_layout_override
        .map(PdoLayout::parse_spec)
        .transpose()?;
    let tx_override = params
        .tx_layout_override
        .map(PdoLayout::parse_spec)
        .transpose()?;

    let (rx_layout, tx_layout) = match (rx_override, tx_override) {
        (Some(rx), Some(tx)) => (rx, tx),
        (rx_opt, tx_opt) => {
            if let Some(sii_path) = params.sii_file {
                let raw = std::fs::read(sii_path).map_err(|e| {
                    CliError::Format(format!(
                        "cannot read SII file '{}': {e}",
                        sii_path.display()
                    ))
                })?;
                let img = parse_sii_image(&raw)?;
                (
                    rx_opt.unwrap_or_else(|| sii_pdos_to_layout(&img.categories.rx_pdos)),
                    tx_opt.unwrap_or_else(|| sii_pdos_to_layout(&img.categories.tx_pdos)),
                )
            } else if params.dry_run && bus.is_none() {
                if let Some(rx) = rx_opt {
                    (rx, tx_opt.unwrap_or_default())
                } else if params.set_fields.is_empty() && params.raw_tx_bytes.is_some() {
                    (PdoLayout::default(), tx_opt.unwrap_or_default())
                } else {
                    return Err(CliError::Usage(
                        "offline `pdo exchange --dry-run` without `-i/--iface` requires `--rx-layout`, `--sii-file`, or `--tx-hex` (without `--set`)".into(),
                    ));
                }
            } else {
                let live_bus = bus.as_deref_mut().ok_or_else(|| {
                    CliError::Usage(
                        "network interface (-i/--iface) is required for live PDO exchange".into(),
                    )
                })?;
                let map = read_slave_pdo_map(
                    live_bus,
                    params.slave,
                    PdoSource::Auto,
                    None,
                    false,
                    params.timeout,
                )?;
                (
                    rx_opt.unwrap_or_else(|| sii_pdos_to_layout(&map.rx_pdos)),
                    tx_opt.unwrap_or_else(|| sii_pdos_to_layout(&map.tx_pdos)),
                )
            }
        }
    };

    let frame_len = rx_layout
        .total_bytes()
        .max(tx_layout.total_bytes())
        .max(params.raw_tx_bytes.as_ref().map_or(0, |b| b.len()))
        .max(1);

    let mut out_buf = vec![0u8; frame_len];
    if let Some(ref raw) = params.raw_tx_bytes {
        out_buf[..raw.len()].copy_from_slice(raw);
    }
    if !params.set_fields.is_empty() {
        encode_pdo_assignments(&mut out_buf, &rx_layout, params.set_fields)?;
    }

    if params.dry_run {
        return Ok(PdoIoReport {
            operation: "exchange",
            dry_run: true,
            slave: params.slave,
            mechanism: "logical_lrw",
            wkc: 0,
            tx_outputs_hex: Some(format_hex(&out_buf)),
            rx_inputs_hex: String::new(),
            decoded_inputs: Vec::new(),
            selected_slice: None,
        });
    }

    let live_bus = bus.ok_or_else(|| {
        CliError::Usage("network interface (-i/--iface) is required unless --dry-run is set".into())
    })?;

    if params.auto_map_fmmu {
        configure_slave_fmmu_for_pdo(
            live_bus,
            params.slave,
            params.logical_addr,
            rx_layout.total_bytes() as u16,
            tx_layout.total_bytes() as u16,
            params.timeout,
        )?;
    }

    let tx_hex = format_hex(&out_buf);
    let (wkc, in_bytes) = live_bus.send_logical_datagram(
        EcatCmd::Lrw,
        params.logical_addr,
        out_buf,
        params.timeout,
    )?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "PDO LRW exchange returned WKC=0 on slave {} (pass `--auto-map` if FMMUs are not yet mapped)",
            params.slave
        )));
    }
    let decoded_inputs = decode_pdo_payload(&in_bytes, &tx_layout)?;

    Ok(PdoIoReport {
        operation: "exchange",
        dry_run: false,
        slave: params.slave,
        mechanism: "logical_lrw",
        wkc,
        tx_outputs_hex: Some(tx_hex),
        rx_inputs_hex: format_hex(&in_bytes),
        decoded_inputs,
        selected_slice: None,
    })
}
