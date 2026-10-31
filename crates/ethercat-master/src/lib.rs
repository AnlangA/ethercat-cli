pub mod coe;
pub mod pdo;
pub mod sim;

pub use ethercat_wire::transport::{list_all_adapters, AdapterInfo, EthercatTransport};

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use ethercat_eeprom::sii::image::parse_sii_image;
use ethercat_eeprom::sii::ops::{read_device_sii_image, SlaveSiiSummary};
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::{
    al_state_name, al_status_code_description, resolve_esc_register, AlStateSpec, EcatCmd,
    EC_STATE_ERROR,
};
use ethercat_wire::protocol::dissector::decode_esc_register_payload;
use ethercat_wire::types::{
    decode_typed_value, encode_typed_value, extract_bits_le, format_hex, is_decimal_float_literal,
    DataTypeSpec,
};

pub const EC_NODEOFFSET: u16 = 0x1000;

pub fn slave_aiadr(slave: u16) -> u16 {
    (1i32 - slave as i32) as u16
}

/// Non-destructively detect how many slaves are on the EtherCAT ring via Broadcast Read of ESC Type (0x0000).
pub fn detect_slave_count(bus: &mut dyn EthercatTransport, timeout: Duration) -> Result<u16> {
    let (wkc, _) = bus.send_datagram(EcatCmd::Brd, 0x0000, 0x0000, vec![0u8; 2], timeout)?;
    Ok(wkc)
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaveScanInfo {
    pub slave: u16,
    pub auto_inc_addr: String,
    pub station_addr: String,
    pub alias: String,
    pub esc_type: String,
    pub esc_revision: u8,
    pub esc_build: u16,
    pub al_state: String,
    pub al_status_code: String,
    pub al_status_description: &'static str,
    pub dl_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sii: Option<SlaveSiiSummary>,
    pub mbx_protocols: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BusScanReport {
    pub interface: String,
    pub readonly: bool,
    pub slave_count: u16,
    pub slaves: Vec<SlaveScanInfo>,
}

pub fn scan_bus(
    bus: &mut dyn EthercatTransport,
    assign_station_addrs: bool,
    read_sii: bool,
    timeout: Duration,
) -> Result<BusScanReport> {
    let count = detect_slave_count(bus, timeout)?;
    let mut slaves = Vec::new();

    for pos in 1..=count {
        let aiadr = slave_aiadr(pos);
        if assign_station_addrs {
            let cfg_addr = EC_NODEOFFSET + pos;
            let _ = bus.send_datagram(
                EcatCmd::Apwr,
                aiadr,
                0x0010,
                cfg_addr.to_le_bytes().to_vec(),
                timeout,
            );
        }

        let (wkc_esc, esc_info) =
            bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0000, vec![0u8; 4], timeout)?;
        if wkc_esc == 0 {
            return Err(CliError::Device(format!(
                "slave {pos} (0x{aiadr:04X}) did not respond during bus scan (WKC=0)"
            )));
        }
        let (_, addr_info) =
            bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0010, vec![0u8; 4], timeout)?;
        let (_, dl_bytes) =
            bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0110, vec![0u8; 2], timeout)?;
        let (_, al_bytes) =
            bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0130, vec![0u8; 6], timeout)?;

        let stadr = u16::from_le_bytes([addr_info[0], addr_info[1]]);
        let alias = u16::from_le_bytes([addr_info[2], addr_info[3]]);
        let dl_stat = u16::from_le_bytes([dl_bytes[0], dl_bytes[1]]);
        let al_stat = u16::from_le_bytes([al_bytes[0], al_bytes[1]]);
        let al_code = u16::from_le_bytes([al_bytes[4], al_bytes[5]]);

        let mut sii_summary = None;
        let mut mbx_protocols = Vec::new();
        if read_sii {
            if let Ok(img) = read_device_sii_image(bus, pos, timeout) {
                sii_summary = Some(SlaveSiiSummary::from_image(pos, &img));
                if let Ok(parsed) = parse_sii_image(&img) {
                    mbx_protocols = parsed.header.mbx_protocols;
                }
            }
        }

        slaves.push(SlaveScanInfo {
            slave: pos,
            auto_inc_addr: format!("0x{aiadr:04X}"),
            station_addr: format!("0x{stadr:04X}"),
            alias: format!("0x{alias:04X}"),
            esc_type: format!("0x{:02X}", esc_info[0]),
            esc_revision: esc_info[1],
            esc_build: u16::from_le_bytes([esc_info[2], esc_info[3]]),
            al_state: al_state_name(al_stat),
            al_status_code: format!("0x{al_code:04X}"),
            al_status_description: al_status_code_description(al_code),
            dl_status: format!("0x{dl_stat:04X}"),
            sii: sii_summary,
            mbx_protocols,
        });
    }

    Ok(BusScanReport {
        interface: bus.name().to_string(),
        readonly: !assign_station_addrs,
        slave_count: count,
        slaves,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaveStateReport {
    pub slave: u16,
    pub dry_run: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_state: Option<String>,
    #[serde(skip)]
    pub actual_state_code: u16,
    pub actual_state_raw: String,
    pub actual_state: String,
    pub error_flag: bool,
    pub al_status_code: String,
    pub al_status_description: &'static str,
    pub wkc: u16,
}

pub fn read_al_state(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    timeout: Duration,
) -> Result<SlaveStateReport> {
    let (cmd, adp) = if slave == 0 {
        (EcatCmd::Brd, 0x0000)
    } else {
        (EcatCmd::Aprd, slave_aiadr(slave))
    };
    let (wkc, bytes) = bus.send_datagram(cmd, adp, 0x0130, vec![0u8; 6], timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "no response reading AL status (0x0130) for slave {slave}"
        )));
    }
    let st = u16::from_le_bytes([bytes[0], bytes[1]]);
    let sc = u16::from_le_bytes([bytes[4], bytes[5]]);
    Ok(SlaveStateReport {
        slave,
        dry_run: false,
        requested_state: None,
        actual_state_code: st,
        actual_state_raw: format!("0x{st:04X}"),
        actual_state: al_state_name(st),
        error_flag: (st & EC_STATE_ERROR) != 0,
        al_status_code: format!("0x{sc:04X}"),
        al_status_description: al_status_code_description(sc),
        wkc,
    })
}

pub fn write_al_state(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    target: AlStateSpec,
    ack_error: bool,
    dry_run: bool,
    timeout: Duration,
) -> Result<SlaveStateReport> {
    let req_word = target.code() | if ack_error { EC_STATE_ERROR } else { 0 };
    if dry_run {
        let mut current = read_al_state(bus, slave, timeout)?;
        current.dry_run = true;
        current.requested_state = Some(al_state_name(req_word));
        return Ok(current);
    }

    let (wr_cmd, adp) = if slave == 0 {
        (EcatCmd::Bwr, 0x0000)
    } else {
        (EcatCmd::Apwr, slave_aiadr(slave))
    };
    let (wkc, _) = bus.send_datagram(
        wr_cmd,
        adp,
        0x0120,
        req_word.to_le_bytes().to_vec(),
        timeout,
    )?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "failed writing AL control (0x0120) on slave {slave} (WKC=0)"
        )));
    }

    let start = Instant::now();
    let deadline = start
        .checked_add(timeout)
        .unwrap_or_else(|| start + Duration::from_secs(3600));
    let poll_timeout = timeout
        .min(Duration::from_millis(250))
        .max(Duration::from_millis(10));
    loop {
        let mut rep = read_al_state(bus, slave, poll_timeout)?;
        rep.requested_state = Some(al_state_name(target.code()));
        let cur_low = rep.actual_state_code & 0x0F;
        if cur_low == target.code() && !rep.error_flag {
            return Ok(rep);
        }
        if Instant::now() >= deadline {
            return Err(CliError::Protocol(format!(
                "slave {} failed to reach {} (actual={}, AL status code={} '{}')",
                slave,
                al_state_name(target.code()),
                rep.actual_state,
                rep.al_status_code,
                rep.al_status_description
            )));
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EscRegAccessReport {
    pub operation: &'static str,
    pub dry_run: bool,
    pub cmd: &'static str,
    pub adp: String,
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_name: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<&'static str>,
    pub length_bytes: usize,
    pub wkc: u16,
    pub raw_hex: String,
    pub decoded_value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_slice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_fields: Option<Value>,
}

pub struct RegReadParams<'a> {
    pub slave: Option<u16>,
    pub config_addr: Option<u16>,
    pub broadcast: bool,
    pub reg_spec: &'a str,
    pub length: Option<u16>,
    pub ty: DataTypeSpec,
    pub bit_offset: Option<usize>,
    pub bit_length: Option<usize>,
    pub timeout: Duration,
}

pub fn read_esc_register(
    bus: &mut dyn EthercatTransport,
    params: &RegReadParams<'_>,
) -> Result<EscRegAccessReport> {
    let (ado, reg_info) = resolve_esc_register(params.reg_spec)?;
    let len = params
        .length
        .or_else(|| reg_info.map(|r| r.default_size))
        .unwrap_or(2) as usize;
    if len == 0 || len > 1024 {
        return Err(CliError::Usage(
            "register read length must be 1..=1024".into(),
        ));
    }

    let (cmd, adp) = if params.broadcast {
        (EcatCmd::Brd, 0x0000)
    } else if let Some(caddr) = params.config_addr {
        (EcatCmd::Fprd, caddr)
    } else {
        let sl = params.slave.unwrap_or(1);
        if sl == 0 {
            (EcatCmd::Brd, 0x0000)
        } else {
            (EcatCmd::Aprd, slave_aiadr(sl))
        }
    };

    let (wkc, bytes) = bus.send_datagram(cmd, adp, ado, vec![0u8; len], params.timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "ESC register read {} at 0x{ado:04X} returned WKC=0",
            cmd.mnemonic()
        )));
    }

    let (decoded_value, bit_slice) = if let Some(boff) = params.bit_offset {
        let blen = params
            .bit_length
            .or_else(|| params.ty.default_bit_len())
            .unwrap_or(1);
        let sliced = extract_bits_le(&bytes, boff, blen)?;
        let val = decode_typed_value(&sliced, params.ty, Some(blen))?;
        (
            val.clone(),
            Some(json!({
                "bit_offset": boff,
                "bit_length": blen,
                "slice_hex": format_hex(&sliced),
                "value": val,
            })),
        )
    } else {
        (decode_typed_value(&bytes, params.ty, None)?, None)
    };

    let mut dummy_ws = BTreeMap::new();
    let reg_fields = decode_esc_register_payload(ado, &bytes, &mut dummy_ws, None);

    Ok(EscRegAccessReport {
        operation: "read",
        dry_run: false,
        cmd: cmd.mnemonic(),
        adp: format!("0x{adp:04X}"),
        address: format!("0x{ado:04X}"),
        register_name: reg_info.map(|r| r.name),
        description: reg_info.map(|r| r.description),
        length_bytes: bytes.len(),
        wkc,
        raw_hex: format_hex(&bytes),
        decoded_value,
        bit_slice,
        register_fields: reg_fields,
    })
}

pub struct RegWriteParams<'a> {
    pub slave: Option<u16>,
    pub config_addr: Option<u16>,
    pub broadcast: bool,
    pub reg_spec: &'a str,
    pub value_str: &'a str,
    pub ty: DataTypeSpec,
    pub dry_run: bool,
    pub timeout: Duration,
}

pub fn write_esc_register(
    bus: Option<&mut dyn EthercatTransport>,
    params: &RegWriteParams<'_>,
) -> Result<EscRegAccessReport> {
    let (ado, reg_info) = resolve_esc_register(params.reg_spec)?;
    let trimmed = params.value_str.trim();
    let effective_ty = if params.ty == DataTypeSpec::Auto {
        if trimmed.starts_with('@') || is_decimal_float_literal(trimmed) {
            DataTypeSpec::Auto
        } else if trimmed.starts_with('-') {
            match reg_info.map(|r| r.default_size) {
                Some(1) => DataTypeSpec::I8,
                Some(2) => DataTypeSpec::I16,
                Some(4) => DataTypeSpec::I32,
                Some(8) => DataTypeSpec::I64,
                _ => DataTypeSpec::Auto,
            }
        } else {
            match reg_info.map(|r| r.default_size) {
                Some(1) => DataTypeSpec::U8,
                Some(2) => DataTypeSpec::U16,
                Some(4) => DataTypeSpec::U32,
                Some(8) => DataTypeSpec::U64,
                _ => DataTypeSpec::Auto,
            }
        }
    } else {
        params.ty
    };
    let (payload, used_auto_fallback) = match encode_typed_value(params.value_str, effective_ty) {
        Ok(b) => (b, false),
        Err(orig_err)
            if params.ty == DataTypeSpec::Auto
                && effective_ty != DataTypeSpec::Auto
                && !trimmed.starts_with('-') =>
        {
            match encode_typed_value(params.value_str, DataTypeSpec::Auto) {
                Ok(b) => (b, true),
                Err(_) => return Err(orig_err),
            }
        }
        Err(e) => return Err(e),
    };
    let (cmd, adp) = if params.broadcast {
        (EcatCmd::Bwr, 0x0000)
    } else if let Some(caddr) = params.config_addr {
        (EcatCmd::Fpwr, caddr)
    } else {
        let sl = params.slave.unwrap_or(1);
        if sl == 0 {
            (EcatCmd::Bwr, 0x0000)
        } else {
            (EcatCmd::Apwr, slave_aiadr(sl))
        }
    };

    let wkc = if params.dry_run {
        0
    } else {
        let live_bus = bus.ok_or_else(|| {
            CliError::Usage(
                "network interface (-i/--iface) is required unless --dry-run is set".into(),
            )
        })?;
        let (w, _) = live_bus.send_datagram(cmd, adp, ado, payload.clone(), params.timeout)?;
        if w == 0 {
            return Err(CliError::Device(format!(
                "ESC register write {} at 0x{ado:04X} returned WKC=0",
                cmd.mnemonic()
            )));
        }
        w
    };

    let decode_ty = if effective_ty == DataTypeSpec::Auto || used_auto_fallback {
        if is_decimal_float_literal(trimmed) {
            match payload.len() {
                4 => DataTypeSpec::F32,
                8 => DataTypeSpec::F64,
                _ => DataTypeSpec::Auto,
            }
        } else if trimmed.starts_with('-') {
            match payload.len() {
                1 => DataTypeSpec::I8,
                2 => DataTypeSpec::I16,
                3 => DataTypeSpec::I24,
                4 => DataTypeSpec::I32,
                8 => DataTypeSpec::I64,
                _ => DataTypeSpec::Auto,
            }
        } else {
            DataTypeSpec::Auto
        }
    } else {
        effective_ty
    };
    let decoded_value = decode_typed_value(&payload, decode_ty, None)?;
    let mut dummy_ws = BTreeMap::new();
    let reg_fields = decode_esc_register_payload(ado, &payload, &mut dummy_ws, None);

    Ok(EscRegAccessReport {
        operation: "write",
        dry_run: params.dry_run,
        cmd: cmd.mnemonic(),
        adp: format!("0x{adp:04X}"),
        address: format!("0x{ado:04X}"),
        register_name: reg_info.map(|r| r.name),
        description: reg_info.map(|r| r.description),
        length_bytes: payload.len(),
        wkc,
        raw_hex: format_hex(&payload),
        decoded_value,
        bit_slice: None,
        register_fields: reg_fields,
    })
}

/// Open either the built-in virtual ring simulator (`sim` / `sim://...`), an EtherCAT-over-UDP
/// endpoint (`udp://...`), or a physical L2 Npcap/libpcap interface.
pub fn open_transport(iface: &str, capture_local: bool) -> Result<Box<dyn EthercatTransport>> {
    let trimmed = iface.trim();
    if trimmed.eq_ignore_ascii_case("sim")
        || trimmed
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("sim://"))
        || trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("sim:"))
    {
        Ok(Box::new(sim::SimulatedBusTransport::open(trimmed)?))
    } else {
        ethercat_wire::transport::open_wire_transport(trimmed, capture_local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coe::{sdo_read, SdoReadParams};

    #[test]
    fn master_scan_state_and_sdo_over_virtual_ring() {
        let mut bus = open_transport("sim", false).unwrap();
        let timeout = Duration::from_millis(200);
        let scan = scan_bus(&mut *bus, true, true, timeout).unwrap();
        assert_eq!(scan.slave_count, 2);

        let st = write_al_state(&mut *bus, 1, AlStateSpec::PreOp, true, false, timeout).unwrap();
        assert_eq!(st.actual_state, "PRE-OP");

        let dev_name = sdo_read(
            &mut *bus,
            &SdoReadParams {
                slave: 1,
                index: 0x1008,
                subindex: 0,
                complete_access: false,
                ty: DataTypeSpec::String,
                bit_offset: None,
                bit_length: None,
                auto_preop: false,
                timeout,
            },
        )
        .unwrap();
        assert!(!dev_name.decoded_value.as_str().unwrap_or("").is_empty());
    }
}
