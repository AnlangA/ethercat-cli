use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::{slave_aiadr, write_al_state, EC_NODEOFFSET};
use ethercat_dissector::{mbx_error_detail_description, sdo_info_entry_name_offset};
use ethercat_eeprom::sii::image::sii_le16;
use ethercat_eeprom::sii::ops::read_device_sii_slice;
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::{
    ect_datatype_name, sdo_abort_description, AlStateSpec, EcatCmd, EC_STATE_PRE_OP,
};
use ethercat_wire::transport::EthercatTransport;
use ethercat_wire::types::{
    decode_typed_value, encode_typed_value, extract_bits_le, format_hex, is_decimal_float_literal,
    DataTypeSpec,
};

#[derive(Debug, Clone)]
pub struct SlaveMailboxConfig {
    pub slave: u16,
    pub station_addr: u16,
    pub mbx_write_offset: u16,
    pub mbx_write_size: u16,
    pub mbx_read_offset: u16,
    pub mbx_read_size: u16,
    pub counter: u8,
}

impl SlaveMailboxConfig {
    fn next_cnt(&mut self) -> u8 {
        self.counter = (self.counter % 7) + 1;
        self.counter
    }
}

/// Ensure the target slave has configured station address, active SM0/SM1 mailbox configuration,
/// and is in >= PRE-OP state (automatically transitioning to PRE-OP when `auto_preop` is true).
pub fn prepare_slave_mailbox(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    auto_preop: bool,
    timeout: Duration,
) -> Result<SlaveMailboxConfig> {
    if slave == 0 {
        return Err(CliError::Usage(
            "CoE/SDO requires a specific slave >= 1".into(),
        ));
    }
    let aiadr = slave_aiadr(slave);

    // 1. Check / assign configured station address (0x0010)
    let (wkc, st_bytes) = bus.send_datagram(EcatCmd::Aprd, aiadr, 0x0010, vec![0u8; 2], timeout)?;
    if wkc == 0 {
        return Err(CliError::Device(format!(
            "slave {slave} not responding on EtherCAT bus"
        )));
    }
    let mut station_addr = u16::from_le_bytes([st_bytes[0], st_bytes[1]]);
    if station_addr == 0 {
        station_addr = EC_NODEOFFSET + slave;
        bus.send_datagram(
            EcatCmd::Apwr,
            aiadr,
            0x0010,
            station_addr.to_le_bytes().to_vec(),
            timeout,
        )?;
    }

    // 2. Read AL state (0x0130) & SM0/SM1 (0x0800..0x0810)
    let (_, al_bytes) =
        bus.send_datagram(EcatCmd::Fprd, station_addr, 0x0130, vec![0u8; 2], timeout)?;
    let al_state = u16::from_le_bytes([al_bytes[0], al_bytes[1]]) & 0x0F;

    let (_, sm_bytes) =
        bus.send_datagram(EcatCmd::Fprd, station_addr, 0x0800, vec![0u8; 16], timeout)?;
    let mut wo = u16::from_le_bytes([sm_bytes[0], sm_bytes[1]]);
    let mut wl = u16::from_le_bytes([sm_bytes[2], sm_bytes[3]]);
    let sm0_active = (sm_bytes[6] & 0x01) != 0;
    let mut ro = u16::from_le_bytes([sm_bytes[8], sm_bytes[9]]);
    let mut rl = u16::from_le_bytes([sm_bytes[10], sm_bytes[11]]);
    let sm1_active = (sm_bytes[14] & 0x01) != 0;

    if wl == 0 || rl == 0 || !sm0_active || !sm1_active {
        if wl == 0 || rl == 0 {
            // Use Bootstrap mailbox (SII 0x0014 -> byte 0x28) in BOOT state, else Standard mailbox (SII 0x0018 -> byte 0x30)
            let sii_mbx_off = if al_state == ethercat_wire::protocol::constants::EC_STATE_BOOT {
                0x28
            } else {
                0x30
            };
            let mbx_hdr = read_device_sii_slice(bus, slave, sii_mbx_off, 8, timeout)?;
            wo = sii_le16(&mbx_hdr[0..2]);
            wl = sii_le16(&mbx_hdr[2..4]);
            ro = sii_le16(&mbx_hdr[4..6]);
            rl = sii_le16(&mbx_hdr[6..8]);
            if (wl == 0 || rl == 0) && sii_mbx_off == 0x28 {
                let std_hdr = read_device_sii_slice(bus, slave, 0x30, 8, timeout)?;
                wo = sii_le16(&std_hdr[0..2]);
                wl = sii_le16(&std_hdr[2..4]);
                ro = sii_le16(&std_hdr[4..6]);
                rl = sii_le16(&std_hdr[6..8]);
            }
            if wl == 0 || rl == 0 {
                return Err(CliError::Protocol(format!(
                    "slave {slave} does not advertise CoE/Mailbox SyncManagers in ESC SM0/SM1 or SII 0x0018"
                )));
            }
        }
        let mut sm0 = Vec::with_capacity(8);
        sm0.extend_from_slice(&wo.to_le_bytes());
        sm0.extend_from_slice(&wl.to_le_bytes());
        sm0.extend_from_slice(&[0x26, 0x00, 0x01, 0x00]);
        let _ = bus.send_datagram(EcatCmd::Fpwr, station_addr, 0x0800, sm0, timeout);

        let mut sm1 = Vec::with_capacity(8);
        sm1.extend_from_slice(&ro.to_le_bytes());
        sm1.extend_from_slice(&rl.to_le_bytes());
        sm1.extend_from_slice(&[0x22, 0x00, 0x01, 0x00]);
        let _ = bus.send_datagram(EcatCmd::Fpwr, station_addr, 0x0808, sm1, timeout);
    }

    // 3. Verify AL state >= PRE-OP (or BOOT); CoE mailbox is inactive in INIT
    if al_state < EC_STATE_PRE_OP {
        if auto_preop {
            write_al_state(bus, slave, AlStateSpec::PreOp, true, false, timeout)?;
        } else {
            return Err(CliError::Protocol(format!(
                "slave {slave} is in INIT state (0x{al_state:02x}); CoE SDO requires PRE-OP/SAFE-OP/OP. Pass `--auto-preop` or run `state --slave {slave} --set pre-op` first."
            )));
        }
    }

    Ok(SlaveMailboxConfig {
        slave,
        station_addr,
        mbx_write_offset: wo,
        mbx_write_size: wl,
        mbx_read_offset: ro,
        mbx_read_size: rl,
        counter: 0,
    })
}

fn mbx_drain_stale(bus: &mut dyn EthercatTransport, cfg: &SlaveMailboxConfig, timeout: Duration) {
    for _ in 0..8 {
        let Ok((wkc, st)) = bus.send_datagram(
            EcatCmd::Fprd,
            cfg.station_addr,
            0x080D,
            vec![0u8; 1],
            timeout,
        ) else {
            break;
        };
        if wkc == 0 || (st[0] & 0x08) == 0 {
            break;
        }
        let _ = bus.send_datagram(
            EcatCmd::Fprd,
            cfg.station_addr,
            cfg.mbx_read_offset,
            vec![0u8; cfg.mbx_read_size as usize],
            timeout,
        );
    }
}

fn mbx_send(
    bus: &mut dyn EthercatTransport,
    cfg: &SlaveMailboxConfig,
    frame: &[u8],
    timeout: Duration,
) -> Result<()> {
    let mut padded = vec![0u8; cfg.mbx_write_size as usize];
    if frame.len() > padded.len() {
        return Err(CliError::Format(format!(
            "mailbox frame ({} bytes) exceeds slave {} SM0 size ({} bytes)",
            frame.len(),
            cfg.slave,
            padded.len()
        )));
    }
    padded[..frame.len()].copy_from_slice(frame);

    let start = Instant::now();
    let deadline = start
        .checked_add(timeout)
        .unwrap_or_else(|| start + Duration::from_secs(3600));
    loop {
        let step_timeout = timeout
            .min(deadline.saturating_duration_since(Instant::now()))
            .max(Duration::from_millis(1));
        // Check SM0 status bit 0x08 (0 = empty)
        let (wkc_s, st) = bus.send_datagram(
            EcatCmd::Fprd,
            cfg.station_addr,
            0x0805,
            vec![0u8; 1],
            step_timeout,
        )?;
        if wkc_s > 0 && (st[0] & 0x08) == 0 {
            let (wkc_w, _) = bus.send_datagram(
                EcatCmd::Fpwr,
                cfg.station_addr,
                cfg.mbx_write_offset,
                padded,
                timeout,
            )?;
            if wkc_w > 0 {
                return Ok(());
            }
            return Err(CliError::Device(format!(
                "SM0 mailbox write to slave {} returned WKC=0",
                cfg.slave
            )));
        }
        if Instant::now() >= deadline {
            return Err(CliError::Device(format!(
                "timeout waiting to write SM0 mailbox on slave {}",
                cfg.slave
            )));
        }
        std::thread::sleep(Duration::from_micros(300));
    }
}

fn mbx_recv(
    bus: &mut dyn EthercatTransport,
    cfg: &SlaveMailboxConfig,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let start = Instant::now();
    let deadline = start
        .checked_add(timeout)
        .unwrap_or_else(|| start + Duration::from_secs(3600));
    loop {
        let step_timeout = timeout
            .min(deadline.saturating_duration_since(Instant::now()))
            .max(Duration::from_millis(1));
        let (wkc_s, st) = bus.send_datagram(
            EcatCmd::Fprd,
            cfg.station_addr,
            0x080D,
            vec![0u8; 1],
            step_timeout,
        )?;
        if wkc_s > 0 && (st[0] & 0x08) != 0 {
            let (wkc_r, mbx) = bus.send_datagram(
                EcatCmd::Fprd,
                cfg.station_addr,
                cfg.mbx_read_offset,
                vec![0u8; cfg.mbx_read_size as usize],
                timeout,
            )?;
            if wkc_r > 0 && mbx.len() >= 6 {
                let mtype = mbx[5] & 0x0F;
                let len = u16::from_le_bytes([mbx[0], mbx[1]]) as usize;
                // Skip asynchronous CoE Emergency frames (service == 0x01) while awaiting SDO reply
                if mtype == 0x03 && mbx.len() >= 8 {
                    let coe_hdr = u16::from_le_bytes([mbx[6], mbx[7]]);
                    if ((coe_hdr >> 12) & 0x0F) == 0x01 {
                        continue;
                    }
                }
                let total = (6 + len).min(mbx.len());
                return Ok(mbx[..total].to_vec());
            }
        }
        if Instant::now() >= deadline {
            return Err(CliError::Device(format!(
                "timeout waiting for SM1 mailbox response from slave {}",
                cfg.slave
            )));
        }
        std::thread::sleep(Duration::from_micros(300));
    }
}

fn recv_coe_service(
    bus: &mut dyn EthercatTransport,
    cfg: &SlaveMailboxConfig,
    expected_service: u8,
    allow_sdo_abort_req: bool,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        let rem = deadline
            .checked_duration_since(now)
            .unwrap_or(Duration::from_millis(1));
        let res = mbx_recv(bus, cfg, rem)?;
        if res.len() < 6 {
            return Err(CliError::Protocol(format!(
                "truncated mailbox header ({} bytes) from slave {}",
                res.len(),
                cfg.slave
            )));
        }
        let mbx_type = res[5] & 0x0F;
        if mbx_type == 0x00 {
            let (err_type, detail) = if res.len() >= 10 {
                (
                    u16::from_le_bytes([res[6], res[7]]),
                    u16::from_le_bytes([res[8], res[9]]),
                )
            } else {
                (0, 0)
            };
            return Err(CliError::Protocol(format!(
                "slave {} returned Mailbox Error (type=0x{err_type:04X}, detail=0x{detail:04X}: {})",
                cfg.slave,
                mbx_error_detail_description(detail)
            )));
        }
        if mbx_type != 0x03 {
            return Err(CliError::Protocol(format!(
                "unexpected non-CoE mailbox reply from slave {} (mbx_type=0x{mbx_type:02X})",
                cfg.slave
            )));
        }
        if res.len() < 8 {
            return Err(CliError::Protocol(
                "truncated CoE mailbox header (< 8 bytes)".into(),
            ));
        }
        let coe_hdr = u16::from_le_bytes([res[6], res[7]]);
        let service = ((coe_hdr >> 12) & 0x0F) as u8;
        if service == 0x01 {
            // Asynchronous CoE Emergency message pushed into SM1; skip and keep waiting for response
            if Instant::now() >= deadline {
                return Err(CliError::Device(format!(
                    "timeout waiting for CoE service 0x{expected_service:02X} after Emergency frame on slave {}",
                    cfg.slave
                )));
            }
            continue;
        }
        let is_abort_on_sdoreq =
            allow_sdo_abort_req && service == 0x02 && res.get(8).is_some_and(|&c| (c >> 5) == 4);
        if service == expected_service || is_abort_on_sdoreq {
            return Ok(res);
        }
        return Err(CliError::Protocol(format!(
            "unexpected CoE service 0x{service:02X} (expected 0x{expected_service:02X}) from slave {}",
            cfg.slave
        )));
    }
}

fn build_coe_mbx(cnt: u8, service: u8, sdo_payload: &[u8]) -> Vec<u8> {
    let body_len = u16::try_from((2 + sdo_payload.len()).max(10)).unwrap_or(u16::MAX);
    let mut out = Vec::with_capacity(6 + body_len as usize);
    out.extend_from_slice(&body_len.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(0x00);
    out.push(0x03 | ((cnt & 0x07) << 4));
    let coe_hdr: u16 = (service as u16) << 12;
    out.extend_from_slice(&coe_hdr.to_le_bytes());
    out.extend_from_slice(sdo_payload);
    while out.len() < 6 + body_len as usize {
        out.push(0);
    }
    out
}

fn check_sdo_abort(index: u16, subindex: u8, sdo_payload: &[u8]) -> Result<()> {
    if !sdo_payload.is_empty() && sdo_payload[0] == 0x80 && sdo_payload.len() >= 8 {
        let abort = u32::from_le_bytes([
            sdo_payload[4],
            sdo_payload[5],
            sdo_payload[6],
            sdo_payload[7],
        ]);
        return Err(CliError::Protocol(format!(
            "SDO abort at 0x{index:04X}:{subindex:02X}: 0x{abort:08X} ({})",
            sdo_abort_description(abort)
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct SdoAccessReport {
    pub operation: &'static str,
    pub dry_run: bool,
    pub slave: u16,
    pub index: String,
    pub subindex: u8,
    pub complete_access: bool,
    pub transfer_mode: &'static str,
    pub size_bytes: usize,
    pub raw_hex: String,
    pub decoded_value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_slice: Option<Value>,
}

pub struct SdoReadParams {
    pub slave: u16,
    pub index: u16,
    pub subindex: u8,
    pub complete_access: bool,
    pub ty: DataTypeSpec,
    pub bit_offset: Option<usize>,
    pub bit_length: Option<usize>,
    pub auto_preop: bool,
    pub timeout: Duration,
}

pub fn sdo_read_raw(
    bus: &mut dyn EthercatTransport,
    cfg: &mut SlaveMailboxConfig,
    index: u16,
    subindex: u8,
    complete_access: bool,
    timeout: Duration,
) -> Result<(Vec<u8>, &'static str)> {
    const MAX_SDO_UPLOAD_BYTES: usize = 16 * 1024 * 1024;
    if complete_access && subindex > 1 {
        return Err(CliError::Usage(format!(
            "SDO Complete Access requires subindex 0 or 1 (got subindex {subindex})"
        )));
    }
    mbx_drain_stale(bus, cfg, timeout);
    let eff_sub = subindex;
    let mut req = vec![0u8; 8];
    req[0] = if complete_access { 0x50 } else { 0x40 };
    req[1..3].copy_from_slice(&index.to_le_bytes());
    req[3] = eff_sub;
    let cnt = cfg.next_cnt();
    let mbx_req = build_coe_mbx(cnt, 0x02, &req);
    mbx_send(bus, cfg, &mbx_req, timeout)?;

    let mbx_res = recv_coe_service(bus, cfg, 0x03, true, timeout)?;
    if mbx_res.len() < 12 {
        return Err(CliError::Protocol(
            "truncated CoE SDO upload response".into(),
        ));
    }
    let sdo = &mbx_res[8..];
    check_sdo_abort(index, eff_sub, sdo)?;
    let cmd = sdo[0];
    if ((cmd >> 5) & 0x07) != 2 {
        return Err(CliError::Protocol(format!(
            "unexpected SDO upload response specifier 0x{cmd:02X}"
        )));
    }
    if sdo.len() >= 4 {
        let resp_idx = u16::from_le_bytes([sdo[1], sdo[2]]);
        let resp_sub = sdo[3];
        if resp_idx != index || resp_sub != eff_sub {
            return Err(CliError::Protocol(format!(
                "SDO upload response address mismatch: expected 0x{index:04X}:{eff_sub:02X}, got 0x{resp_idx:04X}:{resp_sub:02X}"
            )));
        }
    }

    // Expedited response
    if (cmd & 0x02) != 0 {
        let unused = if (cmd & 0x01) != 0 {
            ((cmd >> 2) & 0x03) as usize
        } else {
            0
        };
        let n = 4usize.saturating_sub(unused);
        if sdo.len() < 4 + n {
            return Err(CliError::Protocol(
                "truncated expedited SDO response".into(),
            ));
        }
        return Ok((sdo[4..4 + n].to_vec(), "expedited"));
    }

    // Normal or Segmented response
    if sdo.len() < 8 {
        return Err(CliError::Protocol(
            "truncated normal SDO upload header".into(),
        ));
    }
    let mbx_body_len = u16::from_le_bytes([mbx_res[0], mbx_res[1]]) as usize;
    let frame_data_size = mbx_body_len.saturating_sub(10).min(sdo.len() - 8);
    let size_indicated = (cmd & 0x01) != 0;
    let total_len = if size_indicated {
        u32::from_le_bytes([sdo[4], sdo[5], sdo[6], sdo[7]]) as usize
    } else {
        MAX_SDO_UPLOAD_BYTES
    };
    if size_indicated && total_len > MAX_SDO_UPLOAD_BYTES {
        return Err(CliError::Protocol(format!(
            "SDO upload length ({total_len} bytes) exceeds 16 MiB safety cap"
        )));
    }
    let init_cap = if size_indicated {
        total_len.min(65536)
    } else {
        frame_data_size.max(256)
    };
    let mut out = Vec::with_capacity(init_cap);
    out.extend_from_slice(&sdo[8..8 + frame_data_size.min(total_len)]);

    let max_init_payload = (cfg.mbx_read_size as usize).saturating_sub(16);
    if (size_indicated && out.len() >= total_len)
        || (!size_indicated && (max_init_payload == 0 || frame_data_size < max_init_payload))
    {
        return Ok((out, "normal"));
    }

    // Segmented upload loop
    let mut toggle = 0u8;
    while out.len() < total_len {
        let mut seg_req = vec![0u8; 8];
        seg_req[0] = 0x60 | toggle;
        seg_req[1..3].copy_from_slice(&index.to_le_bytes());
        seg_req[3] = eff_sub;
        let c = cfg.next_cnt();
        let seg_mbx = build_coe_mbx(c, 0x02, &seg_req);
        mbx_send(bus, cfg, &seg_mbx, timeout)?;

        let seg_res = recv_coe_service(bus, cfg, 0x03, true, timeout)?;
        if seg_res.len() < 9 {
            return Err(CliError::Protocol("truncated SDO upload segment".into()));
        }
        let seg_sdo = &seg_res[8..];
        check_sdo_abort(index, eff_sub, seg_sdo)?;
        let scmd = seg_sdo[0];
        if (scmd & 0xE0) != 0x00 {
            return Err(CliError::Protocol(format!(
                "unexpected SDO segment response specifier 0x{scmd:02X}"
            )));
        }
        if (scmd & 0x10) != toggle {
            return Err(CliError::Protocol(format!(
                "SDO upload segment toggle bit mismatch at 0x{index:04X}:{eff_sub:02X}: 0x05030000 ({})",
                sdo_abort_description(0x0503_0000)
            )));
        }
        let seg_mbx_len = u16::from_le_bytes([seg_res[0], seg_res[1]]) as usize;
        let mut seg_bytes = seg_mbx_len.saturating_sub(3).min(seg_sdo.len() - 1);
        let is_last = (scmd & 0x01) != 0;
        if is_last && seg_bytes == 7 {
            let unused = ((scmd >> 1) & 0x07) as usize;
            seg_bytes = seg_bytes.saturating_sub(unused);
        }
        let take = seg_bytes.min(total_len - out.len());
        if take == 0 && !is_last {
            return Err(CliError::Protocol(
                "empty non-final SDO upload segment received".into(),
            ));
        }
        out.extend_from_slice(&seg_sdo[1..1 + take]);
        if is_last {
            if size_indicated && out.len() < total_len {
                return Err(CliError::Protocol(format!(
                    "SDO segmented upload truncated early at 0x{index:04X}:{eff_sub:02X}: expected {total_len} bytes, got {}",
                    out.len()
                )));
            }
            break;
        }
        toggle ^= 0x10;
    }

    Ok((out, "segmented"))
}

pub fn sdo_read(
    bus: &mut dyn EthercatTransport,
    params: &SdoReadParams,
) -> Result<SdoAccessReport> {
    let mut cfg = prepare_slave_mailbox(bus, params.slave, params.auto_preop, params.timeout)?;
    let (bytes, mode) = sdo_read_raw(
        bus,
        &mut cfg,
        params.index,
        params.subindex,
        params.complete_access,
        params.timeout,
    )?;

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

    Ok(SdoAccessReport {
        operation: "read",
        dry_run: false,
        slave: params.slave,
        index: format!("0x{:04X}", params.index),
        subindex: params.subindex,
        complete_access: params.complete_access,
        transfer_mode: mode,
        size_bytes: bytes.len(),
        raw_hex: format_hex(&bytes),
        decoded_value,
        bit_slice,
    })
}

pub struct SdoWriteParams<'a> {
    pub slave: u16,
    pub index: u16,
    pub subindex: u8,
    pub complete_access: bool,
    pub ty: DataTypeSpec,
    pub value_str: &'a str,
    pub auto_preop: bool,
    pub dry_run: bool,
    pub timeout: Duration,
}

fn decode_written_value(payload: &[u8], ty: DataTypeSpec, value_str: &str) -> Result<Value> {
    let trimmed = value_str.trim();
    if ty == DataTypeSpec::Auto {
        if is_decimal_float_literal(trimmed) {
            let float_ty = match payload.len() {
                4 => DataTypeSpec::F32,
                8 => DataTypeSpec::F64,
                _ => DataTypeSpec::Auto,
            };
            return decode_typed_value(payload, float_ty, None);
        }
        if trimmed.starts_with('-') {
            let signed_ty = match payload.len() {
                1 => DataTypeSpec::I8,
                2 => DataTypeSpec::I16,
                3 => DataTypeSpec::I24,
                4 => DataTypeSpec::I32,
                8 => DataTypeSpec::I64,
                _ => DataTypeSpec::Auto,
            };
            return decode_typed_value(payload, signed_ty, None);
        }
    }
    decode_typed_value(payload, ty, None)
}

pub fn sdo_write(
    bus: Option<&mut dyn EthercatTransport>,
    params: &SdoWriteParams<'_>,
) -> Result<SdoAccessReport> {
    if params.slave == 0 {
        return Err(CliError::Usage(
            "CoE/SDO requires a specific slave >= 1".into(),
        ));
    }
    if params.dry_run {
        let payload = encode_typed_value(params.value_str, params.ty)?;
        if payload.is_empty() {
            return Err(CliError::Format("SDO write payload cannot be empty".into()));
        }
        let decoded_value = decode_written_value(&payload, params.ty, params.value_str)?;
        let mode = if payload.len() <= 4 && !params.complete_access {
            "expedited"
        } else {
            "normal_or_segmented"
        };
        return Ok(SdoAccessReport {
            operation: "write",
            dry_run: true,
            slave: params.slave,
            index: format!("0x{:04X}", params.index),
            subindex: params.subindex,
            complete_access: params.complete_access,
            transfer_mode: mode,
            size_bytes: payload.len(),
            raw_hex: format_hex(&payload),
            decoded_value,
            bit_slice: None,
        });
    }

    let bus = bus.ok_or_else(|| {
        CliError::Usage("network interface (-i/--iface) is required unless --dry-run is set".into())
    })?;

    let mut cfg = prepare_slave_mailbox(bus, params.slave, params.auto_preop, params.timeout)?;
    mbx_drain_stale(bus, &cfg, params.timeout);

    // When `--type auto` is used on a scalar entry, consult SDO Info Entry Description if supported
    // so fixed-width CoE objects (e.g. 0x607A INTEGER32 or 0x6040 UNSIGNED16) encode at exact width.
    let mut effective_ty = params.ty;
    if effective_ty == DataTypeSpec::Auto
        && !params.complete_access
        && !params.value_str.trim().starts_with('@')
    {
        if let Some((dt, bit_len, _)) = query_single_entry_description(
            bus,
            &mut cfg,
            params.index,
            params.subindex,
            params.timeout,
        ) {
            if let Some(inferred) = DataTypeSpec::from_coe_datatype(dt, bit_len) {
                if !matches!(inferred, DataTypeSpec::Hex | DataTypeSpec::Auto) {
                    effective_ty = inferred;
                }
            }
        }
    }

    let payload = encode_typed_value(params.value_str, effective_ty)?;
    if payload.is_empty() {
        return Err(CliError::Format("SDO write payload cannot be empty".into()));
    }
    let decoded_value = decode_written_value(&payload, effective_ty, params.value_str)?;

    if params.complete_access && params.subindex > 1 {
        return Err(CliError::Usage(format!(
            "SDO Complete Access requires subindex 0 or 1 (got subindex {})",
            params.subindex
        )));
    }
    let eff_sub = params.subindex;

    let mode = if payload.len() <= 4 && !params.complete_access {
        let mut req = vec![0u8; 8];
        let unused = ((4 - payload.len()) as u8) & 0x03;
        req[0] = 0x23 | (unused << 2);
        req[1..3].copy_from_slice(&params.index.to_le_bytes());
        req[3] = eff_sub;
        req[4..4 + payload.len()].copy_from_slice(&payload);
        let cnt = cfg.next_cnt();
        let mbx_req = build_coe_mbx(cnt, 0x02, &req);
        mbx_send(bus, &cfg, &mbx_req, params.timeout)?;

        let mbx_res = recv_coe_service(bus, &cfg, 0x03, true, params.timeout)?;
        if mbx_res.len() < 12 {
            return Err(CliError::Protocol("short SDO download response".into()));
        }
        let sdo = &mbx_res[8..];
        check_sdo_abort(params.index, eff_sub, sdo)?;
        if (sdo[0] >> 5) != 3 {
            return Err(CliError::Protocol(format!(
                "unexpected SDO download response specifier 0x{:02X}",
                sdo[0]
            )));
        }
        let resp_idx = u16::from_le_bytes([sdo[1], sdo[2]]);
        if resp_idx != params.index || sdo[3] != eff_sub {
            return Err(CliError::Protocol(format!(
                "SDO download response address mismatch: expected 0x{:04X}:{eff_sub:02X}, got 0x{resp_idx:04X}:{:02X}",
                params.index, sdo[3]
            )));
        }
        "expedited"
    } else {
        let max_init_data = (cfg.mbx_write_size as usize).saturating_sub(16).max(4);
        let first_chunk = payload.len().min(max_init_data);
        let segmented = first_chunk < payload.len();

        let mut req = Vec::with_capacity(8 + first_chunk);
        req.push(if params.complete_access { 0x31 } else { 0x21 });
        req.extend_from_slice(&params.index.to_le_bytes());
        req.push(eff_sub);
        req.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        req.extend_from_slice(&payload[..first_chunk]);
        let cnt = cfg.next_cnt();
        let mbx_req = build_coe_mbx(cnt, 0x02, &req);
        mbx_send(bus, &cfg, &mbx_req, params.timeout)?;

        let mbx_res = recv_coe_service(bus, &cfg, 0x03, true, params.timeout)?;
        if mbx_res.len() < 12 {
            return Err(CliError::Protocol(
                "short SDO init download response".into(),
            ));
        }
        let sdo = &mbx_res[8..];
        check_sdo_abort(params.index, eff_sub, sdo)?;
        if (sdo[0] >> 5) != 3 {
            return Err(CliError::Protocol(format!(
                "unexpected SDO init download response specifier 0x{:02X}",
                sdo[0]
            )));
        }
        let resp_idx = u16::from_le_bytes([sdo[1], sdo[2]]);
        if resp_idx != params.index || sdo[3] != eff_sub {
            return Err(CliError::Protocol(format!(
                "SDO init download response address mismatch: expected 0x{:04X}:{eff_sub:02X}, got 0x{resp_idx:04X}:{:02X}",
                params.index, sdo[3]
            )));
        }

        let mut offset = first_chunk;
        let max_seg_data = (cfg.mbx_write_size as usize).saturating_sub(9).max(7);
        let mut toggle = 0u8;
        while offset < payload.len() {
            let rem = payload.len() - offset;
            let take = rem.min(max_seg_data);
            let is_last = offset + take >= payload.len();
            let mut cmd_byte = toggle | if is_last { 0x01 } else { 0x00 };
            if is_last && take < 7 {
                cmd_byte |= ((7 - take) as u8) << 1;
            }
            let mut seg = Vec::with_capacity(1 + take.max(7));
            seg.push(cmd_byte);
            seg.extend_from_slice(&payload[offset..offset + take]);
            while seg.len() < 8 {
                seg.push(0);
            }
            let c = cfg.next_cnt();
            let seg_mbx = build_coe_mbx(c, 0x02, &seg);
            mbx_send(bus, &cfg, &seg_mbx, params.timeout)?;

            let seg_res = recv_coe_service(bus, &cfg, 0x03, true, params.timeout)?;
            if seg_res.len() < 9 {
                return Err(CliError::Protocol(
                    "short SDO segment download response".into(),
                ));
            }
            let seg_sdo = &seg_res[8..];
            check_sdo_abort(params.index, eff_sub, seg_sdo)?;
            let scmd = seg_sdo[0];
            if (scmd & 0xE0) != 0x20 {
                return Err(CliError::Protocol(format!(
                    "unexpected SDO segment download response specifier 0x{scmd:02X}"
                )));
            }
            if (scmd & 0x10) != toggle {
                return Err(CliError::Protocol(format!(
                    "SDO download segment toggle bit mismatch at 0x{:04X}:{eff_sub:02X}: 0x05030000 ({})",
                    params.index,
                    sdo_abort_description(0x0503_0000)
                )));
            }
            offset += take;
            toggle ^= 0x10;
        }
        if segmented {
            "segmented"
        } else {
            "normal"
        }
    };

    Ok(SdoAccessReport {
        operation: "write",
        dry_run: false,
        slave: params.slave,
        index: format!("0x{:04X}", params.index),
        subindex: params.subindex,
        complete_access: params.complete_access,
        transfer_mode: mode,
        size_bytes: payload.len(),
        raw_hex: format_hex(&payload),
        decoded_value,
        bit_slice: None,
    })
}

fn check_sdo_info_error(index: u16, subindex: u8, info: &[u8]) -> Result<()> {
    if !info.is_empty() && (info[0] & 0x7F) == 0x07 {
        let abort = if info.len() >= 8 {
            u32::from_le_bytes([info[4], info[5], info[6], info[7]])
        } else {
            0x0800_0000
        };
        return Err(CliError::Protocol(format!(
            "SDO Info error at 0x{index:04X}:{subindex:02X}: 0x{abort:08X} ({})",
            sdo_abort_description(abort)
        )));
    }
    Ok(())
}

fn recv_sdo_info_reassembled(
    bus: &mut dyn EthercatTransport,
    cfg: &SlaveMailboxConfig,
    expected_opcode: u8,
    index_for_err: u16,
    sub_for_err: u8,
    timeout: Duration,
) -> Result<Vec<u8>> {
    const MAX_SDO_INFO_FRAGMENTS: usize = 256;
    let mut assembled = Vec::new();
    for _ in 0..MAX_SDO_INFO_FRAGMENTS {
        let res = recv_coe_service(bus, cfg, 0x08, false, timeout)?;
        if res.len() < 12 {
            return Err(CliError::Protocol(format!(
                "truncated SDO Info mailbox frame ({} bytes) for 0x{index_for_err:04X}:{sub_for_err:02X}",
                res.len()
            )));
        }
        let body_len = u16::from_le_bytes([res[0], res[1]]) as usize;
        let sdoinfo = &res[8..(6 + body_len).min(res.len())];
        check_sdo_info_error(index_for_err, sub_for_err, sdoinfo)?;
        if sdoinfo.len() < 4 || (sdoinfo[0] & 0x7F) != expected_opcode {
            return Err(CliError::Protocol(format!(
                "unexpected SDO Info response opcode 0x{:02X} (expected 0x{expected_opcode:02X}) for 0x{index_for_err:04X}:{sub_for_err:02X}",
                sdoinfo.first().copied().unwrap_or(0)
            )));
        }
        let incomplete = (sdoinfo[0] & 0x80) != 0;
        let frags_left = u16::from_le_bytes([sdoinfo[2], sdoinfo[3]]);
        assembled.extend_from_slice(&sdoinfo[4..]);
        if !incomplete && frags_left == 0 {
            return Ok(assembled);
        }
    }
    Err(CliError::Protocol(format!(
        "SDO Info response exceeded {MAX_SDO_INFO_FRAGMENTS} fragments at 0x{index_for_err:04X}:{sub_for_err:02X}"
    )))
}

pub(crate) fn query_single_entry_description(
    bus: &mut dyn EthercatTransport,
    cfg: &mut SlaveMailboxConfig,
    index: u16,
    subindex: u8,
    timeout: Duration,
) -> Option<(u16, u16, String)> {
    let mut oe_req = vec![0x05u8, 0x00, 0x00, 0x00];
    oe_req.extend_from_slice(&index.to_le_bytes());
    oe_req.push(subindex);
    oe_req.push(0x07);
    let c = cfg.next_cnt();
    mbx_send(bus, cfg, &build_coe_mbx(c, 0x08, &oe_req), timeout).ok()?;
    let body = recv_sdo_info_reassembled(bus, cfg, 0x06, index, subindex, timeout).ok()?;
    if body.len() < 10 {
        return None;
    }
    let vinfo = body[3];
    let edt = u16::from_le_bytes([body[4], body[5]]);
    let ebits = u16::from_le_bytes([body[6], body[7]]);
    let name_off = sdo_info_entry_name_offset(vinfo, ebits, body.len());
    let ename = String::from_utf8_lossy(&body[name_off..])
        .trim_end_matches('\0')
        .to_string();
    Some((edt, ebits, ename))
}

#[derive(Debug, Clone, Serialize)]
pub struct OdEntryReport {
    pub subindex: u8,
    pub datatype: String,
    pub datatype_name: &'static str,
    pub bit_length: u16,
    pub access_flags: String,
    pub writable: bool,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OdObjectReport {
    pub index: String,
    pub datatype: String,
    pub datatype_name: &'static str,
    pub object_code: u8,
    pub max_subindex: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<OdEntryReport>,
}

pub fn query_od_info(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    filter_index: Option<u16>,
    include_entries: bool,
    auto_preop: bool,
    timeout: Duration,
) -> Result<Vec<OdObjectReport>> {
    let mut cfg = prepare_slave_mailbox(bus, slave, auto_preop, timeout)?;
    mbx_drain_stale(bus, &cfg, timeout);

    let indices = if let Some(idx) = filter_index {
        vec![idx]
    } else {
        // Send Get OD List Request (list_type = 0x0001 all objects)
        let req = [0x01u8, 0x00, 0x00, 0x00, 0x01, 0x00];
        let cnt = cfg.next_cnt();
        let mbx_req = build_coe_mbx(cnt, 0x08, &req);
        mbx_send(bus, &cfg, &mbx_req, timeout)?;
        let list_body = recv_sdo_info_reassembled(bus, &cfg, 0x02, 0, 0, timeout)?;
        let mut list = Vec::new();
        if list_body.len() > 2 {
            for &chunk in list_body[2..].as_chunks::<2>().0 {
                list.push(u16::from_le_bytes(chunk));
            }
        }
        list
    };

    let mut objects = Vec::new();
    for idx in indices {
        let mut od_req = vec![0x03u8, 0x00, 0x00, 0x00];
        od_req.extend_from_slice(&idx.to_le_bytes());
        let cnt = cfg.next_cnt();
        mbx_send(bus, &cfg, &build_coe_mbx(cnt, 0x08, &od_req), timeout)?;
        let body = match recv_sdo_info_reassembled(bus, &cfg, 0x04, idx, 0, timeout) {
            Ok(b) => b,
            Err(e) => {
                if filter_index.is_some() {
                    return Err(e);
                }
                continue;
            }
        };
        if body.len() < 6 {
            if filter_index.is_some() {
                return Err(CliError::Protocol(format!(
                    "truncated SDO Info Object Description response for 0x{idx:04X}"
                )));
            }
            continue;
        }
        let dt = u16::from_le_bytes([body[2], body[3]]);
        let max_sub = body[4];
        let obj_code = body[5];
        let name = String::from_utf8_lossy(&body[6..])
            .trim_end_matches('\0')
            .to_string();

        let mut entries = Vec::new();
        if include_entries {
            for sub in 0..=max_sub {
                let mut oe_req = vec![0x05u8, 0x00, 0x00, 0x00];
                oe_req.extend_from_slice(&idx.to_le_bytes());
                oe_req.push(sub);
                oe_req.push(0x07);
                let c = cfg.next_cnt();
                mbx_send(bus, &cfg, &build_coe_mbx(c, 0x08, &oe_req), timeout)?;
                let Ok(ebody) = recv_sdo_info_reassembled(bus, &cfg, 0x06, idx, sub, timeout)
                else {
                    continue;
                };
                if ebody.len() < 10 {
                    continue;
                }
                let vinfo = ebody[3];
                let edt = u16::from_le_bytes([ebody[4], ebody[5]]);
                let ebits = u16::from_le_bytes([ebody[6], ebody[7]]);
                let eacc = u16::from_le_bytes([ebody[8], ebody[9]]);
                let name_off = sdo_info_entry_name_offset(vinfo, ebits, ebody.len());
                let ename = String::from_utf8_lossy(&ebody[name_off..])
                    .trim_end_matches('\0')
                    .to_string();
                entries.push(OdEntryReport {
                    subindex: sub,
                    datatype: format!("0x{edt:04X}"),
                    datatype_name: ect_datatype_name(edt),
                    bit_length: ebits,
                    access_flags: format!("0x{eacc:04X}"),
                    writable: (eacc & 0x0038) != 0,
                    name: ename,
                });
            }
        }

        objects.push(OdObjectReport {
            index: format!("0x{idx:04X}"),
            datatype: format!("0x{dt:04X}"),
            datatype_name: ect_datatype_name(dt),
            object_code: obj_code,
            max_subindex: max_sub,
            name,
            entries,
        });
    }

    Ok(objects)
}
