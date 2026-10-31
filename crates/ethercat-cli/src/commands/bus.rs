use std::time::Duration;

use serde_json::{json, Value};

use crate::cli::{Cli, PdoSubcommand, RegSubcommand, SdoSubcommand};
use crate::commands::{
    optional_iface, read_file_bytes, require_iface, resolve_offline_pdo_layout, CommandRender,
};
use ethercat_master::coe::{query_od_info, sdo_read, sdo_write, SdoReadParams, SdoWriteParams};
use ethercat_master::pdo::{
    decode_pdo_payload, encode_pdo_assignments, load_pdo_map_from_sii_bytes, pdo_exchange_live,
    pdo_read_live, read_slave_pdo_map, PdoExchangeParams, PdoReadParams,
};
use ethercat_master::{list_all_adapters, open_transport};
use ethercat_master::{
    read_al_state, read_esc_register, scan_bus, write_al_state, write_esc_register, RegReadParams,
    RegWriteParams,
};
use ethercat_wire::error::Result;
use ethercat_wire::protocol::constants::{AlStateSpec, ESC_REGISTERS};
use ethercat_wire::types::{format_hex, parse_bytes_arg};

pub fn handle_adapters(include_sim: bool) -> Result<CommandRender> {
    let adapters = list_all_adapters(include_sim)?;
    let mut lines = vec![format!(
        "Available EtherCAT / Npcap Adapters ({}):",
        adapters.len()
    )];
    for (idx, a) in adapters.iter().enumerate() {
        let tag = if a.virtual_sim {
            "[VIRTUAL-SIM]"
        } else if a.is_loopback {
            "[LOOPBACK]"
        } else {
            "[PHYSICAL]"
        };
        lines.push(format!(
            "  [{idx}] {tag:<13} {}  --  {}",
            a.name, a.description
        ));
    }
    Ok(CommandRender {
        json: json!({
            "count": adapters.len(),
            "adapters": adapters,
        }),
        text: lines.join("\n"),
    })
}

pub fn handle_scan(
    cli: &Cli,
    assign_addresses: bool,
    no_sii: bool,
    timeout: Duration,
) -> Result<CommandRender> {
    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let rep = scan_bus(&mut *bus, assign_addresses, !no_sii, timeout)?;
    let mut lines = vec![format!(
        "Interface: {}  |  Slaves detected: {}  |  Mode: {}",
        rep.interface,
        rep.slave_count,
        if rep.readonly {
            "READ-ONLY"
        } else {
            "STATION-ADDR-ASSIGNED"
        }
    )];
    for s in &rep.slaves {
        let name = s
            .sii
            .as_ref()
            .and_then(|i| i.name.as_deref())
            .unwrap_or("-");
        let vid_pid = s
            .sii
            .as_ref()
            .map(|i| format!("{}:{}", i.vendor_id, i.product_code))
            .unwrap_or_else(|| "no-sii".into());
        lines.push(format!(
            "  [Slave {:>2}] stadr={} alias={} state={:<8} al_code={} ({}) esc={} name=\"{}\" id={} mbx=[{}]",
            s.slave,
            s.station_addr,
            s.alias,
            s.al_state,
            s.al_status_code,
            s.al_status_description,
            s.esc_type,
            name,
            vid_pid,
            s.mbx_protocols.join(",")
        ));
    }
    Ok(CommandRender {
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
        text: lines.join("\n"),
    })
}

pub fn handle_state(
    cli: &Cli,
    slave: u16,
    set: Option<AlStateSpec>,
    ack: bool,
    dry_run: bool,
    timeout: Duration,
) -> Result<CommandRender> {
    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let rep = if let Some(target) = set {
        write_al_state(&mut *bus, slave, target, ack, dry_run, timeout)?
    } else {
        read_al_state(&mut *bus, slave, timeout)?
    };
    let text = format!(
        "Slave {} AL State: {} ({})  AL Status Code: {} ({})  WKC={}  dry_run={}",
        rep.slave,
        rep.actual_state,
        rep.actual_state_raw,
        rep.al_status_code,
        rep.al_status_description,
        rep.wkc,
        rep.dry_run
    );
    Ok(CommandRender {
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
        text,
    })
}

pub fn handle_reg(cli: &Cli, sub: &RegSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        RegSubcommand::List { search } => {
            let needle_norm = search
                .as_ref()
                .map(|s| s.to_ascii_lowercase().replace('_', "-"));
            let needle_raw = search.as_ref().map(|s| s.to_ascii_lowercase());
            let items: Vec<Value> = ESC_REGISTERS
                .iter()
                .filter(|r| {
                    let Some(ref n_norm) = needle_norm else {
                        return true;
                    };
                    let n_raw = needle_raw.as_deref().unwrap_or(n_norm.as_str());
                    r.symbol.to_ascii_lowercase().contains(n_raw)
                        || r.symbol
                            .to_ascii_lowercase()
                            .replace('_', "-")
                            .contains(n_norm.as_str())
                        || r.name.to_ascii_lowercase().contains(n_norm.as_str())
                        || r.description.to_ascii_lowercase().contains(n_raw)
                        || format!("0x{:04x}", r.address).contains(n_raw)
                })
                .map(|r| {
                    json!({
                        "address": format!("0x{:04X}", r.address),
                        "symbol": r.symbol,
                        "name": r.name,
                        "default_size": r.default_size,
                        "description": r.description,
                    })
                })
                .collect();
            let mut lines = vec![format!("ESC Register Catalog ({} entries):", items.len())];
            for item in &items {
                lines.push(format!(
                    "  {}  {:<18} ({}B) {:<16} -- {}",
                    item["address"].as_str().unwrap_or(""),
                    item["symbol"].as_str().unwrap_or(""),
                    item["default_size"].as_u64().unwrap_or(0),
                    item["name"].as_str().unwrap_or(""),
                    item["description"].as_str().unwrap_or(""),
                ));
            }
            Ok(CommandRender {
                json: json!({ "count": items.len(), "registers": items }),
                text: lines.join("\n"),
            })
        }

        RegSubcommand::Read {
            slave,
            config_addr,
            broadcast,
            reg,
            length,
            ty,
            bit_offset,
            bit_length,
        } => {
            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            let rep = read_esc_register(
                &mut *bus,
                &RegReadParams {
                    slave: *slave,
                    config_addr: *config_addr,
                    broadcast: *broadcast,
                    reg_spec: reg,
                    length: *length,
                    ty: *ty,
                    bit_offset: *bit_offset,
                    bit_length: *bit_length,
                    timeout,
                },
            )?;
            let text = format!(
                "ESC Reg Read [{} adp={} ado={} ({})]: raw=0x{}  value={}  WKC={}",
                rep.cmd,
                rep.adp,
                rep.address,
                rep.register_name.unwrap_or("raw"),
                rep.raw_hex,
                rep.decoded_value,
                rep.wkc
            );
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text,
            })
        }

        RegSubcommand::Write {
            slave,
            config_addr,
            broadcast,
            reg,
            value,
            ty,
            dry_run,
        } => {
            let params = RegWriteParams {
                slave: *slave,
                config_addr: *config_addr,
                broadcast: *broadcast,
                reg_spec: reg,
                value_str: value,
                ty: *ty,
                dry_run: *dry_run,
                timeout,
            };
            let rep = if *dry_run {
                write_esc_register(None, &params)?
            } else {
                let iface = require_iface(cli)?;
                let mut bus = open_transport(&iface, false)?;
                write_esc_register(Some(&mut *bus), &params)?
            };
            let text = format!(
                "ESC Reg Write [{} adp={} ado={} ({}) dry_run={}]: raw=0x{}  value={}  WKC={}",
                rep.cmd,
                rep.adp,
                rep.address,
                rep.register_name.unwrap_or("raw"),
                rep.dry_run,
                rep.raw_hex,
                rep.decoded_value,
                rep.wkc
            );
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text,
            })
        }
    }
}

pub fn handle_sdo(cli: &Cli, sub: &SdoSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        SdoSubcommand::Read {
            slave,
            index,
            subindex,
            complete_access,
            ty,
            bit_offset,
            bit_length,
            auto_preop,
        } => {
            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            let rep = sdo_read(
                &mut *bus,
                &SdoReadParams {
                    slave: *slave,
                    index: *index,
                    subindex: *subindex,
                    complete_access: *complete_access,
                    ty: *ty,
                    bit_offset: *bit_offset,
                    bit_length: *bit_length,
                    auto_preop: *auto_preop,
                    timeout,
                },
            )?;
            let text = format!(
                "CoE SDO Upload [Slave {} {}:0x{:02X} mode={} {}B]: value={} (raw=0x{})",
                rep.slave,
                rep.index,
                rep.subindex,
                rep.transfer_mode,
                rep.size_bytes,
                rep.decoded_value,
                rep.raw_hex
            );
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text,
            })
        }

        SdoSubcommand::Write {
            slave,
            index,
            subindex,
            value,
            ty,
            complete_access,
            auto_preop,
            dry_run,
        } => {
            let params = SdoWriteParams {
                slave: *slave,
                index: *index,
                subindex: *subindex,
                complete_access: *complete_access,
                ty: *ty,
                value_str: value,
                auto_preop: *auto_preop,
                dry_run: *dry_run,
                timeout,
            };
            let rep = if *dry_run {
                sdo_write(None, &params)?
            } else {
                let iface = require_iface(cli)?;
                let mut bus = open_transport(&iface, false)?;
                sdo_write(Some(&mut *bus), &params)?
            };
            let text = format!(
                "CoE SDO Download [Slave {} {}:0x{:02X} mode={} {}B dry_run={}]: value={} (raw=0x{})",
                rep.slave,
                rep.index,
                rep.subindex,
                rep.transfer_mode,
                rep.size_bytes,
                rep.dry_run,
                rep.decoded_value,
                rep.raw_hex
            );
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text,
            })
        }

        SdoSubcommand::Info {
            slave,
            index,
            entries,
            auto_preop,
        } => {
            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            let objects = query_od_info(&mut *bus, *slave, *index, *entries, *auto_preop, timeout)?;
            let mut lines = vec![format!(
                "Slave {} CoE Object Dictionary ({} object(s)):",
                slave,
                objects.len()
            )];
            for obj in &objects {
                lines.push(format!(
                    "  {}  max_sub={:<2} type={:<14} \"{}\"",
                    obj.index, obj.max_subindex, obj.datatype_name, obj.name
                ));
                for ent in &obj.entries {
                    lines.push(format!(
                        "    :{:02X}  {:>3}b  {:<14} rw={:<5} \"{}\"",
                        ent.subindex, ent.bit_length, ent.datatype_name, ent.writable, ent.name
                    ));
                }
            }
            Ok(CommandRender {
                json: json!({
                    "slave": slave,
                    "object_count": objects.len(),
                    "objects": objects,
                }),
                text: lines.join("\n"),
            })
        }
    }
}

pub fn handle_pdo(cli: &Cli, sub: &PdoSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        PdoSubcommand::Map {
            slave,
            source,
            sii_file,
            auto_preop,
        } => {
            let rep = if let Some(path) = sii_file {
                let bytes = read_file_bytes(path)?;
                load_pdo_map_from_sii_bytes(&bytes, Some(*slave))?
            } else {
                let iface = require_iface(cli)?;
                let mut bus = open_transport(&iface, false)?;
                read_slave_pdo_map(&mut *bus, *slave, *source, None, *auto_preop, timeout)?
            };
            let mut lines = vec![format!(
                "PDO Mapping (source={}, slave={:?}): RxPDO={} bits ({}B), TxPDO={} bits ({}B)",
                rep.source,
                rep.slave,
                rep.rx_total_bits,
                rep.rx_total_bytes,
                rep.tx_total_bits,
                rep.tx_total_bytes
            )];
            for pdo in rep.rx_pdos.iter().chain(rep.tx_pdos.iter()) {
                lines.push(format!(
                    "  [{} {} sm={} {}b]",
                    pdo.direction, pdo.pdo_index, pdo.sync_manager, pdo.total_bits
                ));
                for e in &pdo.entries {
                    lines.push(format!(
                        "    bit {:>3}..{:<3} ({:>2}b) {}:0x{:02x} {:<12} {:?}",
                        e.bit_offset,
                        e.bit_offset.saturating_add(e.bit_length as usize),
                        e.bit_length,
                        e.index,
                        e.subindex,
                        e.data_type_name,
                        e.name
                    ));
                }
            }
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        PdoSubcommand::Read {
            slave,
            logical_addr,
            auto_map,
            entry,
            bit_offset,
            bit_length,
            ty,
            layout,
            sii_file,
        } => {
            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            let rep = pdo_read_live(
                &mut *bus,
                &PdoReadParams {
                    slave: *slave,
                    logical_addr: *logical_addr,
                    auto_map_fmmu: *auto_map,
                    entry_filter: entry.as_deref(),
                    bit_offset: *bit_offset,
                    bit_length: *bit_length,
                    ty: *ty,
                    layout_override: layout.as_deref(),
                    sii_file: sii_file.as_deref(),
                    timeout,
                },
            )?;
            let mut lines = vec![format!(
                "PDO Read [Slave {} via {} WKC={}]: raw_inputs=0x{}",
                rep.slave, rep.mechanism, rep.wkc, rep.rx_inputs_hex
            )];
            for item in &rep.decoded_inputs {
                lines.push(format!(
                    "  {} ({}) = {}",
                    item["name"].as_str().unwrap_or(""),
                    item["entry"].as_str().unwrap_or("-"),
                    item["value"]
                ));
            }
            if let Some(ref sl) = rep.selected_slice {
                lines.push(format!("  selected_slice = {sl}"));
            }
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        PdoSubcommand::Exchange {
            slave,
            logical_addr,
            auto_map,
            set_fields,
            tx_hex,
            rx_layout,
            tx_layout,
            sii_file,
            dry_run,
        } => {
            let raw_tx_bytes = match tx_hex {
                Some(h) => Some(parse_bytes_arg(h)?),
                None => None,
            };
            let has_offline_layout = rx_layout.is_some()
                || sii_file.is_some()
                || (set_fields.is_empty() && raw_tx_bytes.is_some());
            let params = PdoExchangeParams {
                slave: *slave,
                logical_addr: *logical_addr,
                auto_map_fmmu: *auto_map,
                set_fields,
                raw_tx_bytes,
                rx_layout_override: rx_layout.as_deref(),
                tx_layout_override: tx_layout.as_deref(),
                sii_file: sii_file.as_deref(),
                dry_run: *dry_run,
                timeout,
            };
            let rep = if (*dry_run && has_offline_layout)
                || (*dry_run && optional_iface(cli).is_none())
            {
                pdo_exchange_live(None, &params)?
            } else {
                let iface = require_iface(cli)?;
                let mut bus = open_transport(&iface, false)?;
                pdo_exchange_live(Some(&mut *bus), &params)?
            };
            let mut lines = vec![format!(
                "PDO Exchange [Slave {} LRW dry_run={} WKC={}]: tx_outputs=0x{}  rx_inputs=0x{}",
                rep.slave,
                rep.dry_run,
                rep.wkc,
                rep.tx_outputs_hex.as_deref().unwrap_or(""),
                rep.rx_inputs_hex
            )];
            for item in &rep.decoded_inputs {
                lines.push(format!(
                    "  {} ({}) = {}",
                    item["name"].as_str().unwrap_or(""),
                    item["entry"].as_str().unwrap_or("-"),
                    item["value"]
                ));
            }
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        PdoSubcommand::Decode {
            hex,
            layout,
            sii_file,
            direction,
        } => {
            let bytes = parse_bytes_arg(hex)?;
            let pdo_layout =
                resolve_offline_pdo_layout(layout.as_deref(), sii_file.as_deref(), direction)?;
            let fields = decode_pdo_payload(&bytes, &pdo_layout)?;
            let mut lines = vec![format!("Decoded PDO Payload ({} bytes):", bytes.len())];
            for f in &fields {
                lines.push(format!(
                    "  {} [bit {}..{}] = {}",
                    f["name"].as_str().unwrap_or(""),
                    f["bit_offset"].as_u64().unwrap_or(0),
                    f["bit_offset"]
                        .as_u64()
                        .unwrap_or(0)
                        .saturating_add(f["bit_length"].as_u64().unwrap_or(0)),
                    f["value"]
                ));
            }
            Ok(CommandRender {
                json: json!({
                    "payload_bytes": bytes.len(),
                    "raw_hex": format_hex(&bytes),
                    "fields": fields,
                }),
                text: lines.join("\n"),
            })
        }

        PdoSubcommand::Encode {
            layout,
            sii_file,
            direction,
            set_fields,
        } => {
            let pdo_layout =
                resolve_offline_pdo_layout(layout.as_deref(), sii_file.as_deref(), direction)?;
            let mut buf = vec![0u8; pdo_layout.total_bytes().max(1)];
            encode_pdo_assignments(&mut buf, &pdo_layout, set_fields)?;
            let decoded = decode_pdo_payload(&buf, &pdo_layout)?;
            let hex_out = format_hex(&buf);
            Ok(CommandRender {
                json: json!({
                    "payload_bytes": buf.len(),
                    "raw_hex": hex_out,
                    "fields": decoded,
                }),
                text: format!("Encoded PDO ({} bytes): 0x{hex_out}", buf.len()),
            })
        }
    }
}
