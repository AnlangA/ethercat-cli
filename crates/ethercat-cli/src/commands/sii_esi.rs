use std::time::Duration;

use serde_json::{json, Value};

use crate::cli::{
    Cli, EsiBuildArgs, EsiSubcommand, EsiXmlCompileArgs, SiiReadArgs, SiiSubcommand, SiiVerifyArgs,
    SiiWriteArgs,
};
use crate::commands::bus::handle_adapters;
use crate::commands::{
    optional_iface, read_file_bytes, require_iface, write_file_bytes, CommandRender,
};
use ethercat_eeprom::esi::{
    compile_esi_device_to_sii, load_esi_catalog, select_esi_device, EsiCompileOptions,
};
use ethercat_eeprom::sii::image::{
    parse_sii_image, patch_sii_image, sii_crc8, sii_declared_size, sii_diff_words, sii_validate,
    SiiPatchSpec,
};
use ethercat_eeprom::sii::ops::{
    inspect_sii_data, read_device_sii_image, reload_device_sii, SlaveSiiSummary,
};
use ethercat_eeprom::sii::workflow::{
    build_sii_from_esi_workflow, diff_sii_sources_workflow, program_slave_eeprom_workflow,
    read_slave_eeprom_workflow, verify_slave_eeprom_workflow, write_ssc_header_file,
    SiiProgramWorkflowOptions, SiiReadWorkflowOptions, SiiSourceInput, SiiSourceSpec,
    SiiXmlSourceOptions,
};
use ethercat_master::open_transport;
use ethercat_master::scan_bus;
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::types::{parse_u16, parse_usize};

fn to_xml_source_opts(args: &EsiXmlCompileArgs) -> SiiXmlSourceOptions {
    SiiXmlSourceOptions {
        device: args.device.clone(),
        revision: args.revision,
        profile: args.profile,
        lcid: args.lcid,
        eeprom_size: args.eeprom_size,
        ignore_eeprom_size: args.ignore_eeprom_size,
        include_unassigned_pdos: args.include_unassigned_pdos,
    }
}

fn to_header_patch_spec(alias: Option<u16>, serial: Option<u32>) -> Option<SiiPatchSpec> {
    if alias.is_some() || serial.is_some() {
        Some(SiiPatchSpec {
            alias,
            serial_number: serial,
            ..Default::default()
        })
    } else {
        None
    }
}

fn run_sii_build_cmd(args: &EsiBuildArgs) -> Result<CommandRender> {
    let xml_opts = to_xml_source_opts(&args.xml_opts);
    let patch = to_header_patch_spec(args.alias, args.serial);
    let rep = build_sii_from_esi_workflow(
        &args.xml,
        &xml_opts,
        patch,
        args.output.as_deref(),
        args.header_out.as_deref(),
    )?;
    let mut lines = vec![
        format!(
            "Compiled ESI Device [{}] {} ({:?}) -> {} bytes SII ({:?} profile, CRC={}, used={}B, free={}B)",
            rep.esi_device.index,
            rep.esi_device.order_code,
            rep.esi_device.device_name,
            rep.compile_info.final_byte_size,
            rep.compile_info.profile,
            rep.compile_info.crc8_hex,
            rep.compile_info.used_bytes,
            rep.compile_info.free_bytes,
        ),
        format!(
            "  Identity : Vendor={}  Product={}  Rev={}  Serial={}  Alias={}",
            rep.identity.vendor_id,
            rep.identity.product_code,
            rep.identity.revision_number,
            rep.identity.serial_number,
            rep.identity.alias,
        ),
        format!(
            "  Strings  : interned={}/{} (dropped_by_budget={})",
            rep.compile_info.strings_interned,
            rep.compile_info.total_unique_candidate_strings,
            rep.compile_info.strings_dropped_by_budget,
        ),
    ];
    if let Some(ref b) = rep.output_bin {
        lines.push(format!("  SII Bin  : {b}"));
    }
    if let Some(ref h) = rep.output_header {
        lines.push(format!("  SSC Hdr  : {h}"));
    }
    Ok(CommandRender {
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
        text: lines.join("\n"),
    })
}

fn run_sii_read_cmd(cli: &Cli, args: &SiiReadArgs, timeout: Duration) -> Result<CommandRender> {
    if args.slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let rep = read_slave_eeprom_workflow(
        &mut *bus,
        &SiiReadWorkflowOptions {
            slave: args.slave,
            offset: args.offset,
            length: args.length,
            output_bin: args.output.as_deref(),
            output_header: args.header_out.as_deref(),
            catalog_xml: args.xml.as_deref(),
            lcid: args.lcid,
            decode: args.decode,
            timeout,
        },
    )?;

    let mut text = format!(
        "Read {} bytes from Slave {} SII EEPROM (offset=0x{:04X})",
        rep.size_bytes, rep.slave, rep.offset
    );
    if let Some(ref p) = rep.output_file {
        text.push_str(&format!(" -> saved to '{p}'"));
    }
    if let Some(ref h) = rep.header_out {
        text.push_str(&format!(" (SSC header: '{h}')"));
    }
    if let Some(ref s) = rep.identity {
        text.push_str(&format!(
            "\n  Vendor={}  Product={}  Rev={}  Serial={}  Alias={}  CRC_OK={}  Name={:?}",
            s.vendor_id,
            s.product_code,
            s.revision_number,
            s.serial_number,
            s.alias,
            s.crc_ok,
            s.name
        ));
    } else {
        text.push_str(&format!("\n  Hex: {}", rep.raw_hex));
    }
    if let Some(ref m) = rep.esi_match {
        text.push_str(&format!(
            "\n  ESI Match ({}) : {} ({:?}) from '{}'",
            m.match_kind, m.device.order_code, m.device.device_name, m.device.source_file
        ));
    }

    Ok(CommandRender {
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
        text,
    })
}

fn run_sii_verify_cmd(cli: &Cli, args: &SiiVerifyArgs, timeout: Duration) -> Result<CommandRender> {
    if args.slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let source = SiiSourceSpec::from_file_or_xml(
        args.file.as_deref(),
        args.xml.as_deref(),
        to_xml_source_opts(&args.xml_opts),
        to_header_patch_spec(args.alias, args.serial),
    )?;
    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let rep = verify_slave_eeprom_workflow(&mut *bus, args.slave, &source, timeout)?;
    Ok(CommandRender {
        text: format!(
            "VERIFY OK: Slave {} SII EEPROM ({} bytes) matches '{}' byte-for-byte.",
            rep.slave, rep.size_bytes, rep.source_label
        ),
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
    })
}

fn run_sii_write_cmd(cli: &Cli, args: &SiiWriteArgs, timeout: Duration) -> Result<CommandRender> {
    if args.slave == 0 {
        return Err(CliError::Usage("slave position must be >= 1".into()));
    }
    let source = SiiSourceSpec::from_file_or_xml(
        args.file.as_deref(),
        args.xml.as_deref(),
        to_xml_source_opts(&args.xml_opts),
        to_header_patch_spec(args.alias, args.serial),
    )?;
    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let rep = program_slave_eeprom_workflow(
        &mut *bus,
        &SiiProgramWorkflowOptions {
            slave: args.slave,
            source: &source,
            execute: args.execute,
            backup_path: args.backup.as_deref(),
            confirm_token: args.confirm.as_deref(),
            reload: args.reload,
            check_esc_config: args.check_esc_config,
            timeout,
        },
    )?;

    let wr = &rep.write_report;
    let mut text = if wr.dry_run {
        format!(
            "DRY-RUN ONLY (zero EEPROM words written): Slave {} current={}B, proposed={}B ({}), differing_words={}.\n\
             To execute, pass: --execute --backup <new-backup.bin> --confirm WRITE-SLAVE-{}",
            wr.slave, wr.current_size_bytes, wr.proposed_size_bytes, rep.source_label, wr.differing_words, wr.slave
        )
    } else {
        format!(
            "WRITE & VERIFY OK: Slave {} wrote {} changed word(s) ({} bytes from '{}'), backup saved to '{}'.",
            wr.slave,
            wr.written_words,
            wr.proposed_size_bytes,
            rep.source_label,
            wr.backup_path.as_deref().unwrap_or("-")
        )
    };
    if let Some(ref chk) = wr.esc_config_check {
        text.push_str(&format!(
            "\n  ESC PDI Check : matches={} (ESC 0x0140={} vs SII={}, ESC 0x0150={} vs SII={})",
            chk.matches,
            chk.esc_pdi_control,
            chk.proposed_pdi_control,
            chk.esc_pdi_config,
            chk.proposed_pdi_config
        ));
    }
    Ok(CommandRender {
        json: serde_json::to_value(&rep).unwrap_or(Value::Null),
        text,
    })
}

pub fn handle_sii(cli: &Cli, sub: &SiiSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        SiiSubcommand::List => {
            if let Some(iface) = optional_iface(cli) {
                let mut bus = open_transport(&iface, false)?;
                let rep = scan_bus(&mut *bus, false, true, timeout)?;
                let mut lines = vec![format!(
                    "SII EEPROM Slave Inventory on '{}' ({} slave(s)):",
                    rep.interface, rep.slave_count
                )];
                let mut slaves_json = Vec::with_capacity(rep.slaves.len());
                for s in &rep.slaves {
                    if let Some(ref info) = s.sii {
                        lines.push(format!(
                            "  [Slave {:>2}] Name={:?}  Vendor={}  Product={}  Rev={}  Serial={}  Alias={}  Size={}B  CRC_OK={}  State={}  Mbx=[{}]",
                            s.slave,
                            info.name.as_deref().unwrap_or("-"),
                            info.vendor_id,
                            info.product_code,
                            info.revision_number,
                            info.serial_number,
                            info.alias,
                            info.size_bytes,
                            info.crc_ok,
                            s.al_state,
                            s.mbx_protocols.join(",")
                        ));
                    } else {
                        lines.push(format!(
                            "  [Slave {:>2}] SII unavailable  State={}  ESC={}",
                            s.slave, s.al_state, s.esc_type
                        ));
                    }
                    slaves_json.push(json!({
                        "slave": s.slave,
                        "station_addr": s.station_addr,
                        "al_state": s.al_state,
                        "mbx_protocols": s.mbx_protocols,
                        "sii": s.sii,
                    }));
                }
                Ok(CommandRender {
                    json: json!({
                        "mode": "slaves",
                        "interface": rep.interface,
                        "slave_count": rep.slave_count,
                        "slaves": slaves_json,
                    }),
                    text: lines.join("\n"),
                })
            } else {
                handle_adapters(true)
            }
        }

        SiiSubcommand::Build(args) => run_sii_build_cmd(args),
        SiiSubcommand::Read(args) => run_sii_read_cmd(cli, args, timeout),
        SiiSubcommand::Verify(args) => run_sii_verify_cmd(cli, args, timeout),
        SiiSubcommand::Write(args) => run_sii_write_cmd(cli, args, timeout),

        SiiSubcommand::Inspect {
            file,
            slave,
            header_out,
        } => {
            let (raw, src_label) = if let Some(path) = file {
                let b = read_file_bytes(path)?;
                (b, format!("file '{}'", path.display()))
            } else {
                if *slave == 0 {
                    return Err(CliError::Usage("slave position must be >= 1".into()));
                }
                let iface = require_iface(cli)?;
                let mut bus = open_transport(&iface, false)?;
                let b = read_device_sii_image(&mut *bus, *slave, timeout)?;
                (b, format!("slave {slave} on '{iface}'"))
            };

            let decoded = inspect_sii_data(&raw)?;
            if let Some(hdr_path) = header_out {
                let info = format!("Exported from {src_label}");
                write_ssc_header_file(hdr_path, &raw, Some(&info))?;
            }
            let mut lines = vec![
                format!(
                    "SII Image Inspection ({src_label}, {} bytes, declared={} bytes):",
                    decoded.actual_size_bytes, decoded.header.declared_size_bytes
                ),
                format!(
                    "  Identity : Vendor={}  Product={}  Revision={}  Serial={}  Alias={}",
                    decoded.header.vendor_id_hex,
                    decoded.header.product_code_hex,
                    decoded.header.revision_number_hex,
                    decoded.header.serial_number_hex,
                    decoded.header.configured_station_alias_hex
                ),
                format!(
                    "  CRC-8    : actual={} expected={} ok={}",
                    decoded.header.crc_byte, decoded.header.crc_expected, decoded.header.crc_ok
                ),
                format!(
                    "  Mailbox  : StdRx={} ({}B)  StdTx={} ({}B)  Protocols=[{}]",
                    decoded.header.std_rx_mbx_offset,
                    decoded.header.std_rx_mbx_size,
                    decoded.header.std_tx_mbx_offset,
                    decoded.header.std_tx_mbx_size,
                    decoded.header.mbx_protocols.join(", ")
                ),
                format!("  Strings  : {:?}", decoded.categories.strings),
                format!(
                    "  TLV Cats : {} categories (FMMUs={}, SyncManagers={}, TxPDOs={}, RxPDOs={}, DC={})",
                    decoded.categories.category_headers.len(),
                    decoded.categories.fmmus.len(),
                    decoded.categories.sync_managers.len(),
                    decoded.categories.tx_pdos.len(),
                    decoded.categories.rx_pdos.len(),
                    decoded.categories.dc_modes.len()
                ),
            ];
            if let Some(hdr_path) = header_out {
                lines.push(format!("  SSC Hdr  : '{}'", hdr_path.display()));
            }
            for sm in &decoded.categories.sync_managers {
                lines.push(format!(
                    "    [SM{}] start={} len={} ctrl={} enabled={} type={}",
                    sm.index,
                    sm.physical_start_address,
                    sm.length,
                    sm.control_register,
                    sm.enabled,
                    sm.sm_type_name
                ));
            }
            for pdo in decoded
                .categories
                .rx_pdos
                .iter()
                .chain(decoded.categories.tx_pdos.iter())
            {
                lines.push(format!(
                    "    [{} {}] sm={} bits={} name={:?} entries={}",
                    pdo.direction,
                    pdo.pdo_index,
                    pdo.sync_manager,
                    pdo.total_bits,
                    pdo.name,
                    pdo.entries.len()
                ));
            }
            Ok(CommandRender {
                json: serde_json::to_value(&decoded).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        SiiSubcommand::Validate { file } => {
            let raw = read_file_bytes(file)?;
            sii_validate(&raw)?;
            let parsed = parse_sii_image(&raw)?;
            let summary = SlaveSiiSummary::from_image(1, &raw);
            let json_val = json!({
                "valid": true,
                "file": file.display().to_string(),
                "size_bytes": raw.len(),
                "declared_size_bytes": sii_declared_size(&raw),
                "crc_byte": parsed.header.crc_byte,
                "identity": summary,
                "category_count": parsed.categories.category_headers.len(),
            });
            let text = format!(
                "VALID SII IMAGE: '{}' ({} bytes, CRC {} OK, {} TLV categories, Vendor={}, Product={})",
                file.display(),
                raw.len(),
                parsed.header.crc_byte,
                parsed.categories.category_headers.len(),
                summary.vendor_id,
                summary.product_code
            );
            Ok(CommandRender {
                json: json_val,
                text,
            })
        }

        SiiSubcommand::Diff {
            left,
            right,
            left_device,
            right_device,
            left_revision,
            right_revision,
            profile,
            lcid,
            ignore_eeprom_size,
            max_diffs,
        } => {
            let left_spec = SiiSourceSpec {
                input: SiiSourceInput::from_auto_path(
                    left.clone(),
                    SiiXmlSourceOptions {
                        device: left_device.clone(),
                        revision: *left_revision,
                        profile: *profile,
                        lcid: *lcid,
                        eeprom_size: None,
                        ignore_eeprom_size: *ignore_eeprom_size,
                        include_unassigned_pdos: false,
                    },
                )?,
                patch: None,
            };
            let right_spec = SiiSourceSpec {
                input: SiiSourceInput::from_auto_path(
                    right.clone(),
                    SiiXmlSourceOptions {
                        device: right_device.clone(),
                        revision: *right_revision,
                        profile: *profile,
                        lcid: *lcid,
                        eeprom_size: None,
                        ignore_eeprom_size: *ignore_eeprom_size,
                        include_unassigned_pdos: false,
                    },
                )?,
                patch: None,
            };
            let rep = diff_sii_sources_workflow(&left_spec, &right_spec, *max_diffs)?;
            let mut lines = vec![format!(
                "SII Diff: left='{}' ({}B) vs right='{}' ({}B) -> {} differing 16-bit word(s)",
                rep.left_source,
                rep.left_size_bytes,
                rep.right_source,
                rep.right_size_bytes,
                rep.differing_words
            )];
            for d in &rep.diffs {
                lines.push(format!(
                    "  word {:>4} (byte {}): {:?} -> {:?}",
                    d.word_addr, d.byte_offset, d.left_word, d.right_word
                ));
            }
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        SiiSubcommand::Patch {
            input,
            output,
            alias,
            vendor_id,
            product_code,
            revision,
            serial,
            set_words,
            no_recalc_crc,
        } => {
            let src = read_file_bytes(input)?;
            let mut word_writes = Vec::new();
            for item in set_words {
                let (w_str, v_str) = item.split_once('=').ok_or_else(|| {
                    CliError::Usage(format!(
                        "invalid `--set-word '{item}'`; expected `<WORD_ADDR>=<U16_VAL>`"
                    ))
                })?;
                let w = parse_usize(w_str).map_err(CliError::Format)?;
                let v = parse_u16(v_str).map_err(CliError::Format)?;
                word_writes.push((w, v));
            }
            let patched = patch_sii_image(
                &src,
                &SiiPatchSpec {
                    alias: *alias,
                    vendor_id: *vendor_id,
                    product_code: *product_code,
                    revision_number: *revision,
                    serial_number: *serial,
                    word_writes,
                    recalculate_crc: !*no_recalc_crc,
                },
            )?;
            write_file_bytes(output, &patched)?;
            let (diff_cnt, diffs) = sii_diff_words(&src, &patched, 32);
            let crc_byte = patched.get(14).copied().unwrap_or(0);
            let crc_ok = patched.len() >= 15 && sii_crc8(&patched[0..14]) == crc_byte;
            let summary = SlaveSiiSummary::from_image(1, &patched);
            Ok(CommandRender {
                json: json!({
                    "input": input.display().to_string(),
                    "output": output.display().to_string(),
                    "size_bytes": patched.len(),
                    "changed_words": diff_cnt,
                    "crc_byte": format!("0x{crc_byte:02X}"),
                    "crc_ok": crc_ok,
                    "identity": summary,
                    "diffs": diffs,
                }),
                text: format!(
                    "Patched SII image saved to '{}' ({} changed word(s), CRC=0x{crc_byte:02X} ok={crc_ok}).",
                    output.display(),
                    diff_cnt,
                ),
            })
        }

        SiiSubcommand::Reload { slave, dry_run } => {
            if *slave == 0 {
                return Err(CliError::Usage("slave position must be >= 1".into()));
            }
            if *dry_run {
                return Ok(CommandRender {
                    json: json!({
                        "slave": slave,
                        "dry_run": true,
                        "reloaded": false,
                        "register": "0x0502",
                        "command": "0x0400",
                    }),
                    text: format!(
                        "DRY-RUN ONLY: would claim PDI EEPROM control on Slave {slave} and issue RELOAD (0x0400 -> 0x0502)."
                    ),
                });
            }
            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            reload_device_sii(&mut *bus, *slave, timeout)?;
            Ok(CommandRender {
                json: json!({
                    "slave": slave,
                    "interface": iface,
                    "dry_run": false,
                    "reloaded": true,
                }),
                text: format!(
                    "RELOAD OK: Slave {slave} ESC reloaded SII EEPROM configuration on '{iface}'."
                ),
            })
        }
    }
}

pub fn handle_esi(cli: &Cli, sub: &EsiSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        EsiSubcommand::List { xml, lcid, search } => {
            let catalog = load_esi_catalog(xml, *lcid)?;
            let needle = search.as_ref().map(|s| s.to_ascii_lowercase());
            let summaries: Vec<_> = catalog
                .devices
                .iter()
                .map(|d| d.summary())
                .filter(|s| {
                    needle.as_ref().is_none_or(|n| {
                        s.order_code.to_ascii_lowercase().contains(n)
                            || s.device_name.to_ascii_lowercase().contains(n)
                            || s.group_type.to_ascii_lowercase().contains(n)
                            || s.product_code.to_ascii_lowercase().contains(n)
                            || s.vendor_name.to_ascii_lowercase().contains(n)
                    })
                })
                .collect();

            let mut lines = vec![format!(
                "ESI Catalog '{}' (scanned {} XML file(s), {} matching device(s)):",
                xml.display(),
                catalog.files_loaded.len(),
                summaries.len()
            )];
            for s in &summaries {
                lines.push(format!(
                    "  [{:>3}] {:<20} Product={} Rev={} Size={}B SMs={} PDOs=({}tx/{}rx) Mbx=[{}] -- {:?}",
                    s.index,
                    s.order_code,
                    s.product_code,
                    s.revision_number,
                    s.eeprom_byte_size,
                    s.sm_count,
                    s.assigned_tx_pdo_count,
                    s.assigned_rx_pdo_count,
                    s.mailbox_protocols.join(","),
                    s.device_name,
                ));
            }
            Ok(CommandRender {
                json: json!({
                    "xml": xml.display().to_string(),
                    "files_scanned": catalog.files_loaded.len(),
                    "count": summaries.len(),
                    "devices": summaries,
                }),
                text: lines.join("\n"),
            })
        }

        EsiSubcommand::Inspect { xml, xml_opts } => {
            let catalog = load_esi_catalog(xml, xml_opts.lcid)?;
            let dev = select_esi_device(
                &catalog.devices,
                xml_opts.device.as_deref(),
                xml_opts.revision,
            )?;
            let compiled = compile_esi_device_to_sii(
                dev,
                &EsiCompileOptions {
                    profile: xml_opts.profile,
                    eeprom_size_override: xml_opts.eeprom_size,
                    ignore_eeprom_size: xml_opts.ignore_eeprom_size,
                    include_unassigned_pdos: xml_opts.include_unassigned_pdos,
                    ..Default::default()
                },
            )?;
            let decoded = parse_sii_image(&compiled.bytes)?;
            let summary = dev.summary();
            let lines = [
                format!(
                    "ESI Device [{}] {} ({:?}) from '{}':",
                    summary.index, summary.order_code, summary.device_name, summary.source_file
                ),
                format!(
                    "  Vendor   : {} ({})  |  Group: {} ({:?})",
                    summary.vendor_id, summary.vendor_name, summary.group_type, summary.group_name
                ),
                format!(
                    "  Identity : Product={}  Revision={}  Physics={:?}  EBusCurrent={}mA",
                    summary.product_code,
                    summary.revision_number,
                    summary.physics,
                    dev.current_on_ebus_ma
                ),
                format!(
                    "  Hardware : FMMUs={:?}  SyncManagers={}  TxPDOs={} ({} assigned)  RxPDOs={} ({} assigned)  DC OpModes={}",
                    dev.fmmus,
                    summary.sm_count,
                    summary.total_tx_pdo_count,
                    summary.assigned_tx_pdo_count,
                    summary.total_rx_pdo_count,
                    summary.assigned_rx_pdo_count,
                    summary.dc_mode_count
                ),
                format!(
                    "  SII Spec : mode={}  profile={:?}  size={}B (used={}B, free={}B)  CRC={}  strings={}/{}",
                    compiled.mode,
                    compiled.profile,
                    compiled.final_byte_size,
                    compiled.used_bytes,
                    compiled.free_bytes,
                    compiled.crc8_hex,
                    compiled.strings_interned,
                    compiled.total_unique_candidate_strings
                ),
            ];
            Ok(CommandRender {
                json: json!({
                    "esi_device": summary,
                    "device": dev,
                    "compile_info": compiled,
                    "decoded": decoded,
                }),
                text: lines.join("\n"),
            })
        }

        EsiSubcommand::Build(args) => run_sii_build_cmd(args),
        EsiSubcommand::Burn(args) => run_sii_write_cmd(cli, args, timeout),
        EsiSubcommand::Read(args) => run_sii_read_cmd(cli, args, timeout),
        EsiSubcommand::Verify(args) => run_sii_verify_cmd(cli, args, timeout),
    }
}
