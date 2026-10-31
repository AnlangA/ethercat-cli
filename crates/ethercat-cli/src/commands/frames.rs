use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::cli::{Cli, DatagramArgs, DissectArgs, FieldsCatalogFilter, FrameSubcommand};
use crate::commands::{require_iface, resolve_offline_pdo_layout, write_file_bytes, CommandRender};
use crate::selector::{FieldSelectorDoc, WIRESHARK_FIELD_CATALOG};
use ethercat_master::open_transport;
use ethercat_master::{slave_aiadr, EC_NODEOFFSET};
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::{
    al_status_code_description, sdo_abort_description, EcatCmd, ESC_REGISTERS,
};
use ethercat_wire::protocol::dissector::{dissect_frame, may_contain_ethercat, DissectOptions};
use ethercat_wire::protocol::frame::{parse_dlpdu_datagram_refs, EcatFrameBuilder, RawDatagram};
use ethercat_wire::protocol::pcap_io::{for_each_frame_in_file, write_pcap_file, FrameInputKind};
use ethercat_wire::types::{
    decode_typed_value, extract_bits_le, format_hex, parse_bytes_arg, parse_mac, parse_u16,
    parse_u32, parse_u8, parse_usize,
};

fn parse_bool_modifier(s: &str, name: &str) -> Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        other => Err(CliError::Format(format!(
            "invalid boolean value '{other}' for `{name}` (expected 0, 1, true, or false)"
        ))),
    }
}

pub fn parse_subframe_spec(spec: &str, auto_idx: u8) -> Result<RawDatagram> {
    let mut main_part = spec.trim();
    let mut idx_override: Option<u8> = None;
    let mut wkc_override: Option<u16> = None;
    let mut irq_override: Option<u16> = None;
    let mut circ_override: Option<bool> = None;
    let mut more_override: Option<bool> = None;

    while let Some(at_pos) = main_part.rfind('@') {
        let tail = &main_part[at_pos + 1..];
        let Some((k, v)) = tail.split_once('=') else {
            break;
        };
        match k.trim().to_ascii_lowercase().as_str() {
            "idx" => idx_override = Some(parse_u8(v).map_err(CliError::Format)?),
            "wkc" => wkc_override = Some(parse_u16(v).map_err(CliError::Format)?),
            "irq" => irq_override = Some(parse_u16(v).map_err(CliError::Format)?),
            "c" | "circulating" => circ_override = Some(parse_bool_modifier(v, "@c")?),
            "m" | "more" | "next" => more_override = Some(parse_bool_modifier(v, "@m")?),
            other => {
                return Err(CliError::Usage(format!(
                    "unknown subframe modifier '@{other}={v}' in `{spec}` (supported: @idx=, @wkc=, @irq=, @c=, @m=)"
                )));
            }
        }
        main_part = main_part[..at_pos].trim_end();
    }

    let mut parts = main_part.splitn(3, ':');
    let cmd_str = parts.next().unwrap_or("").trim();
    let addr_str = parts.next().ok_or_else(|| {
        CliError::Usage(format!(
            "invalid `--subframe '{spec}'`; expected `<CMD>:<ADDR>:<HEX_OR_zeros:N>`"
        ))
    })?;
    let data_str = parts.next().ok_or_else(|| {
        CliError::Usage(format!(
            "invalid `--subframe '{spec}'`; missing `:<HEX_OR_zeros:N>` payload segment"
        ))
    })?;

    let cmd = <EcatCmd as clap::ValueEnum>::from_str(cmd_str, true).map_err(|_| {
        CliError::Usage(format!("unknown EtherCAT command '{cmd_str}' in `{spec}`"))
    })?;

    let data = if let Some(n_str) = data_str.trim().strip_prefix("zeros:") {
        let n = parse_usize(n_str).map_err(CliError::Format)?;
        vec![0u8; n]
    } else if data_str.trim().is_empty() {
        Vec::new()
    } else {
        parse_bytes_arg(data_str)?
    };

    let idx = idx_override.unwrap_or(auto_idx);
    let mut dg = if cmd.is_logical() {
        let lad = parse_u32(addr_str).map_err(CliError::Format)?;
        RawDatagram::new_logical(cmd, idx, lad, data)
    } else {
        let (adp_s, ado_s) = addr_str.split_once(',').ok_or_else(|| {
            CliError::Usage(format!(
                "positioned command `{}` requires `<ADP>,<ADO>` in `{spec}` (e.g. `0x0000,0x0130`)",
                cmd.mnemonic()
            ))
        })?;
        let adp = parse_u16(adp_s).map_err(CliError::Format)?;
        let ado = parse_u16(ado_s).map_err(CliError::Format)?;
        RawDatagram::new_positioned(cmd, idx, adp, ado, data)
    };
    if let Some(wkc) = wkc_override {
        dg.wkc = wkc;
    }
    if let Some(irq) = irq_override {
        dg.irq = irq;
    }
    if let Some(c) = circ_override {
        dg.circulating = c;
    }
    if let Some(m) = more_override {
        dg.more = m;
        dg.more_override = Some(m);
    }
    Ok(dg)
}

pub fn handle_frame(cli: &Cli, sub: &FrameSubcommand, timeout: Duration) -> Result<CommandRender> {
    match sub {
        FrameSubcommand::Build {
            dst_mac,
            src_mac,
            vlan,
            pad,
            subframes,
            output,
        } => {
            let mut builder = EcatFrameBuilder {
                dst_mac: parse_mac(dst_mac)?,
                src_mac: parse_mac(src_mac)?,
                vlan_id: *vlan,
                pad_to_min_ethernet: *pad,
                ..Default::default()
            };
            for (i, sf_spec) in subframes.iter().enumerate() {
                let auto_idx = u8::try_from(i.saturating_add(1)).map_err(|_| {
                    CliError::Usage(format!(
                        "too many subframes ({}) for automatic 1-byte datagram index; maximum is 255",
                        subframes.len()
                    ))
                })?;
                builder.add_datagram(parse_subframe_spec(sf_spec, auto_idx)?);
            }
            let frame_bytes = builder.build()?;
            if let Some(path) = output {
                write_file_bytes(path, &frame_bytes)?;
            }
            let dissected = dissect_frame(&frame_bytes, &DissectOptions::default())?;
            let hex_str = format_hex(&frame_bytes);
            Ok(CommandRender {
                json: json!({
                    "wire_len": frame_bytes.len(),
                    "frame_hex": hex_str,
                    "output_file": output.as_ref().map(|p| p.display().to_string()),
                    "dissected": dissected,
                }),
                text: format!(
                    "Built EtherCAT Frame ({} bytes, {} subframe(s)): {hex_str}",
                    frame_bytes.len(),
                    dissected.datagrams.len()
                ),
            })
        }

        FrameSubcommand::Send {
            hex,
            file,
            no_wait_rx,
            dry_run,
        } => {
            let (tx_bytes, tx_dissected) = if let Some(h) = hex {
                let raw = parse_bytes_arg(h)?;
                let dissected = dissect_frame(&raw, &DissectOptions::default())?;
                (raw, dissected)
            } else if let Some(path) = file {
                let mut single_raw: Option<Vec<u8>> = None;
                let mut first_ecat: Option<(
                    Vec<u8>,
                    ethercat_wire::protocol::dissector::DissectedFrame,
                )> = None;
                let mut skipped_non_ecat = 0usize;
                let resolved_kind = for_each_frame_in_file(path, FrameInputKind::Auto, |rec| {
                    if !may_contain_ethercat(&rec.data, false) {
                        if single_raw.is_none() {
                            single_raw = Some(rec.data);
                        }
                        skipped_non_ecat += 1;
                        return Ok(true);
                    }
                    match dissect_frame(&rec.data, &DissectOptions::default()) {
                        Ok(df) => {
                            first_ecat = Some((rec.data, df));
                            Ok(false)
                        }
                        Err(_) => {
                            if single_raw.is_none() {
                                single_raw = Some(rec.data);
                            }
                            skipped_non_ecat += 1;
                            Ok(true)
                        }
                    }
                })?;
                if let Some(found) = first_ecat {
                    found
                } else if matches!(resolved_kind, FrameInputKind::Bin | FrameInputKind::Hex) {
                    let raw = single_raw.unwrap_or_default();
                    let df = dissect_frame(&raw, &DissectOptions::default())?;
                    (raw, df)
                } else {
                    return Err(CliError::Format(format!(
                        "no valid 0x88A4 EtherCAT frames found in '{}' (inspected {} packet(s))",
                        path.display(),
                        skipped_non_ecat
                    )));
                }
            } else {
                return Err(CliError::Usage(
                    "provide either `--hex <HEX>` or `--file <FILE>`".into(),
                ));
            };
            if *dry_run {
                return Ok(CommandRender {
                    json: json!({
                        "dry_run": true,
                        "tx_wire_len": tx_bytes.len(),
                        "tx_hex": format_hex(&tx_bytes),
                        "tx_dissected": tx_dissected,
                    }),
                    text: format!(
                        "DRY-RUN Frame Send ({} bytes, {} subframe(s)): {}",
                        tx_bytes.len(),
                        tx_dissected.datagrams.len(),
                        format_hex(&tx_bytes)
                    ),
                });
            }

            let iface = require_iface(cli)?;
            let mut bus = open_transport(&iface, false)?;
            if *no_wait_rx {
                bus.send_raw_frame(&tx_bytes)?;
                return Ok(CommandRender {
                    json: json!({
                        "sent": true,
                        "waited_rx": false,
                        "tx_wire_len": tx_bytes.len(),
                        "tx_hex": format_hex(&tx_bytes),
                        "tx_dissected": tx_dissected,
                    }),
                    text: format!(
                        "Sent {} byte frame on '{iface}' (no-wait-rx).",
                        tx_bytes.len()
                    ),
                });
            }

            let expected_idx = tx_dissected.datagrams.first().map(|d| d.idx);
            let rx_bytes = bus.transact_frame(&tx_bytes, expected_idx, timeout)?;
            let rx_dissected = dissect_frame(&rx_bytes, &DissectOptions::default())?;
            let wkc_summary: Vec<String> = rx_dissected
                .datagrams
                .iter()
                .map(|d| format!("{}:WKC={}", d.cmd_mnemonic, d.wkc))
                .collect();
            Ok(CommandRender {
                json: json!({
                    "sent": true,
                    "waited_rx": true,
                    "tx_hex": format_hex(&tx_bytes),
                    "rx_hex": format_hex(&rx_bytes),
                    "rx_dissected": rx_dissected,
                }),
                text: format!(
                    "Transacted Frame on '{iface}': RX {} bytes [{}]",
                    rx_bytes.len(),
                    wkc_summary.join(", ")
                ),
            })
        }
    }
}

pub fn handle_datagram(cli: &Cli, args: &DatagramArgs, timeout: Duration) -> Result<CommandRender> {
    let payload = if let Some(ref d) = args.data {
        parse_bytes_arg(d)?
    } else {
        vec![0u8; args.len.unwrap_or(2)]
    };

    let effective_adp = if let Some(sl) = args.slave {
        if sl == 0 {
            0x0000
        } else if args.cmd.is_auto_increment() {
            slave_aiadr(sl)
        } else {
            EC_NODEOFFSET + sl
        }
    } else {
        args.adp
    };

    if args.dry_run {
        let dg = if args.cmd.is_logical() {
            RawDatagram::new_logical(args.cmd, 0x01, args.logical_addr, payload)
        } else {
            RawDatagram::new_positioned(args.cmd, 0x01, effective_adp, args.ado, payload)
        };
        let mut builder = EcatFrameBuilder::new();
        builder.add_datagram(dg);
        let tx_frame = builder.build()?;
        let tx_dissected = dissect_frame(&tx_frame, &DissectOptions::default())?;
        return Ok(CommandRender {
            json: json!({
                "dry_run": true,
                "cmd": args.cmd.mnemonic(),
                "tx_hex": format_hex(&tx_frame),
                "tx_dissected": tx_dissected,
            }),
            text: format!(
                "DRY-RUN Datagram {}: tx_frame={}",
                args.cmd.mnemonic(),
                format_hex(&tx_frame)
            ),
        });
    }

    let iface = require_iface(cli)?;
    let mut bus = open_transport(&iface, false)?;
    let idx = bus.next_index();
    let mut live_builder = EcatFrameBuilder::new();
    let live_dg = if args.cmd.is_logical() {
        RawDatagram::new_logical(args.cmd, idx, args.logical_addr, payload)
    } else {
        RawDatagram::new_positioned(args.cmd, idx, effective_adp, args.ado, payload)
    };
    live_builder.add_datagram(live_dg);
    let live_tx = live_builder.build()?;
    let rx_frame = bus.transact_frame(&live_tx, Some(idx), timeout)?;
    let rx_dissected = dissect_frame(&rx_frame, &DissectOptions::default())?;
    let parsed_dgs = parse_dlpdu_datagram_refs(&rx_frame)?;
    let first = parsed_dgs
        .into_iter()
        .next()
        .ok_or_else(|| CliError::Protocol("empty DLPDU datagram response".into()))?;

    if let Some(exp) = args.expect_wkc {
        if first.wkc != exp {
            return Err(CliError::Mismatch(format!(
                "datagram {} Working Counter mismatch: expected WKC={exp}, actual WKC={}",
                args.cmd.mnemonic(),
                first.wkc
            )));
        }
    }

    let (decoded_value, bit_slice) = if let Some(boff) = args.bit_offset {
        let blen = args
            .bit_length
            .or_else(|| args.ty.default_bit_len())
            .unwrap_or(1);
        let sliced = extract_bits_le(first.data, boff, blen)?;
        let val = decode_typed_value(&sliced, args.ty, Some(blen))?;
        (
            val.clone(),
            Some(json!({
                "bit_offset": boff,
                "bit_length": blen,
                "raw_hex": format_hex(&sliced),
                "value": val,
            })),
        )
    } else {
        (decode_typed_value(first.data, args.ty, None)?, None)
    };

    Ok(CommandRender {
        json: json!({
            "cmd": args.cmd.mnemonic(),
            "wkc": first.wkc,
            "raw_hex": format_hex(first.data),
            "decoded_value": decoded_value,
            "bit_slice": bit_slice,
            "rx_dissected": rx_dissected,
        }),
        text: format!(
            "Datagram {} -> WKC={}  data=0x{}  decoded={}",
            args.cmd.mnemonic(),
            first.wkc,
            format_hex(first.data),
            decoded_value
        ),
    })
}

fn build_dissect_options(
    bare: bool,
    force_mailbox: bool,
    pdo_layout: Option<&str>,
    sii_pdo: Option<&Path>,
    pdo_dir: &str,
) -> Result<DissectOptions> {
    let layout = if pdo_layout.is_some() || sii_pdo.is_some() {
        Some(resolve_offline_pdo_layout(pdo_layout, sii_pdo, pdo_dir)?)
    } else {
        None
    };
    Ok(DissectOptions {
        bare_ecat: bare,
        force_mailbox,
        pdo_layout: layout,
    })
}

fn summarize_dissected_frame_line(
    idx: usize,
    f: &ethercat_wire::protocol::dissector::DissectedFrame,
) -> String {
    let encap = f
        .ethernet
        .as_ref()
        .map(|e| format!("{}->{} ({})", e.src_mac, e.dst_mac, e.ethertype))
        .unwrap_or_else(|| "bare-ecat".into());
    let dgs: Vec<String> = f
        .datagrams
        .iter()
        .map(|d| {
            let addr = d.logical_addr.clone().unwrap_or_else(|| {
                format!(
                    "{}:{}",
                    d.adp_hex.as_deref().unwrap_or("-"),
                    d.ado_hex.as_deref().unwrap_or("-")
                )
            });
            let mbx_tag = d
                .mailbox
                .as_ref()
                .map(|m| format!(" mbx={}", m.mbx_type_name))
                .unwrap_or_default();
            format!(
                "{}({}) len={} WKC={}{}",
                d.cmd_mnemonic, addr, d.length, d.wkc, mbx_tag
            )
        })
        .collect();
    format!(
        "[Frame #{idx}] {}B {encap} | {}",
        f.frame_wire_len,
        if dgs.is_empty() {
            f.ecat_header["type_name"]
                .as_str()
                .unwrap_or("")
                .to_string()
        } else {
            dgs.join(" ; ")
        }
    )
}

pub fn handle_dissect(args: &DissectArgs) -> Result<CommandRender> {
    let opts = build_dissect_options(
        args.bare,
        args.force_mailbox,
        args.pdo_layout.as_deref(),
        args.sii_pdo.as_deref(),
        &args.pdo_dir,
    )?;

    if let Some(ref hex_str) = args.hex {
        let raw = parse_bytes_arg(hex_str)?;
        let frame = dissect_frame(&raw, &opts)?;
        let line = summarize_dissected_frame_line(0, &frame);
        return Ok(CommandRender {
            json: serde_json::to_value(&frame).unwrap_or(Value::Null),
            text: line,
        });
    }

    let path = args.file.as_ref().ok_or_else(|| {
        CliError::Usage("provide either `--hex <HEX>` or `--file <PATH>` to `dissect`".into())
    })?;

    let max_ecat = if args.limit == 0 {
        usize::MAX
    } else {
        args.limit
    };
    let mut single_raw: Option<Vec<u8>> = None;
    let mut frames_json = Vec::new();
    let mut lines = Vec::new();
    let mut skipped_non_ecat = 0usize;

    // Stream packets incrementally; fast-filter non-EtherCAT packets before full dissection.
    let resolved_kind = for_each_frame_in_file(path, args.input_kind, |rec| {
        if !may_contain_ethercat(&rec.data, opts.bare_ecat) {
            if single_raw.is_none() && frames_json.is_empty() {
                single_raw = Some(rec.data);
            }
            skipped_non_ecat += 1;
            return Ok(true);
        }
        match dissect_frame(&rec.data, &opts) {
            Ok(df) => {
                lines.push(summarize_dissected_frame_line(rec.index, &df));
                frames_json.push(json!({
                    "index": rec.index,
                    "timestamp": rec.timestamp,
                    "note": rec.note,
                    "frame": df,
                }));
                Ok(frames_json.len() < max_ecat)
            }
            Err(_) => {
                if single_raw.is_none() && frames_json.is_empty() {
                    single_raw = Some(rec.data);
                }
                skipped_non_ecat += 1;
                Ok(true)
            }
        }
    })?;

    if matches!(resolved_kind, FrameInputKind::Bin | FrameInputKind::Hex) {
        if let Some(mut entry) = frames_json.pop() {
            let line = lines.pop().unwrap_or_default();
            return Ok(CommandRender {
                json: entry["frame"].take(),
                text: line,
            });
        }
        let raw = single_raw.unwrap_or_default();
        let frame = dissect_frame(&raw, &opts)?;
        let line = summarize_dissected_frame_line(0, &frame);
        return Ok(CommandRender {
            json: serde_json::to_value(&frame).unwrap_or(Value::Null),
            text: line,
        });
    }

    if frames_json.is_empty() {
        return Err(CliError::Format(format!(
            "no valid 0x88A4 EtherCAT frames found in '{}' (inspected {} packet(s))",
            path.display(),
            skipped_non_ecat
        )));
    }

    let header_line = format!(
        "Dissected {} EtherCAT frame(s) from '{}' (skipped_non_ethercat={}):",
        frames_json.len(),
        path.display(),
        skipped_non_ecat
    );
    lines.insert(0, header_line);

    Ok(CommandRender {
        json: json!({
            "file": path.display().to_string(),
            "dissected_count": frames_json.len(),
            "skipped_non_ethercat": skipped_non_ecat,
            "frames": frames_json,
        }),
        text: lines.join("\n"),
    })
}

pub fn handle_capture(
    cli: &Cli,
    count: usize,
    duration_ms: u64,
    filter_cmd: Option<EcatCmd>,
    pdo_layout: Option<&str>,
    sii_pdo: Option<&Path>,
    save_pcap: Option<&Path>,
) -> Result<CommandRender> {
    let iface = require_iface(cli)?;
    let opts = build_dissect_options(false, false, pdo_layout, sii_pdo, "tx")?;
    let mut bus = open_transport(&iface, true)?;

    let now = Instant::now();
    let deadline = now
        .checked_add(Duration::from_millis(duration_ms))
        .unwrap_or(now);
    let mut pcap_rows: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut packets_json = Vec::new();
    let mut lines = Vec::new();

    while packets_json.len() < count && Instant::now() < deadline {
        let rem = deadline.saturating_duration_since(Instant::now());
        let step = rem.min(Duration::from_millis(50));
        if step.is_zero() {
            break;
        }
        if let Some(raw) = bus.recv_raw_frame(step)? {
            if !may_contain_ethercat(&raw, opts.bare_ecat) {
                continue;
            }
            if let Ok(df) = dissect_frame(&raw, &opts) {
                if let Some(cmd_filter) = filter_cmd {
                    let hit = df.datagrams.iter().any(|d| d.cmd == cmd_filter.code());
                    if !hit {
                        continue;
                    }
                }
                let ts_us = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_micros() as u64)
                    .unwrap_or(0);
                let idx = packets_json.len();
                lines.push(summarize_dissected_frame_line(idx, &df));
                pcap_rows.push((ts_us, raw));
                packets_json.push(json!({
                    "index": idx,
                    "timestamp_us": ts_us,
                    "frame": df,
                }));
            }
        }
    }

    if let Some(pcap_path) = save_pcap {
        write_pcap_file(pcap_path, &pcap_rows)?;
    }

    lines.insert(
        0,
        format!(
            "Captured {} EtherCAT frame(s) on '{}' (window={}ms):",
            packets_json.len(),
            iface,
            duration_ms
        ),
    );

    Ok(CommandRender {
        json: json!({
            "interface": iface,
            "captured_count": packets_json.len(),
            "saved_pcap": save_pcap.map(|p| p.display().to_string()),
            "packets": packets_json,
        }),
        text: lines.join("\n"),
    })
}

pub fn handle_fields(category: FieldsCatalogFilter, search: Option<&str>) -> Result<CommandRender> {
    let needle = search.map(|s| s.to_ascii_lowercase());
    let matches_str = |hay: &str| {
        needle
            .as_ref()
            .is_none_or(|n| hay.to_ascii_lowercase().contains(n))
    };

    let ws_fields: Vec<&FieldSelectorDoc> = match category {
        FieldsCatalogFilter::All | FieldsCatalogFilter::Wireshark => WIRESHARK_FIELD_CATALOG
            .iter()
            .filter(|f| {
                matches_str(f.selector) || matches_str(f.layer) || matches_str(f.description)
            })
            .collect(),
        FieldsCatalogFilter::Ssc => WIRESHARK_FIELD_CATALOG
            .iter()
            .filter(|f| f.layer == "SSC Generator" || f.selector.starts_with("ssc."))
            .filter(|f| {
                matches_str(f.selector) || matches_str(f.layer) || matches_str(f.description)
            })
            .collect(),
        _ => Vec::new(),
    };

    let cmds: Vec<Value> = if matches!(
        category,
        FieldsCatalogFilter::All | FieldsCatalogFilter::Commands
    ) {
        (0x00u8..=0x0E)
            .filter_map(EcatCmd::from_code)
            .filter(|c| matches_str(c.mnemonic()) || matches_str(c.description()))
            .map(|c| {
                json!({
                    "code": format!("0x{:02X}", c.code()),
                    "mnemonic": c.mnemonic(),
                    "logical": c.is_logical(),
                    "description": c.description(),
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let regs: Vec<Value> = if matches!(
        category,
        FieldsCatalogFilter::All | FieldsCatalogFilter::Registers
    ) {
        ESC_REGISTERS
            .iter()
            .filter(|r| {
                matches_str(r.symbol)
                    || matches_str(r.name)
                    || matches_str(r.description)
                    || matches_str(&format!("0x{:04x}", r.address))
            })
            .map(|r| {
                json!({
                    "address": format!("0x{:04X}", r.address),
                    "symbol": r.symbol,
                    "name": r.name,
                    "size_bytes": r.default_size,
                    "description": r.description,
                })
            })
            .collect()
    } else {
        Vec::new()
    };

    let (sample_al, sample_sdo, codes) = if matches!(
        category,
        FieldsCatalogFilter::All | FieldsCatalogFilter::Codes
    ) {
        let al = [
            0x0000u16, 0x0011, 0x0012, 0x0013, 0x0014, 0x0016, 0x0017, 0x001B, 0x001D, 0x001E,
            0x0024, 0x002D, 0x0030, 0x0050,
        ]
        .into_iter()
        .filter(|&c| {
            matches_str(&format!("0x{c:04x}")) || matches_str(al_status_code_description(c))
        })
        .map(|c| {
            json!({
                "code": format!("0x{c:04X}"),
                "description": al_status_code_description(c),
            })
        })
        .collect::<Vec<_>>();

        let sdo = [
            0x0503_0000u32,
            0x0504_0001,
            0x0601_0000,
            0x0601_0001,
            0x0601_0002,
            0x0602_0000,
            0x0604_0041,
            0x0607_0010,
            0x0609_0011,
            0x0609_0030,
            0x0800_0000,
            0x0800_0020,
            0x0800_0022,
        ]
        .into_iter()
        .filter(|&c| matches_str(&format!("0x{c:08x}")) || matches_str(sdo_abort_description(c)))
        .map(|c| {
            json!({
                "code": format!("0x{c:08X}"),
                "description": sdo_abort_description(c),
            })
        })
        .collect::<Vec<_>>();

        let obj = json!({
            "al_status_codes": al,
            "sdo_abort_codes": sdo,
        });
        (al, sdo, obj)
    } else {
        (Vec::new(), Vec::new(), json!(null))
    };

    let mut lines = Vec::new();
    if !ws_fields.is_empty() {
        lines.push(format!(
            "Wireshark / CLI `--field` Selectors ({}):",
            ws_fields.len()
        ));
        for f in &ws_fields {
            lines.push(format!(
                "  {:<34} [{:<24}] {}",
                f.selector, f.layer, f.description
            ));
        }
    }
    if !cmds.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("EtherCAT Datagram Commands ({}):", cmds.len()));
        for c in &cmds {
            lines.push(format!(
                "  {} {:<5} -- {}",
                c["code"].as_str().unwrap_or(""),
                c["mnemonic"].as_str().unwrap_or(""),
                c["description"].as_str().unwrap_or("")
            ));
        }
    }
    if !regs.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("ESC Hardware Registers ({}):", regs.len()));
        for r in &regs {
            lines.push(format!(
                "  {} {:<18} ({}B) {:<16} -- {}",
                r["address"].as_str().unwrap_or(""),
                r["symbol"].as_str().unwrap_or(""),
                r["size_bytes"].as_u64().unwrap_or(0),
                r["name"].as_str().unwrap_or(""),
                r["description"].as_str().unwrap_or("")
            ));
        }
    }
    if !sample_al.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("AL Status Codes ({}):", sample_al.len()));
        for c in &sample_al {
            lines.push(format!(
                "  {} -- {}",
                c["code"].as_str().unwrap_or(""),
                c["description"].as_str().unwrap_or("")
            ));
        }
    }
    if !sample_sdo.is_empty() {
        if !lines.is_empty() {
            lines.push(String::new());
        }
        lines.push(format!("CoE SDO Abort Codes ({}):", sample_sdo.len()));
        for c in &sample_sdo {
            lines.push(format!(
                "  {} -- {}",
                c["code"].as_str().unwrap_or(""),
                c["description"].as_str().unwrap_or("")
            ));
        }
    }

    Ok(CommandRender {
        json: json!({
            "wireshark_selectors": ws_fields,
            "ethercat_commands": cmds,
            "esc_registers": regs,
            "protocol_codes": codes,
        }),
        text: lines.join("\n"),
    })
}
