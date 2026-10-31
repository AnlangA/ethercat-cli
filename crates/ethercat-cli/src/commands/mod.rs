pub mod bus;
pub mod frames;
pub mod sii_esi;
pub mod ssc;

use std::path::Path;
use std::time::Duration;

use serde_json::Value;

use crate::cli::{Cli, Commands};
use ethercat_eeprom::sii::image::{parse_sii_image, sii_pdos_to_layout};
use ethercat_master::pdo::PdoLayout;
use ethercat_wire::error::{CliError, Result};

pub struct CommandRender {
    pub json: Value,
    pub text: String,
}

pub fn optional_iface(cli: &Cli) -> Option<String> {
    if let Some(ref i) = cli.iface {
        if !i.trim().is_empty() {
            return Some(i.trim().to_string());
        }
    }
    if let Ok(env_if) = std::env::var("ETHERCAT_IFACE") {
        if !env_if.trim().is_empty() {
            return Some(env_if.trim().to_string());
        }
    }
    None
}

pub fn require_iface(cli: &Cli) -> Result<String> {
    optional_iface(cli).ok_or_else(|| {
        CliError::Usage(
            "missing `--iface <IFACE>` (e.g. `-i \"\\Device\\NPF_{GUID}\"` on Windows or `-i sim` for virtual simulator). Run `ethercat-cli adapters` to list available interfaces."
                .into(),
        )
    })
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read '{}': {e}", path.display()),
        ))
    })
}

pub fn write_file_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                CliError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot create directory '{}': {e}", parent.display()),
                ))
            })?;
        }
    }
    std::fs::write(path, bytes).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot write '{}': {e}", path.display()),
        ))
    })
}

pub fn resolve_offline_pdo_layout(
    layout_spec: Option<&str>,
    sii_file: Option<&Path>,
    direction: &str,
) -> Result<PdoLayout> {
    if let Some(spec) = layout_spec {
        return PdoLayout::parse_spec(spec);
    }
    if let Some(path) = sii_file {
        let bytes = read_file_bytes(path)?;
        let parsed = parse_sii_image(&bytes)?;
        let pdos = if direction.eq_ignore_ascii_case("rx") {
            &parsed.categories.rx_pdos
        } else {
            &parsed.categories.tx_pdos
        };
        let layout = sii_pdos_to_layout(pdos);
        if layout.fields.is_empty() {
            return Err(CliError::Format(format!(
                "no {direction} PDO entries found in SII file '{}'",
                path.display()
            )));
        }
        return Ok(layout);
    }
    Err(CliError::Usage(
        "provide either `--layout <SPEC>` or `--sii-file <IMAGE.BIN>`".into(),
    ))
}

pub fn execute_cli(cli: &Cli) -> Result<CommandRender> {
    let timeout = Duration::from_millis(cli.timeout_ms.max(1));

    match &cli.command {
        Commands::Adapters { physical_only } => bus::handle_adapters(!*physical_only),
        Commands::Scan {
            assign_addresses,
            no_sii,
        } => bus::handle_scan(cli, *assign_addresses, *no_sii, timeout),
        Commands::State {
            slave,
            set,
            ack,
            dry_run,
        } => bus::handle_state(cli, *slave, *set, *ack, *dry_run, timeout),
        Commands::Sii(sub) => sii_esi::handle_sii(cli, sub, timeout),
        Commands::Esi(sub) => sii_esi::handle_esi(cli, sub, timeout),
        Commands::Ssc(sub) => ssc::handle_ssc(sub),
        Commands::Reg(sub) => bus::handle_reg(cli, sub, timeout),
        Commands::Sdo(sub) => bus::handle_sdo(cli, sub, timeout),
        Commands::Pdo(sub) => bus::handle_pdo(cli, sub, timeout),
        Commands::Frame(sub) => frames::handle_frame(cli, sub, timeout),
        Commands::Datagram(args) => frames::handle_datagram(cli, args, timeout),
        Commands::Dissect(args) => frames::handle_dissect(args),
        Commands::Capture {
            count,
            duration_ms,
            filter_cmd,
            pdo_layout,
            sii_pdo,
            save_pcap,
        } => frames::handle_capture(
            cli,
            *count,
            *duration_ms,
            *filter_cmd,
            pdo_layout.as_deref(),
            sii_pdo.as_deref(),
            save_pcap.as_deref(),
        ),
        Commands::Fields { category, search } => {
            frames::handle_fields(*category, search.as_deref())
        }
    }
}
