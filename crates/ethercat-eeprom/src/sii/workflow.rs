use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::esi::{
    compile_esi_device_to_sii, load_esi_catalog, match_esi_device_by_identity, select_esi_device,
    EsiCompileOptions, EsiCompiledSii, EsiDeviceSummary,
};
use crate::sii::image::{
    format_ssc_eeprom_header, parse_sii_image, patch_sii_image, sii_diff_words, sii_le32,
    sii_validate, SiiBuildProfile, SiiDecodedImage, SiiPatchSpec, WordDiff, SII_MIN_SIZE,
};
use crate::sii::ops::{
    read_device_sii_image, read_device_sii_slice, write_device_sii_guarded_checked,
    GuardedSiiWriteOptions, SiiWriteReport, SlaveSiiSummary,
};
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::transport::EthercatTransport;
use ethercat_wire::types::format_hex;

#[derive(Debug, Clone)]
pub struct SiiXmlSourceOptions {
    pub device: Option<String>,
    pub revision: Option<u32>,
    pub profile: SiiBuildProfile,
    pub lcid: u32,
    pub eeprom_size: Option<usize>,
    pub ignore_eeprom_size: bool,
    pub include_unassigned_pdos: bool,
}

impl Default for SiiXmlSourceOptions {
    fn default() -> Self {
        Self {
            device: None,
            revision: None,
            profile: SiiBuildProfile::Ssc,
            lcid: 1033,
            eeprom_size: None,
            ignore_eeprom_size: false,
            include_unassigned_pdos: false,
        }
    }
}

#[derive(Debug, Clone)]
pub enum SiiSourceInput {
    BinFile(PathBuf),
    EsiXml {
        xml_path: PathBuf,
        opts: SiiXmlSourceOptions,
    },
}

impl SiiSourceInput {
    /// Detect whether `path` is an ETG.2000 `.xml` file/catalog or a raw SII `.bin` image.
    pub fn from_auto_path(path: PathBuf, opts: SiiXmlSourceOptions) -> Result<Self> {
        if path.is_dir() {
            return Ok(Self::EsiXml {
                xml_path: path,
                opts,
            });
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("xml") {
                return Ok(Self::EsiXml {
                    xml_path: path,
                    opts,
                });
            }
            if ext.eq_ignore_ascii_case("bin") {
                return Ok(Self::BinFile(path));
            }
        }
        let mut head = Vec::with_capacity(512);
        {
            use std::io::Read as _;
            let f = std::fs::File::open(&path).map_err(|e| {
                CliError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot read '{}': {e}", path.display()),
                ))
            })?;
            f.take(512).read_to_end(&mut head).map_err(|e| {
                CliError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot read '{}': {e}", path.display()),
                ))
            })?;
        }
        let looks_like_xml = crate::esi::xml::decode_xml_bytes(&head).is_ok_and(|decoded| {
            let s = decoded.trim_start_matches('\u{FEFF}').trim_start();
            s.starts_with("<?xml")
                || s.starts_with("<!--")
                || s.get(..9)
                    .is_some_and(|p| p.eq_ignore_ascii_case("<!DOCTYPE"))
                || s.get(..9)
                    .is_some_and(|p| p.eq_ignore_ascii_case("<EtherCAT"))
        });
        if looks_like_xml {
            Ok(Self::EsiXml {
                xml_path: path,
                opts,
            })
        } else {
            Ok(Self::BinFile(path))
        }
    }
}

#[derive(Debug, Clone)]
pub struct SiiSourceSpec {
    pub input: SiiSourceInput,
    pub patch: Option<SiiPatchSpec>,
}

impl SiiSourceSpec {
    pub fn from_file_or_xml(
        file: Option<&Path>,
        xml: Option<&Path>,
        xml_opts: SiiXmlSourceOptions,
        patch: Option<SiiPatchSpec>,
    ) -> Result<Self> {
        match (file, xml) {
            (Some(_), Some(_)) => Err(CliError::Usage(
                "specify either --file <image.bin> OR --xml <esi.xml>, not both".into(),
            )),
            (None, None) => Err(CliError::Usage(
                "specify either --file <image.bin> OR --xml <esi.xml>".into(),
            )),
            (Some(path), None) => {
                let is_explicit_xml = path.is_dir()
                    || path
                        .extension()
                        .and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("xml"));
                let input = if is_explicit_xml {
                    SiiSourceInput::EsiXml {
                        xml_path: path.to_path_buf(),
                        opts: xml_opts,
                    }
                } else if path.exists() {
                    SiiSourceInput::from_auto_path(path.to_path_buf(), xml_opts)?
                } else {
                    SiiSourceInput::BinFile(path.to_path_buf())
                };
                Ok(Self { input, patch })
            }
            (None, Some(xml_path)) => Ok(Self {
                input: SiiSourceInput::EsiXml {
                    xml_path: xml_path.to_path_buf(),
                    opts: xml_opts,
                },
                patch,
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedSiiImage {
    #[serde(skip_serializing)]
    pub bytes: Vec<u8>,
    pub source_kind: &'static str,
    pub source_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esi_device: Option<EsiDeviceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_info: Option<EsiCompiledSii>,
    pub decoded: SiiDecodedImage,
}

struct RawResolvedSource {
    bytes: Vec<u8>,
    source_kind: &'static str,
    source_label: String,
    file_path: Option<String>,
    esi_device: Option<EsiDeviceSummary>,
    compile_info: Option<EsiCompiledSii>,
}

fn patch_has_changes(p: &SiiPatchSpec) -> bool {
    p.alias.is_some()
        || p.vendor_id.is_some()
        || p.product_code.is_some()
        || p.revision_number.is_some()
        || p.serial_number.is_some()
        || !p.word_writes.is_empty()
}

fn resolve_sii_source_raw(spec: &SiiSourceSpec, validate_bin: bool) -> Result<RawResolvedSource> {
    match &spec.input {
        SiiSourceInput::BinFile(path) => {
            let raw = std::fs::read(path).map_err(|e| {
                CliError::Io(std::io::Error::new(
                    e.kind(),
                    format!("cannot read SII file '{}': {e}", path.display()),
                ))
            })?;
            let bytes = match &spec.patch {
                Some(p) if patch_has_changes(p) => patch_sii_image(&raw, p)?,
                _ => {
                    if validate_bin {
                        sii_validate(&raw)?;
                    }
                    raw
                }
            };
            let label = path.display().to_string();
            Ok(RawResolvedSource {
                bytes,
                source_kind: "bin_file",
                source_label: label.clone(),
                file_path: Some(label),
                esi_device: None,
                compile_info: None,
            })
        }
        SiiSourceInput::EsiXml { xml_path, opts } => {
            let catalog = load_esi_catalog(xml_path, opts.lcid)?;
            let dev = select_esi_device(&catalog.devices, opts.device.as_deref(), opts.revision)?;
            let compile_opts = EsiCompileOptions {
                profile: opts.profile,
                eeprom_size_override: opts.eeprom_size,
                ignore_eeprom_size: opts.ignore_eeprom_size,
                include_unassigned_pdos: opts.include_unassigned_pdos,
                alias_override: spec.patch.as_ref().and_then(|p| p.alias),
                serial_override: spec.patch.as_ref().and_then(|p| p.serial_number),
                revision_override: spec.patch.as_ref().and_then(|p| p.revision_number),
            };
            let compiled = compile_esi_device_to_sii(dev, &compile_opts)?;
            let bytes = match &spec.patch {
                Some(p)
                    if p.vendor_id.is_some()
                        || p.product_code.is_some()
                        || !p.word_writes.is_empty() =>
                {
                    patch_sii_image(&compiled.bytes, p)?
                }
                _ => compiled.bytes.clone(),
            };
            let label = format!(
                "{}#{} ({}, rev=0x{:08X})",
                xml_path.display(),
                dev.index,
                dev.order_code,
                dev.revision_number
            );
            Ok(RawResolvedSource {
                bytes,
                source_kind: "esi_xml",
                source_label: label,
                file_path: None,
                esi_device: Some(dev.summary()),
                compile_info: Some(compiled),
            })
        }
    }
}

pub fn resolve_sii_source(spec: &SiiSourceSpec) -> Result<ResolvedSiiImage> {
    let raw = resolve_sii_source_raw(spec, true)?;
    let decoded = parse_sii_image(&raw.bytes)?;
    Ok(ResolvedSiiImage {
        bytes: raw.bytes,
        source_kind: raw.source_kind,
        source_label: raw.source_label,
        esi_device: raw.esi_device,
        compile_info: raw.compile_info,
        decoded,
    })
}

pub fn write_ssc_header_file(path: &Path, data: &[u8], info_comment: Option<&str>) -> Result<()> {
    let header_text = format_ssc_eeprom_header(data, info_comment);
    std::fs::write(path, header_text).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot write SSC EEPROM header '{}': {e}", path.display()),
        ))
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiBuildReport {
    pub source_xml: String,
    pub esi_device: EsiDeviceSummary,
    pub compile_info: EsiCompiledSii,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_bin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_header: Option<String>,
    pub identity: SlaveSiiSummary,
    pub decoded: SiiDecodedImage,
}

pub fn build_sii_from_esi_workflow(
    xml_path: &Path,
    xml_opts: &SiiXmlSourceOptions,
    patch: Option<SiiPatchSpec>,
    output_bin: Option<&Path>,
    output_header: Option<&Path>,
) -> Result<SiiBuildReport> {
    if output_bin.is_none() && output_header.is_none() {
        return Err(CliError::Usage(
            "specify --output <file.bin> and/or --header-out <file.h>".into(),
        ));
    }
    let resolved = resolve_sii_source(&SiiSourceSpec {
        input: SiiSourceInput::EsiXml {
            xml_path: xml_path.to_path_buf(),
            opts: xml_opts.clone(),
        },
        patch,
    })?;
    let esi_device = resolved
        .esi_device
        .clone()
        .ok_or_else(|| CliError::Format("missing ESI device metadata".into()))?;
    let compile_info = resolved
        .compile_info
        .clone()
        .ok_or_else(|| CliError::Format("missing ESI compile metadata".into()))?;

    if let Some(bin_path) = output_bin {
        std::fs::write(bin_path, &resolved.bytes).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot write SII binary '{}': {e}", bin_path.display()),
            ))
        })?;
    }
    if let Some(hdr_path) = output_header {
        let info = format!(
            "{} ({}) - compiled from {}",
            esi_device.order_code, esi_device.device_name, esi_device.source_file
        );
        write_ssc_header_file(hdr_path, &resolved.bytes, Some(&info))?;
    }

    let identity = SlaveSiiSummary::from_image(1, &resolved.bytes);
    Ok(SiiBuildReport {
        source_xml: xml_path.display().to_string(),
        esi_device,
        compile_info,
        output_bin: output_bin.map(|p| p.display().to_string()),
        output_header: output_header.map(|p| p.display().to_string()),
        identity,
        decoded: resolved.decoded,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct EsiCatalogMatch {
    pub match_kind: &'static str,
    pub device: EsiDeviceSummary,
}

pub struct SiiReadWorkflowOptions<'a> {
    pub slave: u16,
    pub offset: Option<usize>,
    pub length: Option<usize>,
    pub output_bin: Option<&'a Path>,
    pub output_header: Option<&'a Path>,
    pub catalog_xml: Option<&'a Path>,
    pub lcid: u32,
    pub decode: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiReadWorkflowReport {
    pub slave: u16,
    pub offset: usize,
    pub size_bytes: usize,
    pub output_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header_out: Option<String>,
    pub crc_ok: Option<bool>,
    pub identity: Option<SlaveSiiSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esi_match: Option<EsiCatalogMatch>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<SiiDecodedImage>,
    pub raw_hex: String,
}

pub fn read_slave_eeprom_workflow(
    bus: &mut dyn EthercatTransport,
    opts: &SiiReadWorkflowOptions<'_>,
) -> Result<SiiReadWorkflowReport> {
    let is_slice = opts.offset.is_some() || opts.length.is_some();
    let start_off = opts.offset.unwrap_or(0);
    let raw = if is_slice {
        let len = opts.length.unwrap_or(64);
        read_device_sii_slice(bus, opts.slave, start_off, len, opts.timeout)?
    } else {
        read_device_sii_image(bus, opts.slave, opts.timeout)?
    };

    if let Some(out_path) = opts.output_bin {
        std::fs::write(out_path, &raw).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("cannot write '{}': {e}", out_path.display()),
            ))
        })?;
    }

    let identity = if start_off == 0 && raw.len() >= SII_MIN_SIZE {
        Some(SlaveSiiSummary::from_image(opts.slave, &raw))
    } else {
        None
    };
    let crc_ok = if start_off == 0 && raw.len() >= 15 {
        Some(crate::sii::image::sii_crc8(&raw[0..14]) == raw[14])
    } else {
        None
    };

    if let Some(hdr_path) = opts.output_header {
        let comment = format!(
            "Read from Slave {} ({} bytes at offset 0x{:04X})",
            opts.slave,
            raw.len(),
            start_off
        );
        write_ssc_header_file(hdr_path, &raw, Some(&comment))?;
    }

    let esi_match = if let (0, Some(xml_path)) = (start_off, opts.catalog_xml) {
        if raw.len() >= SII_MIN_SIZE {
            let catalog = load_esi_catalog(xml_path, opts.lcid)?;
            let vendor = sii_le32(&raw[0x10..0x14]);
            let product = sii_le32(&raw[0x14..0x18]);
            let rev = sii_le32(&raw[0x18..0x1C]);
            match_esi_device_by_identity(&catalog.devices, vendor, product, rev).map(
                |(dev, kind)| EsiCatalogMatch {
                    match_kind: kind,
                    device: dev.summary(),
                },
            )
        } else {
            None
        }
    } else {
        None
    };

    let decoded = if opts.decode && start_off == 0 && raw.len() >= SII_MIN_SIZE {
        Some(parse_sii_image(&raw)?)
    } else {
        None
    };

    Ok(SiiReadWorkflowReport {
        slave: opts.slave,
        offset: start_off,
        size_bytes: raw.len(),
        output_file: opts.output_bin.map(|p| p.display().to_string()),
        header_out: opts.output_header.map(|p| p.display().to_string()),
        crc_ok,
        identity,
        esi_match,
        decoded,
        raw_hex: format_hex(&raw),
    })
}

pub struct SiiProgramWorkflowOptions<'a> {
    pub slave: u16,
    pub source: &'a SiiSourceSpec,
    pub execute: bool,
    pub backup_path: Option<&'a Path>,
    pub confirm_token: Option<&'a str>,
    pub reload: bool,
    pub check_esc_config: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiProgramWorkflowReport {
    #[serde(flatten)]
    pub write_report: SiiWriteReport,
    pub source_kind: &'static str,
    pub source_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esi_device: Option<EsiDeviceSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compile_info: Option<EsiCompiledSii>,
}

pub fn program_slave_eeprom_workflow(
    bus: &mut dyn EthercatTransport,
    opts: &SiiProgramWorkflowOptions<'_>,
) -> Result<SiiProgramWorkflowReport> {
    let resolved = resolve_sii_source(opts.source)?;
    let write_opts = GuardedSiiWriteOptions {
        slave: opts.slave,
        proposed: &resolved.bytes,
        execute: opts.execute,
        backup_path: opts.backup_path,
        confirm_token: opts.confirm_token,
        reload: opts.reload,
        timeout: opts.timeout,
    };
    let write_report = if opts.check_esc_config {
        write_device_sii_guarded_checked(bus, &write_opts, true)?
    } else {
        crate::sii::ops::write_device_sii_guarded(bus, &write_opts)?
    };

    Ok(SiiProgramWorkflowReport {
        write_report,
        source_kind: resolved.source_kind,
        source_label: resolved.source_label,
        esi_device: resolved.esi_device,
        compile_info: resolved.compile_info,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiVerifyWorkflowReport {
    pub verified: bool,
    pub slave: u16,
    pub source_kind: &'static str,
    pub source_label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esi_device: Option<EsiDeviceSummary>,
    pub size_bytes: usize,
    pub identity: SlaveSiiSummary,
}

pub fn verify_slave_eeprom_workflow(
    bus: &mut dyn EthercatTransport,
    slave: u16,
    source: &SiiSourceSpec,
    timeout: Duration,
) -> Result<SiiVerifyWorkflowReport> {
    let expected = resolve_sii_source_raw(source, true)?;
    let actual = read_device_sii_image(bus, slave, timeout)?;
    let (diff_words, samples) = sii_diff_words(&actual, &expected.bytes, 16);
    if actual != expected.bytes {
        return Err(CliError::Mismatch(format!(
            "SII EEPROM mismatch on slave {}: device={} bytes vs expected={} bytes ({}), differing_words={} (first diff={:?})",
            slave,
            actual.len(),
            expected.bytes.len(),
            expected.source_label,
            diff_words,
            samples.first()
        )));
    }

    Ok(SiiVerifyWorkflowReport {
        verified: true,
        slave,
        source_kind: expected.source_kind,
        source_label: expected.source_label,
        file: expected.file_path,
        esi_device: expected.esi_device,
        size_bytes: actual.len(),
        identity: SlaveSiiSummary::from_image(slave, &actual),
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct SiiDiffWorkflowReport {
    pub identical: bool,
    pub left_source: String,
    pub left_kind: &'static str,
    pub left_size_bytes: usize,
    pub left_identity: Option<SlaveSiiSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left_esi_device: Option<EsiDeviceSummary>,
    pub right_source: String,
    pub right_kind: &'static str,
    pub right_size_bytes: usize,
    pub right_identity: Option<SlaveSiiSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub right_esi_device: Option<EsiDeviceSummary>,
    pub differing_words: usize,
    pub diffs: Vec<WordDiff>,
}

pub fn diff_sii_sources_workflow(
    left: &SiiSourceSpec,
    right: &SiiSourceSpec,
    max_diffs: usize,
) -> Result<SiiDiffWorkflowReport> {
    let l = resolve_sii_source_raw(left, false)?;
    let r = resolve_sii_source_raw(right, false)?;
    let (diff_cnt, diffs) = sii_diff_words(&l.bytes, &r.bytes, max_diffs);
    let identical = l.bytes == r.bytes;
    let left_identity =
        (l.bytes.len() >= SII_MIN_SIZE).then(|| SlaveSiiSummary::from_image(1, &l.bytes));
    let right_identity =
        (r.bytes.len() >= SII_MIN_SIZE).then(|| SlaveSiiSummary::from_image(1, &r.bytes));

    Ok(SiiDiffWorkflowReport {
        identical,
        left_source: l.source_label,
        left_kind: l.source_kind,
        left_size_bytes: l.bytes.len(),
        left_identity,
        left_esi_device: l.esi_device,
        right_source: r.source_label,
        right_kind: r.source_kind,
        right_size_bytes: r.bytes.len(),
        right_identity,
        right_esi_device: r.esi_device,
        differing_words: diff_cnt,
        diffs,
    })
}
