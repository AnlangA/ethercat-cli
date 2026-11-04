pub mod archive;
pub mod codegen;
pub mod esi_gen;
pub mod expr;
pub mod model;
pub mod od;
pub mod patch;
pub mod xml_dom;

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::archive::bytes_to_text;
use crate::codegen::{
    encode_crlf_lines, preprocess_ssc_source_lines, render_ecat_def_h, render_ssc_eeprom_h,
    split_text_lines, EcatDefEntry,
};
use crate::esi_gen::{
    create_device_description_bytes, update_esi_file, write_device_description,
    write_offline_dictionary, EsiUpdateOutcome,
};
use crate::expr::{
    compute_compiler_command, evaluate_boolean_expression, normalize_line, SrcCodeType,
};
use crate::model::{
    load_external_configurations, load_ssc_options, ActiveConflict, ConflictSeverity,
    ExternalConfiguration, SlaveFile, SlaveFileContent, SlaveFileType, SlaveProject,
};
use crate::od::{
    build_application_slave_files, parse_application_files, write_standalone_od_c_files,
    SlaveApplication,
};
use crate::patch::{apply_patch_to_lines, parse_ssc_patch_sections};
use ethercat_eeprom::esi::{
    compile_esi_device_to_sii, load_esi_catalog_from_bytes, EsiCompileOptions,
};
use ethercat_eeprom::sii::image::SiiBuildProfile;
use ethercat_wire::error::{CliError, Result};

#[derive(Debug, Clone, Default)]
pub struct SscGenerateOptions {
    pub project_source: Option<PathBuf>,
    pub ssc_dir: Option<PathBuf>,
    pub output_dir: Option<PathBuf>,
    pub src_out_dir: Option<PathBuf>,
    pub project_name: Option<String>,
    pub app_files: Vec<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub config_name: Option<String>,
    pub allow_file_import: bool,
    pub patch_file: Option<PathBuf>,
    pub defines: Vec<(String, String)>,
    pub use_gui_options: bool,
    pub options_file: Option<PathBuf>,
    pub raw_files: bool,
    pub add_delete_comment: bool,
    pub no_esp: bool,
    pub no_esi: bool,
    pub esi_code_config: bool,
    pub esi_trace_file: Option<String>,
    pub sii_out: Option<PathBuf>,
    pub strict_conflicts: bool,
    pub ignore_errors: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SscGenerateReport {
    pub project_name: String,
    pub ssc_version: String,
    pub input_source: String,
    pub target_dir: String,
    pub src_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esp_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esi_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eeprom_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sii_bin_file: Option<String>,
    pub written_files: Vec<String>,
    pub skipped_files: Vec<String>,
    pub patched_files: Vec<String>,
    pub active_conflicts: Vec<ActiveConflict>,
    pub warnings: Vec<String>,
}

/// Execute full Beckhoff `SSC Tool` / `SSC Tool Cmd` project, source, ESI, `eeprom.h`, and `.esp` generation.
pub fn generate_ssc_project(opts: &SscGenerateOptions) -> Result<SscGenerateReport> {
    let mut project = SlaveProject::load(opts.project_source.as_deref(), opts.ssc_dir.as_deref())?;

    let mut project_name = if let Some(explicit_name) = &opts.project_name {
        explicit_name.clone()
    } else if project.is_project_file {
        project
            .get_setting_value("DEVICE_NAME")
            .filter(|s| !s.is_empty())
            .unwrap_or("SlaveProject")
            .to_string()
    } else {
        "SlaveProject".to_string()
    };

    let mut add_delete_comment = opts.add_delete_comment;
    let mut add_code_config_to_esi = opts.esi_code_config;
    if opts.use_gui_options || opts.options_file.is_some() {
        let gui_opts = load_ssc_options(opts.options_file.as_deref())?;
        add_delete_comment = add_delete_comment || gui_opts.add_delete_comment;
        add_code_config_to_esi = add_code_config_to_esi || gui_opts.add_code_config_to_esi;
        project.apply_gui_options(&gui_opts)?;
    }

    // Reconstruct embedded `<Application>` if loaded from an `.esp` that already contains one
    let mut active_app: Option<SlaveApplication> = None;
    if let Some(app_xml) = &project.application_xml {
        if let Ok(mut parsed) =
            crate::od::parsers::parse_application_from_dom(app_xml, &project_name)
        {
            parsed.od.finalize_and_validate(true);
            active_app = Some(parsed);
        }
    }

    // 1. `-a`: Import application OD file(s) (`SSC Tool Cmd` runs `-a` before `-c` and `-d`)
    if !opts.app_files.is_empty() {
        let app = parse_application_files(&opts.app_files, true)?;
        attach_application_to_project(&mut project, &app)?;
        active_app = Some(app);
    }

    // 2. `-c`: Apply external or embedded configuration (single `.xml`/`.escfg`/ESI file or directory)
    if let Some(cfg_path) = &opts.config_file {
        if !cfg_path.exists() {
            return Err(CliError::Usage(format!(
                "The configuration file or directory '{}' does not exist",
                cfg_path.display()
            )));
        }
        let cfgs = load_external_configurations(cfg_path)?;
        let selected: &ExternalConfiguration = match opts.config_name.as_deref() {
            None | Some("") => &cfgs[0],
            Some(wanted) => {
                let matches: Vec<&ExternalConfiguration> =
                    cfgs.iter().filter(|c| c.name == wanted).collect();
                if matches.is_empty() {
                    return Err(CliError::Validation(format!(
                        "The configuration '{wanted}' is not defined in the file '{}'",
                        cfg_path.display()
                    )));
                }
                if matches.len() > 1 {
                    return Err(CliError::Validation(format!(
                        "The configuration '{wanted}' is defined multiple times in the file '{}'",
                        cfg_path.display()
                    )));
                }
                matches[0]
            }
        };

        // Note `SSC Tool Cmd` quirk: when `-c <file>` has no `<cfg_name>`, it passes `_ConfigurationAllowFileImport`;
        // when `<cfg_name>` is specified, we also honor `opts.allow_file_import` so explicit `--allow-file-import` works cleanly.
        let cfg_app_path =
            project.apply_configuration(selected, opts.allow_file_import, opts.ignore_errors)?;
        if let Some(ap) = cfg_app_path {
            if opts.app_files.is_empty() && ap.is_file() {
                let app = parse_application_files(&[ap], true)?;
                attach_application_to_project(&mut project, &app)?;
                active_app = Some(app);
            }
        }
    } else if let Some(embedded_name) = opts.config_name.as_deref().filter(|s| !s.is_empty()) {
        // Select from embedded `<Configurations>` inside `SlaveConfigFile.escfg`
        let matches: Vec<ExternalConfiguration> = project
            .embedded_configurations
            .iter()
            .filter(|c| c.name == embedded_name)
            .cloned()
            .collect();
        if matches.is_empty() {
            return Err(CliError::Validation(format!(
                "Embedded configuration '{embedded_name}' not found in '{}'",
                project.input_path.display()
            )));
        }
        let cfg_app_path =
            project.apply_configuration(&matches[0], opts.allow_file_import, opts.ignore_errors)?;
        if let Some(ap) = cfg_app_path {
            if opts.app_files.is_empty() && ap.is_file() {
                let app = parse_application_files(&[ap], true)?;
                attach_application_to_project(&mut project, &app)?;
                active_app = Some(app);
            }
        }
    }

    // 3. Optional explicit `.patch` override
    if let Some(patch_path) = &opts.patch_file {
        project.set_patch_file(patch_path)?;
    }

    // 4. `-d`: Apply CLI define overrides
    let mut seen_defines = HashSet::new();
    for (def_name, def_val) in &opts.defines {
        if !seen_defines.insert(def_name.clone()) {
            return Err(CliError::Usage(format!(
                "The define '{def_name}' is defined twice in the arguments"
            )));
        }
        project.apply_cli_define(def_name, def_val)?;
    }

    // 5. Finalize default project name from attached application (`SSC Tool Cmd` parity)
    if opts.project_name.is_none() && project_name == "SlaveProject" {
        if let Some(app) = &active_app {
            if !app.name.is_empty() {
                project_name = app.name.clone();
                let _ = project.set_setting_value("DEVICE_NAME", &app.name, false, true, true);
            }
        }
    }

    // 6. Conflict check
    let active_conflicts = project.evaluate_active_conflicts();
    if opts.strict_conflicts {
        if let Some(err_conflict) = active_conflicts
            .iter()
            .find(|c| c.severity == ConflictSeverity::Error)
        {
            return Err(CliError::Validation(format!(
                "Active SSC setting conflict ({}): {}",
                err_conflict.expression, err_conflict.message
            )));
        }
    }

    // 7. Resolve target output directory
    let target_dir = if let Some(out) = &opts.output_dir {
        out.clone()
    } else if !opts.app_files.is_empty() {
        let base = opts.app_files[0]
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        base.join("SlaveFiles")
    } else if project.is_project_file {
        project
            .input_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        return Err(CliError::Usage(
            "Output directory required (`--output <dir>`), unless `-a <app_file>` or `-p <file.esp>` is given".into(),
        ));
    };

    fs::create_dir_all(&target_dir)?;

    // 8. Save `.esp` project file
    let esp_file = if !opts.no_esp {
        let esp_target = target_dir.join(format!("{project_name}.esp"));
        let saved = project.save_esp(&esp_target)?;
        Some(saved.display().to_string())
    } else {
        None
    };

    // 9. Write `<ProjectName>.xml` ESI file
    let esi_file_path = target_dir.join(format!("{project_name}.xml"));
    let esi_trace_ref = opts.esi_trace_file.as_deref();
    let esi_bytes = create_device_description_bytes(
        &project,
        active_app.as_ref(),
        add_code_config_to_esi,
        esi_trace_ref,
    )?;
    let esi_file = if !opts.no_esi {
        write_device_description(
            &esi_file_path,
            &project,
            active_app.as_ref(),
            add_code_config_to_esi,
            esi_trace_ref,
        )?;
        Some(esi_file_path.display().to_string())
    } else {
        None
    };

    // 10. Generate `src\` C/H stack & application files + `ecat_def.h` + optional `eeprom.h`
    let src_dir = match &opts.src_out_dir {
        Some(custom_src) => custom_src.clone(),
        None => target_dir.join("src"),
    };
    fs::create_dir_all(&src_dir)?;

    let (written_files, skipped_files, patched_files) =
        write_project_source_files(&project, &src_dir, add_delete_comment, opts.raw_files)?;

    // 11. `CREATE_EEPROM_CONTENT` -> `src\eeprom.h` and/or `--sii-out <file.bin>`
    let all_defs = project.all_defines_map();
    let want_eeprom_h = evaluate_boolean_expression("CREATE_EEPROM_CONTENT", |k| all_defs.get(k));

    let mut eeprom_header = None;
    let mut sii_bin_file = None;

    if want_eeprom_h || opts.sii_out.is_some() {
        // Match `Path.GetTempPath() + "\\EcatSlaveESI.xml"` display string in `eeprom.h`
        // (expand 8.3 short paths such as `ADMINI~1` via `fs::canonicalize` just like .NET `Path.GetTempPath()`),
        // while compiling the ESI bytes directly in memory without touching `%TEMP%\EcatSlaveESI.xml` on disk.
        let temp_dir = std::env::temp_dir();
        let canon_temp = fs::canonicalize(&temp_dir).unwrap_or_else(|_| temp_dir.clone());
        let mut temp_str = canon_temp.to_string_lossy().into_owned();
        if let Some(stripped) = temp_str.strip_prefix(r"\\?\") {
            temp_str = stripped.to_string();
        }
        if !temp_str.ends_with('\\') && !temp_str.ends_with('/') {
            temp_str.push('\\');
        }
        let display_esi = format!("{temp_str}\\EcatSlaveESI.xml");

        let catalog =
            load_esi_catalog_from_bytes(&esi_bytes, &display_esi, Some(&target_dir), 1033)?;
        let dev = catalog.devices.first().ok_or_else(|| {
            CliError::Format("Generated ESI XML contains no <Device> entry".into())
        })?;
        let ignore_size = project
            .get_setting_value("ESC_EEPROM_EMULATION")
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
        let sii_bytes = compile_esi_device_to_sii(
            dev,
            &EsiCompileOptions {
                profile: SiiBuildProfile::Ssc,
                ignore_eeprom_size: ignore_size,
                ..Default::default()
            },
        )?
        .bytes;

        if want_eeprom_h {
            let target_eeprom_size = project
                .get_setting("ESC_EEPROM_SIZE")
                .map(|s| parse_any_usize(&s.value))
                .unwrap_or(0);
            let header_bytes = render_ssc_eeprom_h(&sii_bytes, target_eeprom_size, &display_esi);
            let eeprom_h_path = src_dir.join("eeprom.h");
            fs::write(&eeprom_h_path, header_bytes)?;
            eeprom_header = Some(eeprom_h_path.display().to_string());
        }

        if let Some(sii_path) = &opts.sii_out {
            if let Some(parent) = sii_path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(sii_path, &sii_bytes)?;
            sii_bin_file = Some(sii_path.display().to_string());
        }
    }

    Ok(SscGenerateReport {
        project_name,
        ssc_version: project.ssc_version.clone(),
        input_source: project.input_path.display().to_string(),
        target_dir: target_dir.display().to_string(),
        src_dir: src_dir.display().to_string(),
        esp_file,
        esi_file,
        eeprom_header,
        sii_bin_file,
        written_files,
        skipped_files,
        patched_files,
        active_conflicts,
        warnings: project.warnings.clone(),
    })
}

fn attach_application_to_project(project: &mut SlaveProject, app: &SlaveApplication) -> Result<()> {
    let generated_files = build_application_slave_files(app);
    let app_xml = app.to_esp_xml_element();
    project.apply_imported_application(
        &app.name,
        &app.application_file_name,
        app.get_process_data_length_bytes(0x1C12),
        app.od.contains(0x1C12),
        app.get_process_data_length_bytes(0x1C13),
        app.od.contains(0x1C13),
        app.od.module_profile,
        app.od.device_profile,
        generated_files,
        app_xml,
    )
}

fn apply_project_patch_collection(files: &[SlaveFile]) -> Result<(Vec<SlaveFile>, Vec<String>)> {
    let Some(patch_sf) = files.iter().find(|f| f.file_type == SlaveFileType::Patch) else {
        let non_patch = files
            .iter()
            .filter(|f| f.file_type != SlaveFileType::Patch)
            .cloned()
            .collect();
        return Ok((non_patch, Vec::new()));
    };
    let SlaveFileContent::TextLines(patch_lines) = &patch_sf.content else {
        return Err(CliError::Format(format!(
            "Patch file '{}' does not contain text lines",
            patch_sf.name
        )));
    };

    let sections = parse_ssc_patch_sections(patch_lines);
    let mut patched_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut patched_names: Vec<String> = Vec::new();

    for (target_name, cmds) in sections {
        let orig = files
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(&target_name))
            .ok_or_else(|| {
                CliError::Validation(format!(
                    "Patch references file '{target_name}' which is not in the SSC project"
                ))
            })?;
        let SlaveFileContent::TextLines(src_lines) = &orig.content else {
            return Err(CliError::Format(format!(
                "Patch target '{}' is binary, not text",
                orig.name
            )));
        };
        if let Some(outcome) = apply_patch_to_lines(&orig.name, src_lines, &cmds)? {
            patched_names.push(orig.name.clone());
            patched_map.insert(orig.name.to_ascii_lowercase(), outcome.lines);
        }
    }

    if patched_map.is_empty() {
        return Err(CliError::Format(format!(
            "Failed to apply patch '{}' (no matching hunks applied)",
            patch_sf.name
        )));
    }

    let mut out = Vec::with_capacity(files.len());
    for sf in files {
        if sf.file_type == SlaveFileType::Patch {
            continue;
        }
        if let Some(new_lines) = patched_map.remove(&sf.name.to_ascii_lowercase()) {
            let mut updated = sf.clone();
            updated.content = SlaveFileContent::TextLines(new_lines);
            out.push(updated);
        } else {
            out.push(sf.clone());
        }
    }
    Ok((out, patched_names))
}

fn write_project_source_files(
    project: &SlaveProject,
    src_dir: &Path,
    add_delete_comment: bool,
    raw_files: bool,
) -> Result<(Vec<String>, Vec<String>, Vec<String>)> {
    let eval_defines = if raw_files {
        BTreeMap::new()
    } else {
        project.evaluated_defines_map()
    };

    let (working_files, patched_files) = apply_project_patch_collection(&project.files)?;
    let mut written_files = Vec::new();
    let mut skipped_files = Vec::new();

    for sf in &working_files {
        if sf.file_type == SlaveFileType::Patch || sf.name.eq_ignore_ascii_case("ecat_def.h") {
            continue;
        }

        if !sf.expression.is_empty() {
            let norm = normalize_line(&sf.expression, true, true);
            let state = compute_compiler_command(&norm, |k| eval_defines.get(k).cloned());
            if state == SrcCodeType::Inactive {
                skipped_files.push(sf.name.clone());
                continue;
            }
        }

        let dst_path = src_dir.join(&sf.name);
        match &sf.content {
            SlaveFileContent::Binary(bytes) => {
                fs::write(&dst_path, bytes)?;
            }
            SlaveFileContent::TextLines(lines) => {
                if sf.flags.user_file || raw_files {
                    fs::write(&dst_path, encode_crlf_lines(lines))?;
                } else {
                    let processed =
                        preprocess_ssc_source_lines(lines, &eval_defines, add_delete_comment);
                    fs::write(&dst_path, encode_crlf_lines(&processed))?;
                }
            }
            SlaveFileContent::Empty => {
                continue;
            }
        }
        written_files.push(sf.name.clone());
    }

    // Generate `ecat_def.h` (`CodeGenerator::CreateSlaveCfgSourceFile`)
    let all_defines = project.all_defines_map();
    let mut computed_vals: Vec<String> = Vec::with_capacity(project.settings.len());
    for (idx, s) in project.settings.iter().enumerate() {
        let val = if s.flags.read_only.is_true() {
            project
                .calculate_setting_value(idx, None)
                .unwrap_or_else(|| s.value.clone())
        } else {
            s.value.clone()
        };
        computed_vals.push(val);
    }

    let entries: Vec<EcatDefEntry<'_>> = project
        .settings
        .iter()
        .zip(computed_vals.iter())
        .map(|(s, val)| EcatDefEntry {
            code_define: &s.code_define,
            file_area: &s.file_area,
            description: &s.description,
            value: val,
            is_string_type: s.value_type.is_string_type(),
            is_evaluated: s.flags.evaluate.is_true(),
        })
        .collect();

    let conflict_lines = if raw_files {
        project.render_conflict_directives()
    } else {
        Vec::new()
    };
    let conflict_slice = if raw_files && !conflict_lines.is_empty() {
        Some(conflict_lines.as_slice())
    } else {
        None
    };
    let ecat_def_bytes =
        render_ecat_def_h(&project.ssc_version, &entries, &all_defines, conflict_slice);
    fs::write(src_dir.join("ecat_def.h"), ecat_def_bytes)?;
    written_files.push("ecat_def.h".to_string());

    Ok((written_files, skipped_files, patched_files))
}

#[derive(Debug, Clone, Default)]
pub struct SscOdGenerateOptions {
    pub inputs: Vec<PathBuf>,
    pub worksheet_index: Option<usize>,
    pub src_out_dir: Option<PathBuf>,
    pub esi_file: Option<PathBuf>,
    pub offline_xml_out: Option<PathBuf>,
    pub device_index: usize,
    pub overwrite_app_files: bool,
    pub force: bool,
    pub strict_validation: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SscOdGenerateReport {
    pub app_name: String,
    pub object_count: usize,
    pub src_dir: String,
    pub objects_header: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects_header_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_header: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_source: Option<String>,
    pub skipped_existing_app_files: bool,
    pub module_headers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_od_xml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline_od_backup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_esi: Option<SscEsiUpdateSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub validation_warnings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub skipped_invalid_objects: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SscEsiUpdateSummary {
    pub esi_path: String,
    pub backup_path: String,
    pub preserved_default_objects: Vec<String>,
    pub discarded_custom_default_objects: Vec<String>,
}

impl From<EsiUpdateOutcome> for SscEsiUpdateSummary {
    fn from(o: EsiUpdateOutcome) -> Self {
        Self {
            esi_path: o.esi_path.display().to_string(),
            backup_path: o.backup_path.display().to_string(),
            preserved_default_objects: o
                .preserved_default_objects
                .into_iter()
                .map(|idx| format!("0x{idx:04X}"))
                .collect(),
            discarded_custom_default_objects: o
                .discarded_custom_default_objects
                .into_iter()
                .map(|idx| format!("0x{idx:04X}"))
                .collect(),
        }
    }
}

/// Execute standalone `SSC OD Tool` workflow: parse OD file(s), write `Src/<App>Objects.h` + `<App>.h` + `<App>.c`,
/// and either update an existing ESI XML in place or emit `output/<App>Objects.xml`.
pub fn run_standalone_od_tool(opts: &SscOdGenerateOptions) -> Result<SscOdGenerateReport> {
    if opts.inputs.is_empty() {
        return Err(CliError::Usage(
            "At least one OD input file (.xlsx, .csv, .xml, .eds, .tmc) is required".into(),
        ));
    }

    if let Some(explicit_esi) = &opts.esi_file {
        if !explicit_esi.is_file() {
            return Err(CliError::Usage(format!(
                "ESI file '{}' does not exist",
                explicit_esi.display()
            )));
        }
    }

    let mut app = crate::od::parsers::parse_application_files_with_sheet(
        &opts.inputs,
        false,
        opts.worksheet_index,
    )?;

    if app.name.trim().is_empty() {
        app.name = "MyAppl".to_string();
        app.application_file_name = "MyAppl".to_string();
    }
    if app.od.name.trim().is_empty() {
        app.od.name = app.name.clone();
    }

    let val_rep = app.od.validate_objects(opts.strict_validation, opts.force);
    if !opts.force && !val_rep.errors.is_empty() {
        return Err(CliError::Validation(val_rep.errors.join("; ")));
    }
    if opts.force && !val_rep.skipped_objects.is_empty() {
        // Purge any auto-generated PDO mapping entries pointing to skipped objects and re-finalize
        for (&pdo_idx, pdo_obj) in app.od.objects.iter_mut() {
            if (0x1600..=0x17FF).contains(&pdo_idx) || (0x1A00..=0x1BFF).contains(&pdo_idx) {
                pdo_obj.entries.retain(|e| {
                    if e.sub_index == 0 {
                        return true;
                    }
                    let be = crate::od::types::reverse_hex_byte_pairs(&e.default_data);
                    if be.len() >= 4 {
                        if let Ok(mapped_idx) = u16::from_str_radix(&be[..4], 16) {
                            return !val_rep.skipped_objects.contains(&mapped_idx);
                        }
                    }
                    true
                });
                for (seq, e) in pdo_obj
                    .entries
                    .iter_mut()
                    .filter(|e| e.sub_index > 0)
                    .enumerate()
                {
                    e.sub_index = (seq + 1) as u8;
                }
            }
        }
        app.od.finalize_and_validate(false);
    }

    let input_dir = opts.inputs[0]
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let src_dir = match &opts.src_out_dir {
        Some(d) => d.clone(),
        None => {
            let candidate_src = input_dir.join("Src");
            if candidate_src.is_dir() {
                candidate_src
            } else {
                input_dir.join("output")
            }
        }
    };

    let c_out = write_standalone_od_c_files(&app, &src_dir, opts.overwrite_app_files)?;

    // Determine target ESI (`SSC OD Tool` checks explicit `/esi` first, else `<input_dir>/<od.Name>.xml` if `!= input`)
    let target_esi = if let Some(explicit_esi) = &opts.esi_file {
        Some(explicit_esi.clone())
    } else {
        let auto_esi = input_dir.join(format!("{}.xml", app.od.name));
        let same_as_input = same_file_path(&auto_esi, &opts.inputs[0]);
        if auto_esi.is_file() && !same_as_input {
            Some(auto_esi)
        } else {
            None
        }
    };

    let mut offline_od_xml = None;
    let mut offline_od_backup = None;
    let mut updated_esi = None;

    if let Some(esi_path) = target_esi.filter(|p| p.is_file()) {
        let outcome = update_esi_file(&esi_path, opts.device_index, &app.od, Some(&app))?;
        updated_esi = Some(SscEsiUpdateSummary::from(outcome));
    } else {
        let offline_path = match &opts.offline_xml_out {
            Some(p) => p.clone(),
            None => input_dir
                .join("output")
                .join(format!("{}Objects.xml", app.od.name)),
        };
        if offline_path.is_file() {
            let bak = PathBuf::from(format!("{}.bak", offline_path.display()));
            fs::copy(&offline_path, &bak)?;
            offline_od_backup = Some(bak.display().to_string());
        }
        write_offline_dictionary(&offline_path, &app.od, false, "")?;
        offline_od_xml = Some(offline_path.display().to_string());
    }

    Ok(SscOdGenerateReport {
        app_name: app.name,
        object_count: app.od.objects.len(),
        src_dir: src_dir.display().to_string(),
        objects_header: c_out.objects_header.display().to_string(),
        objects_header_backup: c_out.objects_header_backup.map(|p| p.display().to_string()),
        app_header: c_out.app_header.map(|p| p.display().to_string()),
        app_source: c_out.app_source.map(|p| p.display().to_string()),
        skipped_existing_app_files: c_out.skipped_existing_app_files,
        module_headers: c_out
            .module_headers
            .into_iter()
            .map(|p| p.display().to_string())
            .collect(),
        offline_od_xml,
        offline_od_backup,
        updated_esi,
        validation_warnings: val_rep.warnings,
        skipped_invalid_objects: val_rep
            .skipped_objects
            .into_iter()
            .map(|idx| format!("0x{idx:04X}"))
            .collect(),
    })
}

/// Apply a unified `.patch` file directly to a source directory on disk.
pub fn apply_patch_to_directory(patch_file: &Path, src_dir: &Path) -> Result<Vec<String>> {
    let raw_patch = fs::read(patch_file)?;
    let patch_lines = split_text_lines(&bytes_to_text(&raw_patch));
    let sections = parse_ssc_patch_sections(&patch_lines);
    let mut patched = Vec::new();

    for (basename, cmds) in sections {
        let target_path = src_dir.join(&basename);
        if !target_path.is_file() {
            return Err(CliError::Usage(format!(
                "Patch target '{}' does not exist in '{}'",
                basename,
                src_dir.display()
            )));
        }
        let raw_src = fs::read(&target_path)?;
        let src_lines = split_text_lines(&bytes_to_text(&raw_src));
        if let Some(outcome) = apply_patch_to_lines(&basename, &src_lines, &cmds)? {
            fs::write(&target_path, encode_crlf_lines(&outcome.lines))?;
            patched.push(target_path.display().to_string());
        }
    }

    if patched.is_empty() {
        return Err(CliError::Format(format!(
            "No hunks applied from patch '{}'",
            patch_file.display()
        )));
    }
    Ok(patched)
}

fn same_file_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => a
            .to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy()),
    }
}

fn parse_any_usize(raw: &str) -> usize {
    let s = raw.trim();
    if let Some(hx) = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .or_else(|| s.strip_prefix("#x"))
        .or_else(|| s.strip_prefix("#X"))
    {
        usize::from_str_radix(hx, 16).unwrap_or(0)
    } else {
        s.parse::<usize>().unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::expr::evaluate_boolean_expression;
    use crate::model::{SlaveFileContent, SlaveProject};
    use crate::od::c_codegen::render_application_c;
    use crate::od::parsers::{parse_application_files, parse_single_application_file};
    use crate::od::types::{resolve_data_type_name, reverse_hex_byte_pairs};

    fn make_temp_dir(tag: &str) -> PathBuf {
        static SEQ: AtomicUsize = AtomicUsize::new(1);
        let dir = std::env::temp_dir().join(format!(
            "ethercat_ssc_unit_{tag}_{}_{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn ssc_expression_and_od_type_resolution() {
        let defines = [
            ("COE_SUPPORTED", "1"),
            ("MAILBOX_SUPPORTED", "1"),
            ("FOE_SUPPORTED", "0"),
        ];
        let val = evaluate_boolean_expression("COE_SUPPORTED && !FOE_SUPPORTED", |k| {
            defines.iter().find(|(name, _)| *name == k).map(|(_, v)| *v)
        });
        assert!(val);

        let (dt_id, bit_len) = resolve_data_type_name("UINT32").unwrap();
        assert!(dt_id > 0 && bit_len == 32);
        assert!(resolve_data_type_name("äöü").is_err());
    }

    #[test]
    fn standalone_application_c_callbacks_have_no_format_placeholders() {
        let dir = make_temp_dir("cb");
        let csv_path = dir.join("CallbackApp.csv");
        let csv = concat!(
            "Index;ObjectCode;SI;DataType;Name;Default Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description\r\n",
            "0x2000;VAR;0;UINT16;ControlParam;0x0001;o;;rw;;ReadParam2000;WriteParam2000;Test callback object\r\n",
        );
        fs::write(&csv_path, csv).unwrap();

        let app = parse_single_application_file(&csv_path, false).unwrap();
        let rendered = render_application_c(&app.od, "CallbackApp", "CallbackApp", false);
        assert!(
            !rendered.contains("{0}"),
            "standalone render_application_c must not emit literal C# '{{0}}' placeholders:\n{rendered}"
        );
        assert!(rendered.contains("UINT8 ReadParam2000(UINT16 index, UINT8 subindex"));
        assert!(rendered.contains("UINT8 WriteParam2000(UINT16 index, UINT8 subindex"));
        assert!(rendered.contains("Warning: Implement CoE read callback"));
        assert!(rendered.contains("Warning: Implement CoE write callback"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn multi_file_od_merge_preserves_auto_pdo_mappings() {
        let dir = make_temp_dir("merge");
        let base_csv = dir.join("base.csv");
        let extra_csv = dir.join("extra.csv");

        fs::write(
            &base_csv,
            concat!(
                "Index;ObjectCode;SI;DataType;Name;Default Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description\r\n",
                "0x6000;VAR;0;UINT16;BaseInput;0;m;;ro;tx;;;\r\n",
                "0x7000;VAR;0;UINT16;BaseOutput;0;m;;rw;rx;;;\r\n",
            ),
        )
        .unwrap();
        fs::write(
            &extra_csv,
            concat!(
                "Index;ObjectCode;SI;DataType;Name;Default Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description\r\n",
                "0x6010;VAR;0;UINT32;ExtraInput;0;m;;ro;tx;;;\r\n",
                "0x7010;VAR;0;UINT32;ExtraOutput;0;m;;rw;rx;;;\r\n",
            ),
        )
        .unwrap();

        let merged = parse_application_files(&[&base_csv, &extra_csv], false).unwrap();
        assert!(
            merged.od.get(0x1600).is_some() && merged.od.get(0x1601).is_some(),
            "expected both 0x1600 and 0x1601 RxPDO mappings after merge"
        );
        assert!(
            merged.od.get(0x1A00).is_some() && merged.od.get(0x1A01).is_some(),
            "expected both 0x1A00 and 0x1A01 TxPDO mappings after merge"
        );
        let map_1600 = reverse_hex_byte_pairs(
            &merged
                .od
                .get(0x1600)
                .unwrap()
                .entry(1)
                .unwrap()
                .default_data,
        );
        let map_1601 = reverse_hex_byte_pairs(
            &merged
                .od
                .get(0x1601)
                .unwrap()
                .entry(1)
                .unwrap()
                .default_data,
        );
        assert_eq!(map_1600, "70000010");
        assert_eq!(map_1601, "70100020");

        let sm2 = merged.od.get(0x1C12).expect("0x1C12 auto-created");
        assert_eq!(
            sm2.entry(1)
                .map(|e| reverse_hex_byte_pairs(&e.default_data))
                .as_deref(),
            Some("1600")
        );
        assert_eq!(
            sm2.entry(2)
                .map(|e| reverse_hex_byte_pairs(&e.default_data))
                .as_deref(),
            Some("1601")
        );

        let sm3 = merged.od.get(0x1C13).expect("0x1C13 auto-created");
        assert_eq!(
            sm3.entry(1)
                .map(|e| reverse_hex_byte_pairs(&e.default_data))
                .as_deref(),
            Some("1A00")
        );
        assert_eq!(
            sm3.entry(2)
                .map(|e| reverse_hex_byte_pairs(&e.default_data))
                .as_deref(),
            Some("1A01")
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn esp_embedded_file_preserves_amp_gt_identifiers_and_lf_lines() {
        let dir = make_temp_dir("esp");
        let esp_path = dir.join("LfEmbedded.esp");
        // XML-escaped `&amp;gt_counter` unescapes once in `DomScanner` to `&gt_counter`;
        // `parse_slave_file_element` must NOT re-unescape `&gt` into `>_counter` and must split `\n` lines.
        let esp_xml = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
            "<SlaveConfiguratorProject ToolVersion=\"1.5.0.0\" SSCVersion=\"5.13\">\n",
            "  <Settings />\n",
            "  <Files>\n",
            "    <File Name=\"app_logic.c\" Type=\"Src\" Version=\"1.0.0.0\">int gt_counter = 0;\nint *ptr = &amp;gt_counter;\nreturn *ptr;\n</File>\n",
            "  </Files>\n",
            "</SlaveConfiguratorProject>\n",
        );
        fs::write(&esp_path, esp_xml.as_bytes()).unwrap();

        let proj = SlaveProject::load(Some(&esp_path), None).unwrap();
        assert_eq!(proj.files.len(), 1);
        match &proj.files[0].content {
            SlaveFileContent::TextLines(lines) => {
                assert_eq!(
                    lines.as_slice(),
                    [
                        "int gt_counter = 0;",
                        "int *ptr = &gt_counter;",
                        "return *ptr;",
                    ]
                );
            }
            other => panic!("expected TextLines, got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn esi_default_value_widths_and_eds_sub255() {
        let dir = make_temp_dir("esi_def");
        let esi_path = dir.join("Defaults.xml");
        let esi_xml = concat!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
            "<EtherCATInfo>\n",
            "  <Descriptions>\n",
            "    <Devices>\n",
            "      <Device>\n",
            "        <Type ProductCode=\"#x1000\" RevisionNo=\"#x0001\">DefDev</Type>\n",
            "        <Name>DefDev</Name>\n",
            "        <Profile>\n",
            "          <ProfileNo>5001</ProfileNo>\n",
            "          <Dictionary>\n",
            "            <DataTypes>\n",
            "              <DataType><Name>USINT</Name><BitSize>8</BitSize></DataType>\n",
            "              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>\n",
            "              <DataType><Name>INT</Name><BitSize>16</BitSize></DataType>\n",
            "              <DataType><Name>ULINT</Name><BitSize>64</BitSize></DataType>\n",
            "            </DataTypes>\n",
            "            <Objects>\n",
            "              <Object>\n",
            "                <Index>#x2001</Index><Name>ByteVal</Name><Type>USINT</Type><BitSize>8</BitSize>\n",
            "                <Info><DefaultValue>42</DefaultValue></Info>\n",
            "              </Object>\n",
            "              <Object>\n",
            "                <Index>#x2002</Index><Name>WordVal</Name><Type>UINT</Type><BitSize>16</BitSize>\n",
            "                <Info><DefaultValue>#x1234</DefaultValue></Info>\n",
            "              </Object>\n",
            "              <Object>\n",
            "                <Index>#x2003</Index><Name>NegVal</Name><Type>INT</Type><BitSize>16</BitSize>\n",
            "                <Info><DefaultValue>-300</DefaultValue></Info>\n",
            "              </Object>\n",
            "              <Object>\n",
            "                <Index>#x2004</Index><Name>QwordVal</Name><Type>ULINT</Type><BitSize>64</BitSize>\n",
            "                <Info><DefaultValue>#x0102030405060708</DefaultValue></Info>\n",
            "              </Object>\n",
            "            </Objects>\n",
            "          </Dictionary>\n",
            "        </Profile>\n",
            "      </Device>\n",
            "    </Devices>\n",
            "  </Descriptions>\n",
            "</EtherCATInfo>\n",
        );
        fs::write(&esi_path, esi_xml.as_bytes()).unwrap();

        let app = parse_single_application_file(&esi_path, false).unwrap();
        assert_eq!(
            app.od.get(0x2001).unwrap().entry(0).unwrap().default_data,
            "2A"
        );
        assert_eq!(
            app.od.get(0x2002).unwrap().entry(0).unwrap().default_data,
            "3412"
        );
        assert_eq!(
            app.od.get(0x2003).unwrap().entry(0).unwrap().default_data,
            "D4FE"
        );
        assert_eq!(
            app.od.get(0x2004).unwrap().entry(0).unwrap().default_data,
            "0807060504030201"
        );

        let eds_path = dir.join("MaxSub.eds");
        let eds_txt = concat!(
            "[2100]\nParameterName=BigRec\nObjectType=0x9\nSubNumber=2\n",
            "[2100sub0]\nParameterName=Count\nDataType=0x0005\nAccessType=ro\nDefaultValue=255\n",
            "[2100subff]\nParameterName=LastSub\nDataType=0x0006\nAccessType=rw\nDefaultValue=0xBEEF\n",
        );
        fs::write(&eds_path, eds_txt.as_bytes()).unwrap();
        let eds_app = parse_single_application_file(&eds_path, false).unwrap();
        assert_eq!(
            eds_app
                .od
                .get(0x2100)
                .unwrap()
                .entry(255)
                .unwrap()
                .default_data,
            "EFBE"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
