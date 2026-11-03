use serde_json::{json, Value};

use crate::cli::{SscOdSubcommand, SscSubcommand, SscTemplateKind};
use crate::commands::{write_file_bytes, CommandRender};
use ethercat_ssc::archive::encode_image_data_16x14;
use ethercat_ssc::esi_gen::{combine_esi_files, update_esi_file};
use ethercat_ssc::model::{
    export_ssc_tool_configuration_xml, import_settings_from_ecat_def_h,
    import_settings_from_esi_xml, load_external_configurations, SlaveProject,
};
use ethercat_ssc::od::{
    parse_application_files, parse_single_application_file_with_sheet, write_csv_template,
    write_od_to_csv, write_xlsx_template,
};
use ethercat_ssc::{
    apply_patch_to_directory, generate_ssc_project, run_standalone_od_tool, SscEsiUpdateSummary,
    SscGenerateOptions, SscOdGenerateOptions,
};
use ethercat_wire::error::{CliError, Result};

pub fn handle_ssc(sub: &SscSubcommand) -> Result<CommandRender> {
    match sub {
        SscSubcommand::Generate(args) => {
            let rep = generate_ssc_project(&SscGenerateOptions {
                project_source: args.project.clone(),
                ssc_dir: args.ssc_dir.clone(),
                output_dir: args.output.clone(),
                src_out_dir: args.src_dir.clone(),
                project_name: args.name.clone(),
                app_files: args.app.clone(),
                config_file: args.config.clone(),
                config_name: args.config_name.clone(),
                allow_file_import: args.allow_file_import,
                patch_file: args.patch.clone(),
                defines: args.defines.clone(),
                use_gui_options: args.use_gui_options,
                options_file: args.options_file.clone(),
                raw_files: args.raw_files,
                add_delete_comment: args.delete_comments,
                no_esp: args.no_esp,
                no_esi: args.no_esi,
                esi_code_config: args.esi_code_config,
                esi_trace_file: args.esi_trace_file.clone(),
                sii_out: args.sii_out.clone(),
                strict_conflicts: args.strict_conflicts,
                ignore_errors: args.ignore_errors,
            })?;

            let mut lines = vec![format!(
                "SSC Generate OK: {} (SSC {}) -> '{}'",
                rep.project_name, rep.ssc_version, rep.target_dir
            )];
            lines.push(format!(
                "  Source files : {} written, {} skipped -> '{}'",
                rep.written_files.len(),
                rep.skipped_files.len(),
                rep.src_dir
            ));
            if let Some(ref esp) = rep.esp_file {
                lines.push(format!("  Project .esp : '{esp}'"));
            }
            if let Some(ref esi) = rep.esi_file {
                lines.push(format!("  ESI XML      : '{esi}'"));
            }
            if let Some(ref eep) = rep.eeprom_header {
                lines.push(format!("  EEPROM header: '{eep}'"));
            }
            if let Some(ref bin) = rep.sii_bin_file {
                lines.push(format!("  SII .bin     : '{bin}'"));
            }
            if !rep.patched_files.is_empty() {
                lines.push(format!("  Patched files: {}", rep.patched_files.join(", ")));
            }
            for c in &rep.active_conflicts {
                lines.push(format!(
                    "  Conflict [{:?}] ({}): {}",
                    c.severity, c.expression, c.message
                ));
            }
            Ok(CommandRender {
                json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                text: lines.join("\n"),
            })
        }

        SscSubcommand::ListDefines {
            project,
            ssc_dir,
            config,
            config_name,
            all,
            filter,
        } => {
            let mut prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
            if let Some(cfg_path) = config {
                let cfgs = load_external_configurations(cfg_path)?;
                let sel = match config_name.as_deref() {
                    None | Some("") => &cfgs[0],
                    Some(wanted) => cfgs.iter().find(|c| c.name == wanted).ok_or_else(|| {
                        CliError::Validation(format!(
                            "Configuration '{wanted}' not found in '{}'",
                            cfg_path.display()
                        ))
                    })?,
                };
                let _ = prj.apply_configuration(sel, false, true)?;
            } else if let Some(wanted) = config_name.as_deref().filter(|s| !s.is_empty()) {
                let sel = prj
                    .embedded_configurations
                    .iter()
                    .find(|c| c.name == wanted)
                    .cloned()
                    .ok_or_else(|| {
                        CliError::Validation(format!("Embedded configuration '{wanted}' not found"))
                    })?;
                let _ = prj.apply_configuration(&sel, false, true)?;
            }

            let flt = filter.as_deref().map(str::to_ascii_lowercase);
            let mut items = Vec::new();
            let mut text_lines = vec!["Available defines".to_string()];

            for s in &prj.settings {
                if !*all && s.flags.read_only.is_true() {
                    continue;
                }
                if let Some(ref q) = flt {
                    let hit = s.code_define.to_ascii_lowercase().contains(q)
                        || s.file_area.to_ascii_lowercase().contains(q)
                        || s.node_path.to_ascii_lowercase().contains(q);
                    if !hit {
                        continue;
                    }
                }
                if s.value.is_empty() {
                    text_lines.push(s.code_define.clone());
                } else {
                    text_lines.push(format!("{} {}", s.code_define, s.value));
                }
                items.push(json!({
                    "code_define": s.code_define,
                    "value": s.value,
                    "value_type": s.value_type.to_xml_value_type(),
                    "file_area": s.file_area,
                    "node_path": s.node_path,
                    "read_only": s.flags.read_only.is_true(),
                    "evaluated": s.flags.evaluate.is_true(),
                    "visible": s.flags.visible.is_true(),
                    "description": s.description,
                }));
            }

            Ok(CommandRender {
                json: json!({
                    "ssc_version": prj.ssc_version,
                    "source": prj.input_path.display().to_string(),
                    "count": items.len(),
                    "defines": items,
                }),
                text: text_lines.join("\n"),
            })
        }

        SscSubcommand::ListConfigs {
            project,
            ssc_dir,
            config,
        } => {
            let (source_label, cfgs) = if let Some(cfg_path) = config {
                (
                    cfg_path.display().to_string(),
                    load_external_configurations(cfg_path)?,
                )
            } else {
                let prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
                (
                    prj.input_path.display().to_string(),
                    prj.embedded_configurations,
                )
            };

            let mut lines = vec![format!(
                "SSC Configurations in '{}' ({}):",
                source_label,
                cfgs.len()
            )];
            let mut items = Vec::with_capacity(cfgs.len());
            for (idx, c) in cfgs.iter().enumerate() {
                let ver = if !c.config_version.is_empty() {
                    c.config_version.as_str()
                } else {
                    c.ssc_version.as_str()
                };
                lines.push(format!(
                    "  [{idx}] {} (v{}) -- {} settings, {} files {}",
                    c.name,
                    ver,
                    c.settings.len(),
                    c.files.len(),
                    if c.info.is_empty() {
                        String::new()
                    } else {
                        format!("| {}", c.info)
                    }
                ));
                items.push(json!({
                    "index": idx,
                    "name": c.name,
                    "ssc_version": c.ssc_version,
                    "config_version": c.config_version,
                    "vendor_id": c.vendor_id,
                    "vendor_name": c.vendor_name,
                    "info": c.info,
                    "patch": c.patch_rel_path,
                    "application_file": c.application_rel_path,
                    "setting_count": c.settings.len(),
                    "file_count": c.files.len(),
                }));
            }

            Ok(CommandRender {
                json: json!({
                    "source": source_label,
                    "count": items.len(),
                    "configurations": items,
                }),
                text: lines.join("\n"),
            })
        }

        SscSubcommand::ExportConfig {
            project,
            ssc_dir,
            defines,
            name,
            info,
            output,
        } => {
            let mut prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
            for (k, v) in defines {
                prj.apply_cli_define(k, v)?;
            }
            let xml_bytes = export_ssc_tool_configuration_xml(&prj, name, info);
            write_file_bytes(output, &xml_bytes)?;
            let out_str = output.display().to_string();
            Ok(CommandRender {
                json: json!({
                    "configuration_name": name,
                    "ssc_version": prj.ssc_version,
                    "output_file": out_str,
                    "byte_size": xml_bytes.len(),
                }),
                text: format!(
                    "Exported SSC configuration '{}' (SSC {}) -> '{}' ({} bytes)",
                    name,
                    prj.ssc_version,
                    output.display(),
                    xml_bytes.len()
                ),
            })
        }

        SscSubcommand::ImportHeader {
            header,
            project,
            ssc_dir,
            output,
            ignore_errors,
        } => {
            let imported_cfg = import_settings_from_ecat_def_h(header)?;
            let mut prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
            let _ = prj.apply_configuration(&imported_cfg, false, *ignore_errors)?;
            let is_xml = output
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("xml"));

            let final_path = if is_xml {
                let bytes =
                    export_ssc_tool_configuration_xml(&prj, &imported_cfg.name, &imported_cfg.info);
                write_file_bytes(output, &bytes)?;
                output.clone()
            } else {
                prj.save_esp(output)?
            };

            Ok(CommandRender {
                json: json!({
                    "header_file": header.display().to_string(),
                    "imported_define_count": imported_cfg.settings.len(),
                    "header_ssc_version": imported_cfg.ssc_version,
                    "project_ssc_version": prj.ssc_version,
                    "output_file": final_path.display().to_string(),
                }),
                text: format!(
                    "Imported {} defines from '{}' (SSC {}) -> '{}'",
                    imported_cfg.settings.len(),
                    header.display(),
                    imported_cfg.ssc_version,
                    final_path.display()
                ),
            })
        }

        SscSubcommand::ImportEsi {
            esi,
            device_index,
            project,
            ssc_dir,
            output,
            ignore_errors,
        } => {
            let imported_cfg = import_settings_from_esi_xml(esi, *device_index)?;
            let mut prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
            let _ = prj.apply_configuration(&imported_cfg, false, *ignore_errors)?;
            let is_xml = output
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("xml"));

            let final_path = if is_xml {
                let bytes =
                    export_ssc_tool_configuration_xml(&prj, &imported_cfg.name, &imported_cfg.info);
                write_file_bytes(output, &bytes)?;
                output.clone()
            } else {
                prj.save_esp(output)?
            };

            Ok(CommandRender {
                json: json!({
                    "esi_file": esi.display().to_string(),
                    "device_index": device_index,
                    "configuration_name": imported_cfg.name,
                    "imported_setting_count": imported_cfg.settings.len(),
                    "esi_ssc_version": imported_cfg.ssc_version,
                    "project_ssc_version": prj.ssc_version,
                    "output_file": final_path.display().to_string(),
                }),
                text: format!(
                    "Imported {} settings from ESI '{}' (device #{}) -> '{}'",
                    imported_cfg.settings.len(),
                    esi.display(),
                    device_index,
                    final_path.display()
                ),
            })
        }

        SscSubcommand::Migrate {
            project,
            target_ssc,
            ssc_dir,
            output,
            ignore_errors,
        } => {
            let old_prj = SlaveProject::load(Some(project.as_path()), None)?;
            let mut target_prj = SlaveProject::load(target_ssc.as_deref(), ssc_dir.as_deref())?;
            let rep = target_prj.adapt_from(&old_prj, *ignore_errors)?;
            let has_app = target_prj.application_xml.is_some();
            let saved = target_prj.save_esp(output)?;

            let mut lines = vec![format!(
                "Migrated SSC project '{}' (SSC {} -> {}) -> '{}'",
                project.display(),
                rep.from_ssc_version,
                rep.to_ssc_version,
                saved.display()
            )];
            lines.push(format!(
                "  Settings migrated: {}, user files kept: {}, ESI fragments kept: {}, OD kept: {}",
                rep.migrated_setting_count,
                rep.preserved_user_files.len(),
                rep.preserved_esi_fragments,
                has_app
            ));
            for w in &rep.warnings {
                lines.push(format!("  Warning: {w}"));
            }

            Ok(CommandRender {
                json: json!({
                    "source_project": project.display().to_string(),
                    "output_file": saved.display().to_string(),
                    "preserved_application": has_app,
                    "report": rep,
                }),
                text: lines.join("\n"),
            })
        }

        SscSubcommand::CombineEsi { inputs, output } => {
            let outcome = combine_esi_files(inputs, output)?;
            let mut lines = vec![format!(
                "Combined {} ESI file(s) -> '{}' ({} devices, {} groups, {} modules)",
                outcome.input_count,
                outcome.output_path,
                outcome.device_count,
                outcome.group_count,
                outcome.module_count
            )];
            if let Some(ref bak) = outcome.backup_path {
                lines.push(format!("  Backup saved: '{bak}'"));
            }
            for w in &outcome.warnings {
                lines.push(format!("  Warning: {w}"));
            }
            Ok(CommandRender {
                json: json!({
                    "output_file": outcome.output_path,
                    "backup_file": outcome.backup_path,
                    "input_count": outcome.input_count,
                    "device_count": outcome.device_count,
                    "group_count": outcome.group_count,
                    "module_count": outcome.module_count,
                    "warnings": outcome.warnings,
                }),
                text: lines.join("\n"),
            })
        }

        SscSubcommand::Check {
            project,
            ssc_dir,
            defines,
            issues_xml,
        } => {
            let mut prj = SlaveProject::load(project.as_deref(), ssc_dir.as_deref())?;
            for (k, v) in defines {
                prj.apply_cli_define(k, v)?;
            }
            let conflicts = prj.evaluate_active_conflicts();
            let issues = prj.evaluate_known_issues(issues_xml.as_deref())?;

            let mut lines = vec![format!(
                "SSC Check (SSC {}): {} active conflicts, {} matching known issues",
                prj.ssc_version,
                conflicts.len(),
                issues.len()
            )];
            for c in &conflicts {
                lines.push(format!(
                    "  [CONFLICT:{:?}] ({}) {}",
                    c.severity, c.expression, c.message
                ));
            }
            for iss in &issues {
                lines.push(format!(
                    "  [ISSUE #{}] {} -- {}",
                    iss.number, iss.tag, iss.abstract_title
                ));
            }
            Ok(CommandRender {
                json: json!({
                    "ssc_version": prj.ssc_version,
                    "source": prj.input_path.display().to_string(),
                    "active_conflicts": conflicts,
                    "known_issues": issues,
                }),
                text: lines.join("\n"),
            })
        }

        SscSubcommand::Od(od_sub) => match od_sub {
            SscOdSubcommand::Generate(args) => {
                let rep = run_standalone_od_tool(&SscOdGenerateOptions {
                    inputs: args.inputs.clone(),
                    worksheet_index: args.worksheet,
                    src_out_dir: args.src_dir.clone(),
                    esi_file: args.esi.clone(),
                    offline_xml_out: args.offline_xml.clone(),
                    device_index: args.device_index,
                    overwrite_app_files: args.overwrite_app,
                    force: args.force,
                    strict_validation: args.strict,
                })?;

                let mut lines = vec![format!(
                    "SSC OD Generate OK: '{}' ({} objects) -> '{}'",
                    rep.app_name, rep.object_count, rep.src_dir
                )];
                lines.push(format!("  Objects header : '{}'", rep.objects_header));
                if let Some(ref ah) = rep.app_header {
                    lines.push(format!("  App header     : '{ah}'"));
                }
                if let Some(ref ac) = rep.app_source {
                    lines.push(format!("  App source     : '{ac}'"));
                }
                if rep.skipped_existing_app_files {
                    lines.push(format!(
                        "  Basic app files: skipped ('{}.*' already exists)",
                        rep.app_name
                    ));
                }
                if let Some(ref ox) = rep.offline_od_xml {
                    lines.push(format!("  Offline OD XML : '{ox}'"));
                }
                if let Some(ref ue) = rep.updated_esi {
                    lines.push(format!(
                        "  Updated ESI    : '{}' (backup: '{}')",
                        ue.esi_path, ue.backup_path
                    ));
                }
                if !rep.skipped_invalid_objects.is_empty() {
                    lines.push(format!(
                        "  Skipped invalid: {}",
                        rep.skipped_invalid_objects.join(", ")
                    ));
                }
                for w in &rep.validation_warnings {
                    lines.push(format!("  Warning        : {w}"));
                }

                Ok(CommandRender {
                    json: serde_json::to_value(&rep).unwrap_or(Value::Null),
                    text: lines.join("\n"),
                })
            }

            SscOdSubcommand::Template { output, kind } => {
                let resolved_kind = match kind {
                    Some(k) => *k,
                    None => {
                        let ext = output
                            .extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("")
                            .to_ascii_lowercase();
                        if ext == "csv" {
                            SscTemplateKind::Csv
                        } else {
                            SscTemplateKind::Xlsx
                        }
                    }
                };
                match resolved_kind {
                    SscTemplateKind::Csv => write_csv_template(output)?,
                    SscTemplateKind::Xlsx => write_xlsx_template(output)?,
                }
                let kind_name = match resolved_kind {
                    SscTemplateKind::Csv => "csv",
                    SscTemplateKind::Xlsx => "xlsx",
                };
                Ok(CommandRender {
                    json: json!({
                        "kind": kind_name,
                        "output_file": output.display().to_string(),
                    }),
                    text: format!(
                        "Created SSC Object Dictionary {kind_name} wizard template -> '{}'",
                        output.display()
                    ),
                })
            }

            SscOdSubcommand::Export {
                input,
                output,
                worksheet,
            } => {
                let app = parse_single_application_file_with_sheet(input, false, *worksheet)?;
                write_od_to_csv(&app.od, output)?;
                Ok(CommandRender {
                    json: json!({
                        "input_file": input.display().to_string(),
                        "output_file": output.display().to_string(),
                        "app_name": app.name,
                        "object_count": app.od.objects.len(),
                    }),
                    text: format!(
                        "Exported {} OD objects from '{}' -> '{}'",
                        app.od.objects.len(),
                        input.display(),
                        output.display()
                    ),
                })
            }

            SscOdSubcommand::Check {
                inputs,
                worksheet,
                strict,
            } => {
                let mut app = if let Some(ws) = worksheet {
                    let mut base =
                        parse_single_application_file_with_sheet(&inputs[0], false, Some(*ws))?;
                    for extra in &inputs[1..] {
                        let next =
                            parse_single_application_file_with_sheet(extra, false, Some(*ws))?;
                        for (_, obj) in next.od.objects {
                            base.od.objects.insert(obj.index, obj);
                        }
                    }
                    base.od.finalize_and_validate(true);
                    base
                } else {
                    parse_application_files(inputs, false)?
                };
                let rep = app.od.validate_objects(*strict, false);
                let mut lines = vec![format!(
                    "OD Check '{}': {} objects, {} errors, {} warnings",
                    app.name,
                    app.od.objects.len(),
                    rep.errors.len(),
                    rep.warnings.len()
                )];
                for e in &rep.errors {
                    lines.push(format!("  [ERROR] {e}"));
                }
                for w in &rep.warnings {
                    lines.push(format!("  [WARN ] {w}"));
                }
                if !rep.errors.is_empty() {
                    return Err(CliError::Validation(rep.errors.join("; ")));
                }
                Ok(CommandRender {
                    json: json!({
                        "app_name": app.name,
                        "object_count": app.od.objects.len(),
                        "valid": rep.errors.is_empty(),
                        "errors": rep.errors,
                        "warnings": rep.warnings,
                    }),
                    text: lines.join("\n"),
                })
            }
        },

        SscSubcommand::UpdateEsi {
            esi,
            od,
            device_index,
        } => {
            let app = parse_application_files(od, false)?;
            let outcome = update_esi_file(esi, *device_index, &app.od, Some(&app))?;
            let summary = SscEsiUpdateSummary::from(outcome);
            Ok(CommandRender {
                text: format!(
                    "Updated ESI '{}' from '{}' (backup saved to '{}')",
                    summary.esi_path, app.name, summary.backup_path
                ),
                json: serde_json::to_value(&summary).unwrap_or(Value::Null),
            })
        }

        SscSubcommand::Patch { patch, src_dir } => {
            let patched = apply_patch_to_directory(patch, src_dir)?;
            Ok(CommandRender {
                text: format!(
                    "Applied patch '{}' to {} file(s): {}",
                    patch.display(),
                    patched.len(),
                    patched.join(", ")
                ),
                json: json!({
                    "patch_file": patch.display().to_string(),
                    "src_dir": src_dir.display().to_string(),
                    "patched_files": patched,
                }),
            })
        }

        SscSubcommand::ImageHex { image } => {
            let hex_data = encode_image_data_16x14(image)?;
            Ok(CommandRender {
                text: hex_data.clone(),
                json: json!({
                    "image_file": image.display().to_string(),
                    "dimensions": "16x14",
                    "hex_length": hex_data.len(),
                    "image_data_16x14": hex_data,
                }),
            })
        }
    }
}
