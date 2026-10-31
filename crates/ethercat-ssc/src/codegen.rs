use std::collections::BTreeMap;

use crate::expr::{compute_compiler_command, normalize_line, SrcCodeType};

/// Canonical `ecat_def.h` skeleton matching `ET9300Project.Properties.Resources.CfgSourceFileStructure`
/// (preserving exact tab/space header banners).
const CFG_SOURCE_FILE_STRUCTURE: &str = concat!(
    "/*\r\n",
    "* This source file is part of the EtherCAT Slave Stack Code licensed by Beckhoff Automation GmbH & Co KG, 33415 Verl, Germany.\r\n",
    "* The corresponding license agreement applies. This hint shall not be removed.\r\n",
    "* https://www.beckhoff.com/media/downloads/slave-stack-code/ethercat_ssc_license.pdf\r\n",
    "*/\r\n",
    "\r\n",
    "\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tecat_def.h\r\n",
    "------  SSC version : \r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "\r\n",
    "#ifndef _ECATDEF_H_\r\n",
    "#define _ECATDEF_H_\r\n",
    "\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tIncludes\r\n",
    "------ \r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "#include <stdlib.h>\r\n",
    "#include <string.h>\r\n",
    "\r\n",
    "/*CODE_INSERT_START (SYSTEM_HEADER_FILE)*/\r\n",
    "/*CODE_INSERT_END*/\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tSlave Sample Code Configuration Defines\r\n",
    "------\t\r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "[VersionDefine]\r\n",
    "\r\n",
    "\r\n",
    "[Hardware]\r\n",
    "[Synchronisation]\r\n",
    "[Application]\r\n",
    "[Mailbox]\r\n",
    "[Generic]\r\n",
    "\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tCompiler Defines\r\n",
    "------\t\r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "\r\n",
    "[Compiler]\r\n",
    "\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tApplication Specific Defines\r\n",
    "------\t\r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "\r\n",
    "[ApplicationInfo]\r\n",
    "\r\n",
    "\r\n",
    "/*-----------------------------------------------------------------------------------------\r\n",
    "------\t\r\n",
    "------\tTest Configuration Defines\r\n",
    "------\t\r\n",
    "-----------------------------------------------------------------------------------------*/\r\n",
    "\r\n",
    "[DefineConflicts]\r\n",
    "\r\n",
    "#endif // _ECATDEF_H_\r\n"
);

const EVALUATED_COMMENT_SUFFIX: &str =
    " //This define was already evaluated by ET9300 Project Handler(V. 1.5.3.0)!";

/// Setting entry view passed to `render_ecat_def_h`.
#[derive(Debug, Clone)]
pub struct EcatDefEntry<'a> {
    pub code_define: &'a str,
    pub file_area: &'a str,
    pub description: &'a str,
    pub value: &'a str,
    pub is_string_type: bool,
    pub is_evaluated: bool,
}

/// Format a single `SlaveSetting` block for `ecat_def.h` with exact parity to
/// `SlaveSetting::CreateSourceCode(bIncludeList: false)`.
pub fn format_setting_ecat_def_block(entry: &EcatDefEntry<'_>) -> String {
    let desc_lines: Vec<&str> = entry
        .description
        .split('\n')
        .map(|s| s.strip_suffix('\r').unwrap_or(s))
        .filter(|s| !s.is_empty())
        .collect();
    let joined_desc = desc_lines.join("<br>\r\n");
    let comment = format!("/** \r\n{}: {} */", entry.code_define, joined_desc);

    let guard_name = match entry.code_define.find('(') {
        Some(idx) if idx > 0 => &entry.code_define[..idx],
        _ => entry.code_define,
    };
    let ifndef_line = format!("#ifndef {guard_name}");

    let mut define_line = format!("#define {} ", entry.code_define);
    if !entry.value.is_empty() {
        if define_line.len() < 50 {
            define_line.push_str(&" ".repeat(50 - define_line.len()));
        }
        if entry.is_string_type {
            define_line.push('"');
            define_line.push_str(entry.value);
            define_line.push('"');
        } else {
            define_line.push_str(entry.value);
        }
    }
    if entry.is_evaluated {
        define_line.push_str(EVALUATED_COMMENT_SUFFIX);
    }

    format!("{comment}\r\n{ifndef_line}\r\n{define_line}\r\n#endif\r\n\r\n")
}

/// Render `ecat_def.h` bytes (7-bit ASCII, `\r\n` CRLF) with exact parity to
/// `CodeGenerator::CreateSlaveCfgSourceFile`.
pub fn render_ecat_def_h(
    ssc_version: &str,
    entries: &[EcatDefEntry<'_>],
    all_defines: &BTreeMap<String, String>,
    conflict_directives: Option<&[String]>,
) -> Vec<u8> {
    let raw_tpl_lines: Vec<String> = CFG_SOURCE_FILE_STRUCTURE
        .split("\r\n")
        .map(String::from)
        .collect();

    // Pre-pass on template: expand `/*CODE_INSERT_START (SYSTEM_HEADER_FILE)*/`,
    // fill SSC version banner and `[VersionDefine]`.
    let mut pre_lines: Vec<String> = Vec::with_capacity(raw_tpl_lines.len() + 8);
    let mut i = 0usize;
    while i < raw_tpl_lines.len() {
        let line = &raw_tpl_lines[i];
        if line.contains("/*CODE_INSERT_START") {
            match handle_code_block(
                &mut pre_lines,
                SrcCodeType::Unmanaged,
                &raw_tpl_lines,
                i,
                all_defines,
                false,
                "ET9300 Project Handler",
            ) {
                Some(end_idx) => i = end_idx + 1,
                None => {
                    pre_lines.push(line.clone());
                    i += 1;
                }
            }
            continue;
        }
        if line.starts_with("------  SSC version : ") {
            pre_lines.push(format!("{line}{ssc_version}"));
            i += 1;
            continue;
        }
        if line.contains("[VersionDefine]") {
            let mut parts = ssc_version.split('.');
            let major = parts.next().unwrap_or("5");
            let minor = parts.next().unwrap_or("13");
            pre_lines.push(format!("#define SSC_VERSION_MAJOR {major}"));
            pre_lines.push(format!("#define SSC_VERSION_MINOR {minor}"));
            i += 1;
            continue;
        }
        pre_lines.push(line.clone());
        i += 1;
    }

    // Group entries by FileArea preserving order of first appearance and setting order
    let mut groups: BTreeMap<String, String> = BTreeMap::new();
    for entry in entries {
        if entry.file_area.is_empty() {
            continue;
        }
        let block = format_setting_ecat_def_block(entry);
        groups
            .entry(entry.file_area.to_string())
            .or_default()
            .push_str(&block);
    }

    let mut out_text = String::with_capacity(48 * 1024);
    for line in &pre_lines {
        let mut matched_group = false;
        if line.starts_with('[') && line.ends_with(']') && line != "[DefineConflicts]" {
            let area = &line[1..line.len() - 1];
            if let Some(rendered_group) = groups.get(area) {
                out_text.push_str(rendered_group);
            }
            matched_group = true;
        }
        if matched_group {
            continue;
        }
        if line.contains("[DefineConflicts]") {
            if let Some(conflicts) = conflict_directives {
                for c in conflicts {
                    out_text.push_str(c);
                    out_text.push_str("\r\n");
                }
            }
            continue;
        }
        out_text.push_str(line);
        out_text.push_str("\r\n");
    }

    // Encode as 7-bit ASCII (matching .NET `Encoding.ASCII`)
    out_text
        .chars()
        .map(|ch| if ch.is_ascii() { ch as u8 } else { b'?' })
        .collect()
}

/// Preprocess an SSC core `.c`/`.h` file's lines using ONLY `Evaluate="True"` defines,
/// matching `CodeGenerator::CreateNewSourceFiles` (`HandleIfBlock` + `HandleCodeBlock`).
pub fn preprocess_ssc_source_lines(
    lines: &[String],
    eval_defines: &BTreeMap<String, String>,
    add_delete_comment: bool,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(lines.len());
    let mut i = 0usize;
    while i < lines.len() {
        let line = &lines[i];
        if !line.contains('#') && !line.contains("/*CODE_INSERT_START") {
            out.push(line.clone());
            i += 1;
            continue;
        }
        let norm = if line.contains('#') {
            normalize_line(line, true, false)
        } else {
            String::new()
        };
        if norm.contains("#if") {
            match handle_if_block(
                &mut out,
                SrcCodeType::Unmanaged,
                lines,
                i,
                eval_defines,
                add_delete_comment,
                "ET9300 Project Handler",
            ) {
                Some(end_idx) => i = end_idx + 1,
                None => return lines.to_vec(),
            }
        } else if line.contains("/*CODE_INSERT_START") {
            match handle_code_block(
                &mut out,
                SrcCodeType::Unmanaged,
                lines,
                i,
                eval_defines,
                add_delete_comment,
                "ET9300 Project Handler",
            ) {
                Some(end_idx) => i = end_idx + 1,
                None => return lines.to_vec(),
            }
        } else {
            out.push(line.clone());
            i += 1;
        }
    }
    out
}

fn handle_if_block(
    out: &mut Vec<String>,
    parent_code_type: SrcCodeType,
    lines: &[String],
    start_line: usize,
    eval_defines: &BTreeMap<String, String>,
    add_delete_comment: bool,
    parent_tool: &str,
) -> Option<usize> {
    let mut cur_line = start_line;
    let mut norm = normalize_line(&lines[cur_line], true, false);
    let mut branch_taken = false;
    let mut cur_code_type = parent_code_type;
    let mut delete_start: isize = -1;
    let mut delete_expr = String::new();
    let mut in_block_comment = false;

    if parent_code_type != SrcCodeType::Inactive {
        cur_code_type = compute_compiler_command(&norm, |k| eval_defines.get(k));
        if cur_code_type == SrcCodeType::Inactive {
            delete_start = cur_line as isize;
        }
        delete_expr = norm.clone();
    }
    if parent_code_type == SrcCodeType::Unexpected {
        return None;
    }

    if parent_code_type != SrcCodeType::Inactive
        && cur_code_type != SrcCodeType::Active
        && cur_code_type != SrcCodeType::Inactive
    {
        out.push(lines[cur_line].clone());
    }

    while (!norm.contains("#endif") || in_block_comment) && cur_line + 1 < lines.len() {
        cur_line += 1;
        if lines[cur_line].contains('#') {
            norm = normalize_line(&lines[cur_line], true, false);
        } else {
            norm.clear();
        }

        if lines[cur_line].contains("/*") {
            in_block_comment = true;
        }
        if lines[cur_line].contains("*/") {
            in_block_comment = false;
        }

        if lines[cur_line].contains("/*CODE_INSERT_START") {
            in_block_comment = false;
            cur_line = handle_code_block(
                out,
                cur_code_type,
                lines,
                cur_line,
                eval_defines,
                add_delete_comment,
                parent_tool,
            )?;
            // Refresh `norm` so loop condition sees post-block state (not `#endif`)
            norm.clear();
            continue;
        }

        if norm.contains("#if") && !in_block_comment {
            cur_line = handle_if_block(
                out,
                cur_code_type,
                lines,
                cur_line,
                eval_defines,
                add_delete_comment,
                parent_tool,
            )?;
            // Refresh `norm` so outer loop does NOT exit on inner `#endif`!
            norm.clear();
            continue;
        }

        if norm.contains("#elif") || (norm.contains("#else") && !in_block_comment) {
            let mut emitted_line = lines[cur_line].clone();
            if parent_code_type != SrcCodeType::Inactive
                && cur_code_type != SrcCodeType::Unknown
                && !branch_taken
            {
                if cur_code_type == SrcCodeType::Active {
                    branch_taken = true;
                    cur_code_type = SrcCodeType::Inactive;
                    delete_start = cur_line as isize;
                    if norm.contains("#elif") {
                        delete_expr = norm.clone();
                    } else {
                        delete_expr = format!("{delete_expr} {norm}");
                    }
                } else if cur_code_type == SrcCodeType::Inactive {
                    if norm.contains("#elif") {
                        cur_code_type = compute_compiler_command(&norm, |k| eval_defines.get(k));
                        if cur_code_type == SrcCodeType::Inactive {
                            delete_expr = format!("{delete_expr} {norm}");
                            if delete_start < 0 {
                                delete_start = cur_line as isize;
                            }
                        } else if cur_code_type == SrcCodeType::Active {
                            if delete_start > 0 {
                                if add_delete_comment {
                                    out.push(format!(
                                        "/*{parent_tool} :({delete_expr}) lines {delete_start} to {cur_line} deleted*/"
                                    ));
                                }
                                delete_start = -1;
                                delete_expr.clear();
                            }
                        } else if cur_code_type == SrcCodeType::Unknown {
                            emitted_line = emitted_line.replace("#elif", "#if");
                        }
                    } else {
                        // `#else` when previous branch was Inactive -> becomes Active
                        cur_code_type = SrcCodeType::Active;
                        if delete_start > 0 {
                            if add_delete_comment {
                                out.push(format!(
                                    "/*{parent_tool} :({delete_expr}) lines {delete_start} to {cur_line} deleted*/"
                                ));
                            }
                            delete_start = -1;
                            delete_expr.clear();
                        }
                    }
                } else {
                    return None;
                }
            }
            if cur_code_type != SrcCodeType::Active && cur_code_type != SrcCodeType::Inactive {
                out.push(emitted_line);
            }
            continue;
        }

        if norm.contains("#endif") && !in_block_comment {
            if cur_code_type != SrcCodeType::Active && cur_code_type != SrcCodeType::Inactive {
                out.push(lines[cur_line].clone());
            }
            if delete_start > 0 && add_delete_comment {
                out.push(format!(
                    "/*{parent_tool} :({delete_expr}) lines {delete_start} to {cur_line} deleted*/"
                ));
            }
            return Some(cur_line);
        }

        if cur_code_type != SrcCodeType::Inactive {
            out.push(lines[cur_line].clone());
        }
    }

    Some(cur_line)
}

fn handle_code_block(
    out: &mut Vec<String>,
    parent_code_type: SrcCodeType,
    lines: &[String],
    start_line: usize,
    eval_defines: &BTreeMap<String, String>,
    add_delete_comment: bool,
    parent_tool: &str,
) -> Option<usize> {
    if parent_code_type == SrcCodeType::Inactive {
        // Note: in C# `HandleCodeBlock` returns `_CurLine` immediately when parent is Inactive;
        // subsequent lines until `/*CODE_INSERT_END*/` are skipped by the inactive `HandleIfBlock` loop!
        return Some(start_line);
    }
    if parent_code_type == SrcCodeType::Unexpected {
        return None;
    }

    let mut cur_line = start_line;
    let Some(block_key) = parse_code_insert_start(&lines[cur_line]) else {
        return Some(cur_line);
    };

    let active_val = eval_defines.get(&block_key).filter(|v| !v.is_empty());
    let block_state = if let Some(val) = active_val {
        for split_line in val.split('\n') {
            out.push(split_line.to_string());
        }
        SrcCodeType::Active
    } else {
        SrcCodeType::Inactive
    };

    cur_line += 1;
    while cur_line < lines.len() && !lines[cur_line].contains("/*CODE_INSERT_END*/") {
        if block_state != SrcCodeType::Active {
            let norm = normalize_line(&lines[cur_line], true, true);
            if norm.contains("#if") {
                cur_line = handle_if_block(
                    out,
                    parent_code_type,
                    lines,
                    cur_line,
                    eval_defines,
                    add_delete_comment,
                    parent_tool,
                )?;
            } else {
                out.push(lines[cur_line].clone());
            }
        }
        if cur_line + 1 >= lines.len() {
            break;
        }
        cur_line += 1;
    }

    Some(cur_line)
}

fn parse_code_insert_start(line: &str) -> Option<String> {
    let prefix = "/*CODE_INSERT_START (";
    let suffix = ")*/";
    let start = line.find(prefix)? + prefix.len();
    let rel_end = line[start..].rfind(suffix)?;
    Some(line[start..start + rel_end].to_string())
}

/// Join source lines using Beckhoff `File.WriteAllLines` convention: UTF-8 without BOM, `\r\n` after every line.
pub fn encode_crlf_lines(lines: &[String]) -> Vec<u8> {
    let total_cap: usize = lines.iter().map(|s| s.len() + 2).sum();
    let mut out = String::with_capacity(total_cap);
    for l in lines {
        out.push_str(l);
        out.push_str("\r\n");
    }
    out.into_bytes()
}

/// Split file content into lines matching `.NET` `File.ReadAllLines` (handling `\r\n` and `\n`,
/// without a bogus empty trailing element after the final newline).
pub fn split_text_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text
        .split('\n')
        .map(|s| s.strip_suffix('\r').unwrap_or(s).to_string())
        .collect();
    if text.ends_with('\n') {
        lines.pop();
    }
    lines
}

/// Render `eeprom.h` matching `EsiSiiHandler::CreateSscEepromHeader` (`vectors\vec2_defines\src\eeprom.h`).
pub fn render_ssc_eeprom_h(
    sii_bytes: &[u8],
    target_eeprom_size: usize,
    esi_source_path_display: &str,
) -> Vec<u8> {
    use std::fmt::Write as _;

    let total = sii_bytes.len().max(target_eeprom_size);
    let mut out = String::with_capacity(total.saturating_mul(5) + 256);
    out.push_str("/*\r\n");
    let _ = write!(
        out,
        "The EEPROM data is created based on the information in the file \"{esi_source_path_display}\"\r\n"
    );
    out.push_str("*/\r\n");
    out.push_str("unsigned char aEepromData[] = {\r\n");

    let mut chunk_start = 0usize;
    while chunk_start < total {
        let chunk_end = (chunk_start + 16).min(total);
        for idx in chunk_start..chunk_end {
            let b = sii_bytes.get(idx).copied().unwrap_or(0xFF);
            if idx + 1 < total {
                let _ = write!(out, "0x{b:02X},");
            } else {
                let _ = write!(out, "0x{b:02X}}};");
            }
        }
        out.push_str("\r\n");
        chunk_start = chunk_end;
    }
    out.push_str("\r\n\r\n");
    out.into_bytes()
}
