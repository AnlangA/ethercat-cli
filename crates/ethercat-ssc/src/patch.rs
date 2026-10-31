use ethercat_wire::error::{CliError, Result};

/// Result of applying a unified `.patch` file to a single SSC source/header file.
#[derive(Debug, Clone)]
pub struct PatchedFileOutcome {
    pub lines: Vec<String>,
}

/// Parse a Beckhoff SSC `.patch` file into `(basename, patch_lines)` sections,
/// matching `ET9300Utilities.ET9300Project.PatchHandler::CreatePatchedFiles`.
pub fn parse_ssc_patch_sections(patch_lines: &[String]) -> Vec<(String, Vec<String>)> {
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    let mut current_file = String::new();
    let mut current_cmds: Vec<String> = Vec::new();

    for raw in patch_lines {
        let line = if raw.starts_with("---") {
            raw.replace("---", "Index:")
        } else if raw.starts_with("+++") {
            continue;
        } else {
            raw.clone()
        };

        if let Some(matched_file) = match_patch_header_file(&line) {
            let basename = extract_file_basename(&matched_file);
            if !current_file.is_empty() && basename != current_file {
                sections.push((
                    std::mem::take(&mut current_file),
                    std::mem::take(&mut current_cmds),
                ));
            }
            if basename != current_file {
                current_file = basename;
            }
        } else {
            current_cmds.push(line);
        }
    }

    if !current_file.is_empty() && !current_cmds.is_empty() {
        sections.push((current_file, current_cmds));
    }

    sections
}

/// Apply patch commands to a single file's line array with 100% parity to
/// `ET9300Utilities.ET9300Project.PatchHandler::CreatePatchedFileContent`.
pub fn apply_patch_to_lines(
    filename: &str,
    src_lines: &[String],
    patch_commands: &[String],
) -> Result<Option<PatchedFileOutcome>> {
    let mut lines: Vec<String> = src_lines.to_vec();
    let mut cursor: usize = 0;
    let mut start_index: isize = -1;
    let mut op_count: usize = 0;

    for cmd in patch_commands {
        if cmd.starts_with("@@") {
            let (plus_start, _plus_len) = parse_hunk_header(cmd).ok_or_else(|| {
                CliError::Format(format!(
                    "Failed to get source file line reference from patch line '{cmd}' (source file '{filename}')"
                ))
            })?;
            start_index = plus_start as isize;
            if plus_start > lines.len() {
                return Err(CliError::Format(format!(
                    "Referenced line {plus_start} does not exist in source file '{filename}'."
                )));
            }

            // On the very first hunk of a file, Beckhoff's PatchHandler scans lines 0..(start-1)
            // for `\version X.Y` and appends `.1` (or rejects if Build > 0, i.e., already patched).
            if cursor == 0 {
                let limit = plus_start.saturating_sub(1).min(lines.len());
                for line in lines.iter_mut().take(limit) {
                    if let Some(ver_str) = match_doxygen_version(line) {
                        let parts: Vec<u32> = ver_str
                            .split('.')
                            .filter(|s| !s.is_empty())
                            .filter_map(|s| s.parse::<u32>().ok())
                            .collect();
                        if parts.len() >= 3 && parts[2] > 0 {
                            return Err(CliError::Validation(format!(
                                "The file '{filename}' was already patched."
                            )));
                        }
                        *line = format!("{}.1", line.trim());
                        break;
                    }
                }
            }

            cursor = plus_start.saturating_sub(1);
        } else if start_index > 0 {
            op_count += 1;
            if let Some(expected_removed) = cmd.strip_prefix('-') {
                let actual = lines.get(cursor).map(|s| s.as_str()).unwrap_or("<EOF>");
                if actual != expected_removed {
                    return Err(CliError::Format(format!(
                        "The line to remove '{actual}' is not defined in the source file '{filename}' at line {cursor}"
                    )));
                }
                lines.remove(cursor);
            } else if let Some(added) = cmd.strip_prefix('+') {
                lines.insert(cursor, added.to_string());
                cursor += 1;
            } else if let Some(expected_ctx) = cmd.strip_prefix(' ') {
                let actual = lines.get(cursor).map(|s| s.as_str()).unwrap_or("<EOF>");
                if actual != expected_ctx {
                    return Err(CliError::Format(format!(
                        "The expected equal line '{actual}' is not defined in the source file '{filename}' at line {cursor}"
                    )));
                }
                cursor += 1;
            } else {
                return Err(CliError::Format(format!(
                    "Unknown patch line '{cmd}', expect '+', '-', ' ' or '@'"
                )));
            }
        }
    }

    if op_count == 0 {
        Ok(None)
    } else {
        Ok(Some(PatchedFileOutcome { lines }))
    }
}

fn match_patch_header_file(line: &str) -> Option<String> {
    // Pattern 1: "diff -Nup A/<file.[ch]> ..."
    if let Some(pos) = line.find("diff -Nup A/") {
        let rest = &line[pos + "diff -Nup A/".len()..];
        if let Some(space_idx) = rest.find(' ') {
            let candidate = &rest[..space_idx];
            if is_c_or_h_path(candidate) {
                return Some(candidate.to_string());
            }
        }
    }
    // Pattern 2: "Index: <file.[ch]>" (also handles "--- <file.[ch]>\t..." after replacement)
    if let Some(pos) = line.find("Index: ") {
        let rest = &line[pos + "Index: ".len()..];
        // Take up to optional tab/timestamp or end of `.c` / `.h`
        let token = rest.split(['\t', '\r', '\n']).next().unwrap_or(rest).trim();
        let trimmed = strip_ab_prefix(token);
        if is_c_or_h_path(trimmed) {
            return Some(trimmed.to_string());
        }
        // Fallback if there's trailing metadata separated by spaces
        if let Some(space_tok) = trimmed.split_whitespace().next() {
            if is_c_or_h_path(space_tok) {
                return Some(space_tok.to_string());
            }
        }
    }
    None
}

fn strip_ab_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("a/").or_else(|| path.strip_prefix("A/")) {
        rest
    } else {
        path
    }
}

fn is_c_or_h_path(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    lower.ends_with(".c") || lower.ends_with(".h")
}

fn extract_file_basename(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_string()
}

fn parse_hunk_header(line: &str) -> Option<(usize, usize)> {
    // Matches `@@ -<old_start>[,<old_len>] +<startindex>[,<length>] @@`
    let body = line.strip_prefix("@@ ")?;
    let end = body.find(" @@")?;
    let ranges = &body[..end];
    let mut parts = ranges.split_whitespace();
    let minus_part = parts.next()?.strip_prefix('-')?;
    let plus_part = parts.next()?.strip_prefix('+')?;
    if !valid_range_pair(minus_part) {
        return None;
    }
    parse_range_pair(plus_part)
}

fn valid_range_pair(s: &str) -> bool {
    parse_range_pair(s).is_some()
}

fn parse_range_pair(s: &str) -> Option<(usize, usize)> {
    if let Some((a, b)) = s.split_once(',') {
        Some((a.parse().ok()?, b.parse().ok()?))
    } else {
        Some((s.parse().ok()?, 1))
    }
}

fn match_doxygen_version(line: &str) -> Option<&str> {
    let idx = line.find("\\version ")?;
    let rest = &line[idx + "\\version ".len()..];
    let len = rest
        .bytes()
        .take_while(|b| b.is_ascii_digit() || *b == b'.')
        .count();
    if len == 0 {
        None
    } else {
        Some(&rest[..len])
    }
}
