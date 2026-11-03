use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::archive::{bytes_to_text, read_gzip_or_plain, write_gzip_file};
use crate::codegen::split_text_lines;
use crate::expr::{evaluate_boolean_expression, resolve_value_expression};
use crate::xml_dom::{
    get_clear_value, parse_dom_bytes, parse_dom_file, render_compact_xml, DomElement, DomNode,
};
use ethercat_wire::error::{CliError, Result};

pub const SSC_TOOL_VERSION: &str = "1.5.3.0";

/// Default SSC object indices stripped when importing a user Application OD into a `SlaveProject`
/// (`SlaveProject::GetDefaultSscObjects`, 15 objects including `0x10F8`).
pub const PROJECT_DEFAULT_SSC_OBJECTS: &[u16] = &[
    0x1000, 0x1001, 0x1008, 0x1009, 0x100A, 0x1010, 0x1011, 0x1018, 0x10F0, 0x10F1, 0x10F3, 0x10F8,
    0x1C00, 0x1C32, 0x1C33,
];

/// Default SSC object indices preserved during standalone `SSC OD Tool` `/esi` update
/// (14 objects — `0x10F8` omitted).
pub const STANDALONE_ESI_UPDATE_DEFAULT_SSC_OBJECTS: &[u16] = &[
    0x1000, 0x1001, 0x1008, 0x1009, 0x100A, 0x1010, 0x1011, 0x1018, 0x10F0, 0x10F1, 0x10F3, 0x1C00,
    0x1C32, 0x1C33,
];

/// Sample application setting names reset to `"0"` and locked `ReadOnly=True` when a custom
/// application is attached (`SlaveProject::UpdateApplicationRelatedProjectSettings`).
pub const SAMPLE_APPLICATION_DEFINES: &[&str] = &[
    "TEST_APPLICATION",
    "TEST_APPLICATION_REDUCED_MEMORY",
    "EL9800_APPLICATION",
    "CiA402_SAMPLE_APPLICATION",
    "BOOTLOADER_SAMPLE",
    "CiA402_DEVICE",
    "SAMPLE_APPLICATION",
    "SAMPLE_APPLICATION_INTERFACE",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Tristate {
    Null,
    True,
    False,
}

impl Tristate {
    pub fn from_xml_opt(s: Option<&str>) -> Self {
        match s.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => Self::True,
            Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => Self::False,
            _ => Self::Null,
        }
    }

    pub fn to_xml_str(self) -> Option<&'static str> {
        match self {
            Self::True => Some("True"),
            Self::False => Some("False"),
            Self::Null => None,
        }
    }

    #[inline]
    pub fn is_true(self) -> bool {
        self == Self::True
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SettingFlags {
    pub advanced: Tristate,
    pub visible: Tristate,
    pub read_only: Tristate,
    pub evaluate: Tristate,
}

impl Default for SettingFlags {
    fn default() -> Self {
        Self {
            advanced: Tristate::Null,
            visible: Tristate::True,
            read_only: Tristate::Null,
            evaluate: Tristate::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum SettingValueType {
    NotDefined,
    Boolean,
    String { max_len: Option<usize> },
    Hex { max_len: Option<usize> },
    Dec,
    Code,
    ByteArray { max_len: Option<usize> },
    Byte,
    Uint16,
    Uint32,
    CodeBlock,
}

impl SettingValueType {
    /// Parse `@ValueType` with Beckhoff's legacy `hex(4)`->`Uint16` / `hex(8)`->`Uint32` promotion.
    pub fn parse_ssc(raw: Option<&str>) -> Self {
        let Some(raw_str) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
            return Self::NotDefined;
        };
        let lower = raw_str.to_ascii_lowercase();
        let (base, max_len) = if let Some(open) = lower.find('(') {
            let len_opt = lower[open + 1..]
                .find(')')
                .and_then(|close| lower[open + 1..open + 1 + close].parse::<usize>().ok());
            (&lower[..open], len_opt)
        } else {
            (lower.as_str(), None)
        };

        match base {
            "bool" => Self::Boolean,
            "string" => Self::String { max_len },
            "hex" => match max_len {
                Some(4) => Self::Uint16,
                Some(8) => Self::Uint32,
                other => Self::Hex { max_len: other },
            },
            "dec" => Self::Dec,
            "code" => Self::Code,
            "bytes" => Self::ByteArray { max_len },
            "byte" => Self::Byte,
            "uint16" => Self::Uint16,
            "uint32" => Self::Uint32,
            "codeblock" => Self::CodeBlock,
            _ => Self::NotDefined,
        }
    }

    pub fn to_xml_value_type(&self) -> Option<String> {
        match self {
            Self::NotDefined => None,
            Self::Boolean => Some("bool".to_string()),
            Self::String { max_len: Some(n) } => Some(format!("string({n})")),
            Self::String { max_len: None } => Some("string".to_string()),
            Self::Hex { max_len: Some(n) } => Some(format!("hex({n})")),
            Self::Hex { max_len: None } => Some("hex".to_string()),
            Self::Dec => Some("dec".to_string()),
            Self::Code => Some("code".to_string()),
            Self::ByteArray { max_len: Some(n) } => Some(format!("bytes({n})")),
            Self::ByteArray { max_len: None } => Some("bytes".to_string()),
            Self::Byte => Some("byte".to_string()),
            Self::Uint16 => Some("uint16".to_string()),
            Self::Uint32 => Some("uint32".to_string()),
            Self::CodeBlock => Some("codeblock".to_string()),
        }
    }

    #[inline]
    pub fn is_string_type(&self) -> bool {
        matches!(self, Self::String { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DefineValue {
    pub expression: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingGroupNode {
    pub path: String,
    pub control_type: String,
    pub advanced: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlaveSetting {
    pub code_define: String,
    pub file_area: String,
    pub node_path: String,
    pub parent_setting: String,
    pub display_name: String,
    pub value_type: SettingValueType,
    pub value: String,
    pub default_values: Vec<DefineValue>,
    pub flags: SettingFlags,
    pub description: String,
}

impl SlaveSetting {
    pub fn validate_value(&self, candidate: &str) -> Result<()> {
        match &self.value_type {
            SettingValueType::Boolean => {
                if candidate.is_empty()
                    || candidate == "0"
                    || candidate == "1"
                    || candidate.eq_ignore_ascii_case("true")
                    || candidate.eq_ignore_ascii_case("false")
                {
                    Ok(())
                } else {
                    Err(CliError::Validation(format!(
                        "Invalid boolean value '{candidate}' for setting '{}'",
                        self.code_define
                    )))
                }
            }
            SettingValueType::Byte => {
                let _ = parse_setting_u8(candidate).map_err(|_| {
                    CliError::Validation(format!(
                        "Invalid byte value '{candidate}' for setting '{}'",
                        self.code_define
                    ))
                })?;
                Ok(())
            }
            SettingValueType::Uint16 => {
                let _ = parse_setting_u16(candidate).map_err(|_| {
                    CliError::Validation(format!(
                        "Invalid uint16 value '{candidate}' for setting '{}'",
                        self.code_define
                    ))
                })?;
                Ok(())
            }
            SettingValueType::Uint32 => {
                let _ = parse_setting_u32(candidate).map_err(|_| {
                    CliError::Validation(format!(
                        "Invalid uint32 value '{candidate}' for setting '{}'",
                        self.code_define
                    ))
                })?;
                Ok(())
            }
            SettingValueType::ByteArray { max_len } => {
                if candidate.is_empty() {
                    return Ok(());
                }
                let compact: String = candidate.chars().filter(|&c| c != ' ').collect();
                if !compact.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(CliError::Validation(format!(
                        "Invalid hex byte array '{candidate}' for setting '{}'",
                        self.code_define
                    )));
                }
                let padded_len = if compact.len() % 2 == 1 {
                    compact.len() + 1
                } else {
                    compact.len()
                };
                if let Some(limit) = *max_len {
                    if padded_len > limit {
                        return Err(CliError::Validation(format!(
                            "Hex byte array '{candidate}' exceeds max length {limit} for setting '{}'",
                            self.code_define
                        )));
                    }
                }
                Ok(())
            }
            SettingValueType::String {
                max_len: Some(limit),
            } => {
                if candidate.encode_utf16().count() > *limit {
                    Err(CliError::Validation(format!(
                        "String value '{candidate}' exceeds max length {limit} for setting '{}'",
                        self.code_define
                    )))
                } else {
                    Ok(())
                }
            }
            SettingValueType::Dec => {
                if candidate.chars().all(|c| c.is_ascii_digit()) {
                    Ok(())
                } else {
                    Err(CliError::Validation(format!(
                        "Invalid decimal value '{candidate}' for setting '{}'",
                        self.code_define
                    )))
                }
            }
            SettingValueType::Hex { max_len } => {
                if candidate.is_empty() {
                    return Ok(());
                }
                let digits = candidate
                    .strip_prefix("0x")
                    .or_else(|| candidate.strip_prefix("0X"))
                    .or_else(|| candidate.strip_prefix("0"))
                    .ok_or_else(|| {
                        CliError::Validation(format!(
                            "Invalid hex value '{candidate}' for setting '{}'",
                            self.code_define
                        ))
                    })?;
                if !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(CliError::Validation(format!(
                        "Invalid hex digits '{candidate}' for setting '{}'",
                        self.code_define
                    )));
                }
                if let Some(limit) = *max_len {
                    if digits.len() > limit {
                        return Err(CliError::Validation(format!(
                            "Hex value '{candidate}' exceeds max digits {limit} for setting '{}'",
                            self.code_define
                        )));
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub fn as_bool(&self) -> bool {
        let v = self.value.trim();
        v == "1" || v.eq_ignore_ascii_case("true")
    }

    pub fn as_u16(&self) -> u16 {
        parse_setting_u16(&self.value).unwrap_or(0)
    }

    pub fn as_u32(&self) -> u32 {
        parse_setting_u32(&self.value).unwrap_or(0)
    }

    pub fn clear_default_values(&mut self) {
        self.default_values.clear();
    }
}

pub fn parse_setting_u8(s: &str) -> std::result::Result<u8, std::num::ParseIntError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    if let Some(hex_part) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u8::from_str_radix(hex_part, 16)
    } else {
        t.parse::<u8>()
    }
}

pub fn parse_setting_u16(s: &str) -> std::result::Result<u16, std::num::ParseIntError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    if let Some(hex_part) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix("#x"))
        .or_else(|| t.strip_prefix("#X"))
    {
        u16::from_str_radix(hex_part, 16)
    } else {
        t.parse::<u16>()
    }
}

pub fn parse_setting_u32(s: &str) -> std::result::Result<u32, std::num::ParseIntError> {
    let t = s.trim();
    if t.is_empty() {
        return Ok(0);
    }
    if let Some(hex_part) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix("#x"))
        .or_else(|| t.strip_prefix("#X"))
    {
        u32::from_str_radix(hex_part, 16)
    } else {
        t.parse::<u32>()
    }
}

pub fn parse_setting_bytes(s: &str) -> Vec<u8> {
    let mut hex_bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if hex_bytes.is_empty() {
        return Vec::new();
    }
    if hex_bytes.len() % 2 == 1 {
        hex_bytes.insert(0, b'0');
    }
    let mut out = Vec::with_capacity(hex_bytes.len() / 2);
    for pair in hex_bytes.as_chunks::<2>().0 {
        if let Ok(pair_str) = std::str::from_utf8(pair) {
            if let Ok(b) = u8::from_str_radix(pair_str, 16) {
                out.push(b);
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SlaveFileType {
    Source,
    Header,
    Binary,
    Patch,
}

impl SlaveFileType {
    pub fn parse_ssc(raw: Option<&str>, file_name: &str) -> Self {
        match raw.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("source") => Self::Source,
            Some(v) if v.eq_ignore_ascii_case("header") => Self::Header,
            Some(v) if v.eq_ignore_ascii_case("binary") => Self::Binary,
            Some(v) if v.eq_ignore_ascii_case("patch") => Self::Patch,
            _ => Self::infer_from_name(file_name),
        }
    }

    pub fn infer_from_name(file_name: &str) -> Self {
        let lower = file_name.to_ascii_lowercase();
        if lower.ends_with(".c") || lower.ends_with(".cpp") {
            Self::Source
        } else if lower.ends_with(".h") || lower.ends_with(".hpp") {
            Self::Header
        } else if lower.ends_with(".patch") {
            Self::Patch
        } else {
            Self::Binary
        }
    }

    pub fn as_xml_str(self) -> &'static str {
        match self {
            Self::Source => "source",
            Self::Header => "header",
            Self::Binary => "binary",
            Self::Patch => "patch",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct FileFlags {
    pub user_file: bool,
    pub hw_file: bool,
    pub appl_file: bool,
}

impl FileFlags {
    pub fn is_none(self) -> bool {
        !self.user_file && !self.hw_file && !self.appl_file
    }
}

#[derive(Debug, Clone)]
pub enum SlaveFileContent {
    TextLines(Vec<String>),
    Binary(Vec<u8>),
    Empty,
}

#[derive(Debug, Clone)]
pub struct SlaveFile {
    pub name: String,
    pub file_type: SlaveFileType,
    pub version: String,
    pub expression: String,
    pub flags: FileFlags,
    pub content: SlaveFileContent,
}

impl SlaveFile {
    pub fn from_disk(path: &Path, user_file: bool) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| CliError::Usage(format!("invalid file name '{}'", path.display())))?
            .to_string();
        let file_type = SlaveFileType::infer_from_name(&name);
        let mut flags = FileFlags {
            user_file: user_file || file_type == SlaveFileType::Patch,
            hw_file: false,
            appl_file: false,
        };
        if file_type == SlaveFileType::Patch {
            flags.user_file = true;
        }
        let raw_bytes = fs::read(path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!("failed to read file '{}': {e}", path.display()),
            ))
        })?;
        let (version, content) = if file_type == SlaveFileType::Binary {
            let ver = extract_pe_product_version(&raw_bytes).unwrap_or_default();
            (ver, SlaveFileContent::Binary(raw_bytes))
        } else {
            let lines = split_text_lines(&bytes_to_text(&raw_bytes));
            let ver = extract_doxygen_version_from_lines(&lines).unwrap_or_default();
            (ver, SlaveFileContent::TextLines(lines))
        };
        Ok(Self {
            name,
            file_type,
            version,
            expression: String::new(),
            flags,
            content,
        })
    }
}

fn extract_doxygen_version_from_lines(lines: &[String]) -> Option<String> {
    for line in lines {
        if let Some(pos) = line.find("\\version").or_else(|| line.find("@version")) {
            let after = line[pos + 8..].trim();
            if !after.is_empty() {
                return Some(after.to_string());
            }
        }
    }
    None
}

/// Pure-Rust extraction of `ProductVersion` from a PE `VS_VERSION_INFO` resource block,
/// matching `FileVersionInfo.GetVersionInfo(path).ProductVersion.Replace(",", ".")`.
fn extract_pe_product_version(bytes: &[u8]) -> Option<String> {
    let mut key_utf16 = Vec::with_capacity(30);
    for u in "ProductVersion\0".encode_utf16() {
        key_utf16.extend_from_slice(&u.to_le_bytes());
    }
    if bytes.len() <= key_utf16.len() + 4 {
        return None;
    }
    for i in 0..=(bytes.len() - key_utf16.len() - 4) {
        if bytes[i..i + key_utf16.len()] == key_utf16[..] {
            let mut val_start = i + key_utf16.len();
            while val_start % 4 != 0 {
                val_start += 1;
            }
            while val_start + 1 < bytes.len() && bytes[val_start] == 0 && bytes[val_start + 1] == 0
            {
                val_start += 2;
            }
            let mut u16_chars = Vec::new();
            let mut cur = val_start;
            while cur + 1 < bytes.len() {
                let ch = u16::from_le_bytes([bytes[cur], bytes[cur + 1]]);
                if ch == 0 {
                    break;
                }
                u16_chars.push(ch);
                cur += 2;
                if u16_chars.len() > 128 {
                    break;
                }
            }
            if !u16_chars.is_empty() {
                let decoded = String::from_utf16_lossy(&u16_chars).replace(',', ".");
                return Some(decoded);
            }
        }
    }
    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ConflictSeverity {
    None,
    Info,
    Warning,
    Error,
}

impl ConflictSeverity {
    pub fn from_xml(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(v) if v.eq_ignore_ascii_case("info") => Self::Info,
            Some(v) if v.eq_ignore_ascii_case("warning") => Self::Warning,
            Some(v) if v.eq_ignore_ascii_case("error") => Self::Error,
            _ => Self::None,
        }
    }

    pub fn as_xml_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingConflict {
    pub severity: ConflictSeverity,
    pub tool_only: bool,
    pub define_attr: String,
    pub linked_expression_attr: String,
    pub combined_expression: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConflict {
    pub severity: ConflictSeverity,
    pub tool_only: bool,
    pub expression: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct EsiFragmentValue {
    pub active_expression: String,
    pub nodes: Vec<DomNode>,
}

#[derive(Debug, Clone)]
pub struct EsiFragment {
    pub path: String,
    pub user_specific: bool,
    pub comment: Option<String>,
    pub values: Vec<EsiFragmentValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MigrationSettingRule {
    pub rule_type: String,
    pub code_define: String,
    pub value_type: String,
    pub default_values: Vec<DefineValue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingMigration {
    pub from_version: String,
    pub to_version: String,
    pub hw_interface_changed: bool,
    pub appl_interface_changed: bool,
    pub rules: Vec<MigrationSettingRule>,
    pub info: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalConfigSetting {
    pub code_define: String,
    pub value: Option<String>,
    pub visible_flag: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalConfigFileRef {
    pub name: String,
    pub file_type: SlaveFileType,
    pub rel_path: String,
    pub version: String,
    pub flags: FileFlags,
}

#[derive(Debug, Clone)]
pub struct ExternalConfiguration {
    pub name: String,
    pub ssc_version: String,
    pub config_version: String,
    pub vendor_id: String,
    pub vendor_name: String,
    pub info: String,
    pub patch_rel_path: String,
    pub application_rel_path: String,
    pub source_folder: String,
    pub esi_folder: String,
    pub settings: Vec<ExternalConfigSetting>,
    pub files: Vec<ExternalConfigFileRef>,
    pub esi_fragments: Vec<EsiFragment>,
    pub source_config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SscToolOptions {
    pub options_path: PathBuf,
    pub vendor_id: u32,
    pub vendor_name: String,
    pub apply_default_patch_on_new_projects: Option<bool>,
    pub default_patch_file: Option<PathBuf>,
    pub add_delete_comment: bool,
    pub add_code_config_to_esi: bool,
    pub block_mismatching_values: bool,
    pub dependent_setting_change_apply_all: bool,
    pub external_configuration_files: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProjectAdaptReport {
    pub from_ssc_version: String,
    pub to_ssc_version: String,
    pub traversed_versions: Vec<String>,
    pub hw_interface_changed: bool,
    pub appl_interface_changed: bool,
    pub migrated_setting_count: usize,
    pub preserved_user_files: Vec<String>,
    pub skipped_patch_files: Vec<String>,
    pub preserved_esi_fragments: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KnownIssue {
    pub ssc_version: String,
    pub number: u32,
    pub tag: String,
    pub abstract_title: String,
    pub active_expression: String,
    pub condition: String,
    pub description: String,
    pub solution: String,
    pub included_in_patch: bool,
}

pub struct SlaveProject {
    pub ssc_version: String,
    pub is_project_file: bool,
    pub input_path: PathBuf,
    pub config_comment: Option<String>,
    pub source_code_output_dir: String,
    pub esi_output_dir: String,
    pub setting_nodes: Vec<SettingGroupNode>,
    pub settings: Vec<SlaveSetting>,
    setting_index: BTreeMap<String, usize>,
    pub files: Vec<SlaveFile>,
    pub conflicts: Vec<SettingConflict>,
    pub esi_fragments: Vec<EsiFragment>,
    pub migrations: Vec<SettingMigration>,
    pub embedded_configurations: Vec<ExternalConfiguration>,
    pub application_xml: Option<DomElement>,
    pub warnings: Vec<String>,
}

impl SlaveProject {
    /// Load a `SlaveProject` from an explicit `.esp` / `.escfg` / `SlaveConfigFile.xml` / SSC directory,
    /// or auto-discover the installed Beckhoff SSC configuration if `project_source` is `None`.
    pub fn load(project_source: Option<&Path>, ssc_dir_override: Option<&Path>) -> Result<Self> {
        let resolved_source = if let Some(src) = project_source {
            src.to_path_buf()
        } else if let Some(ssc_dir) = ssc_dir_override {
            ssc_dir.to_path_buf()
        } else if let Ok(env_dir) = std::env::var("ETHERCAT_SSC_DIR") {
            let trimmed = env_dir.trim();
            if !trimmed.is_empty() {
                PathBuf::from(trimmed)
            } else {
                discover_default_ssc_config_path()?
            }
        } else {
            discover_default_ssc_config_path()?
        };

        let input_file = resolve_project_input_file(&resolved_source)?;
        let is_esp = input_file
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("esp"));

        let source_folder = if is_esp {
            None
        } else if let Some(override_dir) = ssc_dir_override {
            let candidate_src = override_dir.join("src");
            if candidate_src.is_dir() {
                Some(candidate_src)
            } else {
                Some(override_dir.to_path_buf())
            }
        } else {
            resolve_source_file_folder(&input_file)
        };

        let xml_bytes = read_gzip_or_plain(&input_file)?;
        let root = parse_dom_bytes(&xml_bytes, false)?;

        let root_name = root.local_name();
        if root_name != "SlaveCodeConfigurations" && root_name != "SlaveConfiguratorProject" {
            return Err(CliError::Format(format!(
                "Invalid SSC project/config XML root '<{}>' in '{}' (expected SlaveCodeConfigurations or SlaveConfiguratorProject)",
                root.name,
                input_file.display()
            )));
        }

        let tool_version = root
            .attr("ToolVersion")
            .map(get_clear_value)
            .ok_or_else(|| {
                CliError::Format(format!(
                    "Missing @ToolVersion on '<{}>' in '{}'",
                    root.name,
                    input_file.display()
                ))
            })?;
        if SSC_TOOL_VERSION < tool_version.as_str() {
            return Err(CliError::Validation(format!(
                "SSC configuration '{}' requires ToolVersion {} (> supported {})",
                input_file.display(),
                tool_version,
                SSC_TOOL_VERSION
            )));
        }

        let ssc_version = root
            .attr("SSCVersion")
            .map(get_clear_value)
            .unwrap_or_else(|| "5.13".to_string());
        let source_code_output_dir = root
            .attr("SourceCodeOutputDir")
            .map(get_clear_value)
            .unwrap_or_default();
        let esi_output_dir = root
            .attr("EsiOutputDir")
            .map(get_clear_value)
            .unwrap_or_default();

        let config_comment = root.children.iter().find_map(|n| match n {
            DomNode::Comment(c) => Some(c.clone()),
            _ => None,
        });

        let mut warnings = Vec::new();
        let mut setting_nodes = Vec::new();
        if let Some(sn_parent) = root.child("SettingNodes") {
            for sn in sn_parent.children_named("SettingNode") {
                if let Some(path) = sn.attr("Path") {
                    setting_nodes.push(SettingGroupNode {
                        path: get_clear_value(path),
                        control_type: sn
                            .attr("ControlType")
                            .map(get_clear_value)
                            .unwrap_or_else(|| "SettingControl".to_string()),
                        advanced: Tristate::from_xml_opt(sn.attr("Advanced")).is_true(),
                    });
                }
            }
        }

        let mut settings = Vec::new();
        let mut setting_index = BTreeMap::new();
        if let Some(s_parent) = root.child("Settings") {
            for s_el in s_parent.children_named("Setting") {
                let setting = parse_slave_setting_element(s_el)?;
                let idx = settings.len();
                setting_index.insert(setting.code_define.clone(), idx);
                settings.push(setting);
            }
        }

        let mut files = Vec::new();
        if let Some(f_parent) = root.child("Files") {
            for f_el in f_parent.children_named("File") {
                let sf = parse_slave_file_element(f_el, source_folder.as_deref(), &mut warnings)?;
                files.push(sf);
            }
        }

        let mut conflicts = Vec::new();
        if let Some(c_parent) = root.child("SettingConflicts") {
            for c_el in c_parent.children_named("SettingConflict") {
                conflicts.push(parse_setting_conflict_element(c_el));
            }
        }

        let mut esi_fragments = Vec::new();
        for esi_el in root.children_named("ESI") {
            if let Some(frag) = parse_esi_fragment_element(esi_el) {
                esi_fragments.push(frag);
            }
        }

        let mut migrations = Vec::new();
        if let Some(m_parent) = root.child("Migrations") {
            for m_el in m_parent.children_named("Migration") {
                migrations.push(parse_migration_element(m_el));
            }
        }

        let mut embedded_configurations = Vec::new();
        if let Some(cfg_parent) = root.child("Configurations") {
            for cfg_el in cfg_parent.children_named("Configuration") {
                embedded_configurations.push(parse_configuration_element(
                    cfg_el,
                    &ssc_version,
                    "",
                    "",
                    Some(&input_file),
                ));
            }
        }

        let application_xml = root.child("Application").cloned();

        let mut project = Self {
            ssc_version,
            is_project_file: is_esp,
            input_path: input_file,
            config_comment,
            source_code_output_dir,
            esi_output_dir,
            setting_nodes,
            settings,
            setting_index,
            files,
            conflicts,
            esi_fragments,
            migrations,
            embedded_configurations,
            application_xml,
            warnings,
        };

        // Match `SlaveSetting(SlaveProject, XmlNode)` constructor:
        // calculate initial values in topological XML order!
        project.recalculate_all_initial();

        // When loading a `.esp` project with `<Application>`, reconstruct `*Objects.h`
        // (which Beckhoff omits from `.esp` `<Files>` and regenerates from `<Application>`).
        if is_esp {
            if let Some(ref app_el) = project.application_xml {
                if let Ok(mut app) =
                    crate::od::parsers::parse_application_from_dom(app_el, "Application")
                {
                    app.od.finalize_and_validate(false);
                    for m in &mut app.modules {
                        m.od.finalize_and_validate(false);
                    }
                    for gf in crate::od::build_application_slave_files(&app) {
                        if !project
                            .files
                            .iter()
                            .any(|f| f.name.eq_ignore_ascii_case(&gf.name))
                        {
                            project.files.push(gf);
                        }
                    }
                }
            }
        }

        Ok(project)
    }

    pub fn get_setting(&self, name: &str) -> Option<&SlaveSetting> {
        self.setting_index.get(name).map(|&idx| &self.settings[idx])
    }

    pub fn get_setting_mut(&mut self, name: &str) -> Option<&mut SlaveSetting> {
        let idx = *self.setting_index.get(name)?;
        Some(&mut self.settings[idx])
    }

    pub fn get_setting_value(&self, name: &str) -> Option<&str> {
        self.get_setting(name).map(|s| s.value.as_str())
    }

    /// Build `BTreeMap` of ALL settings (`CodeDefine -> Value`).
    pub fn all_defines_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for s in &self.settings {
            let val = if s.flags.read_only.is_true() {
                let idx = self.setting_index[&s.code_define];
                self.calculate_setting_value(idx, None)
                    .unwrap_or_else(|| s.value.clone())
            } else {
                s.value.clone()
            };
            map.insert(s.code_define.clone(), val);
        }
        map
    }

    /// Build `BTreeMap` of ONLY settings with `Flags.bEvaluate == Tristate::True`
    /// (`SlaveProject::CreateNewSourceFiles` preprocessor filter!).
    pub fn evaluated_defines_map(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for s in &self.settings {
            if s.flags.evaluate.is_true() {
                map.insert(s.code_define.clone(), s.value.clone());
            }
        }
        map
    }

    /// Initial load calculation in XML order (`SlaveSetting` ctor behavior).
    pub fn recalculate_all_initial(&mut self) {
        for idx in 0..self.settings.len() {
            if let Some(calc) = self.calculate_setting_value(idx, None) {
                if calc != self.settings[idx].value {
                    self.settings[idx].value = calc;
                }
            }
        }
    }

    /// Exact implementation of `Define::CalculateValue(TriggerDefine, settings, updateValue=false)`.
    pub fn calculate_setting_value(
        &self,
        idx: usize,
        trigger_name: Option<&str>,
    ) -> Option<String> {
        let setting = &self.settings[idx];
        if setting.default_values.is_empty() {
            return Some(setting.value.clone());
        }

        if setting.default_values.len() == 1 {
            // Crucial Beckhoff quirk: when `DefaultValues.Count == 1`, `Expression` is ignored!
            return resolve_value_expression(
                &setting.default_values[0].value,
                |k| self.get_setting_value(k),
                false,
            );
        }

        let guard = trigger_name.unwrap_or(setting.code_define.as_str());
        for dv in &setting.default_values {
            let matches_cond = if dv.expression.is_empty() {
                true
            } else {
                evaluate_boolean_expression(&dv.expression, |ident| {
                    if ident == guard {
                        return None;
                    }
                    let dep_idx = *self.setting_index.get(ident)?;
                    let dep = &self.settings[dep_idx];
                    if !dep.value.is_empty() {
                        Some(dep.value.clone())
                    } else {
                        self.calculate_setting_value(dep_idx, Some(guard))
                    }
                })
            };
            if matches_cond {
                return resolve_value_expression(&dv.value, |k| self.get_setting_value(k), false);
            }
        }

        Some(setting.value.clone())
    }

    /// Set a setting's value and propagate cascading `Setting_PropertyChanged` updates!
    pub fn set_setting_value(
        &mut self,
        name: &str,
        new_val: &str,
        clear_defaults_first: bool,
        block_invalid: bool,
        cascade_non_readonly: bool,
    ) -> Result<()> {
        let Some(&idx) = self.setting_index.get(name) else {
            return Err(CliError::Validation(format!(
                "Setting '{name}' does not exist in SSC project"
            )));
        };

        if clear_defaults_first {
            self.settings[idx].clear_default_values();
        }

        if block_invalid {
            self.settings[idx].validate_value(new_val)?;
        }

        let changed = self.settings[idx].value != new_val;
        self.settings[idx].value = new_val.to_string();

        if changed {
            self.propagate_property_changed(idx, cascade_non_readonly);
        }

        Ok(())
    }

    fn propagate_property_changed(&mut self, changed_idx: usize, cascade_non_readonly: bool) {
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(changed_idx);
        let mut guard_steps = 0usize;
        let max_steps = self.settings.len().saturating_mul(16).max(256);

        while let Some(sender_idx) = queue.pop_front() {
            guard_steps += 1;
            if guard_steps > max_steps {
                break;
            }
            for i in 0..self.settings.len() {
                if i == sender_idx || self.settings[i].default_values.is_empty() {
                    continue;
                }
                let should_recalc =
                    self.settings[i].flags.read_only.is_true() || cascade_non_readonly;
                if !should_recalc {
                    continue;
                }
                if let Some(calc) = self.calculate_setting_value(i, None) {
                    if calc != self.settings[i].value
                        && self.settings[i].validate_value(&calc).is_ok()
                    {
                        self.settings[i].value = calc;
                        queue.push_back(i);
                    }
                }
            }
        }
    }

    /// Apply a CLI `-d <name> [value]` override with exact `SSC Tool Cmd.exe` semantics.
    pub fn apply_cli_define(&mut self, name: &str, value: &str) -> Result<()> {
        let Some(&idx) = self.setting_index.get(name) else {
            return Err(CliError::Validation(format!(
                "Unknown SSC define '{name}' (use `ssc settings` to inspect available defines)"
            )));
        };
        if self.settings[idx].flags.read_only.is_true() {
            return Err(CliError::Validation(format!(
                "The setting '{name}' is readonly"
            )));
        }
        self.set_setting_value(name, value, true, true, true)
    }

    /// Evaluate all `<SettingConflict>` rules against current setting values.
    pub fn evaluate_active_conflicts(&self) -> Vec<ActiveConflict> {
        let mut active = Vec::new();
        for c in &self.conflicts {
            if c.combined_expression.is_empty() {
                continue;
            }
            let is_active = evaluate_boolean_expression(&c.combined_expression, |ident| {
                self.get_setting_value(ident).map(String::from)
            });
            if is_active {
                active.push(ActiveConflict {
                    severity: c.severity,
                    tool_only: c.tool_only,
                    expression: c.combined_expression.clone(),
                    message: c.message.clone(),
                });
            }
        }
        active
    }

    /// Render C preprocessor `#if ... #error/#warning ... #endif` blocks for `ecat_def.h`
    /// when exporting un-preprocessed raw slave files (`SettingConflict::GetSourceCode` parity).
    pub fn render_conflict_directives(&self) -> Vec<String> {
        let mut out = Vec::new();
        for c in &self.conflicts {
            if c.tool_only || c.combined_expression.trim().is_empty() {
                continue;
            }
            let directive = match c.severity {
                ConflictSeverity::Error => "#error",
                ConflictSeverity::Warning => "#warning",
                ConflictSeverity::None | ConflictSeverity::Info => continue,
            };
            let clean_msg: String = c
                .message
                .lines()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            out.push(format!("#if ({})", c.combined_expression.trim()));
            if clean_msg.is_empty() {
                out.push(format!("{directive} Invalid SSC configuration"));
            } else {
                out.push(format!("{directive} \"{clean_msg}\""));
            }
            out.push("#endif".to_string());
            out.push(String::new());
        }
        out
    }

    /// Evaluate `UpdateInformation.xml` known issues matching this project's `SSCVersion` and active settings.
    pub fn evaluate_known_issues(&self, custom_path: Option<&Path>) -> Result<Vec<KnownIssue>> {
        let path = match custom_path {
            Some(p) => p.to_path_buf(),
            None => match default_appdata_tool_dir().map(|d| d.join("UpdateInformation.xml")) {
                Some(p) if p.is_file() => p,
                _ => return Ok(Vec::new()),
            },
        };
        let all_issues = load_update_information_issues(&path)?;
        let has_patch = self.patch_file().is_some();
        let mut matched = Vec::new();
        for issue in all_issues {
            if !issue.ssc_version.is_empty() && issue.ssc_version != self.ssc_version {
                continue;
            }
            if has_patch && issue.included_in_patch {
                continue;
            }
            let active = if issue.active_expression.trim().is_empty() {
                true
            } else {
                evaluate_boolean_expression(&issue.active_expression, |ident| {
                    self.get_setting_value(ident).map(String::from)
                })
            };
            if active {
                matched.push(issue);
            }
        }
        Ok(matched)
    }

    pub fn patch_file(&self) -> Option<&SlaveFile> {
        self.files
            .iter()
            .find(|f| f.file_type == SlaveFileType::Patch)
    }

    /// Attach or replace the `.patch` `SlaveFile` in this project.
    pub fn set_patch_file(&mut self, patch_path: &Path) -> Result<()> {
        let sf = SlaveFile::from_disk(patch_path, true)?;
        if let Some(existing) = self
            .files
            .iter_mut()
            .find(|f| f.file_type == SlaveFileType::Patch)
        {
            *existing = sf;
        } else {
            self.files.push(sf);
        }
        Ok(())
    }

    /// Apply optional GUI-mode `Options.xml` overrides (`VendorID`/`VendorName` + `DefaultPatch.patch`).
    pub fn apply_gui_options(&mut self, opts: &SscToolOptions) -> Result<()> {
        if !self.is_project_file {
            if opts.vendor_id != 0 {
                let hex_id = format!("0x{:X}", opts.vendor_id);
                let _ = self.set_setting_value("VENDOR_ID", &hex_id, false, true, true);
                if !opts.vendor_name.is_empty() {
                    let _ =
                        self.set_setting_value("VENDOR_NAME", &opts.vendor_name, false, true, true);
                }
            }
            if opts.apply_default_patch_on_new_projects == Some(true) {
                if let Some(patch_path) = &opts.default_patch_file {
                    if patch_path.is_file() {
                        self.set_patch_file(patch_path)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Update project defines & generated `SlaveFile`s when a custom `SlaveApplication` is attached
    /// (`SlaveProject::set_Application` + `UpdateApplicationRelatedProjectSettings`).
    #[allow(clippy::too_many_arguments)]
    pub fn apply_imported_application(
        &mut self,
        app_name: &str,
        app_file_stem: &str,
        rx_pd_bytes: u16,
        has_0x1c12: bool,
        tx_pd_bytes: u16,
        has_0x1c13: bool,
        module_profile: u16,
        device_profile: u16,
        generated_files: Vec<SlaveFile>,
        application_xml: DomElement,
    ) -> Result<()> {
        // Remove any prior custom/generated application files while preserving core SSC files (`el9800appl.c`, `cia402appl.c`, etc.)
        self.files.retain(|f| {
            !(f.flags.appl_file && (f.flags.user_file || f.name.ends_with("Objects.h")))
        });

        for gf in generated_files {
            if !self
                .files
                .iter()
                .any(|f| f.name.eq_ignore_ascii_case(&gf.name))
            {
                self.files.push(gf);
            }
        }
        self.application_xml = Some(application_xml);

        // 1. Reset all 8 built-in sample application switches to `"0"` and lock ReadOnly=True
        for &def_name in SAMPLE_APPLICATION_DEFINES {
            if self.setting_index.contains_key(def_name) {
                let _ = self.set_setting_value(def_name, "0", false, false, true);
                if let Some(s) = self.get_setting_mut(def_name) {
                    s.flags.read_only = Tristate::True;
                }
            }
        }

        // 2. Set `APPLICATION_FILE = #include "<AppFileName>.h"` and lock ReadOnly=True
        if self.setting_index.contains_key("APPLICATION_FILE") {
            let inc = format!("#include \"{app_file_stem}.h\"");
            let _ = self.set_setting_value("APPLICATION_FILE", &inc, false, false, true);
            if let Some(s) = self.get_setting_mut("APPLICATION_FILE") {
                s.flags.read_only = Tristate::True;
            }
        }

        // 3. `MAX_PD_OUTPUT_SIZE` (`0x1C12`, rounded up to 4-byte multiple!)
        let out_rounded = ((rx_pd_bytes.saturating_add(3)) / 4) * 4;
        if let Some(cur) = self.get_setting("MAX_PD_OUTPUT_SIZE").map(|s| s.as_u16()) {
            if cur < out_rounded {
                let formatted = format!("0x{out_rounded:X}");
                let _ = self.set_setting_value("MAX_PD_OUTPUT_SIZE", &formatted, false, true, true);
            } else if out_rounded == 0 && !has_0x1c12 {
                let _ = self.set_setting_value("MAX_PD_OUTPUT_SIZE", "0x0000", false, true, true);
            }
        }

        // 4. `MAX_PD_INPUT_SIZE` (`0x1C13`, rounded up to 4-byte multiple!)
        let in_rounded = ((tx_pd_bytes.saturating_add(3)) / 4) * 4;
        if let Some(cur) = self.get_setting("MAX_PD_INPUT_SIZE").map(|s| s.as_u16()) {
            if cur < in_rounded {
                let formatted = format!("0x{in_rounded:X}");
                let _ = self.set_setting_value("MAX_PD_INPUT_SIZE", &formatted, false, true, true);
            } else if in_rounded == 0 && !has_0x1c13 {
                let _ = self.set_setting_value("MAX_PD_INPUT_SIZE", "0x0000", false, true, true);
            }
        }

        // 5. `DEVICE_PROFILE_TYPE` (`0x{modProf:X4}{devProf:X4}`)
        let mod_p = if module_profile == 0xFFFF {
            0
        } else {
            module_profile
        };
        let dev_p = if device_profile == 0xFFFF {
            0
        } else {
            device_profile
        };
        let prof_hex = format!("0x{mod_p:04X}{dev_p:04X}");
        let _ = self.set_setting_value("DEVICE_PROFILE_TYPE", &prof_hex, false, true, true);

        // 6. `DEVICE_NAME` (cascades to `DEVICE_NAME_LEN`)
        if !app_name.is_empty() {
            let _ = self.set_setting_value("DEVICE_NAME", app_name, false, true, true);
        }

        Ok(())
    }

    /// Apply an `ExternalConfiguration` (`SlaveProject::ApplyConfiguration` parity, including
    /// `<Migrations>` version chain, patch import, `allow_file_import` gating, and ESI fragments).
    /// Returns any relative `ApplicationFile` path declared in the configuration so the caller can
    /// also load and attach the application OD if present.
    pub fn apply_configuration(
        &mut self,
        cfg: &ExternalConfiguration,
        allow_file_import: bool,
        ignore_errors: bool,
    ) -> Result<Option<PathBuf>> {
        let effective_ver: String = if !cfg.ssc_version.is_empty() {
            cfg.ssc_version.clone()
        } else if !cfg.config_version.is_empty() {
            cfg.config_version.clone()
        } else {
            self.ssc_version.clone()
        };

        if !ignore_errors && (effective_ver.is_empty() || effective_ver.as_str() < "5.01") {
            return Err(CliError::Validation(format!(
                "Configuration '{}' SSCVersion '{effective_ver}' is older than minimum supported 5.01",
                cfg.name
            )));
        }

        let same_version = effective_ver == self.ssc_version;
        let effective_settings = if same_version || cfg.settings.is_empty() {
            cfg.settings.clone()
        } else {
            self.migrate_configuration_settings(&effective_ver, &cfg.settings, ignore_errors)?
        };

        let mut missing_defines = Vec::new();
        for cs in &effective_settings {
            if let Some(&idx) = self.setting_index.get(&cs.code_define) {
                if let Some(val) = &cs.value {
                    // Notice Beckhoff's order in `ApplyConfiguration`: set `Value` FIRST, then
                    // `ClearDefaultValueList()` if `!bReadOnly`!
                    self.set_setting_value(&cs.code_define, val, false, true, true)?;
                    if !self.settings[idx].flags.read_only.is_true() {
                        self.settings[idx].clear_default_values();
                    }
                }
                if let Some(vis) = cs.visible_flag {
                    self.settings[idx].flags.visible =
                        if vis { Tristate::True } else { Tristate::False };
                }
            } else {
                missing_defines.push(cs.code_define.clone());
            }
        }

        if !missing_defines.is_empty() && !ignore_errors {
            return Err(CliError::Validation(format!(
                "Configuration '{}' references unknown SSC settings: {}",
                cfg.name,
                missing_defines.join(", ")
            )));
        }

        let cfg_base_dir = cfg
            .source_config_path
            .as_deref()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf);

        // Patch file import
        if !cfg.patch_rel_path.is_empty() {
            if !same_version && !ignore_errors {
                return Err(CliError::Validation(format!(
                    "Cannot import patch '{}' from configuration '{}' of version '{effective_ver}' into SSC '{}' project",
                    cfg.patch_rel_path, cfg.name, self.ssc_version
                )));
            }
            if let Some(base) = &cfg_base_dir {
                let patch_path = resolve_config_rel_path(base, &cfg.patch_rel_path);
                if patch_path.is_file() {
                    self.set_patch_file(&patch_path)?;
                } else if !ignore_errors {
                    return Err(CliError::Usage(format!(
                        "Patch file '{}' referenced by configuration '{}' does not exist",
                        patch_path.display(),
                        cfg.name
                    )));
                }
            }
        }

        if !cfg.source_folder.is_empty() {
            self.source_code_output_dir = cfg.source_folder.clone();
        }
        if !cfg.esi_folder.is_empty() {
            self.esi_output_dir = cfg.esi_folder.clone();
        }

        // Additional source/binary files — gated by `allow_file_import`!
        if !cfg.files.is_empty() {
            if !allow_file_import {
                self.warnings.push(
                    "Skip to import additional source files due to configuration settings"
                        .to_string(),
                );
            } else if let Some(base) = &cfg_base_dir {
                for fref in &cfg.files {
                    let combined_rel = if fref.rel_path.is_empty() {
                        fref.name.clone()
                    } else {
                        let sep = if fref.rel_path.ends_with('\\') || fref.rel_path.ends_with('/') {
                            ""
                        } else {
                            "\\"
                        };
                        format!("{}{sep}{}", fref.rel_path, fref.name)
                    };
                    let disk_path = resolve_config_rel_path(base, &combined_rel);
                    if !disk_path.is_file() {
                        if ignore_errors {
                            self.warnings.push(format!(
                                "Configured file '{}' not found; skipped",
                                disk_path.display()
                            ));
                            continue;
                        }
                        return Err(CliError::Usage(format!(
                            "Configured external file '{}' not found",
                            disk_path.display()
                        )));
                    }
                    let mut sf = SlaveFile::from_disk(&disk_path, true)?;
                    sf.file_type = fref.file_type;
                    if !fref.version.is_empty() {
                        sf.version = fref.version.clone();
                    }
                    sf.flags = FileFlags {
                        user_file: true,
                        hw_file: fref.flags.hw_file,
                        appl_file: fref.flags.appl_file,
                    };

                    if let Some(pos) = self
                        .files
                        .iter()
                        .position(|existing| existing.name.eq_ignore_ascii_case(&sf.name))
                    {
                        if self.files[pos].flags.user_file {
                            self.files[pos] = sf;
                        } else {
                            self.warnings.push(format!(
                                "The file '{}' already exists as a core SSC file; the new file will not be imported.",
                                sf.name
                            ));
                        }
                    } else {
                        self.files.push(sf);
                    }
                }
            }
        }

        // ESI fragments (not gated by `allow_file_import`)
        for frag in &cfg.esi_fragments {
            let mut cloned = frag.clone();
            cloned.user_specific = true;
            if let Some(existing) = self
                .esi_fragments
                .iter_mut()
                .find(|e| e.path == cloned.path)
            {
                *existing = cloned;
            } else {
                self.esi_fragments.push(cloned);
            }
        }

        let resolved_app_file = if !cfg.application_rel_path.is_empty() {
            cfg_base_dir.map(|base| resolve_config_rel_path(&base, &cfg.application_rel_path))
        } else {
            None
        };

        Ok(resolved_app_file)
    }

    fn migrate_configuration_settings(
        &self,
        from_ver: &str,
        initial: &[ExternalConfigSetting],
        ignore_errors: bool,
    ) -> Result<Vec<ExternalConfigSetting>> {
        let mut cur_ver = from_ver.to_string();
        let mut map: BTreeMap<String, ExternalConfigSetting> = initial
            .iter()
            .map(|s| (s.code_define.clone(), s.clone()))
            .collect();

        let mut steps = 0usize;
        while cur_ver != self.ssc_version && steps < 32 {
            steps += 1;
            let Some(mig) = self.migrations.iter().find(|m| m.from_version == cur_ver) else {
                if ignore_errors {
                    break;
                }
                return Err(CliError::Validation(format!(
                    "No SSC settings migration path found from version '{from_ver}' to '{}' (stopped at '{cur_ver}')",
                    self.ssc_version
                )));
            };

            for rule in &mig.rules {
                if rule.rule_type.eq_ignore_ascii_case("new")
                    || rule.rule_type.eq_ignore_ascii_case("change")
                {
                    if rule.rule_type.eq_ignore_ascii_case("new")
                        && map.contains_key(&rule.code_define)
                    {
                        continue;
                    }
                    let mut evaluated =
                        eval_migration_defaults(&rule.default_values, &map, &self.settings);
                    let wants_hex = rule.value_type.eq_ignore_ascii_case("hex")
                        || self
                            .get_setting(&rule.code_define)
                            .is_some_and(|s| matches!(s.value_type, SettingValueType::Hex { .. }));
                    if wants_hex
                        && !evaluated.is_empty()
                        && !evaluated.starts_with("0x")
                        && !evaluated.starts_with("0X")
                    {
                        if let Ok(n) = evaluated.parse::<u64>() {
                            evaluated = format!("0x{n:04X}");
                        }
                    }
                    map.insert(
                        rule.code_define.clone(),
                        ExternalConfigSetting {
                            code_define: rule.code_define.clone(),
                            value: Some(evaluated),
                            visible_flag: None,
                        },
                    );
                } else if rule.rule_type.eq_ignore_ascii_case("delete") {
                    map.remove(&rule.code_define);
                }
            }

            cur_ver = mig.to_version.clone();
        }

        // Preserve original setting order first, then newly migrated settings
        let mut out = Vec::with_capacity(map.len());
        for orig in initial {
            if let Some(entry) = map.remove(&orig.code_define) {
                out.push(entry);
            }
        }
        for (_, remaining) in map {
            out.push(remaining);
        }
        Ok(out)
    }

    /// Adapt/migrate an existing `.esp` `SlaveProject` (`old`) onto this newer SSC base `SlaveProject`
    /// (`SlaveProject::AdaptProject` / `SSC Tool` `File -> Adapt Project to new SSC...` parity).
    pub fn adapt_from(
        &mut self,
        old: &SlaveProject,
        ignore_errors: bool,
    ) -> Result<ProjectAdaptReport> {
        let mut traversed_versions = vec![old.ssc_version.clone()];
        let mut hw_interface_changed = false;
        let mut appl_interface_changed = false;

        if old.ssc_version != self.ssc_version {
            let mut cur = old.ssc_version.clone();
            let mut steps = 0usize;
            while cur != self.ssc_version && steps < 32 {
                steps += 1;
                if let Some(mig) = self.migrations.iter().find(|m| m.from_version == cur) {
                    hw_interface_changed |= mig.hw_interface_changed;
                    appl_interface_changed |= mig.appl_interface_changed;
                    if !mig.info.trim().is_empty() {
                        self.warnings.push(format!(
                            "Migration {} -> {}: {}",
                            mig.from_version,
                            mig.to_version,
                            mig.info.trim()
                        ));
                    }
                    cur = mig.to_version.clone();
                    traversed_versions.push(cur.clone());
                } else {
                    break;
                }
            }
        }

        if hw_interface_changed {
            self.warnings.push(
                "Hardware interface changed during SSC migration; review custom hardware files."
                    .to_string(),
            );
        }
        if appl_interface_changed {
            self.warnings.push(
                "Application interface changed during SSC migration; review custom application callbacks."
                    .to_string(),
            );
        }

        let old_cfg_settings: Vec<ExternalConfigSetting> = old
            .settings
            .iter()
            .filter(|s| !s.flags.read_only.is_true())
            .map(|s| ExternalConfigSetting {
                code_define: s.code_define.clone(),
                value: Some(s.value.clone()),
                visible_flag: match s.flags.visible {
                    Tristate::True => Some(true),
                    Tristate::False => Some(false),
                    Tristate::Null => None,
                },
            })
            .collect();

        let effective_settings = if old.ssc_version == self.ssc_version {
            old_cfg_settings
        } else {
            self.migrate_configuration_settings(&old.ssc_version, &old_cfg_settings, ignore_errors)?
        };

        let mut migrated_setting_count = 0usize;
        let mut missing_defines = Vec::new();
        for cs in &effective_settings {
            if let Some(&idx) = self.setting_index.get(&cs.code_define) {
                if let Some(val) = &cs.value {
                    self.set_setting_value(&cs.code_define, val, false, !ignore_errors, true)?;
                    if !self.settings[idx].flags.read_only.is_true() {
                        self.settings[idx].clear_default_values();
                    }
                    migrated_setting_count += 1;
                }
                if let Some(vis) = cs.visible_flag {
                    self.settings[idx].flags.visible =
                        if vis { Tristate::True } else { Tristate::False };
                }
            } else {
                missing_defines.push(cs.code_define.clone());
            }
        }
        if !missing_defines.is_empty() {
            let msg = format!(
                "Adapted project contained obsolete/unknown settings: {}",
                missing_defines.join(", ")
            );
            if ignore_errors {
                self.warnings.push(msg);
            } else {
                return Err(CliError::Validation(msg));
            }
        }

        if !old.source_code_output_dir.is_empty() {
            self.source_code_output_dir = old.source_code_output_dir.clone();
        }
        if !old.esi_output_dir.is_empty() {
            self.esi_output_dir = old.esi_output_dir.clone();
        }

        // Preserve user-specific ESI fragments
        let mut preserved_esi_fragments = 0usize;
        for frag in old.esi_fragments.iter().filter(|f| f.user_specific) {
            preserved_esi_fragments += 1;
            if let Some(existing) = self.esi_fragments.iter_mut().find(|e| e.path == frag.path) {
                *existing = frag.clone();
            } else {
                self.esi_fragments.push(frag.clone());
            }
        }

        // Preserve embedded `<Application>` OD if present, regenerating `*Objects.h`
        if let Some(app_el) = &old.application_xml {
            let fallback_name = self
                .get_setting_value("DEVICE_NAME")
                .filter(|s| !s.is_empty())
                .unwrap_or("Application")
                .to_string();
            if let Ok(mut app) =
                crate::od::parsers::parse_application_from_dom(app_el, &fallback_name)
            {
                app.od.finalize_and_validate(false);
                for m in &mut app.modules {
                    m.od.finalize_and_validate(false);
                }
                let gen_files = crate::od::build_application_slave_files(&app);
                self.apply_imported_application(
                    &app.name,
                    &app.application_file_name,
                    app.get_process_data_length_bytes(0x1C12),
                    app.od.contains(0x1C12),
                    app.get_process_data_length_bytes(0x1C13),
                    app.od.contains(0x1C13),
                    app.od.module_profile,
                    app.od.device_profile,
                    gen_files,
                    app_el.clone(),
                )?;
            } else {
                self.application_xml = Some(app_el.clone());
            }
        }

        // Preserve user files (`UserFile="true"`), skipping `.patch` if SSC version changed
        let mut preserved_user_files = Vec::new();
        let mut skipped_patch_files = Vec::new();
        let same_ver = old.ssc_version == self.ssc_version;
        for uf in old.files.iter().filter(|f| f.flags.user_file) {
            if uf.file_type == SlaveFileType::Patch && !same_ver {
                skipped_patch_files.push(uf.name.clone());
                self.warnings.push(format!(
                    "Skipped patch '{}' from SSC {} when adapting to SSC {}",
                    uf.name, old.ssc_version, self.ssc_version
                ));
                continue;
            }
            if let Some(pos) = self
                .files
                .iter()
                .position(|existing| existing.name.eq_ignore_ascii_case(&uf.name))
            {
                self.files[pos] = uf.clone();
            } else {
                self.files.push(uf.clone());
            }
            preserved_user_files.push(uf.name.clone());
        }

        self.is_project_file = true;

        Ok(ProjectAdaptReport {
            from_ssc_version: old.ssc_version.clone(),
            to_ssc_version: self.ssc_version.clone(),
            traversed_versions,
            hw_interface_changed,
            appl_interface_changed,
            migrated_setting_count,
            preserved_user_files,
            skipped_patch_files,
            preserved_esi_fragments,
            warnings: self.warnings.clone(),
        })
    }

    /// Serialize this project to a `DomElement` (`<SlaveConfiguratorProject>` when `as_project_esp == true`,
    /// `<SlaveCodeConfigurations>` when `false`), matching `ConfigXmlDoc::CreateConfiguratorFile`.
    pub fn to_config_dom(&self, as_project_esp: bool) -> DomElement {
        let root_tag = if as_project_esp {
            "SlaveConfiguratorProject"
        } else {
            "SlaveCodeConfigurations"
        };
        let mut root = DomElement::new(root_tag);
        root.push_attr("ToolVersion", SSC_TOOL_VERSION);
        root.push_attr("SSCVersion", &self.ssc_version);
        if !self.source_code_output_dir.is_empty() {
            root.push_attr("SourceCodeOutputDir", &self.source_code_output_dir);
        }
        if !self.esi_output_dir.is_empty() {
            root.push_attr("EsiOutputDir", &self.esi_output_dir);
        }

        if !as_project_esp {
            if let Some(comment) = &self.config_comment {
                root.push_comment(comment.clone());
            }
        }

        // 1. `<SettingNodes>`
        let mut sn_el = DomElement::new("SettingNodes");
        for sn in &self.setting_nodes {
            let mut node = DomElement::new("SettingNode");
            node.push_attr("Path", &sn.path);
            node.push_attr("ControlType", &sn.control_type);
            node.push_attr("Advanced", if sn.advanced { "True" } else { "False" });
            sn_el.push_child(node);
        }
        root.push_child(sn_el);

        // 2. `<Settings>`
        let mut settings_el = DomElement::new("Settings");
        let is_config_node = !as_project_esp;
        for s in &self.settings {
            settings_el.push_child(serialize_slave_setting(s, is_config_node));
        }
        root.push_child(settings_el);

        // 3. `<SettingConflicts>`
        let mut conflicts_el = DomElement::new("SettingConflicts");
        for c in &self.conflicts {
            let mut cel = DomElement::new("SettingConflict");
            cel.push_attr("Type", c.severity.as_xml_str());
            if c.tool_only {
                cel.push_attr("ToolOnly", "true");
            }
            if !c.define_attr.is_empty() {
                cel.push_attr("Define", &c.define_attr);
            }
            if !c.linked_expression_attr.is_empty() {
                cel.push_attr("LinkedExpression", &c.linked_expression_attr);
            }
            cel.push_text(&c.message);
            conflicts_el.push_child(cel);
        }
        root.push_child(conflicts_el);

        // 4. `<Application>`
        if let Some(app_el) = &self.application_xml {
            root.push_child(app_el.clone());
        }

        // 5. Direct `<ESI Path="...">` children
        for frag in &self.esi_fragments {
            let mut fel = DomElement::new("ESI");
            fel.push_attr("Path", &frag.path);
            if frag.user_specific {
                fel.push_attr("Userspecific", "True");
            }
            if let Some(c) = &frag.comment {
                fel.push_comment(c.clone());
            }
            for v in &frag.values {
                let mut vel = DomElement::new("Value");
                if !v.active_expression.is_empty() {
                    vel.push_attr("ActiveExpression", &v.active_expression);
                }
                vel.children = v.nodes.clone();
                fel.push_child(vel);
            }
            root.push_child(fel);
        }

        // 6. `<Files>` (`ConfigXmlDoc::WriteConfiguratorFile` omits generated `*Objects.h` in `.esp`)
        let mut files_el = DomElement::new("Files");
        for f in &self.files {
            if as_project_esp
                && !f.flags.user_file
                && f.flags.appl_file
                && f.name.ends_with("Objects.h")
            {
                continue;
            }
            files_el.push_child(serialize_slave_file(f, as_project_esp));
        }
        root.push_child(files_el);

        // 7. `<Migrations>` (when saving `.escfg`)
        if !as_project_esp && !self.migrations.is_empty() {
            let mut migs_el = DomElement::new("Migrations");
            for m in &self.migrations {
                let mut mel = DomElement::new("Migration");
                mel.push_attr("From", &m.from_version);
                mel.push_attr("To", &m.to_version);
                let mut ic = DomElement::new("InterfaceChanges");
                ic.push_attr(
                    "HwInterface",
                    if m.hw_interface_changed {
                        "True"
                    } else {
                        "False"
                    },
                );
                ic.push_attr(
                    "ApplInterface",
                    if m.appl_interface_changed {
                        "True"
                    } else {
                        "False"
                    },
                );
                mel.push_child(ic);
                if !m.rules.is_empty() {
                    let mut rs_el = DomElement::new("Settings");
                    for r in &m.rules {
                        let mut rel = DomElement::new("Setting");
                        rel.push_attr("Type", &r.rule_type);
                        rel.push_attr("CodeDefine", &r.code_define);
                        if !r.value_type.is_empty() {
                            rel.push_attr("ValueType", &r.value_type);
                        }
                        if !r.default_values.is_empty() {
                            rel.push_child(serialize_default_values(&r.default_values));
                        }
                        rs_el.push_child(rel);
                    }
                    mel.push_child(rs_el);
                }
                if !m.info.is_empty() {
                    mel.push_text(&m.info);
                }
                migs_el.push_child(mel);
            }
            root.push_child(migs_el);
        }

        root
    }

    /// Save `.esp` GZIP-compressed single-line XML (`ConfigXmlDoc::WriteConfiguratorFile` parity).
    pub fn save_esp(&self, dst_path: &Path) -> Result<PathBuf> {
        let final_path = if dst_path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("esp"))
        {
            dst_path.to_path_buf()
        } else {
            dst_path.with_extension("esp")
        };
        let dom = self.to_config_dom(true);
        let compact_xml = render_compact_xml(&dom, Some("<?xml version=\"1.0\"?>"));
        write_gzip_file(&final_path, compact_xml.as_bytes())?;
        Ok(final_path)
    }
}

fn eval_migration_defaults(
    defaults: &[DefineValue],
    cfg_map: &BTreeMap<String, ExternalConfigSetting>,
    base_settings: &[SlaveSetting],
) -> String {
    if defaults.is_empty() {
        return String::new();
    }
    let lookup_val = |key: &str| -> Option<String> {
        if let Some(cs) = cfg_map.get(key) {
            if let Some(v) = &cs.value {
                return Some(v.clone());
            }
        }
        base_settings
            .iter()
            .find(|s| s.code_define == key)
            .map(|s| s.value.clone())
    };

    if defaults.len() == 1 {
        let map_snapshot: BTreeMap<String, String> =
            collect_lookup_snapshot(cfg_map, base_settings);
        return resolve_value_expression(
            &defaults[0].value,
            |k| map_snapshot.get(k).map(String::as_str),
            false,
        )
        .unwrap_or_default();
    }

    let map_snapshot = collect_lookup_snapshot(cfg_map, base_settings);
    for dv in defaults {
        let cond = if dv.expression.is_empty() {
            true
        } else {
            evaluate_boolean_expression(&dv.expression, |ident| lookup_val(ident))
        };
        if cond {
            return resolve_value_expression(
                &dv.value,
                |k| map_snapshot.get(k).map(String::as_str),
                false,
            )
            .unwrap_or_default();
        }
    }
    String::new()
}

fn collect_lookup_snapshot(
    cfg_map: &BTreeMap<String, ExternalConfigSetting>,
    base_settings: &[SlaveSetting],
) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    for s in base_settings {
        m.insert(s.code_define.clone(), s.value.clone());
    }
    for (k, cs) in cfg_map {
        if let Some(v) = &cs.value {
            m.insert(k.clone(), v.clone());
        }
    }
    m
}

fn serialize_default_values(default_values: &[DefineValue]) -> DomElement {
    let mut dv_el = DomElement::new("DefaultValues");
    if let Some(last) = default_values.last() {
        dv_el.push_attr("default", &last.value);
        for item in &default_values[..default_values.len() - 1] {
            let mut v_el = DomElement::new("Value");
            v_el.push_attr("Expression", &item.expression);
            v_el.push_attr("Value", &item.value);
            dv_el.push_child(v_el);
        }
    }
    dv_el
}

fn serialize_slave_setting(s: &SlaveSetting, is_config_node: bool) -> DomElement {
    let mut el = DomElement::new("Setting");
    el.push_attr("CodeDefine", &s.code_define);
    if !s.file_area.is_empty() {
        el.push_attr("FileArea", &s.file_area);
    }
    if !s.node_path.is_empty() {
        el.push_attr("NodePath", &s.node_path);
    }
    if !s.parent_setting.is_empty() {
        el.push_attr("ParentSetting", &s.parent_setting);
    }
    if !s.display_name.is_empty() && s.display_name != s.code_define {
        el.push_attr("DisplayName", &s.display_name);
    }
    if let Some(vt) = s.value_type.to_xml_value_type() {
        el.push_attr("ValueType", vt);
    }

    let emit_defaults =
        !s.default_values.is_empty() && (is_config_node || s.flags.read_only.is_true());
    if emit_defaults {
        el.push_child(serialize_default_values(&s.default_values));
    } else {
        el.push_attr("Value", &s.value);
    }

    let mut flags_el = DomElement::new("Flags");
    if let Some(v) = s.flags.advanced.to_xml_str() {
        flags_el.push_attr("Advanced", v);
    }
    if let Some(v) = s.flags.visible.to_xml_str() {
        flags_el.push_attr("Visible", v);
    }
    if let Some(v) = s.flags.read_only.to_xml_str() {
        flags_el.push_attr("ReadOnly", v);
    }
    if let Some(v) = s.flags.evaluate.to_xml_str() {
        flags_el.push_attr("Evaluate", v);
    }
    if !flags_el.attrs.is_empty() {
        el.push_child(flags_el);
    }

    if !s.description.is_empty() {
        el.push_text(&s.description);
    }
    el
}

fn serialize_slave_file(f: &SlaveFile, embed_content: bool) -> DomElement {
    let mut el = DomElement::new("File");
    el.push_attr("Name", &f.name);
    let ty_str = f.file_type.as_xml_str();
    if !ty_str.is_empty() {
        el.push_attr("Type", ty_str);
    }
    if !f.version.is_empty() {
        el.push_attr("Version", &f.version);
    }
    if !f.expression.is_empty() {
        el.push_attr("Expression", &f.expression);
    }

    if !f.flags.is_none() {
        let mut fl = DomElement::new("Flags");
        if f.flags.hw_file {
            fl.push_attr("HwFile", "true");
        }
        if f.flags.user_file {
            fl.push_attr("UserFile", "true");
        }
        if f.flags.appl_file {
            fl.push_attr("ApplFile", "true");
        }
        el.push_child(fl);
    }

    if embed_content {
        match &f.content {
            SlaveFileContent::TextLines(lines) => {
                el.push_text(lines.join("\r\n"));
            }
            SlaveFileContent::Binary(bytes) => {
                let mut hex_str = String::with_capacity(bytes.len() * 2);
                for &b in bytes {
                    use std::fmt::Write as _;
                    let _ = write!(&mut hex_str, "{b:02X}");
                }
                el.push_text(hex_str);
            }
            SlaveFileContent::Empty => {}
        }
    }

    el
}

fn parse_slave_setting_element(el: &DomElement) -> Result<SlaveSetting> {
    let code_define = el
        .attr("CodeDefine")
        .map(|s| get_clear_value(s).trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Format("Missing @CodeDefine on <Setting> element".into()))?;
    let file_area = el.attr("FileArea").map(get_clear_value).unwrap_or_default();
    let node_path = el.attr("NodePath").map(get_clear_value).unwrap_or_default();
    let parent_setting = el
        .attr("ParentSetting")
        .map(get_clear_value)
        .unwrap_or_default();
    let display_name = el
        .attr("DisplayName")
        .map(get_clear_value)
        .unwrap_or_else(|| code_define.clone());

    let value_type = SettingValueType::parse_ssc(el.attr("ValueType"));
    let mut value = el.attr("Value").map(get_clear_value).unwrap_or_default();
    if matches!(value_type, SettingValueType::Hex { .. })
        && !value.is_empty()
        && !value.starts_with("0x")
    {
        value = format!("0x{value}");
    }

    let mut default_values = Vec::new();
    if let Some(dv_el) = el.child("DefaultValues") {
        for v_el in dv_el.children_named("Value") {
            if let (Some(expr), Some(val)) = (v_el.attr("Expression"), v_el.attr("Value")) {
                default_values.push(DefineValue {
                    expression: get_clear_value(expr),
                    value: get_clear_value(val),
                });
            }
        }
        if let Some(def_attr) = dv_el.attr("default") {
            default_values.push(DefineValue {
                expression: String::new(),
                value: get_clear_value(def_attr),
            });
        }
    }

    let mut flags = SettingFlags::default();
    if let Some(fl_el) = el.child("Flags") {
        flags.advanced = Tristate::from_xml_opt(fl_el.attr("Advanced"));
        flags.visible = Tristate::from_xml_opt(fl_el.attr("Visible"));
        if flags.visible == Tristate::Null {
            flags.visible = Tristate::True;
        }
        flags.read_only = Tristate::from_xml_opt(fl_el.attr("ReadOnly"));
        flags.evaluate = Tristate::from_xml_opt(fl_el.attr("Evaluate"));
    }

    let description = get_clear_value(&el.direct_text());

    Ok(SlaveSetting {
        code_define,
        file_area,
        node_path,
        parent_setting,
        display_name,
        value_type,
        value,
        default_values,
        flags,
        description,
    })
}

fn parse_slave_file_element(
    el: &DomElement,
    source_folder: Option<&Path>,
    warnings: &mut Vec<String>,
) -> Result<SlaveFile> {
    let name = el
        .attr("Name")
        .map(|s| get_clear_value(s).trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CliError::Format("Missing @Name on <File> element".into()))?;
    let file_type = SlaveFileType::parse_ssc(el.attr("Type"), &name);
    let version = el.attr("Version").map(get_clear_value).unwrap_or_default();
    let expression = el
        .attr("Expression")
        .map(get_clear_value)
        .unwrap_or_default();

    let mut flags = FileFlags::default();
    if let Some(fl_el) = el.child("Flags") {
        flags.user_file = Tristate::from_xml_opt(fl_el.attr("UserFile")).is_true();
        flags.hw_file = Tristate::from_xml_opt(fl_el.attr("HwFile")).is_true();
        flags.appl_file = Tristate::from_xml_opt(fl_el.attr("ApplFile")).is_true();
    }
    if file_type == SlaveFileType::Patch {
        flags.user_file = true;
    }

    let disk_candidate = source_folder
        .map(|dir| dir.join(&name))
        .filter(|p| p.is_file());

    let content = if let Some(disk_path) = disk_candidate {
        let raw_bytes = fs::read(&disk_path).map_err(|e| {
            CliError::Io(std::io::Error::new(
                e.kind(),
                format!(
                    "failed to read SSC source file '{}': {e}",
                    disk_path.display()
                ),
            ))
        })?;
        if file_type == SlaveFileType::Binary {
            SlaveFileContent::Binary(raw_bytes)
        } else {
            let lines = split_text_lines(&bytes_to_text(&raw_bytes));
            if !flags.user_file && !version.is_empty() && version != "-" {
                if let Some(found_ver) = extract_doxygen_version(&lines) {
                    if found_ver != version {
                        warnings.push(format!(
                            "SSC source file '{}' has \\version {found_ver} (expected {version})",
                            name
                        ));
                    }
                }
            }
            SlaveFileContent::TextLines(lines)
        }
    } else {
        let embedded = get_clear_value(&el.direct_text());
        if embedded.is_empty() {
            if source_folder.is_some() && !name.eq_ignore_ascii_case("ecat_def.h") {
                warnings.push(format!(
                    "SSC file '{name}' not found in source directory and has no embedded content"
                ));
            }
            SlaveFileContent::Empty
        } else if file_type == SlaveFileType::Binary {
            SlaveFileContent::Binary(parse_setting_bytes(&embedded))
        } else {
            let lines: Vec<String> = embedded.split("\r\n").map(String::from).collect();
            SlaveFileContent::TextLines(lines)
        }
    };

    Ok(SlaveFile {
        name,
        file_type,
        version,
        expression,
        flags,
        content,
    })
}

fn extract_doxygen_version(lines: &[String]) -> Option<String> {
    for l in lines.iter().take(60) {
        if let Some(pos) = l.find("\\version ") {
            let rest = &l[pos + "\\version ".len()..];
            let ver: String = rest
                .chars()
                .take_while(|&c| c.is_ascii_digit() || c == '.')
                .collect();
            if !ver.is_empty() {
                return Some(ver);
            }
        }
    }
    None
}

fn parse_setting_conflict_element(el: &DomElement) -> SettingConflict {
    let severity = ConflictSeverity::from_xml(el.attr("Type"));
    let tool_only = Tristate::from_xml_opt(el.attr("ToolOnly")).is_true();
    let define_attr = el.attr("Define").map(get_clear_value).unwrap_or_default();
    let linked_expression_attr = el
        .attr("LinkedExpression")
        .map(get_clear_value)
        .unwrap_or_default();
    let combined_expression = if !define_attr.is_empty() && !linked_expression_attr.is_empty() {
        format!("{define_attr} {linked_expression_attr}")
    } else if !define_attr.is_empty() {
        define_attr.clone()
    } else {
        linked_expression_attr.clone()
    };
    let message = get_clear_value(&el.direct_text());

    SettingConflict {
        severity,
        tool_only,
        define_attr,
        linked_expression_attr,
        combined_expression,
        message,
    }
}

fn parse_esi_fragment_element(el: &DomElement) -> Option<EsiFragment> {
    let path = get_clear_value(el.attr("Path")?);
    let user_specific = Tristate::from_xml_opt(el.attr("Userspecific")).is_true();
    let comment = el.children.iter().find_map(|n| match n {
        DomNode::Comment(c) => Some(c.clone()),
        _ => None,
    });
    let mut values = Vec::new();
    for v_el in el.children_named("Value") {
        let active_expression = v_el
            .attr("ActiveExpression")
            .map(get_clear_value)
            .unwrap_or_default();
        values.push(EsiFragmentValue {
            active_expression,
            nodes: v_el.children.clone(),
        });
    }
    Some(EsiFragment {
        path,
        user_specific,
        comment,
        values,
    })
}

fn parse_migration_element(el: &DomElement) -> SettingMigration {
    let from_version = el.attr("From").map(get_clear_value).unwrap_or_default();
    let to_version = el.attr("To").map(get_clear_value).unwrap_or_default();
    let mut hw_interface_changed = false;
    let mut appl_interface_changed = false;
    if let Some(ic) = el.child("InterfaceChanges") {
        hw_interface_changed = Tristate::from_xml_opt(ic.attr("HwInterface")).is_true();
        appl_interface_changed = Tristate::from_xml_opt(ic.attr("ApplInterface")).is_true();
    }
    let mut rules = Vec::new();
    if let Some(s_parent) = el.child("Settings") {
        for s_el in s_parent.children_named("Setting") {
            let rule_type = s_el.attr("Type").map(get_clear_value).unwrap_or_default();
            let code_define = s_el
                .attr("CodeDefine")
                .map(get_clear_value)
                .unwrap_or_default();
            let value_type = s_el
                .attr("ValueType")
                .map(get_clear_value)
                .unwrap_or_default();
            let mut default_values = Vec::new();
            if let Some(dv_el) = s_el.child("DefaultValues") {
                for v_el in dv_el.children_named("Value") {
                    if let (Some(expr), Some(val)) = (v_el.attr("Expression"), v_el.attr("Value")) {
                        default_values.push(DefineValue {
                            expression: get_clear_value(expr),
                            value: get_clear_value(val),
                        });
                    }
                }
                if let Some(def_attr) = dv_el.attr("default") {
                    default_values.push(DefineValue {
                        expression: String::new(),
                        value: get_clear_value(def_attr),
                    });
                }
            }
            if !code_define.is_empty() {
                rules.push(MigrationSettingRule {
                    rule_type,
                    code_define,
                    value_type,
                    default_values,
                });
            }
        }
    }
    let info = get_clear_value(&el.direct_text());
    SettingMigration {
        from_version,
        to_version,
        hw_interface_changed,
        appl_interface_changed,
        rules,
        info,
    }
}

fn parse_configuration_element(
    el: &DomElement,
    parent_ssc_version: &str,
    vendor_id: &str,
    vendor_name: &str,
    source_path: Option<&Path>,
) -> ExternalConfiguration {
    let name = el.attr("Name").map(get_clear_value).unwrap_or_default();
    let config_version = el.attr("Version").map(get_clear_value).unwrap_or_default();
    let info = el.attr("Info").map(get_clear_value).unwrap_or_default();
    let patch_rel_path = el.attr("Patch").map(get_clear_value).unwrap_or_default();

    let mut settings = Vec::new();
    for s_el in el.children_named("Setting") {
        if let Some(cd) = s_el.attr("CodeDefine") {
            let visible_flag = s_el
                .child("Flags")
                .and_then(|fl| fl.attr("Visible"))
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1");
            settings.push(ExternalConfigSetting {
                code_define: get_clear_value(cd).trim().to_string(),
                value: s_el.attr("Value").map(get_clear_value),
                visible_flag,
            });
        }
    }
    // Legacy `<Defines Name="..." Value="..." />` alias
    for d_el in el.children_named("Defines") {
        if let Some(cd) = d_el.attr("Name") {
            settings.push(ExternalConfigSetting {
                code_define: get_clear_value(cd).trim().to_string(),
                value: d_el.attr("Value").map(get_clear_value),
                visible_flag: None,
            });
        }
    }

    let mut files = Vec::new();
    for f_el in el.children_named("File") {
        if let Some(fname) = f_el.attr("Name") {
            let clean_name = get_clear_value(fname).trim().to_string();
            let file_type = SlaveFileType::parse_ssc(f_el.attr("Type"), &clean_name);
            let rel_path = f_el.attr("Path").map(get_clear_value).unwrap_or_default();
            let version = f_el
                .attr("Version")
                .map(get_clear_value)
                .unwrap_or_default();
            let mut flags = FileFlags {
                user_file: true,
                hw_file: false,
                appl_file: false,
            };
            if let Some(fl) = f_el.child("Flags") {
                flags.hw_file = Tristate::from_xml_opt(fl.attr("HwFile")).is_true();
                flags.appl_file = Tristate::from_xml_opt(fl.attr("ApplFile")).is_true();
            }
            files.push(ExternalConfigFileRef {
                name: clean_name,
                file_type,
                rel_path,
                version,
                flags,
            });
        }
    }

    let application_rel_path = el
        .child_text("ApplicationFile")
        .map(|s| get_clear_value(s.trim()))
        .unwrap_or_default();

    let (source_folder, esi_folder) = if let Some(out_el) = el.child("Output") {
        (
            out_el
                .attr("SourceFolder")
                .map(get_clear_value)
                .unwrap_or_default(),
            out_el
                .attr("ESIFolder")
                .map(get_clear_value)
                .unwrap_or_default(),
        )
    } else {
        (
            el.attr("SrcDefaultOutput")
                .map(get_clear_value)
                .unwrap_or_default(),
            String::new(),
        )
    };

    let mut esi_fragments = Vec::new();
    for esi_el in el.children_named("ESI") {
        if let Some(frag) = parse_esi_fragment_element(esi_el) {
            esi_fragments.push(frag);
        }
    }

    ExternalConfiguration {
        name,
        ssc_version: parent_ssc_version.to_string(),
        config_version,
        vendor_id: vendor_id.to_string(),
        vendor_name: vendor_name.to_string(),
        info,
        patch_rel_path,
        application_rel_path,
        source_folder,
        esi_folder,
        settings,
        files,
        esi_fragments,
        source_config_path: source_path.map(Path::to_path_buf),
    }
}

/// Load external configurations from `.xml` (`<SscToolConfiguration>`, `<SlaveCodeConfigurations>`,
/// or `<EtherCATInfo>` ESI XML), a directory of `*.xml` configuration files, `.escfg`, `.esp`,
/// or `.h` (`ecat_def.h` `#define` import), matching `SscToolConfiguration::Load` + `ConfigurationCollection::GetConfigurations`.
pub fn load_external_configurations(path: &Path) -> Result<Vec<ExternalConfiguration>> {
    if path.is_dir() {
        let mut entries: Vec<PathBuf> = fs::read_dir(path)
            .map_err(|e| {
                CliError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "cannot read configuration directory '{}': {e}",
                        path.display()
                    ),
                ))
            })?
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.is_file()
                    && p.extension().and_then(|x| x.to_str()).is_some_and(|x| {
                        x.eq_ignore_ascii_case("xml") || x.eq_ignore_ascii_case("escfg")
                    })
            })
            .collect();
        entries.sort();
        let mut combined = Vec::new();
        for file_path in entries {
            if let Ok(cfgs) = load_external_configurations(&file_path) {
                combined.extend(cfgs);
            }
        }
        if combined.is_empty() {
            return Err(CliError::Format(format!(
                "No valid SSC <Configuration> files found in directory '{}'",
                path.display()
            )));
        }
        return Ok(combined);
    }

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    if ext == "h" {
        return Ok(vec![import_settings_from_ecat_def_h(path)?]);
    }

    let xml_bytes = read_gzip_or_plain(path)?;
    let root = parse_dom_bytes(&xml_bytes, false)?;

    if root.local_name() == "EtherCATInfo" {
        return import_configurations_from_esi_dom(&root, Some(path));
    }

    let ssc_version = root
        .attr("SSCVersion")
        .map(get_clear_value)
        .unwrap_or_default();
    let vendor_id = root
        .attr("VendorID")
        .map(get_clear_value)
        .unwrap_or_default();
    let vendor_name = root
        .attr("VendorName")
        .map(get_clear_value)
        .unwrap_or_default();

    let mut out = Vec::new();
    if let Some(cfgs_el) = root.child("Configurations") {
        for cfg_el in cfgs_el.children_named("Configuration") {
            out.push(parse_configuration_element(
                cfg_el,
                &ssc_version,
                &vendor_id,
                &vendor_name,
                Some(path),
            ));
        }
    } else if root.local_name() == "SlaveConfiguratorProject" {
        // Also allow importing settings directly from an `.esp` project file as a configuration
        let mut settings = Vec::new();
        if let Some(s_parent) = root.child("Settings") {
            for s_el in s_parent.children_named("Setting") {
                if let (Some(cd), Some(val)) = (s_el.attr("CodeDefine"), s_el.attr("Value")) {
                    settings.push(ExternalConfigSetting {
                        code_define: get_clear_value(cd),
                        value: Some(get_clear_value(val)),
                        visible_flag: None,
                    });
                }
            }
        }
        out.push(ExternalConfiguration {
            name: path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("ImportedProject")
                .to_string(),
            ssc_version,
            config_version: String::new(),
            vendor_id,
            vendor_name,
            info: String::new(),
            patch_rel_path: String::new(),
            application_rel_path: String::new(),
            source_folder: String::new(),
            esi_folder: String::new(),
            settings,
            files: Vec::new(),
            esi_fragments: Vec::new(),
            source_config_path: Some(path.to_path_buf()),
        });
    }

    if out.is_empty() {
        return Err(CliError::Format(format!(
            "No <Configuration> entries found in '{}'",
            path.display()
        )));
    }
    Ok(out)
}

/// Import SSC settings from an ETG.2000 `<EtherCATInfo>` ESI `.xml` file
/// (`SlaveSetting::ParseESI` + `<VendorSpecific><SSC><Settings>` parity).
pub fn import_settings_from_esi_xml(
    esi_path: &Path,
    device_index: usize,
) -> Result<ExternalConfiguration> {
    let xml_bytes = read_gzip_or_plain(esi_path)?;
    let root = parse_dom_bytes(&xml_bytes, false)?;
    if root.local_name() != "EtherCATInfo" {
        return Err(CliError::Format(format!(
            "Expected <EtherCATInfo> root in '{}', found '<{}>'",
            esi_path.display(),
            root.name
        )));
    }
    let mut cfgs = import_configurations_from_esi_dom(&root, Some(esi_path))?;
    if device_index >= cfgs.len() {
        return Err(CliError::Validation(format!(
            "Device index {device_index} out of range ('{}' has {} <Device> element(s))",
            esi_path.display(),
            cfgs.len()
        )));
    }
    Ok(cfgs.swap_remove(device_index))
}

fn import_configurations_from_esi_dom(
    root: &DomElement,
    source_path: Option<&Path>,
) -> Result<Vec<ExternalConfiguration>> {
    let vendor_el = root.child("Vendor");
    let raw_vid = vendor_el
        .and_then(|v| v.child_text("Id"))
        .unwrap_or_default();
    let vendor_id = parse_setting_u32(&raw_vid)
        .map(|v| format!("0x{v:08X}"))
        .unwrap_or_default();
    let vendor_name = vendor_el
        .and_then(|v| v.child_text("Name"))
        .unwrap_or_default()
        .trim()
        .to_string();
    let vendor_img = vendor_el
        .and_then(|v| v.child_text("ImageData16x14"))
        .unwrap_or_default()
        .trim()
        .to_string();

    let desc_el = root.child("Descriptions");
    let mut group_images: BTreeMap<String, (String, String)> = BTreeMap::new();
    if let Some(groups_el) = desc_el.and_then(|d| d.child("Groups")) {
        for g in groups_el.children_named("Group") {
            let g_type = g.child_text("Type").unwrap_or_default().trim().to_string();
            let g_name = g
                .child_text("Name")
                .unwrap_or_else(|| g_type.clone())
                .trim()
                .to_string();
            let g_img = g
                .child_text("ImageData16x14")
                .unwrap_or_default()
                .trim()
                .to_string();
            if !g_type.is_empty() {
                group_images.insert(g_type, (g_name, g_img));
            }
        }
    }

    let Some(devs_el) = desc_el.and_then(|d| d.child("Devices")) else {
        return Err(CliError::Format(
            "ESI XML contains no <Descriptions>/<Devices> section".into(),
        ));
    };

    let mut out = Vec::new();
    for (dev_idx, dev_el) in devs_el.children_named("Device").enumerate() {
        let mut map: BTreeMap<String, String> = BTreeMap::new();
        let mut order: Vec<String> = Vec::new();
        let mut set_kv = |key: &str, val: String| {
            if !map.contains_key(key) {
                order.push(key.to_string());
            }
            map.insert(key.to_string(), val);
        };

        if !vendor_id.is_empty() {
            set_kv("VENDOR_ID", vendor_id.clone());
        }
        if !vendor_name.is_empty() {
            set_kv("VENDOR_NAME", vendor_name.clone());
        }
        if !vendor_img.is_empty() {
            set_kv("VENDOR_IMAGE", vendor_img.clone());
        }

        let type_el = dev_el.child("Type");
        let type_text = type_el
            .map(|t| t.inner_text().trim().to_string())
            .unwrap_or_default();
        let dev_name = dev_el
            .child_text("Name")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                if !type_text.is_empty() {
                    type_text.clone()
                } else {
                    format!("Device_{dev_idx}")
                }
            });
        set_kv("DEVICE_NAME", dev_name.clone());

        if let Some(te) = type_el {
            if let Some(pc) = te
                .attr("ProductCode")
                .and_then(|s| parse_setting_u32(s).ok())
            {
                set_kv("PRODUCT_CODE", format!("0x{pc:08X}"));
            }
            if let Some(rev) = te
                .attr("RevisionNo")
                .and_then(|s| parse_setting_u32(s).ok())
            {
                set_kv("REVISION_NUMBER", format!("0x{rev:08X}"));
            }
        }

        if let Some(gt) = dev_el.child_text("GroupType") {
            let gt_trim = gt.trim();
            if !gt_trim.is_empty() {
                if let Some((_, g_img)) = group_images.get(gt_trim) {
                    set_kv("GROUP_NAME", gt_trim.to_string());
                    if !g_img.is_empty() {
                        set_kv("GROUP_IMAGE", g_img.clone());
                    }
                } else {
                    set_kv("GROUP_NAME", gt_trim.to_string());
                }
            }
        }

        if let Some(d_img) = dev_el.child_text("ImageData16x14") {
            let t = d_img.trim();
            if !t.is_empty() {
                set_kv("DEVICE_IMAGE", t.to_string());
            }
        }

        if let Some(info_el) = dev_el.child("Info") {
            if let Some(to_el) = info_el
                .child("StateMachine")
                .and_then(|sm| sm.child("Timeout"))
            {
                if let Some(pre) = to_el
                    .child_text("PreopTimeout")
                    .and_then(|s| s.trim().parse::<u32>().ok())
                {
                    set_kv("PREOPTIMEOUT", format!("0x{pre:X}"));
                }
                if let Some(so) = to_el
                    .child_text("SafeopOpTimeout")
                    .and_then(|s| s.trim().parse::<u32>().ok())
                {
                    set_kv("SAFEOP2OPTIMEOUT", format!("0x{so:X}"));
                }
            }
            if let Some(id134) = info_el.child_text("IdentificationReg134") {
                let b = id134.trim() == "1" || id134.trim().eq_ignore_ascii_case("true");
                set_kv("EXPLICIT_DEVICE_ID", if b { "1" } else { "0" }.to_string());
            }
        }

        if let Some(prof_el) = dev_el.child("Profile") {
            let prof_no = prof_el
                .child_text("ProfileNo")
                .or_else(|| {
                    prof_el
                        .child("ChannelInfo")
                        .and_then(|ci| ci.child_text("ProfileNo"))
                })
                .and_then(|s| parse_setting_u16(&s).ok())
                .unwrap_or(0);
            let add_info = prof_el
                .child_text("AddInfo")
                .or_else(|| {
                    prof_el
                        .child("ChannelInfo")
                        .and_then(|ci| ci.child_text("AddInfo"))
                })
                .and_then(|s| parse_setting_u16(&s).ok())
                .unwrap_or(0);
            if prof_no != 0 || add_info != 0 {
                let combined = ((add_info as u32) << 16) | (prof_no as u32);
                set_kv("DEVICE_PROFILE_TYPE", format!("0x{combined:08X}"));
            }
            if prof_el.child("DiagMessages").is_some() {
                set_kv("DIAGNOSIS_SUPPORTED", "1".to_string());
            }
            if let Some(objs_el) = prof_el.child("Dictionary").and_then(|d| d.child("Objects")) {
                for obj in objs_el.children_named("Object") {
                    let Some(idx) = obj
                        .child_text("Index")
                        .and_then(|s| parse_setting_u16(&s).ok())
                    else {
                        continue;
                    };
                    if idx == 0x1009 || idx == 0x100A {
                        if let Some(inf) = obj.child("Info") {
                            let decoded = if let Some(ds) = inf.child_text("DefaultString") {
                                Some(ds)
                            } else if let Some(dd) = inf.child_text("DefaultData") {
                                let raw_bytes = parse_setting_bytes(&dd);
                                let end = raw_bytes
                                    .iter()
                                    .position(|&b| b == 0)
                                    .unwrap_or(raw_bytes.len());
                                String::from_utf8(raw_bytes[..end].to_vec()).ok()
                            } else {
                                None
                            };
                            if let Some(ver_str) = decoded.filter(|s| !s.is_empty()) {
                                if idx == 0x1009 {
                                    set_kv("DEVICE_HW_VERSION", ver_str);
                                } else {
                                    set_kv("DEVICE_SW_VERSION", ver_str);
                                }
                            }
                        }
                    }
                }
            }
        }

        // SyncManagers
        for sm in dev_el.children_named("Sm") {
            let role = sm.text_content();
            let start_opt = sm
                .attr("StartAddress")
                .and_then(|s| parse_setting_u16(s).ok());
            let min_opt = sm.attr("MinSize").and_then(|s| parse_setting_u16(s).ok());
            let max_opt = sm.attr("MaxSize").and_then(|s| parse_setting_u16(s).ok());
            let def_opt = sm
                .attr("DefaultSize")
                .and_then(|s| parse_setting_u16(s).ok());
            match role.trim() {
                "MBoxOut" => {
                    if let Some(st) = start_opt {
                        set_kv("DEF_MBX_WRITE_ADDRESS", format!("0x{st:04X}"));
                    }
                    if let Some(mn) = min_opt {
                        set_kv("MIN_MBX_SIZE", format!("0x{mn:04X}"));
                    }
                    if let Some(mx) = max_opt {
                        set_kv("MAX_MBX_SIZE", format!("0x{mx:04X}"));
                    }
                    if let Some(df) = def_opt {
                        set_kv("DEF_MBX_SIZE", format!("0x{df:04X}"));
                    }
                }
                "MBoxIn" => {
                    if let Some(st) = start_opt {
                        set_kv("DEF_MBX_READ_ADDRESS", format!("0x{st:04X}"));
                    }
                }
                "Outputs" => {
                    if let Some(st) = start_opt {
                        set_kv("MIN_PD_WRITE_ADDRESS", format!("0x{st:04X}"));
                    }
                }
                "Inputs" => {
                    if let Some(st) = start_opt {
                        set_kv("DEF_PD_READ_ADDRESS", format!("0x{st:04X}"));
                    }
                }
                _ => {}
            }
        }

        // Mailbox protocols
        if let Some(mbx_el) = dev_el.child("Mailbox") {
            set_kv("MAILBOX_SUPPORTED", "1".to_string());
            set_kv(
                "AOE_SUPPORTED",
                if mbx_el.child("AoE").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
            set_kv(
                "EOE_SUPPORTED",
                if mbx_el.child("EoE").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
            if let Some(coe_el) = mbx_el.child("CoE") {
                set_kv("COE_SUPPORTED", "1".to_string());
                if let Some(ca) = coe_el.attr("CompleteAccess") {
                    let b = ca == "1" || ca.eq_ignore_ascii_case("true");
                    set_kv(
                        "COMPLETE_ACCESS_SUPPORTED",
                        if b { "1" } else { "0" }.to_string(),
                    );
                }
                if let Some(seg) = coe_el.attr("SegmentedSdo") {
                    let b = seg == "1" || seg.eq_ignore_ascii_case("true");
                    set_kv(
                        "SEGMENTED_SDO_SUPPORTED",
                        if b { "1" } else { "0" }.to_string(),
                    );
                }
                if let Some(dh) = coe_el.attr("DiagHistory") {
                    let b = dh == "1" || dh.eq_ignore_ascii_case("true");
                    set_kv("DIAGNOSIS_SUPPORTED", if b { "1" } else { "0" }.to_string());
                }
            } else {
                set_kv("COE_SUPPORTED", "0".to_string());
            }
            set_kv(
                "FOE_SUPPORTED",
                if mbx_el.child("FoE").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
            set_kv(
                "SOE_SUPPORTED",
                if mbx_el.child("SoE").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
            set_kv(
                "VOE_SUPPORTED",
                if mbx_el.child("VoE").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
        } else {
            set_kv("MAILBOX_SUPPORTED", "0".to_string());
        }

        // Distributed Clocks
        if let Some(dc_el) = dev_el.child("Dc") {
            let has_dc_assign = dc_el.children_named("OpMode").any(|op| {
                op.child_text("AssignActivate")
                    .and_then(|s| parse_setting_u32(&s).ok())
                    .unwrap_or(0)
                    != 0
            });
            if has_dc_assign || dc_el.children_named("OpMode").next().is_some() {
                set_kv("DC_SUPPORTED", "1".to_string());
            }
        }

        // Eeprom
        if let Some(eep_el) = dev_el.child("Eeprom") {
            if let Some(bs) = eep_el
                .child_text("ByteSize")
                .and_then(|s| parse_setting_u32(&s).ok())
            {
                set_kv("ESC_EEPROM_SIZE", format!("0x{bs:X}"));
            }
            if let Some(cd) = eep_el.child_text("ConfigData") {
                let t = cd.trim();
                if !t.is_empty() {
                    set_kv("ESC_CONFIG_DATA", t.to_string());
                }
            }
            set_kv(
                "BOOTSTRAPMODE_SUPPORTED",
                if eep_el.child("BootStrap").is_some() {
                    "1"
                } else {
                    "0"
                }
                .to_string(),
            );
        }

        // Overlay `<Info><VendorSpecific><SSC><Settings>` or `<Device><VendorSpecific><SSC><Settings>` if present!
        let mut ssc_version = String::new();
        for vs_parent in [
            dev_el.child("Info").and_then(|i| i.child("VendorSpecific")),
            dev_el.child("VendorSpecific"),
            dev_el
                .child("Profile")
                .and_then(|p| p.child("VendorSpecific")),
        ]
        .into_iter()
        .flatten()
        {
            if let Some(ssc_el) = vs_parent.child("SSC") {
                if let Some(v) = ssc_el.attr("SSCVersion").or_else(|| ssc_el.attr("Version")) {
                    ssc_version = get_clear_value(v);
                }
                if let Some(settings_el) = ssc_el.child("Settings") {
                    for s_el in settings_el.children_named("Setting") {
                        let cd_opt = s_el.attr("Name").or_else(|| s_el.attr("CodeDefine"));
                        if let (Some(cd), Some(val)) = (cd_opt, s_el.attr("Value")) {
                            let clean_cd = get_clear_value(cd).trim().to_string();
                            if !clean_cd.is_empty() {
                                set_kv(&clean_cd, get_clear_value(val));
                            }
                        }
                    }
                }
            }
        }

        let settings: Vec<ExternalConfigSetting> = order
            .into_iter()
            .filter_map(|k| {
                map.remove(&k).map(|v| ExternalConfigSetting {
                    code_define: k,
                    value: Some(v),
                    visible_flag: None,
                })
            })
            .collect();

        out.push(ExternalConfiguration {
            name: dev_name,
            ssc_version,
            config_version: String::new(),
            vendor_id: vendor_id.clone(),
            vendor_name: vendor_name.clone(),
            info: match source_path {
                Some(p) => format!("Imported from ESI {}", p.display()),
                None => "Imported from ESI XML".to_string(),
            },
            patch_rel_path: String::new(),
            application_rel_path: String::new(),
            source_folder: String::new(),
            esi_folder: String::new(),
            settings,
            files: Vec::new(),
            esi_fragments: Vec::new(),
            source_config_path: source_path.map(Path::to_path_buf),
        });
    }

    if out.is_empty() {
        return Err(CliError::Format(
            "No <Device> entries found inside <EtherCATInfo>".into(),
        ));
    }
    Ok(out)
}

/// Import `#define` settings from an existing `ecat_def.h` header file
/// (`SlaveProject::ImportSettingsFromEcatDef` / `SscToolConfiguration::Load(*.h)` parity).
pub fn import_settings_from_ecat_def_h(header_path: &Path) -> Result<ExternalConfiguration> {
    let raw = fs::read(header_path).map_err(|e| {
        CliError::Io(std::io::Error::new(
            e.kind(),
            format!("cannot read header '{}': {e}", header_path.display()),
        ))
    })?;
    let text = bytes_to_text(&raw);
    let mut major = String::new();
    let mut minor = String::new();
    let mut settings = Vec::new();

    for line in split_text_lines(&text) {
        let trimmed = line.trim();
        let Some(after_define) = trimmed.strip_prefix("#define") else {
            continue;
        };
        let rest = after_define.trim_start();
        if rest.is_empty() {
            continue;
        }
        // Split macro token (first non-whitespace sequence) and value (before `//` comment)
        let split_pos = rest
            .find(|c: char| c.is_ascii_whitespace())
            .unwrap_or(rest.len());
        let def_name = &rest[..split_pos];
        if def_name == "_ECATDEF_H_" {
            continue;
        }
        let val_with_comment = rest[split_pos..].trim_start();
        let val_no_comment = match val_with_comment.find("//") {
            Some(idx) => val_with_comment[..idx].trim(),
            None => val_with_comment.trim(),
        };
        let clean_val = val_no_comment
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .unwrap_or(val_no_comment)
            .to_string();

        if def_name == "SSC_VERSION_MAJOR" {
            major = clean_val;
            continue;
        }
        if def_name == "SSC_VERSION_MINOR" {
            minor = clean_val;
            continue;
        }

        settings.push(ExternalConfigSetting {
            code_define: def_name.to_string(),
            value: Some(clean_val),
            visible_flag: None,
        });
    }

    let ssc_version = if !major.is_empty() && !minor.is_empty() {
        format!("{major}.{minor}")
    } else {
        "5.13".to_string()
    };

    Ok(ExternalConfiguration {
        name: header_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("ecat_def.h")
            .to_string(),
        ssc_version,
        config_version: String::new(),
        vendor_id: String::new(),
        vendor_name: String::new(),
        info: format!("Imported from {}", header_path.display()),
        patch_rel_path: String::new(),
        application_rel_path: String::new(),
        source_folder: String::new(),
        esi_folder: String::new(),
        settings,
        files: Vec::new(),
        esi_fragments: Vec::new(),
        source_config_path: Some(header_path.to_path_buf()),
    })
}

/// Export a standalone `<SscToolConfiguration>` XML document from current project settings
/// (`SscToolConfiguration` export support).
pub fn export_ssc_tool_configuration_xml(
    project: &SlaveProject,
    config_name: &str,
    info: &str,
) -> Vec<u8> {
    let mut root = DomElement::new("SscToolConfiguration");
    root.push_attr("SSCVersion", &project.ssc_version);
    if let Some(vid) = project.get_setting_value("VENDOR_ID") {
        let esi_vid = vid
            .strip_prefix("0x")
            .map(|h| format!("#x{h}"))
            .unwrap_or_else(|| vid.to_string());
        root.push_attr("VendorID", esi_vid);
    }
    if let Some(vname) = project.get_setting_value("VENDOR_NAME") {
        root.push_attr("VendorName", vname);
    }

    let mut cfgs_el = DomElement::new("Configurations");
    let mut cfg_el = DomElement::new("Configuration");
    cfg_el.push_attr("Name", config_name);
    cfg_el.push_attr("Version", &project.ssc_version);
    if !info.is_empty() {
        cfg_el.push_attr("Info", info);
    }
    for s in &project.settings {
        if s.flags.read_only.is_true() {
            continue;
        }
        let mut sel = DomElement::new("Setting");
        sel.push_attr("CodeDefine", &s.code_define);
        sel.push_attr("Value", &s.value);
        cfg_el.push_child(sel);
    }
    cfgs_el.push_child(cfg_el);
    root.push_child(cfgs_el);

    crate::xml_dom::render_indented_xml_bytes(
        &root,
        Some("<?xml version=\"1.0\" encoding=\"utf-8\"?>"),
        "\t",
        false,
        false,
    )
}

/// Load `Options.xml` from an explicit path or `%APPDATA%\Beckhoff Automation GmbH & Co. KG\ET9300 Tool\Options.xml`.
pub fn load_ssc_options(explicit_path: Option<&Path>) -> Result<SscToolOptions> {
    let path = match explicit_path {
        Some(p) => p.to_path_buf(),
        None => default_appdata_tool_dir()
            .map(|d| d.join("Options.xml"))
            .ok_or_else(|| {
                CliError::Usage("Could not locate %APPDATA% for SSC Options.xml".into())
            })?,
    };
    let root = parse_dom_file(&path, false)?;
    let mut vendor_id = 0u32;
    let mut vendor_name = String::new();
    let mut apply_default_patch = None;
    let mut default_patch_file = default_appdata_tool_dir().map(|d| d.join("DefaultPatch.patch"));
    let mut add_delete_comment = false;
    let mut add_code_config_to_esi = false;
    let mut block_mismatching_values = true;
    let mut dependent_apply_all = true;
    let mut external_configuration_files = Vec::new();

    for opt in root.children_named("Option") {
        let Some(name) = opt.attr("Name") else {
            continue;
        };
        let val = opt.attr("Value").unwrap_or("").trim();
        match name {
            "VendorID" => {
                vendor_id = parse_setting_u32(val).unwrap_or(0);
            }
            "VendorName" => {
                vendor_name = val.to_string();
            }
            "ApplyDefaultPatchOnNewProjects" => {
                if val.eq_ignore_ascii_case("true") {
                    apply_default_patch = Some(true);
                } else if val.eq_ignore_ascii_case("false") {
                    apply_default_patch = Some(false);
                }
            }
            "DefaultPatchFile" if !val.is_empty() => {
                default_patch_file = Some(PathBuf::from(val));
            }
            "AddDeleteComment" => {
                add_delete_comment = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "AddCodeConfigToEsi" => {
                add_code_config_to_esi = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "BlockMismatchingValues" => {
                block_mismatching_values = !val.eq_ignore_ascii_case("false") && val != "0";
            }
            "DependentSettingChangeBehaviour" => {
                dependent_apply_all = val.eq_ignore_ascii_case("ApplyAll") || val == "1";
            }
            "ExternalConfigurationFiles" if !val.is_empty() => {
                for item in val.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    external_configuration_files.push(PathBuf::from(item));
                }
            }
            _ => {}
        }
    }

    Ok(SscToolOptions {
        options_path: path,
        vendor_id,
        vendor_name,
        apply_default_patch_on_new_projects: apply_default_patch,
        default_patch_file,
        add_delete_comment,
        add_code_config_to_esi,
        block_mismatching_values,
        dependent_setting_change_apply_all: dependent_apply_all,
        external_configuration_files,
    })
}

pub fn load_update_information_issues(path: &Path) -> Result<Vec<KnownIssue>> {
    let root = parse_dom_file(path, false)?;
    let mut issues = Vec::new();
    if let Some(issues_el) = root.child("Issues") {
        for iss in issues_el.children_named("Issue") {
            issues.push(KnownIssue {
                ssc_version: iss
                    .child_text("SscVersionXmlValue")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                number: iss
                    .child_text("Number")
                    .and_then(|s| s.trim().parse::<u32>().ok())
                    .unwrap_or(0),
                tag: iss.child_text("Tag").unwrap_or_default().trim().to_string(),
                abstract_title: iss
                    .child_text("Abstract")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                active_expression: iss
                    .child_text("ActiveExpression")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                condition: iss
                    .child_text("Condition")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                description: iss
                    .child_text("Description")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                solution: iss
                    .child_text("Solution")
                    .unwrap_or_default()
                    .trim()
                    .to_string(),
                included_in_patch: iss
                    .child_text("IncludedInPatch")
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case("true")),
            });
        }
    }
    Ok(issues)
}

pub fn default_appdata_tool_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|roaming| {
            roaming
                .join("Beckhoff Automation GmbH & Co. KG")
                .join("ET9300 Tool")
        })
}

pub fn discover_default_ssc_config_path() -> Result<PathBuf> {
    // 1. Check Windows Registry `HKLM\SOFTWARE\Beckhoff\ET9300\et9300configfile` and `Wow6432Node`
    #[cfg(windows)]
    {
        if let Some(reg_path) = query_windows_registry_et9300_config() {
            if reg_path.exists() {
                return Ok(reg_path);
            }
        }
    }

    // 2. Fallback to `%APPDATA%\Beckhoff Automation GmbH & Co. KG\ET9300 Tool\SSC\cfg\SlaveConfigFile.escfg`
    if let Some(tool_dir) = default_appdata_tool_dir() {
        let xml_cfg = tool_dir.join("SSC").join("cfg").join("SlaveConfigFile.xml");
        if xml_cfg.is_file() {
            return Ok(xml_cfg);
        }
        let escfg = tool_dir
            .join("SSC")
            .join("cfg")
            .join("SlaveConfigFile.escfg");
        if escfg.is_file() {
            return Ok(escfg);
        }
    }

    Err(CliError::Usage(
        "Could not auto-discover Beckhoff SSC configuration file. Provide `-p <project.esp|SlaveConfigFile.escfg|ssc_dir>`, `--ssc-dir <dir>`, or set `ETHERCAT_SSC_DIR`.".into(),
    ))
}

#[cfg(windows)]
fn query_windows_registry_et9300_config() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "advapi32")]
    extern "system" {
        fn RegGetValueW(
            hkey: isize,
            lp_sub_key: *const u16,
            lp_value: *const u16,
            dw_flags: u32,
            pdw_type: *mut u32,
            pv_data: *mut u8,
            pcb_data: *mut u32,
        ) -> i32;
    }

    const HKEY_LOCAL_MACHINE: isize = -2147483646i32 as isize; // 0x80000002
    const RRF_RT_REG_SZ: u32 = 0x0000_0002;

    fn read_reg_sz(subkey: &str, value_name: &str) -> Option<String> {
        let sub_w: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
        let val_w: Vec<u16> = value_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut buf = vec![0u16; 520];
        let mut byte_len = (buf.len() * 2) as u32;
        // SAFETY: `RegGetValueW` is a standard Win32 OS API reading into a valid stack/heap buffer
        // `buf` with accurate `byte_len` capacity and NUL-terminated UTF-16 subkey/value strings.
        let status = unsafe {
            RegGetValueW(
                HKEY_LOCAL_MACHINE,
                sub_w.as_ptr(),
                val_w.as_ptr(),
                RRF_RT_REG_SZ,
                std::ptr::null_mut(),
                buf.as_mut_ptr().cast::<u8>(),
                &mut byte_len,
            )
        };
        if status != 0 || byte_len < 2 {
            return None;
        }
        let u16_len = (byte_len as usize / 2).saturating_sub(1);
        let slice = &buf[..u16_len];
        let trimmed_len = slice.iter().position(|&c| c == 0).unwrap_or(slice.len());
        let s = OsString::from_wide(&slice[..trimmed_len])
            .to_string_lossy()
            .trim()
            .to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    read_reg_sz("SOFTWARE\\Beckhoff\\ET9300", "et9300configfile")
        .or_else(|| {
            read_reg_sz(
                "SOFTWARE\\Wow6432Node\\Beckhoff\\ET9300",
                "et9300configfile",
            )
        })
        .map(PathBuf::from)
}

/// Resolve a directory or file path into a concrete `.esp` / `.escfg` / `SlaveConfigFile.xml` path,
/// matching `SlaveProject::GetGetProjectInputFile`.
pub fn resolve_project_input_file(source: &Path) -> Result<PathBuf> {
    if source.is_dir() {
        let mut root = source.to_path_buf();
        if root
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case("src"))
        {
            if let Some(parent) = root.parent() {
                root = parent.to_path_buf();
            }
        }
        let xml_candidate = root.join("cfg").join("SlaveConfigFile.xml");
        if xml_candidate.is_file() {
            return Ok(xml_candidate);
        }
        let escfg_candidate = root.join("cfg").join("SlaveConfigFile.escfg");
        if escfg_candidate.is_file() {
            return Ok(escfg_candidate);
        }
        let direct_xml = root.join("SlaveConfigFile.xml");
        if direct_xml.is_file() {
            return Ok(direct_xml);
        }
        let direct_escfg = root.join("SlaveConfigFile.escfg");
        if direct_escfg.is_file() {
            return Ok(direct_escfg);
        }
        return Err(CliError::Usage(format!(
            "No SlaveConfigFile.xml or SlaveConfigFile.escfg found under '{}'",
            source.display()
        )));
    }

    if source.is_file() {
        let name = source
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if name.ends_with(".esp")
            || name.ends_with(".escfg")
            || name.ends_with("slaveconfigfile.xml")
            || name.ends_with(".xml")
        {
            return Ok(source.to_path_buf());
        }
        return Err(CliError::Usage(format!(
            "Unsupported SSC project/config input file '{}' (expected .esp, .escfg, or SlaveConfigFile.xml)",
            source.display()
        )));
    }

    Err(CliError::Usage(format!(
        "SSC project/config path '{}' does not exist",
        source.display()
    )))
}

/// Resolve `SSC\src` folder relative to `.escfg` / `SlaveConfigFile.xml`, matching `SlaveProject::CreateProject`.
pub fn resolve_source_file_folder(config_file: &Path) -> Option<PathBuf> {
    let dir = config_file.parent()?;
    let has_c_in_dir = fs::read_dir(dir).ok().is_some_and(|it| {
        it.flatten().any(|e| {
            e.path()
                .extension()
                .and_then(|x| x.to_str())
                .is_some_and(|x| x.eq_ignore_ascii_case("c"))
        })
    });
    if has_c_in_dir {
        return Some(dir.to_path_buf());
    }
    if dir
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("cfg"))
    {
        if let Some(parent) = dir.parent() {
            let src_dir = parent.join("src");
            if src_dir.is_dir() {
                return Some(src_dir);
            }
        }
    }
    let sibling_src = dir.join("src");
    if sibling_src.is_dir() {
        return Some(sibling_src);
    }
    None
}

fn resolve_config_rel_path(base_dir: &Path, raw_rel: &str) -> PathBuf {
    let expanded = expand_env_vars(raw_rel);
    let normalized = expanded.replace('/', "\\");
    let p = PathBuf::from(&normalized);
    if p.is_absolute() {
        p
    } else {
        base_dir.join(p)
    }
}

fn expand_env_vars(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("$(") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find(')') {
            let var_name = &after[..end];
            if let Ok(val) = std::env::var(var_name) {
                out.push_str(&val);
            }
            rest = &after[end + 1..];
        } else {
            out.push_str("$(");
            rest = after;
        }
    }
    out.push_str(rest);
    out
}
