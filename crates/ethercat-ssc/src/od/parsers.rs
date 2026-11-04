use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::archive::{bytes_to_text, encode_zip_archive, read_gzip_or_plain, ZipArchiveReader};
use crate::model::{SlaveProject, PROJECT_DEFAULT_SSC_OBJECTS};
use crate::od::builtin_ods::build_project_object_dictionary;
use crate::od::types::{
    convert_table_value_to_default_data, create_esi_syntax_for_entry, get_data_type,
    parse_enum_type_syntax, resolve_data_type_name, reverse_hex_byte_pairs, AccessFlags,
    EntryFlags, EntryInfo, ModuleCoEInitCmd, ModuleObjectInfoCollection, ObjectCategory,
    ObjectCode, ObjectInfo, ObjectInfoCollection, PdoMappingMode, SlaveApplication,
};
use crate::xml_dom::{parse_dom_bytes, parse_dom_file, render_compact_xml, DomElement, DomNode};
use ethercat_wire::error::{CliError, Result};

const MAX_OD_REFERENCE_DEPTH: usize = 3;

/// Exact CSV wizard template matching `ET9300Utilities.ApplicationHandler` `MyApplication_csv_SscWizard.txt`.
pub const CSV_WIZARD_TEMPLATE: &str = concat!(
    "Device Profile:;5001;Modular Device Profile;;\"Usage Notes: \n",
    "- The PDO mapping object and SyncManager assignment object doesn't need to be defined. In that case they are created automatically.\n",
    "- The following objects are fixed included in the SSC and shall not be defined in the file : 0x1000, 0x1001, 0x1008, 0x1009, 0x100a, 0x1010, 0x1011, 0x1018, 0x10F0, 0x10F1, 0x10F3, 0x1c00, 0x1c32, 0x1c33\n",
    "- Entries less or equal one 8Bit shall not overlap byte borders.\n",
    "- Entries greater 8Bit shall always start at an exact word border\n",
    "\";;;;;;;;\r\n",
    "Modul Profile:;0;;;;;;;;;;;\r\n",
    "IndexIncrement;0;;;;;;;;;;;\r\n",
    "PdoIndexIncrement:;0;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "The object dictionary defined here shall be used complementary with ETG.5001 and ETG.1000;;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "Index;ObjectCode;SI;DataType;Name;Default Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description\r\n",
    "//0x04xx;Units;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x8xx;Enums (0x0800 - 0xFFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x14nn;RxPDO Parameter (0x1400 - 0x15FF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x16nn;RxPDO Mapping (0x1600 - 0x17FF) | NOTE: if no RxPDO mapping object is defined the will  be created automatically ;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x18nn;TxPDO Paramter (0x1800 - 0x19FF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x1Ann;TxPDO Mapping (0x1A00 - 0x1BFF) | NOTE: if no TxPDO mapping object is defined the will  be created automatically ;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x1C12;SyncManager 2 Assignment | NOTE: if this object is not defined it will  be created automatically ;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x1C13;SyncManager 3 Assignment | NOTE: if this object is not defined it will  be created automatically ;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x6nnx;Input Data of the Module (0x6000 - 0x6FFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x7nnx;Output Data of the Module (0x7000 - 0x7FFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x8nnx;Configuration Data of the Module (0x8000 - 0x8FFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0x9nnx;Information Data of the Module (0x9000 - 0x9FFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0xAnnx;Diagnosis Data of the Module (0xA000 - 0xAFFF);;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    ";;;;;;;;;;;;\r\n",
    "//0xFxxx;Device Objects (0xF000 - 0xFFFF);;;;;;;;;;;\r\n",
    "0xF000;RECORD;;;Modular Device Profile;;m;;;;;;\r\n",
    ";;1;UINT16;Index distance ;0x10;m;;ro;;;;\r\n",
    ";;2;UINT16;Maximum number of modules ;;m;;ro;;;;"
);

/// Write a new `.csv` Object Dictionary wizard template file.
pub fn write_csv_template(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, CSV_WIZARD_TEMPLATE.as_bytes())?;
    Ok(())
}

/// Write a clean, self-contained OpenXML `.xlsx` Object Dictionary wizard template file.
pub fn write_xlsx_template(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let csv_grid = parse_delimited_grid(CSV_WIZARD_TEMPLATE, ';');
    let mut sheet_data = DomElement::new("sheetData");
    let mut shared_strings: Vec<String> = Vec::new();
    let mut shared_index: BTreeMap<String, usize> = BTreeMap::new();

    for (r_idx, row) in csv_grid.iter().enumerate() {
        let row_num = r_idx + 1;
        let mut row_el = DomElement::new("row");
        row_el.set_attr("r", row_num.to_string());
        for (c_idx, val) in row.iter().enumerate() {
            if val.is_empty() {
                continue;
            }
            // Start at Column B (`c_idx + 1`) just like Beckhoff's Excel template
            let col_ref = format!("{}{}", col_idx_to_excel_letters(c_idx + 1), row_num);
            let mut c_el = DomElement::new("c");
            c_el.set_attr("r", col_ref);
            let ss_id = if let Some(&existing) = shared_index.get(val) {
                existing
            } else {
                let id = shared_strings.len();
                shared_strings.push(val.clone());
                shared_index.insert(val.clone(), id);
                id
            };
            c_el.set_attr("t", "s");
            c_el.push_child(DomNode::Element(DomElement::with_text(
                "v",
                ss_id.to_string(),
            )));
            row_el.push_child(DomNode::Element(c_el));
        }
        sheet_data.push_child(DomNode::Element(row_el));
    }

    let mut worksheet = DomElement::new("worksheet");
    worksheet.set_attr(
        "xmlns",
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    );
    worksheet.push_child(DomNode::Element(sheet_data));

    let mut sst = DomElement::new("sst");
    sst.set_attr(
        "xmlns",
        "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
    );
    sst.set_attr("count", shared_strings.len().to_string());
    sst.set_attr("uniqueCount", shared_strings.len().to_string());
    for s in &shared_strings {
        let mut si = DomElement::new("si");
        let mut t = DomElement::with_text("t", s);
        if s.starts_with(' ') || s.ends_with(' ') || s.contains('\n') {
            t.set_attr("xml:space", "preserve");
        }
        si.push_child(DomNode::Element(t));
        sst.push_child(DomNode::Element(si));
    }

    let content_types = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>"#;
    let root_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#;
    let workbook = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Profile" sheetId="1" r:id="rId1"/></sheets></workbook>"#;
    let wb_rels = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>"#;

    let xml_decl = Some(r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>"#);
    let sheet_xml = render_compact_xml(&worksheet, xml_decl);
    let sst_xml = render_compact_xml(&sst, xml_decl);

    let zip_bytes = encode_zip_archive(&[
        ("[Content_Types].xml", content_types.as_bytes()),
        ("_rels/.rels", root_rels.as_bytes()),
        ("xl/workbook.xml", workbook.as_bytes()),
        ("xl/_rels/workbook.xml.rels", wb_rels.as_bytes()),
        ("xl/worksheets/sheet1.xml", sheet_xml.as_bytes()),
        ("xl/sharedStrings.xml", sst_xml.as_bytes()),
    ])?;
    fs::write(path, zip_bytes)?;
    Ok(())
}

/// Parse one or more application / Object Dictionary input files (`.xlsx`, `.csv`, `.xml`, `.eds`, `.tmc`)
/// into a unified `SlaveApplication`.
pub fn parse_application_files(
    paths: &[impl AsRef<Path>],
    strip_default_ssc_objects: bool,
) -> Result<SlaveApplication> {
    parse_application_files_with_sheet(paths, strip_default_ssc_objects, None)
}

/// Parse one or more application / Object Dictionary input files with an optional `.xlsx` worksheet index,
/// deferring automatic PDO / SyncManager object generation until all files' objects and modules are merged.
pub fn parse_application_files_with_sheet(
    paths: &[impl AsRef<Path>],
    strip_default_ssc_objects: bool,
    worksheet_index: Option<usize>,
) -> Result<SlaveApplication> {
    if paths.is_empty() {
        return Err(CliError::SscInvalidData(
            "No application input files specified".to_string(),
        ));
    }
    let mut base_app = parse_single_application_file_raw(
        paths[0].as_ref(),
        strip_default_ssc_objects,
        worksheet_index,
    )?;
    for extra in &paths[1..] {
        let next_app = parse_single_application_file_raw(
            extra.as_ref(),
            strip_default_ssc_objects,
            worksheet_index,
        )?;
        for (_, obj) in next_app.od.objects {
            base_app.od.objects.insert(obj.index, obj);
        }
        base_app.modules.extend(next_app.modules);
    }
    base_app.od.finalize_and_validate(true);
    Ok(base_app)
}

/// Parse a single `.xlsx`, `.csv`, `.xml`, `.eds`, or `.tmc` file into `SlaveApplication`.
pub fn parse_single_application_file(
    path: &Path,
    strip_default_ssc_objects: bool,
) -> Result<SlaveApplication> {
    parse_single_application_file_with_sheet(path, strip_default_ssc_objects, None)
}

/// Parse a single `.xlsx`, `.csv`, `.xml`, `.eds`, or `.tmc` file into `SlaveApplication`,
/// optionally selecting a specific 0-based `.xlsx` worksheet index (`SSC OD Tool <SheetIdx>`).
pub fn parse_single_application_file_with_sheet(
    path: &Path,
    strip_default_ssc_objects: bool,
    worksheet_index: Option<usize>,
) -> Result<SlaveApplication> {
    let mut app =
        parse_single_application_file_raw(path, strip_default_ssc_objects, worksheet_index)?;
    app.od.finalize_and_validate(true);
    Ok(app)
}

/// Parse a single application/OD file and finalize per-object layouts without auto-creating
/// `0x1600`/`0x1A00`/`0x1C12`/`0x1C13` yet (used when merging multiple files).
pub(crate) fn parse_single_application_file_raw(
    path: &Path,
    strip_default_ssc_objects: bool,
    worksheet_index: Option<usize>,
) -> Result<SlaveApplication> {
    if !path.is_file() {
        return Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Application file '{}' not found", path.display()),
        )));
    }
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut app = match ext.as_str() {
        "xlsx" | "xlsm" => parse_xlsx_application(path, worksheet_index)?,
        "csv" | "txt" | "tsv" => parse_csv_application(path)?,
        "xml" | "esp" => parse_xml_application(path)?,
        "eds" => parse_eds_application(path)?,
        "tmc" => parse_tmc_application(path)?,
        _ => {
            return Err(CliError::SscInvalidData(format!(
                "Unsupported application/OD file extension '.{ext}' in '{}'",
                path.display()
            )))
        }
    };
    app.original_file_path = path.display().to_string();
    if strip_default_ssc_objects {
        for &reserved in PROJECT_DEFAULT_SSC_OBJECTS {
            app.od.remove(reserved);
        }
    }
    app.od.finalize_and_validate(false);
    for module in &mut app.modules {
        module.od.finalize_and_validate(true);
    }
    Ok(app)
}

fn sanitize_file_name_keep_spaces(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "Application".to_string();
    }
    trimmed
        .chars()
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => '_',
            _ => c,
        })
        .collect()
}

/// Parse semicolon/tab/comma-delimited CSV into a 2D cell grid (handling RFC-4180 multi-line quoted strings).
fn parse_delimited_grid(text: &str, delimiter: char) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut cur_row: Vec<String> = Vec::new();
    let mut cur_cell = String::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    cur_cell.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                cur_cell.push(ch);
            }
        } else if ch == '"' && cur_cell.is_empty() {
            in_quotes = true;
        } else if ch == delimiter {
            cur_row.push(std::mem::take(&mut cur_cell));
        } else if ch == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            cur_row.push(std::mem::take(&mut cur_cell));
            rows.push(std::mem::take(&mut cur_row));
        } else if ch == '\n' {
            cur_row.push(std::mem::take(&mut cur_cell));
            rows.push(std::mem::take(&mut cur_row));
        } else {
            cur_cell.push(ch);
        }
    }
    if !cur_cell.is_empty() || !cur_row.is_empty() {
        cur_row.push(cur_cell);
        rows.push(cur_row);
    }
    rows
}

fn canonical_or_normalized_path(path: &Path) -> PathBuf {
    fs::canonicalize(path)
        .unwrap_or_else(|_| PathBuf::from(path.to_string_lossy().to_ascii_lowercase()))
}

fn parse_csv_application(path: &Path) -> Result<SlaveApplication> {
    let ancestors = vec![canonical_or_normalized_path(path)];
    parse_csv_application_with_ancestors(path, &ancestors)
}

fn parse_csv_application_with_ancestors(
    path: &Path,
    ancestors: &[PathBuf],
) -> Result<SlaveApplication> {
    let bytes = fs::read(path)?;
    let text = bytes_to_text(&bytes);
    let first_line = text.lines().next().unwrap_or("");
    let delimiter = if first_line.contains(';') {
        ';'
    } else if first_line.contains('\t') {
        '\t'
    } else {
        ','
    };
    let grid = parse_delimited_grid(&text, delimiter);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Application");
    let od = parse_raw_table_grid_with_refs(&grid, stem, true, path.parent(), ancestors)?;
    let app_name = if od.name.is_empty() {
        stem.to_string()
    } else {
        od.name.clone()
    };
    let mut app = SlaveApplication {
        name: app_name.clone(),
        application_file_name: sanitize_file_name_keep_spaces(&app_name),
        original_file_path: path.display().to_string(),
        od,
        modules: Vec::new(),
        max_slots: 0,
        slot_index_increment: 0,
        slot_pdo_increment: 0,
    };
    sync_mdp_f000_into_app(&mut app);
    Ok(app)
}

fn col_idx_to_excel_letters(mut col_zero_based: usize) -> String {
    let mut chars = Vec::new();
    loop {
        chars.push((b'A' + (col_zero_based % 26) as u8) as char);
        if col_zero_based < 26 {
            break;
        }
        col_zero_based = (col_zero_based / 26) - 1;
    }
    chars.into_iter().rev().collect()
}

fn excel_cell_ref_to_col_idx(cell_ref: &str) -> usize {
    const MAX_XLSX_COLS: usize = 16_384;
    let mut col = 0usize;
    let mut any = false;
    for ch in cell_ref.chars() {
        if ch.is_ascii_alphabetic() {
            any = true;
            let digit = (ch.to_ascii_uppercase() as u8 - b'A') as usize + 1;
            col = col
                .saturating_mul(26)
                .saturating_add(digit)
                .min(MAX_XLSX_COLS);
        } else {
            break;
        }
    }
    if any {
        col.saturating_sub(1)
    } else {
        0
    }
}

fn parse_xlsx_application(
    path: &Path,
    selected_worksheet_index: Option<usize>,
) -> Result<SlaveApplication> {
    let ancestors = vec![canonical_or_normalized_path(path)];
    parse_xlsx_application_with_ancestors(path, selected_worksheet_index, &ancestors)
}

fn parse_xlsx_application_with_ancestors(
    path: &Path,
    selected_worksheet_index: Option<usize>,
    ancestors: &[PathBuf],
) -> Result<SlaveApplication> {
    let archive = ZipArchiveReader::open(path)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Application")
        .to_string();

    // 1. Load sharedStrings.xml if present
    let mut shared_strings = Vec::new();
    if let Some(ss_bytes) = archive.get("xl/sharedStrings.xml") {
        let sst = parse_dom_bytes(ss_bytes, false)?;
        for si in sst.children_named("si") {
            if let Some(t) = si.child("t") {
                shared_strings.push(t.inner_text());
            } else {
                let mut combined = String::new();
                for r in si.children_named("r") {
                    if let Some(t) = r.child("t") {
                        combined.push_str(&t.inner_text());
                    }
                }
                shared_strings.push(combined);
            }
        }
    }

    // 2. Map relationship IDs from xl/_rels/workbook.xml.rels
    let mut rel_targets = BTreeMap::new();
    if let Some(rels_bytes) = archive.get("xl/_rels/workbook.xml.rels") {
        let rels_dom = parse_dom_bytes(rels_bytes, false)?;
        for rel in rels_dom.children_named("Relationship") {
            if let (Some(id), Some(target)) = (rel.attr("Id"), rel.attr("Target")) {
                let norm = target.trim_start_matches('/');
                let full_target = if norm.starts_with("xl/") {
                    norm.to_string()
                } else {
                    format!("xl/{norm}")
                };
                rel_targets.insert(id.to_string(), full_target);
            }
        }
    }

    // 3. Read sheet list from xl/workbook.xml
    let wb_bytes = archive.get("xl/workbook.xml").ok_or_else(|| {
        CliError::Format(format!(
            "Invalid .xlsx workbook '{}': missing xl/workbook.xml",
            path.display()
        ))
    })?;
    let wb_dom = parse_dom_bytes(wb_bytes, false)?;
    let mut sheets: Vec<(String, String)> = Vec::new();
    if let Some(sheets_el) = wb_dom.child("sheets") {
        for (idx, sh) in sheets_el.children_named("sheet").enumerate() {
            let sh_name = sh.attr("name").unwrap_or("Profile").to_string();
            let r_id = sh.attr("r:id").or_else(|| sh.attr("id")).unwrap_or("");
            let target = rel_targets
                .get(r_id)
                .cloned()
                .unwrap_or_else(|| format!("xl/worksheets/sheet{}.xml", idx + 1));
            sheets.push((sh_name, target));
        }
    }
    if sheets.is_empty() {
        sheets.push((
            "Profile".to_string(),
            "xl/worksheets/sheet1.xml".to_string(),
        ));
    }

    let mut app = SlaveApplication {
        name: stem.clone(),
        application_file_name: sanitize_file_name_keep_spaces(&stem),
        original_file_path: path.display().to_string(),
        od: ObjectInfoCollection::new(&stem),
        modules: Vec::new(),
        max_slots: 0,
        slot_index_increment: 0,
        slot_pdo_increment: 0,
    };

    if let Some(sel_idx) = selected_worksheet_index {
        let (sh_name, sh_path) = sheets.get(sel_idx).ok_or_else(|| {
            CliError::Validation(format!(
                "Worksheet index {sel_idx} out of range (workbook '{}' has {} sheet(s))",
                path.display(),
                sheets.len()
            ))
        })?;
        let sh_bytes = archive.get(sh_path).ok_or_else(|| {
            CliError::Format(format!(
                "Worksheet '{sh_name}' ('{sh_path}') missing in '{}'",
                path.display()
            ))
        })?;
        let grid = parse_worksheet_xml_to_grid(sh_bytes, &shared_strings)?;
        let mut od = parse_raw_table_grid_with_refs(&grid, &stem, false, path.parent(), ancestors)?;
        od.name = app.name.clone();
        app.od = od;
        sync_mdp_f000_into_app(&mut app);
        return Ok(app);
    }

    for (idx, (sh_name, sh_path)) in sheets.iter().enumerate() {
        let Some(sh_bytes) = archive.get(sh_path) else {
            continue;
        };
        let grid = parse_worksheet_xml_to_grid(sh_bytes, &shared_strings)?;
        let lower_name = sh_name.trim().to_ascii_lowercase();
        if lower_name == "information" || lower_name == "<information>" {
            // Optional metadata sheet in multi-module Excel workbooks
            for row in &grid {
                let cells: Vec<&str> = row
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect();
                if cells.len() >= 2 {
                    if cells[0].eq_ignore_ascii_case("Application Name")
                        || cells[0].eq_ignore_ascii_case("ApplicationName")
                    {
                        app.name = cells[1].to_string();
                        app.application_file_name = sanitize_file_name_keep_spaces(&app.name);
                    } else if cells[0].eq_ignore_ascii_case("MaxSlots") {
                        app.max_slots = parse_u16_any(cells[1]).unwrap_or(0);
                    }
                }
            }
            continue;
        }

        // Check if this sheet contains an `Index` header row
        let has_index_header = grid
            .iter()
            .any(|row| row.iter().any(|c| c.trim().eq_ignore_ascii_case("Index")));
        if !has_index_header {
            continue;
        }

        if idx == 0
            || lower_name == "profile"
            || lower_name == "application"
            || app.od.objects.is_empty()
        {
            let mut od =
                parse_raw_table_grid_with_refs(&grid, &stem, false, path.parent(), ancestors)?;
            od.name = app.name.clone();
            app.od = od;
        } else {
            let mut mod_od =
                parse_raw_table_grid_with_refs(&grid, sh_name, false, path.parent(), ancestors)?;
            let mod_ident = (app.modules.len() as u32) + 1;
            mod_od.source_code_prefix = format!("Module0x{mod_ident:08X}");
            app.modules.push(ModuleObjectInfoCollection {
                name: sh_name.clone(),
                type_name: sh_name.clone(),
                module_ident: mod_ident,
                module_class: None,
                fixed_pdos: true,
                od: mod_od,
                init_cmds: Vec::new(),
            });
        }
    }

    sync_mdp_f000_into_app(&mut app);
    Ok(app)
}

fn parse_worksheet_xml_to_grid(
    xml_bytes: &[u8],
    shared_strings: &[String],
) -> Result<Vec<Vec<String>>> {
    let ws = parse_dom_bytes(xml_bytes, false)?;
    let Some(sheet_data) = ws.child("sheetData") else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for row_el in sheet_data.children_named("row") {
        let mut row_cells: Vec<String> = Vec::new();
        for (seq_idx, c_el) in row_el.children_named("c").enumerate() {
            let col_idx = c_el
                .attr("r")
                .map(excel_cell_ref_to_col_idx)
                .unwrap_or(seq_idx);
            if row_cells.len() <= col_idx {
                row_cells.resize(col_idx + 1, String::new());
            }
            let cell_type = c_el.attr("t").unwrap_or("");
            let text_val = match cell_type {
                "s" => {
                    let idx_str = c_el.child_text("v").unwrap_or_default();
                    let ss_idx = idx_str.trim().parse::<usize>().unwrap_or(usize::MAX);
                    shared_strings.get(ss_idx).cloned().unwrap_or_default()
                }
                "inlineStr" => c_el
                    .child("is")
                    .map(|is_el| is_el.inner_text())
                    .unwrap_or_default(),
                "b" => {
                    let v = c_el.child_text("v").unwrap_or_else(|| "0".to_string());
                    if v.trim() == "1" {
                        "1".to_string()
                    } else {
                        "0".to_string()
                    }
                }
                _ => c_el.child_text("v").unwrap_or_default(),
            };
            row_cells[col_idx] = text_val;
        }
        rows.push(row_cells);
    }
    Ok(rows)
}

fn sync_mdp_f000_into_app(app: &mut SlaveApplication) {
    if let Some(f000) = app.od.get(0xF000) {
        if let Some(si1) = f000.entry(1) {
            let be = reverse_hex_byte_pairs(&si1.default_data);
            if let Ok(dist) = u16::from_str_radix(&be, 16) {
                app.slot_index_increment = dist;
            }
        }
        if let Some(si2) = f000.entry(2) {
            let be = reverse_hex_byte_pairs(&si2.default_data);
            if let Ok(slots) = u16::from_str_radix(&be, 16) {
                app.max_slots = slots;
            }
        }
    }
}

fn parse_u16_any(raw: &str) -> Option<u16> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hx) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix("#x"))
        .or_else(|| t.strip_prefix("#X"))
    {
        u16::from_str_radix(hx, 16).ok()
    } else {
        t.parse::<u16>().ok()
    }
}

fn parse_u32_any(raw: &str) -> Option<u32> {
    let t = raw.trim();
    if t.is_empty() {
        return None;
    }
    if let Some(hx) = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .or_else(|| t.strip_prefix("#x"))
        .or_else(|| t.strip_prefix("#X"))
    {
        u32::from_str_radix(hx, 16).ok()
    } else {
        t.parse::<u32>().ok()
    }
}

#[derive(Default)]
struct TableColumns {
    index: usize,
    object_code: Option<usize>,
    si: Option<usize>,
    data_type: Option<usize>,
    name: Option<usize>,
    unit: Option<usize>,
    default_val: Option<usize>,
    min_val: Option<usize>,
    max_val: Option<usize>,
    moc: Option<usize>,
    bs: Option<usize>,
    access: Option<usize>,
    rx_tx: Option<usize>,
    coe_read: Option<usize>,
    coe_write: Option<usize>,
    description: Option<usize>,
}

impl TableColumns {
    fn get<'a>(&self, row: &'a [String], col: Option<usize>) -> &'a str {
        col.and_then(|i| row.get(i))
            .map(|s| s.as_str())
            .unwrap_or("")
    }
}

fn extract_od_reference_target(cells_after_key: &[String]) -> Option<String> {
    for cell in cells_after_key {
        let trimmed = cell.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(pos) = lower.find("(file:") {
            let rest = &trimmed[pos + 6..];
            let inner = rest.split(')').next().unwrap_or(rest).trim();
            let clean = inner.trim_matches('"').trim_matches('\'').trim();
            if !clean.is_empty() {
                return Some(clean.to_string());
            }
        }
    }
    let val1 = cells_after_key.first().map(|s| s.trim()).unwrap_or("");
    let clean = val1.trim_matches('"').trim_matches('\'').trim();
    if clean.is_empty() || clean == "0" || clean == "-" {
        None
    } else {
        Some(clean.to_string())
    }
}

fn resolve_od_reference_path(target: &str, base_dir: Option<&Path>) -> Option<PathBuf> {
    let raw_p = Path::new(target);
    let candidates: Vec<PathBuf> = if raw_p.is_absolute() || base_dir.is_none() {
        vec![raw_p.to_path_buf()]
    } else if let Some(dir) = base_dir {
        let mut list = vec![dir.join(raw_p)];
        if raw_p.extension().is_none() {
            for ext in ["xlsx", "xlsm", "csv", "xml"] {
                list.push(dir.join(format!("{target}.{ext}")));
            }
        }
        list
    } else {
        Vec::new()
    };
    candidates.into_iter().find(|p| p.is_file())
}

fn load_referenced_od(ref_path: &Path, ancestors: &[PathBuf]) -> Result<ObjectInfoCollection> {
    if ancestors.len() > MAX_OD_REFERENCE_DEPTH {
        return Err(CliError::Validation(format!(
            "Maximum OD_Reference nesting depth ({MAX_OD_REFERENCE_DEPTH}) exceeded at '{}'",
            ref_path.display()
        )));
    }
    let canon = canonical_or_normalized_path(ref_path);
    if ancestors.contains(&canon) {
        return Err(CliError::Validation(format!(
            "Circular or self OD_Reference detected for '{}'",
            ref_path.display()
        )));
    }
    let mut next_ancestors = ancestors.to_vec();
    next_ancestors.push(canon);

    let ext = ref_path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let mut app = match ext.as_str() {
        "csv" | "txt" | "tsv" => parse_csv_application_with_ancestors(ref_path, &next_ancestors)?,
        "xlsx" | "xlsm" => parse_xlsx_application_with_ancestors(ref_path, None, &next_ancestors)?,
        _ => parse_single_application_file(ref_path, false)?,
    };
    app.od.finalize_and_validate(true);
    Ok(app.od)
}

/// Core 2D table parser shared between `.csv` and `.xlsx`/`.xlsm` (`RawTableParser` parity).
#[allow(dead_code)]
fn parse_raw_table_grid(
    grid: &[Vec<String>],
    default_name: &str,
    use_profile_title_as_name: bool,
) -> Result<ObjectInfoCollection> {
    parse_raw_table_grid_with_refs(grid, default_name, use_profile_title_as_name, None, &[])
}

fn parse_raw_table_grid_with_refs(
    grid: &[Vec<String>],
    default_name: &str,
    use_profile_title_as_name: bool,
    base_dir: Option<&Path>,
    ancestors: &[PathBuf],
) -> Result<ObjectInfoCollection> {
    let mut od = ObjectInfoCollection::new(default_name);
    let mut header_row_idx = None;
    let mut cols = TableColumns::default();
    let mut od_reference_targets: Vec<String> = Vec::new();

    // 1. Scan metadata rows until header row (`Index`)
    for (r_idx, row) in grid.iter().enumerate() {
        if let Some(idx_col) = row
            .iter()
            .position(|c| c.trim().eq_ignore_ascii_case("Index"))
        {
            header_row_idx = Some(r_idx);
            cols.index = idx_col;
            for (c_idx, cell) in row.iter().enumerate() {
                let norm = cell.trim().to_ascii_lowercase();
                match norm.as_str() {
                    "objectcode" | "object code" => cols.object_code = Some(c_idx),
                    "si" | "subindex" | "sub-index" => cols.si = Some(c_idx),
                    "datatype" | "data type" => cols.data_type = Some(c_idx),
                    "name" => cols.name = Some(c_idx),
                    "unit" => cols.unit = Some(c_idx),
                    "default value" | "defaultvalue" | "default" => cols.default_val = Some(c_idx),
                    "min value" | "minimum value" | "minvalue" | "min" => {
                        cols.min_val = Some(c_idx)
                    }
                    "max value" | "maximum value" | "maxvalue" | "max" => {
                        cols.max_val = Some(c_idx)
                    }
                    "m/o/c" | "category" => cols.moc = Some(c_idx),
                    "b/s" => cols.bs = Some(c_idx),
                    "access" => cols.access = Some(c_idx),
                    "rx/tx" | "pdomapping" | "pdo" => cols.rx_tx = Some(c_idx),
                    "coeread" | "coe read" => cols.coe_read = Some(c_idx),
                    "coewrite" | "coe write" => cols.coe_write = Some(c_idx),
                    "description" | "comment" => cols.description = Some(c_idx),
                    _ => {}
                }
            }
            break;
        }

        // Metadata key-value check
        if let Some((first_col, key_cell)) =
            row.iter().enumerate().find(|(_, c)| !c.trim().is_empty())
        {
            let key_low = key_cell.trim().trim_end_matches(':').to_ascii_lowercase();
            let val1 = row.get(first_col + 1).map(|s| s.trim()).unwrap_or("");
            let val2 = row.get(first_col + 2).map(|s| s.trim()).unwrap_or("");
            match key_low.as_str() {
                "device profile" => {
                    if let Some(dp) = parse_u16_any(val1) {
                        od.device_profile = dp;
                    }
                    if use_profile_title_as_name && !val2.is_empty() {
                        od.name = val2.to_string();
                    }
                }
                "modul profile" | "module profile" => {
                    if let Some(mp) = parse_u16_any(val1) {
                        od.module_profile = mp;
                    }
                }
                "indexincrement" | "index increment" => {
                    if let Some(inc) = parse_u16_any(val1) {
                        od.index_increment = inc;
                    }
                }
                "pdoindexincrement" | "pdo index increment" => {
                    if let Some(pinc) = parse_u16_any(val1) {
                        od.pdo_index_increment = pinc;
                    }
                }
                _ if key_low.starts_with("od_reference") || key_low.starts_with("od reference") => {
                    if let Some(target) = extract_od_reference_target(&row[first_col + 1..]) {
                        od_reference_targets.push(target);
                    }
                }
                _ => {}
            }
        }
    }

    let Some(start_row) = header_row_idx else {
        return Err(CliError::SscInvalidData(
            "Object Dictionary table is missing header row ('Index')".to_string(),
        ));
    };

    let mut current_obj: Option<ObjectInfo> = None;

    for row in &grid[start_row + 1..] {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let raw_idx = row.get(cols.index).map(|s| s.trim()).unwrap_or("");
        if raw_idx.starts_with("//") {
            continue;
        }
        // Check if any first non-empty cell is a comment
        if let Some(first_non_empty) = row.iter().map(|s| s.trim()).find(|s| !s.is_empty()) {
            if first_non_empty.starts_with("//") {
                continue;
            }
        }

        let raw_obj_code = cols.get(row, cols.object_code).trim();
        let raw_si = cols.get(row, cols.si).trim();
        let raw_dt = cols.get(row, cols.data_type).trim();
        // NOTE: Preserve trailing spaces in `Name`! Look at `DemoWizardObjects.h` line 37:
        // `"Index distance "` has a trailing space that BECKHOFF PRESERVES verbatim in `aName0xF000` and Doxygen comments!
        let raw_name = cols.get(row, cols.name);
        let raw_unit = cols.get(row, cols.unit).trim();
        let raw_def = cols.get(row, cols.default_val).trim();
        let raw_min = cols.get(row, cols.min_val).trim();
        let raw_max = cols.get(row, cols.max_val).trim();
        let raw_moc = cols.get(row, cols.moc).trim();
        let raw_bs = cols.get(row, cols.bs).trim();
        let raw_acc = cols.get(row, cols.access).trim();
        let raw_rxtx = cols.get(row, cols.rx_tx).trim();
        let raw_cread = cols.get(row, cols.coe_read).trim();
        let raw_cwrite = cols.get(row, cols.coe_write).trim();
        let raw_desc = cols.get(row, cols.description).trim();

        if !raw_idx.is_empty() {
            // Flush previous object
            if let Some(prev) = current_obj.take() {
                if !prev.is_unit_definition_only() {
                    od.insert(prev);
                }
            }

            // Replace templated `n` with `0` for base index (e.g. `0x60n0` -> `0x6000`)
            let normalized_idx = if raw_idx.starts_with("0x") || raw_idx.starts_with("0X") {
                let body: String = raw_idx[2..]
                    .chars()
                    .map(|c| if c == 'n' || c == 'N' { '0' } else { c })
                    .collect();
                format!("0x{body}")
            } else {
                raw_idx.to_string()
            };
            let depend_on_slot = raw_idx.len() > 2 && raw_idx[2..].contains(['n', 'N']);
            let Some(obj_index) = parse_u16_any(&normalized_idx) else {
                return Err(CliError::SscInvalidData(format!(
                    "Invalid object index '{raw_idx}'"
                )));
            };

            let obj_code = ObjectCode::parse_str(raw_obj_code);
            let explicit_cat = if raw_moc.is_empty() {
                None
            } else {
                Some(ObjectCategory::parse_str(raw_moc))
            };
            let mut obj = ObjectInfo::new(obj_index, raw_name, obj_code);
            obj.category = explicit_cat.unwrap_or(ObjectCategory::Optional);
            obj.has_explicit_category = explicit_cat.is_some();
            obj.depend_on_slot = depend_on_slot;
            obj.coe_read_callback = raw_cread.to_string();
            obj.coe_write_callback = raw_cwrite.to_string();
            obj.description = raw_desc.to_string();

            // If this is a single-row `VAR` object (or has DataType on the object row itself)
            if obj_code == ObjectCode::Variable || (!raw_dt.is_empty() && raw_si.is_empty()) {
                obj.object_code = ObjectCode::Variable;
                let mut entry = build_entry_from_table_cells(
                    0,
                    raw_name,
                    raw_dt,
                    raw_unit,
                    raw_def,
                    raw_min,
                    raw_max,
                    raw_bs,
                    raw_acc,
                    raw_rxtx,
                    raw_cread,
                    raw_cwrite,
                    raw_desc,
                    obj.is_enum_object(),
                )?;
                entry.category = explicit_cat;
                obj.entries.push(entry);
            } else if matches!(obj_code, ObjectCode::Array | ObjectCode::Record)
                && (!raw_acc.is_empty() || !raw_bs.is_empty())
                && !obj.is_enum_object()
            {
                // Object header row explicitly specifies SubIndex 0 `Access` and/or `B/S` flags (e.g. `0x2001` `o;s;rw` or `0x8000` `o;s;`)
                let bs_low = raw_bs.to_ascii_lowercase();
                let si0_flags = EntryFlags {
                    access: AccessFlags::parse_str(raw_acc, None, None),
                    pdo_mapping: PdoMappingMode::None,
                    backup: bs_low.contains('b'),
                    setting: bs_low.contains('s'),
                };
                obj.entries.push(EntryInfo {
                    sub_index: 0,
                    name: "SubIndex 000".to_string(),
                    data_type_id: 5,
                    bit_length: 8,
                    bit_offset: 0,
                    flags: si0_flags,
                    category: explicit_cat,
                    ..Default::default()
                });
            }
            current_obj = Some(obj);
        } else if !raw_si.is_empty() || !raw_dt.is_empty() {
            let Some(ref mut obj) = current_obj else {
                continue;
            };
            let (si_list, is_range) = parse_subindex_range(raw_si)?;
            let is_enum = obj.is_enum_object();
            // For ENUM `0x0800..0x0FFF`, check if the parent object's name (`DT0800EN08`) defines the bit width
            let enum_bits = if is_enum {
                parse_enum_type_syntax(&obj.name)
                    .map(|(_, b)| b)
                    .unwrap_or(0)
            } else {
                0
            };

            let entry_cat = if raw_moc.is_empty() {
                None
            } else {
                Some(ObjectCategory::parse_str(raw_moc))
            };
            for si in si_list {
                let expanded_name = format_subindex_template(raw_name, si, is_range);
                let expanded_desc = format_subindex_template(raw_desc, si, is_range);
                let mut entry = build_entry_from_table_cells(
                    si,
                    &expanded_name,
                    raw_dt,
                    raw_unit,
                    raw_def,
                    raw_min,
                    raw_max,
                    raw_bs,
                    raw_acc,
                    raw_rxtx,
                    raw_cread,
                    raw_cwrite,
                    &expanded_desc,
                    is_enum,
                )?;
                entry.category = entry_cat;
                if is_enum && enum_bits > 0 {
                    entry.bit_length = enum_bits;
                }
                obj.entries.push(entry);
            }
        }
    }

    if let Some(prev) = current_obj.take() {
        if !prev.is_unit_definition_only() {
            od.insert(prev);
        }
    }

    // Apply `OD_Reference` base dictionary inheritance (`RawTableParser` / `InheritObjects` parity)
    for target in &od_reference_targets {
        let ref_path = resolve_od_reference_path(target, base_dir).ok_or_else(|| {
            CliError::Validation(format!(
                "Referenced OD file '{target}' not found{}",
                base_dir
                    .map(|d| format!(" (searched relative to '{}')", d.display()))
                    .unwrap_or_default()
            ))
        })?;
        let ref_od = load_referenced_od(&ref_path, ancestors)?;
        od.inherit_objects(&ref_od);
    }

    Ok(od)
}

impl ObjectInfo {
    fn is_unit_definition_only(&self) -> bool {
        (0x0400..=0x07FF).contains(&self.index)
    }
}

fn normalize_subindex_bound(raw: &str) -> &str {
    let mut s = raw.trim();
    for prefix in ["0xnn+", "0Xnn+", "0xNN+", "0XNN+", "n+", "N+"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest.trim();
            break;
        }
    }
    s
}

fn parse_subindex_bound(raw: &str, full_expr: &str) -> Result<u8> {
    let norm = normalize_subindex_bound(raw);
    if norm.eq_ignore_ascii_case("partial") || norm.eq_ignore_ascii_case("n") {
        return Ok(0);
    }
    let val_u16 = parse_u16_any(norm).ok_or_else(|| {
        CliError::SscInvalidData(format!("Invalid subindex '{raw}' in '{full_expr}'"))
    })?;
    u8::try_from(val_u16).map_err(|_| {
        CliError::SscInvalidData(format!("Subindex {val_u16} exceeds 255 in '{full_expr}'"))
    })
}

fn split_subindex_range(s: &str) -> Option<(&str, &str)> {
    if let Some(pair) = s.split_once('\u{2026}') {
        return Some(pair);
    }
    if let Some(pair) = s.split_once("...") {
        return Some(pair);
    }
    if let Some(pair) = s.split_once("..") {
        return Some(pair);
    }
    if let Some(idx) = s.find('-') {
        if idx > 0 {
            return Some((&s[..idx], &s[idx + 1..]));
        }
    }
    None
}

fn parse_subindex_range(raw_si: &str) -> Result<(Vec<u8>, bool)> {
    let t = raw_si.trim();
    if t.is_empty() {
        return Ok((vec![0], false));
    }
    if let Some((lo_s, hi_s)) = split_subindex_range(t) {
        let lo = parse_subindex_bound(lo_s, raw_si)?;
        let hi = parse_subindex_bound(hi_s, raw_si)?;
        if hi < lo {
            return Err(CliError::SscInvalidData(format!(
                "Invalid descending subindex range '{raw_si}'"
            )));
        }
        return Ok(((lo..=hi).collect(), true));
    }
    let single = parse_subindex_bound(t, raw_si)?;
    Ok((vec![single], false))
}

fn format_subindex_template(raw: &str, si: u8, is_range: bool) -> String {
    if raw.contains("{_SI_") {
        let mut out = String::with_capacity(raw.len() + 4);
        let mut rest = raw;
        while let Some(start) = rest.find("{_SI_") {
            out.push_str(&rest[..start]);
            let after_prefix = &rest[start + 5..];
            if let Some(end) = after_prefix.find('}') {
                let spec = &after_prefix[..end];
                let formatted = match spec {
                    "" => format!("{si}"),
                    ":X" => format!("{si:X}"),
                    ":x" => format!("{si:x}"),
                    ":X2" => format!("{si:02X}"),
                    ":x2" => format!("{si:02x}"),
                    ":X4" => format!("{si:04X}"),
                    ":x4" => format!("{si:04x}"),
                    ":D2" | ":d2" | ":02" => format!("{si:02}"),
                    ":D3" | ":d3" | ":03" => format!("{si:03}"),
                    _ => format!("{si}"),
                };
                out.push_str(&formatted);
                rest = &after_prefix[end + 1..];
            } else {
                out.push_str("{_SI_");
                rest = after_prefix;
            }
        }
        out.push_str(rest);
        return out;
    }

    if is_range {
        if let Some(prefix) = raw.strip_suffix(" n") {
            return format!("{prefix} {si}");
        }
    }
    raw.to_string()
}

#[allow(clippy::too_many_arguments)]
fn build_entry_from_table_cells(
    sub_index: u8,
    raw_name: &str,
    raw_dt: &str,
    raw_unit: &str,
    raw_def: &str,
    raw_min: &str,
    raw_max: &str,
    raw_bs: &str,
    raw_acc: &str,
    raw_rxtx: &str,
    raw_cread: &str,
    raw_cwrite: &str,
    raw_desc: &str,
    is_enum_entry: bool,
) -> Result<EntryInfo> {
    let (data_type_id, bit_length) = resolve_data_type_name(raw_dt)?;
    let bs_low = raw_bs.to_ascii_lowercase();
    let flags = EntryFlags {
        access: AccessFlags::parse_str(raw_acc, None, None),
        pdo_mapping: PdoMappingMode::parse_str(raw_rxtx),
        backup: bs_low.contains('b'),
        setting: bs_low.contains('s'),
    };

    let enum_value = if is_enum_entry && sub_index > 0 {
        if let Some(hx) = raw_def
            .strip_prefix("0x")
            .or_else(|| raw_def.strip_prefix("0X"))
        {
            i32::from_str_radix(hx, 16).ok()
        } else {
            raw_def.parse::<i32>().ok()
        }
    } else {
        None
    };

    let default_data = convert_table_value_to_default_data(data_type_id, bit_length, raw_def)?;
    let min_data = convert_table_value_to_default_data(data_type_id, bit_length, raw_min)?;
    let max_data = convert_table_value_to_default_data(data_type_id, bit_length, raw_max)?;
    let unit = parse_u32_any(raw_unit);

    Ok(EntryInfo {
        sub_index,
        name: raw_name.to_string(),
        data_type_id,
        bit_length,
        bit_offset: 0,
        flags,
        default_data,
        min_data,
        max_data,
        unit,
        description: raw_desc.to_string(),
        coe_read_callback: raw_cread.to_string(),
        coe_write_callback: raw_cwrite.to_string(),
        enum_value,
        category: None,
    })
}

/// Parse `<EtherCATInfo>`, `<EtherCATDict>`, `<Application>`, or GZIP/plain `.esp` `<SlaveConfiguratorProject>` into `SlaveApplication`.
pub fn parse_xml_application(path: &Path) -> Result<SlaveApplication> {
    let raw_bytes = read_gzip_or_plain(path)?;
    let root = parse_dom_bytes(&raw_bytes, false)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Application")
        .to_string();
    if root.local_name() == "SlaveConfiguratorProject" {
        if let Some(app_el) = root.child("Application") {
            return parse_application_from_dom(app_el, &stem);
        }
        let proj = SlaveProject::load(Some(path), None)?;
        let od = build_project_object_dictionary(&proj, None)?;
        let app_name = if od.name.is_empty() {
            stem
        } else {
            od.name.clone()
        };
        let mut app = SlaveApplication::new(&app_name);
        app.application_file_name = sanitize_file_name_keep_spaces(&app_name);
        app.od = od;
        sync_mdp_f000_into_app(&mut app);
        return Ok(app);
    }
    parse_application_from_dom(&root, &stem)
}

pub fn parse_application_from_dom(
    root: &DomElement,
    default_name: &str,
) -> Result<SlaveApplication> {
    let root_name = root.local_name();
    if root_name == "SlaveConfiguratorProject" {
        if let Some(app_el) = root.child("Application") {
            return parse_application_from_dom(app_el, default_name);
        }
    }
    if root_name == "EtherCATDict" {
        let mut app = SlaveApplication::new(default_name);
        app.application_file_name = sanitize_file_name_keep_spaces(default_name);
        if let Some(dict_el) = root.child("Dictionary") {
            app.od = parse_dictionary_element(dict_el, default_name)?;
        }
        sync_mdp_f000_into_app(&mut app);
        return Ok(app);
    }

    if root_name == "Application" {
        let info_el = root
            .child("Dictionary")
            .and_then(|d| d.child("Information"));
        let name = info_el
            .and_then(|inf| inf.attr("Name"))
            .or_else(|| root.attr("Name"))
            .unwrap_or(default_name)
            .to_string();
        let mut app = SlaveApplication::new(&name);
        if let Some(fn_attr) = root.attr("FileName") {
            app.application_file_name = fn_attr.to_string();
        } else {
            app.application_file_name = sanitize_file_name_keep_spaces(&name);
        }
        app.max_slots = root.attr("MaxSlots").and_then(parse_u16_any).unwrap_or(0);
        if let Some(dict_el) = root.child("Dictionary") {
            app.od = parse_dictionary_element(dict_el, &name)?;
        }
        if app.od.device_profile == 0 {
            app.od.device_profile = root
                .attr("DeviceProfile")
                .and_then(parse_u16_any)
                .unwrap_or(0);
        }
        if app.od.module_profile == 0 {
            app.od.module_profile = root
                .attr("ModuleProfile")
                .and_then(parse_u16_any)
                .unwrap_or(0);
        }
        if app.od.index_increment == 0 {
            app.od.index_increment = root
                .attr("IndexIncrement")
                .and_then(parse_u16_any)
                .unwrap_or(0);
        }
        if app.od.pdo_index_increment == 0 {
            app.od.pdo_index_increment = root
                .attr("PdoIndexIncrement")
                .and_then(parse_u16_any)
                .unwrap_or(0);
        }
        for mod_el in root.children_named("Module") {
            if let Some(mdict) = mod_el.child("Dictionary") {
                let minfo = mdict.child("Information");
                let mname = minfo
                    .and_then(|inf| inf.attr("Name"))
                    .unwrap_or("Module")
                    .to_string();
                let mident = minfo
                    .and_then(|inf| inf.attr("ModuleIdent"))
                    .and_then(parse_u32_any)
                    .unwrap_or(0);
                let mut mod_od = parse_dictionary_element(mdict, &mname)?;
                mod_od.source_code_prefix = format!("Module0x{mident:08X}");
                app.modules.push(ModuleObjectInfoCollection {
                    name: mname.clone(),
                    type_name: mname,
                    module_ident: mident,
                    module_class: None,
                    fixed_pdos: true,
                    od: mod_od,
                    init_cmds: Vec::new(),
                });
            }
        }
        sync_mdp_f000_into_app(&mut app);
        return Ok(app);
    }

    // `<EtherCATInfo>` ESI document
    let dev_el = root
        .child("Descriptions")
        .and_then(|d| d.child("Devices"))
        .and_then(|devs| devs.child("Device"))
        .ok_or_else(|| {
            CliError::SscInvalidData(format!(
                "XML root '<{root_name}>' does not contain <EtherCATDict> or <Descriptions><Devices><Device>"
            ))
        })?;

    let dev_name = dev_el
        .child_text("Name")
        .or_else(|| dev_el.child("Type").map(|_| default_name.to_string()))
        .unwrap_or_else(|| default_name.to_string());
    let mut app = SlaveApplication::new(&dev_name);
    app.application_file_name = sanitize_file_name_keep_spaces(&dev_name);

    if let Some(prof_el) = dev_el.child("Profile") {
        if let Some(pno) = prof_el
            .child_text("ProfileNo")
            .as_deref()
            .and_then(parse_u16_any)
        {
            app.od.device_profile = pno;
        }
        if let Some(dict_el) = prof_el.child("Dictionary") {
            let parsed_od = parse_dictionary_element(dict_el, &dev_name)?;
            app.od.objects = parsed_od.objects;
        }
    }

    if let Some(slots_el) = dev_el.child("Slots") {
        app.max_slots = slots_el
            .attr("MaxSlotCount")
            .and_then(parse_u16_any)
            .unwrap_or(0);
        let slot_el = slots_el.child("Slot");
        app.slot_index_increment = slot_el
            .and_then(|s| s.attr("SlotIndexIncrement"))
            .or_else(|| slots_el.attr("SlotIndexIncrement"))
            .and_then(parse_u16_any)
            .unwrap_or(0);
        app.slot_pdo_increment = slot_el
            .and_then(|s| s.attr("SlotPdoIncrement"))
            .or_else(|| slots_el.attr("SlotPdoIncrement"))
            .and_then(parse_u16_any)
            .unwrap_or(0);
        if app.slot_index_increment != 0 || slot_el.is_some() {
            app.od.index_increment = app.slot_index_increment;
        }
        if app.slot_pdo_increment != 0 || slot_el.is_some() {
            app.od.pdo_index_increment = app.slot_pdo_increment;
        }
    }

    // Parse `<Descriptions><Modules><Module>` if present
    if let Some(mods_el) = root.child("Descriptions").and_then(|d| d.child("Modules")) {
        for mod_el in mods_el.children_named("Module") {
            let type_el = mod_el.child("Type");
            let type_name = type_el.map(|t| t.inner_text()).unwrap_or_default();
            let mod_ident = type_el
                .and_then(|t| t.attr("ModuleIdent"))
                .and_then(parse_u32_any)
                .unwrap_or(0);
            let mod_class = type_el
                .and_then(|t| t.attr("ModuleClass"))
                .map(|s| s.to_string());
            let mod_name = mod_el
                .child_text("Name")
                .unwrap_or_else(|| type_name.clone());
            let mut mod_od = if let Some(dict_el) =
                mod_el.child("Profile").and_then(|p| p.child("Dictionary"))
            {
                parse_dictionary_element(dict_el, &mod_name)?
            } else {
                ObjectInfoCollection::new(&mod_name)
            };
            if let Some(pno) = mod_el
                .child("Profile")
                .and_then(|p| p.child_text("ProfileNo"))
                .as_deref()
                .and_then(parse_u16_any)
            {
                mod_od.module_profile = pno;
            }
            mod_od.source_code_prefix = format!("Module0x{mod_ident:08X}");

            let mut init_cmds = Vec::new();
            if let Some(coe_el) = mod_el.child("Mailbox").and_then(|m| m.child("CoE")) {
                for ic in coe_el.children_named("InitCmd") {
                    let transition = ic
                        .child_text("Transition")
                        .unwrap_or_else(|| "IP".to_string());
                    let idx_el = ic.child("Index");
                    let index = idx_el
                        .map(|e| e.inner_text())
                        .and_then(|s| parse_u16_any(&s))
                        .unwrap_or(0);
                    let depend_on_slot = idx_el
                        .and_then(|e| e.attr("DependOnSlot"))
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let depend_on_slot_group = idx_el
                        .and_then(|e| e.attr("DependOnSlotGroup"))
                        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                        .unwrap_or(false);
                    let sub_index = ic
                        .child_text("SubIndex")
                        .as_deref()
                        .and_then(parse_u16_any)
                        .unwrap_or(0) as u8;
                    let data_hex = ic.child_text("Data").unwrap_or_default();
                    let comment = ic.child_text("Comment").unwrap_or_default();
                    init_cmds.push(ModuleCoEInitCmd {
                        transition,
                        index,
                        sub_index,
                        depend_on_slot,
                        depend_on_slot_group,
                        data_hex,
                        comment,
                    });
                }
            }

            app.modules.push(ModuleObjectInfoCollection {
                name: mod_name,
                type_name,
                module_ident: mod_ident,
                module_class: mod_class,
                fixed_pdos: true,
                od: mod_od,
                init_cmds,
            });
        }
    }

    sync_mdp_f000_into_app(&mut app);
    Ok(app)
}

/// Parse `<Dictionary>` (`<DataTypes>` + `<Objects>`) into `ObjectInfoCollection`.
pub fn parse_dictionary_element(dict_el: &DomElement, name: &str) -> Result<ObjectInfoCollection> {
    let mut od = ObjectInfoCollection::new(name);
    if let Some(inf) = dict_el.child("Information") {
        if let Some(n) = inf.attr("Name") {
            od.name = n.to_string();
        }
        if let Some(dp) = inf.attr("DeviceProfile").and_then(parse_u16_any) {
            od.device_profile = dp;
        }
        if let Some(mp) = inf.attr("ModuleProfile").and_then(parse_u16_any) {
            od.module_profile = mp;
        }
        if let Some(inc) = inf.attr("ObjectIndexIncrement").and_then(parse_u16_any) {
            od.index_increment = inc;
        }
        if let Some(pinc) = inf
            .attr("PdoMappingObjectIndexIncrement")
            .and_then(parse_u16_any)
        {
            od.pdo_index_increment = pinc;
        }
    }
    let mut dt_map: BTreeMap<String, DomElement> = BTreeMap::new();
    if let Some(dts_el) = dict_el.child("DataTypes") {
        for dt in dts_el.children_named("DataType") {
            if let Some(dt_name) = dt.child_text("Name") {
                dt_map.insert(dt_name.trim().to_string(), dt.clone());
            }
        }
    }

    // Reconstruct any `<DataType>` with `<EnumInfo>` into an Enum `ObjectInfo` (`0x0800..0x0FFF`)!
    for (dt_name, dt_el) in &dt_map {
        let enum_infos: Vec<&DomElement> = dt_el.children_named("EnumInfo").collect();
        if !enum_infos.is_empty() && dt_name.starts_with("DT") {
            let parsed_enum = parse_enum_type_syntax(dt_name).or_else(|| {
                u16::from_str_radix(&dt_name[2..], 16)
                    .ok()
                    .map(|id| (id, 0))
            });
            if let Some((enum_idx, parsed_bits)) = parsed_enum {
                if (0x0800..=0x0FFF).contains(&enum_idx) {
                    let bits = dt_el
                        .child_text("BitSize")
                        .and_then(|s| s.trim().parse::<i32>().ok())
                        .unwrap_or(if parsed_bits > 0 { parsed_bits } else { 8 });
                    let mut enum_obj = ObjectInfo::new(
                        enum_idx,
                        format!("DT{enum_idx:04X}EN{bits:02}"),
                        ObjectCode::Defstruct,
                    );
                    enum_obj.data_type_id = 40;
                    for (i, ei) in enum_infos.iter().enumerate() {
                        let txt = ei.child_text("Text").unwrap_or_default();
                        let val = ei
                            .child_text("Enum")
                            .and_then(|s| s.trim().parse::<i32>().ok())
                            .unwrap_or(i as i32);
                        let byte_w = ((bits.max(8) + 7) / 8) as usize;
                        let be = format!("{:0width$X}", (val as u32), width = byte_w * 2);
                        enum_obj.entries.push(EntryInfo {
                            sub_index: (i + 1) as u8,
                            name: txt,
                            data_type_id: 5,
                            bit_length: bits,
                            flags: EntryFlags::RO,
                            default_data: reverse_hex_byte_pairs(&be),
                            enum_value: Some(val),
                            ..Default::default()
                        });
                    }
                    od.insert(enum_obj);
                }
            }
        }
    }

    if let Some(objs_el) = dict_el.child("Objects") {
        for obj_el in objs_el.children_named("Object") {
            let Some(idx_el) = obj_el.child("Index") else {
                continue;
            };
            let Some(index) = parse_u16_any(&idx_el.inner_text()) else {
                continue;
            };
            let depend_on_slot = idx_el
                .attr("DependOnSlot")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let depend_on_slot_group = idx_el
                .attr("DependOnSlotGroup")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let obj_name = obj_el.child_text("Name").unwrap_or_default();
            let type_name = obj_el
                .child_text("Type")
                .unwrap_or_default()
                .trim()
                .to_string();
            let bit_size = obj_el
                .child_text("BitSize")
                .and_then(|s| s.trim().parse::<i32>().ok())
                .unwrap_or(0);

            let cat = obj_el
                .child("Flags")
                .and_then(|f| f.child_text("Category"))
                .as_deref()
                .map(ObjectCategory::parse_str)
                .unwrap_or(ObjectCategory::Optional);

            // Check if `type_name` resolves to a compound `<DataType>` with `<SubItem>`s
            if let Some(dt_el) = dt_map.get(&type_name) {
                let sub_items: Vec<&DomElement> = dt_el.children_named("SubItem").collect();
                if !sub_items.is_empty() {
                    let info_subitems: Vec<&DomElement> = obj_el
                        .child("Info")
                        .map(|inf| inf.children_named("SubItem").collect())
                        .unwrap_or_default();

                    // Check if `SubItem[1]` is an `Elements` array reference (`DTxxxxARR`)
                    let is_arr_wrapper = sub_items.len() == 2
                        && sub_items[1].child_text("SubIdx").is_none()
                        && sub_items[1]
                            .child_text("Type")
                            .and_then(|tn| dt_map.get(tn.trim()))
                            .and_then(|arr_dt| arr_dt.child("ArrayInfo"))
                            .is_some();

                    if is_arr_wrapper {
                        let arr_sub = sub_items[1];
                        let arr_type_raw = arr_sub.child_text("Type").unwrap_or_default();
                        let arr_type_name = arr_type_raw.trim();
                        let arr_dt = &dt_map[arr_type_name];
                        let base_type = arr_dt
                            .child_text("BaseType")
                            .unwrap_or_else(|| "UINT".to_string());
                        let elem_count = arr_dt
                            .child("ArrayInfo")
                            .and_then(|ai| ai.child_text("Elements"))
                            .and_then(|s| s.trim().parse::<usize>().ok())
                            .unwrap_or(0)
                            .min(u8::MAX as usize);
                        let elem_flags = parse_esi_flags_element(arr_sub.child("Flags"));
                        let (elem_dt_id, elem_bits) =
                            resolve_esi_type_name(&base_type, &dt_map).unwrap_or((6, 16));

                        let mut obj = ObjectInfo::new(index, obj_name, ObjectCode::Array);
                        obj.category = cat;
                        obj.depend_on_slot = depend_on_slot;
                        obj.depend_on_slot_group = depend_on_slot_group;

                        let si0_flags = parse_esi_flags_element(sub_items[0].child("Flags"));
                        let si0_def = info_subitems
                            .first()
                            .and_then(|si| extract_esi_info_default(si.child("Info"), 5, 8))
                            .unwrap_or_else(|| format!("{elem_count:02X}"));
                        obj.entries.push(EntryInfo {
                            sub_index: 0,
                            name: sub_items[0]
                                .child_text("Name")
                                .unwrap_or_else(|| "SubIndex 000".to_string()),
                            data_type_id: 5,
                            bit_length: 8,
                            bit_offset: 0,
                            flags: si0_flags,
                            default_data: si0_def,
                            ..Default::default()
                        });

                        for i in 1..=elem_count {
                            let info_si = info_subitems.get(i).copied();
                            let def_data = info_si
                                .and_then(|si| {
                                    extract_esi_info_default(
                                        si.child("Info"),
                                        elem_dt_id,
                                        elem_bits,
                                    )
                                })
                                .unwrap_or_default();
                            let si_name = info_si
                                .and_then(|si| si.child_text("Name"))
                                .unwrap_or_else(|| format!("SubIndex {i:03}"));
                            obj.entries.push(EntryInfo {
                                sub_index: i as u8,
                                name: si_name,
                                data_type_id: elem_dt_id,
                                bit_length: elem_bits,
                                bit_offset: 16 + ((i as i32 - 1) * elem_bits),
                                flags: elem_flags,
                                default_data: def_data,
                                ..Default::default()
                            });
                        }
                        od.insert(obj);
                        continue;
                    }

                    // Otherwise standard RECORD `<DataType>` with explicit `<SubItem>`s
                    let mut obj = ObjectInfo::new(index, obj_name, ObjectCode::Record);
                    obj.category = cat;
                    obj.depend_on_slot = depend_on_slot;
                    obj.depend_on_slot_group = depend_on_slot_group;
                    for (pos, sub) in sub_items.iter().enumerate() {
                        let sub_idx = sub
                            .child_text("SubIdx")
                            .as_deref()
                            .and_then(parse_u16_any)
                            .unwrap_or(pos as u16) as u8;
                        let sub_name = sub.child_text("Name").unwrap_or_default();
                        let sub_type = sub.child_text("Type").unwrap_or_default();
                        let sub_bits = sub
                            .child_text("BitSize")
                            .and_then(|s| s.trim().parse::<i32>().ok())
                            .unwrap_or(0);
                        let sub_offs = sub
                            .child_text("BitOffs")
                            .and_then(|s| s.trim().parse::<i32>().ok())
                            .unwrap_or(0);
                        let (mut dt_id, resolved_bits) =
                            resolve_esi_type_name(&sub_type, &dt_map).unwrap_or((5, sub_bits));
                        if dt_id == 0 && sub_bits > 0 {
                            dt_id = 5;
                        }
                        let final_bits = if sub_bits > 0 {
                            sub_bits
                        } else {
                            resolved_bits
                        };
                        let flags = parse_esi_flags_element(sub.child("Flags"));
                        let sub_cat = sub
                            .child("Flags")
                            .and_then(|f| f.child_text("Category"))
                            .as_deref()
                            .map(ObjectCategory::parse_str);
                        let info_match = info_subitems
                            .iter()
                            .find(|isi| {
                                isi.child_text("Name")
                                    .map(|n| n == sub_name)
                                    .unwrap_or(false)
                            })
                            .copied()
                            .or_else(|| info_subitems.get(pos).copied());
                        let comment = sub
                            .child_text("Comment")
                            .or_else(|| {
                                info_match.and_then(|isi| {
                                    isi.children.iter().find_map(|n| {
                                        if let crate::xml_dom::DomNode::Comment(c) = n {
                                            Some(c.clone())
                                        } else {
                                            None
                                        }
                                    })
                                })
                            })
                            .unwrap_or_default();
                        let def_data = info_match
                            .and_then(|isi| {
                                extract_esi_info_default(isi.child("Info"), dt_id, final_bits)
                            })
                            .unwrap_or_default();
                        obj.entries.push(EntryInfo {
                            sub_index: sub_idx,
                            name: sub_name,
                            data_type_id: dt_id,
                            bit_length: final_bits,
                            bit_offset: sub_offs,
                            flags,
                            default_data: def_data,
                            description: comment,
                            category: sub_cat,
                            ..Default::default()
                        });
                    }
                    od.insert(obj);
                    continue;
                }
            }

            // Simple `VAR` `<Object>`
            let (dt_id, resolved_bits) =
                resolve_esi_type_name(&type_name, &dt_map).unwrap_or((5, bit_size));
            let final_bits = if bit_size > 0 {
                bit_size
            } else {
                resolved_bits
            };
            let flags = parse_esi_flags_element(obj_el.child("Flags"));
            let def_data = extract_esi_info_default(obj_el.child("Info"), dt_id, final_bits)
                .unwrap_or_default();
            let mut obj = ObjectInfo::new(index, obj_name.clone(), ObjectCode::Variable);
            obj.category = cat;
            obj.depend_on_slot = depend_on_slot;
            obj.depend_on_slot_group = depend_on_slot_group;
            if let Some(rd) = obj_el.child_text("CoeRead") {
                obj.coe_read_callback = rd.trim().to_string();
            }
            if let Some(wr) = obj_el.child_text("CoeWrite") {
                obj.coe_write_callback = wr.trim().to_string();
            }
            obj.entries.push(EntryInfo {
                sub_index: 0,
                name: obj_name,
                data_type_id: dt_id,
                bit_length: final_bits,
                bit_offset: 0,
                flags,
                default_data: def_data,
                ..Default::default()
            });
            od.insert(obj);
        }
    }

    Ok(od)
}

fn resolve_esi_type_name(
    type_name: &str,
    dt_map: &BTreeMap<String, DomElement>,
) -> Result<(u16, i32)> {
    let trimmed = type_name.trim();
    if let Ok(pair) = resolve_data_type_name(trimmed) {
        return Ok(pair);
    }
    if let Some(stripped) = trimmed.strip_prefix("DT") {
        if let Ok(idx) = u16::from_str_radix(stripped, 16) {
            if (0x0800..=0x0FFF).contains(&idx) {
                let bits = dt_map
                    .get(trimmed)
                    .and_then(|d| d.child_text("BitSize"))
                    .and_then(|s| s.trim().parse::<i32>().ok())
                    .unwrap_or(8);
                return Ok((idx, bits));
            }
        }
    }
    if let Some(dt_el) = dt_map.get(trimmed) {
        let bits = dt_el
            .child_text("BitSize")
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(8);
        if let Some(base) = dt_el.child_text("BaseType") {
            if let Ok((base_id, _)) = resolve_data_type_name(&base) {
                return Ok((base_id, bits));
            }
        }
        return Ok((10, bits));
    }
    Err(CliError::SscInvalidData(format!(
        "Unrecognized ESI type '{trimmed}'"
    )))
}

fn parse_esi_flags_element(flags_el: Option<&DomElement>) -> EntryFlags {
    let Some(f) = flags_el else {
        return EntryFlags::RO;
    };
    let acc_el = f.child("Access");
    let acc_txt = acc_el
        .map(|a| a.inner_text())
        .unwrap_or_else(|| "ro".to_string());
    let r_restr = acc_el.and_then(|a| a.attr("ReadRestrictions"));
    let w_restr = acc_el.and_then(|a| a.attr("WriteRestrictions"));
    let pdo_mapping = f
        .child_text("PdoMapping")
        .as_deref()
        .map(PdoMappingMode::parse_str)
        .unwrap_or(PdoMappingMode::None);
    let backup = f
        .child_text("Backup")
        .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let setting = f
        .child_text("Setting")
        .map(|v| v.trim() == "1" || v.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    EntryFlags {
        access: AccessFlags::parse_str(&acc_txt, r_restr, w_restr),
        pdo_mapping,
        backup,
        setting,
    }
}

fn extract_esi_info_default(
    info_el: Option<&DomElement>,
    dt_id: u16,
    bit_len: i32,
) -> Option<String> {
    let inf = info_el?;
    if let Some(dd) = inf.child_text("DefaultData") {
        return Some(dd.trim().to_string());
    }
    if let Some(ds) = inf.child_text("DefaultString") {
        let mut hex = String::with_capacity(ds.len() * 2);
        for b in ds.as_bytes() {
            hex.push_str(&format!("{b:02X}"));
        }
        return Some(reverse_hex_byte_pairs(&hex));
    }
    if let Some(dv) = inf.child_text("DefaultValue") {
        let trimmed = dv.trim();
        if trimmed.is_empty() {
            return None;
        }
        let effective_bits = if bit_len > 0 {
            bit_len
        } else {
            get_data_type(dt_id)
                .map(|d| d.bit_length)
                .unwrap_or(8)
                .max(8)
        };
        let normalized = if dt_id != 9 {
            if let Some(hx) = trimmed
                .strip_prefix("#x")
                .or_else(|| trimmed.strip_prefix("#X"))
            {
                format!("0x{hx}")
            } else {
                trimmed.to_string()
            }
        } else {
            trimmed.to_string()
        };
        if let Ok(encoded) = convert_table_value_to_default_data(dt_id, effective_bits, &normalized)
        {
            if !encoded.is_empty() {
                return Some(encoded);
            }
        }
    }
    None
}

/// Parse CANopen / EtherCAT `.eds` INI-style Electronic Data Sheet into `SlaveApplication`.
fn parse_eds_application(path: &Path) -> Result<SlaveApplication> {
    let bytes = fs::read(path)?;
    let text = bytes_to_text(&bytes);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Application")
        .to_string();

    let mut sections: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current_sec = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current_sec = line[1..line.len() - 1].trim().to_string();
            sections.entry(current_sec.clone()).or_default();
        } else if let Some((k, v)) = line.split_once('=') {
            sections
                .entry(current_sec.clone())
                .or_default()
                .insert(k.trim().to_string(), v.trim().to_string());
        }
    }

    let prod_name = sections
        .get("DeviceInfo")
        .and_then(|m| m.get("ProductName"))
        .cloned()
        .unwrap_or(stem);
    let mut app = SlaveApplication::new(&prod_name);
    app.application_file_name = sanitize_file_name_keep_spaces(&prod_name);

    // Collect `[XXXX]` object sections and `[XXXXsubY]` subindex sections
    let mut obj_indices = Vec::new();
    for sec_name in sections.keys() {
        if sec_name.len() == 4 && sec_name.chars().all(|c| c.is_ascii_hexdigit()) {
            if let Ok(idx) = u16::from_str_radix(sec_name, 16) {
                obj_indices.push((idx, sec_name.clone()));
            }
        }
    }
    obj_indices.sort_by_key(|(idx, _)| *idx);

    for (idx, sec_name) in obj_indices {
        let props = &sections[&sec_name];
        let param_name = props
            .get("ParameterName")
            .cloned()
            .unwrap_or_else(|| format!("Object 0x{idx:04X}"));
        let obj_type_num = props
            .get("ObjectType")
            .and_then(|v| parse_u16_any(v))
            .unwrap_or(7);
        let obj_code = match obj_type_num {
            8 => ObjectCode::Array,
            9 => ObjectCode::Record,
            _ => ObjectCode::Variable,
        };
        let mut obj = ObjectInfo::new(idx, &param_name, obj_code);

        if obj_code == ObjectCode::Variable {
            let dt_id = props
                .get("DataType")
                .and_then(|v| parse_u16_any(v))
                .unwrap_or(6);
            let dt_bits = crate::od::types::get_data_type(dt_id)
                .map(|d| d.bit_length.max(8))
                .unwrap_or(16);
            let acc_str = props.get("AccessType").map(|s| s.as_str()).unwrap_or("ro");
            let pdo_map = props
                .get("PDOMapping")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false);
            let pdo_mode = if pdo_map {
                if acc_str.to_ascii_lowercase().contains('w') {
                    PdoMappingMode::RxOrTx
                } else {
                    PdoMappingMode::Tx
                }
            } else {
                PdoMappingMode::None
            };
            let def_str = props.get("DefaultValue").map(|s| s.as_str()).unwrap_or("");
            let default_data =
                convert_table_value_to_default_data(dt_id, dt_bits, def_str).unwrap_or_default();
            obj.entries.push(EntryInfo {
                sub_index: 0,
                name: param_name,
                data_type_id: dt_id,
                bit_length: dt_bits,
                flags: EntryFlags {
                    access: AccessFlags::parse_str(acc_str, None, None),
                    pdo_mapping: pdo_mode,
                    backup: false,
                    setting: false,
                },
                default_data,
                ..Default::default()
            });
        } else {
            for sub in 0u8..=255u8 {
                let sub_key_lower = format!("{sec_name}sub{sub:x}");
                let sub_key_upper = format!("{sec_name}sub{sub:X}");
                let sub_key_dec = format!("{sec_name}sub{sub}");
                let Some(sub_props) = sections
                    .get(&sub_key_lower)
                    .or_else(|| sections.get(&sub_key_upper))
                    .or_else(|| sections.get(&sub_key_dec))
                else {
                    continue;
                };
                let s_name = sub_props
                    .get("ParameterName")
                    .cloned()
                    .unwrap_or_else(|| format!("SubIndex {sub:03}"));
                let dt_id = sub_props
                    .get("DataType")
                    .and_then(|v| parse_u16_any(v))
                    .unwrap_or(6);
                let dt_bits = crate::od::types::get_data_type(dt_id)
                    .map(|d| d.bit_length.max(8))
                    .unwrap_or(16);
                let acc_str = sub_props
                    .get("AccessType")
                    .map(|s| s.as_str())
                    .unwrap_or("ro");
                let pdo_map = sub_props
                    .get("PDOMapping")
                    .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let pdo_mode = if pdo_map {
                    if acc_str.to_ascii_lowercase().contains('w') {
                        PdoMappingMode::Rx
                    } else {
                        PdoMappingMode::Tx
                    }
                } else {
                    PdoMappingMode::None
                };
                let def_str = sub_props
                    .get("DefaultValue")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let default_data = convert_table_value_to_default_data(dt_id, dt_bits, def_str)
                    .unwrap_or_default();
                obj.entries.push(EntryInfo {
                    sub_index: sub,
                    name: s_name,
                    data_type_id: dt_id,
                    bit_length: dt_bits,
                    flags: EntryFlags {
                        access: AccessFlags::parse_str(acc_str, None, None),
                        pdo_mapping: pdo_mode,
                        backup: false,
                        setting: false,
                    },
                    default_data,
                    ..Default::default()
                });
            }
        }
        app.od.insert(obj);
    }

    Ok(app)
}

/// Parse TwinCAT `.tmc` (`<TcModuleClass>`) XML into `SlaveApplication`.
fn parse_tmc_application(path: &Path) -> Result<SlaveApplication> {
    let root = parse_dom_file(path, false)?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Application")
        .to_string();
    let mod_el = root.child("Modules").and_then(|m| m.child("Module"));
    let app_name = mod_el
        .and_then(|m| m.child_text("Name"))
        .unwrap_or_else(|| stem.clone());
    let mut app = SlaveApplication::new(&app_name);
    app.application_file_name = sanitize_file_name_keep_spaces(&app_name);

    if let Some(areas_el) = mod_el.and_then(|m| m.child("DataAreas")) {
        let mut next_tx = 0x6000u16;
        let mut next_rx = 0x7000u16;
        let mut next_cfg = 0x8000u16;
        for area in areas_el.children_named("DataArea") {
            let area_type = area
                .child("AreaNo")
                .and_then(|a| a.attr("AreaType"))
                .unwrap_or("");
            let area_name = area
                .child_text("Name")
                .unwrap_or_else(|| "DataArea".to_string());
            let (obj_idx, flags) = match area_type {
                "InputDst" => {
                    let i = next_tx;
                    next_tx += 0x10;
                    (
                        i,
                        EntryFlags {
                            access: AccessFlags::RO,
                            pdo_mapping: PdoMappingMode::Tx,
                            backup: false,
                            setting: false,
                        },
                    )
                }
                "OutputSrc" => {
                    let i = next_rx;
                    next_rx += 0x10;
                    (
                        i,
                        EntryFlags {
                            access: AccessFlags::RW,
                            pdo_mapping: PdoMappingMode::Rx,
                            backup: false,
                            setting: false,
                        },
                    )
                }
                _ => {
                    let i = next_cfg;
                    next_cfg += 0x10;
                    (
                        i,
                        EntryFlags {
                            access: AccessFlags::RW,
                            pdo_mapping: PdoMappingMode::None,
                            backup: false,
                            setting: true,
                        },
                    )
                }
            };
            let symbols: Vec<&DomElement> = area.children_named("Symbol").collect();
            if symbols.is_empty() {
                continue;
            }
            let mut obj = ObjectInfo::new(obj_idx, area_name, ObjectCode::Record);
            for (si_idx, sym) in symbols.iter().enumerate() {
                let s_name = sym.child_text("Name").unwrap_or_default();
                let s_type = sym
                    .child_text("BaseType")
                    .unwrap_or_else(|| "UINT".to_string());
                let s_bits = sym
                    .child_text("BitSize")
                    .and_then(|v| v.trim().parse::<i32>().ok())
                    .unwrap_or(16);
                let (dt_id, dt_bits) = resolve_data_type_name(&s_type).unwrap_or((6, s_bits));
                obj.entries.push(EntryInfo {
                    sub_index: (si_idx + 1) as u8,
                    name: s_name,
                    data_type_id: dt_id,
                    bit_length: if s_bits > 0 { s_bits } else { dt_bits },
                    flags,
                    ..Default::default()
                });
            }
            app.od.insert(obj);
        }
    }

    Ok(app)
}

fn csv_escape_cell(cell: &str) -> String {
    if cell.contains(';') || cell.contains('"') || cell.contains('\r') || cell.contains('\n') {
        format!("\"{}\"", cell.replace('"', "\"\""))
    } else {
        cell.to_string()
    }
}

fn format_csv_row(cells: &[&str]) -> String {
    cells
        .iter()
        .map(|c| csv_escape_cell(c))
        .collect::<Vec<_>>()
        .join(";")
}

fn format_object_code_csv(code: ObjectCode) -> &'static str {
    match code {
        ObjectCode::Domain => "DOMAIN",
        ObjectCode::Deftype => "DEFTYPE",
        ObjectCode::Defstruct => "DEFSTRUCT",
        ObjectCode::Variable => "VAR",
        ObjectCode::Array => "ARRAY",
        ObjectCode::Record => "RECORD",
        ObjectCode::None => "",
    }
}

fn format_category_csv(cat: ObjectCategory) -> &'static str {
    match cat {
        ObjectCategory::Mandatory => "m",
        ObjectCategory::Optional => "o",
        ObjectCategory::Conditional => "c",
    }
}

fn format_bs_csv(flags: EntryFlags) -> &'static str {
    match (flags.backup, flags.setting) {
        (true, true) => "bs",
        (true, false) => "b",
        (false, true) => "s",
        (false, false) => "",
    }
}

fn format_access_csv(acc: AccessFlags) -> &'static str {
    if acc == AccessFlags::RW {
        "rw"
    } else if acc == AccessFlags::RO {
        "ro"
    } else if acc == AccessFlags::WO {
        "wo"
    } else if acc == AccessFlags::RW_PREOP_RO_OTHER {
        "rw-p"
    } else if acc.all_read() && !acc.write_preop && acc.write_safeop && !acc.write_op {
        "rw-s"
    } else if acc.all_read() && !acc.write_preop && !acc.write_safeop && acc.write_op {
        "rw-o"
    } else if acc.all_read() && acc.write_preop && acc.write_safeop && !acc.write_op {
        "rwps"
    } else if acc.all_read() && acc.write_preop && !acc.write_safeop && acc.write_op {
        "rwpo"
    } else if acc.all_read() && !acc.write_preop && acc.write_safeop && acc.write_op {
        "rwso"
    } else if acc.any_write() && acc.any_read() {
        "rw"
    } else if acc.any_write() {
        "wo"
    } else {
        "ro"
    }
}

fn format_pdo_csv(mode: PdoMappingMode) -> &'static str {
    match mode {
        PdoMappingMode::None => "",
        PdoMappingMode::Rx => "rx",
        PdoMappingMode::Tx => "tx",
        PdoMappingMode::RxOrTx => "rxtx",
        PdoMappingMode::TxAndRx => "txrx",
    }
}

fn format_entry_type_csv(entry: &EntryInfo) -> String {
    if entry.data_type_id == 0 {
        if entry.bit_length > 0 {
            return format!("pad_{}", entry.bit_length);
        }
        return String::new();
    }
    let esi = create_esi_syntax_for_entry(entry);
    if !esi.is_empty() {
        return esi;
    }
    get_data_type(entry.data_type_id)
        .map(|dt| dt.coe_name.to_string())
        .unwrap_or_default()
}

fn format_hex_data_to_table_value(
    data_type_id: u16,
    hex_data: &str,
    enum_val: Option<i32>,
    is_enum_sub: bool,
) -> String {
    if is_enum_sub {
        if let Some(ev) = enum_val {
            return if ev < 0 {
                ev.to_string()
            } else {
                format!("0x{ev:X}")
            };
        }
    }
    let trimmed = hex_data.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if data_type_id == 1 {
        return if trimmed == "00" || trimmed == "0" {
            "0".to_string()
        } else {
            "1".to_string()
        };
    }
    let forward = reverse_hex_byte_pairs(trimmed);
    if forward.is_empty() {
        return String::new();
    }
    if data_type_id == 9 {
        let mut decoded = Vec::with_capacity(forward.len() / 2);
        let mut valid_hex = true;
        for chunk in forward.as_bytes().chunks(2) {
            if let Ok(s) = std::str::from_utf8(chunk) {
                if let Ok(b) = u8::from_str_radix(s, 16) {
                    decoded.push(b);
                    continue;
                }
            }
            valid_hex = false;
            break;
        }
        if valid_hex && !decoded.is_empty() {
            let printable = decoded.iter().all(|&b| (0x20..=0x7E).contains(&b))
                && decoded.first() != Some(&b' ')
                && decoded.last() != Some(&b' ');
            if printable {
                if let Ok(txt) = std::str::from_utf8(&decoded) {
                    if !txt.starts_with("0x") && !txt.starts_with("0X") {
                        return txt.to_string();
                    }
                }
            }
        }
    }
    format!("0x{forward}")
}

/// Export an `ObjectInfoCollection` back into a semicolon-delimited `.csv` Object Dictionary table
/// compatible with `RawTableParser` / `SSC OD Tool` / `SSC Tool` (`OD_Tool` / GUI export parity).
pub fn export_od_to_csv(od: &ObjectInfoCollection) -> String {
    let has_extended_cols = od.objects.values().any(|obj| {
        obj.entries
            .iter()
            .any(|e| e.unit.is_some() || !e.min_data.is_empty() || !e.max_data.is_empty())
    });

    let mut lines: Vec<String> = Vec::new();
    let dp_str = od.device_profile.to_string();
    let mp_str = od.module_profile.to_string();
    let inc_str = if od.index_increment == 0 {
        "0".to_string()
    } else {
        format!("0x{:X}", od.index_increment)
    };
    let pinc_str = if od.pdo_index_increment == 0 {
        "0".to_string()
    } else {
        format!("0x{:X}", od.pdo_index_increment)
    };

    lines.push(format_csv_row(&[
        "Device Profile:",
        &dp_str,
        &od.name,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]));
    lines.push(format_csv_row(&[
        "Modul Profile:",
        &mp_str,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]));
    lines.push(format_csv_row(&[
        "IndexIncrement",
        &inc_str,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]));
    lines.push(format_csv_row(&[
        "PdoIndexIncrement:",
        &pinc_str,
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
        "",
    ]));
    lines.push(String::new());

    if has_extended_cols {
        lines.push(
            "Index;ObjectCode;SI;DataType;Name;Unit;Default Value;Min Value;Max Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description"
                .to_string(),
        );
    } else {
        lines.push(
            "Index;ObjectCode;SI;DataType;Name;Default Value;M/O/C;B/S;Access;rx/tx;CoeRead;CoeWrite;Description"
                .to_string(),
        );
    }

    for obj in od.objects.values() {
        let idx_str = format!("0x{:04X}", obj.index);
        let code_str = format_object_code_csv(obj.object_code);
        let moc_str = format_category_csv(obj.category);
        let is_enum = obj.is_enum_object();

        if obj.object_code == ObjectCode::Variable {
            let e0 = obj.entry(0);
            let dt_str = e0.map(format_entry_type_csv).unwrap_or_default();
            let def_str = e0
                .map(|e| {
                    format_hex_data_to_table_value(
                        e.data_type_id,
                        &e.default_data,
                        e.enum_value,
                        false,
                    )
                })
                .unwrap_or_default();
            let unit_str = e0
                .and_then(|e| e.unit)
                .map(|u| format!("0x{u:X}"))
                .unwrap_or_default();
            let min_str = e0
                .map(|e| format_hex_data_to_table_value(e.data_type_id, &e.min_data, None, false))
                .unwrap_or_default();
            let max_str = e0
                .map(|e| format_hex_data_to_table_value(e.data_type_id, &e.max_data, None, false))
                .unwrap_or_default();
            let bs_str = e0.map(|e| format_bs_csv(e.flags)).unwrap_or("");
            let acc_str = e0
                .map(|e| format_access_csv(e.flags.access))
                .unwrap_or("ro");
            let pdo_str = e0
                .map(|e| format_pdo_csv(e.flags.pdo_mapping))
                .unwrap_or("");
            let cread = e0
                .filter(|e| !e.coe_read_callback.is_empty())
                .map(|e| e.coe_read_callback.as_str())
                .unwrap_or(&obj.coe_read_callback);
            let cwrite = e0
                .filter(|e| !e.coe_write_callback.is_empty())
                .map(|e| e.coe_write_callback.as_str())
                .unwrap_or(&obj.coe_write_callback);
            let desc = e0
                .filter(|e| !e.description.is_empty())
                .map(|e| e.description.as_str())
                .unwrap_or(&obj.description);

            if has_extended_cols {
                lines.push(format_csv_row(&[
                    &idx_str, code_str, "", &dt_str, &obj.name, &unit_str, &def_str, &min_str,
                    &max_str, moc_str, bs_str, acc_str, pdo_str, cread, cwrite, desc,
                ]));
            } else {
                lines.push(format_csv_row(&[
                    &idx_str, code_str, "", &dt_str, &obj.name, &def_str, moc_str, bs_str, acc_str,
                    pdo_str, cread, cwrite, desc,
                ]));
            }
            continue;
        }

        // ARRAY / RECORD / ENUM header row
        let si0 = obj.entry(0);
        let synthetic_si0 = si0.is_some_and(|e| e.name == "SubIndex 000" || is_enum);
        let (hdr_bs, hdr_acc) = if synthetic_si0 {
            if let Some(e0) = si0 {
                let bs = format_bs_csv(e0.flags);
                let acc = if e0.flags.access != AccessFlags::RO {
                    format_access_csv(e0.flags.access)
                } else {
                    ""
                };
                (bs, acc)
            } else {
                ("", "")
            }
        } else {
            ("", "")
        };

        if has_extended_cols {
            lines.push(format_csv_row(&[
                &idx_str,
                code_str,
                "",
                "",
                &obj.name,
                "",
                "",
                "",
                "",
                moc_str,
                hdr_bs,
                hdr_acc,
                "",
                &obj.coe_read_callback,
                &obj.coe_write_callback,
                &obj.description,
            ]));
        } else {
            lines.push(format_csv_row(&[
                &idx_str,
                code_str,
                "",
                "",
                &obj.name,
                "",
                moc_str,
                hdr_bs,
                hdr_acc,
                "",
                &obj.coe_read_callback,
                &obj.coe_write_callback,
                &obj.description,
            ]));
        }

        for entry in &obj.entries {
            if entry.sub_index == 0 && synthetic_si0 {
                continue;
            }
            let si_str = entry.sub_index.to_string();
            let dt_str = format_entry_type_csv(entry);
            let def_str = format_hex_data_to_table_value(
                entry.data_type_id,
                &entry.default_data,
                entry.enum_value,
                is_enum && entry.sub_index > 0,
            );
            let unit_str = entry.unit.map(|u| format!("0x{u:X}")).unwrap_or_default();
            let min_str =
                format_hex_data_to_table_value(entry.data_type_id, &entry.min_data, None, false);
            let max_str =
                format_hex_data_to_table_value(entry.data_type_id, &entry.max_data, None, false);
            let e_moc = entry.category.map(format_category_csv).unwrap_or("");
            let e_bs = format_bs_csv(entry.flags);
            let e_acc = format_access_csv(entry.flags.access);
            let e_pdo = format_pdo_csv(entry.flags.pdo_mapping);

            if has_extended_cols {
                lines.push(format_csv_row(&[
                    "",
                    "",
                    &si_str,
                    &dt_str,
                    &entry.name,
                    &unit_str,
                    &def_str,
                    &min_str,
                    &max_str,
                    e_moc,
                    e_bs,
                    e_acc,
                    e_pdo,
                    &entry.coe_read_callback,
                    &entry.coe_write_callback,
                    &entry.description,
                ]));
            } else {
                lines.push(format_csv_row(&[
                    "",
                    "",
                    &si_str,
                    &dt_str,
                    &entry.name,
                    &def_str,
                    e_moc,
                    e_bs,
                    e_acc,
                    e_pdo,
                    &entry.coe_read_callback,
                    &entry.coe_write_callback,
                    &entry.description,
                ]));
            }
        }
    }

    let mut out = lines.join("\r\n");
    out.push_str("\r\n");
    out
}

/// Write an `ObjectInfoCollection` to disk as a `.csv` Object Dictionary file.
pub fn write_od_to_csv(od: &ObjectInfoCollection, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let csv_text = export_od_to_csv(od);
    fs::write(path, csv_text.as_bytes())?;
    Ok(())
}
