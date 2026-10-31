pub mod builtin_ods;
pub mod c_codegen;
pub mod parsers;
pub mod types;

use std::fs;
use std::path::{Path, PathBuf};

use crate::codegen::split_text_lines;
use crate::model::{FileFlags, SlaveFile, SlaveFileContent, SlaveFileType};
use ethercat_wire::error::Result;

pub use c_codegen::{
    render_application_c, render_application_h, render_module_objects_header,
    render_objects_header, to_upper_snake_macro_ident,
};
pub use parsers::{
    parse_application_files, parse_single_application_file_with_sheet, write_csv_template,
    write_xlsx_template,
};
pub use types::SlaveApplication;

/// Build the `SlaveFile` entries (`<App>.c`, `<App>.h`, `<App>Objects.h`, and optional
/// `Module0x{Ident:08X}_Objects.h`) attached to a `SlaveProject` when importing an application.
pub fn build_application_slave_files(app: &SlaveApplication) -> Vec<SlaveFile> {
    let app_name = if app.name.is_empty() {
        "MyAppl"
    } else {
        app.name.as_str()
    };
    let file_stem = if app.application_file_name.is_empty() {
        app_name
    } else {
        app.application_file_name.as_str()
    };
    let upper = to_upper_snake_macro_ident(app_name);
    let guard_macro = format!("_{upper}_");
    let obj_guard_macro = format!("_{upper}_OBJECTS_H_");
    let file_stem_objects = format!("{file_stem}Objects");

    let mut module_header_names = Vec::with_capacity(app.modules.len());
    for m in &app.modules {
        module_header_names.push(format!("Module0x{:08X}_Objects.h", m.module_ident));
    }

    let c_text = render_application_c(&app.od, app_name, file_stem, true);
    let h_text = render_application_h(app_name, file_stem, &module_header_names);
    let obj_h_text = render_objects_header(
        &app.od,
        app_name,
        &file_stem_objects,
        &guard_macro,
        &obj_guard_macro,
        "ApplicationObjDic",
        true,
    );

    let mut files = Vec::with_capacity(3 + app.modules.len());
    files.push(SlaveFile {
        name: format!("{file_stem}.c"),
        file_type: SlaveFileType::Source,
        version: "0.0.0.1".to_string(),
        expression: String::new(),
        flags: FileFlags {
            user_file: true,
            hw_file: false,
            appl_file: true,
        },
        content: SlaveFileContent::TextLines(split_text_lines(&c_text)),
    });
    files.push(SlaveFile {
        name: format!("{file_stem}.h"),
        file_type: SlaveFileType::Header,
        version: "1.0.0.11".to_string(),
        expression: String::new(),
        flags: FileFlags {
            user_file: true,
            hw_file: false,
            appl_file: true,
        },
        content: SlaveFileContent::TextLines(split_text_lines(&h_text)),
    });
    files.push(SlaveFile {
        name: format!("{file_stem}Objects.h"),
        file_type: SlaveFileType::Header,
        version: String::new(),
        expression: String::new(),
        flags: FileFlags {
            user_file: false,
            hw_file: false,
            appl_file: true,
        },
        content: SlaveFileContent::TextLines(split_text_lines(&obj_h_text)),
    });

    for m in &app.modules {
        let mod_text = render_module_objects_header(m, app_name, true);
        files.push(SlaveFile {
            name: format!("Module0x{:08X}_Objects.h", m.module_ident),
            file_type: SlaveFileType::Header,
            version: String::new(),
            expression: String::new(),
            flags: FileFlags {
                user_file: false,
                hw_file: false,
                appl_file: true,
            },
            content: SlaveFileContent::TextLines(split_text_lines(&mod_text)),
        });
    }

    files
}

#[derive(Debug, Clone)]
pub struct StandaloneOdCFilesOutcome {
    pub objects_header: PathBuf,
    pub objects_header_backup: Option<PathBuf>,
    pub app_header: Option<PathBuf>,
    pub app_source: Option<PathBuf>,
    pub skipped_existing_app_files: bool,
    pub module_headers: Vec<PathBuf>,
}

/// Generate standalone `SSC OD Tool` C source & header files into `src_out_dir`.
///
/// Mirrors `CreateSscApplication::CreateApplication`:
/// - Always writes `<App>Objects.h` (backing up to `<App>Objects.h.bak` if it already exists).
/// - Writes `<App>.c` and `<App>.h` if NO `{file_stem}.*` file exists yet (excluding `{file_stem}Objects.h*`)
///   or if `overwrite_user_files == true` (backing up `.bak` when overwritten).
pub fn write_standalone_od_c_files(
    app: &SlaveApplication,
    src_out_dir: &Path,
    overwrite_user_files: bool,
) -> Result<StandaloneOdCFilesOutcome> {
    fs::create_dir_all(src_out_dir)?;

    let app_name = if app.name.is_empty() {
        "MyAppl"
    } else {
        app.name.as_str()
    };
    let file_stem = if app.application_file_name.is_empty() {
        app_name
    } else {
        app.application_file_name.as_str()
    };
    let upper = to_upper_snake_macro_ident(app_name);
    let guard_macro = format!("_{upper}_");
    let obj_guard_macro = format!("_{upper}_OBJECTS_H_");
    let file_stem_objects = format!("{file_stem}Objects");

    let mut module_header_names = Vec::with_capacity(app.modules.len());
    for m in &app.modules {
        module_header_names.push(format!("Module0x{:08X}_Objects.h", m.module_ident));
    }

    // Check BEFORE writing `<App>Objects.h` whether `{file_stem}.*` already exists (`SSC OD Tool` Directory.GetFiles($"{Name}.*"))
    let h_path = src_out_dir.join(format!("{file_stem}.h"));
    let c_path = src_out_dir.join(format!("{file_stem}.c"));
    let existing_user_files = h_path.is_file() || c_path.is_file();

    // 1. `<App>Objects.h`
    let obj_h_path = src_out_dir.join(format!("{file_stem}Objects.h"));
    let objects_header_backup = if obj_h_path.is_file() {
        let bak_path = src_out_dir.join(format!("{file_stem}Objects.h.bak"));
        fs::copy(&obj_h_path, &bak_path)?;
        Some(bak_path)
    } else {
        None
    };
    let obj_h_text = render_objects_header(
        &app.od,
        app_name,
        &file_stem_objects,
        &guard_macro,
        &obj_guard_macro,
        "ApplicationObjDic",
        false,
    );
    fs::write(&obj_h_path, obj_h_text.as_bytes())?;

    // 2. Module headers (if any)
    let mut module_headers = Vec::new();
    for m in &app.modules {
        let m_name = format!("Module0x{:08X}_Objects.h", m.module_ident);
        let m_path = src_out_dir.join(&m_name);
        if m_path.is_file() {
            let bak = src_out_dir.join(format!("{m_name}.bak"));
            let _ = fs::copy(&m_path, &bak);
        }
        let m_text = render_module_objects_header(m, app_name, false);
        fs::write(&m_path, m_text.as_bytes())?;
        module_headers.push(m_path);
    }

    // 3 & 4. `<App>.h` & `<App>.c`
    let mut app_header = None;
    let mut app_source = None;
    let skipped_existing_app_files = existing_user_files && !overwrite_user_files;

    if !skipped_existing_app_files {
        if h_path.is_file() {
            let bak = src_out_dir.join(format!("{file_stem}.h.bak"));
            let _ = fs::copy(&h_path, &bak);
        }
        let h_text = render_application_h(app_name, file_stem, &module_header_names);
        fs::write(&h_path, h_text.as_bytes())?;
        app_header = Some(h_path);

        if c_path.is_file() {
            let bak = src_out_dir.join(format!("{file_stem}.c.bak"));
            let _ = fs::copy(&c_path, &bak);
        }
        let c_text = render_application_c(&app.od, app_name, file_stem, false);
        fs::write(&c_path, c_text.as_bytes())?;
        app_source = Some(c_path);
    }

    Ok(StandaloneOdCFilesOutcome {
        objects_header: obj_h_path,
        objects_header_backup,
        app_header,
        app_source,
        skipped_existing_app_files,
        module_headers,
    })
}
