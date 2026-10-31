//! Pure-Rust C source & header generator for SSC applications and Object Dictionaries.
//!
//! Reproduces `ET9300Utilities.ApplicationHandler` (`<App>Objects.h`, `<App>.h`, `<App>.c`
//! for `SSC OD Tool`) and `ET9300ProjectHandler` (`<App>.c` for `SSC Tool`), including
//! module object dictionary headers (`Module0x{Ident:08X}_Objects.h`).

use super::types::{
    get_data_type, reverse_hex_byte_pairs, EntryInfo, ModuleObjectInfoCollection, ObjectCode,
    ObjectInfo, ObjectInfoCollection,
};

/// Convert an application or object name into `UPPER_SNAKE_CASE` macro identifier
/// (e.g. `"RichApp"` -> `"RICH_APP"`, `"DemoWizard"` -> `"DEMO_WIZARD"`,
/// `"Modular Device Profile"` -> `"MODULAR_DEVICE_PROFILE"`).
pub fn to_upper_snake_macro_ident(name: &str) -> String {
    let mut out = String::new();
    let mut need_sep = false;
    let mut prev_lower = false;

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !out.is_empty() {
                need_sep = true;
            }
            prev_lower = false;
            continue;
        }
        if !out.is_empty() {
            if need_sep {
                out.push('_');
                need_sep = false;
            } else if ch.is_ascii_uppercase() && prev_lower {
                out.push('_');
            }
        } else {
            need_sep = false;
        }
        out.push(ch.to_ascii_uppercase());
        prev_lower = ch.is_ascii_lowercase();
    }

    if out.is_empty() {
        "APPLICATION".to_string()
    } else if out.as_bytes()[0].is_ascii_digit() {
        format!("_{out}")
    } else {
        out
    }
}

/// Convert an arbitrary display name into a valid Pascal/camel C identifier
/// preserving internal casing (`"ActuatorOutputs process data mapping"` ->
/// `"ActuatorOutputsProcessDataMapping"`, `"Index distance "` -> `"IndexDistance"`).
pub fn to_c_identifier(name: &str) -> String {
    let mut out = String::new();
    let mut cap_next = false;

    for ch in name.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            if !out.is_empty() {
                cap_next = true;
            }
            continue;
        }
        if cap_next {
            out.push(ch.to_ascii_uppercase());
            cap_next = false;
        } else {
            out.push(ch);
        }
    }

    if out.is_empty() {
        "Unnamed".to_string()
    } else if out.as_bytes()[0].is_ascii_digit() {
        format!("_{out}")
    } else {
        out
    }
}

fn is_pdo_mapping_index(index: u16) -> bool {
    (0x1600..=0x17FF).contains(&index) || (0x1A00..=0x1BFF).contains(&index)
}

fn needs_outer_coe_guard(index: u16) -> bool {
    (0x1000..=0x1FFF).contains(&index) || index >= 0xF000
}

fn needs_inner_coe_guard(index: u16) -> bool {
    index >= 0x2000
}

fn is_bit_entry(entry: &EntryInfo) -> bool {
    matches!(entry.data_type_id, 1 | 48..=55) || (entry.bit_length > 0 && entry.bit_length < 8)
}

fn deftype_macro_for_entry(entry: &EntryInfo) -> String {
    if (0x0800..=0x0FFF).contains(&entry.data_type_id) {
        return format!("0x{:04X}", entry.data_type_id);
    }
    if let Some(dt) = get_data_type(entry.data_type_id) {
        if !dt.ssc_entry_info_syntax.is_empty() {
            return dt.ssc_entry_info_syntax.to_string();
        }
    }
    "DEFTYPE_NULL".to_string()
}

fn c_struct_field_decl(entry: &EntryInfo, field_ident: &str) -> String {
    let dt_id = entry.data_type_id;
    let bits = entry.bit_length.max(0) as u32;
    if (0x0800..=0x0FFF).contains(&dt_id) {
        let int_ty = match bits {
            0..=8 => "INT8",
            9..=16 => "INT16",
            _ => "INT32",
        };
        return format!("{int_ty} {field_ident};");
    }
    match dt_id {
        0x0001 => format!("BOOLEAN({field_ident});"),
        0x0030..=0x0037 => {
            let n = dt_id - 0x0030 + 1;
            format!("BIT{n}({field_ident});")
        }
        0x002D => format!("BITARR8 {field_ident};"),
        0x002E => format!("BITARR16 {field_ident};"),
        0x002F => format!("BITARR32 {field_ident};"),
        0x0009 => {
            let len = (bits / 8).max(1);
            format!("CHAR {field_ident}[{len}];")
        }
        0x000A => {
            let len = (bits / 8).max(1);
            format!("UINT8 {field_ident}[{len}];")
        }
        0x000B => {
            let len = (bits / 16).max(1);
            format!("UINT16 {field_ident}[{len}];")
        }
        608 => {
            let len = (bits / 16).max(1);
            format!("INT16 {field_ident}[{len}];")
        }
        609 => {
            let len = (bits / 8).max(1);
            format!("INT8 {field_ident}[{len}];")
        }
        610 => {
            let len = (bits / 32).max(1);
            format!("INT32 {field_ident}[{len}];")
        }
        611 => {
            let len = (bits / 32).max(1);
            format!("UINT32 {field_ident}[{len}];")
        }
        _ => {
            let c_ty = get_data_type(dt_id)
                .map(|d| d.ssc_variable_type)
                .filter(|s| !s.is_empty())
                .unwrap_or("UINT8");
            format!("{c_ty} {field_ident};")
        }
    }
}

fn c_var_decl(entry: &EntryInfo, var_ident: &str) -> (String, bool) {
    let dt_id = entry.data_type_id;
    let bits = entry.bit_length.max(0) as u32;
    match dt_id {
        0x0009 => {
            let len = (bits / 8).max(1);
            (format!("CHAR {var_ident}[{len}]"), true)
        }
        0x000A => {
            let len = (bits / 8).max(1);
            (format!("UINT8 {var_ident}[{len}]"), true)
        }
        0x000B => {
            let len = (bits / 16).max(1);
            (format!("UINT16 {var_ident}[{len}]"), true)
        }
        608 => {
            let len = (bits / 16).max(1);
            (format!("INT16 {var_ident}[{len}]"), true)
        }
        609 => {
            let len = (bits / 8).max(1);
            (format!("INT8 {var_ident}[{len}]"), true)
        }
        610 => {
            let len = (bits / 32).max(1);
            (format!("INT32 {var_ident}[{len}]"), true)
        }
        611 => {
            let len = (bits / 32).max(1);
            (format!("UINT32 {var_ident}[{len}]"), true)
        }
        _ if (0x0800..=0x0FFF).contains(&dt_id) => {
            let int_ty = match bits {
                0..=8 => "INT8",
                9..=16 => "INT16",
                _ => "INT32",
            };
            (format!("{int_ty} {var_ident}"), false)
        }
        _ => {
            let c_ty = get_data_type(dt_id)
                .map(|d| d.ssc_variable_type)
                .filter(|s| !s.is_empty())
                .unwrap_or("UINT32");
            (format!("{c_ty} {var_ident}"), false)
        }
    }
}

fn decode_hex_bytes(hex: &str) -> Vec<u8> {
    let clean = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    let mut hex_bytes: Vec<u8> = clean.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
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

fn format_c_entry_initializer(entry: &EntryInfo) -> String {
    let dt_id = entry.data_type_id;
    let bits = entry.bit_length.max(0) as u32;
    if dt_id == 0x0009 {
        // VISIBLE_STRING: note `convert_table_value_to_default_data` stored byte-reversed ASCII hex
        // OR forward ASCII hex on built-in SSC objects (`0x1008..0x100A`). Wait: check `ModelTag0x2002` in `RichAppObjects.h`!
        // In `RichApp.csv`, `Default Value = ECAT-AI`, `convert_table_value_to_default_data` reversed byte pairs into `"49412D54414345"`,
        // and `RichAppObjects.h` line 409 emitted `= "IA-TACE"` (direct ASCII bytes of `default_data`!)!
        if entry.default_data.is_empty() {
            return "\"\"".to_string();
        }
        let bytes = decode_hex_bytes(&entry.default_data);
        let mut s = String::from("\"");
        for b in bytes {
            if b == 0 {
                break;
            }
            if b == b'"' || b == b'\\' {
                s.push('\\');
                s.push(b as char);
            } else if (0x20..=0x7E).contains(&b) {
                s.push(b as char);
            } else {
                s.push_str(&format!("\\{b:03o}"));
            }
        }
        s.push('"');
        return s;
    }
    if dt_id == 0x000A {
        let len = (bits / 8).max(1) as usize;
        let mut bytes = decode_hex_bytes(&entry.default_data);
        bytes.resize(len, 0);
        let elems: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
        return format!("{{{}}}", elems.join(","));
    }
    if entry.default_data.is_empty() {
        return "0".to_string();
    }
    if dt_id == 0x0008 {
        let bytes = decode_hex_bytes(&entry.default_data);
        if bytes.len() == 4 {
            let val = f32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let mut s = format!("{val}");
            if !s.contains('.') && !s.contains('e') && !s.contains('E') {
                s.push_str(".0");
            }
            return s;
        }
    }
    if dt_id == 0x0011 {
        let bytes = decode_hex_bytes(&entry.default_data);
        if bytes.len() == 8 {
            let val = f64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let mut s = format!("{val}");
            if !s.contains('.') && !s.contains('e') && !s.contains('E') {
                s.push_str(".0");
            }
            return s;
        }
    }

    let be_hex = reverse_hex_byte_pairs(&entry.default_data);
    let hex_digits = match bits {
        0..=8 => 2,
        9..=16 => 4,
        17..=32 => 8,
        _ => 16,
    };
    if be_hex.len() < hex_digits {
        format!("0x{:0>width$}", be_hex, width = hex_digits)
    } else if be_hex.len() > hex_digits {
        let trim_start = be_hex.len() - hex_digits;
        format!("0x{}", &be_hex[trim_start..])
    } else {
        format!("0x{be_hex}")
    }
}

fn pdo_entry_reference_desc(entry: &EntryInfo) -> String {
    if !entry.description.is_empty() {
        return entry.description.clone();
    }
    let be = reverse_hex_byte_pairs(&entry.default_data);
    let raw = u32::from_str_radix(&be, 16).unwrap_or(0);
    let target_idx = ((raw >> 16) & 0xFFFF) as u16;
    let target_sub = ((raw >> 8) & 0xFF) as u8;
    let bit_len = (raw & 0xFF) as u8;
    if target_idx == 0 {
        format!("SubIndex {:03} (Padding {}Bit)", entry.sub_index, bit_len)
    } else {
        format!("Reference to 0x{target_idx:04X}.{target_sub}")
    }
}

fn is_default_subindex_name(name: &str, sub_index: u8) -> bool {
    name.is_empty()
        || name.eq_ignore_ascii_case(&format!("SubIndex {sub_index:03}"))
        || name.eq_ignore_ascii_case(&format!("SubIndex {sub_index}"))
}

fn object_callbacks(obj: &ObjectInfo) -> (String, String) {
    let mut rd = obj.coe_read_callback.clone();
    let mut wr = obj.coe_write_callback.clone();
    if rd.is_empty() {
        if let Some(e) = obj.entries.iter().find(|e| !e.coe_read_callback.is_empty()) {
            rd = e.coe_read_callback.clone();
        }
    }
    if wr.is_empty() {
        if let Some(e) = obj
            .entries
            .iter()
            .find(|e| !e.coe_write_callback.is_empty())
        {
            wr = e.coe_write_callback.clone();
        }
    }
    (rd, wr)
}

fn render_enum_object(out: &mut String, obj: &ObjectInfo) {
    let idx = obj.index;
    let dt_name = obj.name.as_str();

    out.push_str(
        "/******************************************************************************\r\n",
    );
    out.push_str(&format!(
        "*                    Object 0x{idx:04X} : {dt_name}\r\n"
    ));
    out.push_str(
        "******************************************************************************/\r\n",
    );
    out.push_str("/**\r\n");
    out.push_str(&format!(
        "* \\addtogroup 0x{idx:04X} 0x{idx:04X} | {dt_name}\r\n"
    ));
    out.push_str("* @{\r\n");
    out.push_str(&format!("* \\brief Enum 0x{idx:04X} : {dt_name}\r\n"));
    out.push_str("*/\r\n");
    out.push_str("#ifdef _OBJD_\r\n");

    let enum_entries: Vec<&EntryInfo> = if obj.object_code == ObjectCode::Defstruct {
        obj.entries.iter().collect()
    } else {
        let non_si0: Vec<&EntryInfo> = obj.entries.iter().filter(|e| e.sub_index > 0).collect();
        if non_si0.is_empty() {
            obj.entries.iter().collect()
        } else {
            non_si0
        }
    };

    let mut var_names = Vec::with_capacity(enum_entries.len());
    for (pos, e) in enum_entries.iter().enumerate() {
        let val_num = pos + 1;
        let vname = format!("sEnum{idx:04X}_Value{val_num:02}");
        let num_val: u32 = if let Some(ev) = e.enum_value {
            ev as u32
        } else {
            let be = reverse_hex_byte_pairs(&e.default_data);
            u32::from_str_radix(&be, 16).unwrap_or(pos as u32)
        };
        let le_bytes = num_val.to_le_bytes();
        out.push_str(&format!(
            "CHAR {vname}[] = \"\\{:03o}\\{:03o}\\{:03o}\\{:03o}{}\"; /**< \\brief Value = 0x{:x}, Text = {} */\r\n",
            le_bytes[0], le_bytes[1], le_bytes[2], le_bytes[3], e.name, num_val, e.name
        ));
        var_names.push(vname);
    }

    out.push_str(&format!(
        "CHAR *apEnum{idx:04X}[] = {{ {}}};/**< \\brief List of Enum (0x{idx:04X}) values*/\r\n\r\n",
        var_names.join(", ")
    ));
    out.push_str("/**\r\n* \\brief Entry descriptions\r\n*/\r\n");
    out.push_str(&format!(
        "OBJCONST TSDOINFOENTRYDESC    OBJMEM asEntryDesc0x{idx:04X}[] ={{\r\n"
    ));
    out.push_str("#if MEMORY_UNIT_16BIT\r\n");
    out.push_str("{DEFTYPE_UNSIGNED8, 8, ACCESS_READ | OBJACCESS_NOPDOMAPPING}");
    for (pos, vname) in var_names.iter().enumerate() {
        out.push_str(",\r\n");
        let tail = if pos + 1 == var_names.len() { "};" } else { "" };
        out.push_str(&format!(
            "{{DEFTYPE_OCTETSTRING, (8*SIZEOF({vname}) / 2), ACCESS_READ | OBJACCESS_NOPDOMAPPING}}{tail}"
        ));
    }
    if var_names.is_empty() {
        out.push_str("};");
    }
    out.push_str("\r\n#else\r\n");
    out.push_str("{DEFTYPE_UNSIGNED8, 8, ACCESS_READ | OBJACCESS_NOPDOMAPPING}");
    for (pos, vname) in var_names.iter().enumerate() {
        out.push_str(",\r\n");
        let tail = if pos + 1 == var_names.len() { "};" } else { "" };
        out.push_str(&format!(
            "{{DEFTYPE_OCTETSTRING, 8*SIZEOF({vname}), ACCESS_READ | OBJACCESS_NOPDOMAPPING}}{tail}"
        ));
    }
    if var_names.is_empty() {
        out.push_str("};");
    }
    out.push_str("\r\n#endif //#if MEMORY_UNIT_16BIT\r\n");
    out.push_str("#endif //#ifdef _OBJD_\r\n");
    out.push_str("/** @}*/\r\n\r\n\r\n\r\n");
}

fn object_c_var_name(obj: &ObjectInfo) -> String {
    if let Some(ov) = &obj.variable_name_override {
        if !ov.is_empty() {
            return ov.clone();
        }
    }
    match obj.index {
        0x1C12 => "sRxPDOassign".to_string(),
        0x1C13 => "sTxPDOassign".to_string(),
        idx => format!("{}0x{idx:04X}", to_c_identifier(&obj.name)),
    }
}

/// Render `<App>Objects.h` (or `Module0x{Ident:08X}_Objects.h`) matching
/// `ET9300Utilities.ApplicationHandler` line-for-line.
pub fn render_objects_header(
    od: &ObjectInfoCollection,
    app_name: &str,
    file_stem_objects: &str,
    guard_macro: &str,
    objects_guard_macro: &str,
    dic_array_name: &str,
    ssc_project_mode: bool,
) -> String {
    let mut out = String::with_capacity(8192);
    let group_id = to_c_identifier(app_name);

    out.push_str("/*\r\n");
    out.push_str("* This source file is part of the EtherCAT Slave Stack Code licensed by Beckhoff Automation GmbH & Co KG, 33415 Verl, Germany.\r\n");
    out.push_str(
        "* The corresponding license agreement applies. This hint shall not be removed.\r\n",
    );
    out.push_str("*/\r\n\r\n");
    out.push_str("/**\r\n");
    out.push_str(&format!("* \\addtogroup {group_id} {app_name}\r\n"));
    out.push_str("* @{\r\n");
    out.push_str("*/\r\n\r\n");
    out.push_str("/**\r\n");
    out.push_str(&format!("\\file {file_stem_objects}\r\n"));
    out.push_str("\\author ET9300Utilities.ApplicationHandler (Version 1.6.4.0) | EthercatSSC@beckhoff.com\r\n\r\n");
    out.push_str(&format!("\\brief {app_name} specific objects<br>\r\n"));
    out.push_str("\\brief NOTE : This file will be overwritten if a new object dictionary is generated!<br>\r\n");
    out.push_str("*/\r\n\r\n");
    out.push_str(&format!(
        "#if defined({guard_macro}) && ({guard_macro} == 1)\r\n"
    ));
    out.push_str("#define PROTO\r\n");
    out.push_str("#else\r\n");
    out.push_str("#define PROTO extern\r\n");
    out.push_str("#endif\r\n");

    let mut dic_lines: Vec<String> = Vec::with_capacity(od.objects.len());
    let mut callbacks: Vec<String> = Vec::new();
    let mut seen_callbacks: Vec<String> = Vec::new();

    for obj in od.objects.values() {
        let idx = obj.index;
        if obj.is_enum_object() {
            render_enum_object(&mut out, obj);
            let enum_cnt = if obj.object_code == ObjectCode::Defstruct {
                obj.entries.len()
            } else {
                let non_si0 = obj.entries.iter().filter(|e| e.sub_index > 0).count();
                if non_si0 == 0 {
                    obj.entries.len()
                } else {
                    non_si0
                }
            };
            dic_lines.push(format!(
                "/* Object 0x{idx:04X} */\r\n{{NULL , NULL ,  0x{idx:04X} , {{DEFTYPE_ENUM , {enum_cnt} | (OBJCODE_REC << 8)}}, asEntryDesc0x{idx:04X} , 0 , apEnum{idx:04X} }},"
            ));
            continue;
        }

        let (rd_cb_str, wr_cb_str) = object_callbacks(obj);
        if !rd_cb_str.is_empty() && !seen_callbacks.contains(&rd_cb_str) {
            seen_callbacks.push(rd_cb_str.clone());
            callbacks.push(format!(
                "PROTO UINT8 {rd_cb_str}(UINT16 index, UINT8 subindex, UINT32 dataSize, UINT16 MBXMEM * pData, UINT8 bCompleteAccess);\r\n"
            ));
        }
        if !wr_cb_str.is_empty() && !seen_callbacks.contains(&wr_cb_str) {
            seen_callbacks.push(wr_cb_str.clone());
            callbacks.push(format!(
                "PROTO UINT8 {wr_cb_str}(UINT16 index, UINT8 subindex, UINT32 dataSize, UINT16 MBXMEM * pData, UINT8 bCompleteAccess);\r\n"
            ));
        }

        let outer_coe = needs_outer_coe_guard(idx);
        let inner_coe = needs_inner_coe_guard(idx);
        let var_name = object_c_var_name(obj);
        let read_cb = if rd_cb_str.is_empty() {
            "NULL"
        } else {
            rd_cb_str.as_str()
        };
        let write_cb = if wr_cb_str.is_empty() {
            "NULL"
        } else {
            wr_cb_str.as_str()
        };

        if outer_coe {
            out.push_str("#if COE_SUPPORTED\r\n");
        }
        out.push_str(
            "/******************************************************************************\r\n",
        );
        out.push_str(&format!(
            "*                    Object 0x{idx:04X} : {}\r\n",
            obj.name
        ));
        out.push_str(
            "******************************************************************************/\r\n",
        );
        out.push_str("/**\r\n");
        out.push_str(&format!(
            "* \\addtogroup 0x{idx:04X} 0x{idx:04X} | {}\r\n",
            obj.name
        ));
        out.push_str("* @{\r\n");
        out.push_str(&format!(
            "* \\brief Object 0x{idx:04X} ({}) definition\r\n",
            obj.name
        ));
        out.push_str("*/\r\n");

        match obj.effective_ssc_object_code() {
            ObjectCode::Variable => {
                let fallback_entry = EntryInfo::default();
                let si0 = obj
                    .entry(0)
                    .or_else(|| obj.entries.first())
                    .unwrap_or(&fallback_entry);
                let deftype = deftype_macro_for_entry(si0);
                let access = si0.flags.to_ssc_c_syntax();
                let bits = si0.bit_length.max(0) as u32;
                if inner_coe {
                    out.push_str("#if COE_SUPPORTED\r\n");
                }
                out.push_str("#ifdef _OBJD_\r\n");
                out.push_str("/**\r\n* \\brief Entry description\r\n*/\r\n");
                out.push_str(&format!(
                    "OBJCONST TSDOINFOENTRYDESC    OBJMEM sEntryDesc0x{idx:04X} = {{ {deftype} , 0x{bits:X} , {access} }};\r\n"
                ));
                out.push_str("/**\r\n* \\brief Object name\r\n*/\r\n");
                out.push_str(&format!(
                    "OBJCONST UCHAR OBJMEM aName0x{idx:04X}[] = \"{}\\000\\377\";\r\n",
                    obj.name
                ));
                out.push_str("#endif //#ifdef _OBJD_\r\n");
                if inner_coe {
                    out.push_str("\r\n#endif //#if COE_SUPPORTED\r\n");
                } else {
                    out.push_str("\r\n");
                }

                let (c_decl, is_array_var) = c_var_decl(si0, &var_name);
                let init_val = format_c_entry_initializer(si0);
                out.push_str("/**\r\n* \\brief Object variable\r\n*/\r\n");
                out.push_str(&format!("PROTO {c_decl}\r\n"));
                out.push_str(&format!(
                    "#if defined({guard_macro}) && ({guard_macro} == 1)\r\n"
                ));
                out.push_str(&format!("= {init_val}\r\n"));
                out.push_str("#endif\r\n;\r\n");
                out.push_str("/** @}*/\r\n\r\n\r\n\r\n");

                let var_ptr = if is_array_var {
                    var_name
                } else {
                    format!("&{var_name}")
                };
                dic_lines.push(format!(
                    "/* Object 0x{idx:04X} */\r\n{{NULL , NULL ,  0x{idx:04X} , {{{deftype} , 0 | (OBJCODE_VAR << 8)}} , &sEntryDesc0x{idx:04X} , aName0x{idx:04X} , {var_ptr} , {read_cb} , {write_cb} , 0x0000 }},"
                ));
            }
            ObjectCode::Array => {
                let si0 = obj.entry(0);
                let si0_access = si0
                    .map(|e| e.flags.to_ssc_c_syntax())
                    .unwrap_or_else(|| "ACCESS_READ".to_string());
                let elem_template = obj.entries.iter().find(|e| e.sub_index > 0);
                let elem_deftype =
                    elem_template
                        .map(deftype_macro_for_entry)
                        .unwrap_or_else(|| {
                            if idx == 0x1C12 || idx == 0x1C13 {
                                "DEFTYPE_UNSIGNED16".to_string()
                            } else {
                                "DEFTYPE_UNSIGNED8".to_string()
                            }
                        });
                let elem_bits = elem_template.map(|e| e.bit_length.max(0) as u32).unwrap_or(
                    if idx == 0x1C12 || idx == 0x1C13 {
                        16
                    } else {
                        0
                    },
                );
                let elem_access = elem_template
                    .map(|e| e.flags.to_ssc_c_syntax())
                    .unwrap_or_else(|| "ACCESS_READ".to_string());
                let max_sub = obj.max_sub_index();

                if inner_coe {
                    out.push_str("#if COE_SUPPORTED\r\n");
                }
                out.push_str("#ifdef _OBJD_\r\n");
                out.push_str("/**\r\n");
                out.push_str("* \\brief Entry descriptions<br>\r\n");
                out.push_str("* \r\n");
                out.push_str("* Subindex 0<br>\r\n");
                out.push_str("* Subindex 1 - n (the same entry description is used)<br>\r\n");
                out.push_str("*/\r\n");
                out.push_str(&format!(
                    "OBJCONST TSDOINFOENTRYDESC    OBJMEM asEntryDesc0x{idx:04X}[] = {{\r\n"
                ));
                out.push_str(&format!(
                    "{{ DEFTYPE_UNSIGNED8 , 0x8 , {si0_access} }},\r\n"
                ));
                out.push_str(&format!(
                    "{{ {elem_deftype} , 0x{elem_bits:X} , {elem_access} }}}};\r\n\r\n"
                ));
                out.push_str("/**\r\n");
                out.push_str("* \\brief Object name definition<br>\r\n");
                out.push_str("* For Subindex 1 to n the syntax 'Subindex XXX' is used\r\n");
                out.push_str("*/\r\n");
                out.push_str(&format!(
                    "OBJCONST UCHAR OBJMEM aName0x{idx:04X}[] = \"{}\\000\\377\";\r\n",
                    obj.name
                ));
                out.push_str("#endif //#ifdef _OBJD_\r\n\r\n");
                if inner_coe {
                    out.push_str("#endif //#if COE_SUPPORTED\r\n");
                }

                let elem_c_ty = elem_template
                    .and_then(|e| {
                        get_data_type(e.data_type_id)
                            .map(|d| d.ssc_variable_type)
                            .filter(|s| !s.is_empty())
                    })
                    .unwrap_or(if idx == 0x1C12 || idx == 0x1C13 {
                        "UINT16"
                    } else {
                        "UINT8"
                    });

                out.push_str(&format!("#ifndef {objects_guard_macro}\r\n"));
                out.push_str("/**\r\n* \\brief Object structure\r\n*/\r\n");
                out.push_str("typedef struct OBJ_STRUCT_PACKED_START {\r\n");
                out.push_str("UINT16   u16SubIndex0;  /**< \\brief Subindex 0 */\r\n");
                if max_sub > 0 {
                    out.push_str(&format!(
                        "{elem_c_ty} aEntries[{max_sub}];  /**< \\brief Subindex 1 - {max_sub} */\r\n"
                    ));
                }
                out.push_str(&format!("}} OBJ_STRUCT_PACKED_END\r\nTOBJ{idx:04X};\r\n"));
                out.push_str(&format!("#endif //#ifndef {objects_guard_macro}\r\n\r\n"));

                let si0_count = si0
                    .and_then(|e| {
                        u16::from_str_radix(&reverse_hex_byte_pairs(&e.default_data), 16).ok()
                    })
                    .unwrap_or(max_sub as u16);
                let mut arr_inits = Vec::with_capacity(max_sub as usize);
                for s in 1..=max_sub {
                    if let Some(ent) = obj.entry(s) {
                        arr_inits.push(format_c_entry_initializer(ent));
                    } else {
                        arr_inits.push("0".to_string());
                    }
                }
                let struct_init = if max_sub > 0 {
                    format!("={{{si0_count},{{{}}}}}", arr_inits.join(","))
                } else {
                    format!("={{{si0_count}}}")
                };

                out.push_str("/**\r\n* \\brief Object variable\r\n*/\r\n");
                out.push_str(&format!("PROTO TOBJ{idx:04X} {var_name}\r\n"));
                out.push_str(&format!(
                    "#if defined({guard_macro}) && ({guard_macro} == 1)\r\n"
                ));
                out.push_str(&format!("{struct_init}\r\n"));
                out.push_str("#endif\r\n;\r\n");
                out.push_str("/** @}*/\r\n\r\n\r\n\r\n");

                dic_lines.push(format!(
                    "/* Object 0x{idx:04X} */\r\n{{NULL , NULL ,  0x{idx:04X} , {{{elem_deftype} , {max_sub} | (OBJCODE_ARR << 8)}} , asEntryDesc0x{idx:04X} , aName0x{idx:04X} , &{var_name} , {read_cb} , {write_cb} , 0x0000 }},"
                ));
            }
            ObjectCode::Record
            | ObjectCode::Defstruct
            | ObjectCode::Deftype
            | ObjectCode::Domain
            | ObjectCode::None => {
                let is_pdo = is_pdo_mapping_index(idx);
                let si0 = obj.entry(0);
                let si0_access = si0
                    .map(|e| e.flags.to_ssc_c_syntax())
                    .unwrap_or_else(|| "ACCESS_READ".to_string());
                let sub_entries: Vec<&EntryInfo> =
                    obj.entries.iter().filter(|e| e.sub_index > 0).collect();

                if inner_coe {
                    out.push_str("#if COE_SUPPORTED\r\n");
                }
                out.push_str("#ifdef _OBJD_\r\n");
                out.push_str("/**\r\n");
                out.push_str("* \\brief Object entry descriptions<br>\r\n");
                out.push_str("* <br>\r\n");
                out.push_str("* SubIndex 0<br>\r\n");
                for e in &sub_entries {
                    if is_pdo {
                        let desc = pdo_entry_reference_desc(e);
                        out.push_str(&format!("* SubIndex {} - {desc}<br>\r\n", e.sub_index));
                    } else if is_default_subindex_name(&e.name, e.sub_index) {
                        out.push_str(&format!("* SubIndex {}<br>\r\n", e.sub_index));
                    } else {
                        out.push_str(&format!("* SubIndex {} - {}<br>\r\n", e.sub_index, e.name));
                    }
                }
                out.push_str("*/\r\n");
                out.push_str(&format!(
                    "OBJCONST TSDOINFOENTRYDESC    OBJMEM asEntryDesc0x{idx:04X}[] = {{\r\n"
                ));
                if sub_entries.is_empty() {
                    out.push_str(&format!(
                        "{{ DEFTYPE_UNSIGNED8 , 0x8 , {si0_access} }}}};\r\n\r\n"
                    ));
                } else {
                    out.push_str(&format!(
                        "{{ DEFTYPE_UNSIGNED8 , 0x8 , {si0_access} }},\r\n"
                    ));
                    for (pos, e) in sub_entries.iter().enumerate() {
                        let is_last = pos + 1 == sub_entries.len();
                        let dt = if e.data_type_id == 0 {
                            "DEFTYPE_NULL".to_string()
                        } else {
                            deftype_macro_for_entry(e)
                        };
                        let acc = if e.data_type_id == 0 {
                            "0x0000".to_string()
                        } else {
                            e.flags.to_ssc_c_syntax()
                        };
                        let sep = if is_last { "};" } else { "," };
                        let comment = if is_pdo {
                            format!(
                                " /* Subindex{} - {} */",
                                e.sub_index,
                                pdo_entry_reference_desc(e)
                            )
                        } else if is_default_subindex_name(&e.name, e.sub_index) {
                            format!(" /* Subindex{} */", e.sub_index)
                        } else {
                            format!(" /* Subindex{} - {} */", e.sub_index, e.name)
                        };
                        let bits = e.bit_length.max(0) as u32;
                        out.push_str(&format!(
                            "{{ {dt} , 0x{bits:02X} , {acc} }}{sep}{comment}\r\n"
                        ));
                    }
                    out.push_str("\r\n");
                }

                out.push_str("/**\r\n* \\brief Object/Entry names\r\n*/\r\n");
                if sub_entries.is_empty() {
                    out.push_str(&format!(
                        "OBJCONST UCHAR OBJMEM aName0x{idx:04X}[] = \"{}\\000\\377\";\r\n",
                        obj.name
                    ));
                } else {
                    out.push_str(&format!(
                        "OBJCONST UCHAR OBJMEM aName0x{idx:04X}[] = \"{}\\000\"\r\n",
                        obj.name
                    ));
                    for (pos, e) in sub_entries.iter().enumerate() {
                        let ename = if e.name.is_empty() {
                            if e.data_type_id == 0 {
                                String::new()
                            } else {
                                format!("SubIndex {:03}", e.sub_index)
                            }
                        } else {
                            e.name.clone()
                        };
                        if pos + 1 == sub_entries.len() {
                            out.push_str(&format!("\"{ename}\\000\\377\";\r\n"));
                        } else {
                            out.push_str(&format!("\"{ename}\\000\"\r\n"));
                        }
                    }
                }
                out.push_str("#endif //#ifdef _OBJD_\r\n\r\n");
                if inner_coe {
                    out.push_str("#endif //#if COE_SUPPORTED\r\n");
                }

                out.push_str(&format!("#ifndef {objects_guard_macro}\r\n"));
                out.push_str("/**\r\n* \\brief Object structure\r\n*/\r\n");
                out.push_str("typedef struct OBJ_STRUCT_PACKED_START {\r\n");
                out.push_str("UINT16 u16SubIndex0;\r\n");

                let max_sub = obj.max_sub_index();
                let si0_init = si0
                    .and_then(|e| {
                        u16::from_str_radix(&reverse_hex_byte_pairs(&e.default_data), 16).ok()
                    })
                    .unwrap_or(max_sub as u16);
                let mut field_inits: Vec<String> = vec![si0_init.to_string()];
                let mut cur_bit: u32 = 16;
                let mut used_names: Vec<String> = Vec::new();
                let mut pad_idx: u32 = 1;

                for e in &sub_entries {
                    let e_bits = e.bit_length.max(0) as u32;
                    let is_bit = is_bit_entry(e);
                    let target_bit = if is_bit {
                        cur_bit
                    } else if e_bits >= 16 {
                        if !cur_bit.is_multiple_of(16) {
                            cur_bit + (16 - (cur_bit % 16))
                        } else {
                            cur_bit
                        }
                    } else if e_bits >= 8 {
                        if !cur_bit.is_multiple_of(8) {
                            cur_bit + (8 - (cur_bit % 8))
                        } else {
                            cur_bit
                        }
                    } else {
                        cur_bit
                    };

                    let mut gap = target_bit.saturating_sub(cur_bit);
                    while gap > 0 {
                        let chunk = gap.min(15);
                        out.push_str(&format!(
                            "ALIGN{chunk}(SubIndexPad{pad_idx:03}) /* Padding */\r\n"
                        ));
                        field_inits.push("0".to_string());
                        cur_bit += chunk;
                        gap -= chunk;
                        pad_idx += 1;
                    }

                    if e.data_type_id == 0 {
                        let mut rem = e_bits;
                        while rem > 0 {
                            let chunk = rem.min(15);
                            out.push_str(&format!(
                                "ALIGN{chunk}(SubIndex{:03}) /* Subindex{} */\r\n",
                                e.sub_index, e.sub_index
                            ));
                            field_inits.push("0".to_string());
                            cur_bit += chunk;
                            rem -= chunk;
                        }
                        continue;
                    }

                    let display_name = if e.name.is_empty() {
                        format!("SubIndex {:03}", e.sub_index)
                    } else {
                        e.name.clone()
                    };
                    let mut field_ident = if is_pdo {
                        format!("SI{}", e.sub_index)
                    } else {
                        to_c_identifier(&display_name)
                    };
                    if used_names.contains(&field_ident) {
                        field_ident = format!("{field_ident}_{}", e.sub_index);
                    }
                    used_names.push(field_ident.clone());

                    let decl = c_struct_field_decl(e, &field_ident);
                    let comment = if is_pdo {
                        format!(
                            " /* Subindex{} - {} */",
                            e.sub_index,
                            pdo_entry_reference_desc(e)
                        )
                    } else {
                        format!(" /* Subindex{} - {} */", e.sub_index, display_name)
                    };
                    out.push_str(&format!("{decl}{comment}\r\n"));
                    field_inits.push(format_c_entry_initializer(e));
                    cur_bit += e_bits;
                }

                if !cur_bit.is_multiple_of(8) && sub_entries.iter().any(|e| is_bit_entry(e)) {
                    let rem = 8 - (cur_bit % 8);
                    out.push_str(&format!(
                        "ALIGN{rem}(SubIndexPad{pad_idx:03}) /* Padding */\r\n"
                    ));
                    field_inits.push("0".to_string());
                }

                out.push_str(&format!("}} OBJ_STRUCT_PACKED_END\r\nTOBJ{idx:04X};\r\n"));
                out.push_str(&format!("#endif //#ifndef {objects_guard_macro}\r\n\r\n"));

                out.push_str("/**\r\n* \\brief Object variable\r\n*/\r\n");
                out.push_str(&format!("PROTO TOBJ{idx:04X} {var_name}\r\n"));
                out.push_str(&format!(
                    "#if defined({guard_macro}) && ({guard_macro} == 1)\r\n"
                ));
                out.push_str(&format!("={{{}}}\r\n", field_inits.join(",")));
                out.push_str("#endif\r\n;\r\n");
                out.push_str("/** @}*/\r\n\r\n\r\n\r\n");

                let obj_deftype = if is_pdo {
                    "DEFTYPE_PDOMAPPING"
                } else {
                    "DEFTYPE_RECORD"
                };
                dic_lines.push(format!(
                    "/* Object 0x{idx:04X} */\r\n{{NULL , NULL ,  0x{idx:04X} , {{{obj_deftype} , {max_sub} | (OBJCODE_REC << 8)}} , asEntryDesc0x{idx:04X} , aName0x{idx:04X} , &{var_name} , {read_cb} , {write_cb} , 0x0000 }},"
                ));
            }
        }

        if outer_coe {
            out.push_str("#endif //#if COE_SUPPORTED\r\n");
        }
    }

    out.push_str("\r\n\r\n");
    for cb in &callbacks {
        out.push_str(cb);
    }
    out.push_str("\r\n\r\n");

    out.push_str("#if COE_SUPPORTED\r\n");
    out.push_str("#ifdef _OBJD_\r\n");
    out.push_str(&format!("TOBJECT    OBJMEM {dic_array_name}[] = {{\r\n"));
    for dl in &dic_lines {
        out.push_str(dl);
        out.push_str("\r\n");
    }
    out.push_str("{NULL,NULL, 0xFFFF, {0, 0}, NULL, NULL, NULL, NULL}};\r\n");
    if ssc_project_mode {
        out.push_str("#endif    //#ifdef _OBJD_\r\n\r\n");
    } else {
        out.push_str("#endif    //#ifdef _OBJD_\r\n");
    }
    out.push_str("#endif\r\n");
    out.push_str("#undef PROTO\r\n\r\n");
    out.push_str("/** @}*/\r\n");
    out.push_str(&format!("#define {objects_guard_macro}\r\n"));
    out
}

/// Render `<Module>Objects.h` (`Module0x{Ident:08X}_Objects.h`) for an MDP module.
pub fn render_module_objects_header(
    module: &ModuleObjectInfoCollection,
    parent_app_name: &str,
    ssc_project_mode: bool,
) -> String {
    let ident_hex = format!("0x{:08X}", module.module_ident);
    let file_stem = format!("Module{ident_hex}_Objects");
    let guard_macro = format!("_{}_", to_upper_snake_macro_ident(parent_app_name));
    let obj_guard = format!("_MODULE_{:08X}_OBJECTS_H_", module.module_ident);
    let dic_name = format!("Module{:08X}ObjDic", module.module_ident);
    render_objects_header(
        &module.od,
        &module.name,
        &file_stem,
        &guard_macro,
        &obj_guard,
        &dic_name,
        ssc_project_mode,
    )
}

/// Render `<App>.h` matching both `ET9300Utilities.ApplicationHandler` and `ET9300ProjectHandler`.
pub fn render_application_h(app_name: &str, file_stem: &str, module_headers: &[String]) -> String {
    let group_id = to_c_identifier(app_name);
    let upper = to_upper_snake_macro_ident(app_name);
    let mut extra_includes = String::new();
    for mh in module_headers {
        extra_includes.push_str(&format!("#include \"{mh}\"\r\n"));
    }

    format!(
        concat!(
            "/*\r\n",
            "* This source file is part of the EtherCAT Slave Stack Code licensed by Beckhoff Automation GmbH & Co KG, 33415 Verl, Germany.\r\n",
            "* The corresponding license agreement applies. This hint shall not be removed.\r\n",
            "*/\r\n",
            "\r\n",
            "/**\r\n",
            " * \\addtogroup {group_id} {app_name}\r\n",
            " * @{{\r\n",
            " */\r\n",
            "\r\n",
            "/**\r\n",
            "\\file {file_stem}.h\r\n",
            "\\brief {app_name} function prototypes and defines\r\n",
            "\r\n",
            "\\version 1.0.0.11\r\n",
            " */\r\n",
            "\r\n",
            " \r\n",
            " #ifndef _{upper}_H_\r\n",
            "#define _{upper}_H_\r\n",
            "\r\n",
            "\r\n",
            "/*-----------------------------------------------------------------------------------------\r\n",
            "------\r\n",
            "------    Includes\r\n",
            "------\r\n",
            "-----------------------------------------------------------------------------------------*/\r\n",
            "#include \"ecat_def.h\"\r\n",
            "\r\n",
            "#include \"ecatappl.h\"\r\n",
            "\r\n",
            "/*-----------------------------------------------------------------------------------------\r\n",
            "------\r\n",
            "------    Defines and Types\r\n",
            "------\r\n",
            "-----------------------------------------------------------------------------------------*/\r\n",
            "\r\n",
            "#endif //_{upper}_H_\r\n",
            "\r\n",
            "//include custom application object dictionary \r\n",
            "#include \"{file_stem}Objects.h\"\r\n",
            "{extra_includes}\r\n",
            "\r\n",
            "#if defined(_{upper}_) && (_{upper}_ == 1)\r\n",
            "    #define PROTO\r\n",
            "#else\r\n",
            "    #define PROTO extern\r\n",
            "#endif\r\n",
            "\r\n",
            "\r\n",
            "PROTO void APPL_Application(void);\r\n",
            "#if EXPLICIT_DEVICE_ID\r\n",
            "PROTO UINT16 APPL_GetDeviceID(void);\r\n",
            "#endif\r\n",
            "\r\n",
            "PROTO void   APPL_AckErrorInd(UINT16 stateTrans);\r\n",
            "PROTO UINT16 APPL_StartMailboxHandler(void);\r\n",
            "PROTO UINT16 APPL_StopMailboxHandler(void);\r\n",
            "PROTO UINT16 APPL_StartInputHandler(UINT16 *pIntMask);\r\n",
            "PROTO UINT16 APPL_StopInputHandler(void);\r\n",
            "PROTO UINT16 APPL_StartOutputHandler(void);\r\n",
            "PROTO UINT16 APPL_StopOutputHandler(void);\r\n",
            "\r\n",
            "PROTO UINT16 APPL_GenerateMapping(UINT16 *pInputSize,UINT16 *pOutputSize);\r\n",
            "PROTO void APPL_InputMapping(UINT16* pData);\r\n",
            "PROTO void APPL_OutputMapping(UINT16* pData);\r\n",
            "\r\n",
            "#undef PROTO\r\n",
            "/** @}}*/\r\n\r\n"
        ),
        group_id = group_id,
        app_name = app_name,
        file_stem = file_stem,
        upper = upper,
        extra_includes = extra_includes,
    )
}

fn collect_sdo_callbacks(od: &ObjectInfoCollection) -> Vec<(String, bool)> {
    let mut out: Vec<(String, bool)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for obj in od.objects.values() {
        if obj.is_enum_object() {
            continue;
        }
        let (rd, wr) = object_callbacks(obj);
        if !rd.is_empty() && !seen.contains(&rd) {
            seen.push(rd.clone());
            out.push((rd, false));
        }
        if !wr.is_empty() && !seen.contains(&wr) {
            seen.push(wr.clone());
            out.push((wr, true));
        }
    }
    out
}

/// Render `<App>.c`.
pub fn render_application_c(
    od: &ObjectInfoCollection,
    app_name: &str,
    file_stem: &str,
    ssc_project_mode: bool,
) -> String {
    let group_id = to_c_identifier(app_name);
    let upper = to_upper_snake_macro_ident(app_name);
    let callbacks = collect_sdo_callbacks(od);

    if ssc_project_mode {
        let mut cb_block = String::new();
        for (fn_name, is_write) in &callbacks {
            let rw_word = if *is_write { "write" } else { "read" };
            cb_block.push_str(&format!(
                concat!(
                    "\r\n\r\n\r\n/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                    "/**\r\n",
                    "\\param     index               index of the requested object.\r\n",
                    "\\param     subindex            subindex of the requested object.\r\n",
                    "\\param     objSize             size of the requested object data, calculated with OBJ_GetObjectLength\r\n",
                    "\\param     pData               Pointer to the buffer where the data can be copied to\r\n",
                    "\\param     bCompleteAccess     Indicates if a complete read of all subindices of the\r\n",
                    "                               object shall be done or not\r\n",
                    "\r\n",
                    " \\return    result of the read operation (0 (success) or an abort code (ABORTIDX_.... defined in\r\n",
                    "            sdosrv.h))\r\n",
                    " *////////////////////////////////////////////////////////////////////////////////////////\r\n",
                    "UINT8 {fn_name}(UINT16 index, UINT8 subindex, UINT32 dataSize, UINT16 MBXMEM * pData, UINT8 bCompleteAccess) {{\r\n",
                    "#if _WIN32\r\n",
                    "#pragma message (\"Warning: Implement CoE {rw_word} callback\")\r\n",
                    "#else\r\n",
                    " #warning \"Implement CoE {rw_word} callback\"\r\n",
                    "#endif\r\n",
                    " return 0;\r\n",
                    "}}"
                ),
                fn_name = fn_name,
                rw_word = rw_word,
            ));
        }
        let cb_section = if cb_block.is_empty() {
            "\r\n".to_string()
        } else {
            format!("{cb_block}\r\n")
        };

        format!(
            concat!(
                "/*\r\n",
                "* This source file is part of the EtherCAT Slave Stack Code licensed by Beckhoff Automation GmbH & Co KG, 33415 Verl, Germany.\r\n",
                "* The corresponding license agreement applies. This hint shall not be removed.\r\n",
                "*/\r\n",
                "\r\n",
                "/**\r\n",
                "\\addtogroup {group_id} {app_name}\r\n",
                "@{{\r\n",
                "*/\r\n",
                "\r\n",
                "/**\r\n",
                "\\file {file_stem}.c\r\n",
                "\\brief Implementation\r\n",
                " Created with SSC Tool application parser 1.6.4.0\r\n",
                "\\version 0.0.0.1\r\n",
                "*/\r\n",
                "\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    Includes\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "#include \"ecat_def.h\"\r\n",
                "\r\n",
                "#include \"applInterface.h\"\r\n",
                "\r\n",
                "#define _{upper}_ 1\r\n",
                "#include \"{file_stem}.h\"\r\n",
                "#undef _{upper}_\r\n",
                "/*--------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    local types and defines\r\n",
                "------\r\n",
                "--------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    local variables and constants\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    application specific functions\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    generic functions\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\brief    The function is called when an error state was acknowledged by the master\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "void    APPL_AckErrorInd(UINT16 stateTrans)\r\n",
                "{{\r\n",
                "\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from INIT to PREOP when\r\n",
                "             all general settings were checked to start the mailbox handler. This function\r\n",
                "             informs the application about the state transition, the application can refuse\r\n",
                "             the state transition when returning an AL Status error code.\r\n",
                "            The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "            the state transition immediately, in that case this function will be called cyclically\r\n",
                "            until a value unequal NOERROR_INWORK is returned\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartMailboxHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from PREEOP to INIT\r\n",
                "             to stop the mailbox handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopMailboxHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\param    pIntMask    pointer to the AL Event Mask which will be written to the AL event Mask\r\n",
                "                       register (0x204) when this function is succeeded. The event mask can be adapted\r\n",
                "                       in this function\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from PREOP to SAFEOP when\r\n",
                "           all general settings were checked to start the input handler. This function\r\n",
                "           informs the application about the state transition, the application can refuse\r\n",
                "           the state transition when returning an AL Status error code.\r\n",
                "           The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "           the state transition immediately, in that case the application need to be complete \r\n",
                "           the transition by calling ECAT_StateChange.\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartInputHandler(UINT16 *pIntMask)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from SAFEOP to PREEOP\r\n",
                "             to stop the input handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopInputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from SAFEOP to OP when\r\n",
                "             all general settings were checked to start the output handler. This function\r\n",
                "             informs the application about the state transition, the application can refuse\r\n",
                "             the state transition when returning an AL Status error code.\r\n",
                "           The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "           the state transition immediately, in that case the application need to be complete \r\n",
                "           the transition by calling ECAT_StateChange.\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartOutputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from OP to SAFEOP\r\n",
                "             to stop the output handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopOutputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\return     0(ALSTATUSCODE_NOERROR), NOERROR_INWORK\r\n",
                "\\param      pInputSize  pointer to save the input process data length\r\n",
                "\\param      pOutputSize  pointer to save the output process data length\r\n",
                "\r\n",
                "\\brief    This function calculates the process data sizes from the actual SM-PDO-Assign\r\n",
                "            and PDO mapping\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "UINT16 APPL_GenerateMapping(UINT16 *pInputSize,UINT16 *pOutputSize)\r\n",
                "{{\r\n",
                "    UINT16 result = ALSTATUSCODE_NOERROR;\r\n",
                "    UINT16 InputSize = 0;\r\n",
                "    UINT16 OutputSize = 0;\r\n",
                "\r\n",
                "#if COE_SUPPORTED\r\n",
                "    UINT16 PDOAssignEntryCnt = 0;\r\n",
                "    OBJCONST TOBJECT OBJMEM * pPDO = NULL;\r\n",
                "    UINT16 PDOSubindex0 = 0;\r\n",
                "    UINT32 *pPDOEntry = NULL;\r\n",
                "    UINT16 PDOEntryCnt = 0;\r\n",
                "   \r\n",
                "#if MAX_PD_OUTPUT_SIZE > 0\r\n",
                "    /*Scan object 0x1C12 RXPDO assign*/\r\n",
                "    for(PDOAssignEntryCnt = 0; PDOAssignEntryCnt < sRxPDOassign.u16SubIndex0; PDOAssignEntryCnt++)\r\n",
                "    {{\r\n",
                "        pPDO = OBJ_GetObjectHandle(sRxPDOassign.aEntries[PDOAssignEntryCnt]);\r\n",
                "        if(pPDO != NULL)\r\n",
                "        {{\r\n",
                "            PDOSubindex0 = *((UINT16 *)pPDO->pVarPtr);\r\n",
                "            for(PDOEntryCnt = 0; PDOEntryCnt < PDOSubindex0; PDOEntryCnt++)\r\n",
                "            {{\r\n",
                "                pPDOEntry = (UINT32 *)(((UINT16 *)pPDO->pVarPtr) + (OBJ_GetEntryOffset((PDOEntryCnt+1),pPDO)>>4));    //goto PDO entry\r\n",
                "                // we increment the expected output size depending on the mapped Entry\r\n",
                "                OutputSize += (UINT16) ((*pPDOEntry) & 0xFF);\r\n",
                "            }}\r\n",
                "        }}\r\n",
                "        else\r\n",
                "        {{\r\n",
                "            /*assigned PDO was not found in object dictionary. return invalid mapping*/\r\n",
                "            OutputSize = 0;\r\n",
                "            result = ALSTATUSCODE_INVALIDOUTPUTMAPPING;\r\n",
                "            break;\r\n",
                "        }}\r\n",
                "    }}\r\n",
                "\r\n",
                "    OutputSize = (OutputSize + 7) >> 3;\r\n",
                "#endif\r\n",
                "\r\n",
                "#if MAX_PD_INPUT_SIZE > 0\r\n",
                "    if(result == 0)\r\n",
                "    {{\r\n",
                "        /*Scan Object 0x1C13 TXPDO assign*/\r\n",
                "        for(PDOAssignEntryCnt = 0; PDOAssignEntryCnt < sTxPDOassign.u16SubIndex0; PDOAssignEntryCnt++)\r\n",
                "        {{\r\n",
                "            pPDO = OBJ_GetObjectHandle(sTxPDOassign.aEntries[PDOAssignEntryCnt]);\r\n",
                "            if(pPDO != NULL)\r\n",
                "            {{\r\n",
                "                PDOSubindex0 = *((UINT16 *)pPDO->pVarPtr);\r\n",
                "                for(PDOEntryCnt = 0; PDOEntryCnt < PDOSubindex0; PDOEntryCnt++)\r\n",
                "                {{\r\n",
                "                    pPDOEntry = (UINT32 *)(((UINT16 *)pPDO->pVarPtr) + (OBJ_GetEntryOffset((PDOEntryCnt+1),pPDO)>>4));    //goto PDO entry\r\n",
                "                    // we increment the expected output size depending on the mapped Entry\r\n",
                "                    InputSize += (UINT16) ((*pPDOEntry) & 0xFF);\r\n",
                "                }}\r\n",
                "            }}\r\n",
                "            else\r\n",
                "            {{\r\n",
                "                /*assigned PDO was not found in object dictionary. return invalid mapping*/\r\n",
                "                InputSize = 0;\r\n",
                "                result = ALSTATUSCODE_INVALIDINPUTMAPPING;\r\n",
                "                break;\r\n",
                "            }}\r\n",
                "        }}\r\n",
                "    }}\r\n",
                "    InputSize = (InputSize + 7) >> 3;\r\n",
                "#endif\r\n",
                "\r\n",
                "#else\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Define 'InputSize' and 'OutputSize'.\")\r\n",
                "#else\r\n",
                "    #warning \"Define 'InputSize' and 'OutputSize'.\"\r\n",
                "#endif\r\n",
                "#endif\r\n",
                "\r\n",
                "    *pInputSize = InputSize;\r\n",
                "    *pOutputSize = OutputSize;\r\n",
                "    return result;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\param      pData  pointer to input process data\r\n",
                "\r\n",
                "\\brief      This function will copies the inputs from the local memory to the ESC memory\r\n",
                "            to the hardware\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_InputMapping(UINT16* pData)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement input (Slave->Master) mapping\")\r\n",
                "#else\r\n",
                "    #warning \"Implement input (Slave->Master) mapping\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\param      pData  pointer to output process data\r\n",
                "\r\n",
                "\\brief    This function will copies the outputs from the ESC memory to the local memory\r\n",
                "            to the hardware\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_OutputMapping(UINT16* pData)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement output (Master->Slave) mapping\")\r\n",
                "#else\r\n",
                "    #warning \"Implement output (Master->Slave) mapping\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\brief    This function will called from the synchronisation ISR \r\n",
                "            or from the mainloop if no synchronisation is supported\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_Application(void)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement the slave application\")\r\n",
                "#else\r\n",
                "    #warning \"Implement the slave application\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "#if EXPLICIT_DEVICE_ID\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    The Explicit Device ID of the EtherCAT slave\r\n",
                "\r\n",
                " \\brief     Read the Explicit Device ID (from an external ID switch)\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "UINT16 APPL_GetDeviceID()\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement explicit Device ID latching\")\r\n",
                "#else\r\n",
                "    #warning \"Implement explicit Device ID latching\"\r\n",
                "#endif\r\n",
                "    /* Explicit Device 5 is expected by Explicit Device ID conformance tests*/\r\n",
                "    return 0x5;\r\n",
                "}}\r\n",
                "#endif\r\n",
                "{cb_section}#if USE_DEFAULT_MAIN\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\r\n",
                " \\brief    This is the main function\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "#if _PIC24 && EL9800_HW\r\n",
                "int main(void)\r\n",
                "#elif _WIN32\r\n",
                "int main(int argc, char* argv[])\r\n",
                "#else\r\n",
                "void main(void)\r\n",
                "#endif\r\n",
                "{{\r\n",
                "    /* initialize the Hardware and the EtherCAT Slave Controller */\r\n",
                "#if FC1100_HW\r\n",
                "#if _WIN32\r\n",
                "    u16FcInstance = 0;\r\n",
                "    if (argc > 1)\r\n",
                "    {{\r\n",
                "        u16FcInstance = atoi(argv[1]);\r\n",
                "    }}\r\n",
                "#endif\r\n",
                "    if(HW_Init())\r\n",
                "    {{\r\n",
                "        HW_Release();\r\n",
                "        return;\r\n",
                "    }}\r\n",
                "#else\r\n",
                "    HW_Init();\r\n",
                "#endif\r\n",
                "    MainInit();\r\n",
                "\r\n",
                "    bRunApplication = TRUE;\r\n",
                "    do\r\n",
                "    {{\r\n",
                "        MainLoop();\r\n",
                "        \r\n",
                "    }} while (bRunApplication == TRUE);\r\n",
                "\r\n",
                "    HW_Release();\r\n",
                "#if _PIC24\r\n",
                "    return 0;\r\n",
                "#endif\r\n",
                "}}\r\n",
                "#endif //#if USE_DEFAULT_MAIN\r\n",
                "/** @}} */\r\n\r\n"
            ),
            group_id = group_id,
            app_name = app_name,
            file_stem = file_stem,
            upper = upper,
            cb_section = cb_section,
        )
    } else {
        let mut cb_block = String::new();
        for (idx, (fn_name, is_write)) in callbacks.iter().enumerate() {
            let rw_word = if *is_write { "write" } else { "read" };
            let prefix = if idx == 0 { "{0}{0}" } else { "" };
            cb_block.push_str(&format!(
                "{prefix}/////////////////////////////////////////////////////////////////////////////////////////{{0}}/**{{0}}\\param     index               index of the requested object.{{0}}\\param     subindex            subindex of the requested object.{{0}}\\param     objSize             size of the requested object data, calculated with OBJ_GetObjectLength{{0}}\\param     pData               Pointer to the buffer where the data can be copied to{{0}}\\param     bCompleteAccess     Indicates if a complete read of all subindices of the{{0}}                               object shall be done or not{{0}}{{0}} \\return    result of the read operation (0 (success) or an abort code (ABORTIDX_.... defined in{{0}}            sdosrv.h)){{0}} *////////////////////////////////////////////////////////////////////////////////////////{{0}}UINT8 {fn_name}(UINT16 index, UINT8 subindex, UINT32 dataSize, UINT16 MBXMEM * pData, UINT8 bCompleteAccess) {{{{{{0}}#if _WIN32{{0}}#pragma message (\"Warning: Implement CoE {rw_word} callback\"){{0}}#else{{0}} #warning \"Implement CoE {rw_word} callback\"{{0}}#endif{{0}} return 0;{{0}}}}}}"
            ));
        }
        let cb_section = format!("\r\n{cb_block}\r\n\r\n");

        format!(
            concat!(
                "/*\r\n",
                "* This source file is part of the EtherCAT Slave Stack Code licensed by Beckhoff Automation GmbH & Co KG, 33415 Verl, Germany.\r\n",
                "* The corresponding license agreement applies. This hint shall not be removed.\r\n",
                "*/\r\n",
                "\r\n",
                "/**\r\n",
                "\\addtogroup {group_id} {app_name}\r\n",
                "@{{\r\n",
                "*/\r\n",
                "\r\n",
                "/**\r\n",
                "\\file {file_stem}.c\r\n",
                "\\brief Implementation\r\n",
                "\r\n",
                "\\version 1.0.0.11\r\n",
                "*/\r\n",
                "\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    Includes\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "#include \"ecat_def.h\"\r\n",
                "\r\n",
                "#include \"applInterface.h\"\r\n",
                "\r\n",
                "#define _{upper}_ 1\r\n",
                "#include \"{file_stem}.h\"\r\n",
                "#undef _{upper}_\r\n",
                "/*--------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    local types and defines\r\n",
                "------\r\n",
                "--------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    local variables and constants\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    application specific functions\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/*-----------------------------------------------------------------------------------------\r\n",
                "------\r\n",
                "------    generic functions\r\n",
                "------\r\n",
                "-----------------------------------------------------------------------------------------*/\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\brief    The function is called when an error state was acknowledged by the master\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "void    APPL_AckErrorInd(UINT16 stateTrans)\r\n",
                "{{\r\n",
                "\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from INIT to PREOP when\r\n",
                "             all general settings were checked to start the mailbox handler. This function\r\n",
                "             informs the application about the state transition, the application can refuse\r\n",
                "             the state transition when returning an AL Status error code.\r\n",
                "            The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "            the state transition immediately, in that case this function will be called cyclically\r\n",
                "            until a value unequal NOERROR_INWORK is returned\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartMailboxHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from PREEOP to INIT\r\n",
                "             to stop the mailbox handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopMailboxHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\param    pIntMask    pointer to the AL Event Mask which will be written to the AL event Mask\r\n",
                "                        register (0x204) when this function is succeeded. The event mask can be adapted\r\n",
                "                        in this function\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from PREOP to SAFEOP when\r\n",
                "           all general settings were checked to start the input handler. This function\r\n",
                "           informs the application about the state transition, the application can refuse\r\n",
                "           the state transition when returning an AL Status error code.\r\n",
                "           The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "           the state transition immediately, in that case the application need to be complete \r\n",
                "           the transition by calling ECAT_StateChange.\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartInputHandler(UINT16 *pIntMask)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from SAFEOP to PREEOP\r\n",
                "             to stop the input handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopInputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    AL Status Code (see ecatslv.h ALSTATUSCODE_....)\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from SAFEOP to OP when\r\n",
                "             all general settings were checked to start the output handler. This function\r\n",
                "             informs the application about the state transition, the application can refuse\r\n",
                "             the state transition when returning an AL Status error code.\r\n",
                "           The return code NOERROR_INWORK can be used, if the application cannot confirm\r\n",
                "           the state transition immediately, in that case the application need to be complete \r\n",
                "           the transition by calling ECAT_StateChange.\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StartOutputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return     0, NOERROR_INWORK\r\n",
                "\r\n",
                " \\brief    The function is called in the state transition from OP to SAFEOP\r\n",
                "             to stop the output handler. This functions informs the application\r\n",
                "             about the state transition, the application cannot refuse\r\n",
                "             the state transition.\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "\r\n",
                "UINT16 APPL_StopOutputHandler(void)\r\n",
                "{{\r\n",
                "    return ALSTATUSCODE_NOERROR;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\return     0(ALSTATUSCODE_NOERROR), NOERROR_INWORK\r\n",
                "\\param      pInputSize  pointer to save the input process data length\r\n",
                "\\param      pOutputSize  pointer to save the output process data length\r\n",
                "\r\n",
                "\\brief    This function calculates the process data sizes from the actual SM-PDO-Assign\r\n",
                "            and PDO mapping\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "UINT16 APPL_GenerateMapping(UINT16 *pInputSize,UINT16 *pOutputSize)\r\n",
                "{{\r\n",
                "    UINT16 result = ALSTATUSCODE_NOERROR;\r\n",
                "    UINT16 InputSize = 0;\r\n",
                "    UINT16 OutputSize = 0;\r\n",
                "\r\n",
                "#if COE_SUPPORTED\r\n",
                "    UINT16 PDOAssignEntryCnt = 0;\r\n",
                "    OBJCONST TOBJECT OBJMEM * pPDO = NULL;\r\n",
                "    UINT16 PDOSubindex0 = 0;\r\n",
                "    UINT32 *pPDOEntry = NULL;\r\n",
                "    UINT16 PDOEntryCnt = 0;\r\n",
                "   \r\n",
                "#if MAX_PD_OUTPUT_SIZE > 0\r\n",
                "    /*Scan object 0x1C12 RXPDO assign*/\r\n",
                "    for(PDOAssignEntryCnt = 0; PDOAssignEntryCnt < sRxPDOassign.u16SubIndex0; PDOAssignEntryCnt++)\r\n",
                "    {{\r\n",
                "        pPDO = OBJ_GetObjectHandle(sRxPDOassign.aEntries[PDOAssignEntryCnt]);\r\n",
                "        if(pPDO != NULL)\r\n",
                "        {{\r\n",
                "            PDOSubindex0 = *((UINT16 *)pPDO->pVarPtr);\r\n",
                "            for(PDOEntryCnt = 0; PDOEntryCnt < PDOSubindex0; PDOEntryCnt++)\r\n",
                "            {{\r\n",
                "                pPDOEntry = (UINT32 *)(((UINT16 *)pPDO->pVarPtr) + (OBJ_GetEntryOffset((PDOEntryCnt+1),pPDO)>>4));    //goto PDO entry\r\n",
                "                // we increment the expected output size depending on the mapped Entry\r\n",
                "                OutputSize += (UINT16) ((*pPDOEntry) & 0xFF);\r\n",
                "            }}\r\n",
                "        }}\r\n",
                "        else\r\n",
                "        {{\r\n",
                "            /*assigned PDO was not found in object dictionary. return invalid mapping*/\r\n",
                "            OutputSize = 0;\r\n",
                "            result = ALSTATUSCODE_INVALIDOUTPUTMAPPING;\r\n",
                "            break;\r\n",
                "        }}\r\n",
                "    }}\r\n",
                "\r\n",
                "    OutputSize = (OutputSize + 7) >> 3;\r\n",
                "#endif\r\n",
                "\r\n",
                "#if MAX_PD_INPUT_SIZE > 0\r\n",
                "    if(result == 0)\r\n",
                "    {{\r\n",
                "        /*Scan Object 0x1C13 TXPDO assign*/\r\n",
                "        for(PDOAssignEntryCnt = 0; PDOAssignEntryCnt < sTxPDOassign.u16SubIndex0; PDOAssignEntryCnt++)\r\n",
                "        {{\r\n",
                "            pPDO = OBJ_GetObjectHandle(sTxPDOassign.aEntries[PDOAssignEntryCnt]);\r\n",
                "            if(pPDO != NULL)\r\n",
                "            {{\r\n",
                "                PDOSubindex0 = *((UINT16 *)pPDO->pVarPtr);\r\n",
                "                for(PDOEntryCnt = 0; PDOEntryCnt < PDOSubindex0; PDOEntryCnt++)\r\n",
                "                {{\r\n",
                "                    pPDOEntry = (UINT32 *)(((UINT16 *)pPDO->pVarPtr) + (OBJ_GetEntryOffset((PDOEntryCnt+1),pPDO)>>4));    //goto PDO entry\r\n",
                "                    // we increment the expected output size depending on the mapped Entry\r\n",
                "                    InputSize += (UINT16) ((*pPDOEntry) & 0xFF);\r\n",
                "                }}\r\n",
                "            }}\r\n",
                "            else\r\n",
                "            {{\r\n",
                "                /*assigned PDO was not found in object dictionary. return invalid mapping*/\r\n",
                "                InputSize = 0;\r\n",
                "                result = ALSTATUSCODE_INVALIDINPUTMAPPING;\r\n",
                "                break;\r\n",
                "            }}\r\n",
                "        }}\r\n",
                "    }}\r\n",
                "    InputSize = (InputSize + 7) >> 3;\r\n",
                "#endif\r\n",
                "\r\n",
                "#else\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Define 'InputSize' and 'OutputSize'.\")\r\n",
                "#else\r\n",
                "    #warning \"Define 'InputSize' and 'OutputSize'.\"\r\n",
                "#endif\r\n",
                "#endif\r\n",
                "\r\n",
                "    *pInputSize = InputSize;\r\n",
                "    *pOutputSize = OutputSize;\r\n",
                "    return result;\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\param      pData  pointer to input process data\r\n",
                "\r\n",
                "\\brief      This function will copies the inputs from the local memory to the ESC memory\r\n",
                "            to the hardware\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_InputMapping(UINT16* pData)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement input (Slave -> Master) mapping\")\r\n",
                "#else\r\n",
                "    #warning \"Implement input (Slave -> Master) mapping\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\param      pData  pointer to output process data\r\n",
                "\r\n",
                "\\brief    This function will copies the outputs from the ESC memory to the local memory\r\n",
                "            to the hardware\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_OutputMapping(UINT16* pData)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement output(Master -> Slave) mapping\")\r\n",
                "#else\r\n",
                "    #warning \"Implement output (Master -> Slave) mapping\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\\brief    This function will called from the synchronisation ISR \r\n",
                "            or from the mainloop if no synchronisation is supported\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "void APPL_Application(void)\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement the slave application\")\r\n",
                "#else\r\n",
                "    #warning \"Implement the slave application\"\r\n",
                "#endif\r\n",
                "}}\r\n",
                "\r\n",
                "#if EXPLICIT_DEVICE_ID\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                " \\return    The Explicit Device ID of the EtherCAT slave\r\n",
                "\r\n",
                " \\brief     Read the Explicit Device ID (from an external ID switch)\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "UINT16 APPL_GetDeviceID()\r\n",
                "{{\r\n",
                "#if _WIN32\r\n",
                "   #pragma message (\"Warning: Implement explicit Device ID latching\")\r\n",
                "#else\r\n",
                "    #warning \"Implement explicit Device ID latching\"\r\n",
                "#endif\r\n",
                "    /* Explicit Device 5 is expected by Explicit Device ID conformance tests*/\r\n",
                "    return 0x5;\r\n",
                "}}\r\n",
                "#endif\r\n",
                "{cb_section}#if USE_DEFAULT_MAIN\r\n",
                "/////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "/**\r\n",
                "\r\n",
                " \\brief    This is the main function\r\n",
                "\r\n",
                "*////////////////////////////////////////////////////////////////////////////////////////\r\n",
                "#if _PIC24\r\n",
                "int main(void)\r\n",
                "#else\r\n",
                "void main(void)\r\n",
                "#endif\r\n",
                "{{\r\n",
                "    /* initialize the Hardware and the EtherCAT Slave Controller */\r\n",
                "#if FC1100_HW\r\n",
                "    if(HW_Init())\r\n",
                "    {{\r\n",
                "        HW_Release();\r\n",
                "        return;\r\n",
                "    }}\r\n",
                "#else\r\n",
                "    HW_Init();\r\n",
                "#endif\r\n",
                "    MainInit();\r\n",
                "\r\n",
                "    bRunApplication = TRUE;\r\n",
                "    do\r\n",
                "    {{\r\n",
                "        MainLoop();\r\n",
                "        \r\n",
                "    }} while (bRunApplication == TRUE);\r\n",
                "\r\n",
                "    HW_Release();\r\n",
                "#if _PIC24\r\n",
                "    return 0;\r\n",
                "#endif\r\n",
                "}}\r\n",
                "#endif //#if USE_DEFAULT_MAIN\r\n",
                "/** @}} */\r\n\r\n"
            ),
            group_id = group_id,
            app_name = app_name,
            file_stem = file_stem,
            upper = upper,
            cb_section = cb_section,
        )
    }
}
