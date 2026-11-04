use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use ethercat_wire::error::{CliError, Result};
use ethercat_wire::types::{parse_u64, DataTypeSpec};

use crate::xml::dom::{decode_xml_bytes, parse_xml_document, XmlNode};
use crate::xml::{
    default_type_for_bits, xml_type_to_wire_spec, OdObject, OdSubEntry, PdoDirection, XmlCatalog,
    XmlDataType, XmlDeviceProfile, XmlModuleDef, XmlPdoDef, XmlPdoEntry, XmlSlotsSpec, XmlSmDef,
    XmlSubItemDef,
};

fn parse_ecat_int(s: &str) -> Option<u64> {
    parse_u64(s.trim()).ok()
}

fn parse_ecat_signed(s: &str) -> Option<i64> {
    let t = s.trim();
    if let Some(neg) = t.strip_prefix('-') {
        parse_ecat_int(neg).map(|v| -(v as i64))
    } else {
        parse_ecat_int(t).map(|v| v as i64)
    }
}

fn parse_bool_attr(val: Option<&str>, default_val: bool) -> bool {
    match val.map(|s| s.trim()) {
        Some("1") | Some("true") | Some("TRUE") | Some("True") => true,
        Some("0") | Some("false") | Some("FALSE") | Some("False") => false,
        _ => default_val,
    }
}

fn normalize_hex(s: &str) -> Option<String> {
    let mut cleaned = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if (bytes[i] == b'0' || bytes[i] == b'#')
            && i + 1 < bytes.len()
            && (bytes[i + 1] == b'x' || bytes[i + 1] == b'X')
        {
            i += 2;
            continue;
        }
        let ch = bytes[i] as char;
        if ch.is_ascii_hexdigit() {
            cleaned.push(ch.to_ascii_lowercase());
        }
        i += 1;
    }
    if cleaned.is_empty() {
        None
    } else if cleaned.len() % 2 == 1 {
        Some(format!("0{cleaned}"))
    } else {
        Some(cleaned)
    }
}

/// Loads an `XmlCatalog` from a single `.xml` file or a directory of `.xml` files.
pub fn load_xml_catalog(path: &Path) -> Result<XmlCatalog> {
    if path.is_dir() {
        let mut catalog = XmlCatalog {
            source_kind: "Directory".into(),
            devices: Vec::new(),
        };
        let mut entries: Vec<_> = fs::read_dir(path)
            .map_err(|e| {
                CliError::Format(format!(
                    "failed to read XML directory {}: {e}",
                    path.display()
                ))
            })?
            .filter_map(|e| e.ok())
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let p = entry.path();
            if p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("xml"))
            {
                if let Ok(sub) = load_single_xml_file(&p) {
                    catalog.devices.extend(sub.devices);
                }
            }
        }
        if catalog.devices.is_empty() {
            return Err(CliError::Format(format!(
                "no EtherCAT devices or dictionaries found in directory {}",
                path.display()
            )));
        }
        return Ok(catalog);
    }

    load_single_xml_file(path)
}

fn load_single_xml_file(path: &Path) -> Result<XmlCatalog> {
    let raw = fs::read(path).map_err(|e| {
        CliError::Format(format!("failed to read XML file {}: {e}", path.display()))
    })?;
    let text = decode_xml_bytes(&raw)?;
    parse_xml_catalog_str(&text, path.parent())
}

pub fn parse_xml_catalog_str(xml_text: &str, base_dir: Option<&Path>) -> Result<XmlCatalog> {
    let root = parse_xml_document(xml_text)?;
    match root.tag.to_ascii_lowercase().as_str() {
        "ethercatinfo" => parse_esi_root(&root, base_dir),
        "ethercatdict" | "dictionary" => parse_dict_root(&root, base_dir),
        "ethercatconfig" => parse_eni_root(&root),
        other => Err(CliError::Format(format!(
            "unsupported EtherCAT XML root <{other}> (expected <EtherCATInfo>, <EtherCATDict>, or <EtherCATConfig>)"
        ))),
    }
}

fn parse_datatypes_node(dt_parent: &XmlNode, types_out: &mut BTreeMap<String, XmlDataType>) {
    for dt_node in dt_parent.children_named("DataType") {
        let Some(name) = dt_node.child_text("Name").map(|s| s.to_string()) else {
            continue;
        };
        let base_type = dt_node.child_text("BaseType").map(|s| s.to_string());
        let bit_size = dt_node
            .child_text("BitSize")
            .and_then(parse_ecat_int)
            .unwrap_or(0) as u32;

        let mut enum_map = BTreeMap::new();
        for ei in dt_node.children_named("EnumInfo") {
            let text = ei.child_text("Text").unwrap_or("").to_string();
            if let Some(val) = ei.child_text("Enum").and_then(parse_ecat_signed) {
                enum_map.insert(val, text);
            }
        }

        let array_elements = dt_node.child("ArrayInfo").and_then(|ai| {
            let lbound = ai
                .child_text("LBound")
                .and_then(parse_ecat_int)
                .unwrap_or(1) as u16;
            let elems = ai.child_text("Elements").and_then(parse_ecat_int)? as u16;
            Some((lbound, elems))
        });

        let mut subitems = Vec::new();
        for si in dt_node.children_named("SubItem") {
            let subidx = si
                .child_text("SubIdx")
                .and_then(parse_ecat_int)
                .map(|v| v as u8);
            let sname = si.child_text("Name").unwrap_or("SubItem").to_string();
            let stype = si.child_text("Type").unwrap_or("BYTE").to_string();
            let sbits = si
                .child_text("BitSize")
                .and_then(parse_ecat_int)
                .unwrap_or(0) as u32;
            let soffs = si
                .child_text("BitOffs")
                .and_then(parse_ecat_int)
                .map(|v| v as u32);
            let (access, pdo_map) = parse_flags_node(si.child("Flags"));
            let unit = si
                .child("Info")
                .and_then(|i| i.child_text("Unit"))
                .map(|s| s.to_string());
            let def_hex = extract_default_hex(si.child("Info"), sbits);
            subitems.push(XmlSubItemDef {
                subindex: subidx,
                name: sname,
                type_name: stype,
                bit_size: sbits,
                bit_offset: soffs,
                access,
                pdo_mapping: pdo_map,
                unit,
                default_hex: def_hex,
            });
        }

        types_out.insert(
            name.to_ascii_uppercase(),
            XmlDataType {
                name,
                base_type,
                bit_size,
                enum_map,
                array_elements,
                subitems,
            },
        );
    }
}

fn parse_flags_node(flags: Option<&XmlNode>) -> (Option<String>, Option<String>) {
    let Some(f) = flags else {
        return (None, None);
    };
    let access = f.child_text("Access").map(|s| s.to_string());
    let pdo = f.child_text("PdoMapping").map(|s| s.to_string());
    (access, pdo)
}

fn extract_default_hex(info: Option<&XmlNode>, bit_length: u32) -> Option<String> {
    let inf = info?;
    if let Some(dd) = inf.child_text("DefaultData") {
        if let Some(h) = normalize_hex(dd) {
            return Some(h);
        }
    }
    if let Some(ds) = inf.child_text("DefaultString") {
        return Some(hex::encode(ds.as_bytes()));
    }
    if let Some(dv) = inf.child_text("DefaultValue") {
        if let Some(v) = parse_ecat_signed(dv) {
            let full = v.to_le_bytes();
            let byte_len = if bit_length > 0 {
                (bit_length as usize).div_ceil(8).clamp(1, 8)
            } else {
                8
            };
            return Some(hex::encode(&full[..byte_len]));
        }
    }
    None
}

fn find_subitem_override<'a>(
    info_subitems: &[&'a XmlNode],
    sidx: u8,
    pos_i: usize,
) -> Option<&'a XmlNode> {
    if let Some(by_sub) = info_subitems.iter().copied().find(|n| {
        n.child_text("SubIdx")
            .and_then(parse_ecat_int)
            .is_some_and(|v| v as u8 == sidx)
    }) {
        return Some(by_sub);
    }
    info_subitems
        .get(pos_i)
        .copied()
        .filter(|n| n.child_text("SubIdx").is_none())
}

fn resolve_enum_map(
    type_name: &str,
    datatypes: &BTreeMap<String, XmlDataType>,
) -> BTreeMap<i64, String> {
    let mut cur = type_name.trim().to_ascii_uppercase();
    for _ in 0..16 {
        let Some(dt) = datatypes.get(&cur) else {
            break;
        };
        if !dt.enum_map.is_empty() {
            return dt.enum_map.clone();
        }
        if let Some(bt) = &dt.base_type {
            cur = bt.trim().to_ascii_uppercase();
        } else {
            break;
        }
    }
    BTreeMap::new()
}

fn parse_parameterized_type_bits(up: &str) -> Option<u32> {
    for (prefix, bits_per_unit) in [
        ("STRING(", 8u32),
        ("OCTET_STRING(", 8u32),
        ("UNICODE_STRING(", 16u32),
    ] {
        if let Some(rest) = up.strip_prefix(prefix) {
            let end = rest.find(')')?;
            let count = parse_ecat_int(rest[..end].trim())? as u32;
            return count.checked_mul(bits_per_unit);
        }
    }
    None
}

fn resolve_leaf_type(
    type_name: &str,
    explicit_bits: u32,
    datatypes: &BTreeMap<String, XmlDataType>,
) -> (String, u32) {
    let mut cur = type_name.trim().to_string();
    let mut bits = explicit_bits;
    for _ in 0..16 {
        let Some(dt) = datatypes.get(&cur.to_ascii_uppercase()) else {
            break;
        };
        if bits == 0 && dt.bit_size > 0 {
            bits = dt.bit_size;
        }
        if let Some(bt) = &dt.base_type {
            cur = bt.clone();
        } else {
            break;
        }
    }
    if bits == 0 {
        let up = cur.trim().to_ascii_uppercase();
        bits = match up.as_str() {
            "BOOL" | "BOOLEAN" | "BIT" | "BIT1" => 1,
            "BIT2" => 2,
            "BIT3" => 3,
            "BIT4" => 4,
            "BIT5" => 5,
            "BIT6" => 6,
            "BIT7" => 7,
            "BIT8" | "SINT" | "INT8" | "USINT" | "UINT8" | "BYTE" | "BITARR8" => 8,
            "BIT9" => 9,
            "BIT10" => 10,
            "BIT11" => 11,
            "BIT12" => 12,
            "BIT13" => 13,
            "BIT14" => 14,
            "BIT15" => 15,
            "BIT16" | "INT" | "INT16" | "UINT" | "UINT16" | "WORD" | "BITARR16" => 16,
            "INT24" | "UINT24" => 24,
            "DINT" | "INT32" | "UDINT" | "UINT32" | "DWORD" | "REAL" | "REAL32" | "FLOAT"
            | "BITARR32" => 32,
            "INT40" | "UINT40" => 40,
            "INT48" | "UINT48" | "TIME_OF_DAY" | "TIME_DIFFERENCE" => 48,
            "INT56" | "UINT56" => 56,
            "LINT" | "INT64" | "ULINT" | "UINT64" | "LWORD" | "LREAL" | "REAL64" | "DOUBLE" => 64,
            _ => parse_parameterized_type_bits(&up).unwrap_or(0),
        };
    }
    (cur, bits)
}

fn parse_unit_types_node(ut_parent: &XmlNode, units_out: &mut BTreeMap<u64, String>) {
    for ut in ut_parent
        .children
        .iter()
        .filter(|c| c.tag.eq_ignore_ascii_case("UnitType") || c.tag.eq_ignore_ascii_case("Unit"))
    {
        let code_opt = ut
            .child_text("MasterType")
            .or_else(|| ut.child_text("Type"))
            .or_else(|| ut.child_text("Code"))
            .or_else(|| ut.child_text("Index"))
            .or_else(|| ut.attr("MasterType"))
            .or_else(|| ut.attr("Type"))
            .or_else(|| ut.attr("Code"))
            .and_then(parse_ecat_int);
        let label_opt = ["Notation", "Symbol", "Name"]
            .into_iter()
            .find_map(|tag| ut.child_text(tag).map(str::trim).filter(|s| !s.is_empty()))
            .map(str::to_string);
        if let (Some(code), Some(label)) = (code_opt, label_opt) {
            units_out.insert(code, label);
        }
    }
}

fn resolve_unit_text(raw: Option<&str>, unit_types: &BTreeMap<u64, String>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(code) = parse_ecat_int(trimmed) {
        if let Some(lbl) = unit_types.get(&code) {
            return Some(lbl.clone());
        }
    }
    Some(trimmed.to_string())
}

fn extract_node_unit(node: &XmlNode, unit_types: &BTreeMap<u64, String>) -> Option<String> {
    let raw = node
        .child("Info")
        .and_then(|i| i.child_text("Unit"))
        .or_else(|| node.child_text("Unit"));
    resolve_unit_text(raw, unit_types)
}

fn parse_objects_node(
    objs_parent: &XmlNode,
    datatypes: &BTreeMap<String, XmlDataType>,
    unit_types: &BTreeMap<u64, String>,
    objects_out: &mut BTreeMap<u16, OdObject>,
) {
    for obj_node in objs_parent.children_named("Object") {
        let Some(idx_u64) = obj_node.child_text("Index").and_then(parse_ecat_int) else {
            continue;
        };
        let index = idx_u64 as u16;
        let name = obj_node
            .child_text("Name")
            .unwrap_or("Unnamed Object")
            .to_string();
        let raw_type = obj_node.child_text("Type").unwrap_or("BYTE").to_string();
        let bit_size = obj_node
            .child_text("BitSize")
            .and_then(parse_ecat_int)
            .unwrap_or(0) as u32;
        let (obj_access, obj_pdo_map) = parse_flags_node(obj_node.child("Flags"));
        let info_node = obj_node.child("Info");
        let obj_unit = extract_node_unit(obj_node, unit_types);

        // Collect `<Info><SubItem>` overrides if present
        let info_subitems: Vec<&XmlNode> = info_node
            .map(|inf| inf.children_named("SubItem").collect())
            .unwrap_or_default();

        let dt_def = datatypes.get(&raw_type.to_ascii_uppercase());
        let mut subentries = BTreeMap::new();
        let object_code: &'static str;

        if let Some(dt) = dt_def.filter(|d| !d.subitems.is_empty()) {
            // RECORD or ARRAY with explicit SubItems in <DataType>
            object_code = if dt.array_elements.is_some() {
                "ARRAY"
            } else {
                "RECORD"
            };
            let mut next_auto_sub = 0u8;
            for (pos_i, si_def) in dt.subitems.iter().enumerate() {
                let sidx = si_def.subindex.unwrap_or_else(|| {
                    let s = next_auto_sub;
                    next_auto_sub = next_auto_sub.saturating_add(1);
                    s
                });
                next_auto_sub = sidx.saturating_add(1);

                let (leaf_t, leaf_bits) =
                    resolve_leaf_type(&si_def.type_name, si_def.bit_size, datatypes);
                let ov = find_subitem_override(&info_subitems, sidx, pos_i);
                let ov_name = ov.and_then(|n| n.child_text("Name")).map(|s| s.to_string());
                let ov_def =
                    ov.and_then(|n| extract_default_hex(n.child("Info").or(Some(n)), leaf_bits));
                let ov_unit = ov.and_then(|n| extract_node_unit(n, unit_types));
                let (ov_access, ov_pdo_map) = parse_flags_node(ov.and_then(|n| n.child("Flags")));

                let wire_t = xml_type_to_wire_spec(&leaf_t, leaf_bits);
                let enums = resolve_enum_map(&si_def.type_name, datatypes);

                subentries.insert(
                    sidx,
                    OdSubEntry {
                        subindex: sidx,
                        name: ov_name.unwrap_or_else(|| si_def.name.clone()),
                        type_name: si_def.type_name.clone(),
                        wire_type: wire_t,
                        bit_length: leaf_bits,
                        bit_offset: si_def.bit_offset,
                        access: ov_access
                            .or_else(|| si_def.access.clone())
                            .or_else(|| obj_access.clone()),
                        pdo_mapping: ov_pdo_map
                            .or_else(|| si_def.pdo_mapping.clone())
                            .or_else(|| obj_pdo_map.clone()),
                        unit: ov_unit
                            .or_else(|| resolve_unit_text(si_def.unit.as_deref(), unit_types))
                            .or_else(|| (sidx > 0).then(|| obj_unit.clone()).flatten()),
                        default_hex: ov_def.or_else(|| si_def.default_hex.clone()),
                        enum_values: enums,
                    },
                );
            }
        } else if let Some(dt) = dt_def.filter(|d| d.array_elements.is_some()) {
            // Pure `<ArrayInfo>` DataType (e.g. `DT1C12 ARR` with `<BaseType>UINT</BaseType>`)
            object_code = "ARRAY";
            let (lbound, elems) = dt.array_elements.unwrap_or((1, 0));
            let elem_type = dt.base_type.as_deref().unwrap_or("BYTE");
            let (leaf_t, elem_bits) = resolve_leaf_type(elem_type, 0, datatypes);
            let wire_t = xml_type_to_wire_spec(&leaf_t, elem_bits);
            let enums = resolve_enum_map(elem_type, datatypes);

            if lbound > 0 {
                let sub0_ov = find_subitem_override(&info_subitems, 0, 0);
                let (s0_acc, _) = parse_flags_node(sub0_ov.and_then(|n| n.child("Flags")));
                subentries.insert(
                    0,
                    OdSubEntry {
                        subindex: 0,
                        name: sub0_ov
                            .and_then(|n| n.child_text("Name"))
                            .unwrap_or("SubIndex 000")
                            .to_string(),
                        type_name: "USINT".into(),
                        wire_type: DataTypeSpec::U8,
                        bit_length: 8,
                        bit_offset: Some(0),
                        access: s0_acc.or_else(|| obj_access.clone()),
                        pdo_mapping: None,
                        unit: None,
                        default_hex: sub0_ov
                            .and_then(|n| extract_default_hex(n.child("Info").or(Some(n)), 8)),
                        enum_values: BTreeMap::new(),
                    },
                );
            }

            for k in 0..elems {
                let Some(sidx_u16) = lbound.checked_add(k) else {
                    break;
                };
                let Ok(sidx) = u8::try_from(sidx_u16) else {
                    break;
                };
                let ov_idx = if lbound > 0 {
                    (k + 1) as usize
                } else {
                    k as usize
                };
                let ov = find_subitem_override(&info_subitems, sidx, ov_idx);
                let (ov_acc, ov_pdo) = parse_flags_node(ov.and_then(|n| n.child("Flags")));
                let bit_off = if lbound > 0 {
                    16 + (k as u32) * elem_bits
                } else {
                    (k as u32) * elem_bits
                };
                subentries.insert(
                    sidx,
                    OdSubEntry {
                        subindex: sidx,
                        name: ov
                            .and_then(|n| n.child_text("Name"))
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| format!("SubIndex {sidx:03}")),
                        type_name: elem_type.to_string(),
                        wire_type: wire_t,
                        bit_length: elem_bits,
                        bit_offset: Some(bit_off),
                        access: ov_acc.or_else(|| obj_access.clone()),
                        pdo_mapping: ov_pdo.or_else(|| obj_pdo_map.clone()),
                        unit: ov
                            .and_then(|n| extract_node_unit(n, unit_types))
                            .or_else(|| obj_unit.clone()),
                        default_hex: ov.and_then(|n| {
                            extract_default_hex(n.child("Info").or(Some(n)), elem_bits)
                        }),
                        enum_values: enums.clone(),
                    },
                );
            }
        } else if !info_subitems.is_empty() {
            // Inline `<Info><SubItem>` without a separate `<DataType>` struct
            object_code = "RECORD";
            for (pos_i, si_node) in info_subitems.iter().enumerate() {
                let sidx = si_node
                    .child_text("SubIdx")
                    .and_then(parse_ecat_int)
                    .map(|v| v as u8)
                    .unwrap_or(pos_i as u8);
                let sname = si_node
                    .child_text("Name")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("SubIndex {sidx:03}"));
                let stype = si_node.child_text("Type").unwrap_or("UINT").to_string();
                let sbits_raw = si_node
                    .child_text("BitSize")
                    .and_then(parse_ecat_int)
                    .unwrap_or(0) as u32;
                let (leaf_t, leaf_bits) = resolve_leaf_type(&stype, sbits_raw, datatypes);
                let (si_access, si_pdo_map) = parse_flags_node(si_node.child("Flags"));
                subentries.insert(
                    sidx,
                    OdSubEntry {
                        subindex: sidx,
                        name: sname,
                        type_name: stype.clone(),
                        wire_type: xml_type_to_wire_spec(&leaf_t, leaf_bits),
                        bit_length: leaf_bits,
                        bit_offset: si_node
                            .child_text("BitOffs")
                            .and_then(parse_ecat_int)
                            .map(|v| v as u32),
                        access: si_access.or_else(|| obj_access.clone()),
                        pdo_mapping: si_pdo_map.or_else(|| obj_pdo_map.clone()),
                        unit: extract_node_unit(si_node, unit_types)
                            .or_else(|| (sidx > 0).then(|| obj_unit.clone()).flatten()),
                        default_hex: extract_default_hex(
                            si_node.child("Info").or(Some(si_node)),
                            leaf_bits,
                        ),
                        enum_values: resolve_enum_map(&stype, datatypes),
                    },
                );
            }
        } else {
            // Scalar VAR object (`subindex 0`)
            object_code = "VAR";
            let (leaf_t, leaf_bits) = resolve_leaf_type(&raw_type, bit_size, datatypes);
            let def_hex = extract_default_hex(info_node, leaf_bits);
            subentries.insert(
                0,
                OdSubEntry {
                    subindex: 0,
                    name: name.clone(),
                    type_name: raw_type.clone(),
                    wire_type: xml_type_to_wire_spec(&leaf_t, leaf_bits),
                    bit_length: leaf_bits,
                    bit_offset: Some(0),
                    access: obj_access,
                    pdo_mapping: obj_pdo_map,
                    unit: obj_unit,
                    default_hex: def_hex,
                    enum_values: resolve_enum_map(&raw_type, datatypes),
                },
            );
        }

        objects_out.insert(
            index,
            OdObject {
                index,
                name,
                object_code,
                type_name: raw_type,
                bit_size,
                subentries,
            },
        );
    }
}

fn backfill_resolved_units(
    objects: &mut BTreeMap<u16, OdObject>,
    unit_types: &BTreeMap<u64, String>,
) {
    if unit_types.is_empty() {
        return;
    }
    for obj in objects.values_mut() {
        for sub in obj.subentries.values_mut() {
            if let Some(cur) = sub.unit.as_deref() {
                if let Some(resolved) = resolve_unit_text(Some(cur), unit_types) {
                    sub.unit = Some(resolved);
                }
            }
        }
    }
}

fn parse_dictionary_section(
    dict_node: &XmlNode,
    base_dir: Option<&Path>,
    datatypes: &mut BTreeMap<String, XmlDataType>,
    unit_types: &mut BTreeMap<u64, String>,
    objects: &mut BTreeMap<u16, OdObject>,
) {
    if let Some(uts) = dict_node.child("UnitTypes") {
        parse_unit_types_node(uts, unit_types);
    }
    if let Some(dts) = dict_node.child("DataTypes") {
        parse_datatypes_node(dts, datatypes);
    }
    if let Some(objs) = dict_node.child("Objects") {
        parse_objects_node(objs, datatypes, unit_types, objects);
    }
    // Follow `<InfoReference>` external dictionary includes if present
    if let Some(dir) = base_dir {
        for iref in dict_node.children_named("InfoReference") {
            let rel = iref.text.trim();
            if rel.is_empty() {
                continue;
            }
            let target = dir.join(rel);
            if let Ok(raw) = fs::read(&target) {
                if let Ok(txt) = decode_xml_bytes(&raw) {
                    if let Ok(ext_root) = parse_xml_document(&txt) {
                        let dnode = if ext_root.tag.eq_ignore_ascii_case("Dictionary") {
                            Some(&ext_root)
                        } else {
                            ext_root.child("Dictionary")
                        };
                        if let Some(dn) = dnode {
                            parse_dictionary_section(
                                dn,
                                target.parent(),
                                datatypes,
                                unit_types,
                                objects,
                            );
                        }
                    }
                }
            }
        }
    }
    backfill_resolved_units(objects, unit_types);
}

fn parse_pdo_node(
    pdo_node: &XmlNode,
    direction: PdoDirection,
    objects: &BTreeMap<u16, OdObject>,
    datatypes: &BTreeMap<String, XmlDataType>,
    unit_types: &BTreeMap<u64, String>,
) -> Option<XmlPdoDef> {
    let pdo_index = pdo_node.child_text("Index").and_then(parse_ecat_int)? as u16;
    let name = pdo_node
        .child_text("Name")
        .unwrap_or_else(|| direction.label())
        .to_string();
    let default_sm = pdo_node
        .attr("Sm")
        .and_then(parse_ecat_int)
        .map(|v| v as u8);
    let fixed = parse_bool_attr(pdo_node.attr("Fixed"), false);
    let mandatory = parse_bool_attr(pdo_node.attr("Mandatory"), false);

    let mut entries = Vec::new();
    for entry_node in pdo_node.children_named("Entry") {
        let entry_index = entry_node
            .child_text("Index")
            .and_then(parse_ecat_int)
            .unwrap_or(0) as u16;
        let entry_subindex = entry_node
            .child_text("SubIndex")
            .and_then(parse_ecat_int)
            .unwrap_or(0) as u8;
        let bit_length = entry_node
            .child_text("BitLen")
            .and_then(parse_ecat_int)
            .unwrap_or(0) as u16;

        let explicit_name = entry_node.child_text("Name").map(|s| s.to_string());
        let explicit_dt = entry_node.child_text("DataType").map(|s| s.to_string());
        let explicit_unit = resolve_unit_text(entry_node.child_text("Unit"), unit_types);

        let (ename, dt_name, unit, wire_t, enums) = if entry_index == 0 {
            (
                explicit_name.unwrap_or_else(|| "Gap/Padding".into()),
                explicit_dt.unwrap_or_else(|| format!("BIT{bit_length}")),
                None,
                DataTypeSpec::Hex,
                BTreeMap::new(),
            )
        } else if let Some(sub) = objects
            .get(&entry_index)
            .and_then(|o| o.subentries.get(&entry_subindex))
        {
            let obj_n = &objects[&entry_index].name;
            let resolved_n = explicit_name.unwrap_or_else(|| {
                if entry_subindex == 0 || sub.name.eq_ignore_ascii_case(obj_n) {
                    obj_n.clone()
                } else {
                    format!("{obj_n}.{}", sub.name)
                }
            });
            let (dtn, wt, enums) = if let Some(exp_dt) = explicit_dt {
                let (leaf_t, _) = resolve_leaf_type(&exp_dt, bit_length as u32, datatypes);
                let wt = xml_type_to_wire_spec(&leaf_t, bit_length as u32);
                let mut enums = resolve_enum_map(&exp_dt, datatypes);
                if enums.is_empty() {
                    enums = sub.enum_values.clone();
                }
                (exp_dt, wt, enums)
            } else {
                (
                    sub.type_name.clone(),
                    sub.wire_type,
                    sub.enum_values.clone(),
                )
            };
            (
                resolved_n,
                dtn,
                explicit_unit.or_else(|| sub.unit.clone()),
                wt,
                enums,
            )
        } else if let Some(dtn) = explicit_dt {
            let (leaf_t, _) = resolve_leaf_type(&dtn, bit_length as u32, datatypes);
            let wt = xml_type_to_wire_spec(&leaf_t, bit_length as u32);
            let enums = resolve_enum_map(&dtn, datatypes);
            (
                explicit_name
                    .unwrap_or_else(|| format!("0x{entry_index:04x}:{entry_subindex:02x}")),
                dtn,
                explicit_unit,
                wt,
                enums,
            )
        } else {
            let (dtn, wt) = default_type_for_bits(bit_length);
            (
                explicit_name
                    .unwrap_or_else(|| format!("0x{entry_index:04x}:{entry_subindex:02x}")),
                dtn.to_string(),
                explicit_unit,
                wt,
                BTreeMap::new(),
            )
        };

        entries.push(XmlPdoEntry {
            entry_index,
            entry_subindex,
            bit_length,
            name: ename,
            data_type: dt_name,
            unit,
            wire_type: wire_t,
            enum_values: enums,
        });
    }

    Some(XmlPdoDef {
        pdo_index,
        name,
        direction,
        default_sm,
        fixed,
        mandatory,
        eni_bit_offset: None,
        entries,
    })
}

/// Synthesizes candidate PDO definitions from Object Dictionary `0x1600..0x17FF` / `0x1A00..0x1BFF`
/// default values when `<RxPdo>` / `<TxPdo>` XML blocks were not explicitly provided (e.g. `<EtherCATDict>`).
fn synthesize_pdos_from_od(dev: &mut XmlDeviceProfile) {
    // Check 0x1C12 / 0x1C13 default assignments if present
    let assigned_rx: Vec<u16> = extract_od_u16_list(dev.objects.get(&0x1C12));
    let assigned_tx: Vec<u16> = extract_od_u16_list(dev.objects.get(&0x1C13));

    let pdo_indices: Vec<u16> = dev
        .objects
        .keys()
        .copied()
        .filter(|&idx| (0x1600..=0x17FF).contains(&idx) || (0x1A00..=0x1BFF).contains(&idx))
        .collect();

    for pdo_idx in pdo_indices {
        let is_rx = (0x1600..=0x17FF).contains(&pdo_idx);
        if (is_rx && dev.rx_pdos.contains_key(&pdo_idx))
            || (!is_rx && dev.tx_pdos.contains_key(&pdo_idx))
        {
            continue;
        }
        let Some(obj) = dev.objects.get(&pdo_idx) else {
            continue;
        };
        let count = obj
            .subentries
            .get(&0)
            .and_then(|s| s.default_hex.as_deref())
            .and_then(|h| hex::decode(h).ok())
            .and_then(|b| b.first().copied())
            .unwrap_or((obj.subentries.len().saturating_sub(1)) as u8);

        let mut raw_maps = Vec::new();
        for sub_k in 1..=count {
            let Some(sub) = obj.subentries.get(&sub_k) else {
                continue;
            };
            let Some(def_h) = &sub.default_hex else {
                continue;
            };
            let Ok(bytes) = hex::decode(def_h) else {
                continue;
            };
            if bytes.len() >= 4 {
                let map_u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let bit_len = (map_u32 & 0xFF) as u16;
                let esub = ((map_u32 >> 8) & 0xFF) as u8;
                let eidx = ((map_u32 >> 16) & 0xFFFF) as u16;
                if bit_len > 0 {
                    raw_maps.push((eidx, esub, bit_len));
                }
            }
        }
        if raw_maps.is_empty() {
            continue;
        }
        let pdo_name = obj.name.clone();
        let entries: Vec<XmlPdoEntry> = raw_maps
            .into_iter()
            .map(|(eidx, esub, blen)| dev.resolve_pdo_entry(eidx, esub, blen))
            .collect();
        let def_sm = if is_rx && assigned_rx.contains(&pdo_idx) {
            Some(2)
        } else if !is_rx && assigned_tx.contains(&pdo_idx) {
            Some(3)
        } else {
            None
        };
        let pdo_def = XmlPdoDef {
            pdo_index: pdo_idx,
            name: pdo_name,
            direction: if is_rx {
                PdoDirection::RxPdo
            } else {
                PdoDirection::TxPdo
            },
            default_sm: def_sm,
            fixed: false,
            mandatory: false,
            eni_bit_offset: None,
            entries,
        };
        if is_rx {
            dev.rx_pdos.insert(pdo_idx, pdo_def);
        } else {
            dev.tx_pdos.insert(pdo_idx, pdo_def);
        }
    }
}

fn extract_od_u16_list(obj: Option<&OdObject>) -> Vec<u16> {
    let Some(o) = obj else {
        return Vec::new();
    };
    let explicit_cnt = o
        .subentries
        .get(&0)
        .and_then(|s| s.default_hex.as_deref())
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| b.first().copied());
    let mut out = Vec::new();
    for (&sub_k, sub) in &o.subentries {
        if sub_k == 0 {
            continue;
        }
        if let Some(max_k) = explicit_cnt {
            if sub_k > max_k {
                break;
            }
        }
        if let Some(h) = &sub.default_hex {
            if let Ok(b) = hex::decode(h) {
                if b.len() >= 2 {
                    let val = u16::from_le_bytes([b[0], b[1]]);
                    if val != 0 {
                        out.push(val);
                    }
                }
            }
        }
    }
    out
}

fn parse_slots_node(slots_node: Option<&XmlNode>) -> (Option<XmlSlotsSpec>, Vec<u32>) {
    let Some(sn) = slots_node else {
        return (None, Vec::new());
    };
    let pdo_inc = sn
        .attr("SlotPdoIncrement")
        .or_else(|| sn.child_text("SlotPdoIncrement"))
        .and_then(parse_ecat_int)
        .unwrap_or(1) as u16;
    let idx_inc = sn
        .attr("SlotIndexIncrement")
        .or_else(|| sn.child_text("SlotIndexIncrement"))
        .and_then(parse_ecat_int)
        .unwrap_or(0x0010) as u16;
    let slot_elems: Vec<&XmlNode> = sn.children_named("Slot").collect();
    let max_slots = sn
        .attr("MaxSlotCount")
        .or_else(|| sn.child_text("MaxSlotCount"))
        .and_then(parse_ecat_int)
        .map(|v| v as usize)
        .unwrap_or_else(|| slot_elems.len().max(1));
    let mut default_idents = Vec::new();
    for s in slot_elems {
        if let Some(mi) = s
            .child_text("ModuleIdent")
            .or_else(|| s.attr("ModuleIdent"))
            .or_else(|| s.child_text("Default"))
            .and_then(parse_ecat_int)
        {
            default_idents.push(mi as u32);
        }
    }
    (
        Some(XmlSlotsSpec {
            slot_pdo_increment: pdo_inc,
            slot_index_increment: idx_inc,
            max_slot_count: max_slots,
        }),
        default_idents,
    )
}

fn parse_esi_root(root: &XmlNode, base_dir: Option<&Path>) -> Result<XmlCatalog> {
    let vendor_node = root.child("Vendor");
    let vendor_id = vendor_node
        .and_then(|v| v.child_text("Id"))
        .and_then(parse_ecat_int)
        .map(|v| v as u32);
    let vendor_name = vendor_node
        .and_then(|v| v.child_text("Name"))
        .map(|s| s.to_string());

    let Some(desc) = root.child("Descriptions") else {
        return Err(CliError::Format(
            "<EtherCATInfo> missing <Descriptions> section".into(),
        ));
    };

    // Parse optional `<Modules><Module>` library for MDP modular slaves
    let mut parsed_modules = Vec::new();
    let mut shared_mod_datatypes = BTreeMap::new();
    let mut shared_mod_units = BTreeMap::new();
    if let Some(mods) = desc.child("Modules") {
        for mnode in mods.children_named("Module") {
            let mtype = mnode.child("Type");
            let mod_ident = mtype
                .and_then(|t| t.attr("ModuleIdent").or_else(|| t.attr("ModuleClass")))
                .and_then(parse_ecat_int)
                .map(|v| v as u32);
            let mod_name = mnode
                .child_text("Name")
                .or_else(|| mtype.map(|t| t.text.trim()).filter(|s| !s.is_empty()))
                .unwrap_or("Module")
                .to_string();

            let mut m_dts = BTreeMap::new();
            let mut m_units = BTreeMap::new();
            let mut m_objs = BTreeMap::new();
            for pnode in mnode.children_named("Profile") {
                if let Some(dnode) = pnode.child("Dictionary") {
                    parse_dictionary_section(
                        dnode,
                        base_dir,
                        &mut m_dts,
                        &mut m_units,
                        &mut m_objs,
                    );
                }
            }
            for (k, v) in &m_dts {
                shared_mod_datatypes
                    .entry(k.clone())
                    .or_insert_with(|| v.clone());
            }
            for (&k, v) in &m_units {
                shared_mod_units.entry(k).or_insert_with(|| v.clone());
            }
            let mut m_rx = Vec::new();
            let mut m_tx = Vec::new();
            for rx in mnode.children_named("RxPdo") {
                if let Some(p) = parse_pdo_node(rx, PdoDirection::RxPdo, &m_objs, &m_dts, &m_units)
                {
                    m_rx.push(p);
                }
            }
            for tx in mnode.children_named("TxPdo") {
                if let Some(p) = parse_pdo_node(tx, PdoDirection::TxPdo, &m_objs, &m_dts, &m_units)
                {
                    m_tx.push(p);
                }
            }
            parsed_modules.push(XmlModuleDef {
                module_ident: mod_ident,
                name: mod_name,
                objects: m_objs,
                rx_pdos: m_rx,
                tx_pdos: m_tx,
            });
        }
    }

    let mut devices = Vec::new();
    if let Some(devs_node) = desc.child("Devices") {
        for dev_node in devs_node.children_named("Device") {
            let type_node = dev_node.child("Type");
            let type_code = type_node
                .map(|t| t.text.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "Unknown".into());
            let product_code = type_node
                .and_then(|t| t.attr("ProductCode"))
                .and_then(parse_ecat_int)
                .map(|v| v as u32);
            let revision_no = type_node
                .and_then(|t| t.attr("RevisionNo"))
                .and_then(parse_ecat_int)
                .map(|v| v as u32);
            let name = dev_node
                .child_text("Name")
                .unwrap_or(&type_code)
                .to_string();

            let coe_node = dev_node.child("Mailbox").and_then(|m| m.child("CoE"));
            let coe_flags_explicit = coe_node
                .is_some_and(|c| c.attr("PdoAssign").is_some() || c.attr("PdoConfig").is_some());
            let coe_pdo_assign =
                coe_node.is_some_and(|c| parse_bool_attr(c.attr("PdoAssign"), false));
            let coe_pdo_config =
                coe_node.is_some_and(|c| parse_bool_attr(c.attr("PdoConfig"), false));

            let mut sync_managers = Vec::new();
            for (sm_i, sm_node) in dev_node.children_named("Sm").enumerate() {
                sync_managers.push(XmlSmDef {
                    sm_index: sm_i as u8,
                    role: sm_node.text.trim().to_string(),
                    start_address: sm_node
                        .attr("StartAddress")
                        .and_then(parse_ecat_int)
                        .map(|v| v as u16),
                    default_size: sm_node
                        .attr("DefaultSize")
                        .and_then(parse_ecat_int)
                        .map(|v| v as u16),
                    control_byte: sm_node
                        .attr("ControlByte")
                        .and_then(parse_ecat_int)
                        .map(|v| v as u8),
                    enable: parse_bool_attr(sm_node.attr("Enable"), true),
                });
            }

            let mut datatypes = shared_mod_datatypes.clone();
            let mut unit_types = shared_mod_units.clone();
            let mut objects = BTreeMap::new();
            for pnode in dev_node.children_named("Profile") {
                if let Some(dnode) = pnode.child("Dictionary") {
                    parse_dictionary_section(
                        dnode,
                        base_dir,
                        &mut datatypes,
                        &mut unit_types,
                        &mut objects,
                    );
                }
                if let Some(df_txt) = pnode.child_text("DictionaryFile") {
                    if let Some(dir) = base_dir {
                        let target = dir.join(df_txt.trim());
                        if let Ok(raw) = fs::read(&target) {
                            if let Ok(txt) = decode_xml_bytes(&raw) {
                                if let Ok(ext_root) = parse_xml_document(&txt) {
                                    let dnode = if ext_root.tag.eq_ignore_ascii_case("Dictionary") {
                                        Some(&ext_root)
                                    } else {
                                        ext_root.child("Dictionary")
                                    };
                                    if let Some(dn) = dnode {
                                        parse_dictionary_section(
                                            dn,
                                            target.parent(),
                                            &mut datatypes,
                                            &mut unit_types,
                                            &mut objects,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let mut rx_pdos = BTreeMap::new();
            let mut tx_pdos = BTreeMap::new();
            for rx in dev_node.children_named("RxPdo") {
                if let Some(p) =
                    parse_pdo_node(rx, PdoDirection::RxPdo, &objects, &datatypes, &unit_types)
                {
                    rx_pdos.insert(p.pdo_index, p);
                }
            }
            for tx in dev_node.children_named("TxPdo") {
                if let Some(p) =
                    parse_pdo_node(tx, PdoDirection::TxPdo, &objects, &datatypes, &unit_types)
                {
                    tx_pdos.insert(p.pdo_index, p);
                }
            }

            let (slots_spec, default_slot_idents) = parse_slots_node(dev_node.child("Slots"));
            let dev_modules = if slots_spec.is_some() {
                parsed_modules.clone()
            } else {
                Vec::new()
            };
            let coe_supported =
                coe_node.is_some() || !objects.is_empty() || !dev_modules.is_empty();

            let mut profile = XmlDeviceProfile {
                vendor_id,
                vendor_name: vendor_name.clone(),
                type_code,
                name,
                product_code,
                revision_no,
                configured_station_addr: None,
                is_eni: false,
                coe_flags_explicit,
                coe_supported,
                coe_pdo_assign: coe_pdo_assign || slots_spec.is_some(),
                coe_pdo_config,
                sync_managers,
                objects,
                rx_pdos,
                tx_pdos,
                slots: slots_spec,
                modules: dev_modules,
                has_mdp_base_snapshot: false,
                base_objects: BTreeMap::new(),
                base_rx_pdos: BTreeMap::new(),
                base_tx_pdos: BTreeMap::new(),
            };
            synthesize_pdos_from_od(&mut profile);

            if slots_spec.is_some() && !profile.modules.is_empty() {
                profile.base_objects = profile.objects.clone();
                profile.base_rx_pdos = profile.rx_pdos.clone();
                profile.base_tx_pdos = profile.tx_pdos.clone();
                profile.has_mdp_base_snapshot = true;

                // Only instantiate explicit `<Slot><ModuleIdent>` defaults statically;
                // unassigned `<Modules>` libraries wait for runtime `0xF030` selection.
                for (slot_i, m_ident) in default_slot_idents.iter().copied().enumerate() {
                    if let Some(mdef) = profile
                        .modules
                        .iter()
                        .find(|m| m.module_ident == Some(m_ident))
                        .cloned()
                    {
                        let (srx, stx, sobjs) = profile.instantiate_module_at_slot(slot_i, &mdef);
                        for (k, v) in sobjs {
                            profile.objects.entry(k).or_insert(v);
                        }
                        for p in srx {
                            profile.rx_pdos.entry(p.pdo_index).or_insert(p);
                        }
                        for p in stx {
                            profile.tx_pdos.entry(p.pdo_index).or_insert(p);
                        }
                    }
                }
                synthesize_pdos_from_od(&mut profile);
            }

            devices.push(profile);
        }
    }

    if devices.is_empty() {
        return Err(CliError::Format(
            "<EtherCATInfo> contains no <Device> definitions".into(),
        ));
    }

    Ok(XmlCatalog {
        source_kind: "EtherCATInfo (ESI)".into(),
        devices,
    })
}

fn parse_dict_root(root: &XmlNode, base_dir: Option<&Path>) -> Result<XmlCatalog> {
    let dict_node = if root.tag.eq_ignore_ascii_case("Dictionary") {
        root
    } else {
        root.child("Dictionary")
            .ok_or_else(|| CliError::Format("<EtherCATDict> missing <Dictionary> child".into()))?
    };

    let mut datatypes = BTreeMap::new();
    let mut unit_types = BTreeMap::new();
    let mut objects = BTreeMap::new();
    parse_dictionary_section(
        dict_node,
        base_dir,
        &mut datatypes,
        &mut unit_types,
        &mut objects,
    );

    let dev_name = objects
        .get(&0x1008)
        .and_then(|o| o.subentries.get(&0))
        .and_then(|s| s.default_hex.as_deref())
        .and_then(|h| hex::decode(h).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .map(|s| s.trim_end_matches('\0').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "EtherCATDict".into());

    let mut profile = XmlDeviceProfile {
        vendor_id: None,
        vendor_name: None,
        type_code: dev_name.clone(),
        name: dev_name,
        product_code: None,
        revision_no: None,
        configured_station_addr: None,
        is_eni: false,
        coe_flags_explicit: false,
        coe_supported: true,
        coe_pdo_assign: false,
        coe_pdo_config: false,
        sync_managers: Vec::new(),
        objects,
        rx_pdos: BTreeMap::new(),
        tx_pdos: BTreeMap::new(),
        slots: None,
        modules: Vec::new(),
        has_mdp_base_snapshot: false,
        base_objects: BTreeMap::new(),
        base_rx_pdos: BTreeMap::new(),
        base_tx_pdos: BTreeMap::new(),
    };
    synthesize_pdos_from_od(&mut profile);

    Ok(XmlCatalog {
        source_kind: "EtherCATDict (OD)".into(),
        devices: vec![profile],
    })
}

struct EniSpanCursor {
    spans: Vec<(usize, Option<usize>)>,
    span_idx: usize,
    used_in_span: usize,
}

impl EniSpanCursor {
    fn from_nodes<'a>(nodes: impl Iterator<Item = &'a XmlNode>) -> Self {
        let mut spans = Vec::new();
        for n in nodes {
            if let Some(bs) = n.child_text("BitStart").and_then(parse_ecat_int) {
                let bl = n
                    .child_text("BitLength")
                    .and_then(parse_ecat_int)
                    .map(|v| v as usize);
                spans.push((bs as usize, bl));
            }
        }
        Self {
            spans,
            span_idx: 0,
            used_in_span: 0,
        }
    }

    fn alloc(&mut self, pdo_bits: usize) -> Option<usize> {
        let (start, len_opt) = *self.spans.get(self.span_idx)?;
        if let Some(span_len) = len_opt {
            if self.used_in_span > 0
                && self.used_in_span + pdo_bits > span_len
                && self.span_idx + 1 < self.spans.len()
            {
                self.span_idx += 1;
                self.used_in_span = pdo_bits;
                return Some(self.spans[self.span_idx].0);
            }
        }
        let off = start + self.used_in_span;
        self.used_in_span += pdo_bits;
        Some(off)
    }
}

fn parse_eni_root(root: &XmlNode) -> Result<XmlCatalog> {
    let cfg = root
        .child("Config")
        .ok_or_else(|| CliError::Format("<EtherCATConfig> missing <Config> section".into()))?;

    let mut devices = Vec::new();
    for slave_node in cfg.children_named("Slave") {
        let info = slave_node.child("Info");
        let name = info
            .and_then(|i| i.child_text("Name"))
            .unwrap_or("ENI Slave")
            .to_string();
        let phys_addr = info
            .and_then(|i| i.child_text("PhysAddr"))
            .and_then(parse_ecat_int)
            .map(|v| v as u16);
        let vendor_id = info
            .and_then(|i| i.child_text("VendorId"))
            .and_then(parse_ecat_int)
            .map(|v| v as u32);
        let product_code = info
            .and_then(|i| i.child_text("ProductCode"))
            .and_then(parse_ecat_int)
            .map(|v| v as u32);
        let revision_no = info
            .and_then(|i| i.child_text("RevisionNo"))
            .and_then(parse_ecat_int)
            .map(|v| v as u32);

        let mut rx_pdos = BTreeMap::new();
        let mut tx_pdos = BTreeMap::new();
        let mut sync_managers = Vec::new();
        let mut objects = BTreeMap::new();
        let datatypes = BTreeMap::new();
        let unit_types = BTreeMap::new();

        if let Some(pd) = slave_node.child("ProcessData") {
            let mut rx_cursor = EniSpanCursor::from_nodes(pd.children_named("Send"));
            let mut tx_cursor = EniSpanCursor::from_nodes(pd.children_named("Recv"));

            for sm_i in 0..8u8 {
                let tag = format!("Sm{sm_i}");
                if let Some(sm_n) = pd.child(&tag) {
                    let role = sm_n.child_text("Type").unwrap_or("").to_string();
                    sync_managers.push(XmlSmDef {
                        sm_index: sm_i,
                        role: role.clone(),
                        start_address: sm_n
                            .child_text("StartAddress")
                            .and_then(parse_ecat_int)
                            .map(|v| v as u16),
                        default_size: None,
                        control_byte: sm_n
                            .child_text("ControlByte")
                            .and_then(parse_ecat_int)
                            .map(|v| v as u8),
                        enable: parse_bool_attr(sm_n.child_text("Enable"), true),
                    });

                    // Support ENI variants that nest `<Pdo>`/`<RxPdo>`/`<TxPdo>` inside `<Sm{i}>`
                    let is_out = role.eq_ignore_ascii_case("Outputs") || sm_i == 2;
                    for child_pdo in sm_n.children.iter().filter(|c| {
                        c.tag.eq_ignore_ascii_case("Pdo")
                            || c.tag.eq_ignore_ascii_case("RxPdo")
                            || c.tag.eq_ignore_ascii_case("TxPdo")
                    }) {
                        let dir = if child_pdo.tag.eq_ignore_ascii_case("TxPdo")
                            || (!child_pdo.tag.eq_ignore_ascii_case("RxPdo") && !is_out)
                        {
                            PdoDirection::TxPdo
                        } else {
                            PdoDirection::RxPdo
                        };
                        if let Some(mut p) =
                            parse_pdo_node(child_pdo, dir, &objects, &datatypes, &unit_types)
                        {
                            p.default_sm.get_or_insert(sm_i);
                            match dir {
                                PdoDirection::RxPdo => {
                                    p.eni_bit_offset = rx_cursor.alloc(p.total_bits());
                                    register_pdo_entries_into_od(&p, &mut objects);
                                    rx_pdos.insert(p.pdo_index, p);
                                }
                                PdoDirection::TxPdo => {
                                    p.eni_bit_offset = tx_cursor.alloc(p.total_bits());
                                    register_pdo_entries_into_od(&p, &mut objects);
                                    tx_pdos.insert(p.pdo_index, p);
                                }
                            }
                        }
                    }
                }
            }

            for rx in pd.children_named("RxPdo") {
                if let Some(mut p) =
                    parse_pdo_node(rx, PdoDirection::RxPdo, &objects, &datatypes, &unit_types)
                {
                    p.eni_bit_offset = rx_cursor.alloc(p.total_bits());
                    // Register PDO entries in `objects` too so SDO accesses to those indices resolve names/types!
                    register_pdo_entries_into_od(&p, &mut objects);
                    rx_pdos.insert(p.pdo_index, p);
                }
            }
            for tx in pd.children_named("TxPdo") {
                if let Some(mut p) =
                    parse_pdo_node(tx, PdoDirection::TxPdo, &objects, &datatypes, &unit_types)
                {
                    p.eni_bit_offset = tx_cursor.alloc(p.total_bits());
                    register_pdo_entries_into_od(&p, &mut objects);
                    tx_pdos.insert(p.pdo_index, p);
                }
            }
        }

        // Also harvest `<Mailbox><CoE><InitCmds>` (including multi-subentry & CompleteAccess InitCmds)
        let coe_node = slave_node.child("Mailbox").and_then(|m| m.child("CoE"));
        if let Some(init_cmds) = coe_node.and_then(|c| c.child("InitCmds")) {
            for ic in init_cmds.children_named("InitCmd") {
                let Some(idx) = ic.child_text("Index").and_then(parse_ecat_int) else {
                    continue;
                };
                let idx16 = idx as u16;
                let sub = ic
                    .child_text("SubIndex")
                    .and_then(parse_ecat_int)
                    .unwrap_or(0) as u8;
                let ca = parse_bool_attr(
                    ic.attr("CompleteAccess")
                        .or_else(|| ic.child_text("CompleteAccess")),
                    false,
                );
                let data_hex = ic.child_text("Data").and_then(normalize_hex);
                let comment = ic
                    .child_text("Comment")
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let obj_label = comment
                    .clone()
                    .unwrap_or_else(|| format!("Object 0x{idx16:04X}"));

                let obj = objects.entry(idx16).or_insert_with(|| OdObject {
                    index: idx16,
                    name: obj_label.clone(),
                    object_code: if ca || sub > 0 { "ARRAY" } else { "VAR" },
                    type_name: "OCTET_STRING".into(),
                    bit_size: 0,
                    subentries: BTreeMap::new(),
                });

                if ca
                    && matches!(idx16, 0x1C12 | 0x1C13 | 0x1600..=0x17FF | 0x1A00..=0x1BFF)
                    && data_hex.is_some()
                {
                    if let Ok(raw) = hex::decode(data_hex.as_deref().unwrap_or_default()) {
                        let elem_sz = if matches!(idx16, 0x1C12 | 0x1C13) {
                            2usize
                        } else {
                            4usize
                        };
                        if raw.len() >= 2 {
                            let cnt = raw[0];
                            obj.subentries.insert(
                                0,
                                OdSubEntry {
                                    subindex: 0,
                                    name: "SubIndex 000".into(),
                                    type_name: "USINT".into(),
                                    wire_type: DataTypeSpec::U8,
                                    bit_length: 8,
                                    bit_offset: Some(0),
                                    access: Some("rw".into()),
                                    pdo_mapping: None,
                                    unit: None,
                                    default_hex: Some(hex::encode([cnt])),
                                    enum_values: BTreeMap::new(),
                                },
                            );
                            for k in 0..(cnt as usize) {
                                let off = 2 + k * elem_sz;
                                if off + elem_sz <= raw.len() {
                                    obj.subentries.insert(
                                        (k + 1) as u8,
                                        OdSubEntry {
                                            subindex: (k + 1) as u8,
                                            name: format!("SubIndex {:03}", k + 1),
                                            type_name: if elem_sz == 2 {
                                                "UINT".into()
                                            } else {
                                                "UDINT".into()
                                            },
                                            wire_type: if elem_sz == 2 {
                                                DataTypeSpec::U16
                                            } else {
                                                DataTypeSpec::U32
                                            },
                                            bit_length: (elem_sz * 8) as u32,
                                            bit_offset: Some((16 + k * elem_sz * 8) as u32),
                                            access: Some("rw".into()),
                                            pdo_mapping: None,
                                            unit: None,
                                            default_hex: Some(hex::encode(
                                                &raw[off..off + elem_sz],
                                            )),
                                            enum_values: BTreeMap::new(),
                                        },
                                    );
                                }
                            }
                            continue;
                        }
                    }
                }

                if comment.is_some() || data_hex.is_some() {
                    obj.subentries.insert(
                        sub,
                        OdSubEntry {
                            subindex: sub,
                            name: comment.unwrap_or_else(|| format!("SubIndex {sub:03}")),
                            type_name: "OCTET_STRING".into(),
                            wire_type: DataTypeSpec::Auto,
                            bit_length: 0,
                            bit_offset: None,
                            access: Some("rw".into()),
                            pdo_mapping: None,
                            unit: None,
                            default_hex: data_hex,
                            enum_values: BTreeMap::new(),
                        },
                    );
                }
            }
        }

        let coe_pdo_assign = objects.contains_key(&0x1C12) || objects.contains_key(&0x1C13);
        let coe_pdo_config = objects.keys().any(|&k| (0x1600..=0x1BFF).contains(&k));

        let mut profile = XmlDeviceProfile {
            vendor_id,
            vendor_name: None,
            type_code: name.clone(),
            name,
            product_code,
            revision_no,
            configured_station_addr: phys_addr,
            is_eni: true,
            coe_flags_explicit: false,
            coe_supported: coe_node.is_some() || !objects.is_empty(),
            coe_pdo_assign,
            coe_pdo_config,
            sync_managers,
            objects,
            rx_pdos,
            tx_pdos,
            slots: None,
            modules: Vec::new(),
            has_mdp_base_snapshot: false,
            base_objects: BTreeMap::new(),
            base_rx_pdos: BTreeMap::new(),
            base_tx_pdos: BTreeMap::new(),
        };
        synthesize_pdos_from_od(&mut profile);
        devices.push(profile);
    }

    if devices.is_empty() {
        return Err(CliError::Format(
            "<EtherCATConfig> contains no <Slave> definitions".into(),
        ));
    }

    Ok(XmlCatalog {
        source_kind: "EtherCATConfig (ENI)".into(),
        devices,
    })
}

fn register_pdo_entries_into_od(pdo: &XmlPdoDef, objects: &mut BTreeMap<u16, OdObject>) {
    for e in &pdo.entries {
        if e.entry_index == 0 {
            continue;
        }
        let obj = objects.entry(e.entry_index).or_insert_with(|| OdObject {
            index: e.entry_index,
            name: e.name.clone(),
            object_code: "VAR",
            type_name: e.data_type.clone(),
            bit_size: e.bit_length as u32,
            subentries: BTreeMap::new(),
        });
        obj.subentries
            .entry(e.entry_subindex)
            .or_insert_with(|| OdSubEntry {
                subindex: e.entry_subindex,
                name: e.name.clone(),
                type_name: e.data_type.clone(),
                wire_type: e.wire_type,
                bit_length: e.bit_length as u32,
                bit_offset: None,
                access: None,
                pdo_mapping: None,
                unit: e.unit.clone(),
                default_hex: None,
                enum_values: e.enum_values.clone(),
            });
    }
}
