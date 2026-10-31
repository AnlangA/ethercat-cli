//! Pure-Rust EtherCAT Slave Information (ESI `.xml`) & Offline Object Dictionary (`<EtherCATDict>`)
//! generator and in-place ESI updater.
//!
//! Reproduces `ET9300ProjectHandler.EsiGenerator`:
//! - `CreateDeviceDescription` / `CreateESIXmlDoc` (with UTF-8 BOM, `\t` indent, `\r\n`, canonical XSD ordering,
//!   user `EsiFragment` XPath injection + XSD re-sorting, `TEST_APPLICATION` `<TwinCAT>` & 4 DC `OpMode`s,
//!   `DIAGNOSIS_SUPPORTED` `<DiagMessages>`, `CiA402_SAMPLE_APPLICATION` `<Slots>` + `<Modules>`, dynamic MDP)
//! - `CreateOfflineDictionary` (`<?xml version="1.0"?>`, no BOM, 2-space indent, `EtherCATDict` `0.0.9`)
//! - `UpdateEsiFile` (`.bak` backup, preservation of 14 default SSC objects, `<Profile>`, `<Sm>`, `<RxPdo>`, `<TxPdo>`, `<CoE>`, `<Slots>`)

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::expr::{evaluate_boolean_expression, resolve_value_expression};
use crate::model::{EsiFragment, SlaveProject, STANDALONE_ESI_UPDATE_DEFAULT_SSC_OBJECTS};
use crate::od::builtin_ods::build_project_object_dictionary;
use crate::od::types::{
    create_esi_syntax_for_entry, reverse_hex_byte_pairs, EntryInfo, ModuleObjectInfoCollection,
    ObjectCode, ObjectInfo, ObjectInfoCollection, SlaveApplication,
};
use crate::xml_dom::{parse_dom_file, render_indented_xml_bytes, DomElement, DomNode};
use ethercat_wire::error::{CliError, Result};

const ESI_XML_PROLOG: &str = "<?xml version=\"1.0\" encoding=\"utf-8\"?>";
const OFFLINE_DICT_PROLOG: &str = "<?xml version=\"1.0\"?>";

/// Beckhoff's `EsiGenerator::GetInt32(string)`: strips `"0x"`/`"0X"` and parses as base-16 hex
/// EVEN when `"0x"` prefix is absent!
fn parse_esi_hex_i32(raw: &str) -> i32 {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return 0;
    }
    if !trimmed.contains("0x") && !trimmed.contains("0X") {
        return i32::from_str_radix(trimmed, 16).unwrap_or(0);
    }
    let no_prefix = trimmed.replace("0x", "").replace("0X", "");
    i32::from_str_radix(no_prefix.trim(), 16).unwrap_or(0)
}

fn hex_attr_hash(raw: &str) -> String {
    if !raw.contains("0x") && !raw.contains("0X") {
        return raw.to_string();
    }
    raw.replace("0x", "#x").replace("0X", "#x")
}

fn normalize_hex_binary(raw: &str, swapped: bool) -> String {
    let stripped: String = raw
        .trim()
        .replace("0x", "")
        .replace("0X", "")
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if stripped.is_empty() {
        return String::new();
    }
    let padded = if stripped.len() % 2 == 1 {
        format!("0{stripped}")
    } else {
        stripped
    };
    if swapped {
        reverse_hex_byte_pairs(&padded)
    } else {
        padded.to_ascii_uppercase()
    }
}

fn parse_esi_hex_u32_attr(raw: &str) -> u32 {
    let s = raw
        .trim()
        .trim_start_matches("#x")
        .trim_start_matches("#X")
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    if raw.trim().starts_with('#') || raw.trim().starts_with("0x") || raw.trim().starts_with("0X") {
        u32::from_str_radix(s, 16).unwrap_or(0)
    } else {
        s.parse::<u32>()
            .or_else(|_| u32::from_str_radix(s, 16))
            .unwrap_or(0)
    }
}

fn setting_bool(project: &SlaveProject, key: &str) -> bool {
    project.get_setting(key).is_some_and(|s| s.as_bool())
}

fn setting_u32(project: &SlaveProject, key: &str) -> u32 {
    project.get_setting(key).map(|s| s.as_u32()).unwrap_or(0)
}

fn setting_str<'a>(project: &'a SlaveProject, key: &str) -> &'a str {
    project.get_setting_value(key).unwrap_or("")
}

/// Build `<Profile>` (`DeviceTypeProfile::CreateProfileElement` + `<Dictionary>` + `<DiagMessages>`).
pub fn build_profile_element(
    od: &ObjectInfoCollection,
    profile_info_u32: u32,
    include_dictionary: bool,
    diagnosis_supported: bool,
    preserved_diag: Option<DomElement>,
    preserved_vendor_spec: Option<DomElement>,
) -> Option<DomElement> {
    let mut profile_no = (profile_info_u32 & 0xFFFF) as u16;
    if profile_no == 0 {
        profile_no = if od.device_profile == 0xFFFF {
            0
        } else {
            od.device_profile
        };
    }
    let mut add_info = ((profile_info_u32 >> 16) & 0xFFFF) as u16;
    if add_info == 0 {
        add_info = if od.module_profile == 0xFFFF {
            0
        } else {
            od.module_profile
        };
    }

    let mut prof = DomElement::new("Profile");
    let mut has_profile_header = false;

    if profile_no != 0 {
        has_profile_header = true;
        let f010_sub_entries: Vec<&EntryInfo> = od
            .objects
            .get(&0xF010)
            .map(|o| o.entries.iter().filter(|e| e.sub_index > 0).collect())
            .unwrap_or_default();

        if !f010_sub_entries.is_empty() {
            for entry in f010_sub_entries {
                let mut ch_add = if add_info == 0xFFFF { 0 } else { add_info };
                if !entry.default_data.is_empty() {
                    let be = reverse_hex_byte_pairs(&entry.default_data);
                    let val_u32 = u32::from_str_radix(&be, 16).unwrap_or(0);
                    let mut low16 = (val_u32 & 0xFFFF) as u16;
                    if (low16 == 402 || low16 == 5001) && low16 == profile_no {
                        low16 = ((val_u32 >> 16) & 0xFFFF) as u16;
                    }
                    ch_add = low16;
                }
                let mut ci = DomElement::new("ChannelInfo");
                ci.push_child(DomElement::with_text("ProfileNo", profile_no.to_string()));
                ci.push_child(DomElement::with_text("AddInfo", ch_add.to_string()));
                prof.push_child(ci);
            }
        } else {
            prof.push_child(DomElement::with_text("ProfileNo", profile_no.to_string()));
            if add_info != 0xFFFF && (profile_no != 5001 || add_info != 0) {
                prof.push_child(DomElement::with_text("AddInfo", add_info.to_string()));
            }
            if let Some(obj_f010) = od.objects.get(&0xF010) {
                if let Some(si0) = obj_f010.entry(0) {
                    let cnt = u16::from_str_radix(&reverse_hex_byte_pairs(&si0.default_data), 16)
                        .unwrap_or(0);
                    if cnt == 0 {
                        prof.push_child(DomElement::with_text("ChannelCount", "0"));
                    }
                }
            }
        }
    }

    if !has_profile_header && !include_dictionary {
        return None;
    }

    if include_dictionary {
        prof.push_child(od.build_dictionary_element(false));
        if diagnosis_supported {
            prof.push_child(build_diagnostic_messages_element());
        } else if let Some(diag) = preserved_diag {
            prof.push_child(diag);
        }
    }

    if let Some(vs) = preserved_vendor_spec {
        prof.push_child(vs);
    }

    Some(prof)
}

fn build_diagnostic_messages_element() -> DomElement {
    const DIAG_ENTRIES: &[(&str, &str)] = &[
        ("#x1", "State change Request From: %d To:%d"),
        ("#x2", "%d"),
        (
            "#xF",
            "Calculate bus cycle time failed (Local timer too slow)",
        ),
        ("#x11", "Sync Manager %d invalid address (%d)"),
        ("#x12", "Sync Manager %d invalid size (%d)"),
        ("#x13", "Sync Manager %d invalid settings (%d)"),
        ("#x20", "DC activation register is invalid"),
        (
            "#x21",
            "Configured SyncType (0x1C32.1 or 0x1C33.1) not supported. Check DC registers and supported SyncTypes (0x1C32.4 and 0x1C33.4)",
        ),
    ];

    let mut container = DomElement::new("DiagMessages");
    for (tid, msg) in DIAG_ENTRIES {
        let mut dm = DomElement::new("DiagMessage");
        dm.push_child(DomElement::with_text("TextId", *tid));
        dm.push_child(DomElement::with_text("MessageText", *msg));
        container.push_child(dm);
    }
    container
}

/// Build process data `<Sm>` nodes (`Outputs` and `Inputs`), matching `EsiGenerator::CreatePdSmElements`.
pub fn build_pd_sm_elements(
    od: &ObjectInfoCollection,
    external_app: Option<&SlaveApplication>,
    mut next_free_addr: u32,
    default_addrs: &[u32],
) -> Vec<DomElement> {
    let mut out = Vec::new();

    let out_assign_idx = if od.contains(0x1C12) {
        Some(0x1C12u16)
    } else if od.contains(0x1C10) {
        Some(0x1C10u16)
    } else {
        None
    };

    if let Some(assign_idx) = out_assign_idx {
        let out_len = if let Some(app) = external_app {
            app.get_process_data_length_bytes(assign_idx)
        } else {
            od.get_process_data_length_bytes(assign_idx)
        };
        let mut out_addr = next_free_addr;
        if let Some(&def_out) = default_addrs.first() {
            if def_out >= next_free_addr {
                out_addr = def_out;
            }
        }
        if out_addr < 0x1000 {
            out_addr = 0x1000;
        }

        let mut sm = DomElement::with_text("Sm", "Outputs");
        sm.push_attr("DefaultSize", out_len.to_string());
        sm.push_attr("StartAddress", format!("#x{out_addr:X}"));
        sm.push_attr("ControlByte", "#x64");
        sm.push_attr("Enable", if out_len != 0 { "1" } else { "0" });
        out.push(sm);

        next_free_addr = out_addr + (out_len as u32) * 3;
    }

    let in_assign_idx = if od.contains(0x1C13) {
        Some(0x1C13u16)
    } else if od.contains(0x1C11) {
        Some(0x1C11u16)
    } else {
        None
    };

    if let Some(assign_idx) = in_assign_idx {
        let in_len = if let Some(app) = external_app {
            app.get_process_data_length_bytes(assign_idx)
        } else {
            od.get_process_data_length_bytes(assign_idx)
        };
        let in_addr = if default_addrs.len() >= 2 && default_addrs[1] >= next_free_addr {
            default_addrs[1]
        } else if !next_free_addr.is_multiple_of(8) {
            ((next_free_addr / 8) + 1) * 8
        } else {
            next_free_addr
        };

        let mut sm = DomElement::with_text("Sm", "Inputs");
        sm.push_attr("DefaultSize", in_len.to_string());
        sm.push_attr("StartAddress", format!("#x{in_addr:X}"));
        sm.push_attr("ControlByte", "#x20");
        sm.push_attr("Enable", if in_len != 0 { "1" } else { "0" });
        out.push(sm);
    }

    out
}

/// Build `<RxPdo>` or `<TxPdo>` elements from `od` (`PdoType::CreatePdoElements`).
pub fn build_pdo_elements(
    od: &ObjectInfoCollection,
    tag_name: &str,
    is_module: bool,
    module_fixed_sm: Option<u8>,
) -> Vec<DomElement> {
    let is_rx = tag_name == "RxPdo";
    let pdo_objs: Vec<&ObjectInfo> = if is_rx { od.rx_pdos() } else { od.tx_pdos() };
    let mut out = Vec::with_capacity(pdo_objs.len());

    for pdo_obj in pdo_objs {
        let mut pdo_el = DomElement::new(tag_name);

        let si0_writable = pdo_obj.entry(0).is_some_and(|e| e.flags.access.any_write());
        pdo_el.push_attr("Fixed", if !si0_writable { "true" } else { "false" });

        // Find SM assignment (`0x1C10..0x1C1F`)
        let mut assigned_sm: Option<u8> = module_fixed_sm;
        let mut sm_assign_fixed = false;
        if assigned_sm.is_none() {
            for sm_no in 0u8..16u8 {
                let sm_idx = 0x1C10u16 + (sm_no as u16);
                if let Some(sm_obj) = od.objects.get(&sm_idx) {
                    let count = sm_obj
                        .entry(0)
                        .and_then(|e| {
                            u8::from_str_radix(&reverse_hex_byte_pairs(&e.default_data), 16).ok()
                        })
                        .unwrap_or(sm_obj.max_sub_index());
                    for sub in 1..=count {
                        if let Some(se) = sm_obj.entry(sub) {
                            let assigned_pdo =
                                u16::from_str_radix(&reverse_hex_byte_pairs(&se.default_data), 16)
                                    .unwrap_or(0);
                            if assigned_pdo == pdo_obj.index {
                                assigned_sm = Some(sm_no);
                                sm_assign_fixed = sm_obj
                                    .entry(0)
                                    .map(|e| !e.flags.access.any_write())
                                    .unwrap_or(true);
                                break;
                            }
                        }
                    }
                    if assigned_sm.is_some() {
                        break;
                    }
                }
            }
        }

        if assigned_sm.is_some() && sm_assign_fixed && !is_module {
            pdo_el.push_attr("Mandatory", "true");
        }
        if let Some(sm_no) = assigned_sm {
            pdo_el.push_attr("Sm", sm_no.to_string());
        }

        let mut idx_el = DomElement::with_text("Index", format!("#x{:X}", pdo_obj.index));
        if is_module || (od.pdo_index_increment != 0 && pdo_obj.depend_on_slot) {
            idx_el.push_attr("DependOnSlot", "true");
        }
        if pdo_obj.depend_on_slot_group {
            idx_el.push_attr("DependOnSlotGroup", "true");
        }
        pdo_el.push_child(idx_el);
        pdo_el.push_child(DomElement::with_text("Name", &pdo_obj.name));

        for entry in pdo_obj.entries.iter().filter(|e| e.sub_index > 0) {
            let be = reverse_hex_byte_pairs(&entry.default_data);
            let raw = u32::from_str_radix(&be, 16).unwrap_or(0);
            let target_idx = ((raw >> 16) & 0xFFFF) as u16;
            let target_sub = ((raw >> 8) & 0xFF) as u8;
            let bit_len = (raw & 0xFF) as u16;

            let mut ent_el = DomElement::new("Entry");
            if target_idx == 0 {
                ent_el.push_child(DomElement::with_text("Index", "#x0"));
                ent_el.push_child(DomElement::with_text("SubIndex", "0"));
                ent_el.push_child(DomElement::with_text("BitLen", bit_len.to_string()));
            } else {
                let target_obj = od.objects.get(&target_idx);
                let target_entry = target_obj.and_then(|o| {
                    if o.object_code == ObjectCode::Variable {
                        o.entry(0)
                    } else {
                        o.entry(target_sub)
                            .or_else(|| o.entries.iter().find(|e| e.sub_index > 0))
                    }
                });

                let mut e_idx = DomElement::with_text("Index", format!("#x{target_idx:X}"));
                let dep_slot = is_module
                    || target_obj.is_some_and(|o| od.index_increment != 0 && o.depend_on_slot);
                if dep_slot {
                    e_idx.push_attr("DependOnSlot", "true");
                }
                if target_obj.is_some_and(|o| o.depend_on_slot_group) {
                    e_idx.push_attr("DependOnSlotGroup", "true");
                }
                ent_el.push_child(e_idx);
                ent_el.push_child(DomElement::with_text("SubIndex", target_sub.to_string()));
                ent_el.push_child(DomElement::with_text("BitLen", bit_len.to_string()));

                let entry_name = if let Some(tobj) = target_obj {
                    if tobj.object_code == ObjectCode::Variable {
                        tobj.name.clone()
                    } else if let Some(te) = tobj.entry(target_sub) {
                        te.effective_name()
                    } else {
                        format!("SubIndex {target_sub:03}")
                    }
                } else {
                    entry.effective_name()
                };
                ent_el.push_child(DomElement::with_text("Name", entry_name));

                if let Some(te) = target_entry {
                    if !te.description.is_empty() {
                        ent_el.push_child(DomElement::with_text("Comment", &te.description));
                    }
                    let dt_str = create_esi_syntax_for_entry(te);
                    if !dt_str.is_empty() {
                        ent_el.push_child(DomElement::with_text("DataType", dt_str));
                    }
                } else {
                    let fallback_dt = match bit_len {
                        1 => "BOOL",
                        8 => "USINT",
                        16 => "UINT",
                        32 => "UDINT",
                        64 => "ULINT",
                        _ => "BYTE",
                    };
                    ent_el.push_child(DomElement::with_text("DataType", fallback_dt));
                }
            }
            pdo_el.push_child(ent_el);
        }

        out.push(pdo_el);
    }

    out
}

fn build_cia402_slots_element() -> DomElement {
    let mut slots = DomElement::new("Slots");
    slots.push_attr("SlotPdoIncrement", "16");
    slots.push_attr("SlotIndexIncrement", "#x800");

    let mut slot0 = DomElement::new("Slot");
    slot0.push_attr("MinInstances", "1");
    slot0.push_attr("MaxInstances", "1");
    slot0.push_child(DomElement::with_text("Name", "Axis 0"));
    for (ident, def) in [("#x119800", "0"), ("#x219800", "0"), ("#x319800", "1")] {
        let mut mi = DomElement::with_text("ModuleIdent", ident);
        mi.push_attr("Default", def);
        slot0.push_child(mi);
    }
    slots.push_child(slot0);

    let mut slot1 = DomElement::new("Slot");
    slot1.push_attr("MinInstances", "0");
    slot1.push_attr("MaxInstances", "1");
    slot1.push_child(DomElement::with_text("Name", "Axis 1"));
    for ident in ["#x119800", "#x219800", "#x319800"] {
        let mut mi = DomElement::with_text("ModuleIdent", ident);
        mi.push_attr("Default", "0");
        slot1.push_child(mi);
    }
    slots.push_child(slot1);

    slots
}

fn build_dynamic_slots_element(
    od: &ObjectInfoCollection,
    modules: &[ModuleObjectInfoCollection],
) -> Option<DomElement> {
    let f030 = od.objects.get(&0xF030)?;
    let slot_entries: Vec<&EntryInfo> = f030.entries.iter().filter(|e| e.sub_index > 0).collect();
    if slot_entries.is_empty() {
        return None;
    }

    let mut slots = DomElement::new("Slots");
    if f030
        .entry(0)
        .is_some_and(|si0| si0.flags.access.write_preop)
    {
        slots.push_attr("DownloadModuleIdentList", "true");
    }
    slots.push_attr("MaxSlotCount", slot_entries.len().to_string());
    if od.pdo_index_increment != 0 {
        slots.push_attr(
            "SlotPdoIncrement",
            format!("#x{:X}", od.pdo_index_increment),
        );
    }
    let idx_inc = if od.index_increment != 0 {
        od.index_increment
    } else {
        od.objects
            .get(&0xF000)
            .and_then(|o| o.entry(1))
            .and_then(|e| u16::from_str_radix(&reverse_hex_byte_pairs(&e.default_data), 16).ok())
            .unwrap_or(0)
    };
    if idx_inc != 0 {
        slots.push_attr("SlotIndexIncrement", format!("#x{idx_inc:X}"));
    }

    let module_idents: Vec<u32> = modules.iter().map(|m| m.module_ident).collect();

    for entry in slot_entries {
        let def_ident =
            u32::from_str_radix(&reverse_hex_byte_pairs(&entry.default_data), 16).unwrap_or(0);
        let min_val = if entry.min_data.is_empty() {
            None
        } else {
            u32::from_str_radix(&reverse_hex_byte_pairs(&entry.min_data), 16).ok()
        };
        let min_inst = match min_val {
            Some(v) if v > 0 => "1",
            Some(_) => "0",
            None => {
                if def_ident != 0 {
                    "1"
                } else {
                    "0"
                }
            }
        };

        let mut slot = DomElement::new("Slot");
        slot.push_attr("MinInstances", min_inst);
        slot.push_attr("MaxInstances", "1");
        slot.push_child(DomElement::with_text("Name", entry.effective_name()));

        if !module_idents.is_empty() {
            for &m_id in &module_idents {
                let mut mi = DomElement::with_text("ModuleIdent", format!("#x{m_id:X}"));
                if def_ident != 0 && m_id == def_ident {
                    mi.push_attr("Default", "1");
                }
                slot.push_child(mi);
            }
        } else if def_ident != 0 {
            let mut mi = DomElement::with_text("ModuleIdent", format!("#x{def_ident:X}"));
            mi.push_attr("Default", "1");
            slot.push_child(mi);
        }

        slots.push_child(slot);
    }

    Some(slots)
}

fn build_dynamic_modules_element(
    modules: &[ModuleObjectInfoCollection],
    od: &ObjectInfoCollection,
) -> Option<DomElement> {
    if modules.is_empty() {
        return None;
    }
    let out_sm: u8 = if od.contains(0x1C12) { 2 } else { 0 };
    let in_sm: u8 = if od.contains(0x1C13) { 3 } else { 1 };

    let mut mods_el = DomElement::new("Modules");
    let mut has_zero_mod = false;

    for m in modules {
        if m.module_ident == 0 {
            has_zero_mod = true;
        }
        let mut mod_el = DomElement::new("Module");
        let type_text = if m.type_name.is_empty() {
            m.name.as_str()
        } else {
            m.type_name.as_str()
        };
        let mut ty = DomElement::with_text("Type", type_text);
        ty.push_attr("ModuleIdent", format!("#x{:X}", m.module_ident));
        if let Some(mc) = &m.module_class {
            if !mc.is_empty() {
                ty.push_attr("ModuleClass", mc);
            }
        }
        mod_el.push_child(ty);
        mod_el.push_child(DomElement::with_text("Name", &m.name));

        for rx in build_pdo_elements(&m.od, "RxPdo", true, Some(out_sm)) {
            mod_el.push_child(rx);
        }
        for tx in build_pdo_elements(&m.od, "TxPdo", true, Some(in_sm)) {
            mod_el.push_child(tx);
        }

        if !m.init_cmds.is_empty() {
            let mut mbx = DomElement::new("Mailbox");
            let mut coe = DomElement::new("CoE");
            for ic in &m.init_cmds {
                let mut ic_el = DomElement::new("InitCmd");
                ic_el.push_child(DomElement::with_text("Transition", &ic.transition));
                let mut idx_el = DomElement::with_text("Index", format!("#x{:X}", ic.index));
                if ic.depend_on_slot {
                    idx_el.push_attr("DependOnSlot", "true");
                }
                if ic.depend_on_slot_group {
                    idx_el.push_attr("DependOnSlotGroup", "true");
                }
                ic_el.push_child(idx_el);
                ic_el.push_child(DomElement::with_text("SubIndex", ic.sub_index.to_string()));
                ic_el.push_child(DomElement::with_text("Data", &ic.data_hex));
                if !ic.comment.is_empty() {
                    ic_el.push_child(DomElement::with_text("Comment", &ic.comment));
                }
                coe.push_child(ic_el);
            }
            mbx.push_child(coe);
            mod_el.push_child(mbx);
        }

        let has_non_pdo_objs =
            m.od.objects
                .keys()
                .any(|&idx| !(0x1600..=0x1BFF).contains(&idx));
        if let Some(prof) = build_profile_element(&m.od, 0, has_non_pdo_objs, false, None, None) {
            mod_el.push_child(prof);
        }

        mods_el.push_child(mod_el);
    }

    // Append Empty module (`#x00000000`) if any slot allows `0` and no explicit zero module exists
    let slot_allows_empty = od.objects.get(&0xF030).is_some_and(|f030| {
        f030.entries.iter().filter(|e| e.sub_index > 0).any(|e| {
            let def_id =
                u32::from_str_radix(&reverse_hex_byte_pairs(&e.default_data), 16).unwrap_or(0);
            let min_id = if e.min_data.is_empty() {
                1
            } else {
                u32::from_str_radix(&reverse_hex_byte_pairs(&e.min_data), 16).unwrap_or(0)
            };
            def_id == 0 || min_id == 0
        })
    });
    if slot_allows_empty && !has_zero_mod {
        let mut empty_mod = DomElement::new("Module");
        let mut ty = DomElement::with_text("Type", "Empty");
        ty.push_attr("ModuleIdent", "#x00000000");
        empty_mod.push_child(ty);
        empty_mod.push_child(DomElement::with_text("Name", "Empty"));
        mods_el.push_child(empty_mod);
    }

    Some(mods_el)
}

fn build_test_application_twincat_element(max_pd_out: u32, max_pd_in: u32) -> DomElement {
    let mut tc = DomElement::new("TwinCAT");

    let make_sm = |no: &str, pdos: &[&str]| -> DomElement {
        let mut sm = DomElement::new("Sm");
        sm.push_attr("No", no);
        for p in pdos {
            sm.push_child(DomElement::with_text("Pdo", *p));
        }
        sm
    };

    if max_pd_out > 0 && max_pd_in > 0 {
        // 1. Standard io
        let mut m1 = DomElement::new("AlternativeSmMapping");
        m1.push_attr("Default", "1");
        m1.push_child(DomElement::with_text("Name", "Standard io"));
        m1.push_child(make_sm("2", &["#x1601"]));
        m1.push_child(make_sm("3", &["#x1a00"]));
        tc.push_child(m1);

        // 2. Input Only
        let mut m2 = DomElement::new("AlternativeSmMapping");
        m2.push_child(DomElement::with_text("Name", "Input Only"));
        m2.push_child(make_sm("2", &[]));
        m2.push_child(make_sm("3", &["#x1a00"]));
        tc.push_child(m2);

        // 3. Output Only
        let mut m3 = DomElement::new("AlternativeSmMapping");
        m3.push_child(DomElement::with_text("Name", "Output Only"));
        m3.push_child(make_sm("2", &["#x1601"]));
        m3.push_child(make_sm("3", &[]));
        tc.push_child(m3);

        // 4. Enhanced Sycn0 Info (exact Beckhoff spelling!)
        let mut m4 = DomElement::new("AlternativeSmMapping");
        m4.push_attr("DcOpMode", "Sync0");
        m4.push_child(DomElement::with_text("Name", "Enhanced Sycn0 Info"));
        m4.push_child(make_sm("2", &["#x1601"]));
        m4.push_child(make_sm("3", &["#x1a00", "#x1aff"]));
        tc.push_child(m4);

        // 5. Enhanced Sycn0/Sync1 Info
        let mut m5 = DomElement::new("AlternativeSmMapping");
        m5.push_attr("DcOpMode", "Sync0Sync1");
        m5.push_child(DomElement::with_text("Name", "Enhanced Sycn0/Sync1 Info"));
        m5.push_child(make_sm("2", &["#x1601"]));
        m5.push_child(make_sm("3", &["#x1a00", "#x1aff"]));
        tc.push_child(m5);
    }

    let mut mn = DomElement::new("AlternativeSmMapping");
    mn.push_attr("DcOpMode", "NoDC");
    mn.push_child(DomElement::with_text("Name", "No Pd"));
    mn.push_child(make_sm("2", &[]));
    mn.push_child(make_sm("3", &[]));
    tc.push_child(mn);

    tc
}

fn build_dc_op_modes(test_app: bool, al_event_enabled: bool) -> Vec<DomElement> {
    let make_cyc = |tag: &str, factor: i32| -> DomElement {
        let mut el = DomElement::with_text(tag, "0");
        el.push_attr("Factor", factor.to_string());
        el
    };

    if test_app {
        let mut modes = Vec::with_capacity(4);

        let mut op1 = DomElement::new("OpMode");
        op1.push_child(DomElement::with_text("Name", "NoDC"));
        op1.push_child(DomElement::with_text("Desc", "FreeRun / SM Sync"));
        op1.push_child(DomElement::with_text("AssignActivate", "#x0"));
        modes.push(op1);

        let mut op2 = DomElement::new("OpMode");
        op2.push_child(DomElement::with_text("Name", "Sync0"));
        op2.push_child(DomElement::with_text("Desc", "DC-Synchron"));
        op2.push_child(DomElement::with_text("AssignActivate", "#x0300"));
        op2.push_child(make_cyc("CycleTimeSync0", 1));
        op2.push_child(make_cyc("CycleTimeSync1", 1));
        modes.push(op2);

        let mut op3 = DomElement::new("OpMode");
        op3.push_child(DomElement::with_text("Name", "Sync0Sync1"));
        op3.push_child(DomElement::with_text("Desc", "DC-Synchron (Sync0/1)"));
        op3.push_child(DomElement::with_text("AssignActivate", "#x0700"));
        op3.push_child(make_cyc("CycleTimeSync0", 1));
        op3.push_child(make_cyc("CycleTimeSync1", 1));
        let mut sh1 = DomElement::with_text("ShiftTimeSync1", "0");
        sh1.push_attr("Input", "true");
        op3.push_child(sh1);
        modes.push(op3);

        if al_event_enabled {
            let mut op4 = DomElement::new("OpMode");
            op4.push_child(DomElement::with_text("Name", "SubCycleSync0Sync1"));
            op4.push_child(DomElement::with_text(
                "Desc",
                "SubCycleSync0Sync1 (bit7 only to distinguish Sync modes)",
            ));
            op4.push_child(DomElement::with_text("AssignActivate", "#x8700"));
            op4.push_child(make_cyc("CycleTimeSync0", -2));
            op4.push_child(make_cyc("CycleTimeSync1", 2));
            modes.push(op4);
        }

        modes
    } else {
        let mut op1 = DomElement::new("OpMode");
        op1.push_child(DomElement::with_text("Name", "Synchron"));
        op1.push_child(DomElement::with_text("Desc", "SM-Synchron"));
        op1.push_child(DomElement::with_text("AssignActivate", "#x0"));

        let mut op2 = DomElement::new("OpMode");
        op2.push_child(DomElement::with_text("Name", "DC"));
        op2.push_child(DomElement::with_text("Desc", "DC-Synchron"));
        op2.push_child(DomElement::with_text("AssignActivate", "#x300"));
        op2.push_child(make_cyc("CycleTimeSync0", 1));
        op2.push_child(make_cyc("CycleTimeSync1", 1));

        vec![op1, op2]
    }
}

fn build_cia402_sample_modules_element() -> DomElement {
    let make_flags = |access: &str, pdo: Option<&str>| -> DomElement {
        let mut fl = DomElement::new("Flags");
        fl.push_child(DomElement::with_text("Access", access));
        if let Some(pm) = pdo {
            fl.push_child(DomElement::with_text("PdoMapping", pm));
        }
        fl
    };

    let make_subitem = |sub_idx: Option<&str>,
                        name: &str,
                        ty: &str,
                        bit_size: u32,
                        bit_offs: u32,
                        access: &str,
                        pdo: Option<&str>|
     -> DomElement {
        let mut si = DomElement::new("SubItem");
        if let Some(idx) = sub_idx {
            si.push_child(DomElement::with_text("SubIdx", idx));
        }
        si.push_child(DomElement::with_text("Name", name));
        si.push_child(DomElement::with_text("Type", ty));
        si.push_child(DomElement::with_text("BitSize", bit_size.to_string()));
        si.push_child(DomElement::with_text("BitOffs", bit_offs.to_string()));
        si.push_child(make_flags(access, pdo));
        si
    };

    let build_profile = |dt60c2_first: bool| -> DomElement {
        let mut dts = DomElement::new("DataTypes");
        for (name, bits) in [
            ("SINT", 8u32),
            ("USINT", 8),
            ("UDINT", 32),
            ("DINT", 32),
            ("INT", 16),
            ("UINT", 16),
        ] {
            let mut dt = DomElement::new("DataType");
            dt.push_child(DomElement::with_text("Name", name));
            dt.push_child(DomElement::with_text("BitSize", bits.to_string()));
            dts.push_child(dt);
        }

        let mut dt_arr = DomElement::new("DataType");
        dt_arr.push_child(DomElement::with_text("Name", "DT607DARR"));
        dt_arr.push_child(DomElement::with_text("BaseType", "DINT"));
        dt_arr.push_child(DomElement::with_text("BitSize", "64"));
        let mut arr_info = DomElement::new("ArrayInfo");
        arr_info.push_child(DomElement::with_text("LBound", "1"));
        arr_info.push_child(DomElement::with_text("Elements", "2"));
        dt_arr.push_child(arr_info);

        let mut dt_607d = DomElement::new("DataType");
        dt_607d.push_child(DomElement::with_text("Name", "DT607D"));
        dt_607d.push_child(DomElement::with_text("BitSize", "80"));
        dt_607d.push_child(make_subitem(
            Some("0"),
            "SubIndex 000",
            "USINT",
            8,
            0,
            "ro",
            None,
        ));
        dt_607d.push_child(make_subitem(
            None,
            "Elements",
            "DT607DARR",
            64,
            16,
            "rw",
            Some("r"),
        ));

        let mut dt_60c2 = DomElement::new("DataType");
        dt_60c2.push_child(DomElement::with_text("Name", "DT60C2"));
        dt_60c2.push_child(DomElement::with_text("BitSize", "32"));
        dt_60c2.push_child(make_subitem(
            Some("0"),
            "SubIndex 000",
            "USINT",
            8,
            0,
            "ro",
            None,
        ));
        dt_60c2.push_child(make_subitem(
            Some("1"),
            "Interpolation time period value",
            "USINT",
            8,
            16,
            "rw",
            Some("r"),
        ));
        dt_60c2.push_child(make_subitem(
            Some("2"),
            "Interpolation time index",
            "SINT",
            8,
            24,
            "rw",
            Some("r"),
        ));
        if dt60c2_first {
            dts.push_child(dt_60c2);
            dts.push_child(dt_arr);
            dts.push_child(dt_607d);
        } else {
            dts.push_child(dt_arr);
            dts.push_child(dt_607d);
            dts.push_child(dt_60c2);
        }

        let mut objs = DomElement::new("Objects");
        type Cia402ObjSpec = (
            &'static str,
            &'static str,
            &'static str,
            u32,
            Option<(&'static str, Option<&'static str>)>,
        );
        let specs: &[Cia402ObjSpec] = &[
            ("#x603F", "Error Code", "UINT", 16, Some(("ro", Some("t")))),
            (
                "#x6040",
                "Control Word",
                "UINT",
                16,
                Some(("rw", Some("r"))),
            ),
            ("#x6041", "Status Word", "UINT", 16, Some(("ro", Some("t")))),
            (
                "#x605A",
                "Quick stop option code",
                "INT",
                16,
                Some(("rw", None)),
            ),
            (
                "#x605B",
                "Shutdown option code",
                "INT",
                16,
                Some(("rw", None)),
            ),
            (
                "#x605C",
                "Disable operation option code",
                "INT",
                16,
                Some(("rw", None)),
            ),
            (
                "#x605E",
                "Fault reaction option code",
                "INT",
                16,
                Some(("rw", None)),
            ),
            (
                "#x6060",
                "Modes of operation",
                "SINT",
                8,
                Some(("rw", Some("r"))),
            ),
            (
                "#x6061",
                "Modes of operation display",
                "SINT",
                8,
                Some(("ro", Some("t"))),
            ),
            (
                "#x6064",
                "Position actual value",
                "DINT",
                32,
                Some(("ro", Some("t"))),
            ),
            (
                "#x606C",
                "Velocity actual value",
                "DINT",
                32,
                Some(("ro", Some("t"))),
            ),
            (
                "#x6077",
                "Torque actual value",
                "INT",
                16,
                Some(("ro", Some("t"))),
            ),
            ("#x607D", "Software position limit", "DT607D", 80, None),
            (
                "#x607A",
                "Target position",
                "DINT",
                32,
                Some(("rw", Some("r"))),
            ),
            (
                "#x6085",
                "Quick stop deceleration",
                "UDINT",
                32,
                Some(("rw", Some("r"))),
            ),
            ("#x60C2", "Interpolation time period", "DT60C2", 32, None),
            (
                "#x60FF",
                "Target velocity",
                "DINT",
                32,
                Some(("rw", Some("r"))),
            ),
            (
                "#x6502",
                "Supported drive modes",
                "UDINT",
                32,
                Some(("ro", Some("t"))),
            ),
        ];
        for &(idx, name, ty, bits, flags) in specs {
            let mut obj = DomElement::new("Object");
            let mut idx_el = DomElement::with_text("Index", idx);
            idx_el.push_attr("DependOnSlot", "true");
            obj.push_child(idx_el);
            obj.push_child(DomElement::with_text("Name", name));
            obj.push_child(DomElement::with_text("Type", ty));
            obj.push_child(DomElement::with_text("BitSize", bits.to_string()));
            if let Some((acc, pm)) = flags {
                obj.push_child(make_flags(acc, pm));
            }
            objs.push_child(obj);
        }

        let mut dict = DomElement::new("Dictionary");
        dict.push_child(dts);
        dict.push_child(objs);
        let mut prof = DomElement::new("Profile");
        prof.push_child(DomElement::with_text("ProfileNo", "402"));
        prof.push_child(DomElement::with_text("AddInfo", "2"));
        prof.push_child(dict);
        prof
    };

    let make_entry = |idx: &str, bits: u32, name: &str, comment: &str, dt: &str| -> DomElement {
        let mut e = DomElement::new("Entry");
        let mut idx_el = DomElement::with_text("Index", idx);
        idx_el.push_attr("DependOnSlot", "true");
        e.push_child(idx_el);
        e.push_child(DomElement::with_text("SubIndex", "0"));
        e.push_child(DomElement::with_text("BitLen", bits.to_string()));
        e.push_child(DomElement::with_text("Name", name));
        e.push_child(DomElement::with_text("Comment", comment));
        e.push_child(DomElement::with_text("DataType", dt));
        e
    };

    let make_pad = |idx_text: &str, bits: u32, comment: Option<&str>| -> DomElement {
        let mut e = DomElement::new("Entry");
        e.push_child(DomElement::with_text("Index", idx_text));
        e.push_child(DomElement::with_text("SubIndex", "0"));
        e.push_child(DomElement::with_text("BitLen", bits.to_string()));
        if let Some(c) = comment {
            e.push_child(DomElement::with_text("Comment", c));
        }
        e
    };

    let make_pdo =
        |tag: &str, sm: &str, idx: &str, name: &str, entries: Vec<DomElement>| -> DomElement {
            let mut pdo = DomElement::new(tag);
            pdo.push_attr("Fixed", "true");
            pdo.push_attr("Sm", sm);
            let mut idx_el = DomElement::with_text("Index", idx);
            idx_el.push_attr("DependOnSlot", "true");
            pdo.push_child(idx_el);
            pdo.push_child(DomElement::with_text("Name", name));
            for entry in entries {
                pdo.push_child(entry);
            }
            pdo
        };

    let make_mode_mbx = |mode_hex: &str| -> DomElement {
        let mut init = DomElement::new("InitCmd");
        init.push_child(DomElement::with_text("Transition", "SO"));
        let mut idx_el = DomElement::with_text("Index", "#x6060");
        idx_el.push_attr("DependOnSlot", "true");
        init.push_child(idx_el);
        init.push_child(DomElement::with_text("SubIndex", "0"));
        init.push_child(DomElement::with_text("Data", mode_hex));
        let mut coe = DomElement::new("CoE");
        coe.push_child(init);
        let mut mbx = DomElement::new("Mailbox");
        mbx.push_child(coe);
        mbx
    };

    let profile_std = build_profile(false);
    let profile_csp = build_profile(true);
    let mut modules = DomElement::new("Modules");

    // Module 1: csv,csp - axis
    let mut m1 = DomElement::new("Module");
    let mut m1_ty = DomElement::with_text("Type", "csv,csp - axis");
    m1_ty.push_attr("ModuleIdent", "#x119800");
    m1.push_child(m1_ty);
    m1.push_child(DomElement::with_text(
        "Name",
        "dynamic switch bewteen csp/csv",
    ));
    m1.push_child(make_pdo(
        "RxPdo",
        "2",
        "#x1600",
        "Outputs",
        vec![
            make_entry("#x6040", 16, "Control Word", "object 0x6040:0", "UINT"),
            make_entry("#x607A", 32, "TargetPosition", "object 0x607A:0", "DINT"),
            make_entry("#x60FF", 32, "TargetVelocity", "object 0x60FF:0", "DINT"),
            make_entry("#x6060", 8, "ModeOfOperation", "object 0x6060:0", "USINT"),
            make_pad("0", 8, None),
        ],
    ));
    m1.push_child(make_pdo(
        "TxPdo",
        "3",
        "#x1a00",
        "Inputs",
        vec![
            make_entry("#x6041", 16, "Status Word", "object 0x6041:0", "UINT"),
            make_entry("#x6064", 32, "ActualPosition", "object 0x6064:0", "DINT"),
            make_entry("#x606C", 32, "ActualVelocity", "object 0x606C:0", "DINT"),
            make_entry(
                "#x6061",
                8,
                "ModeOfOperationDisplay",
                "object 0x6061:0",
                "USINT",
            ),
            make_pad("0", 8, None),
        ],
    ));
    m1.push_child(profile_std.clone());
    modules.push_child(m1);

    // Module 2: csp - axis
    let mut m2 = DomElement::new("Module");
    let mut m2_ty = DomElement::with_text("Type", "csp - axis");
    m2_ty.push_attr("ModuleIdent", "#x219800");
    m2.push_child(m2_ty);
    m2.push_child(DomElement::with_text("Name", "csp"));
    m2.push_child(make_pdo(
        "RxPdo",
        "2",
        "#x1601",
        "Outputs",
        vec![
            make_entry("#x6040", 16, "Control Word", "object 0x6040:0", "UINT"),
            make_entry("#x607A", 32, "TargetPosition", "object 0x607A:0", "DINT"),
            make_pad("#x0", 16, Some("16bit padding")),
        ],
    ));
    m2.push_child(make_pdo(
        "TxPdo",
        "3",
        "#x1a01",
        "Inputs",
        vec![
            make_entry("#x6041", 16, "Status Word", "object 0x6041:0", "UINT"),
            make_entry("#x6064", 32, "ActualPosition", "object 0x6064:0", "DINT"),
            make_pad("#x0", 16, Some("16bit padding")),
        ],
    ));
    m2.push_child(make_mode_mbx("08"));
    m2.push_child(profile_csp);
    modules.push_child(m2);

    // Module 3: csv -  axis
    let mut m3 = DomElement::new("Module");
    let mut m3_ty = DomElement::with_text("Type", "csv -  axis");
    m3_ty.push_attr("ModuleIdent", "#x319800");
    m3.push_child(m3_ty);
    m3.push_child(DomElement::with_text("Name", "csv"));
    m3.push_child(make_pdo(
        "RxPdo",
        "2",
        "#x1602",
        "Outputs",
        vec![
            make_entry("#x6040", 16, "Control Word", "object 0x6040:0", "UINT"),
            make_entry("#x60FF", 32, "TargetVelocity", "object 0x60FF:0", "DINT"),
            make_pad("#x0", 16, Some("16bit padding")),
        ],
    ));
    m3.push_child(make_pdo(
        "TxPdo",
        "3",
        "#x1a02",
        "Inputs",
        vec![
            make_entry("#x6041", 16, "Status Word", "object 0x6041:0", "UINT"),
            make_entry("#x6064", 32, "ActualPosition", "object 0x6064:0", "DINT"),
            make_pad("#x0", 16, Some("16bit padding")),
        ],
    ));
    m3.push_child(make_mode_mbx("09"));
    m3.push_child(profile_std);
    modules.push_child(m3);

    modules
}

fn apply_user_esi_fragments(esi_root: &mut DomElement, project: &SlaveProject) {
    let settings_map: BTreeMap<String, String> = project
        .settings
        .iter()
        .map(|s| (s.code_define.clone(), s.value.clone()))
        .collect();

    for frag in &project.esi_fragments {
        if !frag.user_specific {
            continue;
        }
        apply_single_fragment(esi_root, frag, &settings_map);
    }

    // Re-sort canonical XSD child order on `<EtherCATInfo>`, `<Descriptions>`, `<Device>`, `<Info>`, `<Mailbox>`, `<Dc>`
    canonicalize_esi_tree(esi_root);
}

fn apply_single_fragment(
    esi_root: &mut DomElement,
    frag: &EsiFragment,
    settings_map: &BTreeMap<String, String>,
) {
    let mut rel_path = frag.path.trim().trim_start_matches('/').to_string();
    if let Some(rest) = rel_path.strip_prefix("EtherCATInfo/") {
        rel_path = rest.to_string();
    } else if rel_path == "EtherCATInfo" {
        rel_path.clear();
    }
    if let Some(rest) = rel_path.strip_prefix("Device/") {
        rel_path = format!("Descriptions/Devices/Device/{rest}");
    } else if rel_path == "Device" {
        rel_path = "Descriptions/Devices/Device".to_string();
    }

    // Check trailing `@Attr` segment
    let (elem_path, attr_target) = if let Some(at_pos) = rel_path.rfind("/@") {
        (
            rel_path[..at_pos].to_string(),
            Some(rel_path[at_pos + 2..].to_string()),
        )
    } else if let Some(attr_only) = rel_path.strip_prefix('@') {
        (String::new(), Some(attr_only.to_string()))
    } else {
        (rel_path, None)
    };

    let target_el = ensure_xpath_element(esi_root, &elem_path);

    for fv in &frag.values {
        let active = fv.active_expression.trim().is_empty()
            || evaluate_boolean_expression(&fv.active_expression, |k| settings_map.get(k).cloned());
        if !active {
            continue;
        }

        if let Some(attr_name) = &attr_target {
            let mut text_val = String::new();
            for n in &fv.nodes {
                if let DomNode::Text(t) = n {
                    text_val.push_str(t);
                }
            }
            let resolved = resolve_value_expression(
                &text_val,
                |k| settings_map.get(k).map(String::as_str),
                false,
            )
            .unwrap_or(text_val);
            target_el.set_attr(attr_name, normalize_bool_attr_for_xsd(attr_name, &resolved));
            continue;
        }

        for node in &fv.nodes {
            match node {
                DomNode::Element(child) => {
                    let mut cloned = substitute_dom_element(child, settings_map);
                    normalize_fragment_element_booleans(&mut cloned);
                    inject_child_element(target_el, cloned);
                }
                DomNode::Text(t) if !t.trim().is_empty() => {
                    let resolved = resolve_value_expression(
                        t,
                        |k| settings_map.get(k).map(String::as_str),
                        false,
                    )
                    .unwrap_or_else(|| t.clone());
                    target_el
                        .children
                        .retain(|c| !matches!(c, DomNode::Text(_)));
                    target_el.push_text(resolved);
                }
                _ => {}
            }
        }
    }
}

fn ensure_xpath_element<'a>(root: &'a mut DomElement, rel_path: &str) -> &'a mut DomElement {
    let mut cur = root;
    for seg in rel_path.split('/').map(str::trim).filter(|s| !s.is_empty()) {
        let clean_seg = seg.split('[').next().unwrap_or(seg);
        let existing_pos = cur
            .children
            .iter()
            .position(|n| matches!(n, DomNode::Element(e) if e.name == clean_seg));
        let idx = if let Some(p) = existing_pos {
            p
        } else {
            cur.children
                .push(DomNode::Element(DomElement::new(clean_seg)));
            cur.children.len() - 1
        };
        cur = match &mut cur.children[idx] {
            DomNode::Element(e) => e,
            _ => unreachable!(),
        };
    }
    cur
}

fn substitute_dom_element(el: &DomElement, settings_map: &BTreeMap<String, String>) -> DomElement {
    let mut out = DomElement::new(&el.name);
    for (k, v) in &el.attrs {
        let rv =
            resolve_value_expression(v, |key| settings_map.get(key).map(String::as_str), false)
                .unwrap_or_else(|| v.clone());
        out.push_attr(k, rv);
    }
    for n in &el.children {
        match n {
            DomNode::Element(c) => out.push_child(substitute_dom_element(c, settings_map)),
            DomNode::Text(t) => {
                let rt = resolve_value_expression(
                    t,
                    |key| settings_map.get(key).map(String::as_str),
                    false,
                )
                .unwrap_or_else(|| t.clone());
                out.push_text(rt);
            }
            other => out.push_child(other.clone()),
        }
    }
    out
}

fn normalize_bool_attr_for_xsd(attr_name: &str, val: &str) -> String {
    if matches!(
        attr_name,
        "CheckProductCode"
            | "CheckRevisionNo"
            | "Invisible"
            | "Fixed"
            | "Mandatory"
            | "Virtual"
            | "DependOnSlot"
            | "DependOnSlotGroup"
            | "DataLinkLayer"
            | "SdoInfo"
            | "PdoAssign"
            | "PdoConfig"
            | "PdoUpload"
            | "CompleteAccess"
            | "SegmentedSdo"
            | "DiagHistory"
            | "AssignToPdi"
            | "Input"
    ) {
        match val.trim() {
            "1" | "true" | "TRUE" => "true".to_string(),
            "0" | "false" | "FALSE" => "false".to_string(),
            other => other.to_string(),
        }
    } else {
        val.to_string()
    }
}

fn normalize_fragment_element_booleans(el: &mut DomElement) {
    for (k, v) in &mut el.attrs {
        *v = normalize_bool_attr_for_xsd(k, v);
    }
    for n in &mut el.children {
        if let DomNode::Element(c) = n {
            normalize_fragment_element_booleans(c);
        }
    }
}

fn inject_child_element(target: &mut DomElement, child: DomElement) {
    const REPEATABLE_TAGS: &[&str] = &[
        "Port",
        "OpMode",
        "Object",
        "DataType",
        "InitCmd",
        "HideType",
        "SubDevice",
        "AlternativeType",
        "RxPdo",
        "TxPdo",
        "Slot",
        "Module",
        "Group",
        "Device",
        "ChannelInfo",
        "DiagMessage",
    ];

    if child.name == "Sm" || child.name == "Fmmu" {
        let child_txt = child.text_content();
        if let Some(pos) = target.children.iter().position(|n| {
            matches!(n, DomNode::Element(e) if e.name == child.name && e.text_content() == child_txt)
        }) {
            target.children[pos] = DomNode::Element(child);
            return;
        }
        target.push_child(child);
        return;
    }

    if REPEATABLE_TAGS.contains(&child.name.as_str()) {
        target.push_child(child);
        return;
    }

    if let Some(pos) = target
        .children
        .iter()
        .position(|n| matches!(n, DomNode::Element(e) if e.name == child.name))
    {
        target.children[pos] = DomNode::Element(child);
    } else {
        target.push_child(child);
    }
}

fn sort_children_by_xsd_order(el: &mut DomElement, order: &[&str]) {
    let mut indexed: Vec<(usize, usize, DomNode)> = el
        .children
        .drain(..)
        .enumerate()
        .map(|(orig_idx, node)| {
            let rank = match &node {
                DomNode::Element(c) => order
                    .iter()
                    .position(|&name| name == c.name)
                    .unwrap_or(order.len()),
                _ => order.len() + 1,
            };
            (rank, orig_idx, node)
        })
        .collect();
    indexed.sort_by_key(|(rank, orig_idx, _)| (*rank, *orig_idx));
    el.children = indexed.into_iter().map(|(_, _, n)| n).collect();
}

fn canonicalize_esi_tree(esi_root: &mut DomElement) {
    sort_children_by_xsd_order(esi_root, &["InfoReference", "Vendor", "Descriptions"]);

    if let Some(vendor) = esi_root.child_mut("Vendor") {
        sort_children_by_xsd_order(
            vendor,
            &[
                "Id",
                "Name",
                "Comment",
                "URL",
                "DescriptionURL",
                "Image16x14",
                "ImageData16x14",
                "ImageFile16x14",
                "VendorSpecific",
            ],
        );
    }

    if let Some(desc) = esi_root.child_mut("Descriptions") {
        sort_children_by_xsd_order(desc, &["Groups", "Scalings", "Devices", "Modules"]);
        if let Some(devs) = desc.child_mut("Devices") {
            for node in &mut devs.children {
                if let DomNode::Element(dev) = node {
                    if dev.name == "Device" {
                        canonicalize_device_element(dev);
                    }
                }
            }
        }
    }
}

fn canonicalize_device_element(dev: &mut DomElement) {
    sort_children_by_xsd_order(
        dev,
        &[
            "Type",
            "HideType",
            "AlternativeType",
            "SubDevice",
            "Name",
            "Comment",
            "URL",
            "Info",
            "GroupType",
            "Profile",
            "Fmmu",
            "Sm",
            "Su",
            "RxPdo",
            "TxPdo",
            "Mailbox",
            "Dc",
            "Slots",
            "ESC",
            "Eeprom",
            "Image16x14",
            "ImageData16x14",
            "ImageFile16x14",
            "VendorSpecific",
        ],
    );

    if let Some(info) = dev.child_mut("Info") {
        sort_children_by_xsd_order(
            info,
            &[
                "Electrical",
                "StateMachine",
                "Mailbox",
                "EtherCATController",
                "Port",
                "ExecutionUnit",
                "VendorSpecific",
                "StationAliasSupported",
                "IdentificationAdo",
                "IdentificationReg134",
                "DeviceFeature",
            ],
        );
    }

    if let Some(mbx) = dev.child_mut("Mailbox") {
        sort_children_by_xsd_order(
            mbx,
            &["AoE", "EoE", "CoE", "FoE", "SoE", "VoE", "VendorSpecific"],
        );
    }

    if let Some(dc) = dev.child_mut("Dc") {
        sort_children_by_xsd_order(dc, &["OpMode", "VendorSpecific"]);
    }
}

/// Generate the full `<EtherCATInfo>` ESI XML bytes (UTF-8 with BOM, `\t` indent, `\r\n`)
/// for a `SlaveProject`.
pub fn create_device_description_bytes(
    project: &SlaveProject,
    external_app: Option<&SlaveApplication>,
    add_code_config_to_esi: bool,
    trace_file_path_in_esi: Option<&str>,
) -> Result<Vec<u8>> {
    let od = build_project_object_dictionary(project, external_app)?;

    let mut root = DomElement::new("EtherCATInfo");
    root.push_attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    root.push_attr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
    root.push_attr("xsi:noNamespaceSchemaLocation", "EtherCATInfo.xsd");
    root.push_attr("Version", "1.6");

    // 1. <Vendor>
    let mut vendor = DomElement::new("Vendor");
    vendor.push_child(DomElement::with_text(
        "Id",
        hex_attr_hash(setting_str(project, "VENDOR_ID")),
    ));
    vendor.push_child(DomElement::with_text(
        "Name",
        setting_str(project, "VENDOR_NAME"),
    ));
    let vendor_img = normalize_hex_binary(setting_str(project, "VENDOR_IMAGE"), false);
    if !vendor_img.is_empty() {
        vendor.push_child(DomElement::with_text("ImageData16x14", vendor_img));
    }
    root.push_child(vendor);

    // 2. <Descriptions>
    let mut descriptions = DomElement::new("Descriptions");

    let raw_group = setting_str(project, "GROUP_NAME");
    let group_name = if raw_group.trim().is_empty() {
        "SscDevice"
    } else {
        raw_group
    };
    let mut groups = DomElement::new("Groups");
    let mut group = DomElement::new("Group");
    group.push_child(DomElement::with_text("Type", group_name));
    group.push_child(DomElement::with_text("Name", group_name));
    let group_img = normalize_hex_binary(setting_str(project, "GROUP_IMAGE"), false);
    if !group_img.is_empty() {
        group.push_child(DomElement::with_text("ImageData16x14", group_img));
    }
    groups.push_child(group);
    descriptions.push_child(groups);

    // 3. <Devices><Device Physics="YY">
    let mailbox_supported = setting_bool(project, "MAILBOX_SUPPORTED");
    let coe_supported = setting_bool(project, "COE_SUPPORTED");
    let dc_supported = setting_bool(project, "DC_SUPPORTED");
    let diagnosis_supported = setting_bool(project, "DIAGNOSIS_SUPPORTED");
    let test_application = setting_bool(project, "TEST_APPLICATION");
    let cia402_sample = setting_bool(project, "CiA402_SAMPLE_APPLICATION");
    let al_event_enabled = setting_bool(project, "AL_EVENT_ENABLED");
    let max_pd_out = setting_u32(project, "MAX_PD_OUTPUT_SIZE");
    let max_pd_in = setting_u32(project, "MAX_PD_INPUT_SIZE");

    let mut device = DomElement::new("Device");
    device.push_attr("Physics", "YY");

    let dev_name = setting_str(project, "DEVICE_NAME");
    let mut dev_type = DomElement::with_text("Type", dev_name);
    dev_type.push_attr(
        "ProductCode",
        hex_attr_hash(setting_str(project, "PRODUCT_CODE")),
    );
    dev_type.push_attr(
        "RevisionNo",
        hex_attr_hash(setting_str(project, "REVISION_NUMBER")),
    );
    device.push_child(dev_type);
    device.push_child(DomElement::with_text("Name", dev_name));

    // <Info>
    let mut info = DomElement::new("Info");
    let mut sm_info = DomElement::new("StateMachine");
    let mut sm_to = DomElement::new("Timeout");
    sm_to.push_child(DomElement::with_text(
        "PreopTimeout",
        parse_esi_hex_i32(setting_str(project, "PREOPTIMEOUT")).to_string(),
    ));
    sm_to.push_child(DomElement::with_text(
        "SafeopOpTimeout",
        parse_esi_hex_i32(setting_str(project, "SAFEOP2OPTIMEOUT")).to_string(),
    ));
    sm_to.push_child(DomElement::with_text("BackToInitTimeout", "5000"));
    sm_to.push_child(DomElement::with_text("BackToSafeopTimeout", "200"));
    sm_info.push_child(sm_to);
    info.push_child(sm_info);

    if mailbox_supported {
        let mut mbx_info = DomElement::new("Mailbox");
        let mut mbx_to = DomElement::new("Timeout");
        mbx_to.push_child(DomElement::with_text("RequestTimeout", "100"));
        mbx_to.push_child(DomElement::with_text("ResponseTimeout", "2000"));
        mbx_info.push_child(mbx_to);
        info.push_child(mbx_info);
    }

    // <Info><VendorSpecific>
    let mut vendor_spec_children: Vec<DomElement> = Vec::new();
    if add_code_config_to_esi || trace_file_path_in_esi.is_some() {
        let mut ssc_vs = DomElement::new("SSC");
        if add_code_config_to_esi {
            let mut settings_vs = DomElement::new("Settings");
            for s in &project.settings {
                if s.flags.evaluate.is_true()
                    && !s.value.contains('"')
                    && !s.value.contains('<')
                    && !s.value.contains('>')
                {
                    let mut st_el = DomElement::new("Setting");
                    st_el.push_attr("Name", &s.code_define);
                    st_el.push_attr("Value", &s.value);
                    settings_vs.push_child(st_el);
                }
            }
            ssc_vs.push_child(settings_vs);
        }
        if let Some(tp) = trace_file_path_in_esi {
            let mut tr_el = DomElement::new("TraceFile");
            tr_el.push_attr("Path", tp);
            ssc_vs.push_child(tr_el);
        }
        vendor_spec_children.push(ssc_vs);
    }
    if test_application && mailbox_supported {
        vendor_spec_children.push(build_test_application_twincat_element(
            max_pd_out, max_pd_in,
        ));
    }
    if !vendor_spec_children.is_empty() {
        let mut vs = DomElement::new("VendorSpecific");
        for vc in vendor_spec_children {
            vs.push_child(vc);
        }
        info.push_child(vs);
    }

    if setting_bool(project, "EXPLICIT_DEVICE_ID") {
        info.push_child(DomElement::with_text("IdentificationReg134", "true"));
    }
    device.push_child(info);

    // <GroupType>
    device.push_child(DomElement::with_text("GroupType", group_name));

    // <Profile>
    let dev_profile_u32 = setting_u32(project, "DEVICE_PROFILE_TYPE");
    if let Some(prof_el) = build_profile_element(
        &od,
        dev_profile_u32,
        coe_supported && mailbox_supported,
        diagnosis_supported,
        None,
        None,
    ) {
        device.push_child(prof_el);
    }

    // <Sm> & <Fmmu>
    let mut sm_elements: Vec<DomElement> = Vec::with_capacity(4);
    let next_free_addr: u32 = if mailbox_supported {
        let min_mbx = format!("#x{:X}", setting_u32(project, "MIN_MBX_SIZE"));
        let max_mbx_val = setting_u32(project, "MAX_MBX_SIZE");
        let max_mbx = format!("#x{max_mbx_val:X}");
        let def_mbx = format!("#x{:X}", setting_u32(project, "DEF_MBX_SIZE"));
        let mbx_wr = setting_u32(project, "DEF_MBX_WRITE_ADDRESS");
        let mbx_rd = setting_u32(project, "DEF_MBX_READ_ADDRESS");

        let mut sm0 = DomElement::with_text("Sm", "MBoxOut");
        sm0.push_attr("MinSize", &min_mbx);
        sm0.push_attr("MaxSize", &max_mbx);
        sm0.push_attr("DefaultSize", &def_mbx);
        sm0.push_attr("StartAddress", format!("#x{mbx_wr:X}"));
        sm0.push_attr("ControlByte", "#x26");
        sm0.push_attr("Enable", "1");
        sm_elements.push(sm0);

        let mut sm1 = DomElement::with_text("Sm", "MBoxIn");
        sm1.push_attr("MinSize", &min_mbx);
        sm1.push_attr("MaxSize", &max_mbx);
        sm1.push_attr("DefaultSize", &def_mbx);
        sm1.push_attr("StartAddress", format!("#x{mbx_rd:X}"));
        sm1.push_attr("ControlByte", "#x22");
        sm1.push_attr("Enable", "1");
        sm_elements.push(sm1);

        mbx_rd + max_mbx_val
    } else {
        0x1000
    };

    let default_pd_addrs = [
        setting_u32(project, "MIN_PD_WRITE_ADDRESS"),
        setting_u32(project, "DEF_PD_READ_ADDRESS"),
    ];
    let pd_sm_nodes = build_pd_sm_elements(&od, external_app, next_free_addr, &default_pd_addrs);
    let pd_sm_defined = !pd_sm_nodes.is_empty() && pd_sm_nodes.len() <= 2;
    if pd_sm_defined {
        sm_elements.extend(pd_sm_nodes);
    }

    if pd_sm_defined {
        device.push_child(DomElement::with_text("Fmmu", "Outputs"));
        device.push_child(DomElement::with_text("Fmmu", "Inputs"));
    }
    if mailbox_supported {
        device.push_child(DomElement::with_text("Fmmu", "MBoxState"));
    }
    for sm in sm_elements {
        device.push_child(sm);
    }

    // <RxPdo> & <TxPdo>
    let mut rx_pdos = build_pdo_elements(&od, "RxPdo", false, None);
    let mut tx_pdos = build_pdo_elements(&od, "TxPdo", false, None);
    if !coe_supported {
        rx_pdos.retain(|p| p.attr("Sm").is_some());
        tx_pdos.retain(|p| p.attr("Sm").is_some());
    }
    for rx in rx_pdos {
        device.push_child(rx);
    }
    for tx in tx_pdos {
        device.push_child(tx);
    }

    // <Mailbox>
    if mailbox_supported {
        let mut mbx = DomElement::new("Mailbox");
        mbx.push_attr("DataLinkLayer", "true");
        if setting_bool(project, "AOE_SUPPORTED") {
            mbx.push_child(DomElement::new("AoE"));
        }
        if setting_bool(project, "EOE_SUPPORTED") {
            mbx.push_child(DomElement::new("EoE"));
        }
        if coe_supported {
            let pdo_assign = external_app
                .map(|a| a.od.pdo_assign_required())
                .unwrap_or_else(|| od.pdo_assign_required());
            let pdo_config = external_app
                .map(|a| a.od.pdo_config_required())
                .unwrap_or_else(|| od.pdo_config_required());

            let mut coe = DomElement::new("CoE");
            coe.push_attr("SdoInfo", "true");
            coe.push_attr("PdoAssign", if pdo_assign { "true" } else { "false" });
            coe.push_attr("PdoConfig", if pdo_config { "true" } else { "false" });
            coe.push_attr(
                "CompleteAccess",
                if setting_bool(project, "COMPLETE_ACCESS_SUPPORTED") {
                    "true"
                } else {
                    "false"
                },
            );
            coe.push_attr(
                "SegmentedSdo",
                if setting_bool(project, "SEGMENTED_SDO_SUPPORTED") {
                    "true"
                } else {
                    "false"
                },
            );
            if diagnosis_supported {
                coe.push_attr("DiagHistory", "true");
            }
            mbx.push_child(coe);
        }
        if setting_bool(project, "FOE_SUPPORTED") {
            mbx.push_child(DomElement::new("FoE"));
        }
        if setting_bool(project, "SOE_SUPPORTED") {
            mbx.push_child(DomElement::new("SoE"));
        }
        if setting_bool(project, "VOE_SUPPORTED") {
            mbx.push_child(DomElement::new("VoE"));
        }
        device.push_child(mbx);
    }

    // Pre-fragment <Dc>
    if dc_supported {
        device.push_child(DomElement::new("Dc"));
    }

    // <Eeprom>
    let mut eeprom = DomElement::new("Eeprom");
    eeprom.push_child(DomElement::with_text(
        "ByteSize",
        setting_u32(project, "ESC_EEPROM_SIZE").to_string(),
    ));
    let cfg_hex = normalize_hex_binary(setting_str(project, "ESC_CONFIG_DATA"), false);
    eeprom.push_child(DomElement::with_text(
        "ConfigData",
        if cfg_hex.is_empty() {
            "00".to_string()
        } else {
            cfg_hex
        },
    ));
    if setting_bool(project, "BOOTSTRAPMODE_SUPPORTED") {
        let mbx_wr = setting_u32(project, "DEF_MBX_WRITE_ADDRESS") as u16;
        let mbx_sz = setting_u32(project, "DEF_MBX_SIZE") as u16;
        let mbx_rd = setting_u32(project, "DEF_MBX_READ_ADDRESS") as u16;
        let mut boot_bytes = [0u8; 8];
        boot_bytes[0..2].copy_from_slice(&mbx_wr.to_le_bytes());
        boot_bytes[2..4].copy_from_slice(&mbx_sz.to_le_bytes());
        boot_bytes[4..6].copy_from_slice(&mbx_rd.to_le_bytes());
        boot_bytes[6..8].copy_from_slice(&mbx_sz.to_le_bytes());
        let mut boot_hex = String::with_capacity(16);
        for b in boot_bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut boot_hex, "{b:02X}");
        }
        eeprom.push_child(DomElement::with_text("BootStrap", boot_hex));
    }
    device.push_child(eeprom);

    // <ImageData16x14>
    let dev_img = normalize_hex_binary(setting_str(project, "DEVICE_IMAGE"), false);
    if !dev_img.is_empty() {
        device.push_child(DomElement::with_text("ImageData16x14", dev_img));
    }

    let mut devices = DomElement::new("Devices");
    devices.push_child(device);
    descriptions.push_child(devices);
    root.push_child(descriptions);

    // 4. User `EsiFragment` round-trip
    if project.esi_fragments.iter().any(|f| f.user_specific) {
        apply_user_esi_fragments(&mut root, project);
    }

    // 5. Post-fragment `Dc.OpMode` + `Slots` & `Modules`
    if let Some(desc_el) = root.child_mut("Descriptions") {
        if let Some(devs_el) = desc_el.child_mut("Devices") {
            if let Some(dev_el) = devs_el.child_mut("Device") {
                if dc_supported {
                    if dev_el.child("Dc").is_none() {
                        dev_el.push_child(DomElement::new("Dc"));
                    }
                    if let Some(dc_el) = dev_el.child_mut("Dc") {
                        let existing_opmodes = dc_el.children_named("OpMode").next().is_some();
                        if test_application {
                            dc_el.children.retain(
                                |n| !matches!(n, DomNode::Element(e) if e.name == "OpMode"),
                            );
                            for op in build_dc_op_modes(true, al_event_enabled) {
                                dc_el.push_child(op);
                            }
                            sort_children_by_xsd_order(dc_el, &["OpMode", "VendorSpecific"]);
                        } else if !existing_opmodes {
                            for op in build_dc_op_modes(false, al_event_enabled) {
                                dc_el.push_child(op);
                            }
                            sort_children_by_xsd_order(dc_el, &["OpMode", "VendorSpecific"]);
                        }
                    }
                }

                if cia402_sample {
                    dev_el.push_child(build_cia402_slots_element());
                } else {
                    let mods_slice = external_app.map(|a| a.modules.as_slice()).unwrap_or(&[]);
                    if let Some(slots_el) = build_dynamic_slots_element(&od, mods_slice) {
                        dev_el.push_child(slots_el);
                    }
                }

                canonicalize_device_element(dev_el);
            }
        }

        if cia402_sample {
            desc_el.push_child(build_cia402_sample_modules_element());
        } else if let Some(app) = external_app {
            if let Some(mods_el) = build_dynamic_modules_element(&app.modules, &od) {
                desc_el.push_child(mods_el);
            }
        }
        sort_children_by_xsd_order(desc_el, &["Groups", "Scalings", "Devices", "Modules"]);
    }

    Ok(render_indented_xml_bytes(
        &root,
        Some(ESI_XML_PROLOG),
        "\t",
        true,
        false,
    ))
}

/// Write full `<EtherCATInfo>` ESI XML file to `out_path`.
pub fn write_device_description(
    out_path: &Path,
    project: &SlaveProject,
    external_app: Option<&SlaveApplication>,
    add_code_config_to_esi: bool,
    trace_file_path_in_esi: Option<&str>,
) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let bytes = create_device_description_bytes(
        project,
        external_app,
        add_code_config_to_esi,
        trace_file_path_in_esi,
    )?;
    fs::write(out_path, bytes)?;
    Ok(())
}

/// Render standalone `<EtherCATDict>` offline Object Dictionary XML bytes
/// (`<?xml version="1.0"?>`, NO UTF-8 BOM, 2-space indent, `\r\n`, `Version="0.0.9"`).
pub fn create_offline_dictionary_bytes(
    od: &ObjectInfoCollection,
    reduced_od: bool,
    comment: &str,
) -> Vec<u8> {
    let mut dict_root = DomElement::new("EtherCATDict");
    dict_root.push_attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    if !reduced_od {
        dict_root.push_attr("xsi:noNamespaceSchemaLocation", "EtherCATDict.xsd");
    }
    dict_root.push_attr("Version", "0.0.9");
    dict_root.push_child(od.build_dictionary_element(true));

    let prolog_str = if comment.is_empty() {
        OFFLINE_DICT_PROLOG.to_string()
    } else {
        format!("{OFFLINE_DICT_PROLOG}\r\n<!--{comment}-->")
    };

    render_indented_xml_bytes(&dict_root, Some(&prolog_str), "  ", false, false)
}

/// Write standalone `<EtherCATDict>` offline Object Dictionary XML file (`<App>Objects.xml`).
pub fn write_offline_dictionary(
    out_path: &Path,
    od: &ObjectInfoCollection,
    reduced_od: bool,
    comment: &str,
) -> Result<()> {
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let bytes = create_offline_dictionary_bytes(od, reduced_od, comment);
    fs::write(out_path, bytes)?;
    Ok(())
}

fn collect_referenced_datatypes_from_esi(
    obj_el: &DomElement,
    dt_map: &BTreeMap<String, DomElement>,
) -> Vec<DomElement> {
    let mut out = Vec::new();
    let mut visited = Vec::new();

    fn visit_type(
        type_name: &str,
        dt_map: &BTreeMap<String, DomElement>,
        visited: &mut Vec<String>,
        out: &mut Vec<DomElement>,
    ) {
        if type_name.is_empty() || visited.iter().any(|v| v == type_name) {
            return;
        }
        visited.push(type_name.to_string());
        let Some(dt_el) = dt_map.get(type_name) else {
            return;
        };
        // Visit BaseType or SubItem/Type dependencies BEFORE pushing complex `DT*` types!
        if let Some(bt) = dt_el.child_text("BaseType") {
            visit_type(bt.trim(), dt_map, visited, out);
        }
        for sub in dt_el.children_named("SubItem") {
            if let Some(st) = sub.child_text("Type") {
                visit_type(st.trim(), dt_map, visited, out);
            }
        }
        out.push(dt_el.clone());
    }

    if let Some(t) = obj_el.child_text("Type") {
        visit_type(t.trim(), dt_map, &mut visited, &mut out);
    }
    out
}

#[derive(Debug, Clone)]
pub struct EsiUpdateOutcome {
    pub esi_path: PathBuf,
    pub backup_path: PathBuf,
    pub preserved_default_objects: Vec<u16>,
    pub discarded_custom_default_objects: Vec<u16>,
}

/// Update an existing ESI `.xml` file in place with a new `ObjectInfoCollection`,
/// matching `SSC OD Tool` + `EsiGenerator::UpdateEsiFile`:
/// 1. Backs up `esi_path` to `{esi_path}.bak`.
/// 2. Preserves any of the 14 `STANDALONE_ESI_UPDATE_DEFAULT_SSC_OBJECTS` present in the
///    target device's `<Dictionary>` that are not already in `app_od`.
/// 3. Updates `<Profile>`, `<Sm>`, `<RxPdo>`, `<TxPdo>`, `<Mailbox><CoE>` (`@PdoAssign`, `@PdoConfig`),
///    and `<Slots>`, then re-serializes in canonical XSD order (UTF-8 BOM, `\t`, `\r\n`).
pub fn update_esi_file(
    esi_path: &Path,
    device_idx: usize,
    app_od: &ObjectInfoCollection,
    external_app: Option<&SlaveApplication>,
) -> Result<EsiUpdateOutcome> {
    if !esi_path.is_file() {
        return Err(CliError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("Target ESI file '{}' not found", esi_path.display()),
        )));
    }

    let mut root = parse_dom_file(esi_path, false)?;
    let bak_path = PathBuf::from(format!("{}.bak", esi_path.display()));
    fs::copy(esi_path, &bak_path)?;

    // Ensure standard `<EtherCATInfo>` attributes match `.NET XmlSerializer` round-trip
    let ver = root.attr("Version").unwrap_or("1.6").to_string();
    let schema_loc = root
        .attr("xsi:noNamespaceSchemaLocation")
        .unwrap_or("EtherCATInfo.xsd")
        .to_string();
    root.attrs.clear();
    root.push_attr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    root.push_attr("xmlns:xsd", "http://www.w3.org/2001/XMLSchema");
    root.push_attr("xsi:noNamespaceSchemaLocation", schema_loc);
    root.push_attr("Version", ver);

    let devs_el = root
        .child_mut("Descriptions")
        .and_then(|d| d.child_mut("Devices"))
        .ok_or_else(|| {
            CliError::Format(format!(
                "ESI file '{}' has no <Descriptions>/<Devices> section",
                esi_path.display()
            ))
        })?;

    let mut dev_positions: Vec<usize> = Vec::new();
    for (idx, n) in devs_el.children.iter().enumerate() {
        if matches!(n, DomNode::Element(e) if e.name == "Device") {
            dev_positions.push(idx);
        }
    }
    if device_idx >= dev_positions.len() {
        return Err(CliError::Validation(format!(
            "Device index {device_idx} out of range (file has {} <Device> element(s))",
            dev_positions.len()
        )));
    }
    let dev_el = match &mut devs_el.children[dev_positions[device_idx]] {
        DomNode::Element(e) => e,
        _ => unreachable!(),
    };

    // Pre-merge the 14 default SSC objects from existing `<Profile>/<Dictionary>` into `merged_od`
    let mut merged_od = app_od.clone();
    let mut preserved_diag: Option<DomElement> = None;
    let mut preserved_prof_vs: Option<DomElement> = None;
    let mut preserved_default_objects: Vec<u16> = Vec::new();
    let mut discarded_custom_default_objects: Vec<u16> = Vec::new();

    if let Some(old_prof) = dev_el.child("Profile") {
        preserved_diag = old_prof
            .child("DiagMessages")
            .cloned()
            .or_else(|| old_prof.child("DiagFile").cloned());
        preserved_prof_vs = old_prof.child("VendorSpecific").cloned();

        if let Some(old_dict) = old_prof.child("Dictionary") {
            let mut dt_map: BTreeMap<String, DomElement> = BTreeMap::new();
            if let Some(dts) = old_dict.child("DataTypes") {
                for dt in dts.children_named("DataType") {
                    if let Some(name) = dt.child_text("Name") {
                        dt_map.insert(name.trim().to_string(), dt.clone());
                    }
                }
            }
            if let Some(objs) = old_dict.child("Objects") {
                for obj_node in objs.children_named("Object") {
                    let Some(idx_str) = obj_node.child_text("Index") else {
                        continue;
                    };
                    let idx = parse_esi_hex_u32_attr(&idx_str) as u16;
                    if STANDALONE_ESI_UPDATE_DEFAULT_SSC_OBJECTS.contains(&idx) {
                        if !merged_od.contains(idx) {
                            let obj_name = obj_node.child_text("Name").unwrap_or_default();
                            let mut passthrough =
                                ObjectInfo::new(idx, obj_name, ObjectCode::Variable);
                            passthrough.raw_esi_datatypes =
                                collect_referenced_datatypes_from_esi(obj_node, &dt_map);
                            passthrough.raw_esi_object = Some(obj_node.clone());
                            merged_od.insert(passthrough);
                            preserved_default_objects.push(idx);
                        } else {
                            discarded_custom_default_objects.push(idx);
                        }
                    }
                }
            }
        }
    }

    // 1. Update `<Profile>`
    dev_el
        .children
        .retain(|n| !matches!(n, DomNode::Element(e) if e.name == "Profile"));
    if let Some(new_prof) = build_profile_element(
        &merged_od,
        0,
        true,
        false,
        preserved_diag,
        preserved_prof_vs,
    ) {
        dev_el.push_child(new_prof);
    }

    // 2. Update `<RxPdo>` & `<TxPdo>`
    dev_el
        .children
        .retain(|n| !matches!(n, DomNode::Element(e) if e.name == "RxPdo" || e.name == "TxPdo"));
    for rx in build_pdo_elements(&merged_od, "RxPdo", false, None) {
        dev_el.push_child(rx);
    }
    for tx in build_pdo_elements(&merged_od, "TxPdo", false, None) {
        dev_el.push_child(tx);
    }

    // 3. Update `<Sm>` (keeping `MBoxOut` / `MBoxIn`, recalculating `Outputs` / `Inputs` PD SMs)
    let mut mbx_sms: Vec<DomElement> = Vec::new();
    let mut next_free_addr: u32 = 0x1000;
    let mut prev_out_addr: u32 = 0;
    let mut prev_in_addr: u32 = 0;

    for sm in dev_el.children_named("Sm") {
        let role = sm.text_content();
        match role.trim() {
            "MBoxOut" => {
                mbx_sms.push(sm.clone());
            }
            "MBoxIn" => {
                let start = sm
                    .attr("StartAddress")
                    .map(parse_esi_hex_u32_attr)
                    .unwrap_or(0x1080);
                let sz = sm
                    .attr("MaxSize")
                    .or_else(|| sm.attr("DefaultSize"))
                    .map(parse_esi_hex_u32_attr)
                    .unwrap_or(0x80);
                next_free_addr = start + sz;
                mbx_sms.push(sm.clone());
            }
            "Outputs" => {
                prev_out_addr = sm
                    .attr("StartAddress")
                    .map(parse_esi_hex_u32_attr)
                    .unwrap_or(0);
            }
            "Inputs" => {
                prev_in_addr = sm
                    .attr("StartAddress")
                    .map(parse_esi_hex_u32_attr)
                    .unwrap_or(0);
            }
            _ => {}
        }
    }

    dev_el
        .children
        .retain(|n| !matches!(n, DomNode::Element(e) if e.name == "Sm"));
    let pd_sms = build_pd_sm_elements(
        &merged_od,
        external_app,
        next_free_addr,
        &[prev_out_addr, prev_in_addr],
    );
    for sm in mbx_sms {
        dev_el.push_child(sm);
    }
    for sm in pd_sms {
        dev_el.push_child(sm);
    }

    // 4. Update `<Mailbox><CoE>` `@PdoAssign` and `@PdoConfig`
    if let Some(mbx_el) = dev_el.child_mut("Mailbox") {
        normalize_fragment_element_booleans(mbx_el);
        if let Some(coe_el) = mbx_el.child_mut("CoE") {
            let pdo_assign = merged_od.pdo_assign_required();
            let pdo_config = merged_od.pdo_config_required();
            coe_el.set_attr("PdoAssign", if pdo_assign { "true" } else { "false" });
            coe_el.set_attr("PdoConfig", if pdo_config { "true" } else { "false" });
        }
    }

    // 5. Update `<Slots>`
    dev_el
        .children
        .retain(|n| !matches!(n, DomNode::Element(e) if e.name == "Slots"));
    let mods_slice = external_app.map(|a| a.modules.as_slice()).unwrap_or(&[]);
    if let Some(slots_el) = build_dynamic_slots_element(&merged_od, mods_slice) {
        dev_el.push_child(slots_el);
    }

    canonicalize_esi_tree(&mut root);

    let out_bytes = render_indented_xml_bytes(&root, Some(ESI_XML_PROLOG), "\t", true, false);
    fs::write(esi_path, out_bytes)?;
    Ok(EsiUpdateOutcome {
        esi_path: esi_path.to_path_buf(),
        backup_path: bak_path,
        preserved_default_objects,
        discarded_custom_default_objects,
    })
}
