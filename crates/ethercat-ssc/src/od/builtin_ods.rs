use crate::model::SlaveProject;
use crate::od::types::{
    encode_ascii_hex_forward, resolve_data_type_name, AccessFlags, EntryFlags, EntryInfo,
    ObjectCategory, ObjectCode, ObjectInfo, ObjectInfoCollection, PdoMappingMode, SlaveApplication,
};
use ethercat_wire::error::{CliError, Result};

fn swap_u32_hex(v: u32) -> String {
    format!("{:08X}", v.swap_bytes())
}

fn swap_u16_hex(v: u16) -> String {
    format!("{:04X}", v.swap_bytes())
}

fn setting_bool(project: &SlaveProject, name: &str) -> bool {
    project.get_setting(name).is_some_and(|s| s.as_bool())
}

fn setting_u16(project: &SlaveProject, name: &str) -> u16 {
    project.get_setting(name).map(|s| s.as_u16()).unwrap_or(0)
}

fn setting_u32(project: &SlaveProject, name: &str) -> u32 {
    project.get_setting(name).map(|s| s.as_u32()).unwrap_or(0)
}

fn setting_str<'a>(project: &'a SlaveProject, name: &str) -> &'a str {
    project.get_setting_value(name).unwrap_or("")
}

fn make_var_object(
    index: u16,
    name: &str,
    type_str: &str,
    flags: EntryFlags,
    default_data: &str,
) -> Result<ObjectInfo> {
    let (dt_id, bit_len) = resolve_data_type_name(type_str)?;
    let mut obj = ObjectInfo::new(index, name, ObjectCode::Variable);
    obj.data_type_id = dt_id;
    obj.entries.push(EntryInfo {
        sub_index: 0,
        name: name.to_string(),
        data_type_id: dt_id,
        bit_length: bit_len,
        bit_offset: 0,
        flags,
        default_data: default_data.to_string(),
        ..Default::default()
    });
    obj.finalize_layout();
    Ok(obj)
}

fn make_entry(
    sub_index: u8,
    name: &str,
    type_str: &str,
    flags: EntryFlags,
    default_data: &str,
) -> Result<EntryInfo> {
    let (dt_id, bit_len) = resolve_data_type_name(type_str)?;
    Ok(EntryInfo {
        sub_index,
        name: name.to_string(),
        data_type_id: dt_id,
        bit_length: bit_len,
        bit_offset: 0,
        flags,
        default_data: default_data.to_string(),
        ..Default::default()
    })
}

fn make_entry_at_offset(
    sub_index: u8,
    name: &str,
    type_str: &str,
    bit_offset: i32,
    flags: EntryFlags,
    default_data: &str,
) -> Result<EntryInfo> {
    let mut e = make_entry(sub_index, name, type_str, flags, default_data)?;
    e.bit_offset = bit_offset;
    Ok(e)
}

const FLAGS_RO: EntryFlags = EntryFlags::RO;
const FLAGS_RW: EntryFlags = EntryFlags::RW;
const FLAGS_WO: EntryFlags = EntryFlags {
    access: AccessFlags::WO,
    pdo_mapping: PdoMappingMode::None,
    backup: false,
    setting: false,
};
const FLAGS_RO_WP: EntryFlags = EntryFlags {
    access: AccessFlags::RW_PREOP_RO_OTHER,
    pdo_mapping: PdoMappingMode::None,
    backup: false,
    setting: false,
};
const FLAGS_RO_TX: EntryFlags = EntryFlags {
    access: AccessFlags::RO,
    pdo_mapping: PdoMappingMode::Tx,
    backup: false,
    setting: false,
};
const FLAGS_RO_RX: EntryFlags = EntryFlags {
    access: AccessFlags::RO,
    pdo_mapping: PdoMappingMode::Rx,
    backup: false,
    setting: false,
};
const FLAGS_RW_RX: EntryFlags = EntryFlags {
    access: AccessFlags::RW,
    pdo_mapping: PdoMappingMode::Rx,
    backup: false,
    setting: false,
};
const FLAGS_RW_TX: EntryFlags = EntryFlags {
    access: AccessFlags::RW,
    pdo_mapping: PdoMappingMode::Tx,
    backup: false,
    setting: false,
};
const FLAGS_RW_TX_BACKUP: EntryFlags = EntryFlags {
    access: AccessFlags::RW,
    pdo_mapping: PdoMappingMode::Tx,
    backup: true,
    setting: false,
};
const FLAGS_RW_BACKUP_SETTING: EntryFlags = EntryFlags {
    access: AccessFlags::RW,
    pdo_mapping: PdoMappingMode::None,
    backup: true,
    setting: true,
};

fn parse_ssc_version_tuple(raw: &str) -> Option<(u32, u32)> {
    let trimmed = raw.trim();
    let (maj_s, min_s) = trimmed.split_once('.')?;
    let major: u32 = maj_s.trim().parse().ok()?;
    let minor_digits: String = min_s
        .trim()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let minor: u32 = minor_digits.parse().ok()?;
    Some((major, minor))
}

/// Build the complete CoE Object Dictionary for a `SlaveProject`, matching `SlaveProject::GetObjectDictionary()`
/// byte-for-byte across Phase 1 (default SSC objects), Phase 2 (EL9800 / CiA402 / Sample / SampleInterface /
/// Test / external `SlaveApplication`), and Phase 3 (`!MAILBOX_SUPPORTED` SM-assign reindexing).
pub fn build_project_object_dictionary(
    project: &SlaveProject,
    external_app: Option<&SlaveApplication>,
) -> Result<ObjectInfoCollection> {
    if parse_ssc_version_tuple(&project.ssc_version).is_some_and(|v| v < (4, 42))
        || (parse_ssc_version_tuple(&project.ssc_version).is_none()
            && project.ssc_version.as_str() < "4.42")
    {
        return Err(CliError::Validation(format!(
            "Project.GetObjectDictionary is not supported by the current project based on SSC {}, update the project.",
            project.ssc_version
        )));
    }

    let mut od = ObjectInfoCollection::new(setting_str(project, "DEVICE_NAME"));

    // =========================================================================
    // Phase 1: Base Default SSC Objects (from SlaveSettings)
    // =========================================================================
    let val_1000 = setting_u32(project, "DEVICE_PROFILE_TYPE");
    od.device_profile = (val_1000 & 0xFFFF) as u16;
    od.module_profile = ((val_1000 >> 16) & 0xFFFF) as u16;
    if od.device_profile == 5001 {
        od.index_increment = 0x10;
        if od.pdo_index_increment == 0 {
            od.pdo_index_increment = 1;
        }
    }

    // 0x1000 Device type
    od.insert(make_var_object(
        0x1000,
        "Device type",
        "UINT32",
        FLAGS_RO,
        &swap_u32_hex(val_1000),
    )?);

    // 0x1001 Error register
    od.insert(make_var_object(
        0x1001,
        "Error register",
        "UINT8",
        FLAGS_RO,
        "00",
    )?);

    // 0x1008 Device name
    let dev_name = setting_str(project, "DEVICE_NAME");
    let dev_name_len = dev_name.len().max(1);
    od.insert(make_var_object(
        0x1008,
        "Device name",
        &format!("STRING({dev_name_len})"),
        FLAGS_RO,
        &encode_ascii_hex_forward(dev_name),
    )?);

    // 0x1009 Manufacturer Hardware version
    let hw_ver = setting_str(project, "DEVICE_HW_VERSION");
    let hw_ver_len = hw_ver.len().max(1);
    od.insert(make_var_object(
        0x1009,
        "Manufacturer Hardware version",
        &format!("STRING({hw_ver_len})"),
        FLAGS_RO,
        &encode_ascii_hex_forward(hw_ver),
    )?);

    // 0x100A Manufacturer Software version
    let sw_ver = setting_str(project, "DEVICE_SW_VERSION");
    let sw_ver_len = sw_ver.len().max(1);
    od.insert(make_var_object(
        0x100A,
        "Manufacturer Software version",
        &format!("STRING({sw_ver_len})"),
        FLAGS_RO,
        &encode_ascii_hex_forward(sw_ver),
    )?);

    // 0x1C00 Sync manager type
    let mbx_supported = setting_bool(project, "MAILBOX_SUPPORTED");
    let max_pd_in = setting_u16(project, "MAX_PD_INPUT_SIZE");
    let max_pd_out = setting_u16(project, "MAX_PD_OUTPUT_SIZE");
    {
        let mut obj_1c00 = ObjectInfo::new(0x1C00, "Sync manager type", ObjectCode::Array);
        obj_1c00.data_type_id = 5; // UINT8
        let mut si = 1u8;
        if mbx_supported {
            obj_1c00.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT8",
                FLAGS_RO,
                "01",
            )?);
            si += 1;
            obj_1c00.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT8",
                FLAGS_RO,
                "02",
            )?);
            si += 1;
        }
        if max_pd_in > 0 || max_pd_out > 0 {
            obj_1c00.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT8",
                FLAGS_RO,
                "03",
            )?);
            si += 1;
            obj_1c00.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT8",
                FLAGS_RO,
                "04",
            )?);
        }
        if !obj_1c00.entries.is_empty() {
            od.insert(obj_1c00);
        }
    }

    // 0x1018 Identity Object
    {
        let mut obj_1018 = ObjectInfo::new(0x1018, "Identity Object", ObjectCode::Record);
        obj_1018.data_type_id = 35; // DEFTYPE_IDENTITY
        obj_1018.entries.push(make_entry(
            1,
            "Vendor ID",
            "UINT32",
            FLAGS_RO,
            &swap_u32_hex(setting_u32(project, "VENDOR_ID")),
        )?);
        obj_1018.entries.push(make_entry(
            2,
            "Product Code",
            "UINT32",
            FLAGS_RO,
            &swap_u32_hex(setting_u32(project, "PRODUCT_CODE")),
        )?);
        obj_1018.entries.push(make_entry(
            3,
            "Revision Number",
            "UINT32",
            FLAGS_RO,
            &swap_u32_hex(setting_u32(project, "REVISION_NUMBER")),
        )?);
        obj_1018.entries.push(make_entry(
            4,
            "Serial number",
            "UINT32",
            FLAGS_RO,
            &swap_u32_hex(setting_u32(project, "SERIAL_NUMBER")),
        )?);
        od.insert(obj_1018);
    }

    // 0x1010 / 0x1011 / 0x10F0 Backup parameter handling
    if setting_bool(project, "BACKUP_PARAMETER_SUPPORTED") {
        let mut obj_1010 = ObjectInfo::new(0x1010, "Store parameters", ObjectCode::Array);
        obj_1010.data_type_id = 7;
        obj_1010
            .entries
            .push(make_entry(1, "SubIndex 001", "UINT32", FLAGS_RW, "")?);
        od.insert(obj_1010);

        let mut obj_1011 = ObjectInfo::new(0x1011, "Restore default parameters", ObjectCode::Array);
        obj_1011.data_type_id = 7;
        obj_1011
            .entries
            .push(make_entry(1, "SubIndex 001", "UINT32", FLAGS_RW, "")?);
        od.insert(obj_1011);

        let mut obj_10f0 = ObjectInfo::new(0x10F0, "Backup parameter handling", ObjectCode::Record);
        obj_10f0.data_type_id = 43;
        obj_10f0
            .entries
            .push(make_entry(1, "Checksum", "UINT32", FLAGS_RO, "00000000")?);
        obj_10f0.entries.push(make_entry(
            2,
            "Backup Parameter Changed",
            "BOOL",
            FLAGS_RW_TX_BACKUP,
            "00",
        )?);
        od.insert(obj_10f0);
    }

    // 0x10F1 Error Settings (when !_PIC18)
    if !setting_bool(project, "_PIC18") {
        let mut obj_10f1 = ObjectInfo::new(0x10F1, "Error Settings", ObjectCode::Record);
        obj_10f1.entries.push(make_entry(
            1,
            "Local Error Reaction",
            "UINT32",
            FLAGS_RO,
            "01000000",
        )?);
        obj_10f1.entries.push(make_entry(
            2,
            "Sync Error Counter Limit",
            "UINT16",
            FLAGS_RW,
            "0400",
        )?);
        od.insert(obj_10f1);
    }

    // 0x10F3 Diagnosis History & 0x10F8 Timestamp Object
    let dc_supported = setting_bool(project, "DC_SUPPORTED");
    if setting_bool(project, "DIAGNOSIS_SUPPORTED") {
        let max_diag = (setting_u32(project, "MAX_DIAG_MSG") & 0xFF) as u8;
        let mut obj_10f3 = ObjectInfo::new(0x10F3, "Diagnosis History", ObjectCode::Record);
        obj_10f3.entries.push(make_entry(
            1,
            "Maximum Messages",
            "UINT8",
            FLAGS_RO,
            &format!("{max_diag:02X}"),
        )?);
        obj_10f3
            .entries
            .push(make_entry(2, "Newest Message", "UINT8", FLAGS_RO, "00")?);
        obj_10f3.entries.push(make_entry(
            3,
            "Newest Acknowledged Message",
            "UINT8",
            FLAGS_RW,
            "00",
        )?);
        obj_10f3.entries.push(make_entry(
            4,
            "New Messages Available",
            "BOOL",
            FLAGS_RO_TX,
            "00",
        )?);
        obj_10f3
            .entries
            .push(make_entry(5, "Flags", "UINT16", FLAGS_RW, "0000")?);
        od.insert(obj_10f3);
    }

    // `0x10F8` Timestamp Object is unconditionally added in `SlaveProject::GetObjectDictionary` (`IL_0A62`).
    od.insert(make_var_object(
        0x10F8,
        "Timestamp Object",
        "UINT64",
        FLAGS_RW_TX,
        "",
    )?);

    let al_event_enabled = setting_bool(project, "AL_EVENT_ENABLED");
    let sync_types_supported = match (al_event_enabled, dc_supported) {
        (true, true) => "0780",
        (true, false) => "0300",
        (false, true) => "0480",
        (false, false) => "0100",
    };
    let min_pd_cycle = setting_u32(project, "MIN_PD_CYCLE_TIME");
    let min_cycle_hex = if min_pd_cycle > 0 {
        swap_u32_hex(min_pd_cycle)
    } else {
        String::new()
    };

    // 0x1C32 SM output parameter
    if max_pd_out > 0 {
        let (sync_flags, sync_def) = if al_event_enabled {
            (FLAGS_RO_WP, "0100")
        } else if dc_supported {
            (FLAGS_RO_WP, "0200")
        } else {
            (FLAGS_RO, "0000")
        };
        let out_calc = setting_u32(project, "PD_OUTPUT_CALC_AND_COPY_TIME");
        let out_delay = setting_u32(project, "PD_OUTPUT_DELAY_TIME");
        od.insert(build_sm_param_object(
            0x1C32,
            "SM output parameter",
            sync_flags,
            sync_def,
            sync_types_supported,
            &min_cycle_hex,
            if out_calc > 0 {
                swap_u32_hex(out_calc)
            } else {
                String::new()
            },
            if out_delay > 0 {
                swap_u32_hex(out_delay)
            } else {
                String::new()
            },
        )?);
    }

    // 0x1C33 SM input parameter
    if max_pd_in > 0 {
        let (sync_flags, sync_def) = if al_event_enabled {
            if max_pd_out > 0 {
                (FLAGS_RO_WP, "2200")
            } else {
                (FLAGS_RO_WP, "0100")
            }
        } else if dc_supported {
            (FLAGS_RO_WP, "0200")
        } else {
            (FLAGS_RO, "0000")
        };
        let in_calc = setting_u32(project, "PD_INPUT_CALC_AND_COPY_TIME");
        let in_delay = setting_u32(project, "PD_INPUT_DELAY_TIME");
        od.insert(build_sm_param_object(
            0x1C33,
            "SM input parameter",
            sync_flags,
            sync_def,
            sync_types_supported,
            &min_cycle_hex,
            if in_calc > 0 {
                swap_u32_hex(in_calc)
            } else {
                String::new()
            },
            if in_delay > 0 {
                swap_u32_hex(in_delay)
            } else {
                String::new()
            },
        )?);
    }

    // =========================================================================
    // Phase 2: Mutually Exclusive Application Branches
    // =========================================================================
    if setting_bool(project, "EL9800_APPLICATION") {
        populate_el9800_application_od(project, &mut od)?;
    } else if setting_bool(project, "CiA402_SAMPLE_APPLICATION") {
        populate_cia402_application_od(&mut od)?;
    } else if setting_bool(project, "SAMPLE_APPLICATION") {
        populate_sample_application_od(&mut od, false)?;
    } else if setting_bool(project, "SAMPLE_APPLICATION_INTERFACE") {
        populate_sample_application_od(&mut od, true)?;
    } else if setting_bool(project, "TEST_APPLICATION") {
        populate_test_application_od(project, &mut od)?;
    } else if let Some(app) = external_app {
        for obj in app.od.objects.values() {
            if !od.contains(obj.index) {
                od.insert(obj.clone());
            }
        }
        // Exact Beckhoff `GetObjectDictionary` check: `if (MaxPdInSize > 0 || MaxPdInSize > 0)` / PD enabled
        if max_pd_in > 0 || max_pd_out > 0 {
            let assign_flags = if app.od.pdo_assign_required() {
                FLAGS_RO_WP
            } else {
                FLAGS_RO
            };
            if !od.contains(0x1C12) {
                let mut sm2 =
                    ObjectInfo::new(0x1C12, "SyncManager 2 assignment", ObjectCode::Array);
                sm2.data_type_id = 6;
                sm2.entries.push(EntryInfo {
                    sub_index: 0,
                    name: "SubIndex 000".to_string(),
                    data_type_id: 5,
                    bit_length: 8,
                    bit_offset: 0,
                    flags: assign_flags,
                    default_data: "00".to_string(),
                    ..Default::default()
                });
                od.insert(sm2);
            }
            if !od.contains(0x1C13) {
                let mut sm3 =
                    ObjectInfo::new(0x1C13, "SyncManager 3 assignment", ObjectCode::Array);
                sm3.data_type_id = 6;
                sm3.entries.push(EntryInfo {
                    sub_index: 0,
                    name: "SubIndex 000".to_string(),
                    data_type_id: 5,
                    bit_length: 8,
                    bit_offset: 0,
                    flags: assign_flags,
                    default_data: "00".to_string(),
                    ..Default::default()
                });
                od.insert(sm3);
            }
        }
        if !app.od.name.is_empty() {
            od.name = app.od.name.clone();
        }
        if app.od.device_profile != 0 {
            od.device_profile = app.od.device_profile;
        }
        if app.od.module_profile != 0 {
            od.module_profile = app.od.module_profile;
        }
        if app.od.index_increment != 0 {
            od.index_increment = app.od.index_increment;
        }
        if app.od.pdo_index_increment != 0 {
            od.pdo_index_increment = app.od.pdo_index_increment;
        }
    }

    // =========================================================================
    // Phase 3: Mailboxless SM Assign Rename (`0x1C12 -> 0x1C10`, `0x1C13 -> 0x1C11`)
    // =========================================================================
    if !mbx_supported {
        if let Some(mut sm2) = od.remove(0x1C12) {
            sm2.index = 0x1C10;
            od.insert(sm2);
        }
        if let Some(mut sm3) = od.remove(0x1C13) {
            sm3.index = 0x1C11;
            od.insert(sm3);
        }
    }

    Ok(od)
}

#[allow(clippy::too_many_arguments)]
fn build_sm_param_object(
    index: u16,
    name: &str,
    sync_flags: EntryFlags,
    sync_def: &str,
    sync_types_supported: &str,
    min_cycle_hex: &str,
    calc_copy_hex: String,
    delay_hex: String,
) -> Result<ObjectInfo> {
    let mut obj = ObjectInfo::new(index, name, ObjectCode::Record);
    obj.data_type_id = 41; // DEFTYPE_SMPAR
    obj.entries.push(make_entry_at_offset(
        0,
        "SubIndex 000",
        "UINT8",
        0,
        FLAGS_RO,
        "20",
    )?);
    obj.entries.push(make_entry_at_offset(
        1,
        "Synchronization Type",
        "UINT16",
        16,
        sync_flags,
        sync_def,
    )?);
    obj.entries.push(make_entry_at_offset(
        2,
        "Cycle Time",
        "UINT32",
        32,
        FLAGS_RO,
        "",
    )?);
    // 32-bit gap for omitted SI3 (`64..96`)
    obj.entries.push(make_entry_at_offset(
        4,
        "Synchronization Types supported",
        "UINT16",
        96,
        FLAGS_RO,
        sync_types_supported,
    )?);
    obj.entries.push(make_entry_at_offset(
        5,
        "Minimum Cycle Time",
        "UINT32",
        112,
        FLAGS_RO,
        min_cycle_hex,
    )?);
    obj.entries.push(make_entry_at_offset(
        6,
        "Calc and Copy Time",
        "UINT32",
        144,
        FLAGS_RO,
        &calc_copy_hex,
    )?);
    // 32-bit gap for omitted SI7 (`176..208`)
    obj.entries.push(make_entry_at_offset(
        8,
        "Get Cycle Time",
        "UINT16",
        208,
        FLAGS_RW,
        "",
    )?);
    obj.entries.push(make_entry_at_offset(
        9,
        "Delay Time",
        "UINT32",
        224,
        FLAGS_RO,
        &delay_hex,
    )?);
    obj.entries.push(make_entry_at_offset(
        10,
        "Sync0 Cycle Time",
        "UINT32",
        256,
        FLAGS_RW,
        "",
    )?);
    obj.entries.push(make_entry_at_offset(
        11,
        "SM-Event Missed",
        "UINT16",
        288,
        FLAGS_RO,
        "",
    )?);
    obj.entries.push(make_entry_at_offset(
        12,
        "Cycle Time Too Small",
        "UINT16",
        304,
        FLAGS_RO,
        "",
    )?);
    obj.entries.push(make_entry_at_offset(
        13,
        "Shift Time Too Short Counter",
        "UINT16",
        320,
        FLAGS_RO,
        "",
    )?);
    // Gap up to SI32 at BitOffs = 480 -> total BitSize = 488!
    obj.entries.push(make_entry_at_offset(
        32,
        "Sync Error",
        "BOOL",
        480,
        FLAGS_RO,
        "",
    )?);
    obj.finalize_layout();
    Ok(obj)
}

fn build_pdo_map_object(index: u16, name: &str, mappings_le: &[&str]) -> Result<ObjectInfo> {
    let mut obj = ObjectInfo::new(index, name, ObjectCode::Record);
    obj.data_type_id = 33; // DEFTYPE_PDOMAPPING
    obj.category = ObjectCategory::Mandatory;
    for (i, &hex_le) in mappings_le.iter().enumerate() {
        let si = (i + 1) as u8;
        obj.entries.push(make_entry(
            si,
            &format!("SubIndex {si:03}"),
            "UINT32",
            FLAGS_RO,
            hex_le,
        )?);
    }
    obj.finalize_layout();
    Ok(obj)
}

fn populate_el9800_application_od(
    project: &SlaveProject,
    od: &mut ObjectInfoCollection,
) -> Result<()> {
    // 0x0800 Enum `DT0800EN03`
    let mut enum_0800 = ObjectInfo::new(0x0800, "DT0800EN03", ObjectCode::Defstruct);
    enum_0800.data_type_id = 40;
    enum_0800.entries.push(EntryInfo {
        sub_index: 1,
        name: "Signed presentation".to_string(),
        data_type_id: 40,
        bit_length: 3,
        bit_offset: 0,
        flags: FLAGS_RO,
        default_data: "00".to_string(),
        enum_value: Some(0),
        ..Default::default()
    });
    enum_0800.entries.push(EntryInfo {
        sub_index: 2,
        name: "Unsigned presentation".to_string(),
        data_type_id: 40,
        bit_length: 3,
        bit_offset: 3,
        flags: FLAGS_RO,
        default_data: "01".to_string(),
        enum_value: Some(1),
        ..Default::default()
    });
    od.insert(enum_0800);

    // `SlaveProject::GetObjectDictionary` (`IL_12CD..IL_12E1`) only populates the EL9800 PIC24 evaluation
    // board PDOs/I/O objects (`0x1601..0xF010`) when `_PIC24` is enabled.
    if !setting_bool(project, "_PIC24") {
        return Ok(());
    }

    // 0x1601 DO RxPDO-Map
    od.insert(build_pdo_map_object(
        0x1601,
        "DO RxPDO-Map",
        &[
            "01011070", "01021070", "01031070", "01041070", "01051070", "01061070", "01071070",
            "01081070", "08000000",
        ],
    )?);

    // 0x1802 TxPDO Parameter (SI0="09", SI7="TxPDOState" @16, SI9="TxPDO Toggle" @17)
    {
        let mut obj_1802 = ObjectInfo::new(0x1802, "TxPDO Parameter", ObjectCode::Record);
        obj_1802.data_type_id = 39;
        obj_1802.entries.push(make_entry_at_offset(
            0,
            "SubIndex 000",
            "UINT8",
            0,
            FLAGS_RO,
            "09",
        )?);
        obj_1802.entries.push(make_entry_at_offset(
            7,
            "TxPDOState",
            "BOOL",
            16,
            FLAGS_RO_TX,
            "",
        )?);
        obj_1802.entries.push(make_entry_at_offset(
            9,
            "TxPDO Toggle",
            "BOOL",
            17,
            FLAGS_RO_TX,
            "",
        )?);
        od.insert(obj_1802);
    }

    // 0x1A00 DI TxPDO-Map
    od.insert(build_pdo_map_object(
        0x1A00,
        "DI TxPDO-Map",
        &[
            "01010060", "01020060", "01030060", "01040060", "01050060", "01060060", "01070060",
            "01080060", "08000000",
        ],
    )?);

    // 0x1A02 AI TxPDO-Map
    od.insert(build_pdo_map_object(
        0x1A02,
        "AI TxPDO-Map",
        &[
            "01012060", "01022060", "02032060", "02052060", "08000000", "01070218", "01090218",
            "10112060",
        ],
    )?);

    // 0x1C12 RxPDO assign
    {
        let mut sm2 = ObjectInfo::new(0x1C12, "RxPDO assign", ObjectCode::Array);
        sm2.data_type_id = 6;
        sm2.entries
            .push(make_entry(1, "SubIndex 001", "UINT16", FLAGS_RO, "0116")?);
        od.insert(sm2);
    }

    // 0x1C13 TxPDO assign
    {
        let mut sm3 = ObjectInfo::new(0x1C13, "TxPDO assign", ObjectCode::Array);
        sm3.data_type_id = 6;
        sm3.entries
            .push(make_entry(1, "SubIndex 001", "UINT16", FLAGS_RO, "001A")?);
        sm3.entries
            .push(make_entry(2, "SubIndex 002", "UINT16", FLAGS_RO, "021A")?);
        od.insert(sm3);
    }

    // 0x6000 DI Inputs
    {
        let mut di = ObjectInfo::new(0x6000, "DI Inputs", ObjectCode::Record);
        for si in 1..=8u8 {
            di.entries.push(make_entry(
                si,
                &format!("Switch {si}"),
                "BOOL",
                FLAGS_RO_TX,
                "00",
            )?);
        }
        od.insert(di);
    }

    // 0x6020 AI Inputs (sparse bit offsets matching `SlaveProject.xml` lines 1020-1105)
    {
        let mut ai = ObjectInfo::new(0x6020, "AI Inputs", ObjectCode::Record);
        ai.entries.push(make_entry_at_offset(
            0,
            "SubIndex 000",
            "UINT8",
            0,
            FLAGS_RO,
            "11",
        )?);
        ai.entries.push(make_entry_at_offset(
            1,
            "Underrange",
            "BOOL",
            16,
            FLAGS_RO_TX,
            "00",
        )?);
        ai.entries.push(make_entry_at_offset(
            2,
            "Overrange",
            "BOOL",
            17,
            FLAGS_RO_TX,
            "00",
        )?);
        ai.entries.push(make_entry_at_offset(
            3,
            "Limit 1",
            "BIT2",
            18,
            FLAGS_RO_TX,
            "00",
        )?);
        ai.entries.push(make_entry_at_offset(
            5,
            "Limit 2",
            "BIT2",
            20,
            FLAGS_RO_TX,
            "00",
        )?);
        ai.entries.push(make_entry_at_offset(
            15,
            "TxPDO State",
            "BOOL",
            30,
            FLAGS_RO_TX,
            "",
        )?);
        ai.entries.push(make_entry_at_offset(
            16,
            "TxPDO Toggle",
            "BOOL",
            31,
            FLAGS_RO_TX,
            "",
        )?);
        ai.entries.push(make_entry_at_offset(
            17,
            "Analog input",
            "INT16",
            32,
            FLAGS_RO_TX,
            "",
        )?);
        od.insert(ai);
    }

    // 0x7010 DO Outputs (`RO + Rx` matching `SlaveProject.xml` lines 1108-1186!)
    {
        let mut do_out = ObjectInfo::new(0x7010, "DO Outputs", ObjectCode::Record);
        for si in 1..=8u8 {
            do_out.entries.push(make_entry(
                si,
                &format!("LED {si}"),
                "BOOL",
                FLAGS_RO_RX,
                "00",
            )?);
        }
        od.insert(do_out);
    }

    // 0x8020 AI Settings (sparse bit offsets matching `SlaveProject.xml` lines 1188-1299)
    {
        let mut ai_cfg = ObjectInfo::new(0x8020, "AI Settings", ObjectCode::Record);
        ai_cfg.entries.push(make_entry_at_offset(
            0,
            "SubIndex 000",
            "UINT8",
            0,
            FLAGS_RO,
            "14",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            1,
            "Enable user scale",
            "BOOL",
            16,
            FLAGS_RW_BACKUP_SETTING,
            "00",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            2,
            "Presentation",
            "DT0800EN03",
            17,
            FLAGS_RW_BACKUP_SETTING,
            "00",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            7,
            "Enable limit 1",
            "BOOL",
            22,
            FLAGS_RW_BACKUP_SETTING,
            "00",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            8,
            "Enable limit 2",
            "BOOL",
            23,
            FLAGS_RW_BACKUP_SETTING,
            "00",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            17,
            "Offset",
            "INT16",
            32,
            FLAGS_RW_BACKUP_SETTING,
            "0000",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            18,
            "Gain",
            "INT32",
            48,
            FLAGS_RW_BACKUP_SETTING,
            "00000000",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            19,
            "Limit 1",
            "INT16",
            80,
            FLAGS_RW_BACKUP_SETTING,
            "0000",
        )?);
        ai_cfg.entries.push(make_entry_at_offset(
            20,
            "Limit 2",
            "INT16",
            96,
            FLAGS_RW_BACKUP_SETTING,
            "0000",
        )?);
        od.insert(ai_cfg);
    }

    // 0xF000 Modular Device Profile
    {
        let mut f000 = ObjectInfo::new(0xF000, "Modular Device Profile", ObjectCode::Record);
        f000.data_type_id = 44;
        f000.entries
            .push(make_entry(1, "Index distance", "UINT16", FLAGS_RO, "1000")?);
        f000.entries.push(make_entry(
            2,
            "Maximum number of modules",
            "UINT16",
            FLAGS_RO,
            "0300",
        )?);
        od.insert(f000);
    }

    // 0xF010 Module Profile List
    {
        let mut f010 = ObjectInfo::new(0xF010, "Module Profile List", ObjectCode::Array);
        f010.data_type_id = 7;
        for si in 1..=3u8 {
            f010.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT32",
                FLAGS_RO,
                "00000000",
            )?);
        }
        od.insert(f010);
    }

    Ok(())
}

fn populate_cia402_application_od(od: &mut ObjectInfoCollection) -> Result<()> {
    // 0x1C12 RxPDO assign (`RW_PREOP_RO_OTHER`)
    {
        let mut sm2 = ObjectInfo::new(0x1C12, "RxPDO assign", ObjectCode::Array);
        sm2.data_type_id = 6;
        sm2.entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "00")?);
        sm2.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT16",
            FLAGS_RO_WP,
            "0000",
        )?);
        sm2.entries.push(make_entry(
            2,
            "SubIndex 002",
            "UINT16",
            FLAGS_RO_WP,
            "0000",
        )?);
        od.insert(sm2);
    }

    // 0x1C13 TxPDO assign (`RW_PREOP_RO_OTHER`)
    {
        let mut sm3 = ObjectInfo::new(0x1C13, "TxPDO assign", ObjectCode::Array);
        sm3.data_type_id = 6;
        sm3.entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "00")?);
        sm3.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT16",
            FLAGS_RO_WP,
            "0000",
        )?);
        sm3.entries.push(make_entry(
            2,
            "SubIndex 002",
            "UINT16",
            FLAGS_RO_WP,
            "0000",
        )?);
        od.insert(sm3);
    }

    // 0xF000 Modular Device Profile (`0x0800` LE = `"0008"`? Wait: `vec3_cia402/SlaveProject.xml` line 963 is `"0080"`? Wait: let's check!)
    // Look at `vec3_cia402/SlaveProject.xml` line 963 that we JUST READ in step 1020:
    // `<DefaultData>0080</DefaultData>` (`0x0800` vs `0x8000` — Beckhoff literally wrote `"0080"` in `steps/865` line 543!)
    {
        let mut f000 = ObjectInfo::new(0xF000, "Modular Device Profile", ObjectCode::Record);
        f000.data_type_id = 44;
        f000.entries
            .push(make_entry(1, "Index distance", "UINT16", FLAGS_RO, "0080")?);
        f000.entries.push(make_entry(
            2,
            "Maximum number of modules",
            "UINT16",
            FLAGS_RO,
            "0200",
        )?);
        od.insert(f000);
    }

    // 0xF010 Module Profile List (`"02000000"`, `"00000000"` — verified in `vec3_cia402/SlaveProject.xml` lines 989 & 995)
    {
        let mut f010 = ObjectInfo::new(0xF010, "Module Profile List", ObjectCode::Array);
        f010.data_type_id = 7;
        f010.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO,
            "02000000",
        )?);
        f010.entries.push(make_entry(
            2,
            "SubIndex 002",
            "UINT32",
            FLAGS_RO,
            "00000000",
        )?);
        od.insert(f010);
    }

    // 0xF030 Configured Module Ident List (SI0="02"? Wait: look at `vec3_cia402/SlaveProject.xml` line 1009: `<DefaultData>02</DefaultData>`! Why `"02"` when `steps/865` line 562 had `"01"`? Because `ObjectInfo::finalize_layout` or `SI2` updates `SI0` or `Entries[0]` was overwritten when SI2 was added — let's check `DTF030` flags in `vec3_cia402` too!)
    {
        let mut f030 = ObjectInfo::new(0xF030, "Configured Module Ident List", ObjectCode::Array);
        f030.data_type_id = 7;
        f030.entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "02")?);
        f030.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO_WP,
            "00983100",
        )?);
        let mut si2 = make_entry(2, "SubIndex 002", "UINT32", FLAGS_RO_WP, "00000000")?;
        si2.min_data = "00000000".to_string();
        f030.entries.push(si2);
        od.insert(f030);
    }

    // 0xF050 Module detected list
    {
        let mut f050 = ObjectInfo::new(0xF050, "Module detected list", ObjectCode::Array);
        f050.data_type_id = 7;
        f050.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO,
            "00983100",
        )?);
        f050.entries.push(make_entry(
            2,
            "SubIndex 002",
            "UINT32",
            FLAGS_RO,
            "00000000",
        )?);
        od.insert(f050);
    }

    Ok(())
}

fn populate_sample_application_od(
    od: &mut ObjectInfoCollection,
    byte_array_interface: bool,
) -> Result<()> {
    od.insert(build_pdo_map_object(0x1601, "RxPDO-Map", &["20001070"])?);
    od.insert(build_pdo_map_object(0x1A00, "TxPDO-Map", &["20000060"])?);

    {
        let mut sm2 = ObjectInfo::new(0x1C12, "RxPDO assign", ObjectCode::Array);
        sm2.data_type_id = 6;
        sm2.entries
            .push(make_entry(1, "SubIndex 001", "UINT16", FLAGS_RO, "0116")?);
        od.insert(sm2);
    }
    {
        let mut sm3 = ObjectInfo::new(0x1C13, "TxPDO assign", ObjectCode::Array);
        sm3.data_type_id = 6;
        sm3.entries
            .push(make_entry(1, "SubIndex 001", "UINT16", FLAGS_RO, "001A")?);
        od.insert(sm3);
    }

    if byte_array_interface {
        od.insert(make_var_object(
            0x6000,
            "Input Data",
            "ARRAY [0..3] OF BYTE",
            FLAGS_RO_TX,
            "00000000",
        )?);
        od.insert(make_var_object(
            0x7010,
            "Output Data",
            "ARRAY [0..3] OF BYTE",
            FLAGS_RW_RX,
            "00000000",
        )?);
    } else {
        od.insert(make_var_object(
            0x6000,
            "InputCounter",
            "UINT32",
            FLAGS_RO_TX,
            "",
        )?);
        od.insert(make_var_object(
            0x7010,
            "OutputCounter",
            "UINT32",
            FLAGS_RW_RX,
            "",
        )?);
    }

    {
        let mut f000 = ObjectInfo::new(0xF000, "Modular Device Profile", ObjectCode::Record);
        f000.data_type_id = 44;
        f000.entries
            .push(make_entry(1, "Index distance", "UINT16", FLAGS_RO, "1000")?);
        f000.entries.push(make_entry(
            2,
            "Maximum number of modules",
            "UINT16",
            FLAGS_RO,
            "0200",
        )?);
        od.insert(f000);
    }
    {
        let mut f010 = ObjectInfo::new(0xF010, "Module Profile List", ObjectCode::Array);
        f010.data_type_id = 7;
        f010.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO,
            "00000000",
        )?);
        f010.entries.push(make_entry(
            2,
            "SubIndex 002",
            "UINT32",
            FLAGS_RO,
            "00000000",
        )?);
        od.insert(f010);
    }

    Ok(())
}

fn populate_test_application_od(
    project: &SlaveProject,
    od: &mut ObjectInfoCollection,
) -> Result<()> {
    // Enums 0x0800..0x0802
    for (idx, dt_name, bits, pairs) in [
        (
            0x0800u16,
            "DT0800EN03",
            3i32,
            &[
                ("Signed presentation", "00", 0i64),
                ("Unsigned presentation", "01", 1i64),
            ][..],
        ),
        (
            0x0801u16,
            "DT0801EN03",
            3i32,
            &[("FALSE", "00", 0i64), ("TRUE", "01", 1i64)][..],
        ),
        (
            0x0802u16,
            "DT0802EN16",
            16i32,
            &[
                ("Two hundred", "C800", 0xC8i64),
                ("One thousand", "E803", 0x03E8i64),
            ][..],
        ),
    ] {
        let mut en = ObjectInfo::new(idx, dt_name, ObjectCode::Defstruct);
        en.data_type_id = 40;
        for (i, &(label, hex_le, val)) in pairs.iter().enumerate() {
            en.entries.push(EntryInfo {
                sub_index: (i + 1) as u8,
                name: label.to_string(),
                data_type_id: 40,
                bit_length: bits,
                bit_offset: (i as i32) * bits,
                flags: FLAGS_RO,
                default_data: hex_le.to_string(),
                enum_value: Some(val as i32),
                ..Default::default()
            });
        }
        od.insert(en);
    }

    // PDOs 0x1601, 0x1603, 0x1A00, 0x1A02, 0x1AFF
    od.insert(build_pdo_map_object(0x1601, "RxPDO-Map", &["20001070"])?);
    {
        let mut p1603 = ObjectInfo::new(0x1603, "RxPDO-Map", ObjectCode::Record);
        p1603.data_type_id = 33;
        p1603
            .entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "01")?);
        p1603.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO_WP,
            "20003070",
        )?);
        od.insert(p1603);
    }
    od.insert(build_pdo_map_object(0x1A00, "TxPDO-Map", &["20000060"])?);
    {
        let mut p1a02 = ObjectInfo::new(0x1A02, "TxPDO-Map", ObjectCode::Record);
        p1a02.data_type_id = 33;
        p1a02
            .entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "01")?);
        p1a02.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO_WP,
            "10002060",
        )?);
        od.insert(p1a02);
    }
    if setting_bool(project, "DC_SUPPORTED") {
        let esm_maps = [
            0xA000_0110u32,
            0xA000_0210,
            0xA000_0310,
            0xA000_0410,
            0xA000_0510,
            0xA000_0601,
            0xA000_0701,
            0xA000_0801,
            0xA000_0901,
            0xA000_0A01,
            0xA000_0B01,
            0x0000_0002,
            0xA000_1101,
            0xA000_1201,
            0xA000_1301,
            0xA000_1401,
            0xA000_1501,
            0x0000_0003,
            0xA000_2110,
            0xA000_2210,
            0xA000_2310,
            0xA000_2410,
            0xA000_2510,
            0xA000_2610,
            0xA000_2710,
            0x1C32_0B10,
            0x1C33_0B10,
        ];
        let mut p1aff = ObjectInfo::new(0x1AFF, "TxPDO-Map Esm variables", ObjectCode::Record);
        p1aff.data_type_id = 33;
        for (i, &m) in esm_maps.iter().enumerate() {
            let si = (i + 1) as u8;
            p1aff.entries.push(make_entry(
                si,
                &format!("SubIndex {si:03}"),
                "UINT32",
                FLAGS_RO,
                &swap_u32_hex(m),
            )?);
        }
        od.insert(p1aff);
    }

    // 0x1C12, 0x1C13, 0x1C14
    {
        let mut sm2 = ObjectInfo::new(0x1C12, "RxPDO assign", ObjectCode::Array);
        sm2.data_type_id = 6;
        if setting_u16(project, "MAX_PD_OUTPUT_SIZE") > 0 {
            sm2.entries
                .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "01")?);
            sm2.entries.push(make_entry(
                1,
                "SubIndex 001",
                "UINT16",
                FLAGS_RO_WP,
                "0116",
            )?);
            sm2.entries.push(make_entry(
                2,
                "SubIndex 002",
                "UINT16",
                FLAGS_RO_WP,
                "0000",
            )?);
        } else {
            sm2.entries
                .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO, "00")?);
        }
        od.insert(sm2);
    }
    {
        let mut sm3 = ObjectInfo::new(0x1C13, "TxPDO assign", ObjectCode::Array);
        sm3.data_type_id = 6;
        if setting_u16(project, "MAX_PD_INPUT_SIZE") > 0 {
            sm3.entries
                .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO_WP, "01")?);
            sm3.entries.push(make_entry(
                1,
                "SubIndex 001",
                "UINT16",
                FLAGS_RO_WP,
                "001A",
            )?);
            sm3.entries.push(make_entry(
                2,
                "SubIndex 002",
                "UINT16",
                FLAGS_RO_WP,
                "0000",
            )?);
        } else {
            sm3.entries
                .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO, "00")?);
        }
        od.insert(sm3);
    }
    {
        let mut sm4 = ObjectInfo::new(0x1C14, "TxPDO assign", ObjectCode::Array);
        sm4.data_type_id = 6;
        sm4.entries
            .push(make_entry(0, "SubIndex 000", "UINT8", FLAGS_RO, "00")?);
        od.insert(sm4);
    }

    // Core test process data & MDP objects (`0x6000..0x7030`, `0xF000`, `0xF010`)
    od.insert(make_var_object(
        0x6000,
        "InputCounter",
        "UINT32",
        FLAGS_RO_TX,
        "",
    )?);
    od.insert(make_var_object(
        0x6020,
        "Counter Overrun",
        "UINT16",
        FLAGS_RO_TX,
        "",
    )?);
    od.insert(make_var_object(
        0x7010,
        "OutputCounter",
        "UINT32",
        FLAGS_RW_RX,
        "",
    )?);
    od.insert(make_var_object(
        0x7030,
        "Output Counter 1",
        "UINT32",
        FLAGS_RW_RX,
        "",
    )?);

    // 0x300C Alignment and Access Test Object (covers WO/RW/RO access tests)
    {
        let mut o300c = ObjectInfo::new(
            0x300C,
            "Alignment and Access Test Object",
            ObjectCode::Record,
        );
        o300c.entries.push(make_entry(
            1,
            "/*SI1*/UINT16_ro(0x1122)",
            "UINT16",
            FLAGS_RO,
            "2211",
        )?);
        o300c.entries.push(make_entry(
            2,
            "/*SI2*/UINT16_rw(0x3344)",
            "UINT16",
            FLAGS_RW,
            "4433",
        )?);
        o300c.entries.push(make_entry(
            3,
            "/*SI3*/UINT16_wo(0x5566)",
            "UINT16",
            FLAGS_WO,
            "6655",
        )?);
        od.insert(o300c);
    }

    {
        let mut f000 = ObjectInfo::new(0xF000, "Modular Device Profile", ObjectCode::Record);
        f000.data_type_id = 44;
        f000.entries
            .push(make_entry(1, "Index distance", "UINT16", FLAGS_RO, "1000")?);
        f000.entries.push(make_entry(
            2,
            "Maximum number of modules",
            "UINT16",
            FLAGS_RO,
            "0000",
        )?);
        od.insert(f000);
    }
    {
        let mut f010 = ObjectInfo::new(0xF010, "Module Profile List", ObjectCode::Array);
        f010.data_type_id = 7;
        f010.entries.push(make_entry(
            1,
            "SubIndex 001",
            "UINT32",
            FLAGS_RO,
            "00000000",
        )?);
        od.insert(f010);
    }

    let _ = swap_u16_hex(0);
    Ok(())
}
