pub mod dom;
pub mod parser;

use std::collections::BTreeMap;
use std::path::Path;

use ethercat_wire::error::Result;
use ethercat_wire::types::{parse_u64, DataTypeSpec};
use serde::Serialize;

/// Direction of cyclic process data relative to an EtherCAT slave.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum PdoDirection {
    /// Master -> Slave outputs (`SM2`, `0x1600..0x17FF`, `0x1C12`).
    RxPdo,
    /// Slave -> Master inputs (`SM3`, `0x1A00..0x1BFF`, `0x1C13`).
    TxPdo,
}

impl PdoDirection {
    pub fn label(self) -> &'static str {
        match self {
            Self::RxPdo => "RxPDO",
            Self::TxPdo => "TxPDO",
        }
    }
}

/// Resolved XML data type metadata from `<Dictionary><DataTypes>`.
#[derive(Debug, Clone, Default)]
pub struct XmlDataType {
    pub name: String,
    pub base_type: Option<String>,
    pub bit_size: u32,
    pub enum_map: BTreeMap<i64, String>,
    pub array_elements: Option<(u16, u16)>, // (lbound, elements)
    pub subitems: Vec<XmlSubItemDef>,
}

#[derive(Debug, Clone)]
pub struct XmlSubItemDef {
    pub subindex: Option<u8>,
    pub name: String,
    pub type_name: String,
    pub bit_size: u32,
    pub bit_offset: Option<u32>,
    pub access: Option<String>,
    pub pdo_mapping: Option<String>,
    pub unit: Option<String>,
    pub default_hex: Option<String>,
}

/// Resolved CoE Object Dictionary sub-entry (`subindex 0..255`).
#[derive(Debug, Clone, Serialize)]
pub struct OdSubEntry {
    pub subindex: u8,
    pub name: String,
    pub type_name: String,
    #[serde(skip)]
    pub wire_type: DataTypeSpec,
    pub bit_length: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_offset: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdo_mapping: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_hex: Option<String>,
    #[serde(skip)]
    pub enum_values: BTreeMap<i64, String>,
}

/// Resolved CoE Object Dictionary object (`0x1000..0xFFFF`).
#[derive(Debug, Clone, Serialize)]
pub struct OdObject {
    pub index: u16,
    pub name: String,
    pub object_code: &'static str,
    pub type_name: String,
    pub bit_size: u32,
    pub subentries: BTreeMap<u8, OdSubEntry>,
}

/// Candidate PDO entry defined in `<RxPdo>` / `<TxPdo>` or OD `0x16xx` / `0x1Axx`.
#[derive(Debug, Clone, Serialize)]
pub struct XmlPdoEntry {
    pub entry_index: u16,
    pub entry_subindex: u8,
    pub bit_length: u16,
    pub name: String,
    pub data_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip)]
    pub wire_type: DataTypeSpec,
    #[serde(skip)]
    pub enum_values: BTreeMap<i64, String>,
}

/// Candidate PDO block (`0x1600..0x17FF` or `0x1A00..0x1BFF`).
#[derive(Debug, Clone, Serialize)]
pub struct XmlPdoDef {
    pub pdo_index: u16,
    pub name: String,
    pub direction: PdoDirection,
    pub default_sm: Option<u8>,
    pub fixed: bool,
    pub mandatory: bool,
    /// Optional logical bit offset when loaded from an ENI (`<EtherCATConfig>`) process image.
    pub eni_bit_offset: Option<usize>,
    pub entries: Vec<XmlPdoEntry>,
}

impl XmlPdoDef {
    pub fn total_bits(&self) -> usize {
        self.entries.iter().map(|e| e.bit_length as usize).sum()
    }
}

/// SyncManager descriptor from `<Sm>` in ESI or ENI.
#[derive(Debug, Clone, Serialize)]
pub struct XmlSmDef {
    pub sm_index: u8,
    pub role: String,
    pub start_address: Option<u16>,
    pub default_size: Option<u16>,
    pub control_byte: Option<u8>,
    pub enable: bool,
}

/// MDP `<Module>` definition from `<Descriptions><Modules><Module>` in ESI XML.
#[derive(Debug, Clone, Serialize)]
pub struct XmlModuleDef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_ident: Option<u32>,
    pub name: String,
    pub objects: BTreeMap<u16, OdObject>,
    pub rx_pdos: Vec<XmlPdoDef>,
    pub tx_pdos: Vec<XmlPdoDef>,
}

/// MDP `<Slots>` increment specification on a modular `<Device>`.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct XmlSlotsSpec {
    pub slot_pdo_increment: u16,
    pub slot_index_increment: u16,
    pub max_slot_count: usize,
}

/// Complete resolved XML profile for a single EtherCAT slave `<Device>` (or `<EtherCATDict>` / ENI `<Slave>`).
#[derive(Debug, Clone, Serialize)]
pub struct XmlDeviceProfile {
    pub vendor_id: Option<u32>,
    pub vendor_name: Option<String>,
    pub type_code: String,
    pub name: String,
    pub product_code: Option<u32>,
    pub revision_no: Option<u32>,
    /// Optional configured station address from ENI `<Slave><Info><PhysAddr>`.
    pub configured_station_addr: Option<u16>,
    #[serde(skip)]
    pub is_eni: bool,
    #[serde(skip)]
    pub coe_flags_explicit: bool,
    pub coe_supported: bool,
    pub coe_pdo_assign: bool,
    pub coe_pdo_config: bool,
    pub sync_managers: Vec<XmlSmDef>,
    pub objects: BTreeMap<u16, OdObject>,
    pub rx_pdos: BTreeMap<u16, XmlPdoDef>,
    pub tx_pdos: BTreeMap<u16, XmlPdoDef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots: Option<XmlSlotsSpec>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub modules: Vec<XmlModuleDef>,
    #[serde(skip)]
    pub has_mdp_base_snapshot: bool,
    #[serde(skip)]
    pub base_objects: BTreeMap<u16, OdObject>,
    #[serde(skip)]
    pub base_rx_pdos: BTreeMap<u16, XmlPdoDef>,
    #[serde(skip)]
    pub base_tx_pdos: BTreeMap<u16, XmlPdoDef>,
}

fn is_od_object_writable(obj: &OdObject) -> bool {
    obj.subentries.values().any(|sub| {
        sub.access
            .as_ref()
            .is_some_and(|a| a.to_ascii_lowercase().contains('w'))
    })
}

impl XmlDeviceProfile {
    /// Returns a clean base profile prior to any default MDP `<Slot>` instantiations so dynamic
    /// runtime `0xF030` module lists replace slots cleanly without stale default slot entries.
    pub fn clean_base_for_mdp(&self) -> XmlDeviceProfile {
        let mut c = self.clone();
        if self.has_mdp_base_snapshot {
            c.objects = self.base_objects.clone();
            c.rx_pdos = self.base_rx_pdos.clone();
            c.tx_pdos = self.base_tx_pdos.clone();
        }
        c
    }

    /// Returns true if PDO field layout in `direction` requires CoE SDO configuration
    /// (`0x1C12`/`0x1C13` or `0x16xx`/`0x1Axx`) rather than fixed hardware SM/FMMU activation.
    pub fn uses_coe_pdo_configuration_dir(&self, direction: PdoDirection) -> bool {
        if !self.coe_supported {
            return false;
        }
        let (assign_idx, map_range, pdos) = match direction {
            PdoDirection::RxPdo => (0x1C12u16, 0x1600u16..=0x17FFu16, &self.rx_pdos),
            PdoDirection::TxPdo => (0x1C13u16, 0x1A00u16..=0x1BFFu16, &self.tx_pdos),
        };
        if self.is_eni {
            if !pdos.is_empty() {
                return false;
            }
            return self.objects.contains_key(&assign_idx)
                || self.objects.keys().any(|k| map_range.contains(k));
        }
        if self.coe_pdo_assign || self.coe_pdo_config {
            return true;
        }
        if self.coe_flags_explicit
            && self.slots.is_none()
            && pdos.values().any(|p| p.default_sm.is_some() || p.fixed)
        {
            return false;
        }
        if self
            .objects
            .get(&assign_idx)
            .is_some_and(is_od_object_writable)
            || self
                .objects
                .iter()
                .any(|(k, o)| map_range.contains(k) && is_od_object_writable(o))
        {
            return true;
        }
        // Multiple alternative PDOs where some are unassigned (`default_sm.is_none()`) or malleable (`!fixed`)
        (pdos.len() > 1 && pdos.values().any(|p| p.default_sm.is_none()))
            || pdos.values().any(|p| !p.fixed && p.default_sm.is_none())
    }

    /// Returns true if either RxPDO or TxPDO layout can vary via CoE SDO configuration.
    pub fn uses_coe_pdo_configuration(&self) -> bool {
        self.uses_coe_pdo_configuration_dir(PdoDirection::RxPdo)
            || self.uses_coe_pdo_configuration_dir(PdoDirection::TxPdo)
    }

    /// Instantiates a modular MDP `<Module>` at 0-based `slot_index` using `<Slots>` increments.
    pub fn instantiate_module_at_slot(
        &self,
        slot_index: usize,
        module: &XmlModuleDef,
    ) -> (Vec<XmlPdoDef>, Vec<XmlPdoDef>, BTreeMap<u16, OdObject>) {
        let spec = self.slots.unwrap_or(XmlSlotsSpec {
            slot_pdo_increment: 1,
            slot_index_increment: 0x0010,
            max_slot_count: 16,
        });
        let pdo_off = (slot_index as u16).saturating_mul(spec.slot_pdo_increment);
        let idx_off = (slot_index as u16).saturating_mul(spec.slot_index_increment);
        let shift_obj_idx = |idx: u16| -> u16 {
            if (0x6000..=0x9FFF).contains(&idx) {
                idx.saturating_add(idx_off)
            } else {
                idx
            }
        };

        let mut shifted_objs = BTreeMap::new();
        for (&oidx, obj) in &module.objects {
            let new_idx = shift_obj_idx(oidx);
            let mut c = obj.clone();
            c.index = new_idx;
            if slot_index > 0 {
                c.name = format!("Slot{} {}", slot_index + 1, c.name);
            }
            shifted_objs.insert(new_idx, c);
        }

        let shift_pdo = |p: &XmlPdoDef| -> XmlPdoDef {
            let mut cp = p.clone();
            cp.pdo_index = cp.pdo_index.saturating_add(pdo_off);
            if slot_index > 0 {
                cp.name = format!("Slot{} {}", slot_index + 1, cp.name);
            }
            for e in &mut cp.entries {
                e.entry_index = shift_obj_idx(e.entry_index);
                if slot_index > 0 && e.entry_index != 0 {
                    e.name = format!("Slot{}_{}", slot_index + 1, e.name);
                }
            }
            cp
        };

        let rx = module.rx_pdos.iter().map(shift_pdo).collect();
        let tx = module.tx_pdos.iter().map(shift_pdo).collect();
        (rx, tx, shifted_objs)
    }

    /// Resolves a mapped `(entry_index, entry_subindex, bit_length)` tuple against this profile's
    /// Object Dictionary and candidate PDO entry tables.
    pub fn resolve_pdo_entry(
        &self,
        entry_index: u16,
        entry_subindex: u8,
        bit_length: u16,
    ) -> XmlPdoEntry {
        if entry_index == 0 {
            return XmlPdoEntry {
                entry_index: 0,
                entry_subindex,
                bit_length,
                name: "Gap/Padding".into(),
                data_type: format!("BIT{bit_length}"),
                unit: None,
                wire_type: DataTypeSpec::Hex,
                enum_values: BTreeMap::new(),
            };
        }
        if let Some(obj) = self.objects.get(&entry_index) {
            if let Some(sub) = obj.subentries.get(&entry_subindex) {
                let effective_name = if obj.subentries.len() <= 1
                    || sub.name.eq_ignore_ascii_case(&obj.name)
                    || entry_subindex == 0
                {
                    obj.name.clone()
                } else {
                    format!("{}.{}", obj.name, sub.name)
                };
                return XmlPdoEntry {
                    entry_index,
                    entry_subindex,
                    bit_length,
                    name: effective_name,
                    data_type: sub.type_name.clone(),
                    unit: sub.unit.clone(),
                    wire_type: sub.wire_type,
                    enum_values: sub.enum_values.clone(),
                };
            }
        }
        for pdo in self.rx_pdos.values().chain(self.tx_pdos.values()) {
            if let Some(found) = pdo
                .entries
                .iter()
                .find(|e| e.entry_index == entry_index && e.entry_subindex == entry_subindex)
            {
                let mut cloned = found.clone();
                if bit_length > 0 {
                    cloned.bit_length = bit_length;
                }
                return cloned;
            }
        }
        XmlPdoEntry {
            entry_index,
            entry_subindex,
            bit_length,
            name: format!("0x{entry_index:04x}:{entry_subindex:02x}"),
            data_type: default_type_for_bits(bit_length).0.into(),
            unit: None,
            wire_type: default_type_for_bits(bit_length).1,
            enum_values: BTreeMap::new(),
        }
    }
}

pub fn default_type_for_bits(bits: u16) -> (&'static str, DataTypeSpec) {
    match bits {
        1 => ("BOOL", DataTypeSpec::Bool),
        2..=8 => ("USINT", DataTypeSpec::U8),
        9..=16 => ("UINT", DataTypeSpec::U16),
        17..=24 => ("UINT24", DataTypeSpec::U24),
        25..=32 => ("UDINT", DataTypeSpec::U32),
        33..=64 => ("ULINT", DataTypeSpec::U64),
        _ => ("OCTET_STRING", DataTypeSpec::Hex),
    }
}

/// Maps an ETG.2000 / IEC 61131-3 XML data type name + bit size to `DataTypeSpec`.
pub fn xml_type_to_wire_spec(type_name: &str, bit_size: u32) -> DataTypeSpec {
    let up = type_name.trim().to_ascii_uppercase();
    match up.as_str() {
        "BOOL" | "BOOLEAN" | "BIT" | "BIT1" => DataTypeSpec::Bool,
        "SINT" | "INT8" => DataTypeSpec::I8,
        "USINT" | "BYTE" | "UINT8" | "BIT2" | "BIT3" | "BIT4" | "BIT5" | "BIT6" | "BIT7"
        | "BIT8" | "BITARR8" => DataTypeSpec::U8,
        "INT" | "INT16" => DataTypeSpec::I16,
        "UINT" | "WORD" | "UINT16" | "BITARR16" | "BIT9" | "BIT10" | "BIT11" | "BIT12"
        | "BIT13" | "BIT14" | "BIT15" | "BIT16" => DataTypeSpec::U16,
        "INT24" => DataTypeSpec::I24,
        "UINT24" => DataTypeSpec::U24,
        "DINT" | "INT32" => DataTypeSpec::I32,
        "UDINT" | "DWORD" | "UINT32" | "BITARR32" => DataTypeSpec::U32,
        "REAL" | "FLOAT" | "REAL32" => DataTypeSpec::F32,
        "LREAL" | "DOUBLE" | "REAL64" => DataTypeSpec::F64,
        "INT40" | "INT48" | "INT56" | "LINT" | "INT64" => DataTypeSpec::I64,
        "UINT40" | "UINT48" | "UINT56" | "ULINT" | "LWORD" | "UINT64" | "TIME_OF_DAY"
        | "TIME_DIFFERENCE" => DataTypeSpec::U64,
        _ if up.starts_with("STRING")
            || up == "VISIBLE_STRING"
            || up.starts_with("UNICODE_STRING") =>
        {
            DataTypeSpec::String
        }
        _ if up.starts_with("OCTET_STRING") || up.starts_with("ARRAY") => DataTypeSpec::Hex,
        _ => match bit_size {
            1 => DataTypeSpec::Bool,
            2..=8 => DataTypeSpec::U8,
            9..=16 => DataTypeSpec::U16,
            17..=24 => DataTypeSpec::U24,
            25..=32 => DataTypeSpec::U32,
            33..=64 => DataTypeSpec::U64,
            _ => DataTypeSpec::Hex,
        },
    }
}

/// Catalog of one or more `XmlDeviceProfile`s loaded from an XML file or directory.
#[derive(Debug, Clone, Default, Serialize)]
pub struct XmlCatalog {
    pub source_kind: String,
    pub devices: Vec<XmlDeviceProfile>,
}

impl XmlCatalog {
    pub fn load_from_path(path: &Path) -> Result<Self> {
        parser::load_xml_catalog(path)
    }

    pub fn load_from_paths<P: AsRef<Path>>(paths: &[P]) -> Result<Self> {
        let mut iter = paths.iter();
        let Some(first) = iter.next() else {
            return Err(ethercat_wire::error::CliError::Usage(
                "at least one XML path is required".into(),
            ));
        };
        let mut combined = Self::load_from_path(first.as_ref())?;
        for p in iter {
            let next = Self::load_from_path(p.as_ref())?;
            combined.merge(next);
        }
        Ok(combined)
    }

    pub fn merge(&mut self, other: Self) {
        if self.source_kind.is_empty() {
            self.source_kind = other.source_kind;
        } else if !other.source_kind.is_empty() && !self.source_kind.contains(&other.source_kind) {
            self.source_kind = format!("{} + {}", self.source_kind, other.source_kind);
        }
        self.devices.extend(other.devices);
    }

    pub fn parse_from_str(xml_text: &str, base_dir: Option<&Path>) -> Result<Self> {
        parser::parse_xml_catalog_str(xml_text, base_dir)
    }

    pub fn parse_xml_str(xml_text: &str) -> Result<Self> {
        parser::parse_xml_catalog_str(xml_text, None)
    }

    pub fn parse_xml_bytes(raw: &[u8]) -> Result<Self> {
        let text = dom::decode_xml_bytes(raw)?;
        parser::parse_xml_catalog_str(&text, None)
    }

    /// Selects a device profile matching an explicit selector (`type_code`, `name`, or `product_code`).
    pub fn select_device(&self, selector: Option<&str>) -> Option<&XmlDeviceProfile> {
        if let Some(sel) = selector {
            let s = sel.trim();
            if !s.is_empty() {
                if let Some(d) = self
                    .devices
                    .iter()
                    .find(|d| d.type_code.eq_ignore_ascii_case(s) || d.name.eq_ignore_ascii_case(s))
                {
                    return Some(d);
                }
                if let Ok(num) = parse_u64(s) {
                    if let Some(d) = self.devices.iter().find(|d| {
                        d.product_code == Some(num as u32)
                            || d.configured_station_addr == Some(num as u16)
                    }) {
                        return Some(d);
                    }
                    if let Some(d) = self.devices.get(num as usize) {
                        return Some(d);
                    }
                }
                let sl = s.to_ascii_lowercase();
                if let Some(d) = self.devices.iter().find(|d| {
                    d.type_code.to_ascii_lowercase().contains(&sl)
                        || d.name.to_ascii_lowercase().contains(&sl)
                }) {
                    return Some(d);
                }
            }
        }
        (self.devices.len() == 1).then(|| &self.devices[0])
    }

    /// Matches a device by ENI configured station address, `(product_code, revision_no)`, or `product_code`.
    pub fn match_slave(
        &self,
        station_addr: Option<u16>,
        product_code: Option<u32>,
        revision_no: Option<u32>,
        explicit_selector: Option<&str>,
    ) -> Option<&XmlDeviceProfile> {
        self.match_slave_ext(
            station_addr,
            None,
            None,
            product_code,
            revision_no,
            explicit_selector,
        )
    }

    /// Extended multi-slave matcher incorporating `vendor_id`, `product_code`, `revision_no`,
    /// ENI `configured_station_addr`, and ENI physical ring position (`topo_pos`, 0-based).
    pub fn match_slave_ext(
        &self,
        station_addr: Option<u16>,
        topo_pos: Option<u16>,
        vendor_id: Option<u32>,
        product_code: Option<u32>,
        revision_no: Option<u32>,
        explicit_selector: Option<&str>,
    ) -> Option<&XmlDeviceProfile> {
        // 1. Observed hardware identity (`ProductCode` / `VendorId` / `RevisionNo` from SII or 0x1018)
        if let Some(pc) = product_code {
            if let (Some(vid), Some(rev)) = (vendor_id, revision_no) {
                if let Some(d) = self.devices.iter().find(|d| {
                    d.vendor_id == Some(vid)
                        && d.product_code == Some(pc)
                        && d.revision_no == Some(rev)
                }) {
                    return Some(d);
                }
            }
            if let Some(rev) = revision_no {
                if let Some(d) = self
                    .devices
                    .iter()
                    .find(|d| d.product_code == Some(pc) && d.revision_no == Some(rev))
                {
                    return Some(d);
                }
            }
            if let Some(vid) = vendor_id {
                if let Some(d) = self
                    .devices
                    .iter()
                    .find(|d| d.vendor_id == Some(vid) && d.product_code == Some(pc))
                {
                    return Some(d);
                }
            }
            if let Some(d) = self.devices.iter().find(|d| d.product_code == Some(pc)) {
                return Some(d);
            }
        }
        // 2. Explicit `--xml-device` selector
        if let Some(sel) = explicit_selector {
            if let Some(d) = self.select_device(Some(sel)) {
                return Some(d);
            }
        }
        // 3. ENI `<Slave><Info><PhysAddr>` exact station address match
        if let Some(st) = station_addr {
            if let Some(d) = self
                .devices
                .iter()
                .find(|d| d.configured_station_addr == Some(st))
            {
                return Some(d);
            }
        }
        // 4. ENI `<Config><Slave>` ring topology order (0-based auto-increment position)
        if let Some(tp) = topo_pos {
            if let Some(d) = self.devices.get(tp as usize) {
                if d.is_eni && (station_addr.is_none() || d.configured_station_addr.is_none()) {
                    return Some(d);
                }
            }
        }
        self.devices.first()
    }

    /// Resolves an Object Dictionary `index` across the catalog (preferring `preferred` device first,
    /// without bleeding across unrelated `<Device>` profiles when `preferred` is known).
    pub fn find_object<'a>(
        &'a self,
        index: u16,
        preferred: Option<&'a XmlDeviceProfile>,
    ) -> Option<(&'a XmlDeviceProfile, &'a OdObject)> {
        if let Some(dev) = preferred {
            if let Some(obj) = dev.objects.get(&index) {
                return Some((dev, obj));
            }
            // Only fall through to supplemental entries representing the same device (e.g. ENI + ESI/Dict)
            for cand in &self.devices {
                let same_hw = dev.product_code.is_some()
                    && cand.product_code == dev.product_code
                    && (dev.vendor_id.is_none()
                        || cand.vendor_id.is_none()
                        || cand.vendor_id == dev.vendor_id);
                let dict_supplement = dev.is_eni
                    && !cand.is_eni
                    && cand.product_code.is_none()
                    && cand.configured_station_addr.is_none();
                if same_hw || dict_supplement {
                    if let Some(obj) = cand.objects.get(&index) {
                        return Some((cand, obj));
                    }
                }
            }
            return None;
        }
        for dev in &self.devices {
            if let Some(obj) = dev.objects.get(&index) {
                return Some((dev, obj));
            }
        }
        None
    }
}
