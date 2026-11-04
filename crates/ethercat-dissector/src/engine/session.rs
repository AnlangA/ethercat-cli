use std::collections::{BTreeMap, VecDeque};

use ethercat_wire::error::Result;
use ethercat_wire::protocol::constants::EcatCmd;
use ethercat_wire::types::{extract_bits_le, format_hex};
use serde_json::{json, Value};

use crate::engine::sdo::{
    decode_sdo_with_xml, decode_xml_scalar_ext, emit_sdo_xml_ws, parse_ca_header,
};
use crate::layers::ams::dissect_ams_tcp_multi;
use crate::layers::mailbox::{
    dissect_coe_sdo_info, dissect_eoe_inner_frame, dissect_mailbox_ext,
    dissect_mailbox_sdo_subblock, sdo_block_crc16,
};
use crate::model::{
    DissectOptions, DissectedDatagram, DissectedFrame, EoeFragmentInfo, SdoEventKind,
    SdoInfoFragmentInfo, SdoXmlDecode,
};
use crate::xml::{PdoDirection, XmlCatalog, XmlDeviceProfile, XmlPdoEntry};

const MAX_AMS_TCP_REASSEMBLY_LEN: usize = 262_144;
const MAX_EOE_REASSEMBLY_LEN: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SdoTransferDir {
    Download,
    Upload,
}

#[derive(Debug, Clone)]
struct InFlightSdo {
    dir: SdoTransferDir,
    index: u16,
    subindex: u8,
    complete_access: bool,
    expected_len: Option<usize>,
    buffer: Vec<u8>,
    segments: usize,
    last_toggle: Option<bool>,
}

#[derive(Debug, Clone)]
struct InFlightBlockSdo {
    dir: SdoTransferDir,
    index: u16,
    subindex: u8,
    complete_access: bool,
    client_crc: bool,
    server_crc: Option<bool>,
    expected_len: Option<usize>,
    buffer: Vec<u8>,
    segments: usize,
    last_subblock_len: usize,
    streaming_subblocks: bool,
    max_seq_in_block: usize,
    block_byte_offsets: [usize; 128],
    last_seq_sig: Option<(u8, bool, Vec<u8>)>,
}

impl InFlightBlockSdo {
    #[allow(clippy::too_many_arguments)]
    fn new(
        dir: SdoTransferDir,
        index: u16,
        subindex: u8,
        complete_access: bool,
        client_crc: bool,
        server_crc: Option<bool>,
        expected_len: Option<usize>,
        streaming_subblocks: bool,
    ) -> Self {
        Self {
            dir,
            index,
            subindex,
            complete_access,
            client_crc,
            server_crc,
            expected_len,
            buffer: Vec::new(),
            segments: 0,
            last_subblock_len: 0,
            streaming_subblocks,
            max_seq_in_block: 0,
            block_byte_offsets: [0usize; 128],
            last_seq_sig: None,
        }
    }

    fn crc_enabled(&self) -> bool {
        match self.server_crc {
            Some(sc) => self.client_crc && sc,
            None => self.client_crc,
        }
    }
}

#[derive(Debug, Clone)]
struct InFlightEoe {
    frame_no: u8,
    expected_frag_no: u8,
    buffer: Vec<u8>,
    max_end: usize,
    fragments: usize,
    last_frag_sig: Option<(u8, bool, Vec<u8>)>,
}

#[derive(Debug, Clone, Default)]
struct AmsTcpStreamState {
    buffer: Vec<u8>,
    next_seq: Option<u32>,
    recent_bytes: Vec<u8>,
    ooo_segments: BTreeMap<u32, Vec<u8>>,
    last_seg_sig: Option<(Option<u32>, Vec<u8>)>,
    segments_in_current_pdu: usize,
}

#[derive(Debug, Clone, Copy)]
struct MappedEntryRaw {
    entry_index: u16,
    entry_subindex: u8,
    bit_length: u16,
}

#[derive(Debug, Clone, Default)]
struct DynamicPdoMap {
    staged: BTreeMap<u8, MappedEntryRaw>,
    /// `None` = untouched in trace; `Some(0)` = cleared / being edited; `Some(n)` = active `1..=n`.
    committed_count: Option<u8>,
    /// `true` ONLY when `0x16xx`/`0x1Axx` was written via SDO Download (not merely read via SDO Upload).
    explicitly_written: bool,
    /// Deferred count & staged map for an in-progress SDO Upload scan (`sub0` -> `sub1..=subN`).
    pending_upload_count: Option<u8>,
    upload_staged: BTreeMap<u8, MappedEntryRaw>,
}

#[derive(Debug, Clone, Default)]
struct DynamicSmAssign {
    staged: BTreeMap<u8, u16>,
    /// `None` = untouched in trace; `Some([])` = cleared (`sub0=0`); `Some([0x1600, ...])` = active assignment.
    committed: Option<Vec<u16>>,
    /// Deferred count & staged map when `sub0` was read via SDO Upload before `sub1..=subN` were read.
    pending_upload_count: Option<u8>,
    upload_staged: BTreeMap<u8, u16>,
}

#[derive(Debug, Clone, Default, Copy)]
struct FmmuShadow {
    log_start: u32,
    log_len: u16,
    log_start_bit: u8,
    log_end_bit: u8,
    phys_start: u16,
    phys_start_bit: u8,
    read_enable: bool,
    write_enable: bool,
    active: bool,
}

impl FmmuShadow {
    fn total_bits(&self) -> usize {
        if self.log_len == 0 {
            return 0;
        }
        if self.log_len == 1 {
            (self.log_end_bit.saturating_sub(self.log_start_bit) as usize) + 1
        } else {
            (8 - self.log_start_bit as usize)
                + ((self.log_len as usize - 2) * 8)
                + (self.log_end_bit as usize + 1)
        }
    }

    /// Returns the bit offset within the slave's process-data SyncManager if this FMMU maps
    /// process data (filtering out ESC status-register FMMUs such as TwinCAT FMMU2 `0x080D`).
    fn maps_process_data(&self, sm_regs: &[SmShadow; 16], want_write: bool) -> Option<usize> {
        let mut any_matching_sm = false;
        for sm in sm_regs {
            if sm.enabled && !sm.is_mailbox && sm.direction_write == want_write {
                any_matching_sm = true;
                let sm_end = sm.phys_start.saturating_add(sm.length.max(1));
                if self.phys_start >= sm.phys_start && (sm.length == 0 || self.phys_start < sm_end)
                {
                    let byte_delta = (self.phys_start - sm.phys_start) as usize;
                    return Some(byte_delta * 8 + (self.phys_start_bit as usize));
                }
            }
        }
        if any_matching_sm {
            return None;
        }
        // When SM register writes were not in the trace, require ESC Digital I/O (`0x0F00..0x0FFF`,
        // e.g. EL2004/EL2008 `StartAddress="#x0F00"`) or Process Data RAM (`>= 0x1000`),
        // still excluding `< 0x0F00` status registers such as TwinCAT FMMU2 `0x080D` / AL `0x0130`.
        (self.phys_start >= 0x0F00).then_some(self.phys_start_bit as usize)
    }
}

#[derive(Debug, Clone, Default, Copy)]
struct SmShadow {
    phys_start: u16,
    length: u16,
    direction_write: bool,
    is_mailbox: bool,
    enabled: bool,
}

#[derive(Debug, Clone)]
struct ResolvedPdoField {
    pdo_index: u16,
    rel_bit_offset: usize,
    entry: XmlPdoEntry,
}

#[derive(Debug, Clone)]
struct ActivePdoBank {
    direction: PdoDirection,
    assigned_pdos: Vec<u16>,
    fields: Vec<ResolvedPdoField>,
    total_bits: usize,
    eni_bit_offset: Option<usize>,
}

impl ActivePdoBank {
    fn total_bytes(&self) -> usize {
        self.total_bits.div_ceil(8)
    }
}

#[derive(Debug, Clone)]
struct PdoStateSnapshot {
    index: u16,
    subindex: u8,
    mdp_staged_idents: BTreeMap<u8, u32>,
    mdp_committed_idents: Option<Vec<u32>>,
    mdp_profile_override: Option<XmlDeviceProfile>,
    dynamic_rx_pdos: BTreeMap<u16, DynamicPdoMap>,
    dynamic_tx_pdos: BTreeMap<u16, DynamicPdoMap>,
    sm2_assign: DynamicSmAssign,
    sm3_assign: DynamicSmAssign,
    rx_active: Option<ActivePdoBank>,
    tx_active: Option<ActivePdoBank>,
}

type CachedDlEcho = (
    Vec<u8>,
    Option<SdoXmlDecode>,
    Option<(bool, u16)>,
    Option<Vec<u8>>,
);

#[derive(Debug, Clone, Default)]
struct SlaveRuntime {
    slot_id: usize,
    topo_pos: Option<u16>,
    station_addr: Option<u16>,
    alias_addr: Option<u16>,
    vendor_id: Option<u32>,
    product_code: Option<u32>,
    revision_no: Option<u32>,
    foe_efw_active: bool,
    in_safeop_or_op: bool,

    // SII EEPROM identity shadow (`0x0502..0x050F` -> EEPROM bytes `0x00..0x20`)
    sii_addr_reg: u32,
    sii_pending_word: Option<u32>,
    sii_r64: Option<bool>,
    sii_head: [Option<u8>; 32],

    // Pending Initiate Upload Request `(index, subindex, complete_access)`
    pending_upload_req: Option<(u16, u8, bool)>,
    pending_block_ul_req: Option<(u16, u8, bool, bool)>,
    in_flight_dl: Option<InFlightSdo>,
    in_flight_ul: Option<InFlightSdo>,
    in_flight_block_dl: Option<InFlightBlockSdo>,
    in_flight_block_ul: Option<InFlightBlockSdo>,
    last_dl_subblock_raw: Option<Vec<u8>>,
    last_dl_echo_enrichment: Option<CachedDlEcho>,
    last_dl_pdo_snapshot: Option<PdoStateSnapshot>,

    // Multi-fragment CoE SDO Information (`0x02`/`0x04`/`0x06`) reassembly: `(opcode, number, rest_buf, frags)`
    in_flight_sdo_info: Option<(u8, u16, Vec<u8>, usize)>,

    // Multi-fragment EoE reassembly keyed by `(is_slave_to_master, eoe_port)`
    in_flight_eoe: BTreeMap<(bool, u8), InFlightEoe>,

    // Hardware SyncManager & FMMU shadow tables
    sm_regs: [SmShadow; 16],
    fmmu_regs: [FmmuShadow; 16],
    has_active_fmmu: bool,

    // Dynamic Modular Device Profile (`0xF030` Configured Module Ident List)
    mdp_staged_idents: BTreeMap<u8, u32>,
    mdp_committed_idents: Option<Vec<u32>>,
    mdp_pending_upload_count: Option<u8>,
    mdp_upload_staged: BTreeMap<u8, u32>,
    mdp_profile_override: Option<XmlDeviceProfile>,

    // Temporal PDO configuration state observed from packet sequence
    dynamic_rx_pdos: BTreeMap<u16, DynamicPdoMap>,
    dynamic_tx_pdos: BTreeMap<u16, DynamicPdoMap>,
    sm2_assign: DynamicSmAssign,
    sm3_assign: DynamicSmAssign,

    // Active PDO layouts — STRICTLY `None` until PDO configuration packets are observed in trace!
    rx_active: Option<ActivePdoBank>,
    tx_active: Option<ActivePdoBank>,
}

impl SlaveRuntime {
    fn label(&self) -> String {
        if let Some(st) = self.station_addr {
            format!("0x{st:04x}")
        } else if let Some(tp) = self.topo_pos {
            format!("pos:{tp}")
        } else {
            format!("slot:{}", self.slot_id)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TxWriteEchoKey {
    slot: Option<usize>,
    cmd: u8,
    idx: u8,
    ado: u16,
    data: Vec<u8>,
}

type AmsTcpStreamKey = (String, u16, String, u16);
type AoeReadKey = (String, u16, u32);

/// Stateful, time-ordered EtherCAT dissection session.
///
/// Tracks slave station addresses (`0x0010`), SII EEPROM identity (`0x0502..0x050F`),
/// CoE SDO segmented & block transfers (including CRC-16), EoE multi-fragment Ethernet frames,
/// `AMS/TCP` (`48898`) multi-segment stream reassembly, ESC SyncManager/FMMU mappings, and CoE PDO
/// configuration sequences (`0x1600..0x17FF`, `0x1A00..0x1BFF`, `0x1C12`, `0x1C13`).
///
/// **Temporal PDO Invariant**: Cyclic process-data frames appearing *before* PDO configuration
/// packets in the capture sequence are intentionally NOT decoded into XML PDO fields, because
/// the active field mapping is unknown until observed in the configuration sequence.
pub struct DissectSession {
    options: DissectOptions,
    packet_counter: usize,
    current_pkt_idx: usize,
    ring_slave_count: Option<u16>,
    prev_dc_cur_time: Option<u32>,
    direct_foe_efw_active: bool,
    direct_in_flight_sdo_info: Option<(u8, u16, Vec<u8>, usize)>,
    direct_in_flight_eoe: BTreeMap<(u16, u8), InFlightEoe>,
    ams_tcp_streams: BTreeMap<AmsTcpStreamKey, AmsTcpStreamState>,
    pending_aoe_sdo_reads: BTreeMap<AoeReadKey, (usize, u16, u8, bool)>,
    pending_aoe_sdo_writes: BTreeMap<AoeReadKey, (usize, u16, u8)>,
    slaves: Vec<SlaveRuntime>,
    topo_to_slot: BTreeMap<u16, usize>,
    station_to_slot: BTreeMap<u16, usize>,
    alias_to_slot: BTreeMap<u16, usize>,
    recent_tx_writes: VecDeque<(usize, TxWriteEchoKey)>,
    recent_tx_autoinc: VecDeque<(usize, u8, u8, u16, usize)>, // (pkt_idx, cmd, idx, ado, slot)
}

impl DissectSession {
    pub fn new(options: DissectOptions) -> Self {
        Self {
            options,
            packet_counter: 0,
            current_pkt_idx: 0,
            ring_slave_count: None,
            prev_dc_cur_time: None,
            direct_foe_efw_active: false,
            direct_in_flight_sdo_info: None,
            direct_in_flight_eoe: BTreeMap::new(),
            ams_tcp_streams: BTreeMap::new(),
            pending_aoe_sdo_reads: BTreeMap::new(),
            pending_aoe_sdo_writes: BTreeMap::new(),
            slaves: Vec::new(),
            topo_to_slot: BTreeMap::new(),
            station_to_slot: BTreeMap::new(),
            alias_to_slot: BTreeMap::new(),
            recent_tx_writes: VecDeque::with_capacity(256),
            recent_tx_autoinc: VecDeque::with_capacity(64),
        }
    }

    pub fn options(&self) -> &DissectOptions {
        &self.options
    }

    /// Dissects the next time-ordered packet in the capture sequence, updating session state
    /// and applying XML SDO + post-configuration XML PDO decoding.
    pub fn dissect_next(&mut self, raw: &[u8]) -> Result<DissectedFrame> {
        let pkt_idx = self.packet_counter;
        self.dissect_packet(pkt_idx, raw)
    }

    /// Dissects a time-ordered packet with an explicit capture `packet_index`, updating session
    /// state and applying XML SDO + post-configuration XML PDO decoding.
    pub fn dissect_packet(&mut self, pkt_idx: usize, raw: &[u8]) -> Result<DissectedFrame> {
        self.current_pkt_idx = pkt_idx;
        self.packet_counter = pkt_idx.saturating_add(1);

        let mut frame = crate::dissect_frame_stateless_inner(raw, &self.options, false)?;
        frame.packet_index = Some(pkt_idx);

        // Stateful AMS/TCP (port 48898) stream reassembly across TCP segments
        if let Some(raw_seg) = frame.raw_ams_tcp_segment.clone() {
            self.process_ams_tcp_segment(&raw_seg, &mut frame);
        }

        // Stateful FoE `.efw` firmware block tracking on direct mailbox frames (`ecatf.type == 5`)
        if let Some(mbx) = &frame.direct_mailbox {
            if let Some(wrq_fn) = &mbx.foe_wrq_filename {
                self.direct_foe_efw_active = wrq_fn.to_ascii_lowercase().ends_with(".efw");
            } else if self.direct_foe_efw_active && mbx.mbx_type == 0x04 {
                let raw_mbx = mbx.raw_bytes.clone();
                if let Some(re_mbx) =
                    dissect_mailbox_ext(&raw_mbx, &mut frame.wireshark_fields, "ecat_mailbox", true)
                {
                    frame.direct_mailbox = Some(re_mbx);
                }
            }
        }

        // Process direct mailbox (ecatf.type == 5)
        if let Some(mbx) = frame.direct_mailbox.as_ref() {
            let slot = self.get_or_create_station_slot(mbx.address.max(0x1001));
            let raw_mbx = mbx.raw_bytes.clone();
            if let Some(svc) = coe_mailbox_service_code(&raw_mbx) {
                let want_subblock = match svc {
                    0x02 => self.slaves[slot]
                        .in_flight_block_dl
                        .as_ref()
                        .is_some_and(|b| b.streaming_subblocks),
                    0x03 => self.slaves[slot]
                        .in_flight_block_ul
                        .as_ref()
                        .is_some_and(|b| b.streaming_subblocks),
                    _ => false,
                };
                if want_subblock {
                    if let Some(re_mbx) = dissect_mailbox_sdo_subblock(
                        &raw_mbx,
                        &mut frame.wireshark_fields,
                        "ecat_mailbox",
                        None,
                    ) {
                        frame.direct_mailbox = Some(re_mbx);
                    }
                }
            }
            if let Some(mbx_mut) = frame.direct_mailbox.as_mut() {
                if let Some(sinfo) = mbx_mut.sdo_info_fragment.clone() {
                    Self::process_sdo_info_fragment(
                        &mut self.direct_in_flight_sdo_info,
                        &sinfo,
                        &mut frame.wireshark_fields,
                        "ecat_mailbox",
                        None,
                        &mut mbx_mut.protocol,
                    );
                } else if mbx_mut.mbx_type == 0x03
                    && mbx_mut.protocol.get("service_code").and_then(Value::as_u64) == Some(8)
                {
                    self.direct_in_flight_sdo_info = None;
                }
                if let Some(ev) = mbx_mut.sdo_event.clone() {
                    let _ = self.process_sdo_event_for_slot(
                        slot,
                        &ev,
                        &mut frame.wireshark_fields,
                        "ecat_mailbox",
                        Some(&mut mbx_mut.protocol),
                        None,
                    );
                }
                if let Some(frag) = mbx_mut.eoe_fragment.clone() {
                    let addr = mbx_mut.address;
                    let completed = Self::reassemble_eoe_fragment(
                        &mut self.direct_in_flight_eoe,
                        (addr, frag.port),
                        &frag,
                    );
                    if let Some((reassembled, frag_cnt)) = completed {
                        Self::apply_reassembled_eoe(
                            &reassembled,
                            frag_cnt,
                            &mut frame.wireshark_fields,
                            &mut mbx_mut.protocol,
                            None,
                        );
                    }
                }
            }
        }

        // Process direct AMS SDO event(s) (ecatf.type == 2 / AMS/TCP / AMS/UDP, single or coalesced)
        if !frame.direct_ams_sdo_events.is_empty() {
            let events = frame.direct_ams_sdo_events.clone();
            for (pdu_i, target_port, ev) in events {
                let slot = match &ev {
                    SdoEventKind::AoeReadRes {
                        sender_net_id,
                        sender_port,
                        invoke_id,
                        ..
                    } => {
                        if let Some(&(req_slot, _, _, _)) = self.pending_aoe_sdo_reads.get(&(
                            sender_net_id.clone(),
                            *sender_port,
                            *invoke_id,
                        )) {
                            req_slot
                        } else {
                            continue;
                        }
                    }
                    SdoEventKind::AoeWriteRes {
                        sender_net_id,
                        sender_port,
                        invoke_id,
                        ..
                    } => {
                        if let Some(&(req_slot, _, _)) = self.pending_aoe_sdo_writes.get(&(
                            sender_net_id.clone(),
                            *sender_port,
                            *invoke_id,
                        )) {
                            req_slot
                        } else {
                            continue;
                        }
                    }
                    _ => self.get_or_create_station_slot(target_port.max(1)),
                };
                let pfx = if pdu_i == 0 {
                    "ams".to_string()
                } else {
                    format!("ams[{pdu_i}]")
                };
                let mut pdu_proto = if pdu_i == 0 {
                    frame.direct_ams.clone().unwrap_or(json!(null))
                } else {
                    frame
                        .direct_ams
                        .as_ref()
                        .and_then(|v| v.get("pdus"))
                        .and_then(Value::as_array)
                        .and_then(|arr| arr.get(pdu_i))
                        .cloned()
                        .unwrap_or(json!(null))
                };
                let xml_dec = self.process_sdo_event_for_slot(
                    slot,
                    &ev,
                    &mut frame.wireshark_fields,
                    &pfx,
                    Some(&mut pdu_proto),
                    None,
                );
                if pdu_i == 0 {
                    // Also mirror `ams[0]` PDU entry when multiple PDUs are present
                    if let Some(ref xd) = xml_dec {
                        if let Some(arr) = frame
                            .direct_ams
                            .as_mut()
                            .and_then(Value::as_object_mut)
                            .and_then(|o| o.get_mut("pdus"))
                            .and_then(Value::as_array_mut)
                        {
                            if let Some(first_pdu) = arr.get_mut(0).and_then(Value::as_object_mut) {
                                first_pdu.insert(
                                    "sdo_xml".into(),
                                    serde_json::to_value(xd).unwrap_or(json!(null)),
                                );
                            }
                        }
                    }
                    if let Some(root_obj) = pdu_proto.as_object() {
                        if let Some(dest_obj) =
                            frame.direct_ams.as_mut().and_then(Value::as_object_mut)
                        {
                            for k in ["sdo_xml", "crc_ok", "computed_crc"] {
                                if let Some(val) = root_obj.get(k) {
                                    dest_obj.insert(k.to_string(), val.clone());
                                }
                            }
                        }
                    }
                } else if let Some(arr) = frame
                    .direct_ams
                    .as_mut()
                    .and_then(Value::as_object_mut)
                    .and_then(|o| o.get_mut("pdus"))
                    .and_then(Value::as_array_mut)
                {
                    if let Some(slot_pdu) = arr.get_mut(pdu_i) {
                        *slot_pdu = pdu_proto;
                    }
                }
            }
        } else if let Some(ev) = frame.direct_ams_sdo_event.clone() {
            let slot_opt = match &ev {
                SdoEventKind::AoeReadRes {
                    sender_net_id,
                    sender_port,
                    invoke_id,
                    ..
                } => self
                    .pending_aoe_sdo_reads
                    .get(&(sender_net_id.clone(), *sender_port, *invoke_id))
                    .map(|&(req_slot, _, _, _)| req_slot),
                SdoEventKind::AoeWriteRes {
                    sender_net_id,
                    sender_port,
                    invoke_id,
                    ..
                } => self
                    .pending_aoe_sdo_writes
                    .get(&(sender_net_id.clone(), *sender_port, *invoke_id))
                    .map(|&(req_slot, _, _)| req_slot),
                _ => {
                    let target_port = frame
                        .wireshark_fields
                        .get("ams.targetport")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0x1001) as u16;
                    Some(self.get_or_create_station_slot(target_port.max(1)))
                }
            };
            if let Some(slot) = slot_opt {
                self.process_sdo_event_for_slot(
                    slot,
                    &ev,
                    &mut frame.wireshark_fields,
                    "ams",
                    frame.direct_ams.as_mut(),
                    None,
                );
            }
        }

        // Process each DLPDU datagram in subframe order
        for sub_i in 0..frame.datagrams.len() {
            self.process_datagram(sub_i, &mut frame);
        }

        Ok(frame)
    }

    /// Returns whether `slave_station_or_pos` currently has an active post-configuration PDO bank.
    pub fn is_pdo_configured(&self, direction: PdoDirection) -> bool {
        self.slaves.iter().any(|s| match direction {
            PdoDirection::RxPdo => s.rx_active.is_some(),
            PdoDirection::TxPdo => s.tx_active.is_some(),
        })
    }

    fn get_or_create_topo_slot(&mut self, topo_pos: u16) -> usize {
        if let Some(&slot) = self.topo_to_slot.get(&topo_pos) {
            return slot;
        }
        let slot = self.slaves.len();
        self.slaves.push(SlaveRuntime {
            slot_id: slot,
            topo_pos: Some(topo_pos),
            ..Default::default()
        });
        self.topo_to_slot.insert(topo_pos, slot);
        slot
    }

    fn get_or_create_station_slot(&mut self, stadr: u16) -> usize {
        if let Some(&slot) = self.station_to_slot.get(&stadr) {
            return slot;
        }
        if let Some(&slot) = self.alias_to_slot.get(&stadr) {
            return slot;
        }
        let slot = self.slaves.len();
        self.slaves.push(SlaveRuntime {
            slot_id: slot,
            station_addr: Some(stadr),
            ..Default::default()
        });
        self.station_to_slot.insert(stadr, slot);
        slot
    }

    fn bind_station_addr(&mut self, slot: usize, stadr: u16) {
        if stadr == 0 {
            return;
        }
        // If another temporary station-only slot existed for `stadr`, keep pointing `stadr` to `slot`
        self.slaves[slot].station_addr = Some(stadr);
        self.station_to_slot.insert(stadr, slot);
    }

    fn resolve_datagram_slave(&mut self, dg: &DissectedDatagram) -> Option<usize> {
        let cmd = EcatCmd::from_code(dg.cmd)?;
        let adp = dg.adp?;
        let ado = dg.ado.unwrap_or(0);
        match cmd {
            EcatCmd::Fprd | EcatCmd::Fpwr | EcatCmd::Fprw | EcatCmd::Frmw => {
                Some(self.get_or_create_station_slot(adp))
            }
            EcatCmd::Aprd | EcatCmd::Apwr | EcatCmd::Aprw | EcatCmd::Armw => {
                if dg.wkc == 0 && !dg.circulating {
                    let topo = (0i16).wrapping_sub(adp as i16) as u16;
                    let slot = self.get_or_create_topo_slot(topo);
                    if self.recent_tx_autoinc.len() >= 64 {
                        self.recent_tx_autoinc.pop_front();
                    }
                    self.recent_tx_autoinc.push_back((
                        self.current_pkt_idx,
                        dg.cmd,
                        dg.idx,
                        ado,
                        slot,
                    ));
                    Some(slot)
                } else {
                    // Match FIFO within the most recent TX packet batch carrying `(cmd, idx, ado)`
                    if let Some(&(latest_pkt, _, _, _, _)) = self
                        .recent_tx_autoinc
                        .iter()
                        .rev()
                        .find(|&&(_, c, idx, a, _)| c == dg.cmd && idx == dg.idx && a == ado)
                    {
                        if let Some(pos) =
                            self.recent_tx_autoinc
                                .iter()
                                .position(|&(p, c, idx, a, _)| {
                                    p == latest_pkt && c == dg.cmd && idx == dg.idx && a == ado
                                })
                        {
                            let (_, _, _, _, slot) = self.recent_tx_autoinc.remove(pos).unwrap();
                            return Some(slot);
                        }
                    }
                    // Otherwise if `adp <= 0` or `adp == 0` (synthetic frame where ADP wasn't ring-incremented)
                    if adp == 0 || (adp as i16) < 0 {
                        let topo = (0i16).wrapping_sub(adp as i16) as u16;
                        return Some(self.get_or_create_topo_slot(topo));
                    }
                    // Or if we know `ring_slave_count` N, returning ADP = N - topo => topo = N - adp
                    if let Some(n) = self.ring_slave_count {
                        if adp <= n {
                            let topo = n - adp;
                            return Some(self.get_or_create_topo_slot(topo));
                        }
                    }
                    Some(self.get_or_create_topo_slot(0))
                }
            }
            EcatCmd::Brd | EcatCmd::Bwr | EcatCmd::Brw => {
                if dg.wkc > 0 && matches!(cmd, EcatCmd::Brd | EcatCmd::Bwr) {
                    self.ring_slave_count = Some(dg.wkc);
                }
                None
            }
            _ => None,
        }
    }

    fn is_duplicate_write_echo(&mut self, slot_opt: Option<usize>, dg: &DissectedDatagram) -> bool {
        let Some(cmd) = EcatCmd::from_code(dg.cmd) else {
            return false;
        };
        if !matches!(
            cmd,
            EcatCmd::Apwr
                | EcatCmd::Fpwr
                | EcatCmd::Bwr
                | EcatCmd::Aprw
                | EcatCmd::Fprw
                | EcatCmd::Brw
        ) {
            return false;
        }
        let key = TxWriteEchoKey {
            slot: slot_opt,
            cmd: dg.cmd,
            idx: dg.idx,
            ado: dg.ado.unwrap_or(0),
            data: dg.raw_data.clone(),
        };
        if dg.wkc == 0 {
            if dg.circulating {
                if let Some(pos) = self.recent_tx_writes.iter().position(|(_, k)| *k == key) {
                    self.recent_tx_writes.remove(pos);
                }
                return true;
            }
            if let Some(pos) = self
                .recent_tx_writes
                .iter()
                .position(|(pkt, k)| *pkt + 1 == self.current_pkt_idx && *k == key)
            {
                self.recent_tx_writes.remove(pos);
                return true;
            }
            if self.recent_tx_writes.len() >= 256 {
                self.recent_tx_writes.pop_front();
            }
            self.recent_tx_writes.push_back((self.current_pkt_idx, key));
            false
        } else if let Some(pos) = self.recent_tx_writes.iter().position(|(_, k)| *k == key) {
            self.recent_tx_writes.remove(pos);
            true
        } else {
            false
        }
    }

    fn mirror_mailbox_prefix_fields(
        ws: &mut BTreeMap<String, Value>,
        mbx_prefix: &str,
        sub_i: Option<usize>,
        leaf_prefix: &str,
    ) {
        let pfx_dot = format!("{mbx_prefix}.{leaf_prefix}");
        let collected: Vec<(String, Value)> = ws
            .iter()
            .filter_map(|(k, v)| {
                k.strip_prefix(&pfx_dot)
                    .map(|rest| (rest.to_string(), v.clone()))
            })
            .collect();
        for (rest, val) in collected {
            if let Some(si) = sub_i {
                ws.insert(
                    format!("ecat[{si}].mailbox.{leaf_prefix}{rest}"),
                    val.clone(),
                );
                if mbx_prefix == "ecat_mailbox" && si == 0 {
                    ws.insert(format!("ecat_mailbox[0].{leaf_prefix}{rest}"), val.clone());
                }
            }
            ws.entry(format!("ecat_mailbox.{leaf_prefix}{rest}"))
                .or_insert(val);
        }
    }

    fn process_sdo_info_fragment(
        state: &mut Option<(u8, u16, Vec<u8>, usize)>,
        info: &SdoInfoFragmentInfo,
        ws: &mut BTreeMap<String, Value>,
        mbx_prefix: &str,
        sub_i: Option<usize>,
        proto_json: &mut Value,
    ) {
        const STATELESS_INFO_LEAVES: &[&str] = &[
            "sdoinfolisttype",
            "sdoinfolist",
            "sdoinfoindex",
            "sdoinfodtype",
            "sdoinfomaxsub",
            "sdoinfoobjcode",
            "sdoinfoobjname",
            "sdoinfosub",
            "sdoinfovalueinfo",
            "sdoinfobitlen",
            "sdoinfoaccess",
            "sdoinfounittype",
            "sdoinfodefault",
            "sdoinfomin",
            "sdoinfomax",
            "sdoinfoentryname",
        ];

        // ETG.1000.6: continuation fragments repeat the OpCode of the first fragment. Anything else
        // (a new request, a different response, an SDO Info error) terminates the stale reassembly.
        if state
            .as_ref()
            .is_some_and(|(orig_op, _, _, _)| (orig_op & 0x7F) != (info.opcode & 0x7F))
        {
            *state = None;
        }

        if let Some((orig_op, orig_num, mut buf, cnt)) = state.take() {
            // Strip bogus stateless header fields parsed from continuation bytes
            for leaf in STATELESS_INFO_LEAVES {
                ws.remove(&format!("{mbx_prefix}.coe.{leaf}"));
                if let Some(si) = sub_i {
                    ws.remove(&format!("ecat[{si}].mailbox.coe.{leaf}"));
                    if mbx_prefix == "ecat_mailbox" && si == 0 {
                        ws.remove(&format!("ecat_mailbox[0].coe.{leaf}"));
                    }
                }
                if mbx_prefix == "ecat_mailbox" || mbx_prefix == "ecat_mailbox[0]" {
                    ws.remove(&format!("ecat_mailbox.coe.{leaf}"));
                }
            }

            buf.extend_from_slice(&info.rest);
            let total_frags = cnt + 1;
            if info.incomplete || info.fragments_left > 0 {
                *state = Some((orig_op, orig_num, buf, total_frags));
                if let Some(obj) = proto_json.as_object_mut() {
                    obj.insert("sdo_info_continuation".into(), json!(true));
                }
            } else {
                let mut full_payload = Vec::with_capacity(4 + buf.len());
                full_payload.extend_from_slice(&[orig_op & 0x7F, 0, 0, 0]);
                full_payload.extend_from_slice(&buf);
                let detail = dissect_coe_sdo_info(orig_num, &full_payload, ws, mbx_prefix);
                ws.insert(
                    format!("{mbx_prefix}.coe.sdoinfo.reassembled_length"),
                    json!(buf.len()),
                );
                ws.insert(
                    format!("{mbx_prefix}.coe.sdoinfo.reassembled_fragments"),
                    json!(total_frags),
                );
                Self::mirror_mailbox_prefix_fields(ws, mbx_prefix, sub_i, "coe.");
                if let Some(obj) = proto_json.as_object_mut() {
                    *obj = detail.as_object().cloned().unwrap_or_default();
                    obj.insert("reassembled_length".into(), json!(buf.len()));
                    obj.insert("reassembled_fragments".into(), json!(total_frags));
                }
            }
        } else if info.incomplete || info.fragments_left > 0 {
            *state = Some((info.opcode, info.number, info.rest.clone(), 1));
        }
    }

    fn is_unanswered_tx_read(dg: &DissectedDatagram) -> bool {
        let Some(cmd) = EcatCmd::from_code(dg.cmd) else {
            return false;
        };
        matches!(cmd, EcatCmd::Aprd | EcatCmd::Fprd | EcatCmd::Brd) && dg.wkc == 0
    }

    fn profile_for_slot<'a>(
        &'a self,
        catalog: &'a XmlCatalog,
        slot: usize,
    ) -> Option<&'a XmlDeviceProfile> {
        let st = &self.slaves[slot];
        if let Some(ref ov) = st.mdp_profile_override {
            return Some(ov);
        }
        catalog.match_slave_ext(
            st.station_addr,
            st.topo_pos,
            st.vendor_id,
            st.product_code,
            st.revision_no,
            self.options.xml_device.as_deref(),
        )
    }

    fn process_datagram(&mut self, sub_i: usize, frame: &mut DissectedFrame) {
        let slot_opt = self.resolve_datagram_slave(&frame.datagrams[sub_i]);
        if let Some(slot) = slot_opt {
            frame.datagrams[sub_i].resolved_slave = self.slaves[slot]
                .station_addr
                .or(self.slaves[slot].topo_pos);
        }

        let is_dup_write = self.is_duplicate_write_echo(slot_opt, &frame.datagrams[sub_i]);
        let is_empty_tx_read = Self::is_unanswered_tx_read(&frame.datagrams[sub_i]);

        // 0. Stateful Wireshark 4.6 `ecat.dc.dif.curtime` across ARMW/FRMW 0x0910 frames
        if let (Some(cmd), Some(0x0910)) = (
            EcatCmd::from_code(frame.datagrams[sub_i].cmd),
            frame.datagrams[sub_i].ado,
        ) {
            if matches!(cmd, EcatCmd::Armw | EcatCmd::Frmw)
                && frame.datagrams[sub_i].raw_data.len() >= 4
            {
                let raw = &frame.datagrams[sub_i].raw_data;
                let cur_time = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
                if cur_time != 0 {
                    if let Some(prev) = self.prev_dc_cur_time {
                        let diff = cur_time.wrapping_sub(prev);
                        frame
                            .wireshark_fields
                            .entry("ecat.dc.dif.curtime".to_string())
                            .or_insert_with(|| json!(diff));
                        frame
                            .wireshark_fields
                            .insert(format!("ecat[{sub_i}].dc.dif.curtime"), json!(diff));
                        let s1 = sub_i + 1;
                        if s1 <= 10 {
                            frame
                                .wireshark_fields
                                .insert(format!("ecat.sub{s1}.dc.dif.curtime"), json!(diff));
                        }
                    }
                    self.prev_dc_cur_time = Some(cur_time);
                }
            }
        }

        // 1. Update ESC register shadows (0x0010 station addr, 0x0120/0x0130 AL state, 0x0502+ SII, 0x0800+ SM, 0x0600+ FMMU)
        if !is_dup_write && !is_empty_tx_read {
            if let Some(ado) = frame.datagrams[sub_i].ado {
                let raw_data = frame.datagrams[sub_i].raw_data.clone();
                let cmd_u8 = frame.datagrams[sub_i].cmd;
                if let Some(slot) = slot_opt {
                    self.update_esc_shadows(slot, cmd_u8, ado, &raw_data);
                } else if (EcatCmd::from_code(cmd_u8) == Some(EcatCmd::Bwr) && ado != 0x0010)
                    || (EcatCmd::from_code(cmd_u8) == Some(EcatCmd::Brd)
                        && frame.datagrams[sub_i].wkc > 0
                        && ado <= 0x0131
                        && ado.saturating_add(raw_data.len() as u16) > 0x0130)
                {
                    for slot in 0..self.slaves.len() {
                        self.update_esc_shadows(slot, cmd_u8, ado, &raw_data);
                    }
                }
            }
        }

        // 2. Re-dissect FoE `.efw` or active CoE SDO Block sub-block (`seq_no = 1..=127`)
        let mbx_prefix = if frame.datagrams.len() == 1 {
            "ecat_mailbox".to_string()
        } else {
            format!("ecat_mailbox[{sub_i}]")
        };

        if let Some(slot) = slot_opt {
            if let Some(mbx) = &frame.datagrams[sub_i].mailbox {
                if let Some(wrq_fn) = &mbx.foe_wrq_filename {
                    self.slaves[slot].foe_efw_active =
                        wrq_fn.to_ascii_lowercase().ends_with(".efw");
                } else if self.slaves[slot].foe_efw_active && mbx.mbx_type == 0x04 {
                    // Re-run mailbox dissector with `force_efw = true`
                    if let Some(re_mbx) = dissect_mailbox_ext(
                        &frame.datagrams[sub_i].raw_data,
                        &mut frame.wireshark_fields,
                        &mbx_prefix,
                        true,
                    ) {
                        Self::mirror_mailbox_prefix_fields(
                            &mut frame.wireshark_fields,
                            &mbx_prefix,
                            Some(sub_i),
                            "foe.",
                        );
                        frame.datagrams[sub_i].mailbox = Some(re_mbx);
                    }
                }
            }
        }

        if frame.datagrams[sub_i].mailbox.is_some() {
            let slot = slot_opt.unwrap_or_else(|| self.get_or_create_topo_slot(0));
            let raw_mbx = frame.datagrams[sub_i].raw_data.clone();
            if let Some(svc) = coe_mailbox_service_code(&raw_mbx) {
                let want_subblock = match svc {
                    0x02 => {
                        self.slaves[slot]
                            .in_flight_block_dl
                            .as_ref()
                            .is_some_and(|b| b.streaming_subblocks)
                            || (is_dup_write
                                && self.slaves[slot].last_dl_subblock_raw.as_deref()
                                    == Some(raw_mbx.as_slice()))
                    }
                    0x03 => {
                        !is_empty_tx_read
                            && self.slaves[slot]
                                .in_flight_block_ul
                                .as_ref()
                                .is_some_and(|b| b.streaming_subblocks)
                    }
                    _ => false,
                };
                if want_subblock {
                    if let Some(re_mbx) = dissect_mailbox_sdo_subblock(
                        &raw_mbx,
                        &mut frame.wireshark_fields,
                        &mbx_prefix,
                        Some(sub_i),
                    ) {
                        if svc == 0x02 && !is_dup_write {
                            self.slaves[slot].last_dl_subblock_raw = Some(raw_mbx);
                        }
                        frame.datagrams[sub_i].mailbox = Some(re_mbx);
                    }
                }
            }
        }

        // 2b. Stateful CoE SDO Information (`0x02`/`0x04`/`0x06`) continuation fragment reassembly
        if !is_dup_write && !is_empty_tx_read {
            if let Some(mbx_mut) = frame.datagrams[sub_i].mailbox.as_mut() {
                if let Some(sinfo) = mbx_mut.sdo_info_fragment.clone() {
                    let slot = slot_opt.unwrap_or_else(|| self.get_or_create_topo_slot(0));
                    Self::process_sdo_info_fragment(
                        &mut self.slaves[slot].in_flight_sdo_info,
                        &sinfo,
                        &mut frame.wireshark_fields,
                        &mbx_prefix,
                        Some(sub_i),
                        &mut mbx_mut.protocol,
                    );
                } else if mbx_mut.mbx_type == 0x03
                    && mbx_mut.protocol.get("service_code").and_then(Value::as_u64) == Some(8)
                {
                    let slot = slot_opt.unwrap_or_else(|| self.get_or_create_topo_slot(0));
                    self.slaves[slot].in_flight_sdo_info = None;
                }
            }
        }

        // 3. Process CoE / AoE SDO events (XML SDO enrichment + Segmented/Block Reassembly + Temporal PDO Config)
        if let Some(mbx) = frame.datagrams[sub_i].mailbox.as_ref() {
            if let Some(ev) = mbx.sdo_event.clone() {
                let slot = slot_opt.unwrap_or_else(|| self.get_or_create_topo_slot(0));
                if is_dup_write {
                    // Replay cached multi-segment/block download enrichment if matching, or single-frame metadata!
                    let raw_mbx = frame.datagrams[sub_i].raw_data.clone();
                    let cached_match = self.slaves[slot]
                        .last_dl_echo_enrichment
                        .as_ref()
                        .filter(|(r, _, _, _)| r.as_slice() == raw_mbx.as_slice())
                        .cloned();
                    if let Some((_, cached_xd, cached_crc, cached_reasm)) = cached_match {
                        if let Some((crc_ok, calc_crc)) = cached_crc {
                            let mut pv = frame.datagrams[sub_i]
                                .mailbox
                                .as_ref()
                                .map(|m| m.protocol.clone())
                                .unwrap_or(json!(null));
                            Self::emit_block_crc_ws(
                                crc_ok,
                                calc_crc,
                                &mut frame.wireshark_fields,
                                &mbx_prefix,
                                Some(&mut pv),
                            );
                            if let Some(m) = frame.datagrams[sub_i].mailbox.as_mut() {
                                m.protocol = pv;
                            }
                        }
                        if let Some(ref rbytes) = cached_reasm {
                            Self::emit_reassembled_sdo_ws(
                                rbytes,
                                &mut frame.wireshark_fields,
                                &mbx_prefix,
                            );
                        }
                        if let Some(xd) = cached_xd {
                            emit_sdo_xml_ws(&xd, &mut frame.wireshark_fields, &mbx_prefix);
                            if let Some(m) = frame.datagrams[sub_i].mailbox.as_mut() {
                                if let Some(obj) = m.protocol.as_object_mut() {
                                    obj.insert(
                                        "sdo_xml".into(),
                                        serde_json::to_value(&xd).unwrap_or(json!(null)),
                                    );
                                }
                            }
                            frame.datagrams[sub_i].sdo_xml = Some(xd);
                        }
                    } else if let Some(cat) = self.options.xml_catalog.clone() {
                        let pref = self.profile_for_slot(&cat, slot);
                        let xml_dec = crate::engine::sdo::enrich_single_frame_sdo(
                            &ev,
                            &cat,
                            pref,
                            &mut frame.wireshark_fields,
                            &mbx_prefix,
                        );
                        if let Some(xd) = xml_dec {
                            if let Some(m) = frame.datagrams[sub_i].mailbox.as_mut() {
                                if let Some(obj) = m.protocol.as_object_mut() {
                                    obj.insert(
                                        "sdo_xml".into(),
                                        serde_json::to_value(&xd).unwrap_or(json!(null)),
                                    );
                                }
                            }
                            frame.datagrams[sub_i].sdo_xml = Some(xd);
                        }
                    }
                } else if !is_empty_tx_read {
                    let raw_mbx = frame.datagrams[sub_i].raw_data.clone();
                    let mut proto_val = frame.datagrams[sub_i]
                        .mailbox
                        .as_ref()
                        .map(|m| m.protocol.clone())
                        .unwrap_or(json!(null));
                    let xml_dec = self.process_sdo_event_for_slot(
                        slot,
                        &ev,
                        &mut frame.wireshark_fields,
                        &mbx_prefix,
                        Some(&mut proto_val),
                        Some(&raw_mbx),
                    );
                    if let Some(m) = frame.datagrams[sub_i].mailbox.as_mut() {
                        m.protocol = proto_val;
                    }
                    if xml_dec.is_some() {
                        frame.datagrams[sub_i].sdo_xml = xml_dec;
                    }
                }
            }
        }

        // 3b. Process EoE multi-fragment reassembly & inner L2/L3/L4 dissection
        if !is_dup_write && !is_empty_tx_read {
            if let Some(frag) = frame.datagrams[sub_i]
                .mailbox
                .as_ref()
                .and_then(|m| m.eoe_fragment.clone())
            {
                let slot = slot_opt.unwrap_or_else(|| self.get_or_create_topo_slot(0));
                let is_slave_to_master = matches!(
                    EcatCmd::from_code(frame.datagrams[sub_i].cmd),
                    Some(EcatCmd::Aprd | EcatCmd::Fprd | EcatCmd::Brd)
                );
                let completed = Self::reassemble_eoe_fragment(
                    &mut self.slaves[slot].in_flight_eoe,
                    (is_slave_to_master, frag.port),
                    &frag,
                );
                if let Some((reassembled, frag_cnt)) = completed {
                    if let Some(mbx_mut) = frame.datagrams[sub_i].mailbox.as_mut() {
                        Self::apply_reassembled_eoe(
                            &reassembled,
                            frag_cnt,
                            &mut frame.wireshark_fields,
                            &mut mbx_mut.protocol,
                            Some(sub_i),
                        );
                    }
                }
            }
        }

        // 4. Decode cyclic PDO payload ONLY if static `pdo_layout` override was NOT already applied
        //    AND PDO configuration has been observed in the packet sequence!
        if self.options.pdo_layout.is_none() && self.options.xml_catalog.is_some() {
            self.try_decode_configured_pdo(sub_i, slot_opt, frame);
        }
    }

    fn append_ams_stream_bytes(stream: &mut AmsTcpStreamState, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let had_prior = !stream.buffer.is_empty();
        stream.buffer.extend_from_slice(bytes);
        stream.segments_in_current_pdu = if had_prior {
            stream.segments_in_current_pdu + 1
        } else {
            1
        };
        stream.recent_bytes.extend_from_slice(bytes);
        if stream.recent_bytes.len() > 8192 {
            let drop_n = stream.recent_bytes.len() - 8192;
            stream.recent_bytes.drain(..drop_n);
        }
    }

    fn drain_ams_ooo_segments(stream: &mut AmsTcpStreamState) {
        while let Some(cur_exp) = stream.next_seq {
            if let Some(ooo) = stream.ooo_segments.remove(&cur_exp) {
                let next = cur_exp.wrapping_add(ooo.len() as u32);
                Self::append_ams_stream_bytes(stream, &ooo);
                stream.next_seq = Some(next);
            } else {
                break;
            }
        }
    }

    fn looks_complete_ams_tcp_frames(buf: &[u8]) -> bool {
        if buf.len() < 38 {
            return false;
        }
        let mut off = 0usize;
        while off < buf.len() {
            if buf.len() - off < 38 {
                return false;
            }
            if u16::from_le_bytes([buf[off], buf[off + 1]]) != 0 {
                return false;
            }
            let len = u32::from_le_bytes([buf[off + 2], buf[off + 3], buf[off + 4], buf[off + 5]])
                as usize;
            if !(32..=MAX_AMS_TCP_REASSEMBLY_LEN).contains(&len) || off + 6 + len > buf.len() {
                return false;
            }
            off += 6 + len;
        }
        true
    }

    fn looks_valid_ams_tcp_start(buf: &[u8]) -> bool {
        if buf.len() < 6 {
            return false;
        }
        if u16::from_le_bytes([buf[0], buf[1]]) != 0 {
            return false;
        }
        let len = u32::from_le_bytes([buf[2], buf[3], buf[4], buf[5]]) as usize;
        (32..=MAX_AMS_TCP_REASSEMBLY_LEN).contains(&len)
    }

    fn mark_ams_retransmission(
        frame: &mut DissectedFrame,
        clear_stateless_ams: bool,
        seg_len: usize,
    ) {
        frame.direct_ams_sdo_event = None;
        frame.direct_ams_sdo_events.clear();
        if clear_stateless_ams {
            frame
                .wireshark_fields
                .retain(|k, _| !k.starts_with("ams.") && !k.starts_with("ams["));
            frame.direct_ams = Some(json!({
                "protocol": "AMS/TCP",
                "tcp_retransmission": true,
                "segment_len": seg_len,
            }));
        } else if let Some(obj) = frame.direct_ams.as_mut().and_then(Value::as_object_mut) {
            obj.insert("tcp_retransmission".into(), json!(true));
        }
        frame
            .wireshark_fields
            .insert("ams.tcp_retransmission".into(), json!(true));
    }

    fn mark_ams_reassembly_pending(
        frame: &mut DissectedFrame,
        clear_stateless_ams: bool,
        seg_len: usize,
    ) {
        frame.direct_ams_sdo_event = None;
        frame.direct_ams_sdo_events.clear();
        if clear_stateless_ams {
            frame
                .wireshark_fields
                .retain(|k, _| !k.starts_with("ams.") && !k.starts_with("ams["));
            frame.direct_ams = Some(json!({
                "protocol": "AMS/TCP",
                "truncated": true,
                "reassembly_pending": true,
                "segment_len": seg_len,
            }));
        } else if let Some(obj) = frame.direct_ams.as_mut().and_then(Value::as_object_mut) {
            obj.insert("reassembly_pending".into(), json!(true));
        }
        frame
            .wireshark_fields
            .insert("ams.reassembly_pending".into(), json!(true));
    }

    fn process_ams_tcp_segment(&mut self, raw_seg: &[u8], frame: &mut DissectedFrame) {
        let stream_key = if let Some(ref eth) = frame.ethernet {
            (
                eth.src_ip.clone().unwrap_or_default(),
                eth.src_port.unwrap_or(0),
                eth.dst_ip.clone().unwrap_or_default(),
                eth.dst_port.unwrap_or(0),
            )
        } else {
            (String::new(), 0, String::new(), 0)
        };
        let tcp_seq = frame.ethernet.as_ref().and_then(|e| e.tcp_seq);
        let tcp_flags = frame
            .ethernet
            .as_ref()
            .and_then(|e| e.tcp_flags)
            .unwrap_or(0);

        let stream = self.ams_tcp_streams.entry(stream_key).or_default();
        // Reset stream state on TCP SYN (0x02) or RST (0x04)
        if (tcp_flags & 0x06) != 0 {
            *stream = AmsTcpStreamState::default();
        }
        if raw_seg.is_empty() {
            return;
        }

        let valid_start = Self::looks_valid_ams_tcp_start(raw_seg);
        let sig = (tcp_seq, raw_seg.to_vec());
        if stream.last_seg_sig.as_ref() == Some(&sig) {
            Self::mark_ams_retransmission(frame, !valid_start, raw_seg.len());
            return;
        }
        stream.last_seg_sig = Some(sig);

        let was_empty_before_seg = stream.buffer.is_empty();

        match (tcp_seq, stream.next_seq) {
            (Some(seq), Some(exp_seq)) => {
                let back = exp_seq.wrapping_sub(seq);
                if seq == exp_seq {
                    Self::append_ams_stream_bytes(stream, raw_seg);
                    stream.next_seq = Some(exp_seq.wrapping_add(raw_seg.len() as u32));
                    Self::drain_ams_ooo_segments(stream);
                } else if back > 0 && (back as usize) <= stream.recent_bytes.len() {
                    let b = back as usize;
                    let tail_start = stream.recent_bytes.len() - b;
                    let overlap = raw_seg.len().min(b);
                    if stream.recent_bytes[tail_start..tail_start + overlap] == raw_seg[..overlap] {
                        if raw_seg.len() <= b {
                            Self::mark_ams_retransmission(frame, !valid_start, raw_seg.len());
                            return;
                        }
                        let new_tail = &raw_seg[b..];
                        Self::append_ams_stream_bytes(stream, new_tail);
                        stream.next_seq = Some(exp_seq.wrapping_add(new_tail.len() as u32));
                        Self::drain_ams_ooo_segments(stream);
                    } else {
                        // Distinct payload (e.g. synthetic test frames using constant seq = 1)
                        Self::append_ams_stream_bytes(stream, raw_seg);
                        stream.next_seq = Some(seq.wrapping_add(raw_seg.len() as u32));
                    }
                } else if (!stream.buffer.is_empty()
                    || !Self::looks_complete_ams_tcp_frames(raw_seg))
                    && seq.wrapping_sub(exp_seq) > 0
                    && seq.wrapping_sub(exp_seq) <= 65_536
                {
                    if stream.ooo_segments.len() < 16 {
                        stream.ooo_segments.insert(seq, raw_seg.to_vec());
                    }
                    Self::mark_ams_reassembly_pending(frame, true, raw_seg.len());
                    return;
                } else {
                    stream.buffer.clear();
                    stream.ooo_segments.clear();
                    stream.recent_bytes.clear();
                    stream.segments_in_current_pdu = 0;
                    Self::append_ams_stream_bytes(stream, raw_seg);
                    stream.next_seq = Some(seq.wrapping_add(raw_seg.len() as u32));
                }
            }
            (Some(seq), None) => {
                Self::append_ams_stream_bytes(stream, raw_seg);
                stream.next_seq = Some(seq.wrapping_add(raw_seg.len() as u32));
            }
            (None, _) => {
                Self::append_ams_stream_bytes(stream, raw_seg);
            }
        }

        let mut complete_end = 0usize;
        let mut bogus_header = false;
        while stream.buffer.len().saturating_sub(complete_end) >= 6 {
            let b = &stream.buffer[complete_end..];
            let tcp_reserved = u16::from_le_bytes([b[0], b[1]]);
            let tcp_len = u32::from_le_bytes([b[2], b[3], b[4], b[5]]) as usize;
            if tcp_reserved != 0 || !(32..=MAX_AMS_TCP_REASSEMBLY_LEN).contains(&tcp_len) {
                bogus_header = true;
                break;
            }
            if complete_end + 6 + tcp_len <= stream.buffer.len() {
                complete_end += 6 + tcp_len;
            } else {
                break;
            }
        }

        if bogus_header {
            let flushed = std::mem::take(&mut stream.buffer);
            let seg_cnt = stream.segments_in_current_pdu;
            stream.segments_in_current_pdu = 0;
            if seg_cnt > 1 || flushed.as_slice() != raw_seg {
                frame
                    .wireshark_fields
                    .retain(|k, _| !k.starts_with("ams.") && !k.starts_with("ams["));
                let (ams_val, sdo_evs) =
                    dissect_ams_tcp_multi(&flushed, &mut frame.wireshark_fields);
                frame.direct_ams_sdo_event = sdo_evs.first().map(|(_, _, e)| e.clone());
                frame.direct_ams_sdo_events = sdo_evs;
                frame.direct_ams = Some(ams_val);
            }
            return;
        }

        if complete_end == 0 {
            let clear_stateless = !was_empty_before_seg || !valid_start;
            Self::mark_ams_reassembly_pending(frame, clear_stateless, raw_seg.len());
            return;
        }

        let was_split = stream.segments_in_current_pdu > 1;
        let complete_bytes: Vec<u8> = stream.buffer.drain(..complete_end).collect();
        let trailing_buffered = stream.buffer.len();
        stream.segments_in_current_pdu = usize::from(trailing_buffered > 0);

        if was_split || trailing_buffered > 0 || complete_bytes.as_slice() != raw_seg {
            frame
                .wireshark_fields
                .retain(|k, _| !k.starts_with("ams.") && !k.starts_with("ams["));
            let (mut ams_val, sdo_evs) =
                dissect_ams_tcp_multi(&complete_bytes, &mut frame.wireshark_fields);
            if was_split {
                frame
                    .wireshark_fields
                    .insert("ams.reassembled".into(), json!(true));
                frame
                    .wireshark_fields
                    .insert("ams.reassembled_length".into(), json!(complete_bytes.len()));
                if let Some(obj) = ams_val.as_object_mut() {
                    obj.insert("reassembled".into(), json!(true));
                    obj.insert("reassembled_length".into(), json!(complete_bytes.len()));
                }
            }
            if trailing_buffered > 0 {
                if let Some(obj) = ams_val.as_object_mut() {
                    obj.insert("trailing_buffered_bytes".into(), json!(trailing_buffered));
                }
            }
            frame.direct_ams_sdo_event = sdo_evs.first().map(|(_, _, e)| e.clone());
            frame.direct_ams_sdo_events = sdo_evs;
            frame.direct_ams = Some(ams_val);
        }
    }

    fn reassemble_eoe_fragment<K: Ord + Copy>(
        map: &mut BTreeMap<K, InFlightEoe>,
        key: K,
        frag: &EoeFragmentInfo,
    ) -> Option<(Vec<u8>, usize)> {
        if frag.frag_no == 0 {
            if frag.last_fragment {
                // Single-fragment EoE frame: already dissected in `mailbox.rs`
                map.remove(&key);
                return None;
            }
            let cap = ((frag.offset_or_size as usize) * 32)
                .max(frag.data.len())
                .min(MAX_EOE_REASSEMBLY_LEN);
            let mut buf = Vec::with_capacity(cap);
            let copy_len = frag.data.len().min(MAX_EOE_REASSEMBLY_LEN);
            buf.extend_from_slice(&frag.data[..copy_len]);
            map.insert(
                key,
                InFlightEoe {
                    frame_no: frag.frame_no,
                    expected_frag_no: 1,
                    buffer: buf,
                    max_end: copy_len,
                    fragments: 1,
                    last_frag_sig: Some((0, false, frag.data.clone())),
                },
            );
            return None;
        }

        let inflight = map.get_mut(&key)?;
        if inflight.frame_no != frag.frame_no {
            map.remove(&key);
            return None;
        }

        let sig = (frag.frag_no, frag.last_fragment, frag.data.clone());
        if inflight.last_frag_sig.as_ref() != Some(&sig) {
            if frag.frag_no != inflight.expected_frag_no {
                // Missing intermediate EoE fragment -> discard rather than fabricating zero bytes
                map.remove(&key);
                return None;
            }
            let byte_offset = if frag.offset_or_size > 0 {
                (frag.offset_or_size as usize) * 32
            } else {
                inflight.max_end
            };
            if byte_offset > inflight.max_end {
                // Unfilled gap in EoE frame -> discard corrupted buffer
                map.remove(&key);
                return None;
            }
            inflight.last_frag_sig = Some(sig);
            inflight.expected_frag_no = (inflight.expected_frag_no + 1) & 0x3F;
            if byte_offset < MAX_EOE_REASSEMBLY_LEN && !frag.data.is_empty() {
                let copy_len = frag.data.len().min(MAX_EOE_REASSEMBLY_LEN - byte_offset);
                let end = byte_offset + copy_len;
                if inflight.buffer.len() < end {
                    inflight.buffer.resize(end, 0);
                }
                inflight.buffer[byte_offset..end].copy_from_slice(&frag.data[..copy_len]);
                inflight.max_end = inflight.max_end.max(end);
            }
            inflight.fragments += 1;
        }

        if frag.last_fragment {
            let mut done = map.remove(&key)?;
            done.buffer.truncate(done.max_end);
            return Some((done.buffer, done.fragments));
        }
        None
    }

    fn apply_reassembled_eoe(
        reassembled: &[u8],
        frag_cnt: usize,
        ws: &mut BTreeMap<String, Value>,
        proto_json: &mut Value,
        sub_idx: Option<usize>,
    ) {
        let hex_data = format_hex(reassembled);
        let mut eoe_ws = BTreeMap::new();
        eoe_ws.insert(
            "ecat_mailbox.eoe.reassembled_data".into(),
            json!(hex_data.clone()),
        );
        eoe_ws.insert(
            "ecat_mailbox.eoe.reassembled_length".into(),
            json!(reassembled.len()),
        );
        eoe_ws.insert(
            "ecat_mailbox.eoe.reassembled_fragments".into(),
            json!(frag_cnt),
        );
        let inner_decoded = dissect_eoe_inner_frame(reassembled, &mut eoe_ws, "ecat_mailbox", true);

        if let Some(sub_i) = sub_idx {
            for (k, v) in eoe_ws {
                if let Some(suffix) = k.strip_prefix("ecat_mailbox.") {
                    ws.insert(format!("ecat[{sub_i}].mailbox.{suffix}"), v.clone());
                    ws.insert(format!("ecat_mailbox[{sub_i}].{suffix}"), v.clone());
                    ws.entry(k).or_insert(v);
                } else {
                    ws.insert(format!("ecat[{sub_i}].{k}"), v.clone());
                    ws.entry(k).or_insert(v);
                }
            }
        } else {
            for (k, v) in eoe_ws {
                ws.insert(k, v);
            }
        }

        if let Some(obj) = proto_json.as_object_mut() {
            obj.insert("reassembled_data_hex".into(), json!(hex_data));
            obj.insert("reassembled_length".into(), json!(reassembled.len()));
            obj.insert("reassembled_fragments".into(), json!(frag_cnt));
            if let Some((inner_eth, inner_pkt)) = inner_decoded {
                obj.insert("inner_ethernet".into(), inner_eth);
                if let Some(pkt) = inner_pkt {
                    obj.insert("inner_packet".into(), pkt);
                }
            }
        }
    }

    fn update_esc_shadows(&mut self, slot: usize, cmd_u8: u8, ado: u16, data: &[u8]) {
        if data.is_empty() || ado >= 0x1000 {
            return;
        }
        let end = ado.saturating_add(data.len() as u16);
        let u16_at = |reg: u16| -> Option<u16> {
            let off = reg.checked_sub(ado)? as usize;
            (off + 2 <= data.len()).then(|| u16::from_le_bytes([data[off], data[off + 1]]))
        };

        let is_write = matches!(
            EcatCmd::from_code(cmd_u8),
            Some(EcatCmd::Apwr | EcatCmd::Fpwr | EcatCmd::Bwr | EcatCmd::Aprw | EcatCmd::Fprw)
        );

        // 0x0010 Configured Station Address & 0x0012 Station Alias
        if let Some(stadr) = u16_at(0x0010) {
            if stadr != 0 {
                self.bind_station_addr(slot, stadr);
            }
        }
        if let Some(alias) = u16_at(0x0012) {
            if alias != 0 && is_write {
                self.slaves[slot].alias_addr = Some(alias);
                self.alias_to_slot.insert(alias, slot);
            }
        }

        // 0x0120 AL Control / 0x0130 AL Status (`SAFE-OP = 4`, `OP = 8`)
        let mut new_safeop_or_op = None;
        if is_write {
            if let Some(al_ctrl) = u16_at(0x0120) {
                let st_code = al_ctrl & 0x000F;
                new_safeop_or_op = Some(matches!(st_code, 0x04 | 0x08));
            }
        } else if let Some(al_stat) = u16_at(0x0130) {
            let st_code = al_stat & 0x000F;
            let has_err = (al_stat & 0x0010) != 0;
            new_safeop_or_op = Some(!has_err && (st_code & 0x0C) != 0 && (st_code & 0x03) == 0);
        }
        if let Some(in_op) = new_safeop_or_op {
            if self.slaves[slot].in_safeop_or_op != in_op {
                self.slaves[slot].in_safeop_or_op = in_op;
                if let Some(cat) = self.options.xml_catalog.clone() {
                    if let Some(prof) = self.profile_for_slot(&cat, slot).cloned() {
                        self.sync_fixed_pdo_banks(slot, &prof);
                    }
                }
            }
        }

        // 0x0502..0x050F SII EEPROM Control/Address/Data identity tracking
        self.update_sii_shadow(slot, is_write, ado, data);

        // 0x0800..0x087F SyncManager shadow
        if ado <= 0x087F && end > 0x0800 {
            for sm_i in 0..16usize {
                let base = 0x0800 + (sm_i as u16) * 8;
                if let Some(off) = base.checked_sub(ado).map(|v| v as usize) {
                    if off + 8 <= data.len() {
                        let pstart = u16::from_le_bytes([data[off], data[off + 1]]);
                        let slen = u16::from_le_bytes([data[off + 2], data[off + 3]]);
                        let ctrl = data[off + 4];
                        let act = data[off + 6];
                        self.slaves[slot].sm_regs[sm_i] = SmShadow {
                            phys_start: pstart,
                            length: slen,
                            direction_write: ((ctrl >> 2) & 0x03) == 0x01,
                            is_mailbox: (ctrl & 0x03) == 0x02,
                            enabled: (act & 0x01) != 0 && slen > 0,
                        };
                    }
                }
            }
            if is_write {
                if let Some(cat) = self.options.xml_catalog.clone() {
                    if let Some(prof) = self.profile_for_slot(&cat, slot).cloned() {
                        self.sync_fixed_pdo_banks(slot, &prof);
                    }
                }
            }
        }

        // 0x0600..0x06FF FMMU shadow
        if ado <= 0x06FF && end > 0x0600 {
            for fmmu_i in 0..16usize {
                let base = 0x0600 + (fmmu_i as u16) * 16;
                if let Some(off) = base.checked_sub(ado).map(|v| v as usize) {
                    if off + 16 <= data.len() {
                        let c = &data[off..off + 16];
                        let fmmu = FmmuShadow {
                            log_start: u32::from_le_bytes([c[0], c[1], c[2], c[3]]),
                            log_len: u16::from_le_bytes([c[4], c[5]]),
                            log_start_bit: c[6] & 0x07,
                            log_end_bit: c[7] & 0x07,
                            phys_start: u16::from_le_bytes([c[8], c[9]]),
                            phys_start_bit: c[10] & 0x07,
                            read_enable: (c[11] & 0x01) != 0,
                            write_enable: (c[11] & 0x02) != 0,
                            active: (c[12] & 0x01) != 0 && u16::from_le_bytes([c[4], c[5]]) > 0,
                        };
                        self.slaves[slot].fmmu_regs[fmmu_i] = fmmu;
                    }
                }
            }
            self.slaves[slot].has_active_fmmu =
                self.slaves[slot].fmmu_regs.iter().any(|f| f.active);

            // For fixed-PDO slaves (non-CoE terminals, fixed CoE slaves, or ENI `<ProcessData>`),
            // FMMU or SM activation IS the hardware PDO configuration packet!
            if is_write || self.slaves[slot].has_active_fmmu {
                if let Some(cat) = self.options.xml_catalog.clone() {
                    if let Some(prof) = self.profile_for_slot(&cat, slot).cloned() {
                        self.sync_fixed_pdo_banks(slot, &prof);
                    }
                }
            }
        }
    }

    fn update_sii_shadow(&mut self, slot: usize, is_write: bool, ado: u16, data: &[u8]) {
        let end = ado.saturating_add(data.len() as u16);
        if ado > 0x050F || end <= 0x0502 {
            return;
        }
        let u16_at = |reg: u16| -> Option<u16> {
            let off = reg.checked_sub(ado)? as usize;
            (off + 2 <= data.len()).then(|| u16::from_le_bytes([data[off], data[off + 1]]))
        };
        if is_write {
            if let Some(off4) = 0x0504u16.checked_sub(ado).map(|v| v as usize) {
                if off4 + 4 <= data.len() {
                    self.slaves[slot].sii_addr_reg = u32::from_le_bytes([
                        data[off4],
                        data[off4 + 1],
                        data[off4 + 2],
                        data[off4 + 3],
                    ]);
                } else if off4 + 2 <= data.len() {
                    self.slaves[slot].sii_addr_reg =
                        u16::from_le_bytes([data[off4], data[off4 + 1]]) as u32;
                }
            }
            if let Some(ctl) = u16_at(0x0502) {
                let cmd_bits = (ctl >> 8) & 0x07;
                if cmd_bits == 0x01 {
                    self.slaves[slot].sii_pending_word = Some(self.slaves[slot].sii_addr_reg);
                } else if cmd_bits != 0x00 {
                    self.slaves[slot].sii_pending_word = None;
                }
            }
        } else {
            if let Some(estat) = u16_at(0x0502) {
                if (estat & 0x8000) != 0 {
                    return;
                }
                if (estat & 0x7800) != 0 {
                    self.slaves[slot].sii_pending_word = None;
                    return;
                }
                self.slaves[slot].sii_r64 = Some((estat & 0x0040) != 0);
            }
            if ado <= 0x050F && end > 0x0508 {
                if let Some(word_addr) = self.slaves[slot].sii_pending_word {
                    let eep_base = (word_addr as usize).saturating_mul(2);
                    let max_reg = if self.slaves[slot].sii_r64 == Some(false) {
                        0x050Cu16
                    } else {
                        0x0510u16
                    };
                    for reg in 0x0508..max_reg {
                        if let Some(off) = reg.checked_sub(ado).map(|v| v as usize) {
                            if off < data.len() {
                                let eep_off = eep_base + (reg - 0x0508) as usize;
                                if eep_off < 32 {
                                    self.slaves[slot].sii_head[eep_off] = Some(data[off]);
                                }
                            }
                        }
                    }
                    let read_sii_u32 = |head: &[Option<u8>; 32], base: usize| -> Option<u32> {
                        Some(u32::from_le_bytes([
                            head[base]?,
                            head[base + 1]?,
                            head[base + 2]?,
                            head[base + 3]?,
                        ]))
                    };
                    let head = self.slaves[slot].sii_head;
                    if let (Some(lo), Some(hi)) = (head[0x08], head[0x09]) {
                        let alias = u16::from_le_bytes([lo, hi]);
                        if alias != 0 && self.slaves[slot].alias_addr.is_none() {
                            self.slaves[slot].alias_addr = Some(alias);
                            self.alias_to_slot.insert(alias, slot);
                        }
                    }
                    let prev_id = (
                        self.slaves[slot].vendor_id,
                        self.slaves[slot].product_code,
                        self.slaves[slot].revision_no,
                    );
                    if let Some(vid) = read_sii_u32(&head, 0x10) {
                        self.slaves[slot].vendor_id = Some(vid);
                    }
                    if let Some(pc) = read_sii_u32(&head, 0x14) {
                        self.slaves[slot].product_code = Some(pc);
                    }
                    if let Some(rev) = read_sii_u32(&head, 0x18) {
                        self.slaves[slot].revision_no = Some(rev);
                    }
                    let new_id = (
                        self.slaves[slot].vendor_id,
                        self.slaves[slot].product_code,
                        self.slaves[slot].revision_no,
                    );
                    if new_id != prev_id {
                        if let Some(cat) = self.options.xml_catalog.clone() {
                            if let Some(prof) = self.profile_for_slot(&cat, slot).cloned() {
                                self.sync_fixed_pdo_banks(slot, &prof);
                            }
                        }
                    }
                }
            }
        }
    }

    fn sync_fixed_pdo_banks(&mut self, slot: usize, prof: &XmlDeviceProfile) {
        let st = &self.slaves[slot];
        let in_op = st.in_safeop_or_op;
        let has_wr_hw = st.fmmu_regs.iter().any(|f| {
            f.active && f.write_enable && f.maps_process_data(&st.sm_regs, true).is_some()
        }) || st
            .sm_regs
            .iter()
            .any(|sm| sm.enabled && !sm.is_mailbox && sm.direction_write);
        let has_rd_hw = st.fmmu_regs.iter().any(|f| {
            f.active && f.read_enable && f.maps_process_data(&st.sm_regs, false).is_some()
        }) || st
            .sm_regs
            .iter()
            .any(|sm| sm.enabled && !sm.is_mailbox && !sm.direction_write);

        let rx_uses_coe = prof.uses_coe_pdo_configuration_dir(PdoDirection::RxPdo);
        let rx_unmodified = self.slaves[slot].sm2_assign.committed.is_none()
            && !self.slaves[slot]
                .dynamic_rx_pdos
                .values()
                .any(|d| d.explicitly_written || d.committed_count == Some(0));
        let rx_can_default = !rx_uses_coe
            || (in_op
                && prof
                    .rx_pdos
                    .values()
                    .any(|p| p.default_sm.is_some() || p.fixed));
        if rx_unmodified {
            if has_wr_hw && rx_can_default && !prof.rx_pdos.is_empty() {
                let pdos = Self::select_default_fixed_pdos(prof, PdoDirection::RxPdo);
                self.slaves[slot].rx_active =
                    Self::compile_pdo_bank(prof, PdoDirection::RxPdo, &pdos, &BTreeMap::new());
            } else if !has_wr_hw || (rx_uses_coe && !in_op) {
                self.slaves[slot].rx_active = None;
            }
        }

        let tx_uses_coe = prof.uses_coe_pdo_configuration_dir(PdoDirection::TxPdo);
        let tx_unmodified = self.slaves[slot].sm3_assign.committed.is_none()
            && !self.slaves[slot]
                .dynamic_tx_pdos
                .values()
                .any(|d| d.explicitly_written || d.committed_count == Some(0));
        let tx_can_default = !tx_uses_coe
            || (in_op
                && prof
                    .tx_pdos
                    .values()
                    .any(|p| p.default_sm.is_some() || p.fixed));
        if tx_unmodified {
            if has_rd_hw && tx_can_default && !prof.tx_pdos.is_empty() {
                let pdos = Self::select_default_fixed_pdos(prof, PdoDirection::TxPdo);
                self.slaves[slot].tx_active =
                    Self::compile_pdo_bank(prof, PdoDirection::TxPdo, &pdos, &BTreeMap::new());
            } else if !has_rd_hw || (tx_uses_coe && !in_op) {
                self.slaves[slot].tx_active = None;
            }
        }
    }

    fn select_default_fixed_pdos(prof: &XmlDeviceProfile, direction: PdoDirection) -> Vec<u16> {
        let map = match direction {
            PdoDirection::RxPdo => &prof.rx_pdos,
            PdoDirection::TxPdo => &prof.tx_pdos,
        };
        if prof.is_eni {
            return map.keys().copied().collect();
        }
        if map.values().any(|p| p.default_sm.is_some()) {
            return map
                .values()
                .filter(|p| p.default_sm.is_some())
                .map(|p| p.pdo_index)
                .collect();
        }
        map.values()
            .filter(|p| p.fixed || map.len() == 1 || !prof.coe_supported)
            .map(|p| p.pdo_index)
            .collect()
    }

    fn clear_slave_pending_upload_scan(&mut self, slot: usize, index: u16) {
        let st = &mut self.slaves[slot];
        match index {
            0xF030 => {
                st.mdp_pending_upload_count = None;
                st.mdp_upload_staged.clear();
            }
            0x1C12 => {
                st.sm2_assign.pending_upload_count = None;
                st.sm2_assign.upload_staged.clear();
            }
            0x1C13 => {
                st.sm3_assign.pending_upload_count = None;
                st.sm3_assign.upload_staged.clear();
            }
            0x1600..=0x17FF => {
                if let Some(pm) = st.dynamic_rx_pdos.get_mut(&index) {
                    pm.pending_upload_count = None;
                    pm.upload_staged.clear();
                }
            }
            0x1A00..=0x1BFF => {
                if let Some(pm) = st.dynamic_tx_pdos.get_mut(&index) {
                    pm.pending_upload_count = None;
                    pm.upload_staged.clear();
                }
            }
            _ => {}
        }
    }

    fn snapshot_slave_pdo_state(&mut self, slot: usize, index: u16, subindex: u8) {
        let st = &mut self.slaves[slot];
        st.last_dl_pdo_snapshot = Some(PdoStateSnapshot {
            index,
            subindex,
            mdp_staged_idents: st.mdp_staged_idents.clone(),
            mdp_committed_idents: st.mdp_committed_idents.clone(),
            mdp_profile_override: st.mdp_profile_override.clone(),
            dynamic_rx_pdos: st.dynamic_rx_pdos.clone(),
            dynamic_tx_pdos: st.dynamic_tx_pdos.clone(),
            sm2_assign: st.sm2_assign.clone(),
            sm3_assign: st.sm3_assign.clone(),
            rx_active: st.rx_active.clone(),
            tx_active: st.tx_active.clone(),
        });
    }

    fn rollback_slave_pdo_state(&mut self, slot: usize, index: u16, subindex: u8) {
        let st = &mut self.slaves[slot];
        if let Some(snap) = st.last_dl_pdo_snapshot.take() {
            if snap.index == index && snap.subindex == subindex {
                st.mdp_staged_idents = snap.mdp_staged_idents;
                st.mdp_committed_idents = snap.mdp_committed_idents;
                st.mdp_profile_override = snap.mdp_profile_override;
                st.dynamic_rx_pdos = snap.dynamic_rx_pdos;
                st.dynamic_tx_pdos = snap.dynamic_tx_pdos;
                st.sm2_assign = snap.sm2_assign;
                st.sm3_assign = snap.sm3_assign;
                st.rx_active = snap.rx_active;
                st.tx_active = snap.tx_active;
            }
        }
    }

    fn emit_block_crc_ws(
        crc_ok: bool,
        calc_crc: u16,
        ws: &mut BTreeMap<String, Value>,
        mbx_prefix: &str,
        proto_json: Option<&mut Value>,
    ) {
        let calc_hex = format!("0x{calc_crc:04x}");
        ws.insert(format!("{mbx_prefix}.coe.sdoblk.crc_ok"), json!(crc_ok));
        ws.insert(
            format!("{mbx_prefix}.coe.sdoblk.computed_crc"),
            json!(calc_hex.clone()),
        );
        if let Some(sub_i_str) = mbx_prefix
            .strip_prefix("ecat_mailbox[")
            .and_then(|s| s.strip_suffix(']'))
        {
            ws.insert(
                format!("ecat[{sub_i_str}].mailbox.coe.sdoblk.crc_ok"),
                json!(crc_ok),
            );
            ws.insert(
                format!("ecat[{sub_i_str}].mailbox.coe.sdoblk.computed_crc"),
                json!(calc_hex.clone()),
            );
        } else if mbx_prefix == "ecat_mailbox" {
            ws.insert("ecat[0].mailbox.coe.sdoblk.crc_ok".into(), json!(crc_ok));
            ws.insert(
                "ecat[0].mailbox.coe.sdoblk.computed_crc".into(),
                json!(calc_hex.clone()),
            );
            ws.insert("ecat_mailbox[0].coe.sdoblk.crc_ok".into(), json!(crc_ok));
            ws.insert(
                "ecat_mailbox[0].coe.sdoblk.computed_crc".into(),
                json!(calc_hex.clone()),
            );
        }
        if !mbx_prefix.starts_with("ams") {
            ws.entry("ecat_mailbox.coe.sdoblk.crc_ok".into())
                .or_insert_with(|| json!(crc_ok));
            ws.entry("ecat_mailbox.coe.sdoblk.computed_crc".into())
                .or_insert_with(|| json!(calc_hex.clone()));
        }
        if let Some(pj) = proto_json {
            if let Some(obj) = pj.as_object_mut() {
                obj.insert("crc_ok".into(), json!(crc_ok));
                obj.insert("computed_crc".into(), json!(calc_hex));
            }
        }
    }

    fn emit_reassembled_sdo_ws(bytes: &[u8], ws: &mut BTreeMap<String, Value>, mbx_prefix: &str) {
        let hex = format_hex(bytes);
        ws.insert(
            format!("{mbx_prefix}.coe.sdo.reassembled_data"),
            json!(hex.clone()),
        );
        if let Some(sub_i_str) = mbx_prefix
            .strip_prefix("ecat_mailbox[")
            .and_then(|s| s.strip_suffix(']'))
        {
            ws.insert(
                format!("ecat[{sub_i_str}].mailbox.coe.sdo.reassembled_data"),
                json!(hex.clone()),
            );
        } else if mbx_prefix == "ecat_mailbox" {
            ws.insert(
                "ecat[0].mailbox.coe.sdo.reassembled_data".into(),
                json!(hex.clone()),
            );
            ws.insert(
                "ecat_mailbox[0].coe.sdo.reassembled_data".into(),
                json!(hex.clone()),
            );
        }
        if !mbx_prefix.starts_with("ams") {
            ws.entry("ecat_mailbox.coe.sdo.reassembled_data".into())
                .or_insert_with(|| json!(hex));
        }
    }

    fn compute_block_sdo_trim(done: &InFlightBlockSdo, buf_len: usize, unused_bytes: u8) -> usize {
        if let Some(exp) = done.expected_len.filter(|&e| e > 0) {
            buf_len.saturating_sub(exp).min(done.last_subblock_len)
        } else if done.last_subblock_len <= 7 {
            done.last_subblock_len
                .saturating_sub(7usize.saturating_sub(unused_bytes as usize))
        } else {
            (unused_bytes as usize).min(done.last_subblock_len)
        }
    }

    fn process_sdo_event_for_slot(
        &mut self,
        mut slot: usize,
        ev: &SdoEventKind,
        ws: &mut BTreeMap<String, Value>,
        mbx_prefix: &str,
        mut proto_json: Option<&mut Value>,
        raw_mbx: Option<&[u8]>,
    ) -> Option<SdoXmlDecode> {
        type CompletedSdoTransfer = (SdoTransferDir, u16, u8, bool, Vec<u8>, Option<usize>);
        let mut completed_transfer: Option<CompletedSdoTransfer> = None;
        let mut block_crc_result: Option<(bool, u16)> = None;
        let mut synth_abort_ev: Option<SdoEventKind> = None;

        match ev {
            SdoEventKind::InitiateDownload {
                index,
                subindex,
                complete_access,
                expedited,
                indicated_size,
                inline_data,
            } => {
                self.slaves[slot].in_flight_dl = None;
                self.slaves[slot].in_flight_block_dl = None;
                self.slaves[slot].last_dl_subblock_raw = None;
                self.slaves[slot].last_dl_pdo_snapshot = None;
                if *expedited || indicated_size.is_some_and(|tot| inline_data.len() >= tot) {
                    completed_transfer = Some((
                        SdoTransferDir::Download,
                        *index,
                        *subindex,
                        *complete_access,
                        inline_data.clone(),
                        None,
                    ));
                } else {
                    self.slaves[slot].in_flight_dl = Some(InFlightSdo {
                        dir: SdoTransferDir::Download,
                        index: *index,
                        subindex: *subindex,
                        complete_access: *complete_access,
                        expected_len: *indicated_size,
                        buffer: inline_data.clone(),
                        segments: 0,
                        last_toggle: None,
                    });
                    if indicated_size.is_none() && !inline_data.is_empty() {
                        completed_transfer = Some((
                            SdoTransferDir::Download,
                            *index,
                            *subindex,
                            *complete_access,
                            inline_data.clone(),
                            None,
                        ));
                    }
                }
            }
            SdoEventKind::DownloadSegmentReq {
                toggle,
                last_segment,
                seg_data,
            } => {
                if let Some(inflight) = self.slaves[slot].in_flight_dl.as_mut() {
                    debug_assert_eq!(inflight.dir, SdoTransferDir::Download);
                    if inflight.last_toggle != Some(*toggle) {
                        inflight.last_toggle = Some(*toggle);
                        inflight.buffer.extend_from_slice(seg_data);
                        inflight.segments += 1;
                    }
                    if *last_segment {
                        let done = self.slaves[slot].in_flight_dl.take().unwrap();
                        let mut buf = done.buffer;
                        if let Some(exp) = done.expected_len {
                            if buf.len() > exp {
                                buf.truncate(exp);
                            }
                        }
                        completed_transfer = Some((
                            done.dir,
                            done.index,
                            done.subindex,
                            done.complete_access,
                            buf,
                            Some(done.segments),
                        ));
                    }
                }
            }
            SdoEventKind::InitiateUploadReq {
                index,
                subindex,
                complete_access,
            } => {
                self.slaves[slot].pending_upload_req = Some((*index, *subindex, *complete_access));
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = None;
            }
            SdoEventKind::AoeReadReq {
                target_net_id,
                target_port,
                invoke_id,
                index,
                subindex,
                complete_access,
            } => {
                if self.pending_aoe_sdo_reads.len() >= 256 {
                    if let Some(first_k) = self.pending_aoe_sdo_reads.keys().next().cloned() {
                        self.pending_aoe_sdo_reads.remove(&first_k);
                    }
                }
                self.pending_aoe_sdo_reads.insert(
                    (target_net_id.clone(), *target_port, *invoke_id),
                    (slot, *index, *subindex, *complete_access),
                );
                self.slaves[slot].pending_upload_req = Some((*index, *subindex, *complete_access));
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = None;
            }
            SdoEventKind::AoeReadWriteReq {
                target_net_id,
                target_port,
                invoke_id,
                index,
                subindex,
                complete_access,
                ..
            } => {
                if self.pending_aoe_sdo_reads.len() >= 256 {
                    if let Some(first_k) = self.pending_aoe_sdo_reads.keys().next().cloned() {
                        self.pending_aoe_sdo_reads.remove(&first_k);
                    }
                }
                self.pending_aoe_sdo_reads.insert(
                    (target_net_id.clone(), *target_port, *invoke_id),
                    (slot, *index, *subindex, *complete_access),
                );
                self.slaves[slot].pending_upload_req = Some((*index, *subindex, *complete_access));
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = None;
            }
            SdoEventKind::AoeWriteReq {
                target_net_id,
                target_port,
                invoke_id,
                index,
                subindex,
                complete_access,
                data,
            } => {
                self.slaves[slot].last_dl_pdo_snapshot = None;
                if self.pending_aoe_sdo_writes.len() >= 256 {
                    if let Some(first_k) = self.pending_aoe_sdo_writes.keys().next().cloned() {
                        self.pending_aoe_sdo_writes.remove(&first_k);
                    }
                }
                self.pending_aoe_sdo_writes.insert(
                    (target_net_id.clone(), *target_port, *invoke_id),
                    (slot, *index, *subindex),
                );
                completed_transfer = Some((
                    SdoTransferDir::Download,
                    *index,
                    *subindex,
                    *complete_access,
                    data.clone(),
                    None,
                ));
            }
            SdoEventKind::AoeWriteRes {
                sender_net_id,
                sender_port,
                invoke_id,
                ads_result,
            } => {
                let (req_slot, idx, sub) = self.pending_aoe_sdo_writes.remove(&(
                    sender_net_id.clone(),
                    *sender_port,
                    *invoke_id,
                ))?;
                slot = req_slot;
                if *ads_result == 0 {
                    self.slaves[slot].last_dl_pdo_snapshot = None;
                    synth_abort_ev = Some(SdoEventKind::InitiateUploadReq {
                        index: idx,
                        subindex: sub,
                        complete_access: false,
                    });
                } else {
                    self.rollback_slave_pdo_state(slot, idx, sub);
                    synth_abort_ev = Some(SdoEventKind::Abort {
                        index: idx,
                        subindex: sub,
                        abort_code: *ads_result,
                    });
                }
            }
            SdoEventKind::AoeReadRes {
                sender_net_id,
                sender_port,
                invoke_id,
                ads_result,
                data,
            } => {
                let (req_slot, idx, sub, ca) = self.pending_aoe_sdo_reads.remove(&(
                    sender_net_id.clone(),
                    *sender_port,
                    *invoke_id,
                ))?;
                slot = req_slot;
                if *ads_result == 0 {
                    completed_transfer =
                        Some((SdoTransferDir::Upload, idx, sub, ca, data.clone(), None));
                } else {
                    self.clear_slave_pending_upload_scan(slot, idx);
                    synth_abort_ev = Some(SdoEventKind::Abort {
                        index: idx,
                        subindex: sub,
                        abort_code: *ads_result,
                    });
                }
            }
            SdoEventKind::InitiateUploadRes {
                index,
                subindex,
                complete_access,
                expedited,
                indicated_size,
                inline_data,
            } => {
                let eff_ca = *complete_access
                    || self.slaves[slot]
                        .pending_upload_req
                        .is_some_and(|(i, s, ca)| i == *index && s == *subindex && ca);
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = None;
                if *expedited || indicated_size.is_some_and(|tot| inline_data.len() >= tot) {
                    completed_transfer = Some((
                        SdoTransferDir::Upload,
                        *index,
                        *subindex,
                        eff_ca,
                        inline_data.clone(),
                        None,
                    ));
                } else {
                    self.slaves[slot].in_flight_ul = Some(InFlightSdo {
                        dir: SdoTransferDir::Upload,
                        index: *index,
                        subindex: *subindex,
                        complete_access: eff_ca,
                        expected_len: *indicated_size,
                        buffer: inline_data.clone(),
                        segments: 0,
                        last_toggle: None,
                    });
                    if indicated_size.is_none() && !inline_data.is_empty() {
                        completed_transfer = Some((
                            SdoTransferDir::Upload,
                            *index,
                            *subindex,
                            eff_ca,
                            inline_data.clone(),
                            None,
                        ));
                    }
                }
            }
            SdoEventKind::UploadSegmentRes {
                toggle,
                last_segment,
                seg_data,
            } => {
                if let Some(inflight) = self.slaves[slot].in_flight_ul.as_mut() {
                    debug_assert_eq!(inflight.dir, SdoTransferDir::Upload);
                    if inflight.last_toggle != Some(*toggle) {
                        inflight.last_toggle = Some(*toggle);
                        inflight.buffer.extend_from_slice(seg_data);
                        inflight.segments += 1;
                    }
                    if *last_segment {
                        let done = self.slaves[slot].in_flight_ul.take().unwrap();
                        let mut buf = done.buffer;
                        if let Some(exp) = done.expected_len {
                            if buf.len() > exp {
                                buf.truncate(exp);
                            }
                        }
                        completed_transfer = Some((
                            done.dir,
                            done.index,
                            done.subindex,
                            done.complete_access,
                            buf,
                            Some(done.segments),
                        ));
                    }
                }
            }
            // CoE SDO Block Download (`ccs == 6` / `scs == 5`)
            SdoEventKind::InitiateBlockDownload {
                index,
                subindex,
                complete_access,
                crc_support,
                indicated_size,
            } => {
                self.slaves[slot].in_flight_dl = None;
                self.slaves[slot].last_dl_subblock_raw = None;
                self.slaves[slot].last_dl_pdo_snapshot = None;
                self.slaves[slot].in_flight_block_dl = Some(InFlightBlockSdo::new(
                    SdoTransferDir::Download,
                    *index,
                    *subindex,
                    *complete_access,
                    *crc_support,
                    None,
                    *indicated_size,
                    true,
                ));
            }
            SdoEventKind::InitiateBlockDownloadRes { crc_support, .. } => {
                if let Some(blk) = self.slaves[slot].in_flight_block_dl.as_mut() {
                    blk.server_crc = Some(*crc_support);
                    blk.streaming_subblocks = true;
                }
            }
            SdoEventKind::BlockDownloadAck { ackseq, .. } => {
                if let Some(blk) = self.slaves[slot].in_flight_block_dl.as_mut() {
                    let ack = (*ackseq as usize).min(127);
                    if ack < blk.max_seq_in_block {
                        blk.buffer.truncate(blk.block_byte_offsets[ack]);
                        blk.last_subblock_len = 0;
                        blk.streaming_subblocks = true;
                    }
                    blk.block_byte_offsets = [blk.buffer.len(); 128];
                    blk.max_seq_in_block = 0;
                    blk.last_seq_sig = None;
                }
            }
            SdoEventKind::EndBlockDownload { unused_bytes, crc } => {
                self.slaves[slot].last_dl_subblock_raw = None;
                if let Some(done) = self.slaves[slot].in_flight_block_dl.take() {
                    debug_assert_eq!(done.dir, SdoTransferDir::Download);
                    let check_crc = done.crc_enabled();
                    let trim_from_last =
                        Self::compute_block_sdo_trim(&done, done.buffer.len(), *unused_bytes);
                    let mut buf = done.buffer;
                    let trimmed = buf.len().saturating_sub(trim_from_last);
                    buf.truncate(trimmed);
                    if let Some(exp) = done.expected_len {
                        if buf.len() > exp {
                            buf.truncate(exp);
                        }
                    }
                    if check_crc {
                        let calc = sdo_block_crc16(&buf);
                        block_crc_result = Some((calc == *crc, calc));
                    }
                    completed_transfer = Some((
                        done.dir,
                        done.index,
                        done.subindex,
                        done.complete_access,
                        buf,
                        Some(done.segments),
                    ));
                }
            }
            SdoEventKind::EndBlockDownloadRes => {
                self.slaves[slot].last_dl_pdo_snapshot = None;
            }
            // CoE SDO Block Upload (`ccs == 5` / `scs == 6`)
            SdoEventKind::InitiateBlockUploadReq {
                index,
                subindex,
                complete_access,
                crc_support,
                ..
            } => {
                self.slaves[slot].pending_block_ul_req =
                    Some((*index, *subindex, *complete_access, *crc_support));
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = None;
            }
            SdoEventKind::InitiateBlockUploadRes {
                index,
                subindex,
                crc_support,
                indicated_size,
            } => {
                let (eff_ca, client_crc) = match self.slaves[slot].pending_block_ul_req.take() {
                    Some((i, s, ca, req_crc)) if i == *index && s == *subindex => (ca, req_crc),
                    _ => (false, *crc_support),
                };
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_ul = Some(InFlightBlockSdo::new(
                    SdoTransferDir::Upload,
                    *index,
                    *subindex,
                    eff_ca,
                    client_crc,
                    Some(*crc_support),
                    *indicated_size,
                    true,
                ));
            }
            SdoEventKind::StartBlockUpload => {
                if let Some(blk) = self.slaves[slot].in_flight_block_ul.as_mut() {
                    blk.streaming_subblocks = true;
                } else if let Some((idx, sub, ca, req_crc)) =
                    self.slaves[slot].pending_block_ul_req.take()
                {
                    // InitiateBlockUploadRes was not captured; bootstrap with `server_crc = None`
                    // so `crc_enabled()` uses `client_crc`!
                    self.slaves[slot].in_flight_block_ul = Some(InFlightBlockSdo::new(
                        SdoTransferDir::Upload,
                        idx,
                        sub,
                        ca,
                        req_crc,
                        None,
                        None,
                        true,
                    ));
                }
            }
            SdoEventKind::BlockUploadAck { ackseq, .. } => {
                if let Some(blk) = self.slaves[slot].in_flight_block_ul.as_mut() {
                    let ack = (*ackseq as usize).min(127);
                    if ack < blk.max_seq_in_block {
                        blk.buffer.truncate(blk.block_byte_offsets[ack]);
                        blk.last_subblock_len = 0;
                        blk.streaming_subblocks = true;
                    }
                    blk.block_byte_offsets = [blk.buffer.len(); 128];
                    blk.max_seq_in_block = 0;
                    blk.last_seq_sig = None;
                }
            }
            SdoEventKind::EndBlockUpload { unused_bytes, crc } => {
                if let Some(done) = self.slaves[slot].in_flight_block_ul.take() {
                    debug_assert_eq!(done.dir, SdoTransferDir::Upload);
                    let check_crc = done.crc_enabled();
                    let trim_from_last =
                        Self::compute_block_sdo_trim(&done, done.buffer.len(), *unused_bytes);
                    let mut buf = done.buffer;
                    let trimmed = buf.len().saturating_sub(trim_from_last);
                    buf.truncate(trimmed);
                    if let Some(exp) = done.expected_len {
                        if buf.len() > exp {
                            buf.truncate(exp);
                        }
                    }
                    if check_crc {
                        let calc = sdo_block_crc16(&buf);
                        block_crc_result = Some((calc == *crc, calc));
                    }
                    completed_transfer = Some((
                        done.dir,
                        done.index,
                        done.subindex,
                        done.complete_access,
                        buf,
                        Some(done.segments),
                    ));
                }
            }
            SdoEventKind::BlockSubblock {
                is_download,
                seq_no,
                last_subblock,
                data,
            } => {
                let blk_opt = if *is_download {
                    self.slaves[slot].in_flight_block_dl.as_mut()
                } else {
                    self.slaves[slot].in_flight_block_ul.as_mut()
                };
                if let Some(blk) = blk_opt {
                    let sig = (*seq_no, *last_subblock, data.clone());
                    if blk.last_seq_sig.as_ref() != Some(&sig) {
                        blk.last_seq_sig = Some(sig);
                        let s = (*seq_no as usize).min(127);
                        let mut skip_duplicate = false;
                        if s == 1 && blk.max_seq_in_block > 0 {
                            let block_start = blk.block_byte_offsets[0];
                            if block_start < blk.buffer.len()
                                && blk.buffer[block_start..].starts_with(data)
                            {
                                // Retransmit of current block starting at seq 1 after missed ACK(0)
                                blk.buffer.truncate(block_start);
                                blk.segments = blk.segments.saturating_sub(blk.max_seq_in_block);
                            }
                            blk.block_byte_offsets = [blk.buffer.len(); 128];
                            blk.max_seq_in_block = 0;
                        } else if s <= blk.max_seq_in_block {
                            skip_duplicate = true;
                        }
                        if !skip_duplicate {
                            blk.buffer.extend_from_slice(data);
                            blk.last_subblock_len = data.len();
                            blk.segments += 1;
                            if s > blk.max_seq_in_block {
                                blk.max_seq_in_block = s;
                            }
                            blk.block_byte_offsets[s] = blk.buffer.len();
                        }
                    }
                    if *last_subblock {
                        blk.streaming_subblocks = false;
                    }
                }
            }
            SdoEventKind::Abort {
                index, subindex, ..
            } => {
                self.slaves[slot].in_flight_dl = None;
                self.slaves[slot].in_flight_ul = None;
                self.slaves[slot].in_flight_block_dl = None;
                self.slaves[slot].in_flight_block_ul = None;
                self.slaves[slot].pending_block_ul_req = None;
                self.slaves[slot].last_dl_subblock_raw = None;
                self.clear_slave_pending_upload_scan(slot, *index);
                self.rollback_slave_pdo_state(slot, *index, *subindex);
            }
            _ => {}
        }

        // Emit SDO Block CRC-16 verification fields even when `--xml` is not supplied
        if let Some((crc_ok, calc_crc)) = block_crc_result {
            Self::emit_block_crc_ws(crc_ok, calc_crc, ws, mbx_prefix, proto_json.as_deref_mut());
        }

        // Emit reassembled payload field even when `--xml` is not supplied
        if let Some((dir, idx, sub, ca, ref bytes, segs)) = completed_transfer {
            if segs.is_some() {
                Self::emit_reassembled_sdo_ws(bytes, ws, mbx_prefix);
            }
            self.observe_identity_sdo(slot, idx, sub, ca, bytes);
            if dir == SdoTransferDir::Download
                && matches!(idx, 0xF030 | 0x1600..=0x17FF | 0x1A00..=0x1BFF | 0x1C12 | 0x1C13)
            {
                self.snapshot_slave_pdo_state(slot, idx, sub);
            }
            self.observe_pdo_config_sdo(slot, dir, idx, sub, ca, bytes);
        }

        // XML SDO Enrichment
        let xml_dec = if let Some(cat) = self.options.xml_catalog.clone() {
            let pref = self.profile_for_slot(&cat, slot);
            if let Some((_, idx, sub, ca, ref bytes, segs)) = completed_transfer {
                decode_sdo_with_xml(&cat, pref, idx, sub, ca, Some(bytes), segs, ws, mbx_prefix)
            } else if let Some(ref ab_ev) = synth_abort_ev {
                crate::engine::sdo::enrich_single_frame_sdo(ab_ev, &cat, pref, ws, mbx_prefix)
            } else {
                crate::engine::sdo::enrich_single_frame_sdo(ev, &cat, pref, ws, mbx_prefix)
            }
        } else {
            None
        };

        if let (Some(ref xd), Some(pj)) = (&xml_dec, proto_json) {
            if let Some(obj) = pj.as_object_mut() {
                obj.insert(
                    "sdo_xml".into(),
                    serde_json::to_value(xd).unwrap_or(json!(null)),
                );
            }
        }

        if let Some(rm) = raw_mbx {
            let is_dl_req = matches!(
                ev,
                SdoEventKind::InitiateDownload { .. }
                    | SdoEventKind::DownloadSegmentReq { .. }
                    | SdoEventKind::InitiateBlockDownload { .. }
                    | SdoEventKind::EndBlockDownload { .. }
                    | SdoEventKind::BlockSubblock {
                        is_download: true,
                        ..
                    }
                    | SdoEventKind::AoeWriteReq { .. }
                    | SdoEventKind::AoeReadWriteReq { .. }
            );
            if is_dl_req {
                let reasm_opt = completed_transfer
                    .as_ref()
                    .and_then(|(_, _, _, _, bytes, segs)| segs.map(|_| bytes.clone()));
                self.slaves[slot].last_dl_echo_enrichment =
                    Some((rm.to_vec(), xml_dec.clone(), block_crc_result, reasm_opt));
            }
        }

        xml_dec
    }

    fn observe_identity_sdo(&mut self, slot: usize, idx: u16, sub: u8, ca: bool, data: &[u8]) {
        if idx != 0x1018 {
            return;
        }
        if ca {
            let (cnt, start) = parse_ca_header(sub, data, 4);
            if cnt >= 1 && start + 4 <= data.len() {
                self.slaves[slot].vendor_id = Some(u32::from_le_bytes([
                    data[start],
                    data[start + 1],
                    data[start + 2],
                    data[start + 3],
                ]));
            }
            if cnt >= 2 && start + 8 <= data.len() {
                self.slaves[slot].product_code = Some(u32::from_le_bytes([
                    data[start + 4],
                    data[start + 5],
                    data[start + 6],
                    data[start + 7],
                ]));
            }
            if cnt >= 3 && start + 12 <= data.len() {
                self.slaves[slot].revision_no = Some(u32::from_le_bytes([
                    data[start + 8],
                    data[start + 9],
                    data[start + 10],
                    data[start + 11],
                ]));
            }
        } else if data.len() >= 4 {
            let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
            match sub {
                1 => self.slaves[slot].vendor_id = Some(v),
                2 => self.slaves[slot].product_code = Some(v),
                3 => self.slaves[slot].revision_no = Some(v),
                _ => {}
            }
        }
    }

    fn observe_pdo_config_sdo(
        &mut self,
        slot: usize,
        dir: SdoTransferDir,
        idx: u16,
        sub: u8,
        ca: bool,
        data: &[u8],
    ) {
        if data.is_empty() {
            return;
        }
        let mut recompute_rx = false;
        let mut recompute_tx = false;
        let mut rebuild_mdp = false;

        match idx {
            // Configured Module Ident List (`0xF030`, ETG.5001 Modular Device Profile)
            0xF030 => {
                let st = &mut self.slaves[slot];
                if ca {
                    let (cnt, start) = parse_ca_header(sub, data, 4);
                    st.mdp_pending_upload_count = None;
                    st.mdp_upload_staged.clear();
                    st.mdp_staged_idents.clear();
                    let mut idents = Vec::with_capacity(cnt);
                    for i in 0..cnt {
                        let off = start + i * 4;
                        if off + 4 <= data.len() {
                            let ident = u32::from_le_bytes([
                                data[off],
                                data[off + 1],
                                data[off + 2],
                                data[off + 3],
                            ]);
                            st.mdp_staged_idents.insert((i + 1) as u8, ident);
                            idents.push(ident);
                        }
                    }
                    st.mdp_committed_idents = Some(idents);
                    rebuild_mdp = true;
                } else if sub == 0 {
                    let cnt = data[0];
                    if cnt == 0 {
                        st.mdp_pending_upload_count = None;
                        st.mdp_upload_staged.clear();
                        st.mdp_staged_idents.clear();
                        st.mdp_committed_idents = Some(Vec::new());
                        rebuild_mdp = true;
                    } else if dir == SdoTransferDir::Download
                        || (st.mdp_committed_idents.is_none()
                            && (1..=cnt).all(|k| st.mdp_staged_idents.contains_key(&k)))
                    {
                        st.mdp_pending_upload_count = None;
                        st.mdp_upload_staged.clear();
                        let mut idents = Vec::with_capacity(cnt as usize);
                        for k in 1..=cnt {
                            idents.push(st.mdp_staged_idents.get(&k).copied().unwrap_or(0));
                        }
                        st.mdp_committed_idents = Some(idents);
                        rebuild_mdp = true;
                    } else {
                        st.mdp_pending_upload_count = Some(cnt);
                        st.mdp_upload_staged.clear();
                    }
                } else if data.len() >= 4 {
                    let ident = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    if dir == SdoTransferDir::Upload {
                        if let Some(pend) = st.mdp_pending_upload_count {
                            st.mdp_upload_staged.insert(sub, ident);
                            if (1..=pend).all(|k| st.mdp_upload_staged.contains_key(&k)) {
                                let mut idents = Vec::with_capacity(pend as usize);
                                for k in 1..=pend {
                                    idents.push(st.mdp_upload_staged.get(&k).copied().unwrap_or(0));
                                }
                                st.mdp_staged_idents = std::mem::take(&mut st.mdp_upload_staged);
                                st.mdp_committed_idents = Some(idents);
                                st.mdp_pending_upload_count = None;
                                rebuild_mdp = true;
                            }
                        } else {
                            st.mdp_staged_idents.insert(sub, ident);
                        }
                    } else {
                        st.mdp_pending_upload_count = None;
                        st.mdp_upload_staged.clear();
                        st.mdp_staged_idents.insert(sub, ident);
                    }
                }
            }
            // RxPDO Mapping (`0x1600..0x17FF`) & TxPDO Mapping (`0x1A00..0x1BFF`)
            0x1600..=0x17FF | 0x1A00..=0x1BFF => {
                let is_rx = idx < 0x1800;
                let map_tbl = if is_rx {
                    &mut self.slaves[slot].dynamic_rx_pdos
                } else {
                    &mut self.slaves[slot].dynamic_tx_pdos
                };
                let pdo_map = map_tbl.entry(idx).or_default();

                if ca {
                    let (cnt, start) = parse_ca_header(sub, data, 4);
                    pdo_map.pending_upload_count = None;
                    pdo_map.upload_staged.clear();
                    pdo_map.staged.clear();
                    for i in 0..cnt {
                        let off = start + i * 4;
                        if off + 4 <= data.len() {
                            let raw = u32::from_le_bytes([
                                data[off],
                                data[off + 1],
                                data[off + 2],
                                data[off + 3],
                            ]);
                            pdo_map.staged.insert(
                                (i + 1) as u8,
                                MappedEntryRaw {
                                    entry_index: ((raw >> 16) & 0xFFFF) as u16,
                                    entry_subindex: ((raw >> 8) & 0xFF) as u8,
                                    bit_length: (raw & 0xFF) as u16,
                                },
                            );
                        }
                    }
                    pdo_map.committed_count = Some(cnt as u8);
                    pdo_map.explicitly_written = dir == SdoTransferDir::Download && cnt > 0;
                } else if sub == 0 {
                    let cnt = data[0];
                    if cnt == 0 {
                        pdo_map.pending_upload_count = None;
                        pdo_map.upload_staged.clear();
                        pdo_map.staged.clear();
                        pdo_map.committed_count = Some(0);
                        pdo_map.explicitly_written = false;
                    } else if dir == SdoTransferDir::Download {
                        pdo_map.pending_upload_count = None;
                        pdo_map.upload_staged.clear();
                        pdo_map.committed_count = Some(cnt);
                        pdo_map.explicitly_written = true;
                    } else if pdo_map.committed_count.is_none()
                        && (1..=cnt).all(|k| pdo_map.staged.contains_key(&k))
                    {
                        // Reverse-order initial SDO Upload (`sub1..=cnt` read before `sub0`)
                        pdo_map.pending_upload_count = None;
                        pdo_map.upload_staged.clear();
                        pdo_map.committed_count = Some(cnt);
                    } else {
                        // Standard SDO Upload (`sub0` read first; commit once `sub1..=cnt` arrive)
                        pdo_map.pending_upload_count = Some(cnt);
                        pdo_map.upload_staged.clear();
                    }
                } else if data.len() >= 4 {
                    let raw = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                    let entry = MappedEntryRaw {
                        entry_index: ((raw >> 16) & 0xFFFF) as u16,
                        entry_subindex: ((raw >> 8) & 0xFF) as u8,
                        bit_length: (raw & 0xFF) as u16,
                    };
                    if dir == SdoTransferDir::Upload {
                        if let Some(pend) = pdo_map.pending_upload_count {
                            pdo_map.upload_staged.insert(sub, entry);
                            if (1..=pend).all(|k| pdo_map.upload_staged.contains_key(&k)) {
                                pdo_map.staged = std::mem::take(&mut pdo_map.upload_staged);
                                pdo_map.committed_count = Some(pend);
                                pdo_map.explicitly_written = false;
                                pdo_map.pending_upload_count = None;
                            }
                        } else {
                            pdo_map.staged.insert(sub, entry);
                        }
                    } else {
                        pdo_map.pending_upload_count = None;
                        pdo_map.upload_staged.clear();
                        pdo_map.staged.insert(sub, entry);
                    }
                }

                if is_rx {
                    recompute_rx = true;
                } else {
                    recompute_tx = true;
                }
            }
            // SM2 RxPDO Assignment (`0x1C12`) & SM3 TxPDO Assignment (`0x1C13`)
            0x1C12 | 0x1C13 => {
                let is_rx = idx == 0x1C12;
                let assign = if is_rx {
                    &mut self.slaves[slot].sm2_assign
                } else {
                    &mut self.slaves[slot].sm3_assign
                };

                if ca {
                    let (cnt, start) = parse_ca_header(sub, data, 2);
                    assign.pending_upload_count = None;
                    assign.upload_staged.clear();
                    assign.staged.clear();
                    let mut list = Vec::with_capacity(cnt);
                    for i in 0..cnt {
                        let off = start + i * 2;
                        if off + 2 <= data.len() {
                            let pdo_idx = u16::from_le_bytes([data[off], data[off + 1]]);
                            assign.staged.insert((i + 1) as u8, pdo_idx);
                            list.push(pdo_idx);
                        }
                    }
                    assign.committed = Some(list);
                } else if sub == 0 {
                    let cnt = data[0];
                    if cnt == 0 {
                        assign.pending_upload_count = None;
                        assign.upload_staged.clear();
                        assign.staged.clear();
                        assign.committed = Some(Vec::new());
                    } else if dir == SdoTransferDir::Download
                        || (assign.committed.is_none()
                            && (1..=cnt).all(|k| assign.staged.contains_key(&k)))
                    {
                        assign.pending_upload_count = None;
                        assign.upload_staged.clear();
                        let mut list = Vec::with_capacity(cnt as usize);
                        for k in 1..=cnt {
                            if let Some(&pdo_idx) = assign.staged.get(&k) {
                                list.push(pdo_idx);
                            }
                        }
                        assign.committed = Some(list);
                    } else {
                        // SDO Upload read `sub0` first; commit once `sub1..=cnt` are read
                        assign.pending_upload_count = Some(cnt);
                        assign.upload_staged.clear();
                    }
                } else if data.len() >= 2 {
                    let pdo_idx = u16::from_le_bytes([data[0], data[1]]);
                    if dir == SdoTransferDir::Upload {
                        if let Some(pend) = assign.pending_upload_count {
                            assign.upload_staged.insert(sub, pdo_idx);
                            if (1..=pend).all(|k| assign.upload_staged.contains_key(&k)) {
                                let mut list = Vec::with_capacity(pend as usize);
                                for k in 1..=pend {
                                    if let Some(&p) = assign.upload_staged.get(&k) {
                                        list.push(p);
                                    }
                                }
                                assign.staged = std::mem::take(&mut assign.upload_staged);
                                assign.committed = Some(list);
                                assign.pending_upload_count = None;
                            }
                        } else {
                            assign.staged.insert(sub, pdo_idx);
                        }
                    } else {
                        assign.pending_upload_count = None;
                        assign.upload_staged.clear();
                        assign.staged.insert(sub, pdo_idx);
                    }
                }

                if is_rx {
                    recompute_rx = true;
                } else {
                    recompute_tx = true;
                }
            }
            _ => {}
        }

        if rebuild_mdp {
            if let Some(cat) = self.options.xml_catalog.clone() {
                let st = &self.slaves[slot];
                if let Some(base_prof) =
                    catalog_base_profile(&cat, st, self.options.xml_device.as_deref())
                {
                    let clean_base = base_prof.clean_base_for_mdp();
                    let mut ov = clean_base.clone();
                    if let Some(ref idents) = st.mdp_committed_idents {
                        for (slot_i, &ident) in idents.iter().enumerate() {
                            if ident == 0 {
                                continue;
                            }
                            if let Some(mdef) = clean_base
                                .modules
                                .iter()
                                .find(|m| m.module_ident == Some(ident))
                            {
                                let (rxs, txs, objs) =
                                    clean_base.instantiate_module_at_slot(slot_i, mdef);
                                for (k, o) in objs {
                                    ov.objects.insert(k, o);
                                }
                                for p in rxs {
                                    ov.rx_pdos.insert(p.pdo_index, p);
                                }
                                for p in txs {
                                    ov.tx_pdos.insert(p.pdo_index, p);
                                }
                            }
                        }
                    }
                    self.slaves[slot].mdp_profile_override = Some(ov);
                    recompute_rx = true;
                    recompute_tx = true;
                }
            }
        }

        if recompute_rx || recompute_tx {
            let Some(cat) = self.options.xml_catalog.clone() else {
                return;
            };
            let Some(prof) = self.profile_for_slot(&cat, slot).cloned() else {
                return;
            };
            if recompute_rx {
                self.rebuild_slave_pdo_bank(slot, &prof, PdoDirection::RxPdo);
            }
            if recompute_tx {
                self.rebuild_slave_pdo_bank(slot, &prof, PdoDirection::TxPdo);
            }
        }
    }

    fn rebuild_slave_pdo_bank(
        &mut self,
        slot: usize,
        prof: &XmlDeviceProfile,
        direction: PdoDirection,
    ) {
        let st = &mut self.slaves[slot];
        let (assign, dyn_pdos, xml_pdos) = match direction {
            PdoDirection::RxPdo => (&st.sm2_assign, &st.dynamic_rx_pdos, &prof.rx_pdos),
            PdoDirection::TxPdo => (&st.sm3_assign, &st.dynamic_tx_pdos, &prof.tx_pdos),
        };

        let assigned_list: Vec<u16> = if let Some(ref committed) = assign.committed {
            if committed.is_empty() {
                // `sub0 = 0` explicitly cleared PDO assignment -> unconfigured!
                match direction {
                    PdoDirection::RxPdo => st.rx_active = None,
                    PdoDirection::TxPdo => st.tx_active = None,
                }
                return;
            }
            committed.clone()
        } else {
            // `0x1C12`/`0x1C13` was NOT touched yet in the trace, so check if one or more
            // `0x16xx`/`0x1Axx` PDO mappings were explicitly WRITTEN via SDO Download
            // (`explicitly_written && committed_count > 0`) — never merely read via SDO Upload!
            let committed_dyn: Vec<u16> = dyn_pdos
                .iter()
                .filter_map(|(&pidx, dm)| {
                    (dm.explicitly_written && dm.committed_count.is_some_and(|c| c > 0))
                        .then_some(pidx)
                })
                .collect();
            if committed_dyn.is_empty() {
                match direction {
                    PdoDirection::RxPdo => st.rx_active = None,
                    PdoDirection::TxPdo => st.tx_active = None,
                }
                return;
            }
            // Prefer XML default-SM order if XML defines default SM, else committed order
            let xml_sm_pdos: Vec<u16> = xml_pdos
                .values()
                .filter(|p| p.default_sm.is_some() && committed_dyn.contains(&p.pdo_index))
                .map(|p| p.pdo_index)
                .collect();
            if !xml_sm_pdos.is_empty() {
                xml_sm_pdos
            } else {
                committed_dyn
            }
        };

        let compiled = Self::compile_pdo_bank(prof, direction, &assigned_list, dyn_pdos);
        match direction {
            PdoDirection::RxPdo => st.rx_active = compiled,
            PdoDirection::TxPdo => st.tx_active = compiled,
        }
    }

    fn compile_pdo_bank(
        prof: &XmlDeviceProfile,
        direction: PdoDirection,
        assigned_pdos: &[u16],
        dyn_pdos: &BTreeMap<u16, DynamicPdoMap>,
    ) -> Option<ActivePdoBank> {
        if assigned_pdos.is_empty() {
            return None;
        }
        let xml_map = match direction {
            PdoDirection::RxPdo => &prof.rx_pdos,
            PdoDirection::TxPdo => &prof.tx_pdos,
        };
        let mut fields = Vec::new();
        let mut bit_cursor = 0usize;
        let mut first_eni_off = None;

        for &pdo_idx in assigned_pdos {
            let xpdo_opt = xml_map.get(&pdo_idx);
            if let Some(dm) = dyn_pdos.get(&pdo_idx) {
                match dm.committed_count {
                    Some(0) => return None, // Currently cleared for editing!
                    Some(cnt)
                        if dm.explicitly_written
                            || (1..=cnt).all(|k| dm.staged.contains_key(&k)) =>
                    {
                        if first_eni_off.is_none() {
                            first_eni_off = xpdo_opt.and_then(|xp| xp.eni_bit_offset);
                        }
                        for k in 1..=cnt {
                            let resolved = if let Some(raw_e) = dm.staged.get(&k) {
                                prof.resolve_pdo_entry(
                                    raw_e.entry_index,
                                    raw_e.entry_subindex,
                                    raw_e.bit_length,
                                )
                            } else {
                                xpdo_opt
                                    .and_then(|xp| xp.entries.get((k - 1) as usize))?
                                    .clone()
                            };
                            let blen = resolved.bit_length as usize;
                            if resolved.entry_index != 0 && blen > 0 {
                                fields.push(ResolvedPdoField {
                                    pdo_index: pdo_idx,
                                    rel_bit_offset: bit_cursor,
                                    entry: resolved,
                                });
                            }
                            bit_cursor += blen;
                        }
                        continue;
                    }
                    _ => {}
                }
            }

            // Fallback to candidate PDO definition in XML (`<RxPdo>` / `<TxPdo>` / OD `0x16xx`/`0x1Axx`)
            let xpdo = xpdo_opt?;
            if first_eni_off.is_none() {
                first_eni_off = xpdo.eni_bit_offset;
            }
            for entry in &xpdo.entries {
                let blen = entry.bit_length as usize;
                if entry.entry_index != 0 && blen > 0 {
                    fields.push(ResolvedPdoField {
                        pdo_index: pdo_idx,
                        rel_bit_offset: bit_cursor,
                        entry: entry.clone(),
                    });
                }
                bit_cursor += blen;
            }
        }

        (bit_cursor > 0 && !fields.is_empty()).then_some(ActivePdoBank {
            direction,
            assigned_pdos: assigned_pdos.to_vec(),
            fields,
            total_bits: bit_cursor,
            eni_bit_offset: first_eni_off,
        })
    }

    fn try_decode_configured_pdo(
        &self,
        sub_i: usize,
        slot_opt: Option<usize>,
        frame: &mut DissectedFrame,
    ) {
        let dg = &frame.datagrams[sub_i];
        if dg.raw_data.is_empty() {
            return;
        }
        let Some(cmd) = EcatCmd::from_code(dg.cmd) else {
            return;
        };

        // Case A: CoE PDO over Mailbox (`service == 0x04` TxPDO or `0x05` RxPDO)
        if let Some(mbx) = &dg.mailbox {
            if mbx.mbx_type == 0x03 {
                let svc = mbx.protocol["service_code"].as_u64().unwrap_or(0);
                if matches!(svc, 4 | 5) && dg.raw_data.len() > 8 {
                    if let Some(slot) = slot_opt {
                        let bank = if svc == 4 {
                            self.slaves[slot].tx_active.as_ref()
                        } else {
                            self.slaves[slot].rx_active.as_ref()
                        };
                        if let Some(b) = bank {
                            let pdo_bytes = &dg.raw_data[8..];
                            let mut out = Vec::new();
                            Self::extract_bank_fields(
                                pdo_bytes,
                                0,
                                b,
                                &self.slaves[slot].label(),
                                sub_i,
                                &mut frame.wireshark_fields,
                                &mut out,
                            );
                            if !out.is_empty() {
                                frame.datagrams[sub_i].pdo_fields = Some(out);
                            }
                        }
                    }
                }
            }
            return;
        }

        // Case B: Physical Process Data SyncManager Addressing (`APWR`/`FPWR` to SM2, `APRD`/`FPRD` to SM3, `APRW`/`FPRW`/`BRW`)
        if !cmd.is_logical() {
            let resolved_slot = slot_opt.or_else(|| (self.slaves.len() == 1).then_some(0));
            let (Some(slot), Some(ado)) = (resolved_slot, dg.ado) else {
                return;
            };
            if ado < 0x1000 || dg.register_decode.is_some() {
                return;
            }
            let st = &self.slaves[slot];
            let is_write = matches!(cmd, EcatCmd::Apwr | EcatCmd::Fpwr | EcatCmd::Bwr);
            let is_read = matches!(cmd, EcatCmd::Aprd | EcatCmd::Fprd | EcatCmd::Brd) && dg.wkc > 0;
            let is_rw = matches!(cmd, EcatCmd::Aprw | EcatCmd::Fprw | EcatCmd::Brw);
            if !is_write && !is_read && !is_rw {
                return;
            }

            let matches_sm = |want_write: bool, default_addr: u16| -> bool {
                if st.sm_regs.iter().any(|sm| {
                    sm.enabled
                        && !sm.is_mailbox
                        && sm.direction_write == want_write
                        && sm.phys_start == ado
                }) {
                    return true;
                }
                if let Some(cat) = &self.options.xml_catalog {
                    if let Some(prof) = self.profile_for_slot(cat, slot) {
                        if prof.sync_managers.iter().any(|sm| {
                            sm.start_address == Some(ado)
                                && ((want_write && sm.role.eq_ignore_ascii_case("Outputs"))
                                    || (!want_write && sm.role.eq_ignore_ascii_case("Inputs")))
                        }) {
                            return true;
                        }
                    }
                }
                ado == default_addr
            };

            let bank = if is_write && matches_sm(true, 0x1100) {
                st.rx_active.as_ref()
            } else if is_read && (matches_sm(false, 0x1400) || matches_sm(false, 0x1180)) {
                st.tx_active.as_ref()
            } else if is_rw {
                if dg.wkc == 0 {
                    matches_sm(true, 0x1100)
                        .then_some(st.rx_active.as_ref())
                        .flatten()
                } else if matches_sm(false, 0x1400) || matches_sm(false, 0x1180) {
                    st.tx_active.as_ref()
                } else if matches_sm(true, 0x1100) {
                    if dg.wkc >= 2 && st.tx_active.is_some() {
                        st.tx_active.as_ref()
                    } else {
                        st.rx_active.as_ref()
                    }
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(b) = bank {
                let mut out = Vec::new();
                Self::extract_bank_fields(
                    &frame.datagrams[sub_i].raw_data,
                    0,
                    b,
                    &st.label(),
                    sub_i,
                    &mut frame.wireshark_fields,
                    &mut out,
                );
                if !out.is_empty() {
                    frame.datagrams[sub_i].pdo_fields = Some(out);
                }
            }
            return;
        }

        // Case C: Logical Process Data Addressing (`LRD`, `LWR`, `LRW`)
        let Some(lad_str) = &dg.logical_addr else {
            return;
        };
        let lad = u32::from_str_radix(lad_str.trim_start_matches("0x"), 16).unwrap_or(0);
        let dlen = dg.raw_data.len();
        let payload = frame.datagrams[sub_i].raw_data.clone();
        let wkc = dg.wkc;

        // C.1: FMMU-mapped multi-slave logical windows (when FMMU config frames were seen)
        let any_fmmu = self.slaves.iter().any(|s| s.has_active_fmmu);
        if any_fmmu {
            let mut out = Vec::new();
            let lad_bit_lo = (lad as u64) * 8;
            let lad_bit_hi = lad_bit_lo + (dlen as u64) * 8;
            // Detect logical bit ranges overwritten by Read-FMMUs when `LRW` returns (`wkc > 0`)
            let mut read_covered_bit_ranges: Vec<(u64, u64)> = Vec::new();
            if cmd == EcatCmd::Lrw && wkc > 0 {
                for s in &self.slaves {
                    for f in &s.fmmu_regs {
                        if f.active && f.read_enable {
                            let r_lo = (f.log_start as u64) * 8 + (f.log_start_bit as u64);
                            let r_hi = r_lo + (f.total_bits() as u64);
                            if r_hi > r_lo {
                                read_covered_bit_ranges.push((r_lo, r_hi));
                            }
                        }
                    }
                }
            }

            for s in &self.slaves {
                for f in &s.fmmu_regs {
                    if !f.active {
                        continue;
                    }
                    let f_bit_lo = (f.log_start as u64) * 8 + (f.log_start_bit as u64);
                    let f_bit_hi = f_bit_lo + (f.total_bits() as u64);
                    if f_bit_hi <= lad_bit_lo || f_bit_lo >= lad_bit_hi {
                        continue;
                    }

                    // Determine whether this FMMU window carries valid RxPDO or TxPDO in this frame
                    let bank_and_skip: Option<(&ActivePdoBank, usize)> = match cmd {
                        EcatCmd::Lwr => f
                            .write_enable
                            .then(|| {
                                let skip = f.maps_process_data(&s.sm_regs, true)?;
                                Some((s.rx_active.as_ref()?, skip))
                            })
                            .flatten(),
                        EcatCmd::Lrd => (f.read_enable
                            && (wkc > 0 || payload.iter().any(|&b| b != 0)))
                        .then(|| {
                            let skip = f.maps_process_data(&s.sm_regs, false)?;
                            Some((s.tx_active.as_ref()?, skip))
                        })
                        .flatten(),
                        EcatCmd::Lrw => {
                            if wkc == 0 {
                                // Outgoing Master -> Slaves frame carries RxPDO in write-enabled FMMUs
                                f.write_enable
                                    .then(|| {
                                        let skip = f.maps_process_data(&s.sm_regs, true)?;
                                        Some((s.rx_active.as_ref()?, skip))
                                    })
                                    .flatten()
                            } else if f.read_enable && s.tx_active.is_some() {
                                // Returning Slaves -> Master frame carries TxPDO in read-enabled FMMUs
                                s.tx_active
                                    .as_ref()
                                    .zip(f.maps_process_data(&s.sm_regs, false))
                            } else if f.write_enable && !f.read_enable {
                                // Non-overlapping write-only FMMU bit range still carries Master's RxPDO!
                                let overlapped = read_covered_bit_ranges
                                    .iter()
                                    .any(|&(r_lo, r_hi)| f_bit_lo < r_hi && f_bit_hi > r_lo);
                                (!overlapped)
                                    .then(|| {
                                        let skip = f.maps_process_data(&s.sm_regs, true)?;
                                        Some((s.rx_active.as_ref()?, skip))
                                    })
                                    .flatten()
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };

                    if let Some((bank, raw_skip_bits)) = bank_and_skip {
                        let (base_bit, eff_skip, win_bits) = if f_bit_lo >= lad_bit_lo {
                            let b_bit = (f_bit_lo - lad_bit_lo) as usize;
                            let avail = (lad_bit_hi - f_bit_lo) as usize;
                            (b_bit, raw_skip_bits, f.total_bits().min(avail))
                        } else {
                            let delta = (lad_bit_lo - f_bit_lo) as usize;
                            let avail = (f_bit_hi - lad_bit_lo) as usize;
                            (0usize, raw_skip_bits + delta, avail.min(dlen * 8))
                        };
                        Self::extract_bank_fields_sliced(
                            &payload,
                            base_bit,
                            eff_skip,
                            Some(win_bits),
                            bank,
                            &s.label(),
                            sub_i,
                            &mut frame.wireshark_fields,
                            &mut out,
                        );
                    }
                }
            }

            if !out.is_empty() {
                frame.datagrams[sub_i].pdo_fields = Some(out);
            }
            return;
        }

        // C.2: Logical Process Data fallback when FMMU register writes were not in the capture
        //      (e.g. capture started in PRE-OP with CoE SDO PDO configuration followed by LRW/LWR/LRD,
        //       or ENI `<ProcessData>` bit offsets are present).
        let mut out = Vec::new();
        let mut rx_bit_cursor = 0usize;
        let mut tx_bit_cursor = 0usize;

        let total_rx_bytes: usize = self
            .slaves
            .iter()
            .filter_map(|s| s.rx_active.as_ref().map(|b| b.total_bytes()))
            .sum();
        let total_tx_bytes: usize = self
            .slaves
            .iter()
            .filter_map(|s| s.tx_active.as_ref().map(|b| b.total_bytes()))
            .sum();
        let split_lrw = cmd == EcatCmd::Lrw
            && wkc > 0
            && total_rx_bytes > 0
            && total_tx_bytes > 0
            && dlen == total_rx_bytes + total_tx_bytes;

        for s in &self.slaves {
            let decode_rx = match cmd {
                EcatCmd::Lwr => true,
                EcatCmd::Lrd => false,
                EcatCmd::Lrw => wkc == 0 || split_lrw || s.tx_active.is_none(),
                _ => false,
            };
            let decode_tx = match cmd {
                EcatCmd::Lwr => false,
                EcatCmd::Lrd => wkc > 0 || payload.iter().any(|&b| b != 0),
                EcatCmd::Lrw => wkc > 0 && s.tx_active.is_some(),
                _ => false,
            };

            if decode_rx {
                if let Some(rx_b) = &s.rx_active {
                    let bit_off = rx_b.eni_bit_offset.unwrap_or(rx_bit_cursor);
                    if bit_off + rx_b.total_bits <= payload.len() * 8 {
                        Self::extract_bank_fields(
                            &payload,
                            bit_off,
                            rx_b,
                            &s.label(),
                            sub_i,
                            &mut frame.wireshark_fields,
                            &mut out,
                        );
                    }
                    rx_bit_cursor = bit_off + rx_b.total_bytes() * 8;
                }
            }
            if decode_tx {
                if let Some(tx_b) = &s.tx_active {
                    let default_tx_base = if split_lrw {
                        total_rx_bytes * 8 + tx_bit_cursor
                    } else {
                        tx_bit_cursor
                    };
                    let bit_off = tx_b.eni_bit_offset.unwrap_or(default_tx_base);
                    if bit_off + tx_b.total_bits <= payload.len() * 8 {
                        Self::extract_bank_fields(
                            &payload,
                            bit_off,
                            tx_b,
                            &s.label(),
                            sub_i,
                            &mut frame.wireshark_fields,
                            &mut out,
                        );
                    }
                    tx_bit_cursor += tx_b.total_bytes() * 8;
                }
            }
        }

        if !out.is_empty() {
            frame.datagrams[sub_i].pdo_fields = Some(out);
        }
    }

    fn extract_bank_fields(
        payload: &[u8],
        base_bit_offset: usize,
        bank: &ActivePdoBank,
        slave_label: &str,
        sub_i: usize,
        ws: &mut BTreeMap<String, Value>,
        out: &mut Vec<Value>,
    ) {
        Self::extract_bank_fields_sliced(
            payload,
            base_bit_offset,
            0,
            None,
            bank,
            slave_label,
            sub_i,
            ws,
            out,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn extract_bank_fields_sliced(
        payload: &[u8],
        base_bit_offset: usize,
        bank_skip_bits: usize,
        window_bits: Option<usize>,
        bank: &ActivePdoBank,
        slave_label: &str,
        sub_i: usize,
        ws: &mut BTreeMap<String, Value>,
        out: &mut Vec<Value>,
    ) {
        if bank.assigned_pdos.is_empty() {
            return;
        }
        for rf in &bank.fields {
            if rf.rel_bit_offset < bank_skip_bits {
                continue;
            }
            let rel_in_win = rf.rel_bit_offset - bank_skip_bits;
            let bit_len = rf.entry.bit_length as u32;
            if let Some(wb) = window_bits {
                if rel_in_win + (bit_len as usize) > wb {
                    continue;
                }
            }
            let bit_off = base_bit_offset + rel_in_win;
            if bit_off + (bit_len as usize) > payload.len() * 8 {
                continue;
            }
            let Some((val, enum_txt)) = decode_xml_scalar_ext(
                payload,
                bit_off,
                bit_len,
                rf.entry.wire_type,
                Some(&rf.entry.data_type),
                &rf.entry.enum_values,
            ) else {
                continue;
            };
            let raw_slice = extract_bits_le(payload, bit_off, bit_len as usize).unwrap_or_default();
            let idx_sub_key = format!(
                "0x{:04x}:{:02x}",
                rf.entry.entry_index, rf.entry.entry_subindex
            );
            let sanitized_name = sanitize_pdo_selector(&rf.entry.name);
            let slave_key = sanitize_pdo_selector(slave_label);
            let leaf_alias = rf
                .entry
                .name
                .rsplit_once('.')
                .map(|(_, leaf)| sanitize_pdo_selector(leaf))
                .filter(|l| {
                    !l.is_empty()
                        && l != &sanitized_name
                        && !l.to_ascii_lowercase().starts_with("subindex")
                });

            // Emit top-level (first-occurrence), `ecat[sub_i].pdo.*`, `ecat.sub{1..10}.pdo.*`,
            // and slave-qualified `ecat.pdo.{slave_key}.*` / `ecat[sub_i].pdo.{slave_key}.*`
            for selector_leaf in [
                Some(idx_sub_key.as_str()),
                Some(sanitized_name.as_str()),
                leaf_alias.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if selector_leaf.is_empty() {
                    continue;
                }
                ws.entry(format!("ecat.pdo.{selector_leaf}"))
                    .or_insert_with(|| val.clone());
                ws.entry(format!("ecat[{sub_i}].pdo.{selector_leaf}"))
                    .or_insert_with(|| val.clone());
                if sub_i < 10 {
                    ws.entry(format!("ecat.sub{}.pdo.{selector_leaf}", sub_i + 1))
                        .or_insert_with(|| val.clone());
                }
                if !slave_key.is_empty() {
                    ws.insert(format!("ecat.pdo.{slave_key}.{selector_leaf}"), val.clone());
                    ws.insert(
                        format!("ecat[{sub_i}].pdo.{slave_key}.{selector_leaf}"),
                        val.clone(),
                    );
                }
                if let Some(ref et) = enum_txt {
                    ws.entry(format!("ecat.pdo.{selector_leaf}.enum"))
                        .or_insert_with(|| json!(et));
                    ws.entry(format!("ecat[{sub_i}].pdo.{selector_leaf}.enum"))
                        .or_insert_with(|| json!(et));
                    if !slave_key.is_empty() {
                        ws.insert(
                            format!("ecat.pdo.{slave_key}.{selector_leaf}.enum"),
                            json!(et),
                        );
                        ws.insert(
                            format!("ecat[{sub_i}].pdo.{slave_key}.{selector_leaf}.enum"),
                            json!(et),
                        );
                    }
                }
                if let Some(ref u) = rf.entry.unit {
                    ws.entry(format!("ecat.pdo.{selector_leaf}.unit"))
                        .or_insert_with(|| json!(u));
                    ws.entry(format!("ecat[{sub_i}].pdo.{selector_leaf}.unit"))
                        .or_insert_with(|| json!(u));
                    if !slave_key.is_empty() {
                        ws.insert(
                            format!("ecat.pdo.{slave_key}.{selector_leaf}.unit"),
                            json!(u),
                        );
                        ws.insert(
                            format!("ecat[{sub_i}].pdo.{slave_key}.{selector_leaf}.unit"),
                            json!(u),
                        );
                    }
                }
            }

            let mut item = serde_json::Map::new();
            item.insert("name".into(), json!(rf.entry.name));
            item.insert("entry".into(), json!(idx_sub_key));
            item.insert(
                "index".into(),
                json!(format!("0x{:04x}", rf.entry.entry_index)),
            );
            item.insert("subindex".into(), json!(rf.entry.entry_subindex));
            item.insert("pdo_index".into(), json!(format!("0x{:04x}", rf.pdo_index)));
            item.insert("direction".into(), json!(bank.direction.label()));
            item.insert("slave".into(), json!(slave_label));
            item.insert("type".into(), json!(rf.entry.data_type));
            if let Some(ref u) = rf.entry.unit {
                item.insert("unit".into(), json!(u));
            }
            item.insert("bit_offset".into(), json!(bit_off));
            item.insert("bit_len".into(), json!(bit_len));
            item.insert("value".into(), val);
            item.insert("raw_hex".into(), json!(format_hex(&raw_slice)));
            if let Some(et) = enum_txt {
                item.insert("enum_text".into(), json!(et));
            }
            out.push(Value::Object(item));
        }
    }
}

fn catalog_base_profile<'a>(
    catalog: &'a XmlCatalog,
    st: &SlaveRuntime,
    device_hint: Option<&str>,
) -> Option<&'a XmlDeviceProfile> {
    catalog.match_slave_ext(
        st.station_addr,
        st.topo_pos,
        st.vendor_id,
        st.product_code,
        st.revision_no,
        device_hint,
    )
}

fn coe_mailbox_service_code(data: &[u8]) -> Option<u8> {
    if data.len() < 9 || (data[5] & 0x0F) != 0x03 {
        return None;
    }
    let len = u16::from_le_bytes([data[0], data[1]]) as usize;
    if len < 3 {
        return None;
    }
    let coe_hdr = u16::from_le_bytes([data[6], data[7]]);
    Some(((coe_hdr >> 12) & 0x0F) as u8)
}

fn sanitize_pdo_selector(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_underscore = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == ':' || ch == '-' {
            out.push(ch);
            prev_underscore = false;
        } else if !prev_underscore && !out.is_empty() {
            out.push('_');
            prev_underscore = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}
