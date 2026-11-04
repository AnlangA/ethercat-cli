use std::collections::BTreeMap;
use std::sync::Arc;

use ethercat_wire::pdo_codec::PdoLayout;
use serde::Serialize;
use serde_json::Value;

use crate::xml::XmlCatalog;

/// Configuration options for stateless (`dissect_frame`) or stateful (`DissectSession`) dissection.
#[derive(Debug, Clone, Default)]
pub struct DissectOptions {
    /// Treat input bytes as starting directly at the 2-byte EtherCAT frame header (`ecatf`)
    /// without an outer Ethernet II / VLAN / UDP / TCP header.
    pub bare_ecat: bool,
    /// Force physical datagram payloads at `ADO >= 0x1000` with `len >= 6` to be dissected as
    /// EtherCAT Mailbox frames even if heuristic header checks are ambiguous.
    pub force_mailbox: bool,
    /// Optional explicit static PDO layout override (`name:type@bit_offset[:bit_len],...`).
    /// When set, applies unconditionally to logical process-data payloads.
    pub pdo_layout: Option<PdoLayout>,
    /// Optional loaded XML catalog (ESI `<EtherCATInfo>`, OD `<EtherCATDict>`, or ENI `<EtherCATConfig>`).
    /// Enables XML Object Dictionary SDO decoding and (in `DissectSession`) stateful temporal PDO decoding.
    pub xml_catalog: Option<Arc<XmlCatalog>>,
    /// Optional device selector (`Name`, `Type`, or `ProductCode` hex/dec) when `xml_catalog`
    /// contains multiple `<Device>` definitions.
    pub xml_device: Option<String>,
}

/// Beckhoff ET2000 EtherCAT Switch Link (`esl`) 16-byte hardware timestamp/status tag.
#[derive(Debug, Clone, Serialize)]
pub struct DissectedEsl {
    pub position: &'static str,
    pub flags: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u8>,
    pub crc_error: bool,
    pub align_error: bool,
    pub timestamp_enabled: bool,
    pub tlv_error: bool,
    pub timestamp_ns: u64,
}

/// Outer L2/L4 encapsulation metadata.
#[derive(Debug, Clone, Serialize)]
pub struct DissectedEthernet {
    pub dst_mac: String,
    pub src_mac: String,
    pub src_locally_administered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vlan_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outer_vlan_id: Option<u16>,
    pub ethertype: String,
    pub encapsulation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src_port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dst_port: Option<u16>,
    #[serde(skip)]
    pub tcp_seq: Option<u32>,
    #[serde(skip)]
    pub tcp_flags: Option<u8>,
}

/// Strongly-typed SDO transaction extracted during CoE or CoE-over-AoE dissection.
/// Used cleanly by `engine::sdo` and `engine::session` without JSON re-parsing.
#[derive(Debug, Clone)]
pub enum SdoEventKind {
    InitiateDownload {
        index: u16,
        subindex: u8,
        complete_access: bool,
        expedited: bool,
        indicated_size: Option<usize>,
        inline_data: Vec<u8>,
    },
    DownloadSegmentReq {
        toggle: bool,
        last_segment: bool,
        seg_data: Vec<u8>,
    },
    DownloadSegmentRes {
        toggle: bool,
    },
    InitiateUploadReq {
        index: u16,
        subindex: u8,
        complete_access: bool,
    },
    InitiateUploadRes {
        index: u16,
        subindex: u8,
        complete_access: bool,
        expedited: bool,
        indicated_size: Option<usize>,
        inline_data: Vec<u8>,
    },
    UploadSegmentReq {
        toggle: bool,
    },
    UploadSegmentRes {
        toggle: bool,
        last_segment: bool,
        seg_data: Vec<u8>,
    },
    InitiateBlockDownload {
        index: u16,
        subindex: u8,
        complete_access: bool,
        crc_support: bool,
        indicated_size: Option<usize>,
    },
    InitiateBlockDownloadRes {
        index: u16,
        subindex: u8,
        crc_support: bool,
        blksize: u8,
    },
    BlockDownloadAck {
        ackseq: u8,
        blksize: u8,
    },
    EndBlockDownload {
        unused_bytes: u8,
        crc: u16,
    },
    EndBlockDownloadRes,
    InitiateBlockUploadReq {
        index: u16,
        subindex: u8,
        complete_access: bool,
        crc_support: bool,
        blksize: u8,
        pst: u8,
    },
    InitiateBlockUploadRes {
        index: u16,
        subindex: u8,
        crc_support: bool,
        indicated_size: Option<usize>,
    },
    StartBlockUpload,
    BlockUploadAck {
        ackseq: u8,
        blksize: u8,
    },
    EndBlockUpload {
        unused_bytes: u8,
        crc: u16,
    },
    EndBlockUploadRes,
    BlockSubblock {
        is_download: bool,
        seq_no: u8,
        last_subblock: bool,
        data: Vec<u8>,
    },
    Abort {
        index: u16,
        subindex: u8,
        abort_code: u32,
    },
    AoeReadReq {
        target_net_id: String,
        target_port: u16,
        invoke_id: u32,
        index: u16,
        subindex: u8,
        complete_access: bool,
    },
    AoeReadRes {
        sender_net_id: String,
        sender_port: u16,
        invoke_id: u32,
        ads_result: u32,
        data: Vec<u8>,
    },
    AoeWriteReq {
        target_net_id: String,
        target_port: u16,
        invoke_id: u32,
        index: u16,
        subindex: u8,
        complete_access: bool,
        data: Vec<u8>,
    },
    AoeWriteRes {
        sender_net_id: String,
        sender_port: u16,
        invoke_id: u32,
        ads_result: u32,
    },
    AoeReadWriteReq {
        target_net_id: String,
        target_port: u16,
        invoke_id: u32,
        index: u16,
        subindex: u8,
        complete_access: bool,
        read_length: usize,
        write_data: Vec<u8>,
    },
}

/// Extracted CoE SDO Information (`service == 0x08`, `opcode == 0x02 | 0x04 | 0x06`) fragment metadata.
#[derive(Debug, Clone)]
pub struct SdoInfoFragmentInfo {
    pub number: u16,
    pub opcode: u8,
    pub incomplete: bool,
    pub fragments_left: u16,
    pub rest: Vec<u8>,
}

/// Extracted EoE Fragment Data (`frame_type == 0x00`) metadata for stateful multi-fragment reassembly.
#[derive(Debug, Clone)]
pub struct EoeFragmentInfo {
    pub port: u8,
    pub last_fragment: bool,
    pub frame_no: u8,
    pub frag_no: u8,
    pub offset_or_size: u8,
    pub data: Vec<u8>,
}

/// Dissected EtherCAT Mailbox PDU (`ecat_mailbox`).
#[derive(Debug, Clone, Serialize)]
pub struct DissectedMailbox {
    pub length: u16,
    pub address: u16,
    pub channel: u8,
    pub priority: u8,
    pub mbx_type: u8,
    pub mbx_type_name: &'static str,
    pub counter: u8,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub malformed: bool,
    pub protocol: Value,
    #[serde(skip)]
    pub sdo_event: Option<SdoEventKind>,
    #[serde(skip)]
    pub sdo_info_fragment: Option<SdoInfoFragmentInfo>,
    #[serde(skip)]
    pub eoe_fragment: Option<EoeFragmentInfo>,
    #[serde(skip)]
    pub foe_wrq_filename: Option<String>,
    #[serde(skip)]
    pub raw_bytes: Vec<u8>,
}

/// XML Object Dictionary enrichment attached to an SDO or SDO Info transaction.
#[derive(Debug, Clone, Serialize)]
pub struct SdoXmlDecode {
    pub index: String,
    pub subindex: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_name: Option<String>,
    pub object_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entry_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enum_text: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subitems: Vec<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pdo_annotations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reassembled_segments: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reassembled_len: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abort_code: Option<String>,
}

/// Dissected EtherCAT DLPDU subframe (`ecat.sub`).
#[derive(Debug, Clone, Serialize)]
pub struct DissectedDatagram {
    pub subframe_index: usize,
    pub cmd: u8,
    pub cmd_mnemonic: String,
    pub cmd_description: String,
    pub idx: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adp: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adp_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_inc_slave_hint: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_slave: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ado_register: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_addr: Option<String>,
    pub length: u16,
    pub reserved: u8,
    pub circulating: bool,
    pub more: bool,
    pub irq: String,
    pub irq_events: Vec<&'static str>,
    pub data_hex: String,
    #[serde(skip)]
    pub raw_data: Vec<u8>,
    pub wkc: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dc_diff: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_decode: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mailbox: Option<DissectedMailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdo_xml: Option<SdoXmlDecode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pdo_fields: Option<Vec<Value>>,
}

/// Complete dissected EtherCAT or standalone AMS/ADS frame.
#[derive(Debug, Clone, Serialize)]
pub struct DissectedFrame {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_index: Option<usize>,
    pub frame_wire_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub esl: Option<DissectedEsl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ethernet: Option<DissectedEthernet>,
    pub ecat_header: Value,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub datagrams: Vec<DissectedDatagram>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_mailbox: Option<DissectedMailbox>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direct_ams: Option<Value>,
    #[serde(skip)]
    pub direct_ams_sdo_event: Option<SdoEventKind>,
    #[serde(skip)]
    pub direct_ams_sdo_events: Vec<(usize, u16, SdoEventKind)>,
    #[serde(skip)]
    pub raw_ams_tcp_segment: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_io: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_variables: Option<Value>,
    pub padding_bytes: usize,
    pub wireshark_fields: BTreeMap<String, Value>,
}
