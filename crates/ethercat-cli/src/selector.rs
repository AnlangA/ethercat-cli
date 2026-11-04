use serde::Serialize;
use serde_json::{json, Map, Value};

use ethercat_wire::error::{CliError, Result};

/// Documentation entry for Wireshark-compatible and domain field selectors (`fields` subcommand).
#[derive(Debug, Clone, Serialize)]
pub struct FieldSelectorDoc {
    pub selector: &'static str,
    pub layer: &'static str,
    pub value_type: &'static str,
    pub description: &'static str,
}

pub const WIRESHARK_FIELD_CATALOG: &[FieldSelectorDoc] = &[
    // L2 Ethernet / VLAN / UDP
    FieldSelectorDoc {
        selector: "eth.dst",
        layer: "Ethernet / L2",
        value_type: "string (MAC)",
        description: "Destination MAC address (e.g. ff:ff:ff:ff:ff:ff)",
    },
    FieldSelectorDoc {
        selector: "eth.src",
        layer: "Ethernet / L2",
        value_type: "string (MAC)",
        description: "Source MAC address (e.g. 01:01:01:01:01:01)",
    },
    FieldSelectorDoc {
        selector: "eth.type",
        layer: "Ethernet / L2",
        value_type: "string (hex)",
        description: "EtherType (0x88a4 for EtherCAT, 0x0800 for UDP/IP EtherCAT)",
    },
    FieldSelectorDoc {
        selector: "vlan.id",
        layer: "Ethernet / 802.1Q",
        value_type: "u16",
        description: "IEEE 802.1Q 12-bit VLAN Identifier when VLAN tag is present",
    },
    FieldSelectorDoc {
        selector: "udp.srcport",
        layer: "UDP/IP EtherCAT",
        value_type: "u16",
        description: "UDP source port when encapsulated in UDP/34980 (0x88a4)",
    },
    FieldSelectorDoc {
        selector: "udp.dstport",
        layer: "UDP/IP EtherCAT",
        value_type: "u16",
        description: "UDP destination port when encapsulated in UDP/34980 (0x88a4)",
    },
    // Beckhoff ET2000 EtherCAT Switch Link (`esl.*`)
    FieldSelectorDoc {
        selector: "esl.port",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "u8",
        description: "Hardware capture port index (0..11) from 16-byte ET2000 ESL prefix/trailer",
    },
    FieldSelectorDoc {
        selector: "esl.flags",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "string (hex u16)",
        description: "Raw 16-bit ESL status/port bitmask word",
    },
    FieldSelectorDoc {
        selector: "esl.crcerror",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "bool",
        description: "Hardware FCS/CRC error flag recorded by ET2000 tap (bit 12, 0x1000)",
    },
    FieldSelectorDoc {
        selector: "esl.alignerror",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "bool",
        description: "Alignment error flag recorded by ET2000 tap (bit 11, 0x0800)",
    },
    FieldSelectorDoc {
        selector: "esl.tsenable",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "bool",
        description: "Hardware timestamp valid/enable flag (bit 13)",
    },
    FieldSelectorDoc {
        selector: "esl.tlverror",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "bool",
        description: "Extended TLV / symbol error flag (bit 8)",
    },
    FieldSelectorDoc {
        selector: "esl.timestamp",
        layer: "Beckhoff ESL (ET2000)",
        value_type: "u64",
        description: "64-bit hardware Start-of-Frame timestamp in nanoseconds",
    },
    // EtherCAT 2-byte Frame Header (Beckhoff `ecatf.*`)
    FieldSelectorDoc {
        selector: "ecatf.length",
        layer: "EtherCAT Frame Header",
        value_type: "u16",
        description: "11-bit EtherCAT frame body byte length",
    },
    FieldSelectorDoc {
        selector: "ecatf.reserved",
        layer: "EtherCAT Frame Header",
        value_type: "u8",
        description: "Reserved bit 11 in 2-byte EtherCAT header",
    },
    FieldSelectorDoc {
        selector: "ecatf.type",
        layer: "EtherCAT Frame Header",
        value_type: "u8",
        description: "4-bit EtherCAT protocol type (0x1=DLPDU, 0x4=NV, 0x5=Mailbox)",
    },
    FieldSelectorDoc {
        selector: "ecatf.type_name",
        layer: "EtherCAT Frame Header",
        value_type: "string",
        description: "Human-readable EtherCAT frame type name",
    },
    // EtherCAT DLPDU Subframe / Datagram (Beckhoff `ecat.*` & indexed `ecat[i].*`)
    FieldSelectorDoc {
        selector: "ecat.cmd",
        layer: "EtherCAT Datagram",
        value_type: "string",
        description: "First subframe command mnemonic (NOP/APRD/APWR/FPRD/FPWR/BRD/BWR/LRD/LWR/LRW/ARMW/FRMW); use ecat[i].cmd for subframe i",
    },
    FieldSelectorDoc {
        selector: "ecat.cmd_code",
        layer: "EtherCAT Datagram",
        value_type: "u8",
        description: "Numeric EtherCAT command byte (0x00..0x0E); use ecat[i].cmd_code for subframe i",
    },
    FieldSelectorDoc {
        selector: "ecat.idx",
        layer: "EtherCAT Datagram",
        value_type: "u8",
        description: "Datagram 8-bit frame/transaction index; use ecat[i].idx for subframe i",
    },
    FieldSelectorDoc {
        selector: "ecat.adp",
        layer: "EtherCAT Datagram",
        value_type: "string (hex u16)",
        description: "16-bit Slave Address Position (auto-increment or configured station address)",
    },
    FieldSelectorDoc {
        selector: "ecat.ado",
        layer: "EtherCAT Datagram",
        value_type: "string (hex u16)",
        description: "16-bit Physical ESC Register / DPRAM Offset Address",
    },
    FieldSelectorDoc {
        selector: "ecat.ado_name",
        layer: "EtherCAT Datagram",
        value_type: "string",
        description: "Symbolic ESC register name resolved from ecat.ado (when known)",
    },
    FieldSelectorDoc {
        selector: "ecat.lad",
        layer: "EtherCAT Datagram",
        value_type: "string (hex u32)",
        description: "32-bit Logical Memory Address (present on LRD/LWR/LRW datagrams)",
    },
    FieldSelectorDoc {
        selector: "ecat.len",
        layer: "EtherCAT Datagram",
        value_type: "u16",
        description: "11-bit datagram payload byte length",
    },
    FieldSelectorDoc {
        selector: "ecat.res",
        layer: "EtherCAT Datagram",
        value_type: "u8",
        description: "3-bit reserved field (bits 11..13 of datagram length/flags word)",
    },
    FieldSelectorDoc {
        selector: "ecat.c",
        layer: "EtherCAT Datagram",
        value_type: "bool",
        description: "Circulating frame flag (bit 14 of length/flags word; alias: ecat.circulating)",
    },
    FieldSelectorDoc {
        selector: "ecat.circulating",
        layer: "EtherCAT Datagram",
        value_type: "bool",
        description: "Circulating frame flag (canonical Wireshark filter alias of ecat.c)",
    },
    FieldSelectorDoc {
        selector: "ecat.m",
        layer: "EtherCAT Datagram",
        value_type: "bool",
        description: "More-datagrams-follow flag (bit 15 of length/flags word; alias: ecat.next)",
    },
    FieldSelectorDoc {
        selector: "ecat.next",
        layer: "EtherCAT Datagram",
        value_type: "bool",
        description: "More-datagrams-follow flag (canonical Wireshark filter alias of ecat.m)",
    },
    FieldSelectorDoc {
        selector: "ecat.irq",
        layer: "EtherCAT Datagram",
        value_type: "string (hex u16)",
        description: "16-bit External Event / Slave Interrupt bitmask",
    },
    FieldSelectorDoc {
        selector: "ecat.data",
        layer: "EtherCAT Datagram",
        value_type: "string (hex)",
        description: "Wireshark 4.6 `ecat.data`: lowercase hex, only when no ESC register is fully covered, minus a recognized mailbox (`ecat[i].data` = full payload)",
    },
    FieldSelectorDoc {
        selector: "ecat.wkc",
        layer: "EtherCAT Datagram",
        value_type: "u16",
        description: "16-bit Working Counter (WKC) at end of subframe; use ecat[i].wkc for subframe i",
    },
    // ESC Register Decoded Fields (`ecat.reg.*` and `ecat[i].reg.*`)
    FieldSelectorDoc {
        selector: "ecat.reg.esc_type",
        layer: "ESC Register",
        value_type: "string (hex u8)",
        description: "ESC chip type decoded from register 0x0000; use ecat[i].reg.* for subframe i",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.station_addr",
        layer: "ESC Register",
        value_type: "string (hex u16)",
        description: "Configured station address decoded from register 0x0010",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.dl_status",
        layer: "ESC Register",
        value_type: "string (hex u16)",
        description: "16-bit DL Status register word decoded from 0x0110",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.al_status",
        layer: "ESC Register",
        value_type: "string (hex u16)",
        description: "16-bit AL Status register word decoded from 0x0130",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.al_state",
        layer: "ESC Register",
        value_type: "string",
        description: "Application Layer state name decoded from register 0x0120 / 0x0130 (INIT/PRE-OP/BOOT/SAFE-OP/OP)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.al_status_code",
        layer: "ESC Register",
        value_type: "string (hex u16)",
        description: "AL Status Code decoded from register 0x0134 (or 6-byte read at 0x0130)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.eep_busy",
        layer: "ESC Register",
        value_type: "bool",
        description: "SII EEPROM busy flag (bit 15 of 0x0502)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.eep_op",
        layer: "ESC Register",
        value_type: "string",
        description: "SII EEPROM command decoded from 0x0502 (NOP/READ/WRITE/RELOAD)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.eep_word_addr",
        layer: "ESC Register",
        value_type: "u32",
        description: "32-bit SII EEPROM word address decoded from 0x0504..0x0507",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.esc_features",
        layer: "ESC Register",
        value_type: "string (hex u16)",
        description: "ESC Features bitmask decoded from 0x0008..0x0009 (also esc_revision, esc_build, fmmu_count, sm_count, ram_size_kb, port_desc)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.rx_err_frame_port0",
        layer: "ESC Register",
        value_type: "u8",
        description: "Port 0 RX frame error counter at 0x0300 (also port0..3 rx_err_phys_port*, fwd_rx_err_port*, lost_link_port*, epu_err_count, pdi_err_count)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.wd_pdata_ok",
        layer: "ESC Register",
        value_type: "bool",
        description: "Process Data Watchdog OK bit decoded from 0x0440 (also wd_divider, wd_time_pdi, wd_time_pdata, wd_status, wd_cnt_pdata, wd_cnt_pdi)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.fmmu0.active",
        layer: "ESC Register",
        value_type: "bool",
        description: "FMMU n activation flag from 0x0600+16*n (also fmmu<n>.log_start, length, phys_start, read, write)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.sm1.mbx_full",
        layer: "ESC Register",
        value_type: "bool",
        description: "SyncManager n mailbox-full bit from 0x0805+8*n (also sm<n>.phys_start, length, ctrl, status, enabled)",
    },
    FieldSelectorDoc {
        selector: "ecat.reg.dc_systime",
        layer: "ESC Register",
        value_type: "u64",
        description: "Distributed Clocks System Time (ns) at 0x0910 (also dc_rx_time_port0..3, dc_sof, dc_sys_offset, dc_sys_delay, dc_sys_diff_ns, dc_sync_act, dc_start0, dc_cycle0, dc_cycle1)",
    },
    // Process Data Object Fields (`ecat.pdo.*`)
    FieldSelectorDoc {
        selector: "ecat.pdo.<field_or_0xXXXX:XX>",
        layer: "PDO Process Data",
        value_type: "typed JSON value",
        description: "Named or CoE-indexed PDO field decoded via --pdo-layout, --sii-pdo, pdo read, or pdo decode",
    },
    // EtherCAT Mailbox & CoE / FoE / SoE / AoE / EoE / VoE (`ecat_mailbox.*` & `ecat_mailbox[i].*`)
    FieldSelectorDoc {
        selector: "ecat_mailbox.length",
        layer: "EtherCAT Mailbox",
        value_type: "u16",
        description: "Mailbox body byte length (excluding 6-byte mailbox header)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.address",
        layer: "EtherCAT Mailbox",
        value_type: "string (hex u16)",
        description: "Mailbox originator/station address",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.type",
        layer: "EtherCAT Mailbox",
        value_type: "u8",
        description: "4-bit Mailbox protocol code (0=ERR, 1=AoE, 2=EoE, 3=CoE, 4=FoE, 5=SoE, 15=VoE)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.type_name",
        layer: "EtherCAT Mailbox",
        value_type: "string",
        description: "Mailbox protocol mnemonic (ERR/AoE/EoE/CoE/FoE/SoE/VoE)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.cnt",
        layer: "EtherCAT Mailbox",
        value_type: "u8",
        description: "3-bit Mailbox sequence counter (1..7)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.service",
        layer: "CoE (CANopen over EtherCAT)",
        value_type: "u8",
        description: "CoE service code (1=Emergency, 2=SDO Req, 3=SDO Res, 4=TxPDO, 5=RxPDO, 8=SDO Info)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.service_name",
        layer: "CoE (CANopen over EtherCAT)",
        value_type: "string",
        description: "CoE service human-readable name",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.cmd",
        layer: "CoE SDO",
        value_type: "string (hex u8)",
        description: "CoE SDO command specifier byte",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.index",
        layer: "CoE SDO",
        value_type: "string (hex u16)",
        description: "CoE Object Dictionary 16-bit Index (e.g. 0x1018, 0x6040)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.subindex",
        layer: "CoE SDO",
        value_type: "u8",
        description: "CoE Object Dictionary 8-bit Subindex",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.expedited",
        layer: "CoE SDO",
        value_type: "bool",
        description: "True when SDO transfer is expedited (<=4 bytes inline)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.ca",
        layer: "CoE SDO",
        value_type: "bool",
        description: "True when CoE SDO Complete Access flag is set",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.data",
        layer: "CoE SDO",
        value_type: "string (hex)",
        description: "SDO payload bytes in hex",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.value",
        layer: "CoE SDO",
        value_type: "typed JSON value",
        description: "Auto-decoded little-endian SDO value",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.abort_code",
        layer: "CoE SDO",
        value_type: "string (hex u32)",
        description: "32-bit CoE SDO Abort Code when SDO command == 0x80",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.emcy.error_code",
        layer: "CoE Emergency",
        value_type: "string (hex u16)",
        description: "16-bit CoE Emergency error code",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdoinfo.opcode",
        layer: "CoE SDO Info",
        value_type: "u8",
        description: "CoE SDO Information opcode (0x01..0x07)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdoinfo.name",
        layer: "CoE SDO Info",
        value_type: "string",
        description: "Object/Entry description name returned by SDO Info",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdoinfo.abort_code",
        layer: "CoE SDO Info",
        value_type: "string (hex u32)",
        description: "32-bit CoE SDO Information error abort code (opcode 0x07)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.foe.opcode",
        layer: "FoE (File over EtherCAT)",
        value_type: "u8",
        description: "FoE opcode (1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERR, 6=BUSY)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.foe.filename",
        layer: "FoE (File over EtherCAT)",
        value_type: "string",
        description: "FoE RRQ/WRQ filename string",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.foe.packet_no",
        layer: "FoE (File over EtherCAT)",
        value_type: "u32",
        description: "FoE DATA/ACK packet number",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.foe.busy_done",
        layer: "FoE (File over EtherCAT)",
        value_type: "u16",
        description: "FoE BUSY progress numerator (`done` out of `busy_entire`)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.soe.opcode",
        layer: "SoE (Servo over EtherCAT)",
        value_type: "u8",
        description: "SoE opcode (1..6)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.soe.idn",
        layer: "SoE (Servo over EtherCAT)",
        value_type: "string",
        description: "SoE Identification Number formatted as S-x-yyyy or P-x-yyyy (when incomplete=false)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.soe.fragments_left",
        layer: "SoE (Servo over EtherCAT)",
        value_type: "u16",
        description: "Remaining SoE fragments when `incomplete` flag is set",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.aoe.cmd",
        layer: "AoE (ADS over EtherCAT)",
        value_type: "u16",
        description: "ADS command ID",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.aoe.target",
        layer: "AoE (ADS over EtherCAT)",
        value_type: "string",
        description: "ADS Target NetId:Port",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.aoe.index_group",
        layer: "AoE (ADS over EtherCAT)",
        value_type: "string (hex u32)",
        description: "ADS IndexGroup on Read/Write/ReadWrite requests (e.g. 0x0000f302 for CoE SDO over AoE)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.aoe.index_offset",
        layer: "AoE (ADS over EtherCAT)",
        value_type: "string (hex u32)",
        description: "ADS IndexOffset on Read/Write/ReadWrite requests",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.aoe.result",
        layer: "AoE (ADS over EtherCAT)",
        value_type: "u32",
        description: "ADS command result code on Read/Write/ReadWrite responses",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.type",
        layer: "EoE (Ethernet over EtherCAT)",
        value_type: "u8",
        description: "EoE frame type nibble",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.port",
        layer: "EoE (Ethernet over EtherCAT)",
        value_type: "u8",
        description: "EoE 4-bit virtual switch port number",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.ip",
        layer: "EoE (Ethernet over EtherCAT)",
        value_type: "string (IPv4)",
        description: "EoE IPv4 address from Set/Get IP Parameter (also .mac, .subnet, .gateway, .dns_ip, .dns_name)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.eth.dst",
        layer: "EoE (Ethernet over EtherCAT)",
        value_type: "string (MAC)",
        description: "Inner Ethernet destination MAC (also .eth.src, .eth.type, .vlan.id, .arp.*, .ip.*, .ipv6.*, .icmp.*, .udp.*, .tcp.*)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.reassembled_data",
        layer: "EoE (Ethernet over EtherCAT)",
        value_type: "string (hex)",
        description: "Reassembled Ethernet frame hex payload across multi-fragment EoE transfers (also .reassembled_length)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.voe.vendor_id",
        layer: "VoE (Vendor specific over EtherCAT)",
        value_type: "string (hex u32)",
        description: "32-bit VoE Vendor ID",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.voe.vendor_type",
        layer: "VoE (Vendor specific over EtherCAT)",
        value_type: "string (hex u16)",
        description: "16-bit VoE Vendor Type",
    },
    // Network Variables (`tc_nv.*` / `nv.*`), Raw-IO (`ioraw.*`), Direct AMS (`ams.*`), DC Diff & XML SDO
    FieldSelectorDoc {
        selector: "tc_nv.publisher",
        layer: "TwinCAT Network Variables",
        value_type: "string (MAC)",
        description: "Wireshark 4.6 `tc_nv` 6-byte Publisher MAC in 12-byte NvParserHDR (also `tc_nv.count`, `tc_nv.cycleindex`, `tc_nv.id`, `tc_nv.hash`, `tc_nv.length`, `tc_nv.quality`, `tc_nv.data`)",
    },
    FieldSelectorDoc {
        selector: "nv.publisher_id",
        layer: "Network Variables",
        value_type: "string (hex)",
        description: "EtherCAT Network Variables 6-byte publisher identifier hex",
    },
    FieldSelectorDoc {
        selector: "nv.count",
        layer: "Network Variables",
        value_type: "u16",
        description: "Number of Network Variables in frame",
    },
    FieldSelectorDoc {
        selector: "ioraw.header",
        layer: "EtherCAT Raw-IO",
        value_type: "string (hex)",
        description: "Wireshark 4.6 `ioraw` 4-byte header (`ecatf.type == 3`; also `ioraw.data`)",
    },
    FieldSelectorDoc {
        selector: "ioraw.data",
        layer: "EtherCAT Raw-IO",
        value_type: "string (hex)",
        description: "Wireshark 4.6 `ioraw` direct process-image variable payload (`ecatf.type == 3`)",
    },
    FieldSelectorDoc {
        selector: "ams.cmdid",
        layer: "Beckhoff AMS / ADS",
        value_type: "u16",
        description: "Wireshark 4.6 AMS/ADS Command ID (`ecatf.type == 2`, `AMS/TCP 48898`, `AMS/UDP 48899`; also `ams.pdu_count`, `ams[i].*`, `ams.reassembled`, `ams.targetnetid`, `ams.sendernetid`, `ams.ads_indexgroup`, `ams.ads_indexoffset`, `ams.adsresult`)",
    },
    FieldSelectorDoc {
        selector: "ecat.dc.dif.curtime",
        layer: "Distributed Clocks",
        value_type: "u32",
        description: "CLI extension (not a Wireshark 4.6 field): DC `0x0910` `ARMW`/`FRMW` difference vs previous frame in nanoseconds. Official Wireshark DC port diffs are `ecat.dc.dif.da`, `.bd`, `.cb`, `.cd`, `.ba`, `.ca` (only for `APRD`/`FPRD` at `0x0900` with WKC > 0)",
    },
    FieldSelectorDoc {
        selector: "ecat.fmmu.lstart",
        layer: "ESC FMMU",
        value_type: "string (hex u32)",
        description: "Wireshark 4.6 canonical FMMU logical start address (`0x0600..0x06FF`; also `.llen`, `.pstart`, `.typeread`, `.typewrite`, `.activate0`)",
    },
    FieldSelectorDoc {
        selector: "ecat.syncman.start",
        layer: "ESC SyncManager",
        value_type: "string (hex u16)",
        description: "Wireshark 4.6 canonical SyncManager physical start address (`0x0800..0x087F`; also `.len`, `.enable`, `.access`, `.opmode`, `.1bufstate`)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.foe.efw.cmd",
        layer: "FoE Firmware (.efw)",
        value_type: "string (hex u16)",
        description: "Wireshark 4.6 FoE `.efw` firmware container command (also `.size`, `.addresslw`, `.addresshw`, `.data`)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.eoe.macfilter.macfiltercount",
        layer: "EoE MAC Filter",
        value_type: "u8",
        description: "Wireshark 4.6 EoE MAC filter count (also `.maskcount`, `.nobroadcasts`, `.filter`, `.filter0..15`, `.filtermask`, `.filtermask0..3`)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdoblk.seqno",
        layer: "CoE SDO Block",
        value_type: "u8",
        description: "CoE SDO Block sub-block sequence number 1..127 (also `.last`, `.blksize`, `.ackseq`, `.unused`, `.crc`, `.crc_support`, `.crc_ok`, `.computed_crc`, `.pst`, `.data`, `ecat_mailbox.coe.sdo.reassembled_data`)",
    },
    FieldSelectorDoc {
        selector: "ecat_mailbox.coe.sdo.xml.entry_name",
        layer: "XML CoE SDO (--xml)",
        value_type: "string",
        description: "Object Dictionary subindex/object name resolved from `--xml` (also `.device_name`, `.object_name`, `.object_code`, `.data_type`, `.bit_size`, `.bit_length`, `.access`, `.unit`, `.value`, `.enum_text`, `.subitems`, `.reassembled_segments`, `.reassembled_len`, and `ams.coe.sdo.xml.*`)",
    },
    // SII / Command Output Convenience Selectors
    FieldSelectorDoc {
        selector: "sii.vendor_id_hex",
        layer: "SII EEPROM",
        value_type: "string (hex u32)",
        description: "SII Header Vendor ID (alias for header.vendor_id_hex on `sii inspect`)",
    },
    FieldSelectorDoc {
        selector: "sii.product_code_hex",
        layer: "SII EEPROM",
        value_type: "string (hex u32)",
        description: "SII Header Product Code (alias for header.product_code_hex on `sii inspect`)",
    },
    FieldSelectorDoc {
        selector: "sii.crc_ok",
        layer: "SII EEPROM",
        value_type: "bool",
        description: "SII Header CRC-8 validity (alias for header.crc_ok on `sii inspect` / `sii build`)",
    },
    FieldSelectorDoc {
        selector: "sii.device_name",
        layer: "SII EEPROM",
        value_type: "string",
        description: "SII Category 30 General device name (resolves categories.general.device_name)",
    },
    FieldSelectorDoc {
        selector: "sii.order_name",
        layer: "SII EEPROM",
        value_type: "string",
        description: "SII Category 30 General order/type code (resolves categories.general.order_name)",
    },
    FieldSelectorDoc {
        selector: "sii.group_name",
        layer: "SII EEPROM",
        value_type: "string",
        description: "SII Category 30 General group type string (resolves categories.general.group_name)",
    },
    FieldSelectorDoc {
        selector: "sii.image_name",
        layer: "SII EEPROM",
        value_type: "string",
        description: "SII Category 30 General image identifier (resolves categories.general.image_name)",
    },
    // ETG.2000 ESI XML Selectors (`esi.*`)
    FieldSelectorDoc {
        selector: "esi.order_code",
        layer: "ESI XML (ETG.2000)",
        value_type: "string",
        description: "ESI <Device><Type> order code (on `esi inspect`, `esi build`, `sii build`, `sii read --xml`)",
    },
    FieldSelectorDoc {
        selector: "esi.device_name",
        layer: "ESI XML (ETG.2000)",
        value_type: "string",
        description: "Localized ESI <Device><Name> string",
    },
    FieldSelectorDoc {
        selector: "esi.product_code",
        layer: "ESI XML (ETG.2000)",
        value_type: "string / u32",
        description: "ESI <Device><Type ProductCode=\"...\"> identifier",
    },
    FieldSelectorDoc {
        selector: "esi.revision_number",
        layer: "ESI XML (ETG.2000)",
        value_type: "string / u32",
        description: "ESI <Device><Type RevisionNo=\"...\"> revision",
    },
    FieldSelectorDoc {
        selector: "esi.eeprom_byte_size",
        layer: "ESI XML (ETG.2000)",
        value_type: "usize",
        description: "Declared <Eeprom><ByteSize> capacity in bytes",
    },
    FieldSelectorDoc {
        selector: "decoded_value",
        layer: "SDO / ESC Reg",
        value_type: "typed JSON value",
        description: "Typed value returned by `sdo read`, `sdo write`, `reg read`, or `reg write`",
    },
    // Pure-Rust SSC / OD Generator Selectors (`ssc.*`)
    FieldSelectorDoc {
        selector: "ssc.project_name",
        layer: "SSC Generator",
        value_type: "string",
        description: "Generated SSC project stem on `ssc generate` (also .ssc_version, .esp_file, .esi_file, .eeprom_header)",
    },
    FieldSelectorDoc {
        selector: "ssc.define.<CODE_DEFINE>",
        layer: "SSC Generator",
        value_type: "string",
        description: "Value of a named SSC `#define` setting in `ssc list-defines` (e.g. `ssc.define.VENDOR_ID`)",
    },
    FieldSelectorDoc {
        selector: "ssc.config.<NAME>",
        layer: "SSC Generator",
        value_type: "object",
        description: "Configuration preset metadata by name in `ssc list-configs`",
    },
    FieldSelectorDoc {
        selector: "ssc.app_name",
        layer: "SSC Generator",
        value_type: "string",
        description: "Application name on `ssc od generate` (also .object_count, .objects_header, .offline_od_xml)",
    },
    FieldSelectorDoc {
        selector: "ssc.image_data_16x14",
        layer: "SSC Generator",
        value_type: "string (hex)",
        description: "Encoded 16x14 icon hex string returned by `ssc image-hex`",
    },
];

#[derive(Debug, Clone)]
enum PathStep {
    Key(String),
    Index(usize),
    WildcardArray,
}

fn parse_json_path(selector: &str) -> Vec<PathStep> {
    let mut steps = Vec::new();
    for segment in selector.split('.') {
        if segment.is_empty() {
            continue;
        }
        let mut rest = segment;
        while let Some(open) = rest.find('[') {
            let prefix = &rest[..open];
            if !prefix.is_empty() {
                steps.push(PathStep::Key(prefix.to_string()));
            }
            if let Some(close_rel) = rest[open + 1..].find(']') {
                let idx_str = &rest[open + 1..open + 1 + close_rel];
                if idx_str == "*" {
                    steps.push(PathStep::WildcardArray);
                } else if let Ok(idx) = idx_str.parse::<usize>() {
                    steps.push(PathStep::Index(idx));
                } else {
                    steps.push(PathStep::Key(idx_str.to_string()));
                }
                rest = &rest[open + 1 + close_rel + 1..];
            } else {
                steps.push(PathStep::Key(rest.to_string()));
                rest = "";
            }
        }
        if !rest.is_empty() {
            steps.push(PathStep::Key(rest.to_string()));
        }
    }
    steps
}

fn eval_steps(val: &Value, steps: &[PathStep]) -> Option<Value> {
    if steps.is_empty() {
        return Some(val.clone());
    }
    match (&steps[0], val) {
        (PathStep::Key(k), Value::Object(map)) => {
            let next = map.get(k).or_else(|| {
                map.iter()
                    .find(|(mk, _)| mk.eq_ignore_ascii_case(k))
                    .map(|(_, mv)| mv)
            })?;
            eval_steps(next, &steps[1..])
        }
        (PathStep::Index(i), Value::Array(arr)) => {
            let next = arr.get(*i)?;
            eval_steps(next, &steps[1..])
        }
        (PathStep::WildcardArray, Value::Array(arr)) => {
            let mut collected = Vec::new();
            for item in arr {
                if let Some(v) = eval_steps(item, &steps[1..]) {
                    collected.push(v);
                }
            }
            Some(Value::Array(collected))
        }
        _ => None,
    }
}

fn find_pdo_entry_in_array(arr: &[Value], key: &str) -> Option<Value> {
    let stripped = key
        .strip_prefix("ecat.pdo.")
        .or_else(|| key.strip_prefix("pdo."))
        .unwrap_or(key);
    for item in arr {
        let name_match = item
            .get("name")
            .and_then(|v| v.as_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(stripped));
        let entry_match = item
            .get("entry")
            .and_then(|v| v.as_str())
            .is_some_and(|e| e.eq_ignore_ascii_case(stripped));
        if name_match || entry_match {
            return item.get("value").cloned().or_else(|| Some(item.clone()));
        }
    }
    None
}

fn match_ws_wildcard_indices(
    chunks: &[&str],
    key: &str,
    allow_dot_tail: bool,
) -> Option<Vec<usize>> {
    let mut rem = key;
    let first = chunks.first()?;
    if rem.len() < first.len() || !rem[..first.len()].eq_ignore_ascii_case(first) {
        return None;
    }
    rem = &rem[first.len()..];
    let mut indices = Vec::with_capacity(chunks.len().saturating_sub(1));
    for chunk in &chunks[1..] {
        let after_open = rem.strip_prefix('[')?;
        let close_pos = after_open.find(']')?;
        let idx: usize = after_open[..close_pos].parse().ok()?;
        indices.push(idx);
        rem = &after_open[close_pos + 1..];
        if rem.len() < chunk.len() || !rem[..chunk.len()].eq_ignore_ascii_case(chunk) {
            return None;
        }
        rem = &rem[chunk.len()..];
    }
    if rem.is_empty() || (allow_dot_tail && rem.starts_with('.')) {
        Some(indices)
    } else {
        None
    }
}

fn eval_ws_wildcard(ws: &Map<String, Value>, sel: &str) -> Option<Value> {
    if !sel.contains("[*]") {
        return None;
    }
    let (core, trailing_star) = match sel.strip_suffix(".*") {
        Some(p) => (p, true),
        None => (sel, false),
    };
    let chunks: Vec<&str> = core.split("[*]").collect();
    if chunks.len() < 2 {
        return None;
    }
    if trailing_star {
        let mut matched = Map::new();
        for (k, v) in ws {
            if match_ws_wildcard_indices(&chunks, k, true).is_some() {
                matched.insert(k.clone(), v.clone());
            }
        }
        if !matched.is_empty() {
            return Some(Value::Object(matched));
        }
        return None;
    }

    let mut rows: Vec<(Vec<usize>, Value)> = Vec::new();
    for (k, v) in ws {
        if let Some(idxs) = match_ws_wildcard_indices(&chunks, k, false) {
            rows.push((idxs, v.clone()));
        }
    }
    if !rows.is_empty() {
        rows.sort_by(|a, b| a.0.cmp(&b.0));
        return Some(Value::Array(rows.into_iter().map(|(_, v)| v).collect()));
    }

    // Singleton fallback when unindexed key exists (e.g. single AMS/UDP `ams.cmdid`)
    if chunks.len() == 2 {
        let singleton = format!("{}{}", chunks[0], chunks[1]);
        if let Some(v) = ws.get(&singleton).or_else(|| {
            ws.iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(&singleton))
                .map(|(_, v)| v)
        }) {
            return Some(Value::Array(vec![v.clone()]));
        }
    }
    None
}

/// Resolve a single selector against a JSON object/value (supporting Wireshark keys, wildcards,
/// PDO/SII/SDO/Reg convenience aliases, and arbitrary JSON dot/index paths).
pub fn resolve_single_selector(root: &Value, selector: &str) -> Option<Value> {
    let sel = selector.trim();
    if sel.is_empty() {
        return Some(root.clone());
    }

    // 1. Check `wireshark_fields` map directly (or inside nested `dissected` / `rx_dissected` / `frame`)
    for candidate in [
        Some(root),
        root.get("frame"),
        root.get("rx_dissected"),
        root.get("tx_dissected"),
        root.get("dissected"),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(Value::Object(ws)) = candidate.get("wireshark_fields") {
            if let Some(exact) = ws.get(sel).or_else(|| {
                ws.iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(sel))
                    .map(|(_, v)| v)
            }) {
                return Some(exact.clone());
            }
            if let Some(wild_val) = eval_ws_wildcard(ws, sel) {
                return Some(wild_val);
            }
            if let Some(prefix) = sel.strip_suffix(".*") {
                let pfx_dot = format!("{prefix}.");
                let mut matched = Map::new();
                for (k, v) in ws {
                    if k == prefix || k.starts_with(&pfx_dot) {
                        matched.insert(k.clone(), v.clone());
                    }
                }
                if !matched.is_empty() {
                    return Some(Value::Object(matched));
                }
            }
        }
        // Check PDO decoded arrays inside dissected datagrams when querying ecat.pdo.<entry>
        if sel.starts_with("ecat.pdo.") || sel.starts_with("pdo.") {
            if let Some(Value::Array(dgs)) = candidate.get("datagrams") {
                for dg in dgs {
                    if let Some(Value::Array(pf)) = dg.get("pdo_fields") {
                        if let Some(v) = find_pdo_entry_in_array(pf, sel) {
                            return Some(v);
                        }
                    }
                }
            }
        }
    }

    // 2. Check PDO arrays on `pdo read` / `pdo exchange` / `pdo decode`
    for arr_key in ["decoded_inputs", "fields"] {
        if let Some(Value::Array(arr)) = root.get(arr_key) {
            if let Some(v) = find_pdo_entry_in_array(arr, sel) {
                return Some(v);
            }
        }
    }

    // 3. Check SII convenience alias (`sii.<key>` -> `header.<key>`, `categories.<key>`, `categories.general.<key>`, or `identity.<key>`)
    if let Some(sii_rest) = sel.strip_prefix("sii.") {
        for sii_root in [
            Some(root),
            root.get("decoded"),
            root.get("compiled_sii_decoded"),
        ]
        .into_iter()
        .flatten()
        {
            for path_candidate in [
                format!("header.{sii_rest}"),
                format!("categories.{sii_rest}"),
                format!("categories.general.{sii_rest}"),
                format!("identity.{sii_rest}"),
                format!("summary.{sii_rest}"),
                format!("proposed_identity.{sii_rest}"),
            ] {
                if let Some(v) = eval_steps(sii_root, &parse_json_path(&path_candidate)) {
                    return Some(v);
                }
            }
        }
        if sii_rest.eq_ignore_ascii_case("device_name") {
            for fb in ["identity.name", "summary.name", "proposed_identity.name"] {
                if let Some(v) = eval_steps(root, &parse_json_path(fb)) {
                    return Some(v);
                }
            }
        }
    }

    // 3b. Check ESI convenience alias (`esi.<key>` -> `esi_device.<key>`, `device.<key>`, or `esi_match.device.<key>`)
    if let Some(esi_rest) = sel.strip_prefix("esi.") {
        for esi_candidate in [
            format!("esi_device.{esi_rest}"),
            format!("device.{esi_rest}"),
            format!("esi_match.device.{esi_rest}"),
            esi_rest.to_string(),
        ] {
            if let Some(v) = eval_steps(root, &parse_json_path(&esi_candidate)) {
                return Some(v);
            }
        }
    }

    // 3c. Check SSC convenience aliases (`ssc.define.<NAME>`, `ssc.config.<NAME>`, `ssc.<field>`)
    if let Some(ssc_rest) = sel.strip_prefix("ssc.") {
        if let Some(def_name) = ssc_rest.strip_prefix("define.") {
            if let Some(Value::Array(defs)) = root.get("defines") {
                for item in defs {
                    if item
                        .get("code_define")
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.eq_ignore_ascii_case(def_name))
                    {
                        return item.get("value").cloned().or_else(|| Some(item.clone()));
                    }
                }
            }
        }
        if let Some(cfg_name) = ssc_rest.strip_prefix("config.") {
            if let Some(Value::Array(cfgs)) = root.get("configurations") {
                for item in cfgs {
                    if item
                        .get("name")
                        .and_then(Value::as_str)
                        .is_some_and(|n| n.eq_ignore_ascii_case(cfg_name))
                    {
                        return Some(item.clone());
                    }
                }
            }
        }
        if let Some(v) = eval_steps(root, &parse_json_path(ssc_rest)) {
            return Some(v);
        }
    }

    // 4. Value convenience alias (`value` -> `decoded_value`, `selected_slice.value`, `bit_slice.value`, or `image_data_16x14`)
    if sel.eq_ignore_ascii_case("value") {
        for k in ["value", "decoded_value", "image_data_16x14"] {
            if let Some(v) = root.get(k) {
                return Some(v.clone());
            }
        }
        for slice_key in ["selected_slice", "bit_slice"] {
            if let Some(v) = root.get(slice_key).and_then(|s| s.get("value")) {
                return Some(v.clone());
            }
        }
    }

    // 5. General JSON path navigation (`a.b[0].c` or `frames[*].frame...`)
    let steps = parse_json_path(sel);
    if let Some(v) = eval_steps(root, &steps) {
        return Some(v);
    }

    // Root-array convenience fallback when selector starts with `[` (e.g. `-f "[0].name"` on `adapters`)
    if matches!(
        steps.first(),
        Some(PathStep::Index(_) | PathStep::WildcardArray)
    ) {
        for arr_wrapper_key in [
            "adapters",
            "slaves",
            "devices",
            "objects",
            "registers",
            "defines",
            "configurations",
            "frames",
            "packets",
        ] {
            if let Some(arr_val @ Value::Array(_)) = root.get(arr_wrapper_key) {
                if let Some(v) = eval_steps(arr_val, &steps) {
                    return Some(v);
                }
            }
        }
    }

    // Also try relative to nested `frame` wrapper if `root` is a single capture packet record
    if let Some(inner_frame) = root.get("frame") {
        if let Some(v) = eval_steps(inner_frame, &steps) {
            return Some(v);
        }
    }

    None
}

/// Apply one or more `--field` selectors to any command output JSON value.
/// - For multi-frame outputs (`{ "frames": [...] }` or `{ "packets": [...] }`), projects the
///   requested selectors across every frame unless the selector explicitly addresses root keys (e.g. `frames[0]...`).
/// - Returns `CliError::Mismatch` (exit code 4) if no requested field matched.
pub fn apply_field_selectors(root: &Value, selectors: &[String]) -> Result<Value> {
    if selectors.is_empty() {
        return Ok(root.clone());
    }

    // Check if root is a multi-packet container (`frames` or `packets`) and selectors target packet fields
    for list_key in ["frames", "packets"] {
        if let Some(Value::Array(items)) = root.get(list_key) {
            let root_level_explicit = selectors.iter().all(|raw_s| {
                let s = raw_s.trim();
                s.starts_with(list_key) || s.starts_with('[') || root.get(s).is_some()
            });
            if !root_level_explicit {
                let mut projected = Vec::new();
                let mut any_hit = false;
                for (idx, item) in items.iter().enumerate() {
                    let mut row = Map::new();
                    let mut row_hit = false;
                    for raw_sel in selectors {
                        let sel = raw_sel.trim();
                        if let Some(val) = resolve_single_selector(item, sel) {
                            row.insert(sel.to_string(), val);
                            row_hit = true;
                            any_hit = true;
                        } else {
                            row.insert(sel.to_string(), Value::Null);
                        }
                    }
                    if row_hit {
                        let pkt_idx = item
                            .get("index")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(idx as u64);
                        projected.push(json!({
                            "index": pkt_idx,
                            "fields": Value::Object(row),
                        }));
                    }
                }
                if !any_hit {
                    return Err(CliError::Mismatch(format!(
                        "none of the {} packet(s) matched field selector(s) [{}]. Run `ethercat-cli fields` to inspect valid selectors.",
                        items.len(),
                        selectors.join(", ")
                    )));
                }
                return Ok(Value::Array(projected));
            }
        }
    }

    if selectors.len() == 1 {
        let sel = selectors[0].trim();
        let val = resolve_single_selector(root, sel).ok_or_else(|| {
            CliError::Mismatch(format!(
                "field selector '{sel}' not found in output. Run `ethercat-cli fields` or omit `-f` with `--format json` to inspect keys."
            ))
        })?;
        let mut map = Map::new();
        map.insert(sel.to_string(), val);
        return Ok(Value::Object(map));
    }

    let mut out = Map::new();
    let mut missing = Vec::new();
    for raw_sel in selectors {
        let sel = raw_sel.trim();
        match resolve_single_selector(root, sel) {
            Some(v) => {
                out.insert(sel.to_string(), v);
            }
            None => missing.push(sel),
        }
    }
    if !missing.is_empty() {
        return Err(CliError::Mismatch(format!(
            "field selector(s) not found: [{}]. Run `ethercat-cli fields` to list valid Wireshark & JSON selectors.",
            missing.join(", ")
        )));
    }
    Ok(Value::Object(out))
}

/// Render a field-selected `Value` concisely in human/script-friendly plain text.
pub fn format_selected_fields_text(selected: &Value, selectors: &[String]) -> String {
    match selected {
        Value::Object(map) if selectors.len() == 1 => {
            if let Some((_, v)) = map.iter().next() {
                return scalar_or_compact_json(v);
            }
            String::new()
        }
        Value::Object(map) => map
            .iter()
            .map(|(k, v)| format!("{k}={}", scalar_or_compact_json(v)))
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Array(rows) => rows
            .iter()
            .map(|row| {
                let idx = row.get("index").and_then(|v| v.as_u64()).unwrap_or(0);
                if let Some(Value::Object(fields)) = row.get("fields") {
                    let kvs = fields
                        .iter()
                        .map(|(k, v)| format!("{k}={}", scalar_or_compact_json(v)))
                        .collect::<Vec<_>>()
                        .join("  ");
                    format!("[frame #{idx}] {kvs}")
                } else {
                    scalar_or_compact_json(row)
                }
            })
            .collect::<Vec<_>>()
            .join("\n"),
        other => scalar_or_compact_json(other),
    }
}

fn scalar_or_compact_json(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}
