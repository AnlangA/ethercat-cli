use clap::ValueEnum;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::types::parse_u16;

pub const ETH_P_ECAT: u16 = 0x88A4;
pub const UDP_PORT_ECAT: u16 = 0x88A4; // 34980
pub const ETH_HEADER_LEN: usize = 14;
pub const ECAT_FRAME_HEADER_LEN: usize = 2;
pub const ECAT_DATAGRAM_HEADER_LEN: usize = 10;
pub const ECAT_WKC_LEN: usize = 2;
pub const MIN_ETHERNET_FRAME_LEN: usize = 60;

/// Default SOEM primary master MAC: `01:01:01:01:01:01`.
pub const DEFAULT_MASTER_MAC: [u8; 6] = [0x01, 0x01, 0x01, 0x01, 0x01, 0x01];
pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// EtherCAT Frame Header type (upper 4 bits of the 16-bit EtherCAT header).
pub const ECAT_FRAME_TYPE_DLPDU: u8 = 0x01;
pub const ECAT_FRAME_TYPE_NV: u8 = 0x04;
pub const ECAT_FRAME_TYPE_MAILBOX: u8 = 0x05;

pub fn ecat_frame_type_name(ft: u8) -> &'static str {
    match ft {
        0x01 => "ECAT_COMMAND (DLPDU)",
        0x04 => "NETWORK_VARIABLES (NV)",
        0x05 => "MAILBOX",
        _ => "RESERVED/UNKNOWN",
    }
}

/// EtherCAT Datagram Command codes (matching Wireshark `ecat.cmd` and ETG.1000.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EcatCmd {
    /// 0x00: No Operation (ignores slave memory, WKC unchanged).
    Nop,
    /// 0x01: Auto-Increment Physical Read (executes when ADP == 0, increments ADP at every slave).
    Aprd,
    /// 0x02: Auto-Increment Physical Write (executes when ADP == 0, increments ADP at every slave).
    Apwr,
    /// 0x03: Auto-Increment Physical Read/Write.
    Aprw,
    /// 0x04: Configured Station Physical Read (executes when ADP == ESC 0x0010 or Alias 0x0012).
    Fprd,
    /// 0x05: Configured Station Physical Write (executes when ADP == ESC 0x0010 or Alias 0x0012).
    Fpwr,
    /// 0x06: Configured Station Physical Read/Write.
    Fprw,
    /// 0x07: Broadcast Read (all slaves bitwise-OR data into payload and increment ADP & WKC).
    Brd,
    /// 0x08: Broadcast Write (all slaves write payload to ADO and increment ADP & WKC).
    Bwr,
    /// 0x09: Broadcast Read/Write.
    Brw,
    /// 0x0A: Logical Memory Read (32-bit Logical Address via FMMU).
    Lrd,
    /// 0x0B: Logical Memory Write (32-bit Logical Address via FMMU).
    Lwr,
    /// 0x0C: Logical Memory Read/Write (32-bit Logical Address via FMMU; WKC += 1 read, +2 write, +3 RW).
    Lrw,
    /// 0x0D: Auto-Increment Physical Read Multiple Write (slave with ADP==0 reads, others write; DC sync).
    Armw,
    /// 0x0E: Configured Station Physical Read Multiple Write (matching slave reads, others write; DC sync).
    Frmw,
}

impl EcatCmd {
    pub fn code(self) -> u8 {
        match self {
            Self::Nop => 0x00,
            Self::Aprd => 0x01,
            Self::Apwr => 0x02,
            Self::Aprw => 0x03,
            Self::Fprd => 0x04,
            Self::Fpwr => 0x05,
            Self::Fprw => 0x06,
            Self::Brd => 0x07,
            Self::Bwr => 0x08,
            Self::Brw => 0x09,
            Self::Lrd => 0x0A,
            Self::Lwr => 0x0B,
            Self::Lrw => 0x0C,
            Self::Armw => 0x0D,
            Self::Frmw => 0x0E,
        }
    }

    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0x00 => Some(Self::Nop),
            0x01 => Some(Self::Aprd),
            0x02 => Some(Self::Apwr),
            0x03 => Some(Self::Aprw),
            0x04 => Some(Self::Fprd),
            0x05 => Some(Self::Fpwr),
            0x06 => Some(Self::Fprw),
            0x07 => Some(Self::Brd),
            0x08 => Some(Self::Bwr),
            0x09 => Some(Self::Brw),
            0x0A => Some(Self::Lrd),
            0x0B => Some(Self::Lwr),
            0x0C => Some(Self::Lrw),
            0x0D => Some(Self::Armw),
            0x0E => Some(Self::Frmw),
            _ => None,
        }
    }

    pub fn mnemonic(self) -> &'static str {
        match self {
            Self::Nop => "NOP",
            Self::Aprd => "APRD",
            Self::Apwr => "APWR",
            Self::Aprw => "APRW",
            Self::Fprd => "FPRD",
            Self::Fpwr => "FPWR",
            Self::Fprw => "FPRW",
            Self::Brd => "BRD",
            Self::Bwr => "BWR",
            Self::Brw => "BRW",
            Self::Lrd => "LRD",
            Self::Lwr => "LWR",
            Self::Lrw => "LRW",
            Self::Armw => "ARMW",
            Self::Frmw => "FRMW",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Nop => "No Operation",
            Self::Aprd => "Auto Increment Physical Read",
            Self::Apwr => "Auto Increment Physical Write",
            Self::Aprw => "Auto Increment Physical Read Write",
            Self::Fprd => "Configured Address Physical Read",
            Self::Fpwr => "Configured Address Physical Write",
            Self::Fprw => "Configured Address Physical Read Write",
            Self::Brd => "Broadcast Read",
            Self::Bwr => "Broadcast Write",
            Self::Brw => "Broadcast Read Write",
            Self::Lrd => "Logical Memory Read",
            Self::Lwr => "Logical Memory Write",
            Self::Lrw => "Logical Memory Read Write",
            Self::Armw => "Auto Increment Physical Read Multiple Write",
            Self::Frmw => "Configured Address Physical Read Multiple Write",
        }
    }

    pub fn is_logical(self) -> bool {
        matches!(self, Self::Lrd | Self::Lwr | Self::Lrw)
    }

    pub fn is_auto_increment(self) -> bool {
        matches!(self, Self::Aprd | Self::Apwr | Self::Aprw | Self::Armw)
    }

    #[allow(dead_code)]
    pub fn is_write_capable(self) -> bool {
        matches!(
            self,
            Self::Apwr
                | Self::Aprw
                | Self::Fpwr
                | Self::Fprw
                | Self::Bwr
                | Self::Brw
                | Self::Lwr
                | Self::Lrw
                | Self::Armw
                | Self::Frmw
        )
    }
}

/// ESC Register descriptor for symbolic CLI access & Wireshark-style dissection.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct EscRegisterInfo {
    pub address: u16,
    pub default_size: u16,
    pub name: &'static str,
    pub symbol: &'static str,
    pub description: &'static str,
}

pub const ESC_REGISTERS: &[EscRegisterInfo] = &[
    EscRegisterInfo {
        address: 0x0000,
        default_size: 1,
        name: "type",
        symbol: "ECT_REG_TYPE",
        description: "ESC Type",
    },
    EscRegisterInfo {
        address: 0x0001,
        default_size: 1,
        name: "revision",
        symbol: "ECT_REG_REVISION",
        description: "ESC Revision",
    },
    EscRegisterInfo {
        address: 0x0002,
        default_size: 2,
        name: "build",
        symbol: "ECT_REG_BUILD",
        description: "ESC Build",
    },
    EscRegisterInfo {
        address: 0x0004,
        default_size: 1,
        name: "fmmu-count",
        symbol: "ECT_REG_FMMUSUP",
        description: "FMMUs Supported",
    },
    EscRegisterInfo {
        address: 0x0005,
        default_size: 1,
        name: "sm-count",
        symbol: "ECT_REG_SMSUP",
        description: "SyncManagers Supported",
    },
    EscRegisterInfo {
        address: 0x0006,
        default_size: 1,
        name: "ram-size",
        symbol: "ECT_REG_RAMSIZE",
        description: "RAM Size (KB)",
    },
    EscRegisterInfo {
        address: 0x0007,
        default_size: 1,
        name: "port-desc",
        symbol: "ECT_REG_PORTDES",
        description: "Port Descriptor (ports 0..3)",
    },
    EscRegisterInfo {
        address: 0x0008,
        default_size: 2,
        name: "esc-features",
        symbol: "ECT_REG_ESCSUP",
        description: "ESC Features Supported",
    },
    EscRegisterInfo {
        address: 0x0010,
        default_size: 2,
        name: "station-addr",
        symbol: "ECT_REG_STADR",
        description: "Configured Station Address",
    },
    EscRegisterInfo {
        address: 0x0012,
        default_size: 2,
        name: "alias",
        symbol: "ECT_REG_ALIAS",
        description: "Configured Station Alias",
    },
    EscRegisterInfo {
        address: 0x0100,
        default_size: 4,
        name: "dl-control",
        symbol: "ECT_REG_DLCTL",
        description: "ESC DL Control",
    },
    EscRegisterInfo {
        address: 0x0101,
        default_size: 1,
        name: "dl-port",
        symbol: "ECT_REG_DLPORT",
        description: "Physical Read/Write Offset / Loop Control",
    },
    EscRegisterInfo {
        address: 0x0103,
        default_size: 1,
        name: "dl-alias",
        symbol: "ECT_REG_DLALIAS",
        description: "Station Alias Enable",
    },
    EscRegisterInfo {
        address: 0x0110,
        default_size: 2,
        name: "dl-status",
        symbol: "ECT_REG_DLSTAT",
        description: "ESC DL Status (PDI, link, loop, signal)",
    },
    EscRegisterInfo {
        address: 0x0120,
        default_size: 2,
        name: "al-control",
        symbol: "ECT_REG_ALCTL",
        description: "AL Control (Requested State + Error Ack)",
    },
    EscRegisterInfo {
        address: 0x0130,
        default_size: 2,
        name: "al-status",
        symbol: "ECT_REG_ALSTAT",
        description: "AL Status (Actual State + Error Ind)",
    },
    EscRegisterInfo {
        address: 0x0134,
        default_size: 2,
        name: "al-status-code",
        symbol: "ECT_REG_ALSTATCODE",
        description: "AL Status Code (ETG.1000.6 error reason)",
    },
    EscRegisterInfo {
        address: 0x0140,
        default_size: 2,
        name: "pdi-control",
        symbol: "ECT_REG_PDICTL",
        description: "PDI Control / Interface Type",
    },
    EscRegisterInfo {
        address: 0x0200,
        default_size: 2,
        name: "irq-mask",
        symbol: "ECT_REG_IRQMASK",
        description: "ECAT Event Mask",
    },
    EscRegisterInfo {
        address: 0x0210,
        default_size: 2,
        name: "ecat-event",
        symbol: "ECT_REG_ECATEVT",
        description: "ECAT Event Request",
    },
    EscRegisterInfo {
        address: 0x0300,
        default_size: 8,
        name: "rx-err",
        symbol: "ECT_REG_RXERR",
        description: "RX Error Counters (Ports 0..3 Frame/Physical)",
    },
    EscRegisterInfo {
        address: 0x0308,
        default_size: 4,
        name: "fwd-rx-err",
        symbol: "ECT_REG_FRXERR",
        description: "Forwarded RX Error Counters (Ports 0..3)",
    },
    EscRegisterInfo {
        address: 0x030C,
        default_size: 1,
        name: "epu-err",
        symbol: "ECT_REG_EPUECNT",
        description: "ECAT Processing Unit Error Counter",
    },
    EscRegisterInfo {
        address: 0x030D,
        default_size: 1,
        name: "pdi-err",
        symbol: "ECT_REG_PECNT",
        description: "PDI Error Counter",
    },
    EscRegisterInfo {
        address: 0x0310,
        default_size: 4,
        name: "lost-link",
        symbol: "ECT_REG_LLCNT",
        description: "Lost Link Counters (Ports 0..3)",
    },
    EscRegisterInfo {
        address: 0x0400,
        default_size: 2,
        name: "wd-divider",
        symbol: "ECT_REG_WDDIV",
        description: "Watchdog Divider",
    },
    EscRegisterInfo {
        address: 0x0410,
        default_size: 2,
        name: "wd-time-pdi",
        symbol: "ECT_REG_WDTPDI",
        description: "Watchdog Time PDI",
    },
    EscRegisterInfo {
        address: 0x0420,
        default_size: 2,
        name: "wd-time-pdata",
        symbol: "ECT_REG_WDTPDATA",
        description: "Watchdog Time Process Data",
    },
    EscRegisterInfo {
        address: 0x0440,
        default_size: 2,
        name: "wd-status",
        symbol: "ECT_REG_WDSTAT",
        description: "Watchdog Status Process Data",
    },
    EscRegisterInfo {
        address: 0x0442,
        default_size: 2,
        name: "wd-counter",
        symbol: "ECT_REG_WDCNT",
        description: "Watchdog Counter Process Data / PDI",
    },
    EscRegisterInfo {
        address: 0x0500,
        default_size: 2,
        name: "eep-cfg",
        symbol: "ECT_REG_EEPCFG",
        description: "SII EEPROM Configuration & PDI Access State",
    },
    EscRegisterInfo {
        address: 0x0502,
        default_size: 2,
        name: "eep-stat",
        symbol: "ECT_REG_EEPSTAT",
        description: "SII EEPROM Control/Status",
    },
    EscRegisterInfo {
        address: 0x0504,
        default_size: 4,
        name: "eep-addr",
        symbol: "ECT_REG_EEPADR",
        description: "SII EEPROM Word Address",
    },
    EscRegisterInfo {
        address: 0x0508,
        default_size: 8,
        name: "eep-data",
        symbol: "ECT_REG_EEPDAT",
        description: "SII EEPROM Data Buffer (4 or 8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0600,
        default_size: 16,
        name: "fmmu0",
        symbol: "ECT_REG_FMMU0",
        description: "FMMU 0 Configuration (16 bytes)",
    },
    EscRegisterInfo {
        address: 0x0610,
        default_size: 16,
        name: "fmmu1",
        symbol: "ECT_REG_FMMU1",
        description: "FMMU 1 Configuration (16 bytes)",
    },
    EscRegisterInfo {
        address: 0x0620,
        default_size: 16,
        name: "fmmu2",
        symbol: "ECT_REG_FMMU2",
        description: "FMMU 2 Configuration (16 bytes)",
    },
    EscRegisterInfo {
        address: 0x0630,
        default_size: 16,
        name: "fmmu3",
        symbol: "ECT_REG_FMMU3",
        description: "FMMU 3 Configuration (16 bytes)",
    },
    EscRegisterInfo {
        address: 0x0800,
        default_size: 8,
        name: "sm0",
        symbol: "ECT_REG_SM0",
        description: "SyncManager 0 (Write Mailbox / Outputs, 8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0805,
        default_size: 1,
        name: "sm0-stat",
        symbol: "ECT_REG_SM0STAT",
        description: "SyncManager 0 Status",
    },
    EscRegisterInfo {
        address: 0x0808,
        default_size: 8,
        name: "sm1",
        symbol: "ECT_REG_SM1",
        description: "SyncManager 1 (Read Mailbox / Inputs, 8 bytes)",
    },
    EscRegisterInfo {
        address: 0x080D,
        default_size: 1,
        name: "sm1-stat",
        symbol: "ECT_REG_SM1STAT",
        description: "SyncManager 1 Status",
    },
    EscRegisterInfo {
        address: 0x0810,
        default_size: 8,
        name: "sm2",
        symbol: "ECT_REG_SM2",
        description: "SyncManager 2 (Process Data Outputs, 8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0818,
        default_size: 8,
        name: "sm3",
        symbol: "ECT_REG_SM3",
        description: "SyncManager 3 (Process Data Inputs, 8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0820,
        default_size: 8,
        name: "sm4",
        symbol: "ECT_REG_SM4",
        description: "SyncManager 4 (8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0828,
        default_size: 8,
        name: "sm5",
        symbol: "ECT_REG_SM5",
        description: "SyncManager 5 (8 bytes)",
    },
    EscRegisterInfo {
        address: 0x0900,
        default_size: 4,
        name: "dc-time0",
        symbol: "ECT_REG_DCTIME0",
        description: "DC Receive Time Port 0 (ns)",
    },
    EscRegisterInfo {
        address: 0x0904,
        default_size: 4,
        name: "dc-time1",
        symbol: "ECT_REG_DCTIME1",
        description: "DC Receive Time Port 1 (ns)",
    },
    EscRegisterInfo {
        address: 0x0908,
        default_size: 4,
        name: "dc-time2",
        symbol: "ECT_REG_DCTIME2",
        description: "DC Receive Time Port 2 (ns)",
    },
    EscRegisterInfo {
        address: 0x090C,
        default_size: 4,
        name: "dc-time3",
        symbol: "ECT_REG_DCTIME3",
        description: "DC Receive Time Port 3 (ns)",
    },
    EscRegisterInfo {
        address: 0x0910,
        default_size: 8,
        name: "dc-systime",
        symbol: "ECT_REG_DCSYSTIME",
        description: "DC System Time (64-bit ns)",
    },
    EscRegisterInfo {
        address: 0x0918,
        default_size: 8,
        name: "dc-sof",
        symbol: "ECT_REG_DCSOF",
        description: "DC Receive Time ECAT Processing Unit",
    },
    EscRegisterInfo {
        address: 0x0920,
        default_size: 8,
        name: "dc-sysoffset",
        symbol: "ECT_REG_DCSYSOFFSET",
        description: "DC System Time Offset (64-bit ns)",
    },
    EscRegisterInfo {
        address: 0x0928,
        default_size: 4,
        name: "dc-sysdelay",
        symbol: "ECT_REG_DCSYSDELAY",
        description: "DC System Time Transmission Delay (ns)",
    },
    EscRegisterInfo {
        address: 0x092C,
        default_size: 4,
        name: "dc-sysdiff",
        symbol: "ECT_REG_DCSYSDIFF",
        description: "DC System Time Difference",
    },
    EscRegisterInfo {
        address: 0x0981,
        default_size: 1,
        name: "dc-sync-act",
        symbol: "ECT_REG_DCSYNCACT",
        description: "DC Cyclic Unit Activation (SYNC0/SYNC1)",
    },
    EscRegisterInfo {
        address: 0x0990,
        default_size: 8,
        name: "dc-start0",
        symbol: "ECT_REG_DCSTART0",
        description: "DC Start Time Cyclic Operation (ns)",
    },
    EscRegisterInfo {
        address: 0x09A0,
        default_size: 4,
        name: "dc-cycle0",
        symbol: "ECT_REG_DCCYCLE0",
        description: "DC SYNC0 Cycle Time (ns)",
    },
    EscRegisterInfo {
        address: 0x09A4,
        default_size: 4,
        name: "dc-cycle1",
        symbol: "ECT_REG_DCCYCLE1",
        description: "DC SYNC1 Cycle Time (ns)",
    },
];

pub fn lookup_esc_register_by_addr(addr: u16) -> Option<&'static EscRegisterInfo> {
    ESC_REGISTERS.iter().find(|r| r.address == addr)
}

pub fn resolve_esc_register(spec: &str) -> Result<(u16, Option<&'static EscRegisterInfo>)> {
    let raw_trim = spec.trim();
    let lower_hyph = raw_trim.to_ascii_lowercase().replace('_', "-");
    let alias_norm = match lower_hyph.as_str() {
        "dc-sys-time" => "dc-systime",
        "eep-ctl" | "eep-ctl-stat" => "eep-stat",
        other => other,
    };
    if let Some(info) = ESC_REGISTERS
        .iter()
        .find(|r| r.name == alias_norm || r.symbol.eq_ignore_ascii_case(raw_trim))
    {
        return Ok((info.address, Some(info)));
    }
    let addr = parse_u16(raw_trim).map_err(|e| {
        CliError::Format(format!(
            "unknown ESC register '{spec}' ({e}); use hex address like 0x0130 or run `reg list`"
        ))
    })?;
    Ok((addr, lookup_esc_register_by_addr(addr)))
}

/// EtherCAT AL State constants.
#[allow(dead_code)]
pub const EC_STATE_NONE: u16 = 0x00;
pub const EC_STATE_INIT: u16 = 0x01;
pub const EC_STATE_PRE_OP: u16 = 0x02;
pub const EC_STATE_BOOT: u16 = 0x03;
pub const EC_STATE_SAFE_OP: u16 = 0x04;
pub const EC_STATE_OPERATIONAL: u16 = 0x08;
pub const EC_STATE_ERROR: u16 = 0x10; // Error Ind (AL Status) or Error Ack (AL Control)

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AlStateSpec {
    /// 0x01: Init state (no mailbox, no PDO communication; SII & ESC register access allowed).
    Init,
    /// 0x02: Pre-Operational state (Mailbox/SDO active; no PDO communication).
    PreOp,
    /// 0x03: Bootstrap state (FoE firmware update mode).
    Boot,
    /// 0x04: Safe-Operational state (Mailbox + TxPDO inputs active; outputs remain in safe state).
    SafeOp,
    /// 0x08: Operational state (Mailbox + full RxPDO/TxPDO cyclic I/O active).
    Op,
}

impl AlStateSpec {
    pub fn code(self) -> u16 {
        match self {
            Self::Init => EC_STATE_INIT,
            Self::PreOp => EC_STATE_PRE_OP,
            Self::Boot => EC_STATE_BOOT,
            Self::SafeOp => EC_STATE_SAFE_OP,
            Self::Op => EC_STATE_OPERATIONAL,
        }
    }
}

pub fn al_state_name(raw_state: u16) -> String {
    let base = match raw_state & 0x0F {
        0x00 => "NONE",
        0x01 => "INIT",
        0x02 => "PRE-OP",
        0x03 => "BOOT",
        0x04 => "SAFE-OP",
        0x08 => "OP",
        _ => "UNKNOWN",
    };
    if (raw_state & EC_STATE_ERROR) != 0 {
        format!("{base}+ERR")
    } else {
        base.to_string()
    }
}

/// ETG.1000.6 AL Status Code description table.
pub fn al_status_code_description(code: u16) -> &'static str {
    match code {
        0x0000 => "No error",
        0x0001 => "Unspecified error",
        0x0002 => "No memory",
        0x0003 => "Invalid device setup",
        0x0004 => "Invalid revision",
        0x0006 => "SII/EEPROM information does not match firmware",
        0x0007 => "Firmware update not successful",
        0x000E => "License error",
        0x0011 => "Invalid requested state change",
        0x0012 => "Unknown requested state",
        0x0013 => "Bootstrap not supported",
        0x0014 => "No valid firmware",
        0x0015 => "Invalid mailbox configuration (Bootstrap)",
        0x0016 => "Invalid mailbox configuration (Pre-Op)",
        0x0017 => "Invalid sync manager configuration",
        0x0018 => "No valid inputs available",
        0x0019 => "No valid outputs",
        0x001A => "Synchronization error",
        0x001B => "Sync manager watchdog",
        0x001C => "Invalid Sync Manager Types",
        0x001D => "Invalid Output Configuration",
        0x001E => "Invalid Input Configuration",
        0x001F => "Invalid Watchdog Configuration",
        0x0020 => "Slave needs cold start",
        0x0021 => "Slave needs INIT",
        0x0022 => "Slave needs PREOP",
        0x0023 => "Slave needs SAFEOP",
        0x0024 => "Invalid Input Mapping",
        0x0025 => "Invalid Output Mapping",
        0x0026 => "Inconsistent Settings",
        0x0027 => "FreeRun not supported",
        0x0028 => "SyncMode not supported",
        0x0029 => "FreeRun needs 3Buffer Mode",
        0x002A => "Background Watchdog",
        0x002B => "No valid Inputs and Outputs",
        0x002C => "Fatal Sync Error",
        0x002D => "No Sync Error",
        0x002E => "Invalid DC SYNC Cycle Time",
        0x0030 => "Invalid DC Latch Configuration",
        0x0032 => "PLL Error",
        0x0033 => "DC Sync IO Error",
        0x0034 => "DC Sync Timeout Error",
        0x0035 => "DC Invalid Sync Cycle Time",
        0x0036 => "DC Sync0 Cycle Time",
        0x0037 => "DC Sync1 Cycle Time",
        0x0041 => "MBX_AOE",
        0x0042 => "MBX_EOE",
        0x0043 => "MBX_COE",
        0x0044 => "MBX_FOE",
        0x0045 => "MBX_SOE",
        0x004F => "MBX_VOE",
        0x0050 => "EEPROM no access",
        0x0051 => "EEPROM Error",
        0x0052 => "External hardware not ready",
        0x0060 => "Slave restarted locally",
        0x0061 => "Device Identification value updated",
        0x0070 => "Detected Module Ident List does not match",
        0x00F0 => "Application controller available",
        _ => "Vendor-specific or reserved AL status code",
    }
}

/// ETG.1000.6 / CiA 301 CoE SDO Abort Code description table.
pub fn sdo_abort_description(code: u32) -> &'static str {
    match code {
        0x0000_0000 => "No abort",
        0x0503_0000 => "Toggle bit not changed",
        0x0504_0000 => "SDO protocol timeout",
        0x0504_0001 => "Client/Server command specifier not valid or unknown",
        0x0504_0002 => "Invalid block size",
        0x0504_0003 => "Invalid sequence number",
        0x0504_0004 => "CRC error",
        0x0504_0005 => "Out of memory",
        0x0601_0000 => "Unsupported access to an object",
        0x0601_0001 => "Attempt to read a write-only object",
        0x0601_0002 => "Attempt to write to a read-only object",
        0x0601_0003 => "Subindex cannot be written, SI0 must be 0 for write access",
        0x0601_0004 => "SDO Complete Access not supported for variable length objects",
        0x0601_0005 => "Object length exceeds mailbox size",
        0x0601_0006 => "Object mapped to RxPDO, SDO download blocked",
        0x0602_0000 => "The object does not exist in the object dictionary",
        0x0604_0041 => "The object cannot be mapped into the PDO",
        0x0604_0042 => "The number and length of the objects to be mapped would exceed the PDO length",
        0x0604_0043 => "General parameter incompatibility reason",
        0x0604_0047 => "General internal incompatibility in the device",
        0x0606_0000 => "Access failed due to a hardware error",
        0x0607_0010 => "Data type does not match, length of service parameter does not match",
        0x0607_0012 => "Data type does not match, length of service parameter too high",
        0x0607_0013 => "Data type does not match, length of service parameter too low",
        0x0609_0011 => "Subindex does not exist",
        0x0609_0030 => "Value range of parameter exceeded",
        0x0609_0031 => "Value of parameter written too high",
        0x0609_0032 => "Value of parameter written too low",
        0x0609_0036 => "Maximum value is less than minimum value",
        0x0800_0000 => "General error",
        0x0800_0020 => "Data cannot be transferred or stored to the application",
        0x0800_0021 => "Data cannot be transferred or stored to the application because of local control",
        0x0800_0022 => "Data cannot be transferred or stored to the application because of the present device state",
        0x0800_0023 => "Object dictionary dynamic generation fails or no object dictionary is present",
        _ => "Unknown or vendor-specific SDO abort code",
    }
}

pub fn ect_datatype_name(code: u16) -> &'static str {
    match code {
        0x0000 => "NONE",
        0x0001 => "BOOLEAN",
        0x0002 => "INTEGER8",
        0x0003 => "INTEGER16",
        0x0004 => "INTEGER32",
        0x0005 => "UNSIGNED8",
        0x0006 => "UNSIGNED16",
        0x0007 => "UNSIGNED32",
        0x0008 => "REAL32",
        0x0009 => "VISIBLE_STRING",
        0x000A => "OCTET_STRING",
        0x000B => "UNICODE_STRING",
        0x000C => "TIME_OF_DAY",
        0x000D => "TIME_DIFFERENCE",
        0x000F => "DOMAIN",
        0x0010 => "INTEGER24",
        0x0011 => "REAL64",
        0x0012 => "INTEGER40",
        0x0013 => "INTEGER48",
        0x0014 => "INTEGER56",
        0x0015 => "INTEGER64",
        0x0016 => "UNSIGNED24",
        0x0018 => "UNSIGNED40",
        0x0019 => "UNSIGNED48",
        0x001A => "UNSIGNED56",
        0x001B => "UNSIGNED64",
        0x001D => "GUID",
        0x001E => "BYTE",
        0x001F => "WORD",
        0x0020 => "DWORD",
        0x002D => "BITARR8",
        0x002E => "BITARR16",
        0x002F => "BITARR32",
        0x0030 => "BIT1",
        0x0031 => "BIT2",
        0x0032 => "BIT3",
        0x0033 => "BIT4",
        0x0034 => "BIT5",
        0x0035 => "BIT6",
        0x0036 => "BIT7",
        0x0037 => "BIT8",
        _ => "CUSTOM_TYPE",
    }
}

pub fn mailbox_type_name(mbx_type: u8) -> &'static str {
    match mbx_type & 0x0F {
        0x00 => "ERR",
        0x01 => "AoE",
        0x02 => "EoE",
        0x03 => "CoE",
        0x04 => "FoE",
        0x05 => "SoE",
        0x0F => "VoE",
        _ => "Reserved",
    }
}

pub fn coe_service_name(svc: u8) -> &'static str {
    match svc {
        0x01 => "Emergency",
        0x02 => "SDO Request",
        0x03 => "SDO Response",
        0x04 => "TxPDO",
        0x05 => "RxPDO",
        0x06 => "TxPDO Remote Request",
        0x07 => "RxPDO Remote Request",
        0x08 => "SDO Information",
        _ => "Reserved",
    }
}
