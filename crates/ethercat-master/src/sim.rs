use std::collections::{BTreeMap, VecDeque};
use std::path::Path;
use std::time::Duration;

use ethercat_eeprom::esi::{
    compile_esi_device_to_sii, load_esi_catalog, parse_esi_bool, parse_esi_u64, select_esi_device,
    EsiCompileOptions, EsiDevice,
};
use ethercat_eeprom::sii::image::{parse_sii_image, sii_crc8, sii_le16, sii_le32, SiiBuildProfile};
use ethercat_wire::error::{CliError, Result};
use ethercat_wire::protocol::constants::{
    EcatCmd, EC_STATE_BOOT, EC_STATE_ERROR, EC_STATE_INIT, EC_STATE_OPERATIONAL, EC_STATE_PRE_OP,
    EC_STATE_SAFE_OP, ETH_HEADER_LEN, ETH_P_ECAT, MIN_ETHERNET_FRAME_LEN,
};
use ethercat_wire::protocol::frame::{parse_dlpdu_datagrams, EcatFrameBuilder, RawDatagram};
use ethercat_wire::transport::EthercatTransport;
use ethercat_wire::types::{extract_bits_le, insert_bits_le};

#[derive(Debug, Clone)]
struct OdEntry {
    datatype: u16,
    bit_len: u16,
    access: u16, // 0x0007 = R/O all states, 0x003F = R/W all states
    name: String,
    data: Vec<u8>,
    writable: bool,
}

#[derive(Debug, Clone)]
struct OdObject {
    datatype: u16,
    object_code: u8, // 7=VAR, 8=ARRAY, 9=RECORD
    name: String,
    entries: BTreeMap<u8, OdEntry>,
}

#[derive(Debug, Clone)]
struct PendingSdoUpload {
    index: u16,
    subindex: u8,
    data: Vec<u8>,
    offset: usize,
    expect_toggle: bool,
}

#[derive(Debug, Clone)]
struct PendingSdoDownload {
    index: u16,
    subindex: u8,
    complete_access: bool,
    expected_len: usize,
    buf: Vec<u8>,
    expect_toggle: bool,
}

struct SimSlave {
    regs: Vec<u8>, // 0x0000..0x2000 physical ESC + DPRAM space
    eeprom: Vec<u8>,
    od: BTreeMap<u16, OdObject>,
    mbx_out_queue: VecDeque<Vec<u8>>, // Slave -> Master (SM1)
    sdo_upload: Option<PendingSdoUpload>,
    sdo_download: Option<PendingSdoDownload>,
    injected_sm0_replies: Option<(Vec<Vec<u8>>, bool)>,
}

impl SimSlave {
    fn new_servo_402() -> Self {
        let eeprom = build_servo_402_sii();
        let mut sl = Self::from_eeprom(eeprom);
        sl.populate_servo_402_od();
        sl
    }

    fn new_dio_terminal() -> Self {
        let eeprom = build_dio_sii();
        let mut sl = Self::from_eeprom(eeprom);
        sl.populate_dio_od();
        sl
    }

    fn from_eeprom(eeprom: Vec<u8>) -> Self {
        let mut regs = vec![0u8; 0x2000];
        // ESC Type = 0xC8, Revision = 0x02, Build = 0x0100, FMMUs = 4, SMs = 8, RAM = 8KB, Ports = MII
        regs[0x0000] = 0xC8;
        regs[0x0001] = 0x02;
        regs[0x0002..0x0004].copy_from_slice(&0x0100u16.to_le_bytes());
        regs[0x0004] = 4;
        regs[0x0005] = 8;
        regs[0x0006] = 8;
        regs[0x0007] = 0x0F;
        regs[0x0008..0x000A].copy_from_slice(&0x000Cu16.to_le_bytes()); // DC supported

        // Alias from EEPROM word 4 (bytes 0x08..0x0A)
        if eeprom.len() >= 0x0A {
            regs[0x0012..0x0014].copy_from_slice(&eeprom[0x08..0x0A]);
        }
        // DL Status: PDI operational + Port 0/1 link & signal
        regs[0x0110..0x0112].copy_from_slice(&0x0A31u16.to_le_bytes());
        // AL Control & AL Status = INIT (0x0001)
        regs[0x0120..0x0122].copy_from_slice(&EC_STATE_INIT.to_le_bytes());
        regs[0x0130..0x0132].copy_from_slice(&EC_STATE_INIT.to_le_bytes());
        if eeprom.len() >= 2 {
            regs[0x0140..0x0142].copy_from_slice(&eeprom[0x00..0x02]);
        } else {
            regs[0x0140..0x0142].copy_from_slice(&0x0005u16.to_le_bytes()); // PDI SPI
        }
        if eeprom.len() >= 4 {
            regs[0x0150..0x0152].copy_from_slice(&eeprom[0x02..0x04]);
        }
        if eeprom.len() >= 8 {
            regs[0x0152..0x0154].copy_from_slice(&eeprom[0x06..0x08]);
        }

        // EEPROM config: initially owned by PDI (0x0500=1, 0x0501=1) to exercise PDI claim/release!
        regs[0x0500] = 0x01;
        regs[0x0501] = 0x01;
        // EEPROM status: R64 supported (0x0040)
        regs[0x0502..0x0504].copy_from_slice(&0x0040u16.to_le_bytes());

        // Pre-populate SM0/SM1 from SII header standard mailbox fields if present
        if eeprom.len() >= 0x38 {
            let rx_off = sii_le16(&eeprom[0x30..0x32]);
            let rx_sz = sii_le16(&eeprom[0x32..0x34]);
            let tx_off = sii_le16(&eeprom[0x34..0x36]);
            let tx_sz = sii_le16(&eeprom[0x36..0x38]);
            if rx_sz > 0 {
                regs[0x0800..0x0802].copy_from_slice(&rx_off.to_le_bytes());
                regs[0x0802..0x0804].copy_from_slice(&rx_sz.to_le_bytes());
                regs[0x0804] = 0x26;
                regs[0x0806] = 0x01;
            }
            if tx_sz > 0 {
                regs[0x0808..0x080A].copy_from_slice(&tx_off.to_le_bytes());
                regs[0x080A..0x080C].copy_from_slice(&tx_sz.to_le_bytes());
                regs[0x080C] = 0x22;
                regs[0x080E] = 0x01;
            }
        }

        // Pre-populate SM2 (0x1100, 6B) and SM3 (0x1400, 6B) + initial TxPDO data
        regs[0x0810..0x0812].copy_from_slice(&0x1100u16.to_le_bytes());
        regs[0x0812..0x0814].copy_from_slice(&6u16.to_le_bytes());
        regs[0x0814] = 0x64;
        regs[0x0816] = 0x01;

        regs[0x0818..0x081A].copy_from_slice(&0x1400u16.to_le_bytes());
        regs[0x081A..0x081C].copy_from_slice(&6u16.to_le_bytes());
        regs[0x081C] = 0x20;
        regs[0x081E] = 0x01;

        // If SII Category 41 (SyncM) is present, override ESC 0x0800..0x0840 with exact SII SyncManagers
        if let Ok(decoded) = parse_sii_image(&eeprom) {
            if !decoded.categories.sync_managers.is_empty() {
                regs[0x0800..0x0840].fill(0);
                for (i, sm) in decoded.categories.sync_managers.iter().take(8).enumerate() {
                    let base = 0x0800 + i * 8;
                    regs[base..base + 2].copy_from_slice(&sm.physical_start_u16.to_le_bytes());
                    regs[base + 2..base + 4].copy_from_slice(&sm.length.to_le_bytes());
                    let creg = sm
                        .control_register
                        .strip_prefix("0x")
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                        .unwrap_or(0);
                    let en = sm
                        .enable_byte
                        .strip_prefix("0x")
                        .and_then(|h| u8::from_str_radix(h, 16).ok())
                        .unwrap_or(u8::from(sm.enabled));
                    regs[base + 4] = creg;
                    regs[base + 6] = en;
                }
            }
        }

        // Initial simulated TxPDO input buffer at 0x1400: Statusword=0x0637, ActualPosition=12500
        regs[0x1400..0x1402].copy_from_slice(&0x0637u16.to_le_bytes());
        regs[0x1402..0x1406].copy_from_slice(&12500i32.to_le_bytes());

        //DC system time
        regs[0x0910..0x0918].copy_from_slice(&1_000_000_000u64.to_le_bytes());

        Self {
            regs,
            eeprom,
            od: BTreeMap::new(),
            mbx_out_queue: VecDeque::new(),
            sdo_upload: None,
            sdo_download: None,
            injected_sm0_replies: None,
        }
    }

    fn from_esi_device(device: &EsiDevice, eeprom: Vec<u8>) -> Self {
        let rev = if eeprom.len() >= 0x1C {
            sii_le32(&eeprom[0x18..0x1C])
        } else {
            device.revision_number
        };
        let serial = if eeprom.len() >= 0x20 {
            sii_le32(&eeprom[0x1C..0x20])
        } else {
            device.serial_number
        };
        let mut sl = Self::from_eeprom(eeprom);

        // Populate CoE OD from ESI Device (0x1000, 0x1008, 0x1018, 0x1C00)
        let dev_type = device.profile_numbers.first().copied().unwrap_or(5001);
        sl.insert_var(
            0x1000,
            0x0007,
            32,
            "Device Type",
            &dev_type.to_le_bytes(),
            false,
        );
        let name_bytes = device.device_name.as_bytes();
        sl.insert_var(
            0x1008,
            0x0009,
            (name_bytes.len().max(1) * 8).min(u16::MAX as usize) as u16,
            "Manufacturer Device Name",
            name_bytes,
            false,
        );

        let mut id_entries = BTreeMap::new();
        id_entries.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SubIndex 000".into(),
                data: vec![4],
                writable: false,
            },
        );
        id_entries.insert(
            1,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Vendor ID".into(),
                data: device.vendor_id.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            2,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Product Code".into(),
                data: device.product_code.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            3,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Revision Number".into(),
                data: rev.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            4,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Serial Number".into(),
                data: serial.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        sl.od.insert(
            0x1018,
            OdObject {
                datatype: 0x0023,
                object_code: 9,
                name: "Identity Object".into(),
                entries: id_entries,
            },
        );

        if !device.sync_managers.is_empty() {
            let mut sm_comm = BTreeMap::new();
            let sm_cnt = device.sync_managers.len().min(32) as u8;
            sm_comm.insert(
                0,
                OdEntry {
                    datatype: 0x0005,
                    bit_len: 8,
                    access: 0x07,
                    name: "Number of used SyncManager channels".into(),
                    data: vec![sm_cnt],
                    writable: false,
                },
            );
            for (idx, sm) in device.sync_managers.iter().take(32).enumerate() {
                sm_comm.insert(
                    (idx + 1) as u8,
                    OdEntry {
                        datatype: 0x0005,
                        bit_len: 8,
                        access: 0x07,
                        name: format!("SM{idx} {}", sm.sm_type_name),
                        data: vec![sm.sm_type_code],
                        writable: false,
                    },
                );
            }
            sl.od.insert(
                0x1C00,
                OdObject {
                    datatype: 0x0005,
                    object_code: 8,
                    name: "Sync Manager Communication Type".into(),
                    entries: sm_comm,
                },
            );
        }

        sl
    }

    fn populate_servo_402_od(&mut self) {
        self.insert_var(
            0x1000,
            0x0007,
            32,
            "Device Type",
            &0x0002_0192u32.to_le_bytes(),
            false,
        );
        self.insert_var(
            0x1008,
            0x0009,
            96,
            "Manufacturer Device Name",
            b"EC-SERVO-402",
            false,
        );
        self.insert_var(
            0x1009,
            0x0009,
            32,
            "Manufacturer Hardware Version",
            b"v1.0",
            false,
        );
        self.insert_var(
            0x100A,
            0x0009,
            320,
            "Manufacturer Software Version",
            b"2.4.0-ethercat-sim-segmented-firmware-id",
            false,
        );

        // 0x1018 Identity Object
        let mut id_entries = BTreeMap::new();
        id_entries.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SubIndex 000".into(),
                data: vec![4],
                writable: false,
            },
        );
        id_entries.insert(
            1,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Vendor ID".into(),
                data: 0x0000_0931u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            2,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Product Code".into(),
                data: 0x0000_0402u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            3,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Revision".into(),
                data: 0x0001_0000u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        id_entries.insert(
            4,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Serial Number".into(),
                data: 0x2026_0001u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        self.od.insert(
            0x1018,
            OdObject {
                datatype: 0x0023,
                object_code: 9,
                name: "Identity Object".into(),
                entries: id_entries,
            },
        );

        // 0x1600 RxPDO Mapping: 0x6040:00 (16b) + 0x607A:00 (32b)
        let mut rx_map = BTreeMap::new();
        rx_map.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "Number of Entries".into(),
                data: vec![2],
                writable: false,
            },
        );
        rx_map.insert(
            1,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Controlword Mapping".into(),
                data: 0x6040_0010u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        rx_map.insert(
            2,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Target Position Mapping".into(),
                data: 0x607A_0020u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        self.od.insert(
            0x1600,
            OdObject {
                datatype: 0x0021,
                object_code: 9,
                name: "Receive PDO Mapping 1".into(),
                entries: rx_map,
            },
        );

        // 0x1A00 TxPDO Mapping: 0x6041:00 (16b) + 0x6064:00 (32b)
        let mut tx_map = BTreeMap::new();
        tx_map.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "Number of Entries".into(),
                data: vec![2],
                writable: false,
            },
        );
        tx_map.insert(
            1,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Statusword Mapping".into(),
                data: 0x6041_0010u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        tx_map.insert(
            2,
            OdEntry {
                datatype: 0x0007,
                bit_len: 32,
                access: 0x07,
                name: "Actual Position Mapping".into(),
                data: 0x6064_0020u32.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        self.od.insert(
            0x1A00,
            OdObject {
                datatype: 0x0021,
                object_code: 9,
                name: "Transmit PDO Mapping 1".into(),
                entries: tx_map,
            },
        );

        // 0x1C00 SM Communication Type
        let mut sm_comm = BTreeMap::new();
        sm_comm.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SubIndex 000".into(),
                data: vec![4],
                writable: false,
            },
        );
        sm_comm.insert(
            1,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SM0 Mailbox Out".into(),
                data: vec![1],
                writable: false,
            },
        );
        sm_comm.insert(
            2,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SM1 Mailbox In".into(),
                data: vec![2],
                writable: false,
            },
        );
        sm_comm.insert(
            3,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SM2 Process Data Out".into(),
                data: vec![3],
                writable: false,
            },
        );
        sm_comm.insert(
            4,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SM3 Process Data In".into(),
                data: vec![4],
                writable: false,
            },
        );
        self.od.insert(
            0x1C00,
            OdObject {
                datatype: 0x0005,
                object_code: 8,
                name: "Sync Manager Communication Type".into(),
                entries: sm_comm,
            },
        );

        // 0x1C12 RxPDO Assign & 0x1C13 TxPDO Assign
        let mut rx_assign = BTreeMap::new();
        rx_assign.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "Count".into(),
                data: vec![1],
                writable: false,
            },
        );
        rx_assign.insert(
            1,
            OdEntry {
                datatype: 0x0006,
                bit_len: 16,
                access: 0x07,
                name: "PDO 1".into(),
                data: 0x1600u16.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        self.od.insert(
            0x1C12,
            OdObject {
                datatype: 0x0006,
                object_code: 8,
                name: "Sync Manager 2 PDO Assignment".into(),
                entries: rx_assign,
            },
        );

        let mut tx_assign = BTreeMap::new();
        tx_assign.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "Count".into(),
                data: vec![1],
                writable: false,
            },
        );
        tx_assign.insert(
            1,
            OdEntry {
                datatype: 0x0006,
                bit_len: 16,
                access: 0x07,
                name: "PDO 1".into(),
                data: 0x1A00u16.to_le_bytes().to_vec(),
                writable: false,
            },
        );
        self.od.insert(
            0x1C13,
            OdObject {
                datatype: 0x0006,
                object_code: 8,
                name: "Sync Manager 3 PDO Assignment".into(),
                entries: tx_assign,
            },
        );

        // CiA-402 Objects
        self.insert_var(
            0x6040,
            0x0006,
            16,
            "Controlword",
            &0x000Fu16.to_le_bytes(),
            true,
        );
        self.insert_var(
            0x6041,
            0x0006,
            16,
            "Statusword",
            &0x0637u16.to_le_bytes(),
            false,
        );
        self.insert_var(0x6060, 0x0002, 8, "Modes of Operation", &[8u8], true);
        self.insert_var(
            0x6064,
            0x0004,
            32,
            "Position Actual Value",
            &12500i32.to_le_bytes(),
            false,
        );
        self.insert_var(
            0x607A,
            0x0004,
            32,
            "Target Position",
            &12500i32.to_le_bytes(),
            true,
        );
        self.insert_var(
            0x60FD,
            0x0007,
            32,
            "Digital Inputs",
            &0x0001_0000u32.to_le_bytes(),
            false,
        );

        // Manufacturer / User writable objects for segmented & Complete Access SDO testing
        self.insert_var(
            0x2000,
            0x0009,
            1280,
            "User Parameter Buffer",
            b"initial-user-parameter-buffer",
            true,
        );
        let mut cal_arr = BTreeMap::new();
        cal_arr.insert(
            0,
            OdEntry {
                datatype: 0x0005,
                bit_len: 8,
                access: 0x07,
                name: "SubIndex 000".into(),
                data: vec![3],
                writable: false,
            },
        );
        for s in 1..=3u8 {
            cal_arr.insert(
                s,
                OdEntry {
                    datatype: 0x0006,
                    bit_len: 16,
                    access: 0x3F,
                    name: format!("Calibration Gain {s}"),
                    data: ((s as u16) * 100).to_le_bytes().to_vec(),
                    writable: true,
                },
            );
        }
        self.od.insert(
            0x2001,
            OdObject {
                datatype: 0x0006,
                object_code: 8,
                name: "User Calibration Array".into(),
                entries: cal_arr,
            },
        );
    }

    fn populate_dio_od(&mut self) {
        self.insert_var(
            0x1000,
            0x0007,
            32,
            "Device Type",
            &0x000F_0191u32.to_le_bytes(),
            false,
        );
        self.insert_var(
            0x1008,
            0x0009,
            64,
            "Manufacturer Device Name",
            b"PC-1000",
            false,
        );
    }

    fn insert_var(
        &mut self,
        index: u16,
        datatype: u16,
        bit_len: u16,
        name: &str,
        data: &[u8],
        writable: bool,
    ) {
        let mut entries = BTreeMap::new();
        entries.insert(
            0,
            OdEntry {
                datatype,
                bit_len,
                access: if writable { 0x003F } else { 0x0007 },
                name: name.to_string(),
                data: data.to_vec(),
                writable,
            },
        );
        self.od.insert(
            index,
            OdObject {
                datatype,
                object_code: 7,
                name: name.to_string(),
                entries,
            },
        );
    }

    fn station_addr(&self) -> u16 {
        u16::from_le_bytes([self.regs[0x0010], self.regs[0x0011]])
    }

    fn matches_configured_addr(&self, adp: u16) -> bool {
        if adp != 0 && self.station_addr() == adp {
            return true;
        }
        if self.regs[0x0103] != 0 {
            let alias = u16::from_le_bytes([self.regs[0x0012], self.regs[0x0013]]);
            if adp != 0 && alias == adp {
                return true;
            }
        }
        false
    }

    fn sm0_bounds(&self) -> (usize, usize) {
        let start = u16::from_le_bytes([self.regs[0x0800], self.regs[0x0801]]) as usize;
        let len = u16::from_le_bytes([self.regs[0x0802], self.regs[0x0803]]) as usize;
        (start, len)
    }

    fn sm1_bounds(&self) -> (usize, usize) {
        let start = u16::from_le_bytes([self.regs[0x0808], self.regs[0x0809]]) as usize;
        let len = u16::from_le_bytes([self.regs[0x080A], self.regs[0x080B]]) as usize;
        (start, len)
    }

    fn refresh_sm1_buffer(&mut self) {
        let (sm1_start, sm1_len) = self.sm1_bounds();
        if let Some(front) = self.mbx_out_queue.front() {
            if sm1_start > 0 && sm1_start + sm1_len <= self.regs.len() {
                for b in &mut self.regs[sm1_start..sm1_start + sm1_len] {
                    *b = 0;
                }
                let n = front.len().min(sm1_len);
                self.regs[sm1_start..sm1_start + n].copy_from_slice(&front[..n]);
            }
            self.regs[0x080D] |= 0x08; // SM1 status: mailbox full (response ready)
        } else {
            self.regs[0x080D] &= !0x08;
        }
    }

    fn read_physical(&mut self, ado: u16, len: usize) -> Vec<u8> {
        let start = ado as usize;
        self.refresh_sm1_buffer();
        let mut out = vec![0u8; len];
        if start < self.regs.len() {
            let end = (start + len).min(self.regs.len());
            out[..end - start].copy_from_slice(&self.regs[start..end]);
        }
        // If master read SM1 mailbox buffer completely, pop the queued response!
        let (sm1_start, sm1_len) = self.sm1_bounds();
        if sm1_len > 0 && start == sm1_start && len >= 6 && !self.mbx_out_queue.is_empty() {
            self.mbx_out_queue.pop_front();
            self.refresh_sm1_buffer();
        }
        out
    }

    fn write_physical(&mut self, ado: u16, data: &[u8]) {
        let start = ado as usize;
        if start + data.len() > self.regs.len() {
            return;
        }
        self.regs[start..start + data.len()].copy_from_slice(data);

        // Side-effect 1: AL Control (0x0120) -> transition AL Status (0x0130)
        if start <= 0x0120 && start + data.len() >= 0x0122 {
            let req = u16::from_le_bytes([self.regs[0x0120], self.regs[0x0121]]);
            let target = req & 0x0F;
            let ack = (req & EC_STATE_ERROR) != 0;
            if matches!(
                target,
                EC_STATE_INIT
                    | EC_STATE_PRE_OP
                    | EC_STATE_BOOT
                    | EC_STATE_SAFE_OP
                    | EC_STATE_OPERATIONAL
            ) {
                self.regs[0x0130..0x0132].copy_from_slice(&target.to_le_bytes());
                if ack {
                    self.regs[0x0134..0x0136].copy_from_slice(&0u16.to_le_bytes());
                }
            } else {
                let err_st = (self.regs[0x0130] as u16 & 0x0F) | EC_STATE_ERROR;
                self.regs[0x0130..0x0132].copy_from_slice(&err_st.to_le_bytes());
                self.regs[0x0134..0x0136].copy_from_slice(&0x0012u16.to_le_bytes());
                // Unknown requested state
            }
        }

        // Side-effect 2: EEPROM Config (0x0500)
        if start == 0x0500 && !data.is_empty() {
            let v = data[0];
            if (v & 0x02) != 0 || v == 0 {
                self.regs[0x0501] = 0x00; // Handed over to ECAT
            } else if (v & 0x01) != 0 {
                self.regs[0x0501] = 0x01; // Returned to PDI
            }
        }

        // Side-effect 3: EEPROM Control/Status + Address (0x0502..0x0508)
        if start <= 0x0502 && start + data.len() >= 0x0504 {
            let ctl = u16::from_le_bytes([self.regs[0x0502], self.regs[0x0503]]);
            let word_addr = u32::from_le_bytes([
                self.regs[0x0504],
                self.regs[0x0505],
                self.regs[0x0506],
                self.regs[0x0507],
            ]) as usize;
            let cmd_bits = (ctl >> 8) & 0x07;
            match cmd_bits {
                1 => {
                    // READ 8 bytes into 0x0508..0x0510
                    let byte_off = word_addr.saturating_mul(2);
                    for i in 0..8 {
                        self.regs[0x0508 + i] = byte_off
                            .checked_add(i)
                            .and_then(|off| self.eeprom.get(off).copied())
                            .unwrap_or(0xFF);
                    }
                    self.regs[0x0502..0x0504].copy_from_slice(&0x0040u16.to_le_bytes());
                }
                2 if (ctl & 0x0001) != 0 => {
                    // WRITE 2 bytes from 0x0508..0x050A into EEPROM
                    let byte_off = word_addr.saturating_mul(2);
                    if let Some(end_off) = byte_off.checked_add(2) {
                        if end_off > self.eeprom.len() && end_off <= 524_288 {
                            self.eeprom.resize(end_off, 0xFF);
                        }
                        if end_off <= self.eeprom.len() {
                            self.eeprom[byte_off] = self.regs[0x0508];
                            self.eeprom[byte_off + 1] = self.regs[0x0509];
                            self.regs[0x0502..0x0504].copy_from_slice(&0x0040u16.to_le_bytes());
                        } else {
                            self.regs[0x0502..0x0504].copy_from_slice(&0x2040u16.to_le_bytes());
                            // NACK
                        }
                    } else {
                        self.regs[0x0502..0x0504].copy_from_slice(&0x2040u16.to_le_bytes());
                    }
                }
                4 => {
                    // RELOAD PDI Control (0x0140), PDI Configuration (0x0150), and Station Alias (0x0012)
                    if self.eeprom.len() >= 2 {
                        self.regs[0x0140..0x0142].copy_from_slice(&self.eeprom[0x00..0x02]);
                    }
                    if self.eeprom.len() >= 4 {
                        self.regs[0x0150..0x0152].copy_from_slice(&self.eeprom[0x02..0x04]);
                    }
                    if self.eeprom.len() >= 8 {
                        self.regs[0x0152..0x0154].copy_from_slice(&self.eeprom[0x06..0x08]);
                    }
                    if self.eeprom.len() >= 0x0A {
                        self.regs[0x0012..0x0014].copy_from_slice(&self.eeprom[0x08..0x0A]);
                    }
                    self.regs[0x0502..0x0504].copy_from_slice(&0x0040u16.to_le_bytes());
                }
                _ => {
                    self.regs[0x0502..0x0504].copy_from_slice(&0x0040u16.to_le_bytes());
                }
            }
        }

        // Side-effect 4: RxPDO Output write at 0x1100 updates mirroredservo TargetPosition -> ActualPosition
        if start == 0x1100 && data.len() >= 6 {
            let cw = u16::from_le_bytes([data[0], data[1]]);
            let target_pos = i32::from_le_bytes([data[2], data[3], data[4], data[5]]);
            if let Some(obj) = self.od.get_mut(&0x6040) {
                if let Some(e) = obj.entries.get_mut(&0) {
                    e.data = cw.to_le_bytes().to_vec();
                }
            }
            if let Some(obj) = self.od.get_mut(&0x607A) {
                if let Some(e) = obj.entries.get_mut(&0) {
                    e.data = target_pos.to_le_bytes().to_vec();
                }
            }
            // Mirror into TxPDO input buffer (0x1400) so cyclic exchange is observable
            self.regs[0x1402..0x1406].copy_from_slice(&target_pos.to_le_bytes());
            if let Some(obj) = self.od.get_mut(&0x6064) {
                if let Some(e) = obj.entries.get_mut(&0) {
                    e.data = target_pos.to_le_bytes().to_vec();
                }
            }
        }

        // Side-effect 5: SM0 Write Mailbox (Master -> Slave)
        let (sm0_start, sm0_len) = self.sm0_bounds();
        if sm0_len >= 16 && start == sm0_start && data.len() >= 6 {
            self.handle_mailbox_write(data);
            self.refresh_sm1_buffer();
        }
    }

    fn handle_mailbox_write(&mut self, mbx: &[u8]) {
        if let Some((frames, suppress_normal)) = self.injected_sm0_replies.take() {
            for f in frames {
                self.mbx_out_queue.push_back(f);
            }
            if suppress_normal {
                return;
            }
        }
        let len = u16::from_le_bytes([mbx[0], mbx[1]]) as usize;
        if 6 + len > mbx.len() || len < 2 {
            return;
        }
        let mbx_type = mbx[5] & 0x0F;
        let cnt = (mbx[5] >> 4) & 0x07;
        let body = &mbx[6..6 + len];
        if mbx_type == 0x03 && body.len() >= 2 {
            let coe_hdr = u16::from_le_bytes([body[0], body[1]]);
            let svc = ((coe_hdr >> 12) & 0x0F) as u8;
            let payload = &body[2..];
            match svc {
                0x02 => self.handle_coe_sdo_req(cnt, payload),
                0x08 => self.handle_coe_sdo_info_req(cnt, payload),
                _ => self.push_mbx_error(cnt, 0x0001, 0x0004),
            }
        } else {
            self.push_mbx_error(cnt, 0x0001, 0x0002);
        }
    }

    fn push_mbx_error(&mut self, cnt: u8, err_type: u16, detail: u16) {
        let mut resp = Vec::with_capacity(10);
        resp.extend_from_slice(&4u16.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.push(0x00);
        resp.push((cnt & 0x07) << 4); // mbx_type = 0x00 (ERR)
        resp.extend_from_slice(&err_type.to_le_bytes());
        resp.extend_from_slice(&detail.to_le_bytes());
        self.mbx_out_queue.push_back(resp);
    }

    fn push_coe_response(&mut self, cnt: u8, service: u8, payload: &[u8]) {
        let body_len = (2 + payload.len()) as u16;
        let mut resp = Vec::with_capacity(6 + body_len as usize);
        resp.extend_from_slice(&body_len.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());
        resp.push(0x00);
        resp.push(0x03 | ((cnt & 0x07) << 4));
        let coe_hdr: u16 = (service as u16) << 12;
        resp.extend_from_slice(&coe_hdr.to_le_bytes());
        resp.extend_from_slice(payload);
        self.mbx_out_queue.push_back(resp);
    }

    fn push_sdo_abort(&mut self, cnt: u8, index: u16, subindex: u8, abort_code: u32) {
        let mut p = Vec::with_capacity(8);
        p.push(0x80);
        p.extend_from_slice(&index.to_le_bytes());
        p.push(subindex);
        p.extend_from_slice(&abort_code.to_le_bytes());
        self.push_coe_response(cnt, 0x03, &p);
    }

    fn handle_coe_sdo_req(&mut self, cnt: u8, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        let cmd = payload[0];
        let ccs = (cmd >> 5) & 0x07;

        // Upload Segment Request (ccs == 3)
        if ccs == 3 {
            let toggle = (cmd & 0x10) != 0;
            let Some(mut up) = self.sdo_upload.take() else {
                self.push_sdo_abort(cnt, 0, 0, 0x0504_0001);
                return;
            };
            if toggle != up.expect_toggle {
                self.push_sdo_abort(cnt, up.index, up.subindex, 0x0503_0000);
                return;
            }
            let (_, sm1_len) = self.sm1_bounds();
            let max_seg = sm1_len.saturating_sub(9).max(7);
            let rem = &up.data[up.offset..];
            let chunk_len = rem.len().min(max_seg);
            let is_last = up.offset + chunk_len >= up.data.len();

            let mut resp = Vec::new();
            let mut scs_byte = if toggle { 0x10 } else { 0x00 };
            if is_last {
                scs_byte |= 0x01;
                if chunk_len < 7 {
                    let unused = (7 - chunk_len) as u8;
                    scs_byte |= unused << 1;
                }
            }
            resp.push(scs_byte);
            resp.extend_from_slice(&rem[..chunk_len]);
            if resp.len() < 8 {
                resp.resize(8, 0);
            }
            self.push_coe_response(cnt, 0x03, &resp);
            if !is_last {
                up.offset += chunk_len;
                up.expect_toggle = !up.expect_toggle;
                self.sdo_upload = Some(up);
            }
            return;
        }

        // Download Segment Request (ccs == 0)
        if ccs == 0 {
            let toggle = (cmd & 0x10) != 0;
            let last_seg = (cmd & 0x01) != 0;
            let unused = ((cmd >> 1) & 0x07) as usize;
            let Some(mut dl) = self.sdo_download.take() else {
                self.push_sdo_abort(cnt, 0, 0, 0x0504_0001);
                return;
            };
            if toggle != dl.expect_toggle {
                self.push_sdo_abort(cnt, dl.index, dl.subindex, 0x0503_0000);
                return;
            }
            let raw_seg = &payload[1..];
            let valid = if last_seg && raw_seg.len() == 7 {
                raw_seg.len().saturating_sub(unused)
            } else {
                raw_seg.len()
            };
            let take = valid.min(dl.expected_len.saturating_sub(dl.buf.len()));
            dl.buf.extend_from_slice(&raw_seg[..take]);

            if last_seg {
                if let Err(abort) =
                    self.commit_sdo_write(dl.index, dl.subindex, dl.complete_access, &dl.buf)
                {
                    self.push_sdo_abort(cnt, dl.index, dl.subindex, abort);
                    return;
                }
            } else {
                dl.expect_toggle = !dl.expect_toggle;
                self.sdo_download = Some(dl);
            }
            let mut resp = vec![0u8; 8];
            resp[0] = 0x20 | if toggle { 0x10 } else { 0x00 };
            self.push_coe_response(cnt, 0x03, &resp);
            return;
        }

        if payload.len() < 4 {
            return;
        }
        let index = u16::from_le_bytes([payload[1], payload[2]]);
        let subindex = payload[3];
        let complete_access = (cmd & 0x10) != 0;

        match ccs {
            // Initiate Upload Request
            2 => {
                let data = match self.read_sdo_bytes(index, subindex, complete_access) {
                    Ok(d) => d,
                    Err(abort) => {
                        self.push_sdo_abort(cnt, index, subindex, abort);
                        return;
                    }
                };
                if data.len() <= 4 && !complete_access {
                    let unused = (4 - data.len()) as u8;
                    let mut resp = vec![0u8; 8];
                    resp[0] = 0x43 | (unused << 2);
                    resp[1..3].copy_from_slice(&index.to_le_bytes());
                    resp[3] = subindex;
                    resp[4..4 + data.len()].copy_from_slice(&data);
                    self.push_coe_response(cnt, 0x03, &resp);
                } else {
                    let (_, sm1_len) = self.sm1_bounds();
                    // Force segmentation at 24 bytes if mailbox is 128 bytes so segmented upload is testable!
                    let max_inline = sm1_len.saturating_sub(16).clamp(8, 24);
                    let inline_len = data.len().min(max_inline);
                    let mut resp = Vec::with_capacity(8 + inline_len);
                    resp.push(if complete_access { 0x51 } else { 0x41 });
                    resp.extend_from_slice(&index.to_le_bytes());
                    resp.push(subindex);
                    resp.extend_from_slice(&(data.len() as u32).to_le_bytes());
                    resp.extend_from_slice(&data[..inline_len]);
                    self.push_coe_response(cnt, 0x03, &resp);
                    if inline_len < data.len() {
                        self.sdo_upload = Some(PendingSdoUpload {
                            index,
                            subindex,
                            data,
                            offset: inline_len,
                            expect_toggle: false,
                        });
                    }
                }
            }
            // Initiate Download Request
            1 => {
                let expedited = (cmd & 0x02) != 0;
                let size_ind = (cmd & 0x01) != 0;
                if expedited {
                    if payload.len() < 8 {
                        self.push_sdo_abort(cnt, index, subindex, 0x0607_0013);
                        return;
                    }
                    let unused = if size_ind {
                        ((cmd >> 2) & 0x03) as usize
                    } else {
                        0
                    };
                    let dlen = 4usize.saturating_sub(unused);
                    if let Err(abort) = self.commit_sdo_write(
                        index,
                        subindex,
                        complete_access,
                        &payload[4..4 + dlen],
                    ) {
                        self.push_sdo_abort(cnt, index, subindex, abort);
                        return;
                    }
                    let mut resp = vec![0u8; 8];
                    resp[0] = 0x60;
                    resp[1..3].copy_from_slice(&index.to_le_bytes());
                    resp[3] = subindex;
                    self.push_coe_response(cnt, 0x03, &resp);
                } else {
                    if payload.len() < 8 {
                        self.push_sdo_abort(cnt, index, subindex, 0x0607_0013);
                        return;
                    }
                    let total = if (cmd & 0x01) != 0 {
                        u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
                            as usize
                    } else {
                        payload.len() - 8
                    };
                    let inline = &payload[8..];
                    if inline.len() >= total {
                        if let Err(abort) = self.commit_sdo_write(
                            index,
                            subindex,
                            complete_access,
                            &inline[..total],
                        ) {
                            self.push_sdo_abort(cnt, index, subindex, abort);
                            return;
                        }
                    } else {
                        self.sdo_download = Some(PendingSdoDownload {
                            index,
                            subindex,
                            complete_access,
                            expected_len: total,
                            buf: inline.to_vec(),
                            expect_toggle: false,
                        });
                    }
                    let mut resp = vec![0u8; 8];
                    resp[0] = 0x60;
                    resp[1..3].copy_from_slice(&index.to_le_bytes());
                    resp[3] = subindex;
                    self.push_coe_response(cnt, 0x03, &resp);
                }
            }
            _ => {
                self.push_sdo_abort(cnt, index, subindex, 0x0504_0001);
            }
        }
    }

    fn read_sdo_bytes(
        &self,
        index: u16,
        subindex: u8,
        complete_access: bool,
    ) -> std::result::Result<Vec<u8>, u32> {
        let obj = self.od.get(&index).ok_or(0x0602_0000u32)?;
        if complete_access {
            if subindex > 1 {
                return Err(0x0601_0000);
            }
            let mut out = Vec::new();
            let max_sub = obj.entries.keys().copied().max().unwrap_or(0);
            if subindex == 0 {
                out.push(max_sub);
                out.push(0); // 16-bit aligned SI0 in EtherCAT CA
            }
            for s in 1..=max_sub {
                if let Some(e) = obj.entries.get(&s) {
                    out.extend_from_slice(&e.data);
                }
            }
            if out.is_empty() {
                if let Some(e0) = obj.entries.get(&0) {
                    return Ok(e0.data.clone());
                }
            }
            Ok(out)
        } else {
            let entry = obj.entries.get(&subindex).ok_or(0x0609_0011u32)?;
            Ok(entry.data.clone())
        }
    }

    fn commit_sdo_write(
        &mut self,
        index: u16,
        subindex: u8,
        complete_access: bool,
        data: &[u8],
    ) -> std::result::Result<(), u32> {
        let obj = self.od.get_mut(&index).ok_or(0x0602_0000u32)?;
        if complete_access {
            if subindex > 1 {
                return Err(0x0601_0000);
            }
            let max_sub = obj.entries.keys().copied().max().unwrap_or(0);
            if max_sub == 0 {
                let entry = obj.entries.get_mut(&0).ok_or(0x0609_0011u32)?;
                if !entry.writable {
                    return Err(0x0601_0002);
                }
                entry.data = data.to_vec();
                return Ok(());
            }
            let (target_subs, mut cursor) = if subindex == 0 {
                if data.len() < 2 {
                    return Err(0x0607_0013);
                }
                let count = data[0];
                if count > max_sub {
                    return Err(0x0609_0011);
                }
                (count, 2usize)
            } else {
                (max_sub, 0usize)
            };
            // Validate all target subindices before mutating
            for s in 1..=target_subs {
                let e = obj.entries.get(&s).ok_or(0x0609_0011u32)?;
                if !e.writable {
                    return Err(0x0601_0002);
                }
                let need = (e.bit_len as usize).div_ceil(8);
                if cursor + need > data.len() {
                    return Err(0x0607_0013);
                }
                cursor += need;
            }
            let mut off = if subindex == 0 { 2usize } else { 0usize };
            if subindex == 0 {
                if let Some(e0) = obj.entries.get_mut(&0) {
                    if e0.writable {
                        e0.data = vec![target_subs];
                    }
                }
            }
            for s in 1..=target_subs {
                if let Some(e) = obj.entries.get_mut(&s) {
                    let need = (e.bit_len as usize).div_ceil(8);
                    e.data = data[off..off + need].to_vec();
                    off += need;
                }
            }
            return Ok(());
        }
        let entry = obj.entries.get_mut(&subindex).ok_or(0x0609_0011u32)?;
        if !entry.writable {
            return Err(0x0601_0002);
        }
        // Fixed-width scalar CoE types require exact byte width (0x06070010)
        if matches!(entry.datatype, 0x0001..=0x0008 | 0x0010..=0x001B) {
            let expected_bytes = (entry.bit_len as usize).div_ceil(8);
            if data.len() != expected_bytes {
                return Err(0x0607_0010);
            }
        } else if data.len() * 8 > entry.bit_len as usize && entry.bit_len > 0 {
            return Err(0x0607_0012);
        }
        entry.data = data.to_vec();
        if index == 0x607A && subindex == 0 && data.len() == 4 {
            self.regs[0x1402..0x1406].copy_from_slice(data);
            if let Some(pos_obj) = self.od.get_mut(&0x6064) {
                if let Some(pe) = pos_obj.entries.get_mut(&0) {
                    pe.data = data.to_vec();
                }
            }
        }
        Ok(())
    }

    fn push_sdo_info_fragmented(&mut self, mut cnt: u8, opcode: u8, data: &[u8]) {
        let (_, sm1_len) = self.sm1_bounds();
        // 6-byte mbx header + 2-byte CoE header + 4-byte SDO Info header = 12 bytes overhead
        let mut max_chunk = sm1_len.saturating_sub(12).max(16);
        if opcode == 0x02 {
            max_chunk &= !1;
        }
        let slices: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(max_chunk).collect()
        };
        let total = slices.len();
        for (i, chunk) in slices.into_iter().enumerate() {
            let frags_left = (total - 1 - i) as u16;
            let op_byte = if frags_left > 0 {
                opcode | 0x80
            } else {
                opcode
            };
            let mut resp = Vec::with_capacity(4 + chunk.len());
            resp.push(op_byte);
            resp.push(0x00);
            resp.extend_from_slice(&frags_left.to_le_bytes());
            resp.extend_from_slice(chunk);
            self.push_coe_response(cnt, 0x08, &resp);
            cnt = if cnt >= 7 { 1 } else { cnt + 1 };
        }
    }

    fn handle_coe_sdo_info_req(&mut self, cnt: u8, payload: &[u8]) {
        if payload.len() < 4 {
            return;
        }
        let opcode = payload[0] & 0x7F;
        match opcode {
            // Get OD List Req -> Res (0x02)
            0x01 if payload.len() >= 6 => {
                let list_type = u16::from_le_bytes([payload[4], payload[5]]);
                let mut data = Vec::with_capacity(2 + self.od.len() * 2);
                data.extend_from_slice(&list_type.to_le_bytes());
                let count_matching = |mask: u16| -> u16 {
                    self.od
                        .values()
                        .filter(|obj| obj.entries.values().any(|e| (e.access & mask) != 0))
                        .count() as u16
                };
                match list_type {
                    // ETG.1000.6 §5.6.3.3: list_type 0 returns 5 u16 counts [all, rxpdo, txpdo, backup, settings]
                    0 => {
                        data.extend_from_slice(&(self.od.len() as u16).to_le_bytes());
                        data.extend_from_slice(&count_matching(0x0040).to_le_bytes());
                        data.extend_from_slice(&count_matching(0x0080).to_le_bytes());
                        data.extend_from_slice(&count_matching(0x0100).to_le_bytes());
                        data.extend_from_slice(&count_matching(0x0200).to_le_bytes());
                    }
                    1 => {
                        for &idx in self.od.keys() {
                            data.extend_from_slice(&idx.to_le_bytes());
                        }
                    }
                    2..=5 => {
                        let mask = 0x0040u16 << (list_type - 2);
                        for (&idx, obj) in &self.od {
                            if obj.entries.values().any(|e| (e.access & mask) != 0) {
                                data.extend_from_slice(&idx.to_le_bytes());
                            }
                        }
                    }
                    _ => {}
                }
                self.push_sdo_info_fragmented(cnt, 0x02, &data);
            }
            // Get Object Description Req -> Res (0x04)
            0x03 if payload.len() >= 6 => {
                let idx = u16::from_le_bytes([payload[4], payload[5]]);
                if let Some(obj) = self.od.get(&idx).cloned() {
                    let max_sub = obj.entries.keys().copied().max().unwrap_or(0);
                    let mut data = Vec::with_capacity(6 + obj.name.len());
                    data.extend_from_slice(&idx.to_le_bytes());
                    data.extend_from_slice(&obj.datatype.to_le_bytes());
                    data.push(max_sub);
                    data.push(obj.object_code);
                    data.extend_from_slice(obj.name.as_bytes());
                    self.push_sdo_info_fragmented(cnt, 0x04, &data);
                } else {
                    let mut err = vec![0x07, 0x00, 0x00, 0x00];
                    err.extend_from_slice(&0x0602_0000u32.to_le_bytes());
                    self.push_coe_response(cnt, 0x08, &err);
                }
            }
            // Get Entry Description Req -> Res (0x06)
            0x05 if payload.len() >= 8 => {
                let idx = u16::from_le_bytes([payload[4], payload[5]]);
                let sub = payload[6];
                let vinfo = payload[7];
                if let Some(entry) = self.od.get(&idx).and_then(|o| o.entries.get(&sub)).cloned() {
                    let mut data = Vec::with_capacity(10 + entry.name.len());
                    data.extend_from_slice(&idx.to_le_bytes());
                    data.push(sub);
                    data.push(vinfo & 0x07);
                    data.extend_from_slice(&entry.datatype.to_le_bytes());
                    data.extend_from_slice(&entry.bit_len.to_le_bytes());
                    data.extend_from_slice(&entry.access.to_le_bytes());
                    data.extend_from_slice(entry.name.as_bytes());
                    self.push_sdo_info_fragmented(cnt, 0x06, &data);
                } else {
                    let mut err = vec![0x07, 0x00, 0x00, 0x00];
                    err.extend_from_slice(&0x0609_0011u32.to_le_bytes());
                    self.push_coe_response(cnt, 0x08, &err);
                }
            }
            _ => {
                let mut err = vec![0x07, 0x00, 0x00, 0x00];
                err.extend_from_slice(&0x0504_0001u32.to_le_bytes());
                self.push_coe_response(cnt, 0x08, &err);
            }
        }
    }

    fn process_logical(&mut self, cmd: EcatCmd, lad: u32, payload: &mut [u8]) -> u16 {
        let mut wkc_delta = 0u16;
        let can_read = matches!(cmd, EcatCmd::Lrd | EcatCmd::Lrw);
        let can_write = matches!(cmd, EcatCmd::Lwr | EcatCmd::Lrw);

        for fmmu_idx in 0..4 {
            let base = 0x0600 + fmmu_idx * 16;
            let active = (self.regs[base + 12] & 0x01) != 0;
            if !active {
                continue;
            }
            let log_start = u32::from_le_bytes([
                self.regs[base],
                self.regs[base + 1],
                self.regs[base + 2],
                self.regs[base + 3],
            ]);
            let log_len = u16::from_le_bytes([self.regs[base + 4], self.regs[base + 5]]) as u32;
            let log_sbit = (self.regs[base + 6] & 0x07) as usize;
            let log_ebit = (self.regs[base + 7] & 0x07) as usize;
            let phys_start =
                u16::from_le_bytes([self.regs[base + 8], self.regs[base + 9]]) as usize;
            let phys_sbit = (self.regs[base + 10] & 0x07) as usize;
            let fmmu_type = self.regs[base + 11];
            let fmmu_rd = (fmmu_type & 0x01) != 0;
            let fmmu_wr = (fmmu_type & 0x02) != 0;

            if log_len == 0 || payload.is_empty() || (log_len == 1 && log_ebit < log_sbit) {
                continue;
            }
            let fmmu_total_bits = if log_len == 1 {
                log_ebit - log_sbit + 1
            } else {
                (8 - log_sbit) + ((log_len as usize - 2) * 8) + (log_ebit + 1)
            };
            let fmmu_start_bit = (log_start as u64) * 8 + (log_sbit as u64);
            let fmmu_end_bit = fmmu_start_bit + (fmmu_total_bits as u64);
            let pkt_start_bit = (lad as u64) * 8;
            let pkt_end_bit = pkt_start_bit + (payload.len() as u64) * 8;

            let ov_start = fmmu_start_bit.max(pkt_start_bit);
            let ov_end = fmmu_end_bit.min(pkt_end_bit);
            if ov_start >= ov_end {
                continue;
            }

            let total_bits = (ov_end - ov_start) as usize;
            let log_bit_off = (ov_start - pkt_start_bit) as usize;
            let fmmu_bit_delta = (ov_start - fmmu_start_bit) as usize;
            let eff_phys_bit = phys_sbit + fmmu_bit_delta;
            let eff_phys_start = phys_start + (eff_phys_bit / 8);
            let eff_phys_sbit = eff_phys_bit % 8;
            if eff_phys_start > u16::MAX as usize {
                continue;
            }

            let mut did_rd = false;
            let mut did_wr = false;

            // On LRW, capture old inputs BEFORE overwriting outputs, then write outputs
            let rd_bits = if can_read && fmmu_rd {
                let phys_byte_span = (eff_phys_sbit + total_bits).div_ceil(8);
                let phys_slice = self.read_physical(eff_phys_start as u16, phys_byte_span);
                extract_bits_le(&phys_slice, eff_phys_sbit, total_bits).ok()
            } else {
                None
            };

            if can_write && fmmu_wr {
                if let Ok(wr_bits) = extract_bits_le(payload, log_bit_off, total_bits) {
                    let phys_byte_span = (eff_phys_sbit + total_bits).div_ceil(8);
                    let mut phys_slice = self.read_physical(eff_phys_start as u16, phys_byte_span);
                    if insert_bits_le(&mut phys_slice, eff_phys_sbit, total_bits, &wr_bits).is_ok()
                    {
                        self.write_physical(eff_phys_start as u16, &phys_slice);
                        did_wr = true;
                    }
                }
            }

            if let Some(bits) = rd_bits {
                if insert_bits_le(payload, log_bit_off, total_bits, &bits).is_ok() {
                    did_rd = true;
                }
            }

            match (did_rd, did_wr) {
                (true, true) => wkc_delta = wkc_delta.max(3),
                (false, true) => {
                    if matches!(cmd, EcatCmd::Lrw) {
                        wkc_delta += 2;
                    } else {
                        wkc_delta += 1;
                    }
                }
                (true, false) => wkc_delta += 1,
                (false, false) => {}
            }
        }
        wkc_delta
    }
}

pub struct SimulatedBusTransport {
    spec: String,
    slaves: Vec<SimSlave>,
    rx_queue: VecDeque<Vec<u8>>,
    next_idx: u8,
}

impl SimulatedBusTransport {
    pub fn open(spec: &str) -> Result<Self> {
        let mut slaves = Vec::new();
        let trimmed = spec.trim();
        let rest = if trimmed.eq_ignore_ascii_case("sim") {
            ""
        } else if trimmed
            .get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case("sim://"))
        {
            &trimmed[6..]
        } else if trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("sim:"))
        {
            &trimmed[4..]
        } else {
            return Err(CliError::Usage(format!(
                "invalid simulator URI '{spec}'; expected 'sim', 'sim://slaves=<N>', or 'sim://esi=<path>'"
            )));
        };

        if rest.starts_with("esi=") {
            let mut esi_path_str = "";
            let mut device_sel: Option<String> = None;
            let mut revision: Option<u32> = None;
            let mut profile = SiiBuildProfile::Ssc;
            let mut lcid = 1033u32;
            let mut ignore_size = false;

            for part in rest.split(';') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some(p) = part.strip_prefix("esi=") {
                    esi_path_str = p.trim();
                } else if let Some(d) = part.strip_prefix("device=") {
                    device_sel = Some(d.trim().to_string());
                } else if let Some(r) = part.strip_prefix("revision=") {
                    let v = parse_esi_u64(r)?;
                    revision = Some(u32::try_from(v).map_err(|_| {
                        CliError::Usage(format!("sim revision '{r}' overflows u32"))
                    })?);
                } else if let Some(pr) = part.strip_prefix("profile=") {
                    profile = match pr.trim().to_ascii_lowercase().as_str() {
                        "ssc" => SiiBuildProfile::Ssc,
                        "minimal" => SiiBuildProfile::Minimal,
                        other => {
                            return Err(CliError::Usage(format!(
                                "unknown sim ESI profile '{other}' (expected ssc or minimal)"
                            )))
                        }
                    };
                } else if let Some(lc) = part.strip_prefix("lcid=") {
                    lcid = u32::try_from(parse_esi_u64(lc)?).unwrap_or(1033);
                } else if let Some(ig) = part.strip_prefix("ignore_size=") {
                    ignore_size = parse_esi_bool(ig);
                } else {
                    return Err(CliError::Usage(format!(
                        "unknown sim://esi option '{part}' (supported: esi=, device=, revision=, profile=, lcid=, ignore_size=)"
                    )));
                }
            }
            if esi_path_str.is_empty() {
                return Err(CliError::Usage("empty path in sim://esi=<path.xml>".into()));
            }
            let catalog = load_esi_catalog(Path::new(esi_path_str), lcid)?;
            let dev = select_esi_device(&catalog.devices, device_sel.as_deref(), revision)?;
            let compiled = compile_esi_device_to_sii(
                dev,
                &EsiCompileOptions {
                    profile,
                    ignore_eeprom_size: ignore_size,
                    ..Default::default()
                },
            )?;
            slaves.push(SimSlave::from_esi_device(dev, compiled.bytes));
        } else if let Some(eeprom_path) = rest.strip_prefix("eeprom=") {
            let raw = std::fs::read(Path::new(eeprom_path)).map_err(|e| {
                CliError::Format(format!("cannot load sim EEPROM '{eeprom_path}': {e}"))
            })?;
            let mut sl = SimSlave::from_eeprom(raw);
            sl.populate_servo_402_od();
            slaves.push(sl);
        } else if let Some(n_str) = rest.strip_prefix("slaves=") {
            let count: usize = n_str
                .parse()
                .map_err(|e| CliError::Usage(format!("invalid sim slave count '{n_str}': {e}")))?;
            for i in 0..count {
                if i % 2 == 0 {
                    slaves.push(SimSlave::new_servo_402());
                } else {
                    slaves.push(SimSlave::new_dio_terminal());
                }
            }
        } else if rest.is_empty() {
            slaves.push(SimSlave::new_servo_402());
            slaves.push(SimSlave::new_dio_terminal());
        } else {
            return Err(CliError::Usage(format!(
                "unknown simulator option '{rest}' in '{spec}'; expected 'sim', 'sim://slaves=<N>', or 'sim://esi=<path>'"
            )));
        }

        Ok(Self {
            spec: spec.to_string(),
            slaves,
            rx_queue: VecDeque::new(),
            next_idx: 1,
        })
    }
    pub fn insert_long_od_object_for_test(
        &mut self,
        slave_idx: usize,
        index: u16,
        obj_name: &str,
        entry_name: &str,
    ) {
        if let Some(sl) = self.slaves.get_mut(slave_idx) {
            let mut entries = BTreeMap::new();
            entries.insert(
                0,
                OdEntry {
                    datatype: 0x0009,
                    bit_len: 64,
                    access: 0x07,
                    name: entry_name.into(),
                    data: b"fragtest".to_vec(),
                    writable: false,
                },
            );
            sl.od.insert(
                index,
                OdObject {
                    datatype: 0x0009,
                    object_code: 7,
                    name: obj_name.into(),
                    entries,
                },
            );
        }
    }
    pub fn strip_slave_pdo_metadata_for_test(&mut self, slave_idx: usize) {
        if let Some(sl) = self.slaves.get_mut(slave_idx) {
            sl.od.clear();
            if sl.eeprom.len() >= 130 {
                sl.eeprom[128..].fill(0xFF);
            }
        }
    }
    pub fn inject_sm0_replies_for_test(
        &mut self,
        slave_idx: usize,
        frames: Vec<Vec<u8>>,
        suppress_normal: bool,
    ) {
        if let Some(sl) = self.slaves.get_mut(slave_idx) {
            sl.injected_sm0_replies = Some((frames, suppress_normal));
        }
    }

    fn process_frame(&mut self, tx_frame: &[u8]) -> Result<Vec<u8>> {
        if tx_frame.len() < ETH_HEADER_LEN + 2 {
            return Err(CliError::Format("TX frame too short".into()));
        }
        let Ok((etype, vlan_id, _off)) =
            ethercat_wire::protocol::frame::skip_ethernet_vlan_tags(tx_frame, 12)
        else {
            return Ok(tx_frame.to_vec());
        };
        if etype != ETH_P_ECAT {
            return Ok(tx_frame.to_vec());
        }
        let mut datagrams = parse_dlpdu_datagrams(tx_frame)?;
        for dg in &mut datagrams {
            self.process_datagram(dg);
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&tx_frame[0..6]);
        src.copy_from_slice(&tx_frame[6..12]);
        // Slaves set locally administered MAC bit (0x02) on passing frame
        src[0] |= 0x02;

        let mut builder = EcatFrameBuilder {
            dst_mac: dst,
            src_mac: src,
            vlan_id,
            frame_type: 0x01,
            datagrams,
            pad_to_min_ethernet: true,
        };
        let _ = &mut builder;
        let mut rx = builder.build()?;
        if rx.len() < MIN_ETHERNET_FRAME_LEN {
            rx.resize(MIN_ETHERNET_FRAME_LEN, 0);
        }
        Ok(rx)
    }

    fn process_datagram(&mut self, dg: &mut RawDatagram) {
        let Some(cmd) = EcatCmd::from_code(dg.cmd) else {
            return;
        };
        match cmd {
            EcatCmd::Nop => {}
            EcatCmd::Aprd | EcatCmd::Apwr | EcatCmd::Aprw => {
                for sl in &mut self.slaves {
                    let active = dg.adp == 0;
                    dg.adp = dg.adp.wrapping_add(1);
                    if active {
                        match cmd {
                            EcatCmd::Aprd => {
                                dg.data = sl.read_physical(dg.ado, dg.data.len());
                                dg.wkc = dg.wkc.wrapping_add(1);
                            }
                            EcatCmd::Apwr => {
                                sl.write_physical(dg.ado, &dg.data);
                                dg.wkc = dg.wkc.wrapping_add(1);
                            }
                            EcatCmd::Aprw => {
                                let old = sl.read_physical(dg.ado, dg.data.len());
                                sl.write_physical(dg.ado, &dg.data);
                                dg.data = old;
                                dg.wkc = dg.wkc.wrapping_add(3);
                            }
                            _ => {}
                        }
                    }
                }
            }
            EcatCmd::Armw => {
                for sl in &mut self.slaves {
                    let is_reader = dg.adp == 0;
                    dg.adp = dg.adp.wrapping_add(1);
                    if is_reader {
                        dg.data = sl.read_physical(dg.ado, dg.data.len());
                        dg.wkc = dg.wkc.wrapping_add(1);
                    } else {
                        sl.write_physical(dg.ado, &dg.data);
                        dg.wkc = dg.wkc.wrapping_add(2);
                    }
                }
            }
            EcatCmd::Fprd | EcatCmd::Fpwr | EcatCmd::Fprw => {
                for sl in &mut self.slaves {
                    if sl.matches_configured_addr(dg.adp) {
                        match cmd {
                            EcatCmd::Fprd => {
                                dg.data = sl.read_physical(dg.ado, dg.data.len());
                                dg.wkc = dg.wkc.wrapping_add(1);
                            }
                            EcatCmd::Fpwr => {
                                sl.write_physical(dg.ado, &dg.data);
                                dg.wkc = dg.wkc.wrapping_add(1);
                            }
                            EcatCmd::Fprw => {
                                let old = sl.read_physical(dg.ado, dg.data.len());
                                sl.write_physical(dg.ado, &dg.data);
                                dg.data = old;
                                dg.wkc = dg.wkc.wrapping_add(3);
                            }
                            _ => {}
                        }
                    }
                }
            }
            EcatCmd::Frmw => {
                let mut reader_seen = false;
                for sl in &mut self.slaves {
                    if sl.matches_configured_addr(dg.adp) {
                        dg.data = sl.read_physical(dg.ado, dg.data.len());
                        dg.wkc = dg.wkc.wrapping_add(1);
                        reader_seen = true;
                    } else if reader_seen {
                        sl.write_physical(dg.ado, &dg.data);
                        dg.wkc = dg.wkc.wrapping_add(2);
                    }
                }
            }
            EcatCmd::Brd => {
                for sl in &mut self.slaves {
                    dg.adp = dg.adp.wrapping_add(1);
                    let rd = sl.read_physical(dg.ado, dg.data.len());
                    for (dst, &src) in dg.data.iter_mut().zip(rd.iter()) {
                        *dst |= src;
                    }
                    dg.wkc = dg.wkc.wrapping_add(1);
                }
            }
            EcatCmd::Bwr => {
                for sl in &mut self.slaves {
                    dg.adp = dg.adp.wrapping_add(1);
                    sl.write_physical(dg.ado, &dg.data);
                    dg.wkc = dg.wkc.wrapping_add(1);
                }
            }
            EcatCmd::Brw => {
                for sl in &mut self.slaves {
                    dg.adp = dg.adp.wrapping_add(1);
                    let rd = sl.read_physical(dg.ado, dg.data.len());
                    sl.write_physical(dg.ado, &dg.data);
                    for (dst, &src) in dg.data.iter_mut().zip(rd.iter()) {
                        *dst |= src;
                    }
                    dg.wkc = dg.wkc.wrapping_add(3);
                }
            }
            EcatCmd::Lrd | EcatCmd::Lwr | EcatCmd::Lrw => {
                for sl in &mut self.slaves {
                    let delta = sl.process_logical(cmd, dg.logical_addr, &mut dg.data);
                    dg.wkc = dg.wkc.wrapping_add(delta);
                }
            }
        }
    }
}

impl EthercatTransport for SimulatedBusTransport {
    fn name(&self) -> &str {
        &self.spec
    }

    fn next_index(&mut self) -> u8 {
        let idx = self.next_idx;
        self.next_idx = self.next_idx.wrapping_add(1);
        idx
    }

    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<()> {
        let rx = self.process_frame(frame)?;
        self.rx_queue.push_back(rx);
        Ok(())
    }

    fn recv_raw_frame(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
        Ok(self.rx_queue.pop_front())
    }

    fn transact_frame(
        &mut self,
        tx_frame: &[u8],
        _expected_idx: Option<u8>,
        _timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.process_frame(tx_frame)
    }
}

fn push_cat(buf: &mut Vec<u8>, cat_type: u16, mut body: Vec<u8>) {
    if !body.len().is_multiple_of(2) {
        body.push(0);
    }
    let word_len = (body.len() / 2) as u16;
    buf.extend_from_slice(&cat_type.to_le_bytes());
    buf.extend_from_slice(&word_len.to_le_bytes());
    buf.extend_from_slice(&body);
}

pub fn build_servo_402_sii() -> Vec<u8> {
    let mut img = vec![0u8; 128];
    img[0x00..0x02].copy_from_slice(&0x0005u16.to_le_bytes()); // PDI SPI
    img[0x08..0x0A].copy_from_slice(&0x0001u16.to_le_bytes()); // Alias 1
    img[0x10..0x14].copy_from_slice(&0x0000_0931u32.to_le_bytes()); // Vendor
    img[0x14..0x18].copy_from_slice(&0x0000_0402u32.to_le_bytes()); // Product
    img[0x18..0x1C].copy_from_slice(&0x0001_0000u32.to_le_bytes()); // Revision
    img[0x1C..0x20].copy_from_slice(&0x2026_0001u32.to_le_bytes()); // Serial
                                                                    // Std Mailbox: Rx=0x1000/128, Tx=0x1080/128, CoE|FoE (0x000C)
    img[0x30..0x32].copy_from_slice(&0x1000u16.to_le_bytes());
    img[0x32..0x34].copy_from_slice(&128u16.to_le_bytes());
    img[0x34..0x36].copy_from_slice(&0x1080u16.to_le_bytes());
    img[0x36..0x38].copy_from_slice(&128u16.to_le_bytes());
    img[0x38..0x3A].copy_from_slice(&0x000Cu16.to_le_bytes());
    // 512 bytes => (512 / 128) - 1 = 3
    img[0x7C..0x7E].copy_from_slice(&3u16.to_le_bytes());
    img[0x7E..0x80].copy_from_slice(&1u16.to_le_bytes());
    img[14] = sii_crc8(&img[0..14]);

    // Cat 10: Strings (1..6)
    let strs = [
        "EC-SERVO-402",
        "Drives",
        "Statusword",
        "ActualPosition",
        "Controlword",
        "TargetPosition",
    ];
    let mut sbody = vec![strs.len() as u8];
    for s in strs {
        sbody.push(s.len() as u8);
        sbody.extend_from_slice(s.as_bytes());
    }
    push_cat(&mut img, 10, sbody);

    // Cat 30: General (32 bytes)
    let mut gbody = vec![0u8; 32];
    gbody[0] = 2; // GroupIdx = "Drives"
    gbody[2] = 1; // OrderIdx = "EC-SERVO-402"
    gbody[3] = 1; // NameIdx  = "EC-SERVO-402"
    gbody[5] = 0x27; // SDO + SDOInfo + PDOAssign + CompleteAccess
    gbody[6] = 0x01; // FoE
    gbody[9] = 0x01; // DS402
    gbody[12..14].copy_from_slice(&120i16.to_le_bytes());
    gbody[16..18].copy_from_slice(&0x0011u16.to_le_bytes()); // Port 0 & 1 MII
    push_cat(&mut img, 30, gbody);

    // Cat 40: FMMU (Outputs, Inputs, SyncMStatus)
    push_cat(&mut img, 40, vec![0x01, 0x02, 0x03, 0xFF]);

    // Cat 41: SyncM (SM0..SM3)
    let mut sm = Vec::new();
    let push_sm = |v: &mut Vec<u8>, start: u16, len: u16, creg: u8, en: u8, ty: u8| {
        v.extend_from_slice(&start.to_le_bytes());
        v.extend_from_slice(&len.to_le_bytes());
        v.push(creg);
        v.push(0);
        v.push(en);
        v.push(ty);
    };
    push_sm(&mut sm, 0x1000, 128, 0x26, 0x01, 1);
    push_sm(&mut sm, 0x1080, 128, 0x22, 0x01, 2);
    push_sm(&mut sm, 0x1100, 6, 0x64, 0x01, 3);
    push_sm(&mut sm, 0x1400, 6, 0x20, 0x01, 4);
    push_cat(&mut img, 41, sm);

    // Cat 50: TxPDO (0x1A00 -> 0x6041:00 u16 16b, 0x6064:00 i32 32b)
    let mut txpdo = Vec::new();
    txpdo.extend_from_slice(&0x1A00u16.to_le_bytes());
    txpdo.extend_from_slice(&[2, 3, 0, 1, 0, 0]); // 2 entries, SM3, NameIdx=1
    txpdo.extend_from_slice(&0x6041u16.to_le_bytes());
    txpdo.extend_from_slice(&[0, 3, 0x06, 16, 0, 0]); // Statusword UNSIGNED16 16b
    txpdo.extend_from_slice(&0x6064u16.to_le_bytes());
    txpdo.extend_from_slice(&[0, 4, 0x04, 32, 0, 0]); // ActualPosition INTEGER32 32b
    push_cat(&mut img, 50, txpdo);

    // Cat 51: RxPDO (0x1600 -> 0x6040:00 u16 16b, 0x607A:00 i32 32b)
    let mut rxpdo = Vec::new();
    rxpdo.extend_from_slice(&0x1600u16.to_le_bytes());
    rxpdo.extend_from_slice(&[2, 2, 0, 1, 0, 0]); // 2 entries, SM2, NameIdx=1
    rxpdo.extend_from_slice(&0x6040u16.to_le_bytes());
    rxpdo.extend_from_slice(&[0, 5, 0x06, 16, 0, 0]); // Controlword UNSIGNED16 16b
    rxpdo.extend_from_slice(&0x607Au16.to_le_bytes());
    rxpdo.extend_from_slice(&[0, 6, 0x04, 32, 0, 0]); // TargetPosition INTEGER32 32b
    push_cat(&mut img, 51, rxpdo);

    img.extend_from_slice(&0xFFFFu16.to_le_bytes());
    img.resize(512, 0xFF);
    img
}

fn build_dio_sii() -> Vec<u8> {
    let mut img = vec![0u8; 128];
    img[0x00..0x02].copy_from_slice(&0x0004u16.to_le_bytes());
    img[0x08..0x0A].copy_from_slice(&0x0002u16.to_le_bytes());
    img[0x10..0x14].copy_from_slice(&0x0000_0931u32.to_le_bytes());
    img[0x14..0x18].copy_from_slice(&0x0000_0067u32.to_le_bytes());
    img[0x18..0x1C].copy_from_slice(&0x0000_0001u32.to_le_bytes());
    img[0x1C..0x20].copy_from_slice(&0x2026_0002u32.to_le_bytes());
    img[0x30..0x32].copy_from_slice(&0x1000u16.to_le_bytes());
    img[0x32..0x34].copy_from_slice(&128u16.to_le_bytes());
    img[0x34..0x36].copy_from_slice(&0x1080u16.to_le_bytes());
    img[0x36..0x38].copy_from_slice(&128u16.to_le_bytes());
    img[0x38..0x3A].copy_from_slice(&0x0004u16.to_le_bytes());
    img[0x7C..0x7E].copy_from_slice(&3u16.to_le_bytes()); // 512 bytes
    img[0x7E..0x80].copy_from_slice(&1u16.to_le_bytes());
    img[14] = sii_crc8(&img[0..14]);

    let mut sbody = vec![2u8];
    sbody.push(7);
    sbody.extend_from_slice(b"PC-1000");
    sbody.push(3);
    sbody.extend_from_slice(b"GPC");
    push_cat(&mut img, 10, sbody);
    img.extend_from_slice(&0xFFFFu16.to_le_bytes());
    img.resize(512, 0xFF);
    img
}
