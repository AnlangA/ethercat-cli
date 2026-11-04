use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use ethercat_eeprom::sii::image::SiiBuildProfile;
use ethercat_master::pdo::PdoSource;
use ethercat_wire::protocol::constants::{AlStateSpec, EcatCmd};
use ethercat_wire::protocol::pcap_io::FrameInputKind;
use ethercat_wire::types::{parse_u16, parse_u32, parse_u64, parse_u8, parse_usize, DataTypeSpec};

pub fn parse_esi_u32_cli(input: &str) -> std::result::Result<u32, String> {
    let trimmed = input.trim();
    if let Some(hex_part) = trimmed
        .strip_prefix("#x")
        .or_else(|| trimmed.strip_prefix("#X"))
    {
        parse_u32(&format!("0x{hex_part}"))
    } else {
        parse_u32(trimmed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human- and LLM-readable structured plain text tables/summaries.
    Text,
    /// Pretty-printed deterministic JSON (recommended for AI inspection).
    Json,
    /// Single-line compact JSON (recommended for JSONL pipelines and tool calls).
    JsonCompact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FieldsCatalogFilter {
    /// Show all catalogs: Wireshark/CLI field selectors, EtherCAT commands, ESC registers, AL/SDO codes, and SSC selectors.
    All,
    /// Beckhoff/Wireshark dissector & CLI `--field` selectors (`eth.*`, `esl.*`, `ecatf.*`, `ecat.*`, `ecat_mailbox.*`, `ecat.pdo.*`, `sii.*`, `esi.*`).
    Wireshark,
    /// EtherCAT DLPDU datagram command codes (`0x00 NOP` .. `0x0E FRMW`).
    Commands,
    /// ESC hardware register map (`0x0000` .. `0x0FFF`) with symbolic names and byte widths.
    Registers,
    /// Application Layer (AL) status codes (`0x0000` .. `0x0050`, ETG.1000.6) and SDO abort codes (`0x05030000` .. `0x08000023`).
    Codes,
    /// Pure-Rust SSC / OD generator `--field` selectors (`ssc.*`, `ssc.define.<NAME>`, `ssc.config.<NAME>`).
    Ssc,
}

const ROOT_AFTER_HELP: &str = r#"AI & AUTOMATION QUICK REFERENCE
===============================
1. INTERFACE SELECTION (`--iface` / `-i`):
   - Windows Npcap adapter : `\Device\NPF_{GUID}` (discover with `ethercat-cli adapters`)
   - Linux libpcap adapter : `eth0`, `enp3s0`, etc.
   - EtherCAT-over-UDP     : `udp://<target_ip>[:34980]` or `udp://<bind_ip>[:port]@<target_ip>[:34980]`
                             (ETG.1000.4 UDP port `0x88A4 = 34980`, matching Beckhoff SSC `EEPROM Programmer`)
   - Virtual ring simulator: `sim` (default 2 slaves: Slave 1 = CiA-402 Servo, Slave 2 = 16ch DIO)
                             `sim://slaves=4` (custom slave count)
                             `sim://eeprom=path/to/slave1.bin` (seed Slave 1 SII from `.bin` dump)
                             `sim://esi=path/to/device.xml[;device=0]` (compile ETG.2000 ESI XML & seed Slave 1)
   NOTE: Offline commands (`adapters`, `ssc *`, `esi list/inspect/build`, `sii build/inspect/validate/diff/patch`,
         `frame build`, `dissect`, `pdo decode/encode`, `fields`, and `--dry-run` modes) DO NOT require `--iface`.

2. UNIVERSAL FIELD EXTRACTION (`--field` / `-f`, repeatable):
   Modeled on Wireshark's built-in Beckhoff EtherCAT dissector (`eth.*`, `esl.*`, `ecatf.*`, `ecat.*`,
   `ecat[i].*`, `ecat.reg.*`, `ecat.pdo.*`, `ecat_mailbox.coe.*`, `ecat_mailbox.foe.*`,
   `ecat_mailbox.soe.*`, `ecat_mailbox.aoe.*`, `ecat_mailbox.eoe.*`, `nv.*`, `sii.*`, `esi.*`) PLUS full
   JSON dot/index paths (`header.vendor_id_hex`, `slaves[0].al_state`, `decoded_value`) and prefix wildcards
   (`ecat_mailbox.coe.*`). Run `ethercat-cli fields` for the full dictionary.

3. SAFETY MODEL:
   - `[OFFLINE]`       : Pure local file/memory parsing & ESI XML->SII compilation; zero network I/O.
   - `[READ-ONLY]`     : Non-destructive bus reads (`BRD`, `APRD`, `FPRD`, `LRD`, SDO upload, `sii/esi read`, `verify`).
   - `[GUARDED-WRITE]` : `sii write` & `esi burn` default to DRY-RUN (zero EEPROM writes). Real EEPROM writes
                         require ALL THREE locks: `--execute`, non-existing `--backup <FILE>`, and
                         exact `--confirm WRITE-SLAVE-<N>`, optional `--check-esc-config` (`0x0140`/`0x0150`),
                         writing body words first, header words (0..15) last, followed by full read-back verify.
   - `[BUS-WRITE]`     : `sii reload`, `state --set`, `reg write`, `sdo write`, `pdo exchange`, `datagram`,
                         `frame send` support `--dry-run` to preview actions/frames before bus transmission.

4. DETERMINISTIC EXIT CODES:
   0 = Success
   1 = CLI usage / invalid argument combination / ambiguous multi-device ESI XML
   2 = Network interface / Npcap / UDP socket / transport error
   3 = EtherCAT device / bus / WKC=0 / timeout error
   4 = Verification mismatch (`sii/esi verify`, `--check-esc-config`) or `--field` selector not found
   5 = Data / ETG.2000 ESI XML / SII image / CRC-8 / hex / PCAP format error
   6 = Write lock rejected (`sii write` / `esi burn` 3-factor safety lock)
   7 = EtherCAT protocol error (AL state transition failure or CoE SDO abort)

5. CONCRETE EXAMPLES:
   # Compile an ETG.2000 ESI XML device into a Beckhoff SSC-compatible SII .bin and C array header .h
   ethercat-cli esi build --xml device.xml --output eeprom.bin --header-out eeprom.h

   # List all slave devices inside a multi-device ESI XML or TwinCAT catalog directory
   ethercat-cli --format json esi list --xml "C:\Program Files (x86)\Beckhoff\TwinCAT\3.1\Config\Io\EtherCAT\Beckhoff AX8600.xml"

   # Guarded ESI XML burn dry-run against virtual simulator seeded from ESI XML (zero writes performed)
   ethercat-cli -i "sim://esi=device.xml" --format json esi burn --slave 1 --xml device.xml --alias 5

   # Read slave SII EEPROM over EtherCAT-over-UDP (port 34980) and match against ESI XML catalog
   ethercat-cli -i udp://192.168.1.255:34980 esi read --slave 1 --output backup.bin --xml ./esi/

   # Inspect a real SII EEPROM dump and extract Vendor ID + Product Code + Device Name
   ethercat-cli --format json -f sii.vendor_id_hex -f sii.product_code_hex -f sii.device_name sii inspect --file slave1.bin

   # Read CoE SDO 0x1008:00 (Manufacturer Device Name, segmented string) on slave 1
   ethercat-cli -i sim --format json sdo read --slave 1 --index 0x1008 --subindex 0 --type string --auto-preop

   # Dissect a Windows PktMon capture, .pcap, or Wireshark .pcapng and extract Wireshark fields
   ethercat-cli dissect --file scan.txt --limit 10 -f ecat.cmd -f ecat.ado -f ecat.wkc

   # Pure-Rust SSC Tool: generate full EtherCAT Slave Stack Code, ESI XML, eeprom.h, and .esp from XLSX/CSV OD
   ethercat-cli ssc generate -a MyApplication.xlsx -d CREATE_EEPROM_CONTENT=1 --output ./slave_out

   # Pure-Rust SSC OD Tool: generate Src/<App>Objects.h, <App>.h, <App>.c, and output/<App>Objects.xml
   ethercat-cli ssc od generate MyApplication.csv
"#;

#[derive(Debug, Parser)]
#[command(
    name = "ethercat-cli",
    version,
    about = "AI-oriented EtherCAT CLI: pure-Rust SSC code/OD/ESI generator, ETG.2000 ESI->SII compiler, guarded EEPROM programmer, Wireshark dissector, ESC reg, CoE SDO, and PDO toolkit",
    long_about = "ethercat-cli is a deterministic, self-documenting EtherCAT command-line toolkit engineered for AI agents, automated diagnostics, and embedded systems engineers.\n\n\
Structured across 5 clean layers:\n  \
(1) Transport Layer (`--iface`): Npcap/libpcap raw L2 (`0x88A4`), ETG.1000.4 EtherCAT-over-UDP (`udp://<ip>[:34980]`), and built-in virtual ring (`sim`, `sim://eeprom=...`, `sim://esi=...`);\n  \
(2) SII Binary Codec & ESC EEPROM Primitives (`sii`): ETG.2010 SII encoding/decoding, SSC `aEepromData[]` C header export, PDI handover, 3-factor guarded programming, ESC `0x0140`/`0x0150` PDI verification, and `0x0400` EEPROM reload;\n  \
(3) ESI XML Compiler & Application Workflows (`esi` & `sii`): Beckhoff SSC Tool / `EEPROM Programmer` compatible ETG.2000 `.xml` (UTF-8, UTF-16, ISO-8859-1, `<InfoReference>`) -> `.bin`/`.h` compilation, catalog matching, verification, and guarded burning;\n  \
(4) Pure-Rust Slave Stack Code & Object Dictionary Generator (`ssc`): 100% native re-implementation of Beckhoff `SSC Tool`, `SSC Tool Cmd`, and `SSC OD Tool` (`.escfg`/`.esp` projects, `#if`/`CODE_INSERT` preprocessing, `.patch` engine, `.xlsx`/`.csv`/`.xml`/`.eds`/`.tmc` OD codegen, ESI generation & in-place updating);\n  \
(5) Protocol Dissector & Master Diagnostics (`frame`, `datagram`, `dissect`, `capture`, `reg`, `sdo`, `pdo`): Wireshark-compatible dissection plus granular ESC register, CoE SDO, and cyclic PDO bit/field access.",
    after_long_help = ROOT_AFTER_HELP,
    propagate_version = true
)]
pub struct Cli {
    /// EtherCAT transport interface: `\Device\NPF_{GUID}` (Windows Npcap), `eth0` (Linux), `udp://<ip>[:34980]` (EtherCAT-over-UDP), or `sim` / `sim://slaves=N` / `sim://eeprom=file.bin` / `sim://esi=file.xml[;device=0]`. Can also be set via `ETHERCAT_IFACE`.
    #[arg(global = true, short = 'i', long = "iface", value_name = "IFACE")]
    pub iface: Option<String>,

    /// Output serialization format (`text`, `json`, or `json-compact`). In JSON modes, both stdout results and error envelopes are strict machine-parseable JSON.
    #[arg(
        global = true,
        short = 'o',
        long = "format",
        value_enum, ignore_case = true,
        default_value_t = OutputFormat::Text,
        value_name = "FORMAT"
    )]
    pub format: OutputFormat,

    /// Extract specific Wireshark dissector fields (`ecat.cmd`, `ecat.wkc`, `ecat_mailbox.coe.sdo.index`, `ecat.pdo.<name>`, `sii.device_name`, `esi.order_code`) or JSON paths (`header.vendor_id_hex`, `slaves[0].al_state`, `decoded_value`). Repeatable.
    #[arg(global = true, short = 'f', long = "field", value_name = "SELECTOR")]
    pub fields: Vec<String>,

    /// Per-transaction EtherCAT / mailbox timeout in milliseconds.
    #[arg(
        global = true,
        long = "timeout-ms",
        visible_alias = "timeout",
        default_value_t = 500,
        value_parser = parse_u64,
        value_name = "MS"
    )]
    pub timeout_ms: u64,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// [OFFLINE/READ-ONLY] Enumerate local Npcap/libpcap Ethernet adapters and the built-in `sim` bus.
    #[command(
        long_about = "[OFFLINE/READ-ONLY] Enumerate all available Npcap (Windows) or libpcap (Linux) network interfaces together with the built-in `sim` virtual EtherCAT ring.\n\n\
Use the returned `name` field (for example `\\Device\\NPF_{...}` or `sim`) as the `--iface` argument for online bus commands.",
        after_long_help = "EXAMPLES:\n  ethercat-cli adapters\n  ethercat-cli --format json adapters -f \"[0].name\"\n  ethercat-cli --format json adapters -f \"adapters[0].name\""
    )]
    Adapters {
        /// Omit the virtual `sim` interface and fail with exit code 2 if Npcap/libpcap cannot be loaded.
        #[arg(long)]
        physical_only: bool,
    },

    /// [READ-ONLY DEFAULT] Scan the EtherCAT ring for slaves, ESC info, AL status, DL link flags, and SII identity.
    #[command(
        long_about = "[READ-ONLY DEFAULT] Discover all slaves on the EtherCAT ring in topological order (1..N) using Broadcast Read (`BRD 0x0000`) and Auto-Increment Physical Reads (`APRD`).\n\n\
By default, zero write datagrams are transmitted unless `--assign-addresses` is explicitly passed, except temporary EEPROM PDI handover if SII reading is enabled and the slave's PDI holds EEPROM access (pass `--no-sii` for strictly passive register-only scanning).",
        after_long_help = "EXAMPLES:\n  ethercat-cli -i sim scan\n  ethercat-cli -i sim --format json scan --no-sii\n  ethercat-cli -i \"\\Device\\NPF_{GUID}\" scan -f slaves[*].al_state"
    )]
    Scan {
        /// Assign configured station addresses (`0x1001..0x1000+N` to ESC `0x0010`) during scan [BUS-WRITE].
        #[arg(long)]
        assign_addresses: bool,

        /// Skip reading SII EEPROM identity/protocols (strictly passive `BRD`/`APRD` register reads only).
        #[arg(long)]
        no_sii: bool,
    },

    /// [READ-ONLY / BUS-WRITE] Read or transition Slave Application Layer (AL) state (`INIT`, `PRE-OP`, `BOOT`, `SAFE-OP`, `OP`).
    #[command(
        long_about = "[READ-ONLY / BUS-WRITE] Read ESC AL Status (`0x0130`) and AL Status Code (`0x0134`), or request an AL state transition via AL Control (`0x0120`) and poll until confirmed.\n\n\
Pass `--slave 0` to address all slaves on the ring simultaneously (`BRD` / `BWR`).",
        after_long_help = "EXAMPLES:\n  # Read Slave 1 AL state and AL status code\n  ethercat-cli -i sim state --slave 1\n\n  # Transition Slave 1 to PRE-OP with error-acknowledge bit (0x0010)\n  ethercat-cli -i sim state --slave 1 --set pre-op --ack\n\n  # Dry-run transition of all slaves (slave=0) to SAFE-OP\n  ethercat-cli -i sim state --slave 0 --set safe-op --dry-run"
    )]
    State {
        /// Target 1-based slave position (`1..N`), or `0` for broadcast across all slaves.
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Request transition to target AL state (`init`, `pre-op`, `boot`, `safe-op`, `op`) [BUS-WRITE]. Omit to perform a read-only check.
        #[arg(long, value_enum, ignore_case = true, value_name = "STATE")]
        set: Option<AlStateSpec>,

        /// Set the Error Ind / Acknowledge flag (`0x0010`) in AL Control (`0x0120`) to clear sticky AL state errors.
        #[arg(long)]
        ack: bool,

        /// Preview requested AL Control word while only reading current AL Status (zero bus writes).
        #[arg(long)]
        dry_run: bool,
    },

    /// [GUARDED] Complete SII / ESI EEPROM interface: `list`, `build`, `read`, `verify`, `write` (3-factor lock), `inspect`, `validate`, `diff`, `patch`, `reload`.
    #[command(
        subcommand,
        visible_alias = "eeprom",
        long_about = "Complete EtherCAT Slave Information Interface (SII / ESI EEPROM, ETG.2010) toolkit.\n\n\
Preserves and extends every safety invariant of `esi-eeprom` while integrating Beckhoff SSC Tool / `EEPROM Programmer` workflows:\n  \
- Offline ETG.2000 ESI `.xml` -> ETG.2010 SII `.bin` & SSC `unsigned char aEepromData[]` C header `.h` compilation (`sii build`)\n  \
- Automatic PDI EEPROM access handover/restore via `ECT_REG_EEPCFG` (`0x0500`) and `0x0400` EEPROM `RELOAD` (`sii reload`)\n  \
- Automatic 4-byte vs 8-byte (`EC_ESTAT_R64`) read bursts via `0x0502`/`0x0508` with full 32-bit word addressing (`0x0504..0x0507` up to 512 KiB)\n  \
- Strict validation of image length (128..524288 even bytes), `0x007C` capacity header, and CRC-8 (poly `0x07`, init `0xFF`)\n  \
- `sii write` accepts `--file <image.bin>` OR `--xml <esi.xml>`, defaults to DRY-RUN, supports `--check-esc-config` (`0x0140`/`0x0150`), and requires `--execute` + non-existing `--backup <FILE>` + exact `--confirm WRITE-SLAVE-<N>`\n  \
- Differential word-level programming: body words (`end..16`) written first, critical header words (`0..15`) written last, followed by full read-back verification."
    )]
    Sii(SiiSubcommand),

    /// [OFFLINE / GUARDED] ETG.2000 ESI XML device catalog, inspector, SII `.bin`/`.h` compiler, and guarded slave EEPROM programmer.
    #[command(
        subcommand,
        long_about = "ETG.2000 EtherCAT Slave Information (ESI `.xml`) compiler and Beckhoff SSC `EEPROM Programmer` application layer.\n\n\
Built cleanly on top of the `sii` binary codec and ESC EEPROM bus primitives (`Npcap` L2 `0x88A4`, `udp://` port `34980`, or `sim`):\n  \
- Parses ETG.2000 `<EtherCATInfo>` files and TwinCAT catalog folders (`UTF-8`, `UTF-16LE/BE`, `ISO-8859-1`, and `<InfoReference>` external XML includes)\n  \
- Matches Beckhoff `ET9300Utilities.EsiSiiHandler` byte-for-byte (`ssc` profile, string-table byte budgeting `General -> DC -> TxPDO -> RxPDO`, `<ConfigData>` + CRC-8, `<BootStrap>`, `<Dc>`, and raw `<Eeprom><Data>` blobs)\n  \
- Exports both binary `.bin` EEPROM images and Beckhoff Slave Stack Code C headers (`unsigned char aEepromData[]`)\n  \
- Shares the exact 3-factor guarded EEPROM programming, verification, and catalog-matching workflows with `sii`."
    )]
    Esi(EsiSubcommand),

    /// [OFFLINE] Pure-Rust Beckhoff Slave Stack Code (SSC) project/code/ESI/OD generator (`SSC Tool` + `SSC OD Tool` parity).
    #[command(
        subcommand,
        long_about = "[OFFLINE] 100% pure-Rust implementation of Beckhoff's EtherCAT Slave Stack Code (SSC) Tool, `SSC Tool Cmd`, and `SSC OD Tool` — zero proprietary `.dll`/`.exe` dependencies.\n\n\
Capabilities:\n  \
- `ssc generate`      : Load `.escfg`/`.esp`/`SlaveConfigFile.xml`, apply configurations & migrations, import `.xlsx`/`.csv`/`.xml`/`.eds`/`.tmc` Object Dictionaries, apply `.patch` diffs, preprocess `#if`/`CODE_INSERT` directives into `src/*.c/*.h`, emit `ecat_def.h`, `eeprom.h`, `<Project>.xml` ESI, and GZIP `<Project>.esp`\n  \
- `ssc list-defines`  : List SSC configuration defines, values, types, flags, and descriptions (`SSC Tool Cmd -l` parity)\n  \
- `ssc list-configs`  : Enumerate embedded & external hardware/application `<Configuration>` presets\n  \
- `ssc export-config` : Export current project settings into a reusable `<SscToolConfiguration>` XML file\n  \
- `ssc import-header` : Import `#define` settings from an existing `ecat_def.h` header into an `.esp` project or configuration XML\n  \
- `ssc check`         : Evaluate `<SettingConflicts>` rules and `UpdateInformation.xml` known issues\n  \
- `ssc od generate`   : Standalone `SSC OD Tool` mode — generate `Src/<App>Objects.h`, `<App>.h`, `<App>.c`, and `output/<App>Objects.xml` (or update an existing ESI XML in place)\n  \
- `ssc od template`   : Create a Beckhoff SSC Object Dictionary wizard `.csv` or `.xlsx` spreadsheet template\n  \
- `ssc update-esi`    : Update `<Dictionary>`, `<TxPdo>`, `<RxPdo>`, `<Sm>`, and `<Slots>` inside an existing ESI `.xml` (with `.bak` backup)\n  \
- `ssc patch`         : Apply a Beckhoff unified `.patch` diff to a source directory with Doxygen `\\version` `.1` tracking\n  \
- `ssc image-hex`     : Encode a `16x14` `.bmp`/`.png`/`.gif` icon into ESI `<ImageData16x14>` uppercase hex"
    )]
    Ssc(SscSubcommand),

    /// [READ-ONLY / BUS-WRITE] Read, bit-slice, decode, write, or list ESC hardware registers (`0x0000..0x0FFF`).
    #[command(
        subcommand,
        long_about = "Direct EtherCAT Slave Controller (ESC) hardware register interface (`0x0000..0x0FFF`).\n\n\
Accepts either hexadecimal/decimal register offsets (`0x0130`, `0x0502`, `0x0800`) OR symbolic names (`al_status`, `dl_status`, `eep_ctl_stat`, `sm0`, `fmmu0`, `dc_sys_time`). Supports arbitrary little-endian bit slicing (`--bit-offset` + `--bit-length`) and typed decoding (`--type`)."
    )]
    Reg(RegSubcommand),

    /// [READ-ONLY / BUS-WRITE] CoE (CANopen over EtherCAT) SDO upload/download (expedited, normal, segmented, CA) & Object Dictionary browser.
    #[command(
        subcommand,
        long_about = "CANopen over EtherCAT (CoE, ETG.1000.6) Service Data Object (SDO) client and SDO Information Object Dictionary browser.\n\n\
Automatically configures station address (`0x0010`) and Mailbox SyncManagers (`SM0`/`SM1` from SII `0x0018..0x001F` or `BOOT` `0x0014..0x0017` if uninitialized), supports `--auto-preop` when a slave is in `INIT`, and handles Expedited (<=4B), Normal, Segmented (arbitrary length with toggle-bit verification), and Complete Access (`--ca`) transfers."
    )]
    Sdo(SdoSubcommand),

    /// [READ-ONLY / BUS-WRITE / OFFLINE] Process Data Object (PDO) mapping discovery, single-field/bit reading, cyclic `LRW` exchange, and offline codec.
    #[command(
        subcommand,
        long_about = "Process Data Object (PDO) inspection, field-level reading, logical `LRW` exchange, and offline payload codec.\n\n\
Supports discovering `RxPDO` (outputs) and `TxPDO` (inputs) bit layouts from live CoE (`0x1C12`/`0x1C13`), live SII EEPROM (Categories 50/51), offline `.bin` SII dumps, or explicit compact layout strings (`name:type@bit_offset[:bit_len]`)."
    )]
    Pdo(PdoSubcommand),

    /// [OFFLINE / BUS-WRITE] Build raw `0x88A4` Ethernet frames (single or multi-datagram) or transmit & dissect live responses.
    #[command(
        subcommand,
        long_about = "Low-level Ethernet II (`0x88A4`, optional IEEE 802.1Q VLAN) EtherCAT DLPDU frame constructor and raw frame transmitter."
    )]
    Frame(FrameSubcommand),

    /// [BUS-WRITE / READ] Send a single EtherCAT datagram (`NOP`..`FRMW`), verify Working Counter (`WKC`), and decode typed/bit-sliced response data.
    #[command(
        long_about = "Construct, send, and receive a single EtherCAT DLPDU datagram (`BRD`, `BWR`, `APRD`, `APWR`, `FPRD`, `FPWR`, `LRD`, `LWR`, `LRW`, `ARMW`, `FRMW`) on `--iface`, optionally asserting an expected Working Counter (`--expect-wkc`) and decoding specific bits or data types.",
        after_long_help = "ADDRESSING RULES:\n  - Positioned commands (`APRD`, `APWR`, `FPRD`, `FPWR`, `BRD`, `BWR`, `ARMW`, `FRMW`):\n      Use `--slave <1..N>` (sets `ADP = 1 - slave` for `AP*`), OR explicit `--adp <U16>` + `--ado <U16>`.\n  - Logical commands (`LRD`, `LWR`, `LRW`):\n      Use `--logical-addr <U32>` (e.g. `0x00010000`).\n\nEXAMPLES:\n  # Broadcast read ESC Type/Revision (4 bytes at 0x0000)\n  ethercat-cli -i sim datagram --cmd brd --adp 0 --ado 0x0000 --len 4\n\n  # Auto-increment read AL Status (0x0130, 2 bytes) from Slave 1 expecting WKC=1\n  ethercat-cli -i sim --format json datagram --cmd aprd --slave 1 --ado 0x0130 --len 2 --type u16 --expect-wkc 1"
    )]
    Datagram(DatagramArgs),

    /// [OFFLINE] Dissect EtherCAT frames from hex, `.pcap`, `.pcapng`, Windows PktMon `.txt`, or `.bin` using Wireshark 4.6 field names and optional `--xml` SDO/temporal PDO enrichment.
    #[command(
        long_about = "[OFFLINE] Deep-packet EtherCAT protocol dissector implementing 100% of the official Wireshark 4.6 EtherCAT plugin (`esl`, `ecatf`, `ecat`, `ecat_mailbox`, `ams`, `tc_nv`, `ioraw`) plus XML-driven CoE SDO and stateful temporal PDO dissection.\n\n\
Decodes:\n  \
- Encapsulations: Ethernet II (`0x88A4`), IEEE 802.1Q/802.1ad VLAN, IPv4/UDP `34980` (`0x88A4`), Beckhoff ET2000 ESL (`esl.*` prefix & trailer), AMS/TCP (`48898`) & AMS/UDP (`48899`), or headerless (`--bare`)\n  \
- EtherCAT 2-byte Frame Header (`ecatf.*`): DLPDU (`0x1`), Direct ADS/AMS (`0x2`, `ams.*`), Raw-IO (`0x3`, `ioraw.*`), TwinCAT Network Variables (`0x4`, `tc_nv.*` / `nv.*`), Direct Mailbox (`0x5`, `ecat_mailbox.*`)\n  \
- Chained DLPDU subframes (`ecat.*`, `ecat[i].*`, `ecat.sub1..10.*`): command, idx, ADP/ADO/LAD, C/M (`circulating`/`next`), IRQ bits, WKC, and Distributed Clocks `0x0910` `ARMW`/`FRMW` difference (`ecat.dc.dif.*`)\n  \
- ESC Hardware Registers (`ecat.reg.*`, `ecat.fmmu.*`, `ecat.syncman.*`): `0x0000..0x09FF` bitfields across ESC info, station/alias, DL/AL, error counters, watchdogs, SII, FMMU0..15, SM0..15, and DC\n  \
- Mailbox protocols (`ecat_mailbox.*` & `ecat_mailbox[i].*`): CoE (Emergency, SDO Expedited/Normal/Segmented/Block/Abort/CA, SDO Info `0x01..0x07`, CoE PDO), FoE (incl. `.efw` firmware blocks), SoE, AoE/ADS (incl. CoE-over-AoE `0xF302`), EoE (IP params, MAC filter, Ethernet fragments), VoE, ERR\n  \
- XML SDO & Temporal PDO (`--xml <ESI_OD_OR_ENI_XML>`, repeatable for multi-slave topologies):\n    \
* CoE SDO Expedited/Normal/Segmented/Block reassembly resolved against `<EtherCATInfo>`, `<EtherCATDict>`, or `<EtherCATConfig>` (`ecat_mailbox.coe.sdo.xml.*`, `ecat_mailbox.coe.sdo.reassembled_data`)\n    \
* Automatic per-slave XML profile matching via SII EEPROM reads (`0x0502..0x050F`), CoE `0x1018` Identity SDOs, station addresses (`0x0010` / ENI `<PhysAddr>`), and MDP `0xF030` module slots\n    \
* Stateful temporal PDO tracking across packet sequence (`0x1600..0x17FF`, `0x1A00..0x1BFF`, `0x1C12`, `0x1C13`, ESC SM `0x0800+`, FMMU `0x0600+`): cyclic PDO frames occurring BEFORE PDO configuration frames in the trace are intentionally NOT decoded into XML PDO fields; PDO frames AFTER configuration decode exact mapped XML fields (`ecat.pdo.*`).",
        after_long_help = "SUPPORTED FILE FORMATS (`--file` / `--input`):\n  - `.pcap`   : Standard libpcap capture (streamed incrementally; microsecond & nanosecond magic, LE/BE)\n  - `.pcapng` : Wireshark PCAP-NG capture (streamed multi-section SHB/IDB/EPB/SPB, LE/BE, `if_tsresol`)\n  - `.txt`    : Microsoft-Windows-PktMon hex dump logs (UTF-16LE/BE BOM or UTF-8)\n  - `.hex`    : Whitespace/colon/0x-delimited hexadecimal frame text\n  - `.bin`    : Raw binary Ethernet/EtherCAT frame bytes\n\nEXAMPLES:\n  # Dissect a single hex frame and extract Wireshark fields\n  ethercat-cli dissect --hex \"ffffffffffff01010101010188a4101007010000000004000000000000000000\" -f ecat.cmd -f ecat.ado_name\n\n  # Dissect a multi-slave startup + cyclic trace with multiple ESI/OD/ENI XML files\n  ethercat-cli --format json dissect --file startup_and_op.pcapng --xml ./esi/EL2004.xml --xml ./esi/ServoDrive.xml --limit 0\n\n  # Decode cyclic LRW PDO fields inside a mid-stream capture using a static SII EEPROM dump\n  ethercat-cli dissect --file trace.pcapng --sii-pdo slave1.bin --pdo-dir tx -f ecat.pdo.0x6041:00"
    )]
    Dissect(DissectArgs),

    /// [READ-ONLY] Capture live `0x88A4` EtherCAT frames from `--iface`, dissect in real time, and optionally save to `.pcap` / `.pcapng`.
    #[command(
        long_about = "[READ-ONLY] Passively capture live EtherCAT (`0x88A4`) Ethernet frames from `--iface` via Npcap/libpcap (promiscuous mode), dissect each frame through a stateful Wireshark 4.6 dissector session (with optional repeatable `--xml` SDO/temporal PDO decoding), apply optional command/field filters, and optionally write a `.pcap` or `.pcapng` file.",
        after_long_help = "EXAMPLES:\n  # Capture up to 20 EtherCAT frames over 3 seconds and save to trace.pcapng\n  ethercat-cli -i \"\\Device\\NPF_{GUID}\" capture --count 20 --duration-ms 3000 --save-pcap trace.pcapng\n\n  # Capture with ESI XML enrichment for live CoE SDO and post-config PDO decoding\n  ethercat-cli -i \"\\Device\\NPF_{GUID}\" capture --count 100 --xml ./esi/ --save-pcap startup.pcapng"
    )]
    Capture {
        /// Maximum number of matching EtherCAT packets to capture before stopping.
        #[arg(short = 'c', long, default_value_t = 10, value_parser = parse_usize, value_name = "N")]
        count: usize,

        /// Total capture window duration in milliseconds before stopping.
        #[arg(long, default_value_t = 3000, value_parser = parse_u64, value_name = "MS")]
        duration_ms: u64,

        /// Capture only frames containing at least one subframe with this EtherCAT command (`aprd`, `fpwr`, `lrw`, etc.).
        #[arg(long, value_enum, ignore_case = true, value_name = "CMD")]
        filter_cmd: Option<EcatCmd>,

        /// Optional compact PDO layout (`name:type@bit_offset[:bit_len]`) to decode `ecat.pdo.*` fields live.
        #[arg(long, value_name = "SPEC")]
        pdo_layout: Option<String>,

        /// Optional SII `.bin` file to decode `TxPDO`/`RxPDO` fields during live capture.
        #[arg(long, value_name = "FILE")]
        sii_pdo: Option<PathBuf>,

        /// Repeatable ETG.2000 ESI `<EtherCATInfo>`, Offline OD `<EtherCATDict>`, or ETG.2100 ENI `<EtherCATConfig>` `.xml` file or directory for live SDO & stateful temporal PDO dissection.
        #[arg(long = "xml", value_name = "XML_OR_DIR")]
        xml: Vec<PathBuf>,

        /// Optional device selector (`<Type>`, `<Name>`, `ProductCode`, or index) when `--xml` contains multiple `<Device>` profiles.
        #[arg(long, value_name = "DEVICE")]
        xml_device: Option<String>,

        /// Save raw captured Ethernet frames to a Wireshark-compatible `.pcap` or `.pcapng` file (selected by extension).
        #[arg(long, value_name = "PCAP_OUT")]
        save_pcap: Option<PathBuf>,
    },

    /// [OFFLINE] Reference dictionary of Wireshark `--field` selectors, EtherCAT commands, ESC registers, and status/abort codes.
    #[command(
        long_about = "[OFFLINE] Output the built-in machine-readable protocol reference tables: Beckhoff/Wireshark `--field` selectors, EtherCAT datagram command codes, ESC register catalog (`0x0000..0x0FFF`), AL status codes, and CoE SDO abort codes.",
        after_long_help = "EXAMPLES:\n  ethercat-cli fields\n  ethercat-cli --format json fields --category wireshark\n  ethercat-cli fields --category registers --search eep"
    )]
    Fields {
        /// Restrict reference output to a specific table.
        #[arg(long, value_enum, ignore_case = true, default_value_t = FieldsCatalogFilter::All, value_name = "CATEGORY")]
        category: FieldsCatalogFilter,

        /// Case-insensitive substring filter across selector/register/command names and descriptions.
        #[arg(long, value_name = "SUBSTR")]
        search: Option<String>,
    },
}

/// Shared ETG.2000 ESI XML device selection and SII compilation options.
#[derive(Debug, Clone, Args)]
pub struct EsiXmlCompileArgs {
    /// Select `<Device>` in a multi-device ESI XML by 0-based index (`0`, `1`), `<Type>` order code (`PC-1000`, `EL1008`), `ProductCode` (`0x00000067`), or `type@rev` / `product_code:rev`. Auto-selected when XML contains 1 device.
    #[arg(long, value_name = "SELECTOR")]
    pub device: Option<String>,

    /// Disambiguate `<Device>` by 32-bit `<Type RevisionNo="...">` (`0x00010001` or `"#x00010001"`).
    #[arg(long, value_parser = parse_esi_u32_cli, value_name = "REV_U32")]
    pub revision: Option<u32>,

    /// SII binary compilation profile (`ssc` = Beckhoff SSC Tool / `ET9300Utilities` byte-exact layout; `minimal` = compact ETG.2010 layout omitting CoE PDOs & empty DC).
    #[arg(long, value_enum, ignore_case = true, default_value_t = SiiBuildProfile::Ssc, value_name = "PROFILE")]
    pub profile: SiiBuildProfile,

    /// Preferred ETG.2000 `LcId` language ID for localized `<Name>`/`<Desc>` strings (`1033` = English, `1031` = German, `0` = first element in XML order).
    #[arg(long, default_value_t = 1033, value_parser = parse_u32, value_name = "LCID")]
    pub lcid: u32,

    /// Override declared EEPROM capacity in bytes (rounded up to 128-byte boundary; defaults to `<Eeprom><ByteSize>` in XML).
    #[arg(long, value_parser = parse_usize, value_name = "BYTES")]
    pub eeprom_size: Option<usize>,

    /// Ignore `<Eeprom><ByteSize>` string-budget truncation and auto-grow SII image size (128-byte aligned) so all categories and strings fit.
    #[arg(long)]
    pub ignore_eeprom_size: bool,

    /// Include unassigned alternative `<RxPdo>`/`<TxPdo>` definitions without an `Sm` attribute (`Sm = -1`) in SII Categories 50/51.
    #[arg(long)]
    pub include_unassigned_pdos: bool,
}

#[derive(Debug, Clone, Args)]
pub struct EsiBuildArgs {
    /// Path to an ETG.2000 ESI `.xml` file or directory of `.xml` files.
    #[arg(long, visible_aliases = ["file", "input"], value_name = "ESI_XML_OR_DIR")]
    pub xml: PathBuf,

    #[command(flatten)]
    pub xml_opts: EsiXmlCompileArgs,

    /// Optional 16-bit Configured Station Alias override at SII bytes `0x08..0x0A` (recomputes CRC-8).
    #[arg(long, value_parser = parse_u16, value_name = "U16")]
    pub alias: Option<u16>,

    /// Optional 32-bit Serial Number override at SII bytes `0x1C..0x20`.
    #[arg(long, value_parser = parse_esi_u32_cli, value_name = "U32")]
    pub serial: Option<u32>,

    /// Output path for compiled ETG.2010 SII binary image (`.bin`).
    #[arg(long = "output", visible_alias = "out", value_name = "OUT_BIN")]
    pub output: Option<PathBuf>,

    /// Output path for Beckhoff Slave Stack Code C header (`unsigned char aEepromData[] = { ... };`).
    #[arg(long = "header-out", visible_alias = "header", value_name = "OUT_H")]
    pub header_out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct SiiReadArgs {
    /// 1-based slave position on the EtherCAT ring (`1..N`).
    #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
    pub slave: u16,

    /// Write raw EEPROM bytes to this binary `.bin` file path (recommended for full backups).
    #[arg(long = "output", visible_alias = "out", value_name = "FILE_BIN")]
    pub output: Option<PathBuf>,

    /// Also export read EEPROM bytes as a Beckhoff SSC C array header (`unsigned char aEepromData[]`).
    #[arg(long = "header-out", visible_alias = "header", value_name = "FILE_H")]
    pub header_out: Option<PathBuf>,

    /// Optional even byte offset (`0, 2, 4, ...`) for partial slice read instead of full image read.
    #[arg(long, value_parser = parse_usize, value_name = "BYTE_OFFSET")]
    pub offset: Option<usize>,

    /// Byte count to read when `--offset` is specified (defaults to 64 if `--offset` is set).
    #[arg(long, value_parser = parse_usize, value_name = "BYTES")]
    pub length: Option<usize>,

    /// Optional ETG.2000 ESI `.xml` file or catalog folder to match the slave's live `(VendorId, ProductCode, RevisionNo)`.
    #[arg(long, value_name = "ESI_XML_OR_DIR")]
    pub xml: Option<PathBuf>,

    /// Preferred `LcId` language ID when matching against `--xml` (`1033` = English default).
    #[arg(long, default_value_t = 1033, value_parser = parse_u32, value_name = "LCID")]
    pub lcid: u32,

    /// Decode full SII header and TLV categories (`Strings`, `General`, `FMMU`, `SyncM`, `PDO`, `DC`) in the output.
    #[arg(long)]
    pub decode: bool,
}

#[derive(Debug, Clone, Args)]
pub struct SiiVerifyArgs {
    /// 1-based slave position on the EtherCAT ring (`1..N`).
    #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
    pub slave: u16,

    /// Expected SII EEPROM `.bin` image file to compare against (mutually exclusive with `--xml`).
    #[arg(
        long,
        visible_alias = "input",
        conflicts_with = "xml",
        value_name = "IMAGE_BIN"
    )]
    pub file: Option<PathBuf>,

    /// Expected ETG.2000 ESI `.xml` file/catalog to compile in memory and compare against (mutually exclusive with `--file`).
    #[arg(long, conflicts_with = "file", value_name = "ESI_XML_OR_DIR")]
    pub xml: Option<PathBuf>,

    #[command(flatten)]
    pub xml_opts: EsiXmlCompileArgs,

    /// Optional expected 16-bit Configured Station Alias override before comparing.
    #[arg(long, value_parser = parse_u16, value_name = "U16")]
    pub alias: Option<u16>,

    /// Optional expected 32-bit Serial Number override before comparing.
    #[arg(long, value_parser = parse_esi_u32_cli, value_name = "U32")]
    pub serial: Option<u32>,
}

#[derive(Debug, Clone, Args)]
pub struct SiiWriteArgs {
    /// 1-based slave position on the EtherCAT ring (`1..N`).
    #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
    pub slave: u16,

    /// Validated SII `.bin` image (or `.xml`) to compare/program (mutually exclusive with `--xml`).
    #[arg(
        long,
        visible_alias = "input",
        conflicts_with = "xml",
        value_name = "IMAGE_BIN"
    )]
    pub file: Option<PathBuf>,

    /// ETG.2000 ESI `.xml` file or catalog folder to compile and compare/program onto `--slave` (mutually exclusive with `--file`).
    #[arg(long, conflicts_with = "file", value_name = "ESI_XML_OR_DIR")]
    pub xml: Option<PathBuf>,

    #[command(flatten)]
    pub xml_opts: EsiXmlCompileArgs,

    /// Optional 16-bit Configured Station Alias override (SII bytes `0x08..0x0A`, auto-updates CRC-8).
    #[arg(long, value_parser = parse_u16, value_name = "U16")]
    pub alias: Option<u16>,

    /// Optional 32-bit Serial Number override (SII bytes `0x1C..0x20`).
    #[arg(long, value_parser = parse_esi_u32_cli, value_name = "U32")]
    pub serial: Option<u32>,

    /// Actually execute EEPROM word writes (omit for safe DRY-RUN comparison with zero writes).
    #[arg(long)]
    pub execute: bool,

    /// Mandatory path for pre-write EEPROM backup when `--execute` is set (must NOT already exist).
    #[arg(long, value_name = "NEW_BACKUP_BIN")]
    pub backup: Option<PathBuf>,

    /// Mandatory confirmation token when `--execute` is set: must equal exact `WRITE-SLAVE-<N>`.
    #[arg(long, value_name = "WRITE-SLAVE-N")]
    pub confirm: Option<String>,

    /// Issue ESC EEPROM `RELOAD` (`0x0400` in `0x0502`) command after programming (including when image words already match).
    #[arg(long)]
    pub reload: bool,

    /// Verify active ESC PDI Control (`0x0140`) & PDI Configuration (`0x0150`) registers match proposed SII `ConfigData[0..4]` before writing (matching Beckhoff `EEPROM Programmer` `CheckEscConfigData`).
    #[arg(long)]
    pub check_esc_config: bool,
}

#[derive(Debug, Subcommand)]
pub enum SiiSubcommand {
    /// [OFFLINE/READ-ONLY] Without `--iface`, list Npcap adapters & `sim`; with `--iface`, list SII EEPROM inventory of all slaves on the ring (matching `esi-eeprom list`).
    #[command(
        long_about = "[OFFLINE / READ-ONLY] Dual-mode discovery matching `esi-eeprom list`:\n  \
- Without `--iface` (and `ETHERCAT_IFACE` unset): enumerates local Npcap/libpcap adapters and `sim`.\n  \
- With `--iface <IFACE>`: scans the EtherCAT ring and lists each slave's SII EEPROM summary (Vendor/Product/Rev/Serial, Alias, declared byte size, CRC-8 status, and mailbox protocols).",
        after_long_help = "EXAMPLES:\n  # List local Npcap adapters and virtual simulator\n  ethercat-cli sii list\n\n  # List SII EEPROM inventory for all slaves on virtual or physical ring\n  ethercat-cli -i sim sii list\n  ethercat-cli -i sim --format json sii list"
    )]
    List,

    /// [OFFLINE] Compile an ETG.2000 ESI `.xml` device description into a validated SII `.bin` image and/or Beckhoff SSC `aEepromData[]` `.h` header.
    #[command(
        visible_alias = "from-xml",
        long_about = "[OFFLINE] Compile an ETG.2000 EtherCAT Slave Information (`.xml`) `<Device>` into an ETG.2010 SII `.bin` EEPROM image and/or Beckhoff Slave Stack Code C header (`unsigned char aEepromData[]`).\n\n\
Matches Beckhoff `ET9300Utilities.EsiSiiHandler` byte-for-byte in default `--profile ssc` mode, including `<ConfigData>` + CRC-8 (`0x0E`), string-table byte-budget priority (`General -> DC -> TxPDO -> RxPDO`), odd-FMMU `0xFF` padding, assigned `<Sm>` PDO filtering, and `<Dc>` category generation.",
        after_long_help = "EXAMPLES:\n  # Compile single-device ESI XML to SII .bin and SSC eeprom.h\n  ethercat-cli sii build --xml device.xml --output eeprom.bin --header-out eeprom.h\n\n  # Compile a specific device/revision from a multi-device ESI XML and set station alias 4\n  ethercat-cli sii build --xml Beckhoff_AX8600.xml --device AX8620-0000-0000 --revision 0x00110000 --alias 4 --output ax8620.bin"
    )]
    Build(EsiBuildArgs),

    /// [READ-ONLY] Read full SII EEPROM image (or `--offset`/`--length` slice) from a slave to `.bin` and/or SSC `.h`, with optional `--xml` catalog matching.
    #[command(
        long_about = "[READ-ONLY] Read SII/ESI EEPROM data from 1-based `--slave` on `--iface` (`Npcap`, `udp://`, or `sim`).\n\n\
Automatically claims EEPROM access from PDI if needed (`0x0500`), detects 4-byte vs 8-byte read bursts (`EC_ESTAT_R64`), reads either the full capacity declared at byte `0x007C` (up to 512 KiB via 32-bit `0x0504` word addressing) or a custom byte slice (`--offset` + `--length`), optionally matches live `(VendorId, ProductCode, RevisionNo)` against `--xml`, and restores PDI ownership.",
        after_long_help = "EXAMPLES:\n  # Full SII backup to binary file and SSC C header\n  ethercat-cli -i sim sii read --slave 1 --output slave1-backup.bin --header-out slave1_eeprom.h\n\n  # Read live SII and identify slave against an ESI XML file or directory\n  ethercat-cli -i sim --format json sii read --slave 1 --xml ./esi/ --decode\n\n  # Read 16-byte SII configuration header slice\n  ethercat-cli -i sim --format json sii read --slave 1 --offset 0 --length 16"
    )]
    Read(SiiReadArgs),

    /// [READ-ONLY] Compare a slave's live SII EEPROM byte-for-byte against a `.bin` file or compiled ESI `.xml` device (exit code 4 on mismatch).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli -i sim sii verify --slave 1 --file slave1-eeprom.bin\n  ethercat-cli -i sim --format json sii verify --slave 1 --xml device.xml --device 0"
    )]
    Verify(SiiVerifyArgs),

    /// [DRY-RUN DEFAULT / 3-FACTOR GUARDED WRITE] Diff or program a validated SII `.bin` or compiled ESI `.xml` onto a slave EEPROM.
    #[command(
        visible_aliases = ["burn", "program"],
        long_about = "[DRY-RUN DEFAULT / 3-FACTOR GUARDED WRITE] Program an SII/ESI EEPROM image (from `--file <image.bin>` OR compiled on the fly from `--xml <esi.xml>`) onto `--slave`.\n\n\
SAFETY LOCKS (all enforced before any EEPROM write command is transmitted):\n  \
1. Proposed `.bin` or compiled `.xml` image must pass strict ETG.2010 size, `0x007C` capacity, and CRC-8 validation (else exit code 5).\n  \
2. Optional `--check-esc-config` reads live ESC `0x0140`/`0x0150` PDI registers and aborts with exit code 4 if they do not match `proposed[0..4]`.\n  \
3. Without `--execute`, runs in DRY-RUN mode: reads current EEPROM, reports word diff count & sample diffs, and exits 0 with zero writes.\n  \
4. With `--execute`, BOTH `--backup <NEW_FILE>` (must NOT already exist) AND `--confirm WRITE-SLAVE-<N>` (exact case-sensitive match for target slave `N`) are mandatory (else exit code 6 `WRITE LOCKED`).\n  \
5. Saves full pre-write backup to `--backup`, writes only differing 16-bit words (body words `end..16` first, header words `0..15` last), restores PDI ownership, and verifies full read-back byte-for-byte.",
        after_long_help = "EXAMPLES:\n  # Step 1: Safe dry-run word-diff preview from .bin or .xml (zero writes)\n  ethercat-cli -i sim sii write --slave 1 --file patched.bin\n  ethercat-cli -i sim sii write --slave 1 --xml device.xml --check-esc-config\n\n  # Step 2: Unlocked guarded write with mandatory new backup & confirmation token\n  ethercat-cli -i sim sii write --slave 1 --xml device.xml --reload \\\n    --execute --backup prewrite-slave1.bin --confirm WRITE-SLAVE-1"
    )]
    Write(SiiWriteArgs),

    /// [OFFLINE / READ-ONLY] Decode full SII header and TLV Categories (`Strings`, `General`, `FMMU`, `SyncM`, `TxPDO`, `RxPDO`, `DC`), optionally exporting SSC `.h`.
    #[command(
        after_long_help = "EXAMPLES:\n  # Inspect an offline SII dump and export SSC C header\n  ethercat-cli --format json sii inspect --file slave1.bin --header-out eeprom.h\n\n  # Extract only Strings and Device Name using --field\n  ethercat-cli --format json -f sii.device_name -f sii.strings sii inspect --file slave1.bin\n\n  # Inspect live Slave 1 SII directly from the bus\n  ethercat-cli -i sim sii inspect --slave 1"
    )]
    Inspect {
        /// Offline SII `.bin` file to decode (omit to read live from `--slave` on `--iface`).
        #[arg(long, visible_alias = "input", value_name = "IMAGE_BIN")]
        file: Option<PathBuf>,

        /// 1-based slave position when reading live from `--iface` (ignored if `--file` is provided).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Optional path to export the SII bytes as a Beckhoff SSC C array header (`unsigned char aEepromData[]`).
        #[arg(long = "header-out", visible_alias = "header", value_name = "OUT_H")]
        header_out: Option<PathBuf>,
    },

    /// [OFFLINE] Strictly validate SII `.bin` size alignment, byte `0x007C` capacity declaration, CRC-8 (`0..14`), and TLV bounds.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli sii validate --file slave1-eeprom-20260810-132422.bin"
    )]
    Validate {
        /// SII `.bin` image file to validate.
        #[arg(long, visible_alias = "input", value_name = "IMAGE_BIN")]
        file: PathBuf,
    },

    /// [OFFLINE] Compare two SII `.bin` or ESI `.xml` sources at 16-bit word granularity and summarize identity differences.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli sii diff --left before.bin --right after.bin --max-diffs 64\n  ethercat-cli --format json sii diff --left device.xml --right slave1-dump.bin"
    )]
    Diff {
        /// Left / baseline SII `.bin` image or ETG.2000 ESI `.xml` file.
        #[arg(long, value_name = "LEFT_BIN_OR_XML")]
        left: PathBuf,

        /// Right / comparison SII `.bin` image or ETG.2000 ESI `.xml` file.
        #[arg(long, value_name = "RIGHT_BIN_OR_XML")]
        right: PathBuf,

        /// Device selector (`index`, `<Type>`, or `ProductCode`) when `--left` is an ESI `.xml`.
        #[arg(long, value_name = "SELECTOR")]
        left_device: Option<String>,

        /// Device selector (`index`, `<Type>`, or `ProductCode`) when `--right` is an ESI `.xml`.
        #[arg(long, value_name = "SELECTOR")]
        right_device: Option<String>,

        /// Revision filter (`0x...` or `"#x..."`) when `--left` is a multi-revision ESI `.xml`.
        #[arg(long, value_parser = parse_esi_u32_cli, value_name = "REV_U32")]
        left_revision: Option<u32>,

        /// Revision filter (`0x...` or `"#x..."`) when `--right` is a multi-revision ESI `.xml`.
        #[arg(long, value_parser = parse_esi_u32_cli, value_name = "REV_U32")]
        right_revision: Option<u32>,

        /// SII compilation profile (`ssc` or `minimal`) when compiling `.xml` side(s).
        #[arg(long, value_enum, ignore_case = true, default_value_t = SiiBuildProfile::Ssc, value_name = "PROFILE")]
        profile: SiiBuildProfile,

        /// Preferred `LcId` language ID when compiling `.xml` side(s).
        #[arg(long, default_value_t = 1033, value_parser = parse_u32, value_name = "LCID")]
        lcid: u32,

        /// Ignore `<Eeprom><ByteSize>` string truncation when compiling `.xml` side(s).
        #[arg(long)]
        ignore_eeprom_size: bool,

        /// Maximum number of individual differing 16-bit words to list in output.
        #[arg(long, default_value_t = 64, value_parser = parse_usize, value_name = "COUNT")]
        max_diffs: usize,
    },

    /// [OFFLINE] Patch SII header fields (`alias`, `vendor-id`, `product-code`, `revision`, `serial`) or arbitrary words and recompute CRC-8.
    #[command(
        after_long_help = "EXAMPLES:\n  # Set Configured Station Alias (word 4) to 0x0005 and auto-recompute byte 14 CRC-8\n  ethercat-cli sii patch --input slave1.bin --output slave1-alias5.bin --alias 0x0005\n\n  # Patch Serial Number and arbitrary word 0x0042\n  ethercat-cli sii patch --input slave1.bin --output patched.bin --serial 0x20260009 --set-word 0x0042=0x1234"
    )]
    Patch {
        /// Source SII `.bin` image file.
        #[arg(long, visible_alias = "file", value_name = "IN_BIN")]
        input: PathBuf,

        /// Destination path for patched & validated SII `.bin` image.
        #[arg(long, value_name = "OUT_BIN")]
        output: PathBuf,

        /// New 16-bit Configured Station Alias (bytes `0x08..0x0A`, triggers CRC-8 recalculation).
        #[arg(long, value_parser = parse_u16, value_name = "U16")]
        alias: Option<u16>,

        /// New 32-bit Vendor ID (bytes `0x10..0x14`).
        #[arg(long, value_parser = parse_u32, value_name = "U32")]
        vendor_id: Option<u32>,

        /// New 32-bit Product Code (bytes `0x14..0x18`).
        #[arg(long, value_parser = parse_u32, value_name = "U32")]
        product_code: Option<u32>,

        /// New 32-bit Revision Number (bytes `0x18..0x1C`).
        #[arg(long, value_parser = parse_u32, value_name = "U32")]
        revision: Option<u32>,

        /// New 32-bit Serial Number (bytes `0x1C..0x20`).
        #[arg(long, value_parser = parse_u32, value_name = "U32")]
        serial: Option<u32>,

        /// Patch arbitrary 16-bit word(s) formatted as `<WORD_ADDR>=<U16_VAL>` (e.g. `0x0004=0x0002`). Repeatable.
        #[arg(long = "set-word", value_name = "WORD=VAL")]
        set_words: Vec<String>,

        /// Skip automatic CRC-8 recalculation at byte 14 (`word 7` low byte).
        #[arg(long)]
        no_recalc_crc: bool,
    },

    /// [BUS-WRITE] Trigger ESC EEPROM `RELOAD` (`0x0502` command `0x0400`) on `--slave`, claiming and restoring PDI ownership.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli -i sim sii reload --slave 1\n  ethercat-cli sii reload --slave 1 --dry-run"
    )]
    Reload {
        /// 1-based slave position on the EtherCAT ring (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Preview the EEPROM reload command (`0x0502 <- 0x0400`) without opening `--iface` or touching the bus.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum EsiSubcommand {
    /// [OFFLINE] List all `<Device>` definitions in an ETG.2000 ESI `.xml` file or TwinCAT catalog directory.
    #[command(
        visible_alias = "devices",
        after_long_help = "EXAMPLES:\n  ethercat-cli esi list --xml device.xml\n  ethercat-cli --format json esi list --xml \"C:\\Program Files (x86)\\Beckhoff\\TwinCAT\\3.1\\Config\\Io\\EtherCAT\" --search AX86"
    )]
    List {
        /// Path to an ETG.2000 ESI `.xml` file or a directory containing `.xml` files.
        #[arg(long, visible_aliases = ["file", "input"], value_name = "ESI_XML_OR_DIR")]
        xml: PathBuf,

        /// Preferred ETG.2000 `LcId` language ID (`1033` = English default, `0` = first in XML order).
        #[arg(long, default_value_t = 1033, value_parser = parse_u32, value_name = "LCID")]
        lcid: u32,

        /// Optional case-insensitive substring filter across `<Type>` order code, `<Name>`, group, or `ProductCode`.
        #[arg(long, value_name = "SUBSTR")]
        search: Option<String>,
    },

    /// [OFFLINE] Inspect an ESI `.xml` device definition (ESC `ConfigData` + CRC-8, FMMUs, SMs, PDOs, Mailbox, DC OpModes, and compiled SII layout).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli esi inspect --xml device.xml\n  ethercat-cli --format json -f esi.order_code -f sii.crc_byte esi inspect --xml Beckhoff_AX8600.xml --device 0"
    )]
    Inspect {
        /// Path to an ETG.2000 ESI `.xml` file or directory.
        #[arg(long, visible_aliases = ["file", "input"], value_name = "ESI_XML_OR_DIR")]
        xml: PathBuf,

        #[command(flatten)]
        xml_opts: EsiXmlCompileArgs,
    },

    /// [OFFLINE] Compile an ETG.2000 ESI `.xml` device into an ETG.2010 SII `.bin` image (`--output`) and/or Beckhoff SSC C header (`--header-out`).
    #[command(
        visible_alias = "to-sii",
        after_long_help = "EXAMPLES:\n  ethercat-cli esi build --xml device.xml --output eeprom.bin --header-out eeprom.h\n  ethercat-cli --format json esi build --xml device.xml --profile minimal --output minimal.bin"
    )]
    Build(EsiBuildArgs),

    /// [DRY-RUN DEFAULT / 3-FACTOR GUARDED WRITE] Compile ESI `.xml` (or load `.bin`) and burn to `--slave` on `--iface` (`Npcap`, `udp://`, or `sim`).
    #[command(
        visible_alias = "program",
        after_long_help = "EXAMPLES:\n  # Dry-run diff of compiled ESI XML against live Slave 1 (zero writes)\n  ethercat-cli -i sim esi burn --slave 1 --xml device.xml --check-esc-config\n\n  # Unlocked 3-factor guarded burn over EtherCAT-over-UDP or Npcap\n  ethercat-cli -i udp://192.168.1.255:34980 esi burn --slave 1 --xml device.xml --reload \\\n    --execute --backup backup-slave1.bin --confirm WRITE-SLAVE-1"
    )]
    Burn(SiiWriteArgs),

    /// [READ-ONLY] Read slave SII EEPROM on `--iface` to `.bin` (`--output`) and/or SSC `.h` (`--header-out`), with optional `--xml` catalog matching.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli -i sim esi read --slave 1 --output readback.bin --header-out eeprom.h --xml ./esi/"
    )]
    Read(SiiReadArgs),

    /// [READ-ONLY] Verify live slave SII EEPROM on `--iface` byte-for-byte against a compiled ESI `.xml` device (or `.bin` file).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli -i \"sim://esi=device.xml\" esi verify --slave 1 --xml device.xml"
    )]
    Verify(SiiVerifyArgs),
}

#[derive(Debug, Subcommand)]
pub enum RegSubcommand {
    /// [OFFLINE] List known ESC hardware registers (`0x0000..0x0FFF`), symbolic names, byte widths, and access modes.
    List {
        /// Optional case-insensitive filter string (e.g. `al_`, `sm`, `fmmu`, `dc`, `eep`).
        #[arg(long, value_name = "SUBSTR")]
        search: Option<String>,
    },

    /// [READ-ONLY] Read an ESC register by hex offset (`0x0130`) or symbol (`al_status`), with optional bit-slicing and type decoding.
    #[command(
        after_long_help = "EXAMPLES:\n  # Read AL Status register by symbolic name\n  ethercat-cli -i sim reg read --slave 1 --reg al_status\n\n  # Read bit 4 (Port 0 Link Status) of DL Status (0x0110) as bool\n  ethercat-cli -i sim --format json -f value reg read --slave 1 --reg 0x0110 --bit-offset 4 --bit-length 1 --type bool\n\n  # Read SyncManager 0..3 (32 bytes at 0x0800) via Configured Station Address 0x1001\n  ethercat-cli -i sim reg read --config-addr 0x1001 --reg 0x0800 --length 32 --type hex"
    )]
    Read {
        /// 1-based slave position (`1..N` uses `APRD`; `0` uses `BRD`). Ignored if `--config-addr` or `--broadcast` is set.
        #[arg(short = 's', long, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: Option<u16>,

        /// Address slave by 16-bit Configured Station Address (`FPRD`, e.g. `0x1001`).
        #[arg(long, value_parser = parse_u16, value_name = "STATION_ADDR")]
        config_addr: Option<u16>,

        /// Broadcast read across all slaves (`BRD`).
        #[arg(long)]
        broadcast: bool,

        /// ESC register offset (`0x0000..0x0FFF`) or symbolic name (`al_status`, `dl_status`, `sm0`, `fmmu0`, `dc_sys_time`, etc.).
        #[arg(long, value_name = "ADDR_OR_SYMBOL")]
        reg: String,

        /// Number of bytes to read (defaults to the register's standard byte width in the catalog, or 2).
        #[arg(long, value_parser = parse_u16, value_name = "BYTES")]
        length: Option<u16>,

        /// Decode register payload (or extracted bit slice) as this type.
        #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
        ty: DataTypeSpec,

        /// Extract bitfield starting at little-endian bit offset `0..len*8-1` (bit 0 = LSB of byte 0).
        #[arg(long, value_parser = parse_usize, value_name = "BIT")]
        bit_offset: Option<usize>,

        /// Number of bits to extract when `--bit-offset` is given (defaults to width of `--type` or 1).
        #[arg(long, value_parser = parse_usize, value_name = "BITS")]
        bit_length: Option<usize>,
    },

    /// [BUS-WRITE] Write a typed or hex value to an ESC register (`APWR`, `FPWR`, or `BWR`). Supports offline `--dry-run`.
    #[command(
        after_long_help = "EXAMPLES:\n  # Preview writing Configured Station Address 0x1001 to 0x0010 offline (dry-run, no --iface needed)\n  ethercat-cli reg write --slave 1 --reg station_addr --value 0x1001 --type u16 --dry-run\n\n  # Write 0x1001 to Slave 1 ESC 0x0010\n  ethercat-cli -i sim reg write --slave 1 --reg 0x0010 --value 0x1001 --type u16"
    )]
    Write {
        /// 1-based slave position (`1..N` uses `APWR`; `0` uses `BWR`).
        #[arg(short = 's', long, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: Option<u16>,

        /// Address slave by 16-bit Configured Station Address (`FPWR`, e.g. `0x1001`).
        #[arg(long, value_parser = parse_u16, value_name = "STATION_ADDR")]
        config_addr: Option<u16>,

        /// Broadcast write across all slaves (`BWR`).
        #[arg(long)]
        broadcast: bool,

        /// ESC register offset (`0x0000..0x0FFF`) or symbolic name.
        #[arg(long, value_name = "ADDR_OR_SYMBOL")]
        reg: String,

        /// Value to encode and write (integer `0x1001`/`4097`/`-10`, float `1.5`, bool `true`, hex string, or `@file.bin`).
        #[arg(long, allow_hyphen_values = true, value_name = "VALUE")]
        value: String,

        /// Data type used to encode `--value` into little-endian bytes (`auto` uses register width if known).
        #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
        ty: DataTypeSpec,

        /// Encode and decode the register write locally without opening an interface or transmitting any frame.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum SdoSubcommand {
    /// [READ-ONLY] Upload (read) a CoE Object Dictionary entry (`index:subindex`), supporting expedited, normal, segmented, CA, and bit-slicing.
    #[command(
        after_long_help = "EXAMPLES:\n  # Read Identity Vendor ID (0x1018:01, u32) from Slave 1, auto-transitioning INIT -> PRE-OP if needed\n  ethercat-cli -i sim sdo read --slave 1 --index 0x1018 --subindex 1 --type u32 --auto-preop\n\n  # Read Manufacturer Device Name (0x1008:00, segmented string) and output raw string via -f value\n  ethercat-cli -i sim -f value sdo read --slave 1 --index 0x1008 --subindex 0 --type string --auto-preop\n\n  # Read bit 10 ('Target Reached') of CiA-402 Statusword (0x6041:00) as bool\n  ethercat-cli -i sim --format json sdo read --slave 1 --index 0x6041 --subindex 0 --bit-offset 10 --bit-length 1 --type bool --auto-preop"
    )]
    Read {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// 16-bit CoE Object Dictionary Index (e.g. `0x1018`, `0x1008`, `0x6040`).
        #[arg(long, value_parser = parse_u16, value_name = "INDEX")]
        index: u16,

        /// 8-bit CoE Object Dictionary Subindex (e.g. `0`, `1`, `0x02`).
        #[arg(long, default_value_t = 0, value_parser = parse_u8, value_name = "SUBINDEX")]
        subindex: u8,

        /// Use CoE SDO Complete Access (reads all subindices of `--index` in a single transfer).
        #[arg(long = "ca")]
        complete_access: bool,

        /// Decode uploaded bytes (or extracted bit slice) as this data type.
        #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
        ty: DataTypeSpec,

        /// Optional little-endian bit offset (`0..N`) to slice out of the uploaded SDO payload.
        #[arg(long, value_parser = parse_usize, value_name = "BIT")]
        bit_offset: Option<usize>,

        /// Number of bits to extract when `--bit-offset` is specified.
        #[arg(long, value_parser = parse_usize, value_name = "BITS")]
        bit_length: Option<usize>,

        /// Automatically transition slave from `INIT` to `PRE-OP` if mailbox is not yet active.
        #[arg(long)]
        auto_preop: bool,
    },

    /// [BUS-WRITE] Download (write) a typed value to a CoE Object Dictionary entry (`index:subindex`). Supports `--dry-run`.
    #[command(
        after_long_help = "EXAMPLES:\n  # Write CiA-402 Controlword (0x6040:00 = 0x000F Enable Operation) as u16\n  ethercat-cli -i sim sdo write --slave 1 --index 0x6040 --subindex 0 --value 0x000F --type u16 --auto-preop\n\n  # Write Target Position (0x607A:00 = -25000) as i32 in dry-run mode\n  ethercat-cli -i sim --format json sdo write --slave 1 --index 0x607A --subindex 0 --value=-25000 --type i32 --dry-run"
    )]
    Write {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// 16-bit CoE Object Dictionary Index (e.g. `0x6040`, `0x607A`).
        #[arg(long, value_parser = parse_u16, value_name = "INDEX")]
        index: u16,

        /// 8-bit CoE Object Dictionary Subindex.
        #[arg(long, default_value_t = 0, value_parser = parse_u8, value_name = "SUBINDEX")]
        subindex: u8,

        /// Value to encode and download (supports negative numbers when `--type i8/i16/i32/i64/f32/f64`, hex, strings, or `@file`).
        #[arg(long, allow_hyphen_values = true, value_name = "VALUE")]
        value: String,

        /// Data type used to encode `--value` (`u8`, `u16`, `u32`, `i16`, `i32`, `f32`, `string`, `hex`, etc.).
        #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
        ty: DataTypeSpec,

        /// Use CoE SDO Complete Access download.
        #[arg(long = "ca")]
        complete_access: bool,

        /// Automatically transition slave from `INIT` to `PRE-OP` if mailbox is inactive.
        #[arg(long)]
        auto_preop: bool,

        /// Validate and encode payload without transmitting any mailbox frame on the bus.
        #[arg(long)]
        dry_run: bool,
    },

    /// [READ-ONLY] Query live CoE Object Dictionary list, object descriptions, and subindex entry metadata via SDO Information (`0x08`).
    #[command(
        after_long_help = "EXAMPLES:\n  # List all CoE Object Dictionary objects on Slave 1\n  ethercat-cli -i sim sdo info --slave 1 --auto-preop\n\n  # Inspect all subindex entries, bit lengths, and access flags of 0x1018 (Identity Object)\n  ethercat-cli -i sim --format json sdo info --slave 1 --index 0x1018 --entries --auto-preop"
    )]
    Info {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Inspect only a single 16-bit Object Dictionary index instead of querying the entire OD list.
        #[arg(long, value_parser = parse_u16, value_name = "INDEX")]
        index: Option<u16>,

        /// Also query `Get Entry Description` (`0x05`) for every subindex (`0..max_subindex`).
        #[arg(long)]
        entries: bool,

        /// Automatically transition slave from `INIT` to `PRE-OP` if mailbox is inactive.
        #[arg(long)]
        auto_preop: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum PdoSubcommand {
    /// [READ-ONLY / OFFLINE] Discover `RxPDO` (outputs) and `TxPDO` (inputs) bit-level mapping via CoE (`0x1C12`/`0x1C13`) or SII EEPROM.
    #[command(
        after_long_help = "EXAMPLES:\n  # Read live PDO mapping from Slave 1 (auto-tries CoE 0x1C12/0x1C13 then SII Categories 50/51)\n  ethercat-cli -i sim pdo map --slave 1 --auto-preop\n\n  # Extract PDO mapping offline from an SII .bin dump without touching the bus\n  ethercat-cli --format json pdo map --sii-file slave1-eeprom.bin"
    )]
    Map {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Mapping discovery source (`auto`, `sii`, or `coe`).
        #[arg(long, value_enum, ignore_case = true, default_value_t = PdoSource::Auto, value_name = "SOURCE")]
        source: PdoSource,

        /// Offline SII `.bin` file to parse PDO categories from (runs 100% offline when provided).
        #[arg(long, value_name = "IMAGE_BIN")]
        sii_file: Option<PathBuf>,

        /// Automatically transition slave to `PRE-OP` when querying live CoE PDO assignment (`0x1C12`/`0x1C13`).
        #[arg(long)]
        auto_preop: bool,
    },

    /// [READ-ONLY] Read live `TxPDO` process inputs from a slave (via `SM3` physical `APRD` or logical `LRD`), filtering by entry or bit slice.
    #[command(
        after_long_help = "EXAMPLES:\n  # Read and decode all mapped TxPDO inputs from Slave 1\n  ethercat-cli -i sim pdo read --slave 1\n\n  # Read only CiA-402 Position Actual Value (0x6064:00) using -f\n  ethercat-cli -i sim --format json -f 0x6064:00 pdo read --slave 1\n\n  # Read arbitrary bit slice (offset 16, 32 bits as i32) via logical address 0x00010000\n  ethercat-cli -i sim pdo read --slave 1 --logical-addr 0x00010000 --auto-map --bit-offset 16 --bit-length 32 --type i32"
    )]
    Read {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// Read via 32-bit Logical Memory Read (`LRD`) instead of physical SyncManager 3 (`APRD`).
        #[arg(long, value_parser = parse_u32, value_name = "LOGICAL_ADDR")]
        logical_addr: Option<u32>,

        /// Program FMMU0/FMMU1 for `--logical-addr` before issuing `LRD` [BUS-WRITE to FMMU].
        #[arg(long)]
        auto_map: bool,

        /// Filter decoded PDO entries to a specific field name or `0xXXXX:XX` CoE entry ID.
        #[arg(long, value_name = "NAME_OR_0xXXXX:XX")]
        entry: Option<String>,

        /// Extract raw bit slice starting at little-endian bit offset `0..N`.
        #[arg(long, value_parser = parse_usize, value_name = "BIT")]
        bit_offset: Option<usize>,

        /// Bit slice width when `--bit-offset` is given.
        #[arg(long, value_parser = parse_usize, value_name = "BITS")]
        bit_length: Option<usize>,

        /// Data type for `--bit-offset` slice decoding.
        #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
        ty: DataTypeSpec,

        /// Override slave PDO layout with explicit spec (`statusword:u16@0,actual_pos:i32@16`). Skips live CoE/SII PDO queries.
        #[arg(long, value_name = "LAYOUT_SPEC")]
        layout: Option<String>,

        /// Optional SII `.bin` file providing PDO layout instead of reading slave SII/CoE.
        #[arg(long, value_name = "IMAGE_BIN")]
        sii_file: Option<PathBuf>,
    },

    /// [BUS-WRITE] Execute a cyclic `LRW` process data exchange: pack `RxPDO` output assignments, send `LRW`, and decode returned `TxPDO` inputs.
    #[command(
        after_long_help = "EXAMPLES:\n  # Set Controlword (0x6040:00=0x000F) & Target Position (0x607A:00=12500), map FMMUs, and run LRW\n  ethercat-cli -i sim --format json pdo exchange --slave 1 --auto-map \\\n    --set 0x6040:00=0x000F --set 0x607A:00=12500\n\n  # Offline dry-run PDO packing with explicit RxPDO layout (no --iface needed)\n  ethercat-cli pdo exchange --rx-layout \"ctrl:u16@0,target:i32@16\" --set ctrl=0x0006 --set target=-500 --dry-run"
    )]
    Exchange {
        /// 1-based slave position (`1..N`).
        #[arg(short = 's', long, default_value_t = 1, value_parser = parse_u16, value_name = "SLAVE_POS")]
        slave: u16,

        /// 32-bit Logical Memory Address for `LRW` exchange.
        #[arg(long, default_value_t = 0x0001_0000, value_parser = parse_u32, value_name = "LOGICAL_ADDR")]
        logical_addr: u32,

        /// Automatically configure FMMU0 (`SM2` outputs) and FMMU1 (`SM3` inputs) to `--logical-addr`.
        #[arg(long)]
        auto_map: bool,

        /// Set mapped `RxPDO` field(s) by name or `0xXXXX:XX` (`<field>=<value>`). Repeatable.
        #[arg(long = "set", allow_hyphen_values = true, value_name = "FIELD=VALUE")]
        set_fields: Vec<String>,

        /// Optional baseline output payload in hex before applying `--set` overrides.
        #[arg(long, value_name = "HEX")]
        tx_hex: Option<String>,

        /// Optional explicit `RxPDO` output layout override (`ctrl:u16@0,target:i32@16`).
        #[arg(long, value_name = "LAYOUT_SPEC")]
        rx_layout: Option<String>,

        /// Optional explicit `TxPDO` input layout override (`status:u16@0,actual:i32@16`).
        #[arg(long, value_name = "LAYOUT_SPEC")]
        tx_layout: Option<String>,

        /// Optional SII `.bin` file providing PDO layout.
        #[arg(long, value_name = "IMAGE_BIN")]
        sii_file: Option<PathBuf>,

        /// Pack `RxPDO` output bytes and print hex without transmitting on the bus (works offline with `--rx-layout` or `--sii-file`).
        #[arg(long)]
        dry_run: bool,
    },

    /// [OFFLINE] Decode a raw PDO payload hex string using a compact `--layout` spec or `--sii-file`.
    #[command(
        after_long_help = "LAYOUT SPEC FORMAT:\n  Comma-separated `<name>:<type>@<bit_offset>[:<bit_len>]`\n  Example: `statusword:u16@0,actual_pos:i32@16,op_mode:i8@48,ready:bool@0`\n\nEXAMPLES:\n  ethercat-cli --format json pdo decode --hex \"3704d430000008\" --layout \"statusword:u16@0,actual_pos:i32@16,mode:i8@48\"\n  ethercat-cli -f actual_pos pdo decode --hex \"3704d430000008\" --layout \"statusword:u16@0,actual_pos:i32@16\""
    )]
    Decode {
        /// Raw PDO bytes in hex (or `@file.bin`).
        #[arg(long, value_name = "HEX_OR_AT_FILE")]
        hex: String,

        /// Compact PDO layout specification (`name:type@bit_offset[:bit_len],...`).
        #[arg(long, value_name = "LAYOUT_SPEC")]
        layout: Option<String>,

        /// Or load layout from an SII `.bin` file (`tx` or `rx` direction).
        #[arg(long, value_name = "IMAGE_BIN")]
        sii_file: Option<PathBuf>,

        /// PDO direction (`tx` = slave inputs, `rx` = slave outputs) when `--sii-file` is used.
        #[arg(long, default_value = "tx", value_name = "tx|rx")]
        direction: String,
    },

    /// [OFFLINE] Pack `FIELD=VALUE` assignments into a little-endian PDO hex payload according to `--layout` or `--sii-file`.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli pdo encode --layout \"ctrl:u16@0,target_pos:i32@16\" --set ctrl=0x000F --set target_pos=-5000"
    )]
    Encode {
        /// Compact PDO layout specification (`name:type@bit_offset[:bit_len],...`).
        #[arg(long, value_name = "LAYOUT_SPEC")]
        layout: Option<String>,

        /// Or load layout from an SII `.bin` file.
        #[arg(long, value_name = "IMAGE_BIN")]
        sii_file: Option<PathBuf>,

        /// PDO direction (`rx` or `tx`) when `--sii-file` is used.
        #[arg(long, default_value = "rx", value_name = "rx|tx")]
        direction: String,

        /// Field assignment(s) `<name_or_0xXXXX:XX>=<value>`. Repeatable.
        #[arg(
            long = "set",
            allow_hyphen_values = true,
            required = true,
            value_name = "FIELD=VALUE"
        )]
        set_fields: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum FrameSubcommand {
    /// [OFFLINE] Construct a valid `0x88A4` Ethernet + EtherCAT DLPDU frame (1 or more chained subframes), dissect it, and output hex/binary.
    #[command(
        after_long_help = "SUBFRAME SPEC FORMAT (`--subframe`, repeatable for multi-datagram frames):\n  `<CMD>:<ADDR>:<DATA_HEX_OR_ZERO_LEN>[@idx=<U8>][@wkc=<U16>][@irq=<U16>][@c=<0|1>][@m=<0|1>]`\n  - Positioned commands (`APRD`, `FPWR`, `BRD`, ...): `<ADDR>` is `<ADP>,<ADO>` (e.g. `0x0000,0x0130`)\n  - Logical commands (`LRD`, `LWR`, `LRW`): `<ADDR>` is `<LOGICAL_ADDR_U32>` (e.g. `0x00010000`)\n  - `<DATA>`: `0x...` hex bytes OR `zeros:<N>` to allocate `N` zero bytes (e.g. `zeros:6`)\n  - Optional `@key=val` header/trailer overrides (repeatable in any order): `@idx=`, `@wkc=`, `@irq=`, `@c=`, `@m=`\n\nEXAMPLES:\n  # Build a multi-datagram frame chaining BRD 0x0000 (4B) + BRD 0x0130 (6B), padded to 60B Ethernet min\n  ethercat-cli frame build \\\n    --subframe \"BRD:0x0000,0x0000:zeros:4@idx=0x10\" \\\n    --subframe \"BRD:0x0000,0x0130:zeros:6@wkc=2@irq=0x0004\" \\\n    --pad"
    )]
    Build {
        /// Destination MAC address (defaults to broadcast `ff:ff:ff:ff:ff:ff`).
        #[arg(long, default_value = "ff:ff:ff:ff:ff:ff", value_name = "MAC")]
        dst_mac: String,

        /// Source MAC address (defaults to SOEM primary master `01:01:01:01:01:01`).
        #[arg(long, default_value = "01:01:01:01:01:01", value_name = "MAC")]
        src_mac: String,

        /// Optional IEEE 802.1Q 12-bit VLAN ID (`0..4095`).
        #[arg(long, value_parser = parse_u16, value_name = "VID")]
        vlan: Option<u16>,

        /// Pad Ethernet frame with trailing zeroes to 60 bytes minimum wire length.
        #[arg(long)]
        pad: bool,

        /// Subframe specification `<CMD>:<ADP,ADO_or_LAD>:<HEX_or_zeros:N>[@idx=..][@wkc=..][@irq=..][@c=..]`. Repeatable; sets `M` (more) bit on non-final subframes unless `@m=` overrides it.
        #[arg(long = "subframe", required = true, value_name = "SPEC")]
        subframes: Vec<String>,

        /// Optional file path to write raw binary frame bytes.
        #[arg(long, value_name = "OUT_BIN")]
        output: Option<PathBuf>,
    },

    /// [BUS-WRITE] Transmit a raw `0x88A4` Ethernet frame (from `--hex` or `--file`) on `--iface`, optionally awaiting & dissecting the response.
    #[command(
        after_long_help = "EXAMPLES:\n  # Send raw BRD 0x0000 frame on virtual simulator and dissect returned frame\n  ethercat-cli -i sim --format json frame send \\\n    --hex \"ffffffffffff01010101010188a41010072a0000000004000000000000000000\"\n\n  # Dry-run: dissect TX frame without sending\n  ethercat-cli frame send --hex \"ffffffffffff01010101010188a40e100701000000000200000000000000\" --dry-run"
    )]
    Send {
        /// Raw Ethernet frame bytes in hex (`0x88A4`). Mutually exclusive with `--file`.
        #[arg(long, conflicts_with = "file", value_name = "HEX")]
        hex: Option<String>,

        /// Read raw Ethernet frame from `.bin`, `.hex`, `.pcap`, or `.pcapng` file.
        #[arg(long, visible_alias = "input", value_name = "FILE")]
        file: Option<PathBuf>,

        /// Fire-and-forget TX without waiting for the returning EtherCAT ring frame.
        #[arg(long)]
        no_wait_rx: bool,

        /// Validate and dissect TX frame locally without sending onto `--iface`.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Args)]
pub struct DatagramArgs {
    /// EtherCAT datagram command (`nop`, `aprd`, `apwr`, `aprw`, `fprd`, `fpwr`, `fprw`, `brd`, `bwr`, `brw`, `lrd`, `lwr`, `lrw`, `armw`, `frmw`).
    #[arg(long, value_enum, ignore_case = true, value_name = "CMD")]
    pub cmd: EcatCmd,

    /// Convenience 1-based slave position (`1..N`): sets `ADP = 1 - slave` for auto-increment commands (`AP*`/`ARMW`) or `0x1000 + slave` for `FP*`/`FRMW`.
    #[arg(short = 's', long, value_parser = parse_u16, value_name = "SLAVE_POS")]
    pub slave: Option<u16>,

    /// Explicit 16-bit Address Position (`ADP`) for positioned/broadcast commands.
    #[arg(long, default_value_t = 0, value_parser = parse_u16, value_name = "U16")]
    pub adp: u16,

    /// 16-bit Physical Offset Address (`ADO`, e.g. `0x0130`) for positioned/broadcast commands.
    #[arg(long, default_value_t = 0, value_parser = parse_u16, value_name = "U16")]
    pub ado: u16,

    /// 32-bit Logical Memory Address (`LAD`) for `LRD`, `LWR`, and `LRW` commands.
    #[arg(long, default_value_t = 0, value_parser = parse_u32, value_name = "U32")]
    pub logical_addr: u32,

    /// Payload bytes to send in hex (`"01 00"` or `@payload.bin`), OR omit and pass `--len <N>` for zero-filled read buffers.
    #[arg(long, value_name = "HEX_OR_AT_FILE")]
    pub data: Option<String>,

    /// Zero-filled payload byte length when `--data` is omitted (defaults to 2).
    #[arg(long, value_parser = parse_usize, value_name = "BYTES")]
    pub len: Option<usize>,

    /// Decode returned datagram payload (or extracted bit slice) as this type.
    #[arg(long = "type", value_enum, ignore_case = true, default_value_t = DataTypeSpec::Auto, value_name = "TYPE")]
    pub ty: DataTypeSpec,

    /// Extract little-endian bit slice starting at `BIT` from response payload.
    #[arg(long, value_parser = parse_usize, value_name = "BIT")]
    pub bit_offset: Option<usize>,

    /// Bit slice length when `--bit-offset` is set.
    #[arg(long, value_parser = parse_usize, value_name = "BITS")]
    pub bit_length: Option<usize>,

    /// Fail with exit code 4 (`Mismatch`) if returned Working Counter (`WKC`) does not equal this value.
    #[arg(long, value_parser = parse_u16, value_name = "WKC")]
    pub expect_wkc: Option<u16>,

    /// Build and dissect the outgoing datagram frame without transmitting on `--iface`.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct DissectArgs {
    /// Hexadecimal string of a single Ethernet/EtherCAT frame. Mutually exclusive with `--file`.
    #[arg(long, conflicts_with = "file", value_name = "HEX")]
    pub hex: Option<String>,

    /// Path to `.pcap`, `.pcapng`, Windows PktMon `.txt`, `.hex`, or `.bin` capture file.
    #[arg(long, visible_alias = "input", value_name = "PATH")]
    pub file: Option<PathBuf>,

    /// Explicit input file format (`auto`, `pcap`, `pcapng`, `pktmon`, `hex`, `bin`).
    #[arg(long, value_enum, ignore_case = true, default_value_t = FrameInputKind::Auto, value_name = "KIND")]
    pub input_kind: FrameInputKind,

    /// Maximum number of EtherCAT frames to dissect when reading multi-packet `.pcap`, `.pcapng`, or PktMon `.txt` files (`0` = unlimited).
    #[arg(long, default_value_t = 50, value_parser = parse_usize, value_name = "MAX_FRAMES")]
    pub limit: usize,

    /// Input bytes start directly at the 2-byte EtherCAT Frame Header without a 14-byte Ethernet II header.
    #[arg(long)]
    pub bare: bool,

    /// Force mailbox dissection on physical datagram payloads even if heuristic checks do not trigger.
    #[arg(long)]
    pub force_mailbox: bool,

    /// Compact PDO layout specification (`name:type@bit_offset[:bit_len],...`) to populate `ecat.pdo.*` fields.
    #[arg(long, value_name = "SPEC")]
    pub pdo_layout: Option<String>,

    /// Load PDO layout from an SII `.bin` image to populate `ecat.pdo.*` fields.
    #[arg(long, value_name = "IMAGE_BIN")]
    pub sii_pdo: Option<PathBuf>,

    /// Direction (`tx` or `rx`) when loading PDO layout from `--sii-pdo`.
    #[arg(long, default_value = "tx", value_name = "tx|rx")]
    pub pdo_dir: String,

    /// Repeatable ETG.2000 ESI `<EtherCATInfo>`, Offline OD `<EtherCATDict>`, or ETG.2100 ENI `<EtherCATConfig>` `.xml` file or directory for XML-driven CoE SDO decoding (`ecat_mailbox.coe.sdo.xml.*`) and stateful temporal PDO dissection (`ecat.pdo.*` only on cyclic frames appearing AFTER PDO configuration packets in the capture).
    #[arg(long = "xml", value_name = "XML_OR_DIR")]
    pub xml: Vec<PathBuf>,

    /// Optional device selector (`<Type>`, `<Name>`, `ProductCode`, or 0-based index) when `--xml` contains multiple `<Device>` profiles and trace packets do not carry SII (`0x0508`) or `0x1018` identity reads.
    #[arg(long, value_name = "DEVICE")]
    pub xml_device: Option<String>,
}

pub fn parse_ssc_define_kv(raw: &str) -> std::result::Result<(String, String), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("SSC define override cannot be empty (expected `NAME=VALUE`)".into());
    }
    if let Some((k, v)) = trimmed.split_once('=') {
        let key = k.trim();
        if key.is_empty() {
            return Err(format!("invalid SSC define override '{raw}': empty name"));
        }
        Ok((key.to_string(), v.trim().to_string()))
    } else {
        Ok((trimmed.to_string(), String::new()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SscTemplateKind {
    /// Semicolon-delimited `.csv` SSC Object Dictionary wizard template.
    Csv,
    /// Self-contained OpenXML `.xlsx` SSC Object Dictionary wizard spreadsheet.
    Xlsx,
}

#[derive(Debug, Subcommand)]
pub enum SscSubcommand {
    /// [OFFLINE] Generate EtherCAT Slave Stack Code (`src/*.c/*.h`, `ecat_def.h`, `eeprom.h`), `<Project>.xml` ESI, and `<Project>.esp` (`SSC Tool Cmd` parity).
    #[command(
        long_about = "[OFFLINE] Full pure-Rust EtherCAT Slave Stack Code (SSC) project generator with byte/line parity to Beckhoff `SSC Tool` and `SSC Tool Cmd`.\n\n\
Discovers the installed SSC configuration automatically (from `-p`, `--ssc-dir`, `ETHERCAT_SSC_DIR`, Windows Registry `HKLM\\SOFTWARE\\(Wow6432Node\\)Beckhoff\\ET9300`, or `%APPDATA%\\Beckhoff Automation GmbH & Co. KG\\ET9300 Tool\\SSC\\cfg\\SlaveConfigFile.escfg`).",
        after_long_help = "EXAMPLES:\n  # Generate default EL9800 SSC stack, SlaveProject.xml ESI, and SlaveProject.esp\n  ethercat-cli ssc generate --output ./out_slave\n\n  # Import a custom XLSX/CSV Object Dictionary and override VENDOR_ID + CREATE_EEPROM_CONTENT\n  ethercat-cli ssc generate -a MyDrive.xlsx -d VENDOR_ID=0xE0000002 -d CREATE_EEPROM_CONTENT=1 --output ./out_drive\n\n  # Apply an external hardware configuration with third-party source file import enabled\n  ethercat-cli ssc generate -c CustomConfigs.xml --config-name \"FC1100 Sample\" --allow-file-import --output ./out_fc1100"
    )]
    Generate(Box<SscGenerateArgs>),

    /// [OFFLINE] List SSC configuration defines, values, types, flags, and descriptions (`SSC Tool Cmd -l` parity).
    #[command(
        visible_alias = "defines",
        after_long_help = "EXAMPLES:\n  # Exact `SSC Tool Cmd -l` text output of writable defines\n  ethercat-cli ssc list-defines\n\n  # Full JSON schema including read-only/evaluated flags and descriptions filtered by 'MBX'\n  ethercat-cli --format json ssc list-defines --all --filter MBX"
    )]
    ListDefines {
        /// SSC `.esp` project, `.escfg` / `SlaveConfigFile.xml`, or SSC folder. Auto-discovered if omitted.
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root or `src` directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Optional configuration `.xml`/`.escfg`/`.h` to apply before listing defines.
        #[arg(short = 'c', long = "config", value_name = "FILE")]
        config: Option<PathBuf>,

        /// Configuration name inside `--config` (or embedded in `.escfg`).
        #[arg(long, value_name = "NAME")]
        config_name: Option<String>,

        /// Include `ReadOnly="True"` computed defines as well (by default only writable defines are listed, matching `SSC Tool Cmd -l`).
        #[arg(long)]
        all: bool,

        /// Case-insensitive substring filter on `CodeDefine`, `FileArea`, or `NodePath`.
        #[arg(long, value_name = "SUBSTR")]
        filter: Option<String>,
    },

    /// [OFFLINE] List hardware/sample `<Configuration>` presets embedded in `.escfg` or inside an external configuration XML.
    #[command(
        visible_alias = "configs",
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc list-configs\n  ethercat-cli --format json ssc list-configs -c Beckhoff_Configs.xml"
    )]
    ListConfigs {
        /// SSC `.esp`/`.escfg` project/config path (used when `--config` is omitted).
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// External `<SscToolConfiguration>` `.xml` or `.h` file to inspect instead of embedded presets.
        #[arg(short = 'c', long = "config", value_name = "FILE")]
        config: Option<PathBuf>,
    },

    /// [OFFLINE] Export current SSC project settings to a reusable `<SscToolConfiguration>` `.xml` file.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc export-config -p MySlave.esp --name \"Board Rev B\" --output board_rev_b_cfg.xml"
    )]
    ExportConfig {
        /// SSC `.esp` project or `.escfg` source. Auto-discovered if omitted.
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Optional `NAME=VALUE` define overrides to apply prior to export. Repeatable.
        #[arg(short = 'd', long = "define", value_parser = parse_ssc_define_kv, value_name = "NAME=VALUE")]
        defines: Vec<(String, String)>,

        /// Configuration `@Name` written into `<Configuration Name="...">`.
        #[arg(long, default_value = "ExportedConfiguration", value_name = "NAME")]
        name: String,

        /// Optional `@Info` description attribute on `<Configuration>`.
        #[arg(long, default_value = "", value_name = "TEXT")]
        info: String,

        /// Output `.xml` file path for `<SscToolConfiguration>`.
        #[arg(long = "output", value_name = "XML_OUT")]
        output: PathBuf,
    },

    /// [OFFLINE] Import `#define` settings from an existing `ecat_def.h` C header into an `.esp` project or `.xml` config.
    #[command(
        after_long_help = "EXAMPLES:\n  # Create a new .esp project populated from an existing firmware ecat_def.h\n  ethercat-cli ssc import-header --header ./firmware/ecat_def.h --output ImportedSlave.esp"
    )]
    ImportHeader {
        /// Path to existing `ecat_def.h` header file.
        #[arg(long, value_name = "ECAT_DEF_H")]
        header: PathBuf,

        /// Base SSC `.escfg`/`.esp` template to apply imported settings onto. Auto-discovered if omitted.
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Output `.esp` project path (or `.xml` if ending with `.xml` to save as `<SscToolConfiguration>`).
        #[arg(long = "output", value_name = "OUT_PATH")]
        output: PathBuf,

        /// Ignore unknown/legacy `#define` macros not present in the base SSC schema.
        #[arg(long)]
        ignore_errors: bool,
    },

    /// [OFFLINE] Import SSC device/mailbox/SM/DC settings from an ETG.2000 ESI `.xml` (`SlaveSetting::ParseESI` parity) into `.esp` or `.xml` config.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc import-esi --esi Device.xml --output ImportedFromEsi.esp"
    )]
    ImportEsi {
        /// Path to source ETG.2000 ESI `.xml` file.
        #[arg(long, value_name = "ESI_XML")]
        esi: PathBuf,

        /// 0-based `<Device>` index inside `<Devices>` to import from.
        #[arg(long, default_value_t = 0, value_parser = parse_usize, value_name = "IDX")]
        device_index: usize,

        /// Base SSC `.escfg`/`.esp` template to apply imported settings onto. Auto-discovered if omitted.
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Output `.esp` project path (or `.xml` if ending with `.xml` to save as `<SscToolConfiguration>`).
        #[arg(long = "output", value_name = "OUT_PATH")]
        output: PathBuf,

        /// Ignore unknown settings not present in the base SSC schema.
        #[arg(long)]
        ignore_errors: bool,
    },

    /// [OFFLINE] Migrate/adapt an older `.esp` SSC project onto a newer SSC version (`SlaveProject::AdaptProject` parity).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc migrate -p OldSlave_5v12.esp --output MigratedSlave_5v13.esp"
    )]
    Migrate {
        /// Existing `.esp` project file to migrate.
        #[arg(short = 'p', long = "project", value_name = "OLD_ESP")]
        project: PathBuf,

        /// Target SSC `.escfg` / `SlaveConfigFile.xml` or SSC folder (auto-discovered if omitted).
        #[arg(long, value_name = "TARGET_CFG")]
        target_ssc: Option<PathBuf>,

        /// Explicit SSC root directory override for the target SSC version.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Output path for the migrated `.esp` project file.
        #[arg(long = "output", value_name = "NEW_ESP")]
        output: PathBuf,

        /// Continue past non-fatal setting migration mismatches.
        #[arg(long)]
        ignore_errors: bool,
    },

    /// [OFFLINE] Combine multiple ETG.2000 ESI `.xml` files into one multi-device ESI XML (`EsiGenerator::CombineEsiFiles` parity).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc combine-esi -i SlaveA.xml -i SlaveB.xml --output CombinedCatalog.xml"
    )]
    CombineEsi {
        /// Two or more input ETG.2000 ESI `.xml` files to merge (`<Groups>`, `<Scalings>`, `<Devices>`, `<Modules>`).
        #[arg(short = 'i', long = "input", required = true, num_args = 1.., value_name = "ESI_XML")]
        inputs: Vec<PathBuf>,

        /// Destination combined ESI `.xml` path (backs up existing file to `<output>.bak`).
        #[arg(long = "output", value_name = "OUT_ESI_XML")]
        output: PathBuf,
    },

    /// [OFFLINE] Validate `<SettingConflicts>` rules and `UpdateInformation.xml` known issues on an SSC project.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli --format json ssc check -p SlaveProject.esp\n  ethercat-cli ssc check -d COE_SUPPORTED=1 -d MAILBOX_SUPPORTED=0"
    )]
    Check {
        /// SSC `.esp` project or `.escfg` config. Auto-discovered if omitted.
        #[arg(short = 'p', long = "project", value_name = "PATH")]
        project: Option<PathBuf>,

        /// Explicit SSC root directory override.
        #[arg(long, value_name = "DIR")]
        ssc_dir: Option<PathBuf>,

        /// Optional `NAME=VALUE` define overrides to test before checking conflicts. Repeatable.
        #[arg(short = 'd', long = "define", value_parser = parse_ssc_define_kv, value_name = "NAME=VALUE")]
        defines: Vec<(String, String)>,

        /// Optional explicit path to `UpdateInformation.xml` (defaults to `%APPDATA%\\...\\UpdateInformation.xml` if installed).
        #[arg(long, value_name = "XML")]
        issues_xml: Option<PathBuf>,
    },

    /// [OFFLINE] Standalone Object Dictionary (`SSC OD Tool`) C code/header/offline-XML generator and CSV/XLSX wizard templates.
    #[command(subcommand)]
    Od(SscOdSubcommand),

    /// [OFFLINE] Update an existing ETG.2000 ESI `.xml` in place from an OD file (`.xlsx`, `.csv`, `.xml`, `.eds`, `.tmc`) with `.bak` backup.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc update-esi --esi TargetSlave.xml --od MyOd.xlsx"
    )]
    UpdateEsi {
        /// Existing target ETG.2000 ESI `.xml` file to update in place (original is backed up to `<file>.bak`).
        #[arg(long, value_name = "ESI_XML")]
        esi: PathBuf,

        /// Input Object Dictionary file(s) (`.xlsx`, `.csv`, `.xml`, `.eds`, `.tmc`).
        #[arg(long, required = true, num_args = 1.., value_name = "OD_FILE")]
        od: Vec<PathBuf>,

        /// 0-based `<Device>` index inside `<Devices>` to update.
        #[arg(long, default_value_t = 0, value_parser = parse_usize, value_name = "IDX")]
        device_index: usize,
    },

    /// [OFFLINE] Apply a Beckhoff unified `.patch` diff directly to a directory of SSC `.c`/`.h` source files.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc patch --patch Hotfix.patch --src-dir ./src"
    )]
    Patch {
        /// Unified `.patch` file to apply.
        #[arg(long, value_name = "PATCH_FILE")]
        patch: PathBuf,

        /// Target source directory containing `.c`/`.h` files referenced in `--patch`.
        #[arg(long, value_name = "SRC_DIR")]
        src_dir: PathBuf,
    },

    /// [OFFLINE] Encode a `16x14` `.bmp`/`.png`/`.gif` icon into ESI `<ImageData16x14>` uppercase hex (`SSC Tool` parity).
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc image-hex --image device_16x14.bmp"
    )]
    ImageHex {
        /// Path to `16x14` `.bmp`, `.png`, or `.gif` image file.
        #[arg(long, value_name = "IMAGE_PATH")]
        image: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct SscGenerateArgs {
    /// SSC `.esp` project, `.escfg` / `SlaveConfigFile.xml`, or SSC folder. Auto-discovered from Registry / `%APPDATA%` / `ETHERCAT_SSC_DIR` if omitted.
    #[arg(short = 'p', long = "project", value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Explicit directory containing Beckhoff SSC (`cfg/` and `src/`).
    #[arg(long, value_name = "DIR")]
    pub ssc_dir: Option<PathBuf>,

    /// Target output directory for `<Project>.esp`, `<Project>.xml`, and `src/*` (defaults to `<AppDir>/SlaveFiles` when `-a` is given, or `<EspDir>` when `-p *.esp` is given).
    #[arg(long = "output", value_name = "OUT_DIR")]
    pub output: Option<PathBuf>,

    /// Override C/H source output directory (defaults to `<output>/src`).
    #[arg(long, value_name = "SRC_DIR")]
    pub src_dir: Option<PathBuf>,

    /// Override output project stem for `<Name>.esp` and `<Name>.xml` (defaults to `SlaveProject`, or `<AppName>` when `-a` is provided).
    #[arg(long, value_name = "PROJECT_NAME")]
    pub name: Option<String>,

    /// Import custom Application / Object Dictionary file(s) (`.xlsx`, `.csv`, `.xml`, `.eds`, `.tmc`). Repeatable (`-a base.xlsx -a mod.xlsx`).
    #[arg(short = 'a', long = "app", value_name = "OD_FILE")]
    pub app: Vec<PathBuf>,

    /// Apply external `<SscToolConfiguration>` `.xml`, `.escfg`, `.esp`, or `ecat_def.h` configuration file.
    #[arg(short = 'c', long = "config", value_name = "CFG_FILE")]
    pub config: Option<PathBuf>,

    /// Select a named `<Configuration Name="...">` inside `--config` (or embedded in `.escfg`).
    #[arg(long, value_name = "CFG_NAME")]
    pub config_name: Option<String>,

    /// Allow importing third-party `<File>` entries referenced by `--config` (`SSC Tool Cmd -co allowFileImport` parity).
    #[arg(long)]
    pub allow_file_import: bool,

    /// Attach and apply a unified `.patch` file during C/H code generation.
    #[arg(long, value_name = "PATCH_FILE")]
    pub patch: Option<PathBuf>,

    /// Override SSC configuration define (`NAME=VALUE`, e.g. `-d VENDOR_ID=0xE0000002 -d CREATE_EEPROM_CONTENT=1`). Repeatable.
    #[arg(short = 'd', long = "define", value_parser = parse_ssc_define_kv, value_name = "NAME=VALUE")]
    pub defines: Vec<(String, String)>,

    /// Apply installed GUI `Options.xml` defaults (`VendorID`, `VendorName`, `DefaultPatch.patch`).
    #[arg(long)]
    pub use_gui_options: bool,

    /// Explicit `Options.xml` file to apply.
    #[arg(long, value_name = "OPTIONS_XML")]
    pub options_file: Option<PathBuf>,

    /// Emit raw SSC `.c`/`.h` source files without stripping `Evaluate="True"` `#if` blocks.
    #[arg(long)]
    pub raw_files: bool,

    /// Insert `/*ET9300 Project Handler :(...) lines X to Y deleted*/` comments when `#if` branches are stripped.
    #[arg(long)]
    pub delete_comments: bool,

    /// Skip writing `<Project>.esp` project archive.
    #[arg(long)]
    pub no_esp: bool,

    /// Skip writing `<Project>.xml` ETG.2000 ESI device description.
    #[arg(long)]
    pub no_esi: bool,

    /// Embed `<VendorSpecific><SSC><Settings>` inside generated `<Project>.xml` ESI (`AddCodeConfigToEsi` parity).
    #[arg(long)]
    pub esi_code_config: bool,

    /// Embed `<VendorSpecific><TwinCAT><TraceFile>` path inside generated `<Project>.xml` ESI.
    #[arg(long, value_name = "TRACE_PATH")]
    pub esi_trace_file: Option<String>,

    /// Also compile the generated ESI XML directly into a binary SII EEPROM image (`.bin`).
    #[arg(long, value_name = "SII_BIN")]
    pub sii_out: Option<PathBuf>,

    /// Fail with exit code 5 if any `<SettingConflict Type="error">` evaluates active.
    #[arg(long)]
    pub strict_conflicts: bool,

    /// Continue past non-fatal configuration migration or missing-file errors.
    #[arg(long)]
    pub ignore_errors: bool,
}

#[derive(Debug, Subcommand)]
pub enum SscOdSubcommand {
    /// [OFFLINE] Standalone `SSC OD Tool` generator: parse `.xlsx`/`.xlsm`/`.csv`/`.xml`/`.esp`/`.eds`/`.tmc` into `<App>Objects.h`, `<App>.h`, `<App>.c`, and `output/<App>Objects.xml` (or update ESI).
    #[command(
        after_long_help = "EXAMPLES:\n  # Generate <App>Objects.h, <App>.h, <App>.c, and output/<App>Objects.xml\n  ethercat-cli ssc od generate MyOd.xlsx\n\n  # Generate C headers into custom dir and update an existing ESI XML in place\n  ethercat-cli ssc od generate MyOd.csv --src-dir ./firmware/Src --esi ./TargetEsi.xml"
    )]
    Generate(SscOdGenerateArgs),

    /// [OFFLINE] Create a new Beckhoff SSC Object Dictionary wizard `.csv` or `.xlsx` spreadsheet template.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc od template --output MyApplication.xlsx\n  ethercat-cli ssc od template --kind csv --output MyApplication.csv"
    )]
    Template {
        /// Output `.xlsx` or `.csv` file path.
        #[arg(long = "output", value_name = "FILE")]
        output: PathBuf,

        /// Template format (`csv` or `xlsx`; inferred from `--output` extension when omitted).
        #[arg(long, value_enum, ignore_case = true, value_name = "csv|xlsx")]
        kind: Option<SscTemplateKind>,
    },

    /// [OFFLINE] Export any Object Dictionary source (`.xlsx`, `.xlsm`, `.xml`, `.esp`, `.eds`, `.tmc`, `.csv`) to a semicolon-delimited SSC `.csv` table.
    #[command(
        after_long_help = "EXAMPLES:\n  ethercat-cli ssc od export --input SlaveProject.esp --output ExportedOd.csv\n  ethercat-cli ssc od export --input Device.xml --output DeviceOd.csv"
    )]
    Export {
        /// Source Object Dictionary file (`.xlsx`, `.xlsm`, `.csv`, `.xml`, `.esp`, `.eds`, `.tmc`).
        #[arg(short = 'i', long = "input", value_name = "OD_INPUT")]
        input: PathBuf,

        /// Destination `.csv` file path.
        #[arg(short = 'o', long = "output", value_name = "CSV_OUT")]
        output: PathBuf,

        /// Optional 0-based worksheet index when `--input` is `.xlsx`/`.xlsm`.
        #[arg(long, value_parser = parse_usize, value_name = "SHEET_IDX")]
        worksheet: Option<usize>,
    },

    /// [OFFLINE] Validate Object Dictionary rules (reserved C keywords, MDP `0x6000`/`0x7000` PDO directions, ObjectCode, bit/word alignment).
    #[command(after_long_help = "EXAMPLES:\n  ethercat-cli ssc od check MyOd.xlsx --strict")]
    Check {
        /// Input Object Dictionary file(s) (`.xlsx`, `.xlsm`, `.csv`, `.xml`, `.esp`, `.eds`, `.tmc`).
        #[arg(required = true, num_args = 1.., value_name = "OD_INPUT")]
        inputs: Vec<PathBuf>,

        /// Optional 0-based worksheet index when parsing `.xlsx`/`.xlsm`.
        #[arg(long, value_parser = parse_usize, value_name = "SHEET_IDX")]
        worksheet: Option<usize>,

        /// Also check SSC C struct bit/word alignment rules (`check_ssc_alignment_rules`).
        #[arg(long)]
        strict: bool,
    },
}

#[derive(Debug, Args)]
pub struct SscOdGenerateArgs {
    /// Input Object Dictionary file(s) (`.xlsx`, `.xlsm`, `.csv`, `.xml`, `.esp`, `.eds`, `.tmc`).
    #[arg(required = true, num_args = 1.., value_name = "OD_INPUT")]
    pub inputs: Vec<PathBuf>,

    /// 0-based worksheet index when parsing multi-sheet `.xlsx`/`.xlsm` files (`/WS<N>` parity).
    #[arg(long, value_parser = parse_usize, value_name = "SHEET_IDX")]
    pub worksheet: Option<usize>,

    /// Output folder for `<App>Objects.h`, `<App>.h`, and `<App>.c` (defaults to `<InputDir>/Src` if present, else `<InputDir>/output`).
    #[arg(long, value_name = "SRC_DIR")]
    pub src_dir: Option<PathBuf>,

    /// Target ETG.2000 ESI `.xml` file to update in place (if omitted and `<InputDir>/<AppName>.xml` exists, updates it automatically; otherwise writes `output/<AppName>Objects.xml`).
    #[arg(long, value_name = "ESI_XML")]
    pub esi: Option<PathBuf>,

    /// Custom output path for offline `<EtherCATDict>` XML when not updating an ESI file (defaults to `<InputDir>/output/<AppName>Objects.xml`).
    #[arg(long, value_name = "OFFLINE_XML")]
    pub offline_xml: Option<PathBuf>,

    /// 0-based `<Device>` index when updating an ESI XML file.
    #[arg(long, default_value_t = 0, value_parser = parse_usize, value_name = "IDX")]
    pub device_index: usize,

    /// Overwrite `<App>.c` and `<App>.h` even if `<App>.*` already exists in `--src-dir` (`<App>Objects.h` is always updated with `.bak` backup).
    #[arg(long)]
    pub overwrite_app: bool,

    /// Force generation (`SSC_OD_Tool -f` parity): skip invalid OD objects instead of aborting on validation errors.
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Enforce SSC C struct bit/word alignment rules during OD validation.
    #[arg(long)]
    pub strict: bool,
}
