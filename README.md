# `ethercat-cli` — Modular Rust EtherCAT Protocol, ESI/SII EEPROM & Pure-Rust SSC Codegen Workspace

`ethercat-cli` is a deterministic, AI-friendly Rust Cargo Workspace and command-line toolkit for EtherCAT protocol engineering, ETG.2000/ETG.2010 EEPROM workflows, live/virtual master diagnostics, and clean-room Beckhoff Slave Stack Code (SSC) & Object Dictionary (OD) code generation:

- **Low-Level Wire Codec, Dissector & Transport (`ethercat-wire`)**: Raw EtherCAT (`0x88A4` L2 + 802.1Q / 802.1ad QinQ VLAN & `udp://` port `34980`) frame builder, Wireshark-compatible protocol dissector (`eth`, `esl`, `ecatf`, `ecat`, `ecat_mailbox` CoE/FoE/EoE/SoE/AoE/VoE, `nv`), streaming `.pcap` / `.pcapng` / Windows `PktMon` I/O, wire-level PDO bit-slice codec, and dynamic Npcap/libpcap + UDP drivers.
- **ETG.2000 ESI XML -> ETG.2010 SII `.bin`/`.h` Compiler & Guarded EEPROM Programmer (`ethercat-eeprom`)**: Structured SII binary decoder/validator/encoder/patcher/differ, multi-encoding (`UTF-8` / `UTF-16LE/BE` / `ISO-8859-1`) ESI XML catalog loader with `<InfoReference>` resolution, `aEepromData[]` C header emitter, and hardware-safe 3-factor guarded ESC EEPROM read/verify/burn/reload workflows (`--execute`, non-existing `--backup`, `--confirm WRITE-SLAVE-<n>`).
- **EtherCAT Master Diagnostics, CoE SDO/OD, Cyclic PDO & Virtual Ring Simulator (`ethercat-master`)**: Bus topology scanner, AL state controller, ESC hardware register client (`0x0000..0xFFFF` + symbolic bitfields), CoE SDO upload/download (expedited, segmented, block) & Object Dictionary browser (`0x1000..0xFFFF`), cyclic `LRW`/`LRD`/`LWR` PDO exchange, and deterministic virtual slave ring simulator (`--iface sim`, `sim://slaves=N`, `sim://eeprom=...`, `sim://esi=...`).
- **100% Pure-Rust Beckhoff SSC Project & Object Dictionary Engine (`ethercat-ssc`)**: Project preprocessor (`src/*.c`, `src/*.h`, `ecat_def.h`, `eeprom.h`), `<Project>.esp` GZIP persistence, `<Project>.xml` XSD-ordered ESI generation, standalone OD codegen (`.xlsx`, `.csv`, `.xml`, `.eds`, `.tmc` -> `<App>Objects.h`, `<App>.h`, `<App>.c`, `<App>Objects.xml`), in-place ESI updating, unified `.patch` engine, `ecat_def.h` header import, `<SettingConflicts>` / `UpdateInformation.xml` validation, and `16x14` `.bmp`/`.png`/`.gif` icon hex encoding — with **zero proprietary `.dll`/`.exe` dependencies**.
- **AI-Ready CLI & Universal Field Selector (`ethercat-cli`)**: Self-documenting `clap` v4 binary with structured exit codes (`0..=7`), `--format text|json|json-compact`, and repeatable `-f / --field <SELECTOR>` extraction across Wireshark display-filter names and JSON dot/index paths.

---

## 1. Cargo Workspace Architecture

The repository is organized as a zero-cycle 5-crate Cargo Workspace (`resolver = "2"`, offline-ready with minimal dependencies):

```text
ethercat/
├── Cargo.toml                  # Workspace manifest & shared dependency versions
└── crates/
    ├── ethercat-wire/          # L2/VLAN/UDP EtherCAT frame codec, Wireshark dissector, PCAP/PktMon I/O, Npcap & UDP transports
    ├── ethercat-eeprom/        # ETG.2010 SII binary codec, ETG.2000 ESI XML -> SII .bin/.h compiler & guarded EEPROM workflows
    ├── ethercat-master/        # Bus scan, AL state, ESC registers, CoE SDO/OD client, cyclic PDO & virtual slave ring simulator
    ├── ethercat-ssc/           # Pure-Rust SSC project/C preprocessor, XLSX/CSV/XML/EDS/TMC OD codegen, ESI generator & patcher
    └── ethercat-cli/           # CLI command tree, universal Wireshark/JSON field selector & end-to-end integration tests
```

### Dependency Graph

- `ethercat-wire` *(foundational protocol, PDO bit codec & L2/UDP transport traits — zero internal dependencies)*
- `ethercat-eeprom` -> `ethercat-wire`
- `ethercat-master` -> `ethercat-wire`, `ethercat-eeprom`
- `ethercat-ssc` -> `ethercat-wire`, `ethercat-eeprom`
- `ethercat-cli` -> `ethercat-wire`, `ethercat-eeprom`, `ethercat-master`, `ethercat-ssc`

> **Clean-Room Note on SSC C Templates**: Proprietary Beckhoff SSC C slave stack source templates (`*.c` / `*.h`) are **never** bundled in this repository. At runtime, `ethercat-cli ssc` loads user-supplied templates via `-p <file.esp|.escfg>`, `--ssc-dir <dir>`, `ETHERCAT_SSC_DIR`, or standard local SSC Tool installation paths.

---

## 2. Build & Local Verification (No CI/CD Required)

```powershell
# Format & lint checks across all 5 workspace crates
cargo fmt --all -- --check
cargo clippy --workspace --offline --all-targets -- -D warnings

# Run all crate unit tests & CLI end-to-end integration suites locally
cargo test --workspace --offline

# Build optimized release binary (target/release/ethercat-cli.exe)
cargo build --release --offline
```

---

## 3. Command Overview & AI Usage Examples

Every subcommand provides detailed `--help` documentation, `--format text|json|json-compact`, and repeatable `-f / --field <SELECTOR>`:

```powershell
# 1. Pure-Rust SSC project generation & diagnostics
.\target\release\ethercat-cli.exe ssc generate --ssc-dir "C:\Path\To\SSC" --output .\out_slave
.\target\release\ethercat-cli.exe ssc generate -a MyDrive.xlsx -d VENDOR_ID=0xE0000002 -d CREATE_EEPROM_CONTENT=1 --sii-out .\out_drive\eeprom.bin --output .\out_drive
.\target\release\ethercat-cli.exe ssc list-defines --all --filter MBX
.\target\release\ethercat-cli.exe ssc check -p .\out_slave\SlaveProject.esp

# 2. Standalone SSC Object Dictionary templates, C/XML codegen, in-place ESI update & unified patching
.\target\release\ethercat-cli.exe ssc od template --output MyApplication.xlsx
.\target\release\ethercat-cli.exe ssc od generate MyApplication.xlsx --src-dir .\firmware\Src
.\target\release\ethercat-cli.exe ssc update-esi --esi .\out_slave\SlaveProject.xml --od MyApplication.xlsx
.\target\release\ethercat-cli.exe ssc import-header --header .\out_slave\src\ecat_def.h --output ImportedSlave.esp
.\target\release\ethercat-cli.exe ssc patch --patch Hotfix.patch --src-dir .\out_slave\src
.\target\release\ethercat-cli.exe ssc image-hex --image icon_16x14.bmp

# 3. Inspect ETG.2000 ESI XML devices & compile to ETG.2010 SII .bin / aEepromData[] .h
.\target\release\ethercat-cli.exe esi list --xml slave.xml
.\target\release\ethercat-cli.exe esi build --xml slave.xml --device PC-1000 --output eeprom.bin --header-out eeprom.h
.\target\release\ethercat-cli.exe sii diff --left slave.xml --left-device PC-1000 --right eeprom.bin

# 4. Guarded ESI/SII EEPROM burn (defaults to safe DRY-RUN; 3-factor lock + optional ESC 0x0140/0x0150 check)
.\target\release\ethercat-cli.exe -i "sim://esi=slave.xml;device=PC-1000" esi burn --slave 1 --xml slave.xml --device PC-1000 --alias 0x0009 --check-esc-config
.\target\release\ethercat-cli.exe -i "sim://esi=slave.xml;device=PC-1000" esi burn --slave 1 --xml slave.xml --device PC-1000 --alias 0x0009 --check-esc-config `
  --execute --backup prewrite-slave1.bin --confirm WRITE-SLAVE-1 --reload

# 5. Read/verify slave EEPROM over Npcap L2, EtherCAT-over-UDP (udp://), or virtual ring (sim://)
.\target\release\ethercat-cli.exe -i udp://192.168.1.100:34980 esi read --slave 1 --output dump.bin --header-out dump.h --xml .\esi_catalog\ --decode
.\target\release\ethercat-cli.exe -i "sim://esi=slave.xml" esi verify --slave 1 --xml slave.xml

# 6. Dissect .pcap, Wireshark .pcapng, or Windows PktMon .txt captures & execute CoE SDO / cyclic PDO
.\target\release\ethercat-cli.exe dissect --file capture.pcapng --limit 5 -f ecat.cmd -f ecat.adp -f ecat.ado_name -f ecat.wkc
.\target\release\ethercat-cli.exe -i sim --format json sdo read --slave 1 --index 0x100A --subindex 0 --type string --auto-preop
.\target\release\ethercat-cli.exe -i sim --format json pdo exchange --slave 1 --auto-map --set 0x6040:00=0x000F --set 0x607A:00=12500
```

---

## 4. Structured Exit Codes

| Code | Kind | Meaning |
|---|---|---|
| `0` | `ok` | Command succeeded |
| `1` | `usage_error` | Invalid CLI flags, ambiguous multi-device ESI XML without `--device`, or missing option |
| `2` | `interface_error` | Npcap/libpcap load, adapter open, or UDP socket bind/send failure |
| `3` | `device_error` | Slave unresponsive (`WKC=0`), EEPROM busy/NACK, or bus timeout |
| `4` | `mismatch_error` | `sii/esi verify` mismatch, `--check-esc-config` PDI mismatch, `--expect-wkc` mismatch, or `--field` not found |
| `5` | `format_error` | Invalid ESI XML / SII size / CRC-8, malformed hex, or truncated frame/PCAP |
| `6` | `write_locked` | `sii write` / `esi burn --execute` rejected due to missing/existing `--backup` or wrong `--confirm` |
| `7` | `protocol_error` | EtherCAT AL state transition error or CoE SDO abort response |
