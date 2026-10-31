use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::time::Duration;

use clap::Parser;
use serde_json::json;

use crate::cli::{Cli, DissectArgs, SscOdSubcommand, SscSubcommand, SscTemplateKind};
use crate::commands::execute_cli;
use crate::commands::frames::{handle_dissect, parse_subframe_spec};
use crate::commands::ssc::handle_ssc;
use crate::selector::apply_field_selectors;
use ethercat_eeprom::sii::image::{patch_sii_image, sii_validate, SiiPatchSpec};
use ethercat_eeprom::sii::ops::{
    inspect_sii_data, read_device_sii_slice, write_device_sii_guarded, GuardedSiiWriteOptions,
};
use ethercat_master::coe::{query_od_info, sdo_read, sdo_write, SdoReadParams, SdoWriteParams};
use ethercat_master::open_transport;
use ethercat_master::pdo::{
    pdo_exchange_live, pdo_read_live, read_slave_pdo_map, PdoExchangeParams, PdoLayout,
    PdoReadParams, PdoSource,
};
use ethercat_master::{
    read_esc_register, scan_bus, write_al_state, write_esc_register, RegReadParams, RegWriteParams,
};
use ethercat_wire::error::CliError;
use ethercat_wire::protocol::constants::{AlStateSpec, EcatCmd};
use ethercat_wire::protocol::dissector::{dissect_frame, DissectOptions};
use ethercat_wire::protocol::frame::{parse_dlpdu_datagrams, EcatFrameBuilder, RawDatagram};
use ethercat_wire::protocol::pcap_io::{
    for_each_frame_in_file, load_frames_from_file, write_pcap_file, FrameInputKind,
};
use ethercat_wire::types::{
    decode_typed_value, encode_typed_value, extract_bits_le, format_hex, DataTypeSpec,
};
use ethercat_wire::{protocol, types};

fn unique_temp_id() -> String {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT_ID.fetch_add(1, AtomicOrdering::Relaxed)
    )
}
#[test]
fn real_sii_fixture_validate_inspect_patch_guarded_write_and_32bit_eeprom_addr() {
    let raw = ethercat_master::sim::build_servo_402_sii();
    let fixture_buf = std::env::temp_dir().join(format!(
        "ethercat-cli-servo-fixture-{}.bin",
        unique_temp_id()
    ));
    std::fs::write(&fixture_buf, &raw).expect("write synthetic SII fixture");
    let fixture = fixture_buf.as_path();
    sii_validate(&raw).expect("fixture must pass ETG.2010 SII validation");

    let inspected = inspect_sii_data(&raw).expect("parse SII TLV categories");
    assert_eq!(inspected.header.vendor_id, 0x0000_0931);
    assert_eq!(inspected.header.product_code, 0x0000_0402);
    assert!(inspected.header.crc_ok);
    assert!(inspected
        .categories
        .strings
        .iter()
        .any(|s| s == "EC-SERVO-402"));
    assert!(!inspected.categories.sync_managers.is_empty());

    // Patch alias + serial using SiiPatchSpec::default() (recalculate_crc defaults to true)
    let patched = patch_sii_image(
        &raw,
        &SiiPatchSpec {
            alias: Some(0x0007),
            serial_number: Some(0x2026_0999),
            ..Default::default()
        },
    )
    .expect("patch SII image");
    sii_validate(&patched).expect("patched SII image valid with auto-recomputed CRC");

    // Corrupt CRC byte 14 -> must fail validation with Format error
    let mut bad_crc = patched.clone();
    bad_crc[14] ^= 0xFF;
    assert!(matches!(sii_validate(&bad_crc), Err(CliError::Format(_))));

    // Test guarded write locks on virtual simulator seeded with real fixture
    let sim_spec = format!("sim://eeprom={}", fixture.display());
    let mut bus = open_transport(&sim_spec, false).expect("open sim with real eeprom");
    let timeout = Duration::from_millis(200);

    // 1. Default dry-run: zero writes
    let dry = write_device_sii_guarded(
        &mut *bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &patched,
            execute: false,
            backup_path: None,
            confirm_token: None,
            reload: false,
            timeout,
        },
    )
    .expect("dry-run succeeds");
    assert!(dry.dry_run && !dry.executed && dry.written_words == 0 && dry.differing_words > 0);

    // 2. Execute without confirm/backup -> WriteLocked (exit code 6)
    let locked = write_device_sii_guarded(
        &mut *bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &patched,
            execute: true,
            backup_path: None,
            confirm_token: Some("WRONG-TOKEN"),
            reload: false,
            timeout,
        },
    );
    assert!(matches!(locked, Err(CliError::WriteLocked(_))));

    // 3. Execute with existing backup path -> WriteLocked (refuse overwrite)
    let locked_existing = write_device_sii_guarded(
        &mut *bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &patched,
            execute: true,
            backup_path: Some(fixture),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: false,
            timeout,
        },
    );
    assert!(matches!(locked_existing, Err(CliError::WriteLocked(_))));

    // 4. Execute with fresh temp backup + exact confirm token -> writes, reloads ESC 0x0012 alias, & verifies
    let tmp_backup =
        std::env::temp_dir().join(format!("ethercat-cli-test-backup-{}.bin", unique_temp_id()));
    let _ = std::fs::remove_file(&tmp_backup);
    let ok_rep = write_device_sii_guarded(
        &mut *bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &patched,
            execute: true,
            backup_path: Some(&tmp_backup),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: true,
            timeout,
        },
    )
    .expect("unlocked guarded write succeeds");
    assert!(ok_rep.executed && ok_rep.verified && ok_rep.written_words == dry.differing_words);
    assert_eq!(std::fs::read(&tmp_backup).unwrap(), raw);
    let _ = std::fs::remove_file(&tmp_backup);

    // Verify ESC 0x0012 Configured Station Alias updated to 0x0007 via 0x0400 RELOAD command
    let alias_reg = read_esc_register(
        &mut *bus,
        &RegReadParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "0x0012",
            length: Some(2),
            ty: DataTypeSpec::U16,
            bit_offset: None,
            bit_length: None,
            timeout,
        },
    )
    .expect("read ESC 0x0012 station alias after reload");
    assert_eq!(alias_reg.decoded_value, json!(0x0007));

    // Verify reload: true also triggers 0x0400 RELOAD even when differing_words == 0
    write_esc_register(
        Some(&mut *bus),
        &RegWriteParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "0x0012",
            value_str: "0x0099",
            ty: DataTypeSpec::U16,
            dry_run: false,
            timeout,
        },
    )
    .unwrap();
    let tmp_backup2 = std::env::temp_dir().join(format!(
        "ethercat-cli-test-backup2-{}.bin",
        unique_temp_id()
    ));
    let _ = std::fs::remove_file(&tmp_backup2);
    let same_reload = write_device_sii_guarded(
        &mut *bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &patched,
            execute: true,
            backup_path: Some(&tmp_backup2),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: true,
            timeout,
        },
    )
    .expect("reload when differing_words == 0");
    let _ = std::fs::remove_file(&tmp_backup2);
    assert_eq!(same_reload.written_words, 0);
    let alias_reloaded = read_esc_register(
        &mut *bus,
        &RegReadParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "0x0012",
            length: Some(2),
            ty: DataTypeSpec::U16,
            bit_offset: None,
            bit_length: None,
            timeout,
        },
    )
    .unwrap();
    assert_eq!(alias_reloaded.decoded_value, json!(0x0007));

    // 5. 32-bit SII EEPROM word addressing (>128 KiB, word_addr >= 0x10000 must NOT wrap to 0)
    let mut big_sii = vec![0xFFu8; 262_144]; // 256 KiB = 2048 Kbit -> size_code = 2047 (0x07FF)
    big_sii[..raw.len()].copy_from_slice(&raw);
    big_sii[0x7C..0x7E].copy_from_slice(&2047u16.to_le_bytes());
    big_sii[0x20000..0x20004].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    sii_validate(&big_sii).expect("valid 256 KiB SII image");

    let tmp_big =
        std::env::temp_dir().join(format!("ethercat-cli-big-sii-{}.bin", unique_temp_id()));
    std::fs::write(&tmp_big, &big_sii).unwrap();
    let mut big_bus =
        open_transport(&format!("sim://eeprom={}", tmp_big.display()), false).unwrap();
    let high_slice = read_device_sii_slice(&mut *big_bus, 1, 0x20000, 8, timeout)
        .expect("read above 128 KiB boundary");
    assert_eq!(
        &high_slice,
        &[0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    let _ = std::fs::remove_file(&tmp_big);
    let _ = std::fs::remove_file(&fixture_buf);
}

#[test]
fn wireshark_dissector_selectors_multi_subframe_mailbox_and_streaming_pcap() {
    // Subframe 0: APRD AL Status (0x0130)
    // Subframe 1: FPRD CoE SDO Expedited Upload Response (mailbox in subframe > 0!)
    // Subframe 2: Logical LRW PDO frame
    let mut dg0 =
        RawDatagram::new_positioned(EcatCmd::Aprd, 0x06, 0x0000, 0x0130, vec![0x02, 0x00]);
    dg0.circulating = true;
    dg0.wkc = 1;

    let mut coe_mbx = vec![0u8; 16];
    coe_mbx[0..2].copy_from_slice(&10u16.to_le_bytes());
    coe_mbx[2..4].copy_from_slice(&0x1001u16.to_le_bytes());
    coe_mbx[5] = 0x23; // cnt=2, type=3 (CoE)
    coe_mbx[6..8].copy_from_slice(&(0x03u16 << 12).to_le_bytes()); // SDO Response
    coe_mbx[8] = 0x43; // expedited, 4 bytes
    coe_mbx[9..11].copy_from_slice(&0x1018u16.to_le_bytes());
    coe_mbx[11] = 0x01;
    coe_mbx[12..16].copy_from_slice(&0x0000_0931u32.to_le_bytes());
    let mut dg1 = RawDatagram::new_positioned(EcatCmd::Fprd, 0x07, 0x1001, 0x1080, coe_mbx);
    dg1.wkc = 1;

    let mut dg2 = RawDatagram::new_logical(
        EcatCmd::Lrw,
        0x08,
        0x0001_0000,
        vec![0x37, 0x04, 0xE8, 0x03, 0x00, 0x00],
    );
    dg2.wkc = 3;

    let mut builder = EcatFrameBuilder::new();
    builder
        .add_datagram(dg0)
        .add_datagram(dg1)
        .add_datagram(dg2);
    let raw_frame = builder.build().expect("build 3-subframe packet");

    let opts = DissectOptions {
        pdo_layout: Some(PdoLayout::parse_spec("0x6041:00:u16@0:16,0x6064:00:i32@16:32").unwrap()),
        ..Default::default()
    };
    let df = dissect_frame(&raw_frame, &opts).expect("dissect chained frame");
    let df_json = serde_json::to_value(&df).unwrap();

    let sel = apply_field_selectors(
        &df_json,
        &[
            "ecat.cmd".into(),
            "ecat.circulating".into(),
            "ecat.next".into(),
            "ecat[0].reg.al_state".into(),
            "ecat_mailbox.coe.sdo.index".into(),
            "ecat_mailbox[1].coe.sdo.value".into(),
            "ecat[2].cmd".into(),
            "ecat.pdo.0x6064:00".into(),
            "ecat[2].pdo.0x6064:00".into(),
        ],
    )
    .expect("extract Wireshark fields across subframes");
    assert_eq!(sel["ecat.cmd"], "APRD");
    assert_eq!(sel["ecat.circulating"], true);
    assert_eq!(sel["ecat.next"], true);
    assert_eq!(sel["ecat[0].reg.al_state"], "PRE-OP");
    assert_eq!(sel["ecat_mailbox.coe.sdo.index"], "0x1018");
    assert_eq!(sel["ecat_mailbox[1].coe.sdo.value"], 0x0931);
    assert_eq!(sel["ecat[2].cmd"], "LRW");
    assert_eq!(sel["ecat.pdo.0x6064:00"], 1000);
    assert_eq!(sel["ecat[2].pdo.0x6064:00"], 1000);

    // Beckhoff ET2000 ESL prefix & trailer dissection
    let mut esl_tag = [0u8; 16];
    esl_tag[0..6].copy_from_slice(&[0x01, 0x01, 0x05, 0x10, 0x00, 0x00]);
    esl_tag[6..8].copy_from_slice(&0x2840u16.to_le_bytes()); // ts_enable | crc_error | port 1
    esl_tag[8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
    let mut esl_prefix = esl_tag.to_vec();
    esl_prefix.extend_from_slice(&raw_frame);
    let esl_p_df = dissect_frame(&esl_prefix, &DissectOptions::default()).unwrap();
    assert_eq!(esl_p_df.wireshark_fields["esl.port"], 1);
    assert_eq!(esl_p_df.wireshark_fields["esl.crcerror"], true);
    assert_eq!(esl_p_df.wireshark_fields["esl.tsenable"], true);
    assert_eq!(
        esl_p_df.wireshark_fields["esl.timestamp"],
        0x0102_0304_0506_0708u64
    );
    let mut esl_trailer = raw_frame.clone();
    esl_trailer.extend_from_slice(&esl_tag);
    let esl_t_df = dissect_frame(&esl_trailer, &DissectOptions::default()).unwrap();
    assert_eq!(esl_t_df.esl.as_ref().unwrap().position, "trailer");
    assert_eq!(esl_t_df.wireshark_fields["esl.port"], 1);

    // Expanded ESC register dissection: 0x0000 (10B), 0x0300, 0x0440, 0x0600, 0x0805, 0x092C (sign-magnitude -100ns)
    let mut esc_b = EcatFrameBuilder::new();
    esc_b
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Brd,
            1,
            0,
            0x0000,
            vec![0x11, 0x02, 0x03, 0x00, 8, 8, 64, 0xAF, 0x0C, 0x00],
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Aprd,
            2,
            0,
            0x092C,
            0x8000_0064u32.to_le_bytes().to_vec(),
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Aprd,
            3,
            0,
            0x0805,
            vec![0x09], // mbx_full | irq_write
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Aprd,
            4,
            0,
            0x0300,
            vec![3, 1, 0, 0], // rx_err_frame_port0=3, rx_err_phys_port0=1
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Aprd,
            5,
            0,
            0x0440,
            vec![0x01, 0x00], // wd_pdata_ok=true
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Aprd,
            6,
            0,
            0x0600,
            vec![
                0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0, 7, 0x00, 0x11, 0, 0x02, 0x01, 0, 0, 0,
            ],
        ));
    let esc_df = dissect_frame(&esc_b.build().unwrap(), &DissectOptions::default()).unwrap();
    assert_eq!(esc_df.wireshark_fields["ecat.reg.fmmu_count"], 8);
    assert_eq!(esc_df.wireshark_fields["ecat.reg.ram_size_kb"], 64);
    assert_eq!(esc_df.wireshark_fields["ecat.reg.esc_features"], "0x000c");
    assert_eq!(esc_df.wireshark_fields["ecat.reg.dc_supported"], true);
    assert_eq!(esc_df.wireshark_fields["ecat[1].reg.dc_sys_diff_ns"], -100);
    assert_eq!(esc_df.wireshark_fields["ecat[2].reg.sm0.mbx_full"], true);
    assert_eq!(esc_df.wireshark_fields["ecat[3].reg.rx_err_frame_port0"], 3);
    assert_eq!(esc_df.wireshark_fields["ecat[4].reg.wd_pdata_ok"], true);
    assert_eq!(
        esc_df.wireshark_fields["ecat[5].reg.fmmu0.log_start"],
        "0x00010000"
    );
    assert_eq!(esc_df.wireshark_fields["ecat[5].reg.fmmu0.active"], true);

    // SoE incomplete fragment, SDO Info "number", AoE ADS group/offset, and EoE LE IPv4 + frag 0 Ethernet
    let mut soe_mbx = vec![0u8; 12];
    soe_mbx[0..2].copy_from_slice(&6u16.to_le_bytes());
    soe_mbx[5] = 0x15; // cnt=1, type=5 (SoE)
    soe_mbx[6] = 0x0A; // opcode=2 (Read Res) | incomplete (0x08)
    soe_mbx[8..10].copy_from_slice(&3u16.to_le_bytes()); // 3 fragments left

    let mut sdo_info_mbx = vec![0u8; 18];
    sdo_info_mbx[0..2].copy_from_slice(&12u16.to_le_bytes());
    sdo_info_mbx[5] = 0x23; // CoE
    sdo_info_mbx[6..8].copy_from_slice(&((0x08u16 << 12) | 5).to_le_bytes()); // number=5, SDO Info
    sdo_info_mbx[8] = 0x04; // Get Object Description Res
    sdo_info_mbx[12..14].copy_from_slice(&0x1018u16.to_le_bytes());

    let mut aoe_mbx = vec![0u8; 6 + 32 + 12];
    aoe_mbx[0..2].copy_from_slice(&44u16.to_le_bytes());
    aoe_mbx[5] = 0x11; // AoE
    aoe_mbx[6 + 16..6 + 18].copy_from_slice(&2u16.to_le_bytes()); // ADS Read
    aoe_mbx[6 + 20..6 + 24].copy_from_slice(&12u32.to_le_bytes());
    aoe_mbx[6 + 32..6 + 36].copy_from_slice(&0xF020u32.to_le_bytes());
    aoe_mbx[6 + 36..6 + 40].copy_from_slice(&0x0010u32.to_le_bytes());
    aoe_mbx[6 + 40..6 + 44].copy_from_slice(&4u32.to_le_bytes());

    let mut eoe_ip_mbx = vec![0u8; 6 + 4 + 4 + 6 + 4 + 4 + 4];
    let eoe_body_len = (eoe_ip_mbx.len() - 6) as u16;
    eoe_ip_mbx[0..2].copy_from_slice(&eoe_body_len.to_le_bytes());
    eoe_ip_mbx[5] = 0x12; // EoE
    eoe_ip_mbx[6] = 0x02; // Set IP Parameter Req
    eoe_ip_mbx[10..14].copy_from_slice(&0x0Fu32.to_le_bytes()); // MAC | IP | Subnet | Gateway present
    eoe_ip_mbx[14..20].copy_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
    eoe_ip_mbx[20..24].copy_from_slice(&[50, 1, 168, 192]); // ETG.1000.6 LE IPv4 -> 192.168.1.50
    eoe_ip_mbx[24..28].copy_from_slice(&[0, 255, 255, 255]); // 255.255.255.0
    eoe_ip_mbx[28..32].copy_from_slice(&[1, 1, 168, 192]); // 192.168.1.1

    let mut eoe_eth_mbx = vec![0u8; 6 + 4 + 14];
    eoe_eth_mbx[0..2].copy_from_slice(&18u16.to_le_bytes());
    eoe_eth_mbx[5] = 0x12; // EoE frag 0
    eoe_eth_mbx[6] = 0x10; // last_fragment=1, frag_type=0
    eoe_eth_mbx[10..16].copy_from_slice(&[0xFF; 6]);
    eoe_eth_mbx[16..22].copy_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    eoe_eth_mbx[22..24].copy_from_slice(&0x0800u16.to_be_bytes());

    let mut mbx_b = EcatFrameBuilder::new();
    mbx_b
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Fprd,
            1,
            0x1001,
            0x1080,
            soe_mbx,
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Fprd,
            2,
            0x1001,
            0x1080,
            sdo_info_mbx,
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Fpwr,
            3,
            0x1001,
            0x1000,
            aoe_mbx,
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Fpwr,
            4,
            0x1001,
            0x1000,
            eoe_ip_mbx,
        ))
        .add_datagram(RawDatagram::new_positioned(
            EcatCmd::Fpwr,
            5,
            0x1001,
            0x1000,
            eoe_eth_mbx,
        ));
    let mbx_df = dissect_frame(
        &mbx_b.build().unwrap(),
        &DissectOptions {
            force_mailbox: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox.soe.fragments_left"],
        3
    );
    assert!(!mbx_df.wireshark_fields.contains_key("ecat_mailbox.soe.idn"));
    assert_eq!(
        mbx_df.datagrams[1].mailbox.as_ref().unwrap().protocol["number"],
        5
    );
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox[2].aoe.index_group"],
        "0x0000f020"
    );
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox[2].aoe.index_offset"],
        "0x00000010"
    );
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox[3].eoe.ip"],
        "192.168.1.50"
    );
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox[3].eoe.subnet"],
        "255.255.255.0"
    );
    assert_eq!(
        mbx_df.wireshark_fields["ecat_mailbox[4].eoe.eth.type"],
        "0x0800"
    );

    // Streaming .pcap AND .pcapng (LE + BE with if_tsresol=9 + SPB) with --limit 1 early stop
    for ext in ["pcap", "pcapng"] {
        let tmp_cap =
            std::env::temp_dir().join(format!("ethercat-cli-stream-{}.{ext}", unique_temp_id()));
        write_pcap_file(
            &tmp_cap,
            &[
                (1_000, raw_frame.clone()),
                (2_000, raw_frame.clone()),
                (3_000, raw_frame.clone()),
            ],
        )
        .unwrap();
        let mut streamed = 0usize;
        let kind = for_each_frame_in_file(&tmp_cap, FrameInputKind::Auto, |_r| {
            streamed += 1;
            Ok(false)
        })
        .unwrap();
        assert_eq!(
            kind,
            if ext == "pcapng" {
                FrameInputKind::Pcapng
            } else {
                FrameInputKind::Pcap
            }
        );
        assert_eq!(streamed, 1);

        let dissect_rep = handle_dissect(&DissectArgs {
            hex: None,
            file: Some(tmp_cap.clone()),
            input_kind: FrameInputKind::Auto,
            limit: 1,
            bare: false,
            force_mailbox: false,
            pdo_layout: None,
            sii_pdo: None,
            pdo_dir: "tx".into(),
        })
        .unwrap();
        assert_eq!(dissect_rep.json["dissected_count"], 1);
        assert_eq!(dissect_rep.json["frames"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_file(&tmp_cap);
    }

    // Big-endian PCAPNG with IDB option 9 (if_tsresol = 9 -> nanoseconds) + EPB + SPB
    let mut be_ng = Vec::new();
    // SHB (28B, BE)
    be_ng.extend_from_slice(&0x0A0D_0D0Au32.to_be_bytes());
    be_ng.extend_from_slice(&28u32.to_be_bytes());
    be_ng.extend_from_slice(&0x1A2B_3C4Du32.to_be_bytes());
    be_ng.extend_from_slice(&1u16.to_be_bytes());
    be_ng.extend_from_slice(&0u16.to_be_bytes());
    be_ng.extend_from_slice(&(-1i64).to_be_bytes());
    be_ng.extend_from_slice(&28u32.to_be_bytes());
    // IDB (32B, BE: linktype=1, snaplen=65535, opt 9 len 1 = 9 + pad + opt 0)
    be_ng.extend_from_slice(&1u32.to_be_bytes());
    be_ng.extend_from_slice(&32u32.to_be_bytes());
    be_ng.extend_from_slice(&1u16.to_be_bytes());
    be_ng.extend_from_slice(&0u16.to_be_bytes());
    be_ng.extend_from_slice(&65535u32.to_be_bytes());
    be_ng.extend_from_slice(&9u16.to_be_bytes());
    be_ng.extend_from_slice(&1u16.to_be_bytes());
    be_ng.extend_from_slice(&[9, 0, 0, 0]);
    be_ng.extend_from_slice(&0u32.to_be_bytes()); // opt_endofopt
    be_ng.extend_from_slice(&32u32.to_be_bytes());
    // EPB with ts = 1_500_000_000 ns
    let padded_len = (raw_frame.len() + 3) & !3;
    let epb_len = (32 + padded_len) as u32;
    be_ng.extend_from_slice(&6u32.to_be_bytes());
    be_ng.extend_from_slice(&epb_len.to_be_bytes());
    be_ng.extend_from_slice(&0u32.to_be_bytes());
    be_ng.extend_from_slice(&0u32.to_be_bytes());
    be_ng.extend_from_slice(&1_500_000_000u32.to_be_bytes());
    be_ng.extend_from_slice(&(raw_frame.len() as u32).to_be_bytes());
    be_ng.extend_from_slice(&(raw_frame.len() as u32).to_be_bytes());
    be_ng.extend_from_slice(&raw_frame);
    be_ng.resize(be_ng.len() + (padded_len - raw_frame.len()), 0);
    be_ng.extend_from_slice(&epb_len.to_be_bytes());
    // SPB (Simple Packet Block, type 3)
    let spb_len = (16 + padded_len) as u32;
    be_ng.extend_from_slice(&3u32.to_be_bytes());
    be_ng.extend_from_slice(&spb_len.to_be_bytes());
    be_ng.extend_from_slice(&(raw_frame.len() as u32).to_be_bytes());
    be_ng.extend_from_slice(&raw_frame);
    be_ng.resize(be_ng.len() + (padded_len - raw_frame.len()), 0);
    be_ng.extend_from_slice(&spb_len.to_be_bytes());

    let tmp_be = std::env::temp_dir().join(format!("ethercat-cli-be-{}.bin", unique_temp_id()));
    std::fs::write(&tmp_be, &be_ng).unwrap();
    let be_recs = load_frames_from_file(&tmp_be, FrameInputKind::Auto, 10).unwrap();
    let _ = std::fs::remove_file(&tmp_be);
    assert_eq!(be_recs.len(), 2);
    assert_eq!(be_recs[0].timestamp.as_deref(), Some("1.500000000"));
    assert_eq!(be_recs[1].data, raw_frame);

    // Also dissect UTF-16LE BOM Windows PktMon capture format
    let pktmon_path =
        std::env::temp_dir().join(format!("ethercat-cli-pktmon-{}.txt", unique_temp_id()));
    let mut pktmon_text = String::from(
        "[00]0000.0000::2026-10-31 12:00:00.000 [Microsoft-Windows-PktMon] PktGroupId 1, Packet, Appearance 1\r\n",
    );
    for (ci, chunk) in raw_frame.chunks(16).enumerate() {
        let words: Vec<String> = chunk
            .chunks(2)
            .map(|w| {
                if w.len() == 2 {
                    format!("{:02x}{:02x}", w[0], w[1])
                } else {
                    format!("{:02x}", w[0])
                }
            })
            .collect();
        pktmon_text.push_str(&format!(
            "        0x{:04x}:  {:<39}  ................\r\n",
            ci * 16,
            words.join(" ")
        ));
    }
    let mut utf16le_bytes = vec![0xFFu8, 0xFEu8];
    for u in pktmon_text.encode_utf16() {
        utf16le_bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&pktmon_path, &utf16le_bytes).unwrap();
    let recs = load_frames_from_file(&pktmon_path, FrameInputKind::Auto, 5)
        .expect("parse UTF-16LE PktMon capture");
    let _ = std::fs::remove_file(&pktmon_path);
    assert_eq!(recs.len(), 1);
    let first_df = dissect_frame(&recs[0].data, &DissectOptions::default())
        .expect("dissect UTF-16LE PktMon EtherCAT frame");
    assert!(!first_df.datagrams.is_empty());
}

#[test]
fn sim_bus_sdo_pdo_reg_state_boot_and_vlan_end_to_end() {
    let mut bus = open_transport("sim", false).expect("open virtual ring");
    let timeout = Duration::from_millis(200);

    let scan = scan_bus(&mut *bus, true, true, timeout).expect("scan sim bus");
    assert_eq!(scan.slave_count, 2);

    // VLAN-tagged (0x8100, VID=100) EtherCAT frame transaction on simulator
    let mut vlan_builder = EcatFrameBuilder {
        vlan_id: Some(100),
        ..Default::default()
    };
    vlan_builder.add_datagram(RawDatagram::new_positioned(
        EcatCmd::Brd,
        0x22,
        0,
        0x0000,
        vec![0; 4],
    ));
    let vlan_tx = vlan_builder.build().unwrap();
    let vlan_rx = bus.transact_frame(&vlan_tx, Some(0x22), timeout).unwrap();
    let vlan_df = dissect_frame(&vlan_rx, &DissectOptions::default()).unwrap();
    assert_eq!(vlan_df.wireshark_fields["vlan.id"], 100);
    assert_eq!(vlan_df.wireshark_fields["ecat.wkc"], 2);

    // ESC register bit-slice read (DL Status 0x0110 bit 4 = Port 0 link = true)
    let reg_rep = read_esc_register(
        &mut *bus,
        &RegReadParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "dl_status",
            length: None,
            ty: DataTypeSpec::Bool,
            bit_offset: Some(4),
            bit_length: Some(1),
            timeout,
        },
    )
    .expect("read dl_status bit 4");
    assert_eq!(reg_rep.decoded_value, json!(true));

    // BOOT state mailbox SDO read using Bootstrap mailbox config (SII 0x28..0x30)
    write_al_state(&mut *bus, 1, AlStateSpec::Boot, false, false, timeout).unwrap();
    let boot_vid = sdo_read(
        &mut *bus,
        &SdoReadParams {
            slave: 1,
            index: 0x1018,
            subindex: 1,
            complete_access: false,
            ty: DataTypeSpec::U32,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .expect("SDO read in BOOT state");
    assert_eq!(boot_vid.decoded_value, json!(0x0000_0931));

    // Transition to PRE-OP for full CoE tests
    write_al_state(&mut *bus, 1, AlStateSpec::PreOp, false, false, timeout).unwrap();

    // Negative Auto SDO write on 0x607A (INTEGER32) must query OD width (4B) and encode -1000 as i32
    let neg_wr = sdo_write(
        Some(&mut *bus),
        &SdoWriteParams {
            slave: 1,
            index: 0x607A,
            subindex: 0,
            complete_access: false,
            ty: DataTypeSpec::Auto,
            value_str: "-1000",
            auto_preop: false,
            dry_run: false,
            timeout,
        },
    )
    .expect("negative Auto SDO write");
    assert_eq!(neg_wr.size_bytes, 4);
    assert_eq!(neg_wr.raw_hex, "18fcffff");
    assert_eq!(neg_wr.decoded_value, json!(-1000));

    // Multi-segment SDO download (>140B) + multi-segment SDO upload round-trip on 0x2000:00
    let big_str = "SDO-SEGMENTED-WRITE-PAYLOAD-".repeat(5) + "END"; // 143 bytes
    let seg_wr = sdo_write(
        Some(&mut *bus),
        &SdoWriteParams {
            slave: 1,
            index: 0x2000,
            subindex: 0,
            complete_access: false,
            ty: DataTypeSpec::String,
            value_str: &big_str,
            auto_preop: false,
            dry_run: false,
            timeout,
        },
    )
    .expect("segmented SDO download");
    assert_eq!(seg_wr.transfer_mode, "segmented");
    let seg_rd = sdo_read(
        &mut *bus,
        &SdoReadParams {
            slave: 1,
            index: 0x2000,
            subindex: 0,
            complete_access: false,
            ty: DataTypeSpec::String,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .expect("segmented SDO upload round-trip");
    assert_eq!(seg_rd.transfer_mode, "segmented");
    assert_eq!(seg_rd.decoded_value, json!(big_str));

    // Complete Access SDO write & read on 0x2001 (3 x u16 array)
    let mut ca_payload = vec![3u8, 0x00];
    ca_payload.extend_from_slice(&0x1111u16.to_le_bytes());
    ca_payload.extend_from_slice(&0x2222u16.to_le_bytes());
    ca_payload.extend_from_slice(&0x3333u16.to_le_bytes());
    sdo_write(
        Some(&mut *bus),
        &SdoWriteParams {
            slave: 1,
            index: 0x2001,
            subindex: 0,
            complete_access: true,
            ty: DataTypeSpec::Hex,
            value_str: &format_hex(&ca_payload),
            auto_preop: false,
            dry_run: false,
            timeout,
        },
    )
    .expect("Complete Access SDO write");
    let si2 = sdo_read(
        &mut *bus,
        &SdoReadParams {
            slave: 1,
            index: 0x2001,
            subindex: 2,
            complete_access: false,
            ty: DataTypeSpec::U16,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .unwrap();
    assert_eq!(si2.decoded_value, json!(0x2222));

    // Non-existent SDO index and SDO Info index must both fail with Protocol error 0x06020000
    let sdo_err = sdo_read(
        &mut *bus,
        &SdoReadParams {
            slave: 1,
            index: 0x9999,
            subindex: 0,
            complete_access: false,
            ty: DataTypeSpec::U32,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    );
    assert!(matches!(sdo_err, Err(CliError::Protocol(msg)) if msg.contains("0x06020000")));
    let od_err = query_od_info(&mut *bus, 1, Some(0x9999), false, false, timeout);
    assert!(matches!(od_err, Err(CliError::Protocol(msg)) if msg.contains("0x06020000")));

    // CoE PDO mapping discovery must query entry descriptions (UNSIGNED16 / INTEGER32 + OD names)
    let coe_map = read_slave_pdo_map(&mut *bus, 1, PdoSource::Coe, None, false, timeout).unwrap();
    assert_eq!(coe_map.rx_pdos[0].entries[0].data_type_name, "UNSIGNED16");
    assert_eq!(coe_map.rx_pdos[0].entries[1].data_type_name, "INTEGER32");
    assert_eq!(
        coe_map.rx_pdos[0].entries[0].name.as_deref(),
        Some("Controlword")
    );
    assert_eq!(
        coe_map.tx_pdos[0].entries[1].name.as_deref(),
        Some("Position Actual Value")
    );

    // Transition to OP, verify nonexistent --entry fails with Mismatch, and run cyclic LRW PDO exchange
    write_al_state(&mut *bus, 1, AlStateSpec::SafeOp, false, false, timeout).unwrap();
    write_al_state(&mut *bus, 1, AlStateSpec::Op, false, false, timeout).unwrap();

    let bad_entry = pdo_read_live(
        &mut *bus,
        &PdoReadParams {
            slave: 1,
            logical_addr: None,
            auto_map_fmmu: false,
            entry_filter: Some("0x9999:00"),
            bit_offset: None,
            bit_length: None,
            ty: DataTypeSpec::Auto,
            layout_override: None,
            sii_file: None,
            timeout,
        },
    );
    assert!(matches!(bad_entry, Err(CliError::Mismatch(_))));

    let pdo_ex = pdo_exchange_live(
        Some(&mut *bus),
        &PdoExchangeParams {
            slave: 1,
            logical_addr: 0x0001_0000,
            auto_map_fmmu: true,
            set_fields: &["0x6040:00=0x000F".into(), "0x607A:00=-4200".into()],
            raw_tx_bytes: None,
            rx_layout_override: None,
            tx_layout_override: None,
            sii_file: None,
            dry_run: false,
            timeout,
        },
    )
    .expect("PDO LRW exchange");
    assert_eq!(pdo_ex.wkc, 3);
    let ex_json = serde_json::to_value(&pdo_ex).unwrap();
    let pos = apply_field_selectors(&ex_json, &["0x6064:00".into()]).unwrap();
    assert_eq!(pos["0x6064:00"], json!(-4200));

    // Multi-fragment SDO Info (0x04 Object Desc & 0x06 Entry Desc) reassembly + SM1 drain check
    let mut frag_sim = ethercat_master::sim::SimulatedBusTransport::open("sim").unwrap();
    let long_obj = "LongManufacturerDiagnosticObject_".repeat(6); // 198 bytes (>128B mailbox)
    let long_ent = "LongSubindexZeroDescriptionText_".repeat(6); // 192 bytes (>128B mailbox)
    frag_sim.insert_long_od_object_for_test(0, 0x20FF, &long_obj, &long_ent);
    let frag_od = query_od_info(&mut frag_sim, 1, Some(0x20FF), true, true, timeout)
        .expect("reassemble fragmented SDO Info");
    assert_eq!(frag_od.len(), 1);
    assert_eq!(frag_od[0].name, long_obj);
    assert_eq!(frag_od[0].entries[0].name, long_ent);
    // Subsequent SDO upload must succeed without stale SDO Info fragments left in SM1
    let after_frag = sdo_read(
        &mut frag_sim,
        &SdoReadParams {
            slave: 1,
            index: 0x1018,
            subindex: 1,
            complete_access: false,
            ty: DataTypeSpec::U32,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .expect("clean mailbox after fragmented SDO Info");
    assert_eq!(after_frag.decoded_value, json!(0x0000_0931));

    // pdo_read_live with --layout must NOT touch CoE or SII PDO metadata on slave
    frag_sim.strip_slave_pdo_metadata_for_test(0);
    let layout_only_read = pdo_read_live(
        &mut frag_sim,
        &PdoReadParams {
            slave: 1,
            logical_addr: None,
            auto_map_fmmu: false,
            entry_filter: Some("sw"),
            bit_offset: None,
            bit_length: None,
            ty: DataTypeSpec::Auto,
            layout_override: Some("sw:u16@0,pos:i32@16"),
            sii_file: None,
            timeout,
        },
    )
    .expect("pdo_read_live with --layout on stripped slave");
    assert_eq!(layout_only_read.decoded_inputs.len(), 1);

    // CoE Emergency (service 0x01) pushed ahead of SDO upload reply must be skipped,
    // and ETG.1000.4 Mailbox Error (mbx_type 0x00, detail 0x0004) must fail with Protocol error.
    let mut mbx_sim = ethercat_master::sim::SimulatedBusTransport::open("sim").unwrap();
    write_al_state(&mut mbx_sim, 1, AlStateSpec::PreOp, false, false, timeout).unwrap();
    let emcy = vec![
        10, 0, 0, 0, 0, 0x13, // 6B mbx header (len=10, cnt=1, type=CoE 0x03)
        0x00, 0x10, // CoE header: service = 0x01 (Emergency) << 12
        0x10, 0x81, 0x01, 0, 0, 0, 0, 0, // 8B Emergency payload
    ];
    mbx_sim.inject_sm0_replies_for_test(0, vec![emcy], false);
    let after_emcy = sdo_read(
        &mut mbx_sim,
        &SdoReadParams {
            slave: 1,
            index: 0x1018,
            subindex: 1,
            complete_access: false,
            ty: DataTypeSpec::U32,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .expect("SDO read skips async CoE Emergency");
    assert_eq!(after_emcy.decoded_value, json!(0x0000_0931));

    let mbx_err_frame = vec![4, 0, 0, 0, 0, 0x20, 0x01, 0x00, 0x04, 0x00]; // type=0x00, detail=0x0004 (Invalid Size)
    mbx_sim.inject_sm0_replies_for_test(0, vec![mbx_err_frame], true);
    let mbx_err = sdo_read(
        &mut mbx_sim,
        &SdoReadParams {
            slave: 1,
            index: 0x1018,
            subindex: 1,
            complete_access: false,
            ty: DataTypeSpec::U32,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    )
    .unwrap_err();
    assert!(matches!(mbx_err, CliError::Protocol(ref m) if m.contains("Mailbox Error")));
}

#[test]
fn boundary_and_malformed_input_edge_cases() {
    // Negative numbers and malformed delimiter strings must NEVER parse as hex bytes
    for bad in ["0x123", "-1000", ":aa", "aa:", "aa--bb", "a:b"] {
        assert!(
            matches!(types::parse_hex_bytes(bad), Err(CliError::Format(_))),
            "expected Format error for {bad:?}"
        );
    }
    assert_eq!(
        types::parse_hex_bytes("01:02:03:04:05:06").unwrap(),
        vec![1, 2, 3, 4, 5, 6]
    );
    // Auto & explicit float encoding (including '_' digit separators)
    assert_eq!(
        encode_typed_value("-1000", DataTypeSpec::Auto).unwrap(),
        vec![0x18, 0xFC]
    );
    assert_eq!(
        encode_typed_value("1.5", DataTypeSpec::Auto).unwrap(),
        1.5f32.to_le_bytes().to_vec()
    );
    assert_eq!(
        encode_typed_value("-2.5", DataTypeSpec::Auto).unwrap(),
        (-2.5f32).to_le_bytes().to_vec()
    );
    assert_eq!(
        encode_typed_value("1_000.5", DataTypeSpec::F32).unwrap(),
        1000.5f32.to_le_bytes().to_vec()
    );
    assert_eq!(
        encode_typed_value("1_000.5", DataTypeSpec::F64).unwrap(),
        1000.5f64.to_le_bytes().to_vec()
    );
    // Non-finite IEEE-754 floats must serialize as deterministic strings, never JSON null
    assert_eq!(
        decode_typed_value(&f32::NAN.to_le_bytes(), DataTypeSpec::F32, None).unwrap(),
        json!("NaN")
    );
    assert_eq!(
        decode_typed_value(&f32::INFINITY.to_le_bytes(), DataTypeSpec::F32, None).unwrap(),
        json!("Infinity")
    );
    assert_eq!(
        decode_typed_value(&f64::NEG_INFINITY.to_le_bytes(), DataTypeSpec::F64, None).unwrap(),
        json!("-Infinity")
    );
    // Sub-word bit_len masking on unsigned types (12 bits of 0xFFFF = 0x0FFF = 4095)
    assert_eq!(
        decode_typed_value(&[0xFF, 0xFF], DataTypeSpec::U16, Some(12)).unwrap(),
        json!(0x0FFF)
    );
    // PdoLayout::to_spec_string -> parse_spec round-trip with 0xXXXX:XX colon names
    let layout = PdoLayout::parse_spec("0x6040:00:u16@0:16,0x607a:00:i32@16:32").unwrap();
    let roundtrip = PdoLayout::parse_spec(&layout.to_spec_string()).unwrap();
    assert_eq!(roundtrip.fields.len(), 2);
    assert_eq!(roundtrip.fields[0].name, "0x6040:00");
    assert_eq!(roundtrip.fields[1].bit_offset, 16);

    // Subframe spec @idx / @wkc / @irq / @c / @m modifiers, @m=0 override on non-final subframe,
    // and unknown modifier rejection
    let sf = parse_subframe_spec(
        "BRD:0x0000,0x0130:zeros:4@idx=0x15@wkc=3@irq=0x0004@c=1@m=1",
        1,
    )
    .unwrap();
    assert_eq!(sf.idx, 0x15);
    assert_eq!(sf.wkc, 3);
    assert_eq!(sf.irq, 0x0004);
    assert!(sf.circulating && sf.more);
    assert!(matches!(
        parse_subframe_spec("BRD:0x0000,0x0000:zeros:2@bogus=1", 1),
        Err(CliError::Usage(_))
    ));
    let build_m0 = Cli::try_parse_from([
        "ethercat-cli",
        "frame",
        "build",
        "--subframe",
        "BRD:0x0000,0x0000:zeros:4@m=0",
        "--subframe",
        "BRD:0x0000,0x0130:zeros:6",
    ])
    .unwrap();
    let m0_out = execute_cli(&build_m0).unwrap();
    let m0_bytes = types::parse_hex_bytes(m0_out.json["frame_hex"].as_str().unwrap()).unwrap();
    // Subframe 0 len_flags is at Ethernet(14) + EcatHdr(2) + CmdIdxAdpAdo(6) = offset 22..24
    assert_eq!(u16::from_le_bytes([m0_bytes[22], m0_bytes[23]]) & 0x8000, 0);

    // Standard Ethernet II + EtherCAT frame with dst_mac = 01:01:05:10:00:00 (no 16B ESL tag)
    let mut mc_builder = EcatFrameBuilder {
        dst_mac: [0x01, 0x01, 0x05, 0x10, 0x00, 0x00],
        ..Default::default()
    };
    mc_builder.add_datagram(RawDatagram::new_positioned(
        EcatCmd::Brd,
        1,
        0,
        0x0130,
        vec![0; 2],
    ));
    let mc_raw = mc_builder.build().unwrap();
    let mc_df = dissect_frame(&mc_raw, &DissectOptions::default()).unwrap();
    assert!(!mc_df.wireshark_fields.contains_key("esl.ports"));
    assert_eq!(mc_df.wireshark_fields["ecat.cmd"], "BRD");

    // CoE SDO Abort "number", non-expedited !size_indicated inline_data, and SDO Info 0x06 value_info skip
    let mut ws = std::collections::BTreeMap::new();
    let mut sdo_abort_mbx = vec![10, 0, 0, 0, 0, 0x13, 0x03, 0x20, 0x80, 0x18, 0x10, 0x01];
    sdo_abort_mbx.extend_from_slice(&0x0602_0000u32.to_le_bytes());
    let abort_d =
        protocol::mailbox::dissect_mailbox(&sdo_abort_mbx, &mut ws, "ecat_mailbox").unwrap();
    assert_eq!(abort_d.protocol["number"], 3);
    let sdo_noseg_mbx = vec![
        14, 0, 0, 0, 0, 0x13, 0x00, 0x20, 0x20, 0x00, 0x20, 0x00, 0, 0, 0, 0, 0xDE, 0xAD, 0xBE,
        0xEF,
    ];
    let noseg_d =
        protocol::mailbox::dissect_mailbox(&sdo_noseg_mbx, &mut ws, "ecat_mailbox").unwrap();
    assert_eq!(noseg_d.protocol["data_hex"], "deadbeef");
    assert_eq!(ws["ecat_mailbox.coe.sdo.data"], "deadbeef");
    let mut info06 = vec![0u8; 24];
    info06[5] = 0x13;
    info06[6..8].copy_from_slice(&0x8000u16.to_le_bytes()); // service = 0x08 (SDO Info)
    info06[8] = 0x06; // Entry Description Response
    info06[12..14].copy_from_slice(&0x6071u16.to_le_bytes());
    info06[15] = 0x19; // access(0x01) + unit_type(0x08 -> 4B) + default_value(0x10 -> 2B)
    info06[16..18].copy_from_slice(&0x0003u16.to_le_bytes()); // INTEGER16
    info06[18..20].copy_from_slice(&16u16.to_le_bytes()); // 16 bits
    info06[20..22].copy_from_slice(&0x003Fu16.to_le_bytes());
    info06[22..24].copy_from_slice(&[0xAA, 0xBB]); // start of unit_type
    info06.extend_from_slice(&[0xCC, 0xDD, 0x11, 0x22]); // rest of unit_type (2B) + default_value (2B)
    info06.extend_from_slice(b"Torque");
    let len_hdr = (info06.len() - 6) as u16;
    info06[0..2].copy_from_slice(&len_hdr.to_le_bytes());
    let info06_d = protocol::mailbox::dissect_mailbox(&info06, &mut ws, "ecat_mailbox").unwrap();
    assert_eq!(info06_d.protocol["name"], "Torque");
    assert_eq!(ws["ecat_mailbox.coe.sdoinfo.name"], "Torque");

    // PCAPNG linktype / IDB ordering / compressed archive checks + mixed ARP/EtherCAT frame send --file
    let make_shb = || {
        let mut b = Vec::new();
        b.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        b.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&(-1i64).to_le_bytes());
        b.extend_from_slice(&28u32.to_le_bytes());
        b
    };
    let push_idb = |b: &mut Vec<u8>, lt: u16| {
        b.extend_from_slice(&1u32.to_le_bytes());
        b.extend_from_slice(&20u32.to_le_bytes());
        b.extend_from_slice(&lt.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&65535u32.to_le_bytes());
        b.extend_from_slice(&20u32.to_le_bytes());
    };
    let push_epb = |b: &mut Vec<u8>, if_id: u32, pkt: &[u8]| {
        let pad = (pkt.len() + 3) & !3;
        let blen = (32 + pad) as u32;
        b.extend_from_slice(&6u32.to_le_bytes());
        b.extend_from_slice(&blen.to_le_bytes());
        b.extend_from_slice(&if_id.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        b.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        b.extend_from_slice(pkt);
        b.resize(b.len() + (pad - pkt.len()), 0);
        b.extend_from_slice(&blen.to_le_bytes());
    };
    let tmp_ng =
        std::env::temp_dir().join(format!("ethercat-cli-edge-{}.pcapng", unique_temp_id()));
    // 1) EPB referencing undefined interface_id = 1 -> Format error
    let mut bad_if = make_shb();
    push_idb(&mut bad_if, 1);
    push_epb(&mut bad_if, 1, &mc_raw);
    std::fs::write(&tmp_ng, &bad_if).unwrap();
    assert!(matches!(
        load_frames_from_file(&tmp_ng, FrameInputKind::Auto, 5),
        Err(CliError::Format(_))
    ));
    // 2) Non-Ethernet LINKTYPE_RAW (101) only -> Format error
    let mut raw_ip = make_shb();
    push_idb(&mut raw_ip, 101);
    push_epb(&mut raw_ip, 0, &[0x45; 20]);
    std::fs::write(&tmp_ng, &raw_ip).unwrap();
    assert!(matches!(
        load_frames_from_file(&tmp_ng, FrameInputKind::Auto, 5),
        Err(CliError::Format(_))
    ));
    // 3) Gzip-compressed capture -> clear Format error
    std::fs::write(&tmp_ng, [0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0]).unwrap();
    assert!(matches!(
        load_frames_from_file(&tmp_ng, FrameInputKind::Auto, 5),
        Err(CliError::Format(_))
    ));
    // 4) Mixed multi-IDB (IDB 0 = USBPcap 249, IDB 1 = Ethernet 1 with ARP #0 + EtherCAT #1) -> frame send --file skips non-ECAT!
    let mut mixed_ng = make_shb();
    push_idb(&mut mixed_ng, 249);
    push_idb(&mut mixed_ng, 1);
    push_epb(&mut mixed_ng, 0, &[0xAA; 28]); // USBPcap packet on IDB 0
    let mut arp_pkt = vec![0xFF; 60];
    arp_pkt[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP on IDB 1
    push_epb(&mut mixed_ng, 1, &arp_pkt);
    push_epb(&mut mixed_ng, 1, &mc_raw); // EtherCAT on IDB 1
    std::fs::write(&tmp_ng, &mixed_ng).unwrap();
    let send_mixed = Cli::try_parse_from([
        "ethercat-cli",
        "frame",
        "send",
        "--file",
        tmp_ng.to_str().unwrap(),
        "--dry-run",
    ])
    .unwrap();
    let send_out = execute_cli(&send_mixed).unwrap();
    let _ = std::fs::remove_file(&tmp_ng);
    assert_eq!(send_out.json["dry_run"], true);
    assert_eq!(send_out.json["tx_wire_len"], mc_raw.len());

    // Offline CLI --dry-run (even when -i points to an offline NPF adapter) for reg write, sdo write & pdo exchange,
    // plus --slave 0 rejection and --input aliases
    let reg_cli = Cli::try_parse_from([
        "ethercat-cli",
        "reg",
        "write",
        "--slave",
        "1",
        "--reg",
        "station_addr",
        "--value",
        "0x1001",
        "--dry-run",
    ])
    .unwrap();
    let reg_out = execute_cli(&reg_cli).unwrap();
    assert_eq!(reg_out.json["dry_run"], true);
    assert_eq!(reg_out.json["raw_hex"], "0110");

    let sdo_dry_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        r"\Device\NPF_{00000000-0000-0000-0000-000000000000}",
        "sdo",
        "write",
        "--slave",
        "1",
        "--index",
        "0x607A",
        "--subindex",
        "0",
        "--value=-25000",
        "--type",
        "i32",
        "--dry-run",
    ])
    .unwrap();
    let sdo_dry_out = execute_cli(&sdo_dry_cli).unwrap();
    assert_eq!(sdo_dry_out.json["dry_run"], true);
    assert_eq!(sdo_dry_out.json["raw_hex"], "589effff");

    for zero_slave_cmd in [
        vec![
            "ethercat-cli",
            "sdo",
            "write",
            "--slave",
            "0",
            "--index",
            "0x6040",
            "--value",
            "1",
            "--type",
            "u16",
            "--dry-run",
        ],
        vec![
            "ethercat-cli",
            "pdo",
            "exchange",
            "--slave",
            "0",
            "--rx-layout",
            "c:u16@0",
            "--set",
            "c=1",
            "--dry-run",
        ],
        vec!["ethercat-cli", "-i", "sim", "pdo", "read", "--slave", "0"],
    ] {
        let parsed = Cli::try_parse_from(zero_slave_cmd).unwrap();
        assert!(matches!(execute_cli(&parsed), Err(CliError::Usage(_))));
    }

    let pdo_cli = Cli::try_parse_from([
        "ethercat-cli",
        "pdo",
        "exchange",
        "--rx-layout",
        "ctrl:u16@0,target:i32@16",
        "--set",
        "ctrl=0x000F",
        "--set",
        "target=-500",
        "--dry-run",
    ])
    .unwrap();
    let pdo_out = execute_cli(&pdo_cli).unwrap();
    assert_eq!(pdo_out.json["dry_run"], true);
    assert_eq!(pdo_out.json["tx_outputs_hex"], "0f000cfeffff");

    assert!(Cli::try_parse_from(["ethercat-cli", "dissect", "--input", "capture.pcapng"]).is_ok());
    assert!(Cli::try_parse_from([
        "ethercat-cli",
        "frame",
        "send",
        "--input",
        "tx.bin",
        "--dry-run"
    ])
    .is_ok());

    // Out-of-bounds bit slice -> Format error
    assert!(matches!(
        extract_bits_le(&[0xAA, 0x55], 12, 5),
        Err(CliError::Format(_))
    ));
    // Truncated Ethernet/EtherCAT frame -> Format error
    assert!(matches!(
        dissect_frame(&[0xFF; 10], &DissectOptions::default()),
        Err(CliError::Format(_))
    ));
    // Unknown field selector -> Mismatch error (exit code 4)
    assert!(matches!(
        apply_field_selectors(&json!({"a": 1}), &["nonexistent.field".into()]),
        Err(CliError::Mismatch(_))
    ));
}

#[test]
fn esi_xml_compiler_ssc_parity_workflows_sim_esi_and_udp_transport_end_to_end() {
    use ethercat_eeprom::esi::{
        compile_esi_device_to_sii, load_esi_catalog, select_esi_device, EsiCompileOptions,
    };
    use ethercat_eeprom::sii::image::SiiBuildProfile;
    use ethercat_eeprom::sii::ops::reload_device_sii;
    use ethercat_eeprom::sii::workflow::{
        program_slave_eeprom_workflow, SiiProgramWorkflowOptions, SiiSourceInput, SiiSourceSpec,
        SiiXmlSourceOptions,
    };
    use ethercat_master::sim::SimulatedBusTransport;
    use ethercat_wire::transport::udp::{
        extract_udp_ecat_payload, wrap_udp_ecat_payload, UdpEcatTransport,
    };
    use ethercat_wire::transport::EthercatTransport;
    use std::net::UdpSocket;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    let tmp = std::env::temp_dir().join(format!("ecat_esi_ssc_test_{}", unique_temp_id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let sub_dir = tmp.join("sub");
    std::fs::create_dir_all(&sub_dir).unwrap();

    // 1. Write external InfoReference XML (with two revisions of EXT-2000: DC OpMode + pre-encoded <Eeprom><Data>)
    let ext_xml_path = sub_dir.join("ext_dev.xml");
    let hex_128_zeros = "00".repeat(128);
    let ext_xml = format!(
        r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Descriptions>
<Devices>
  <Device Physics="YY  ">
    <Type ProductCode="#x00002000" RevisionNo="#x00010001" SerialNo="#x00000042">EXT-2000</Type>
    <Name LcId="1033">EXT-2000 DC Servo</Name>
    <GroupType>Drives</GroupType>
    <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
    <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
    <Mailbox DataLinkLayer="true">
      <CoE SdoInfo="true" PdoAssign="true"/>
    </Mailbox>
    <Dc>
      <OpMode>
        <Name>DC-Sync</Name>
        <Desc>DC Synchron 250us</Desc>
        <AssignActivate>#x0300</AssignActivate>
        <CycleTimeSync0 Factor="1">250000</CycleTimeSync0>
        <ShiftTimeSync0>1000</ShiftTimeSync0>
        <CycleTimeSync1 Factor="-2">0</CycleTimeSync1>
        <ShiftTimeSync1>0</ShiftTimeSync1>
      </OpMode>
    </Dc>
    <Eeprom>
      <ByteSize>512</ByteSize>
      <ConfigData>04070244640000</ConfigData>
    </Eeprom>
  </Device>
  <Device Physics="YY">
    <Type ProductCode="#x00002000" RevisionNo="#x00010002" SerialNo="#x00000099">EXT-2000</Type>
    <Name LcId="1033">EXT-2000 Blob Mode</Name>
    <GroupType>Drives</GroupType>
    <Eeprom>
      <ByteSize>128</ByteSize>
      <Data>{hex_128_zeros}</Data>
    </Eeprom>
  </Device>
</Devices>
  </Descriptions>
</EtherCATInfo>"##
    );
    std::fs::write(&ext_xml_path, ext_xml.as_bytes()).unwrap();

    // 2. Write ISO-8859-1 root ESI XML with raw Latin-1 bytes (0xE4='ä', 0xB0='°'),
    //    <InfoReference>, custom <Dictionary><DataTypes>, skipped <ImageData16x14>/<Objects>,
    //    <BootStrap>, odd 3-FMMU 0xFF padding, assigned + unassigned PDOs, and tight 512B budget!
    let root_xml_path = tmp.join("catalog_root.xml");
    let root_xml_prefix = br##"<?xml version="1.0" encoding="ISO-8859-1"?>
<!-- Beckhoff SSC / ETG.2000 parity fixture -->
<EtherCATInfo>
  <Vendor>
<Id>#x00000931</Id>
<Name>Pr"##;
    let root_xml_mid = br##"zision 25"##;
    let root_xml_suffix = br##"C GmbH</Name>
  </Vendor>
  <Descriptions>
<Groups>
  <Group>
    <Type>GPC</Type>
    <Name LcId="1031">Gertegruppe</Name>
    <Name LcId="1033">GPC</Name>
  </Group>
  <Group>
    <Type>Drives</Type>
    <Name LcId="1033">Servo Drives</Name>
  </Group>
</Groups>
<Devices>
  <Device Physics="YKY ">
    <Type ProductCode="#x00000067" RevisionNo="#x00000001">PC-1000</Type>
    <Name LcId="1031">PC-1000 Deutsch</Name>
    <Name LcId="1033">PC-1000 Analog &amp; DIO</Name>
    <GroupType>GPC</GroupType>
    <Profile>
      <ProfileNo>5001</ProfileNo>
      <Dictionary>
        <DataTypes>
          <DataType>
            <Name>MY_STATUS_WORD</Name>
            <BaseType>UINT</BaseType>
            <BitSize>16</BitSize>
          </DataType>
        </DataTypes>
        <Objects>
          <Object><Index>#x1000</Index><Name>Ignored Heavy Subtree</Name></Object>
        </Objects>
      </Dictionary>
    </Profile>
    <Info>
      <IdentificationReg134>1</IdentificationReg134>
      <Electrical><EBusCurrent>-120</EBusCurrent></Electrical>
    </Info>
    <Fmmu>Outputs</Fmmu>
    <Fmmu>Inputs</Fmmu>
    <Fmmu>MBoxState</Fmmu>
    <Sm StartAddress="#x1000" DefaultSize="128" ControlByte="#x26" Enable="1">MBoxOut</Sm>
    <Sm StartAddress="#x1080" DefaultSize="128" ControlByte="#x22" Enable="1">MBoxIn</Sm>
    <Sm StartAddress="#x1100" DefaultSize="6" ControlByte="#x64" Enable="1">Outputs</Sm>
    <Sm StartAddress="#x1400" DefaultSize="6" ControlByte="#x20" Enable="1">Inputs</Sm>
    <TxPdo Fixed="1" Mandatory="1" Sm="3">
      <Index>#x1A00</Index>
      <Name>TxPDO_Primary_Feedback_Channel_A</Name>
      <Entry>
        <Index>#x6041</Index>
        <SubIndex>0</SubIndex>
        <BitLen>16</BitLen>
        <Name>Statusword_Primary_Feedback_Axis_1</Name>
        <DataType>MY_STATUS_WORD</DataType>
      </Entry>
      <Entry>
        <Index>#x6064</Index>
        <SubIndex>0</SubIndex>
        <BitLen>32</BitLen>
        <Name>Position_Actual_Value_Primary_Axis_1</Name>
        <DataType>DINT</DataType>
      </Entry>
    </TxPdo>
    <TxPdo Fixed="1">
      <Index>#x1A01</Index>
      <Name>Unassigned_Optional_TxPDO</Name>
      <Entry>
        <Index>#x60FD</Index>
        <SubIndex>0</SubIndex>
        <BitLen>32</BitLen>
        <Name>Digital_Inputs</Name>
        <DataType>UDINT</DataType>
      </Entry>
    </TxPdo>
    <RxPdo Fixed="1" Mandatory="1" Sm="2">
      <Index>#x1600</Index>
      <Name>RxPDO_Overflowing_Command_Set_With_Very_Long_Description_String_01</Name>
      <Entry>
        <Index>#x6040</Index>
        <SubIndex>0</SubIndex>
        <BitLen>16</BitLen>
        <Name>Controlword_Overflowing_Entry_Name_Exceeding_512_Byte_EEPROM_Budget_02</Name>
        <DataType>UINT</DataType>
      </Entry>
      <Entry>
        <Index>#x607A</Index>
        <SubIndex>0</SubIndex>
        <BitLen>32</BitLen>
        <Name>Target_Position_Overflowing_Entry_Name_Exceeding_512_Byte_EEPROM_Budget_03</Name>
        <DataType>DINT</DataType>
      </Entry>
    </RxPdo>
    <Mailbox DataLinkLayer="true">
      <CoE SdoInfo="true" PdoAssign="false" PdoConfig="false" CompleteAccess="true"/>
      <FoE/>
    </Mailbox>
    <Eeprom>
      <ByteSize>512</ByteSize>
      <ConfigData>050603440A00000000001A007FFF</ConfigData>
      <BootStrap>0010800080108000</BootStrap>
    </Eeprom>
    <ImageData16x14>FFFF0000AABBCCDD</ImageData16x14>
  </Device>
</Devices>
<InfoReference>sub/ext_dev.xml</InfoReference>
  </Descriptions>
</EtherCATInfo>"##;
    let mut latin1_bytes = Vec::new();
    latin1_bytes.extend_from_slice(root_xml_prefix);
    latin1_bytes.push(0xE4); // 'ä' in ISO-8859-1 (invalid standalone UTF-8!)
    latin1_bytes.extend_from_slice(root_xml_mid);
    latin1_bytes.push(0xB0); // '°' in ISO-8859-1
    latin1_bytes.extend_from_slice(root_xml_suffix);
    std::fs::write(&root_xml_path, &latin1_bytes).unwrap();

    // 3. UTF-16LE BOM single-device XML + self-referencing <InfoReference> cycle guard check
    let utf16_path = sub_dir.join("utf16_single.xml");
    let utf16_src = r##"<?xml version="1.0" encoding="UTF-16"?>
<EtherCATInfo>
  <Vendor><Id>2</Id><Name>Beckhoff</Name></Vendor>
  <Descriptions>
<InfoReference>utf16_single.xml</InfoReference>
<Devices>
  <Device Physics="KK">
    <Type ProductCode="#x03f03052" RevisionNo="#x00100000">EL1008</Type>
    <Name>EL1008 8Ch. Dig. Input</Name>
    <Eeprom><ByteSize>256</ByteSize><ConfigData>80030000000000</ConfigData></Eeprom>
  </Device>
</Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let mut utf16_bytes = vec![0xFFu8, 0xFEu8];
    for u in utf16_src.encode_utf16() {
        utf16_bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&utf16_path, &utf16_bytes).unwrap();
    let utf16_cat = load_esi_catalog(&utf16_path, 1033).unwrap();
    assert_eq!(utf16_cat.devices.len(), 1);
    let single_dev = select_esi_device(&utf16_cat.devices, None, None).unwrap();
    assert_eq!(single_dev.order_code, "EL1008");

    // 4. Multi-device catalog loading, Latin-1 decoding, <InfoReference> inheritance & selection
    let cat = load_esi_catalog(&root_xml_path, 1033).unwrap();
    assert_eq!(cat.files_loaded.len(), 2);
    assert_eq!(cat.devices.len(), 3);
    assert!(cat.devices[0].vendor_name.contains('ä') && cat.devices[0].vendor_name.contains('°'));
    assert_eq!(cat.devices[0].device_name, "PC-1000 Analog & DIO");
    // Inherited Vendor ID on <InfoReference> child devices:
    assert_eq!(cat.devices[1].vendor_id, 0x0000_0931);

    // Omitting --device on a multi-device catalog must return a helpful Usage error
    assert!(matches!(
        select_esi_device(&cat.devices, None, None),
        Err(CliError::Usage(_))
    ));
    let dev_pc1000 = select_esi_device(&cat.devices, Some("PC-1000"), None).unwrap();
    assert_eq!(dev_pc1000.product_code, 0x0000_0067);
    let dev_ext_dc = select_esi_device(&cat.devices, Some("EXT-2000@#x00010001"), None).unwrap();
    assert_eq!(dev_ext_dc.revision_number, 0x0001_0001);
    let dev_ext_blob =
        select_esi_device(&cat.devices, Some("EXT-2000"), Some(0x0001_0002)).unwrap();
    assert_eq!(dev_ext_blob.revision_number, 0x0001_0002);

    // 5. Compile PC-1000 under SSC profile (512B tight budget) and verify exact ETG.2010 / SSC parity
    let ssc_compiled =
        compile_esi_device_to_sii(dev_pc1000, &EsiCompileOptions::default()).unwrap();
    assert!(ssc_compiled.strings_dropped_by_budget > 0);
    let ssc_bytes = ssc_compiled.bytes;
    assert_eq!(ssc_bytes.len(), 512);
    sii_validate(&ssc_bytes).unwrap();
    assert_eq!(
        &ssc_bytes[0x00..0x0E],
        &[0x05, 0x06, 0x03, 0x44, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x7F, 0xFF]
    );
    assert_eq!(
        ssc_bytes[0x0E], 0x87,
        "ConfigData 050603440A00000000001A007FFF CRC-8 must be 0x87"
    );
    assert_eq!(
        &ssc_bytes[0x28..0x30],
        &[0x00, 0x10, 0x80, 0x00, 0x80, 0x10, 0x80, 0x00],
        "BootStrap mailbox words at 0x28..0x30"
    );
    assert_eq!(
        u16::from_le_bytes([ssc_bytes[0x30], ssc_bytes[0x31]]),
        0x1000
    );
    assert_eq!(
        u16::from_le_bytes([ssc_bytes[0x34], ssc_bytes[0x35]]),
        0x1080
    );
    assert_eq!(
        u16::from_le_bytes([ssc_bytes[0x38], ssc_bytes[0x39]]),
        0x000C
    ); // CoE(0x04) | FoE(0x08)
    assert_eq!(u16::from_le_bytes([ssc_bytes[0x7C], ssc_bytes[0x7D]]), 3); // 512 / 128 - 1
    assert_eq!(u16::from_le_bytes([ssc_bytes[0x7E], ssc_bytes[0x7F]]), 1); // Version 1

    let ssc_dec = inspect_sii_data(&ssc_bytes).unwrap();
    // SSC string order: Group ("GPC"), Order/Image ("PC-1000"), Name ("PC-1000 Analog & DIO")
    assert_eq!(ssc_dec.categories.strings[0], "GPC");
    assert_eq!(ssc_dec.categories.strings[1], "PC-1000");
    assert_eq!(ssc_dec.categories.strings[2], "PC-1000 Analog & DIO");
    let gen = ssc_dec.categories.general.as_ref().unwrap();
    assert_eq!(dev_pc1000.current_on_ebus_ma, -120);
    assert_eq!(
        gen.current_on_ebus_ma, 0,
        "SSC profile leaves General.CurrentOnEBus = 0 matching ET9300Utilities.dll"
    );
    assert_eq!(gen.physical_ports, ["MII", "EBUS", "MII", "NotImplemented"]);
    assert_eq!(gen.flags, 0x0C); // MboxDataLinkLayer(0x04) | IdentificationReg134(0x08)
    assert_eq!(ssc_dec.categories.fmmus.len(), 3);
    let fmmu_cat = ssc_dec
        .categories
        .category_headers
        .iter()
        .find(|c| c.category_code == 40)
        .unwrap();
    assert_eq!(
        fmmu_cat.word_length, 2,
        "3 FMMUs must pad with 0xFF to 2 words"
    );
    // Unassigned TxPDO #x1A01 omitted by default; custom MY_STATUS_WORD resolved to UINT (0x06)
    assert_eq!(ssc_dec.categories.tx_pdos.len(), 1);
    assert_eq!(
        ssc_dec.categories.tx_pdos[0].entries[0].data_type_name,
        "UNSIGNED16"
    );
    assert_eq!(ssc_dec.categories.tx_pdos[0].entries[0].data_type, 0x06);
    // Byte budget priority: General + TxPDO strings fit in 512B, overflowing RxPDO strings dropped to index 0!
    assert!(ssc_dec.categories.tx_pdos[0].name.is_some());
    assert_eq!(ssc_dec.categories.rx_pdos.len(), 1);
    assert!(
        ssc_dec.categories.rx_pdos[0].name.is_none(),
        "Overflowing RxPDO strings must drop to string index 0 when tight 512B budget is enforced"
    );
    // SSC profile emits 24-byte zero DC block even when <Dc> is absent
    assert!(ssc_dec
        .categories
        .category_headers
        .iter()
        .any(|c| c.category_code == 60 && c.word_length == 12));

    // SSC profile also emits 0-word FMMU (40) and SyncM (41) TLV headers on passive/simple slaves (EL1008)
    let el1008_ssc = compile_esi_device_to_sii(single_dev, &EsiCompileOptions::default()).unwrap();
    let el1008_dec = inspect_sii_data(&el1008_ssc.bytes).unwrap();
    assert!(el1008_dec
        .categories
        .category_headers
        .iter()
        .any(|c| c.category_code == 40 && c.word_length == 0));
    assert!(el1008_dec
        .categories
        .category_headers
        .iter()
        .any(|c| c.category_code == 41 && c.word_length == 0));

    // --ignore-eeprom-size auto-grows image and keeps ALL RxPDO strings + --include-unassigned-pdos includes #x1A01
    let grown_bytes = compile_esi_device_to_sii(
        dev_pc1000,
        &EsiCompileOptions {
            ignore_eeprom_size: true,
            include_unassigned_pdos: true,
            ..Default::default()
        },
    )
    .unwrap()
    .bytes;
    assert!(grown_bytes.len() > 512 && grown_bytes.len().is_multiple_of(128));
    let grown_dec = inspect_sii_data(&grown_bytes).unwrap();
    assert_eq!(grown_dec.categories.tx_pdos.len(), 2);
    assert!(grown_dec.categories.rx_pdos[0].name.is_some());

    // Minimal profile: Order string before Group, EBusCurrent preserved, CoE PDOs omitted, empty DC omitted
    let min_bytes = compile_esi_device_to_sii(
        dev_pc1000,
        &EsiCompileOptions {
            profile: SiiBuildProfile::Minimal,
            ..Default::default()
        },
    )
    .unwrap()
    .bytes;
    let min_dec = inspect_sii_data(&min_bytes).unwrap();
    assert_eq!(min_dec.categories.strings[0], "PC-1000");
    assert_eq!(
        min_dec
            .categories
            .general
            .as_ref()
            .unwrap()
            .current_on_ebus_ma,
        -120
    );
    assert!(min_dec.categories.tx_pdos.is_empty() && min_dec.categories.rx_pdos.is_empty());
    assert!(!min_dec
        .categories
        .category_headers
        .iter()
        .any(|c| c.category_code == 60));

    // DC OpMode compilation + <Eeprom><Data> hex blob compilation
    let dc_bytes = compile_esi_device_to_sii(dev_ext_dc, &EsiCompileOptions::default())
        .unwrap()
        .bytes;
    let dc_dec = inspect_sii_data(&dc_bytes).unwrap();
    assert_eq!(dc_dec.categories.dc_modes.len(), 1);
    assert_eq!(dc_dec.categories.dc_modes[0].assign_activate, "0x0300");
    assert_eq!(dc_dec.categories.dc_modes[0].cycle_time_0_ns, 250_000);

    let blob_bytes = compile_esi_device_to_sii(
        dev_ext_blob,
        &EsiCompileOptions {
            alias_override: Some(0x0015),
            ..Default::default()
        },
    )
    .unwrap()
    .bytes;
    sii_validate(&blob_bytes).unwrap();
    let blob_dec = inspect_sii_data(&blob_bytes).unwrap();
    assert_eq!(blob_dec.header.product_code, 0x0000_2000);
    assert_eq!(blob_dec.header.revision_number, 0x0001_0002);
    assert_eq!(blob_dec.header.configured_station_alias, 0x0015);

    // 6. CLI `esi list`, `esi inspect`, `esi build`, `sii inspect --header-out`, and `sii diff` (.xml vs .bin)
    let out_bin = tmp.join("pc1000.bin");
    let out_hdr = tmp.join("eeprom.h");
    let build_cli = Cli::try_parse_from([
        "ethercat-cli",
        "esi",
        "build",
        "--xml",
        root_xml_path.to_str().unwrap(),
        "--device",
        "PC-1000",
        "--output",
        out_bin.to_str().unwrap(),
        "--header-out",
        out_hdr.to_str().unwrap(),
    ])
    .unwrap();
    let build_res = execute_cli(&build_cli).unwrap();
    assert_eq!(build_res.json["identity"]["crc_ok"], true);
    assert_eq!(std::fs::read(&out_bin).unwrap(), ssc_bytes);
    let hdr_text = std::fs::read_to_string(&out_hdr).unwrap();
    assert!(hdr_text.contains("unsigned char aEepromData[] = {"));
    assert!(hdr_text.contains("0x05,0x06,0x03,0x44,"));

    let diff_cli = Cli::try_parse_from([
        "ethercat-cli",
        "sii",
        "diff",
        "--left",
        root_xml_path.to_str().unwrap(),
        "--left-device",
        "PC-1000",
        "--right",
        out_bin.to_str().unwrap(),
    ])
    .unwrap();
    let diff_res = execute_cli(&diff_cli).unwrap();
    assert_eq!(diff_res.json["identical"], true);
    assert_eq!(diff_res.json["differing_words"], 0);

    let inspect_esi_cli = Cli::try_parse_from([
        "ethercat-cli",
        "esi",
        "inspect",
        "--xml",
        root_xml_path.to_str().unwrap(),
        "--device",
        "PC-1000",
        "-f",
        "esi.order_code",
        "-f",
        "sii.device_name",
    ])
    .unwrap();
    let inspect_esi_res = execute_cli(&inspect_esi_cli).unwrap();
    let selected_inspect =
        apply_field_selectors(&inspect_esi_res.json, &inspect_esi_cli.fields).unwrap();
    assert_eq!(selected_inspect["esi.order_code"], "PC-1000");
    assert_eq!(selected_inspect["sii.device_name"], "PC-1000 Analog & DIO");

    // 7. End-to-end `sim://esi=<xml>;device=PC-1000` + `esi read`, `esi verify`, CoE SDO, `esi burn`, `sii reload`
    let sim_esi_uri = format!("sim://esi={};device=PC-1000", root_xml_path.display());
    let read_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        &sim_esi_uri,
        "esi",
        "read",
        "--slave",
        "1",
        "--xml",
        tmp.to_str().unwrap(),
        "--decode",
    ])
    .unwrap();
    let read_res = execute_cli(&read_cli).unwrap();
    assert_eq!(read_res.json["esi_match"]["match_kind"], "exact");
    assert_eq!(
        read_res.json["esi_match"]["device"]["order_code"],
        "PC-1000"
    );
    let sel_read = apply_field_selectors(
        &read_res.json,
        &["sii.device_name".into(), "esi.order_code".into()],
    )
    .unwrap();
    assert_eq!(sel_read["sii.device_name"], "PC-1000 Analog & DIO");
    assert_eq!(sel_read["esi.order_code"], "PC-1000");

    let sdo_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        &sim_esi_uri,
        "sdo",
        "read",
        "--slave",
        "1",
        "--index",
        "0x1008",
        "--subindex",
        "0",
        "--type",
        "string",
        "--auto-preop",
    ])
    .unwrap();
    let sdo_res = execute_cli(&sdo_cli).unwrap();
    assert_eq!(sdo_res.json["decoded_value"], "PC-1000 Analog & DIO");

    let verify_ok_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        &sim_esi_uri,
        "esi",
        "verify",
        "--slave",
        "1",
        "--xml",
        root_xml_path.to_str().unwrap(),
        "--device",
        "PC-1000",
    ])
    .unwrap();
    assert_eq!(execute_cli(&verify_ok_cli).unwrap().json["verified"], true);

    let verify_fail_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        &sim_esi_uri,
        "esi",
        "verify",
        "--slave",
        "1",
        "--xml",
        root_xml_path.to_str().unwrap(),
        "--device",
        "EXT-2000@#x00010001",
    ])
    .unwrap();
    assert!(matches!(
        execute_cli(&verify_fail_cli),
        Err(CliError::Mismatch(_))
    ));

    // Stateful guarded burn + --check-esc-config + reload on SimulatedBusTransport
    let mut sim_bus = SimulatedBusTransport::open(&sim_esi_uri).unwrap();
    // Non-string SII categories exceeding 128B must return CliError::Format unless --ignore-eeprom-size
    assert!(matches!(
        compile_esi_device_to_sii(
            dev_pc1000,
            &EsiCompileOptions {
                eeprom_size_override: Some(128),
                ..Default::default()
            }
        ),
        Err(CliError::Format(_))
    ));

    let bad_esc_xml = tmp.join("bad_esc.xml");
    std::fs::write(
        &bad_esc_xml,
        r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>#x00000931</Id><Name>Test</Name></Vendor>
  <Descriptions><Devices><Device>
<Type ProductCode="#x00000067" RevisionNo="#x00000001">PC-1000</Type>
<Name>Mismatch PDI</Name>
<Eeprom><ByteSize>256</ByteSize><ConfigData>FF990244640000</ConfigData></Eeprom>
  </Device></Devices></Descriptions>
</EtherCATInfo>"##,
    )
    .unwrap();
    let bad_source = SiiSourceSpec {
        input: SiiSourceInput::EsiXml {
            xml_path: bad_esc_xml,
            opts: SiiXmlSourceOptions::default(),
        },
        patch: None,
    };
    let mismatch_dry = program_slave_eeprom_workflow(
        &mut sim_bus,
        &SiiProgramWorkflowOptions {
            slave: 1,
            source: &bad_source,
            execute: false,
            backup_path: None,
            confirm_token: None,
            reload: false,
            check_esc_config: true,
            timeout: Duration::from_millis(200),
        },
    )
    .unwrap();
    assert!(mismatch_dry.write_report.dry_run);
    assert!(!mismatch_dry.write_report.esc_config_check.unwrap().matches);

    let mismatch_exec = program_slave_eeprom_workflow(
        &mut sim_bus,
        &SiiProgramWorkflowOptions {
            slave: 1,
            source: &bad_source,
            execute: true,
            backup_path: Some(&tmp.join("never_written_backup.bin")),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: false,
            check_esc_config: true,
            timeout: Duration::from_millis(200),
        },
    );
    assert!(
        matches!(mismatch_exec, Err(CliError::Mismatch(_))),
        "--check-esc-config with --execute must reject PDI Control mismatch against live ESC 0x0140"
    );
    assert!(!tmp.join("never_written_backup.bin").exists());

    let backup_bin = tmp.join("slave1_backup.bin");
    let good_source = SiiSourceSpec {
        input: SiiSourceInput::EsiXml {
            xml_path: root_xml_path.clone(),
            opts: SiiXmlSourceOptions {
                device: Some("PC-1000".into()),
                ..Default::default()
            },
        },
        patch: Some(SiiPatchSpec {
            alias: Some(0x0009),
            recalculate_crc: true,
            ..Default::default()
        }),
    };
    let burn_report = program_slave_eeprom_workflow(
        &mut sim_bus,
        &SiiProgramWorkflowOptions {
            slave: 1,
            source: &good_source,
            execute: true,
            backup_path: Some(&backup_bin),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: false,
            check_esc_config: true,
            timeout: Duration::from_millis(200),
        },
    )
    .unwrap();
    assert!(burn_report.write_report.executed && burn_report.write_report.verified);
    assert!(burn_report.write_report.esc_config_check.unwrap().matches);
    assert_eq!(std::fs::read(&backup_bin).unwrap(), ssc_bytes);

    // Before reload, ESC 0x0012 configured station alias is still 0x0000; after reload_device_sii, 0x0009!
    let (_, alias_before) = sim_bus
        .send_datagram(
            EcatCmd::Aprd,
            0,
            0x0012,
            vec![0, 0],
            Duration::from_millis(100),
        )
        .unwrap();
    assert_eq!(
        u16::from_le_bytes([alias_before[0], alias_before[1]]),
        0x0000
    );
    reload_device_sii(&mut sim_bus, 1, Duration::from_millis(200)).unwrap();
    let (_, alias_after) = sim_bus
        .send_datagram(
            EcatCmd::Aprd,
            0,
            0x0012,
            vec![0, 0],
            Duration::from_millis(100),
        )
        .unwrap();
    assert_eq!(u16::from_le_bytes([alias_after[0], alias_after[1]]), 0x0009);

    let reload_dry_cli = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        "sim",
        "sii",
        "reload",
        "--slave",
        "1",
        "--dry-run",
    ])
    .unwrap();
    assert_eq!(execute_cli(&reload_dry_cli).unwrap().json["dry_run"], true);

    // 8. Layer 1 `UdpEcatTransport` real local UDP socket round-trip against SimulatedBusTransport
    let udp_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
    let srv_addr = udp_srv.local_addr().unwrap();
    udp_srv
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop_flag);
    let responder = std::thread::spawn(move || {
        let mut gw_sim = SimulatedBusTransport::open("sim").unwrap();
        let mut rx_buf = [0u8; 2048];
        while !stop_bg.load(Ordering::Relaxed) {
            if let Ok((n, peer)) = udp_srv.recv_from(&mut rx_buf) {
                // Verify wire format: no 14B Ethernet header on the UDP wire!
                let eth_req = wrap_udp_ecat_payload(&rx_buf[..n]).unwrap();
                let eth_resp = gw_sim
                    .transact_frame(&eth_req, None, Duration::from_millis(100))
                    .unwrap();
                let udp_resp = extract_udp_ecat_payload(&eth_resp).unwrap();
                udp_srv.send_to(udp_resp, peer).unwrap();
            }
        }
    });

    let udp_uri = format!("udp://127.0.0.1@{srv_addr}");
    let udp_probe = UdpEcatTransport::open(&udp_uri).unwrap();
    assert_eq!(udp_probe.target_addr(), srv_addr);
    assert!(udp_probe.local_addr().unwrap().ip().is_loopback());
    drop(udp_probe);

    let udp_scan_cli = Cli::try_parse_from(["ethercat-cli", "-i", &udp_uri, "scan"]).unwrap();
    let udp_scan_res = execute_cli(&udp_scan_cli).unwrap();
    stop_flag.store(true, Ordering::Relaxed);
    responder.join().unwrap();

    assert_eq!(udp_scan_res.json["slave_count"], 2);
    assert_eq!(
        udp_scan_res.json["slaves"][0]["sii"]["name"],
        "EC-SERVO-402"
    );

    // 9. Adversarial & Beckhoff catalog regression checks:
    //    (a) Single-byte ETG.2010 VISIBLESTRING (CP1252/Latin-1) SII string encoding + 255-string clamp
    {
        use ethercat_eeprom::sii::image::SiiStringTable;
        let mut st = SiiStringTable::new();
        assert_eq!(st.intern("1µs"), 1);
        assert_eq!(st.intern("25°C"), 2);
        assert_eq!(st.intern("Präzision €"), 3);
        let body = st.encode_body();
        // body[0] = count (3), then len=3 [0x31, 0xB5, 0x73], len=4 [0x32, 0x35, 0xB0, 0x43], ...
        assert_eq!(&body[0..9], &[3, 3, 0x31, 0xB5, 0x73, 4, 0x32, 0x35, 0xB0]);
        assert_eq!(body[9], 0x43);
        assert!(body.contains(&0x80), "'€' must encode to CP1252 byte 0x80");

        for i in 0..260 {
            let _ = st.intern(&format!("S_{i:03}"));
        }
        assert_eq!(st.len(), 255);
        assert_eq!(st.intern("S_OVERFLOW"), 0);
    }

    //    (b) >255-bit PDO Entry (`<BitLen>512</BitLen>`), `<Fmmu>DynamicInputs</Fmmu>`, and `"1µs"` round-trip
    let adv_xml_path = tmp.join("adv_beckhoff_quirks.xml");
    std::fs::write(
        &adv_xml_path,
        r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>#x00000002</Id><Name>Beckhoff Automation GmbH</Name></Vendor>
  <Descriptions><Devices>
<Device Physics="YY">
  <Type ProductCode="#x10005250" RevisionNo="#x00100000">ATH-512-COE</Type>
  <Name LcId="1033">ATH2000 1µs Fast Capture</Name>
  <Fmmu>Outputs</Fmmu>
  <Fmmu>Inputs</Fmmu>
  <Fmmu>MBoxState</Fmmu>
  <Fmmu>DynamicInputs</Fmmu>
  <Fmmu>DynamicOutputs</Fmmu>
  <Sm StartAddress="#x1000" DefaultSize="128" ControlByte="#x26" Enable="1">MBoxOut</Sm>
  <Sm StartAddress="#x1080" DefaultSize="128" ControlByte="#x22" Enable="1">MBoxIn</Sm>
  <Sm StartAddress="#x1100" DefaultSize="64" ControlByte="#x20" Enable="1">Inputs</Sm>
  <TxPdo Fixed="1" Sm="2">
    <Index>#x1A00</Index>
    <Name>Oversized Array PDO</Name>
    <Entry>
      <Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>512</BitLen>
      <Name>Raw 64B Frame</Name><DataType>ARRAY [0..63] OF BYTE</DataType>
    </Entry>
  </TxPdo>
  <TxPdo Fixed="1" Sm="2" Su="1">
    <Index>#x1A01</Index>
    <Name>AI Standard </Name>
    <Entry>
      <Index>#x6001</Index><SubIndex>1</SubIndex><BitLen>8</BitLen>
      <Name>Status</Name><DataType>BYTE</DataType>
    </Entry>
    <Entry>
      <Index>#x6001</Index><SubIndex>2</SubIndex><BitLen>16</BitLen>
      <Name>Control</Name><DataType>WORD</DataType>
    </Entry>
  </TxPdo>
  <Mailbox DataLinkLayer="true"><CoE SdoInfo="true"/><SoE ChannelCount="1"/></Mailbox>
  <Dc>
    <OpMode>
      <Name>DcSync250</Name><Desc>250us</Desc>
      <AssignActivate>#x0300</AssignActivate>
      <CycleTimeSync0 Factor="1">250000</CycleTimeSync0>
      <ShiftTimeSync0>-115000</ShiftTimeSync0>
    </OpMode>
    <OpMode>
      <Name>DcSync125</Name><Desc>125us</Desc>
      <AssignActivate>#x0300</AssignActivate>
      <CycleTimeSync0 Factor="1">125000</CycleTimeSync0>
    </OpMode>
  </Dc>
  <Eeprom><ByteSize>2048</ByteSize><ConfigData>80030000000000</ConfigData></Eeprom>
</Device>
<Device Physics="YY">
  <Type ProductCode="#x10005251" RevisionNo="#x00100000">ATH-512-NOCOE</Type>
  <Name LcId="1033">Non-CoE 512b PDO</Name>
  <Sm StartAddress="#x1100" DefaultSize="64" ControlByte="#x20" Enable="1">Inputs</Sm>
  <TxPdo Fixed="1" Sm="0">
    <Index>#x1A00</Index>
    <Entry><Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>512</BitLen><DataType>ARRAY [0..63] OF BYTE</DataType></Entry>
  </TxPdo>
  <Eeprom><ByteSize>2048</ByteSize><ConfigData>80030000000000</ConfigData></Eeprom>
</Device>
  </Devices></Descriptions>
</EtherCATInfo>"##,
    )
    .unwrap();
    let adv_cat = load_esi_catalog(&adv_xml_path, 1033).unwrap();
    assert_eq!(adv_cat.devices.len(), 2);
    assert_eq!(adv_cat.devices[0].tx_pdos[0].entries[0].bit_len, 512);
    assert_eq!(adv_cat.devices[0].tx_pdos[1].su, 1);
    assert_eq!(adv_cat.devices[0].fmmus.len(), 5);
    assert_eq!(adv_cat.devices[0].fmmu_codes, vec![1, 2, 3]);
    assert_eq!(adv_cat.devices[0].dc_modes.len(), 2);
    let adv_sii =
        compile_esi_device_to_sii(&adv_cat.devices[0], &EsiCompileOptions::default()).unwrap();
    let adv_dec = inspect_sii_data(&adv_sii.bytes).unwrap();
    let adv_gen = adv_dec.categories.general.as_ref().unwrap();
    assert_eq!(
        adv_gen.device_name.as_deref(),
        Some("ATH2000 1µs Fast Capture")
    );
    assert_eq!(adv_gen.soe_channels, 0);
    assert_eq!(adv_dec.categories.fmmus.len(), 3);
    assert_eq!(
        adv_dec.categories.dc_modes.len(),
        1,
        "SSC profile selects only first <Dc><OpMode> matching ET9300Utilities"
    );
    assert_eq!(
        adv_dec.categories.dc_modes[0].shift_time_0_ns, 0,
        "SSC profile clamps negative ShiftTimeSync0 to 0 matching UInt32.TryParse"
    );
    assert_eq!(
        adv_dec.categories.tx_pdos.len(),
        1,
        "CoE slave must omit >255-bit PDO #x1A00 while keeping valid #x1A01"
    );
    assert_eq!(adv_dec.categories.tx_pdos[0].pdo_index_u16, 0x1A01);
    assert_eq!(
        adv_dec.categories.tx_pdos[0].name.as_deref(),
        Some("AI Standard "),
        "Trailing ASCII space in ESI <Name> must be preserved verbatim"
    );
    assert_eq!(
        adv_dec.categories.tx_pdos[0].dc_sync, 0,
        "TwinCAT Su attribute must not populate SII PDO Synchronization under SSC profile"
    );
    assert_eq!(adv_dec.categories.tx_pdos[0].entries[0].data_type, 0x1E);
    assert_eq!(
        adv_dec.categories.tx_pdos[0].entries[0].data_type_name,
        "BYTE"
    );
    assert_eq!(adv_dec.categories.tx_pdos[0].entries[1].data_type, 0x1F);
    assert_eq!(
        adv_dec.categories.tx_pdos[0].entries[1].data_type_name,
        "WORD"
    );
    let adv_min = inspect_sii_data(
        &compile_esi_device_to_sii(
            &adv_cat.devices[0],
            &EsiCompileOptions {
                profile: SiiBuildProfile::Minimal,
                ..Default::default()
            },
        )
        .unwrap()
        .bytes,
    )
    .unwrap();
    assert_eq!(adv_min.categories.general.as_ref().unwrap().soe_channels, 1);
    assert_eq!(adv_min.categories.dc_modes.len(), 2);
    assert_eq!(adv_min.categories.dc_modes[0].shift_time_0_ns, -115_000);
    let noncoe_ssc =
        compile_esi_device_to_sii(&adv_cat.devices[1], &EsiCompileOptions::default()).unwrap();
    assert!(
        inspect_sii_data(&noncoe_ssc.bytes)
            .unwrap()
            .categories
            .tx_pdos
            .is_empty(),
        "SSC profile omits >255-bit PDO even on non-CoE devices matching Beckhoff ATH2000-5250"
    );
    assert!(
        matches!(
            compile_esi_device_to_sii(
                &adv_cat.devices[1],
                &EsiCompileOptions {
                    profile: SiiBuildProfile::Minimal,
                    ..Default::default()
                }
            ),
            Err(CliError::Format(_))
        ),
        "Non-CoE Minimal profile with >255-bit PDO entry must fail instead of truncating BitLen"
    );

    //    (c) CoE slave with tight `<ByteSize>256</ByteSize>` drops optional PDO categories; non-CoE fails
    let tight_xml_path = tmp.join("tight_coe_256.xml");
    let mut many_entries = String::new();
    for idx in 1..=20 {
        many_entries.push_str(&format!(
            "<Entry><Index>#x6000</Index><SubIndex>{idx}</SubIndex><BitLen>8</BitLen><Name>E{idx}</Name><DataType>USINT</DataType></Entry>"
        ));
    }
    std::fs::write(
        &tight_xml_path,
        format!(
            r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id><Name>Beckhoff</Name></Vendor>
  <Descriptions><Devices>
<Device Physics="YY">
  <Type ProductCode="#x1111" RevisionNo="#x0001">TIGHT-COE</Type>
  <Name>Tight CoE</Name>
  <Fmmu>Outputs</Fmmu><Fmmu>Inputs</Fmmu>
  <Sm StartAddress="#x1000" DefaultSize="128" ControlByte="#x26" Enable="1">MBoxOut</Sm>
  <Sm StartAddress="#x1080" DefaultSize="128" ControlByte="#x22" Enable="1">MBoxIn</Sm>
  <Sm StartAddress="#x1100" DefaultSize="20" ControlByte="#x20" Enable="1">Inputs</Sm>
  <TxPdo Fixed="1" Sm="2"><Index>#x1A00</Index><Name>BigTx</Name>{many_entries}</TxPdo>
  <Mailbox DataLinkLayer="true"><CoE SdoInfo="true"/></Mailbox>
  <Eeprom><ByteSize>256</ByteSize><ConfigData>80030000000000</ConfigData></Eeprom>
</Device>
<Device Physics="YY">
  <Type ProductCode="#x1112" RevisionNo="#x0001">TIGHT-NOCOE</Type>
  <Name>Tight NoCoE</Name>
  <Sm StartAddress="#x1100" DefaultSize="20" ControlByte="#x20" Enable="1">Inputs</Sm>
  <TxPdo Fixed="1" Sm="0"><Index>#x1A00</Index><Name>BigTx</Name>{many_entries}</TxPdo>
  <Eeprom><ByteSize>256</ByteSize><ConfigData>80030000000000</ConfigData></Eeprom>
</Device>
  </Devices></Descriptions>
</EtherCATInfo>"##
        ),
    )
    .unwrap();
    let tight_cat = load_esi_catalog(&tight_xml_path, 1033).unwrap();
    let tight_coe_sii =
        compile_esi_device_to_sii(&tight_cat.devices[0], &EsiCompileOptions::default()).unwrap();
    assert_eq!(tight_coe_sii.bytes.len(), 256);
    assert!(inspect_sii_data(&tight_coe_sii.bytes)
        .unwrap()
        .categories
        .tx_pdos
        .is_empty());
    assert!(matches!(
        compile_esi_device_to_sii(&tight_cat.devices[1], &EsiCompileOptions::default()),
        Err(CliError::Format(_))
    ));

    //    (d) Deeply nested XML depth guard + BOM-less UTF-16BE + non-.xml `--file` auto-detection + `--slave 0`
    {
        use ethercat_eeprom::esi::xml::{parse_xml_bytes, parse_xml_str};
        let deep_xml = format!("{}{}", "<a>".repeat(200), "</a>".repeat(200));
        assert!(matches!(parse_xml_str(&deep_xml), Err(CliError::Format(_))));

        let mut utf16be_no_bom = Vec::new();
        for u in "  \n<EtherCATInfo><Vendor><Id>2</Id></Vendor></EtherCATInfo>".encode_utf16() {
            utf16be_no_bom.extend_from_slice(&u.to_be_bytes());
        }
        let root_be = parse_xml_bytes(&utf16be_no_bom).unwrap();
        assert_eq!(root_be.name, "EtherCATInfo");

        let esi_ext_path = sub_dir.join("el1008_custom.esi");
        std::fs::copy(&utf16_path, &esi_ext_path).unwrap();
        let auto_write_dry_cli = Cli::try_parse_from([
            "ethercat-cli",
            "-i",
            "sim",
            "sii",
            "write",
            "--slave",
            "1",
            "--file",
            esi_ext_path.to_str().unwrap(),
            "--device",
            "0",
        ])
        .unwrap();
        assert_eq!(
            execute_cli(&auto_write_dry_cli).unwrap().json["source_kind"],
            "esi_xml"
        );

        for bad_sii_zero in [
            vec![
                "ethercat-cli",
                "-i",
                "nonexistent_iface",
                "sii",
                "read",
                "--slave",
                "0",
            ],
            vec![
                "ethercat-cli",
                "-i",
                "nonexistent_iface",
                "sii",
                "inspect",
                "--slave",
                "0",
            ],
            vec![
                "ethercat-cli",
                "-i",
                "nonexistent_iface",
                "sii",
                "verify",
                "--slave",
                "0",
                "--file",
                out_bin.to_str().unwrap(),
            ],
            vec![
                "ethercat-cli",
                "-i",
                "nonexistent_iface",
                "sii",
                "write",
                "--slave",
                "0",
                "--file",
                out_bin.to_str().unwrap(),
            ],
        ] {
            let parsed_zero = Cli::try_parse_from(bad_sii_zero).unwrap();
            assert!(matches!(execute_cli(&parsed_zero), Err(CliError::Usage(_))));
        }
    }

    //    (e) UDP frame extraction edge cases (ARP rejection + IPv4/UDP 34980 unwrap) & noise/stale-idx resilience
    {
        // Non-EtherCAT ARP frame (0x0806) must be rejected by extract_udp_ecat_payload
        let mut arp_frame = vec![0u8; 60];
        arp_frame[0..6].fill(0xFF);
        arp_frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert!(matches!(
            extract_udp_ecat_payload(&arp_frame),
            Err(CliError::Format(_))
        ));

        // Ethernet + IPv4 + UDP (dst port 34980) frame must unwrap to bare EtherCAT DLPDU
        let mut fb = EcatFrameBuilder::new();
        fb.add_datagram(RawDatagram::new_positioned(
            EcatCmd::Brd,
            0x55,
            0,
            0x0130,
            vec![0, 0],
        ));
        let eth_ecat = fb.build().unwrap();
        let bare_dlpdu = extract_udp_ecat_payload(&eth_ecat).unwrap().to_vec();
        let udp_total_len = (8 + bare_dlpdu.len()) as u16;
        let ip_total_len = 20 + udp_total_len;
        let mut ipv4_udp_frame = Vec::new();
        ipv4_udp_frame.extend_from_slice(&[0xFF; 6]);
        ipv4_udp_frame.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        ipv4_udp_frame.extend_from_slice(&0x0800u16.to_be_bytes());
        // Minimal 20B IPv4 header (ver=4, ihl=5, proto=17)
        let mut ip_hdr = [0u8; 20];
        ip_hdr[0] = 0x45;
        ip_hdr[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
        ip_hdr[8] = 64;
        ip_hdr[9] = 17;
        ipv4_udp_frame.extend_from_slice(&ip_hdr);
        // 8B UDP header (src=34980, dst=34980)
        ipv4_udp_frame.extend_from_slice(&34980u16.to_be_bytes());
        ipv4_udp_frame.extend_from_slice(&34980u16.to_be_bytes());
        ipv4_udp_frame.extend_from_slice(&udp_total_len.to_be_bytes());
        ipv4_udp_frame.extend_from_slice(&0u16.to_be_bytes());
        ipv4_udp_frame.extend_from_slice(&bare_dlpdu);
        ipv4_udp_frame.extend_from_slice(&[0u8; 8]); // trailing Ethernet pad
        assert_eq!(
            extract_udp_ecat_payload(&ipv4_udp_frame).unwrap(),
            bare_dlpdu.as_slice()
        );

        // Noisy UDP responder sending 1-byte noise, 2-byte short DLPDU, and wrong-idx DLPDU before real reply
        let noisy_srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let noisy_addr = noisy_srv.local_addr().unwrap();
        let noisy_handle = std::thread::spawn(move || {
            let mut gw_sim = SimulatedBusTransport::open("sim").unwrap();
            let mut rx_buf = [0u8; 2048];
            let (n, peer) = noisy_srv.recv_from(&mut rx_buf).unwrap();
            // 1) 1-byte noise (< 2B header)
            noisy_srv.send_to(&[0xFF], peer).unwrap();
            // 2) 2-byte header-only DLPDU (shorter than idx_pos!)
            noisy_srv.send_to(&[0x00, 0x10], peer).unwrap();
            // 3) Stale wrong-idx DLPDU
            let mut stale = rx_buf[..n].to_vec();
            stale[3] = stale[3].wrapping_add(1);
            noisy_srv.send_to(&stale, peer).unwrap();
            // 4) Valid processed response with matching idx and WKC=2
            let eth_req = wrap_udp_ecat_payload(&rx_buf[..n]).unwrap();
            let eth_resp = gw_sim
                .transact_frame(&eth_req, None, Duration::from_millis(100))
                .unwrap();
            let udp_resp = extract_udp_ecat_payload(&eth_resp).unwrap();
            noisy_srv.send_to(udp_resp, peer).unwrap();
        });

        let mut noisy_client =
            UdpEcatTransport::open(&format!("udp://127.0.0.1@{noisy_addr}")).unwrap();
        let rx_valid = noisy_client
            .transact_frame(&eth_ecat, Some(0x55), Duration::from_millis(500))
            .unwrap();
        noisy_handle.join().unwrap();
        let rx_dgs = parse_dlpdu_datagrams(&rx_valid).unwrap();
        assert_eq!(rx_dgs[0].idx, 0x55);
        assert_eq!(rx_dgs[0].wkc, 2);

        // Self-broadcast echo filter: bind on loopback port P targeting broadcast `127.255.255.255:P`
        let bcast_client = UdpEcatTransport::open("udp://127.0.0.1:0@127.255.255.255:9").unwrap();
        let bcast_port = bcast_client.local_addr().unwrap().port();
        drop(bcast_client);
        let mut bcast_self = UdpEcatTransport::open(&format!(
            "udp://127.0.0.1:{bcast_port}@127.255.255.255:{bcast_port}"
        ))
        .unwrap();
        // With no slave responder, self-broadcast loopback echo must be ignored and time out cleanly!
        let self_echo_res =
            bcast_self.transact_frame(&eth_ecat, Some(0x55), Duration::from_millis(40));
        assert!(
            matches!(self_echo_res, Err(CliError::Device(_))),
            "Self-broadcast loopback echo must not be accepted as a slave response"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn ssc_pure_rust_end_to_end_smoke() {
    use crate::cli::{SscGenerateArgs, SscOdGenerateArgs};
    let tmp = std::env::temp_dir().join(format!("ethercat-cli-ssc-smoke-{}", unique_temp_id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    // 1. Standalone OD wizard template (.csv & .xlsx) + standalone `ssc od generate`
    let csv_tpl = tmp.join("DemoApp.csv");
    let xlsx_tpl = tmp.join("DemoApp.xlsx");
    handle_ssc(&SscSubcommand::Od(SscOdSubcommand::Template {
        output: csv_tpl.clone(),
        kind: Some(SscTemplateKind::Csv),
    }))
    .expect("generate csv OD template");
    handle_ssc(&SscSubcommand::Od(SscOdSubcommand::Template {
        output: xlsx_tpl.clone(),
        kind: Some(SscTemplateKind::Xlsx),
    }))
    .expect("generate xlsx OD template");
    assert!(csv_tpl.is_file() && xlsx_tpl.is_file());

    // Append TxPDO (0x6000) and RxPDO (0x7000) to CSV template to exercise auto-PDO & SM assignment
    let mut rich_csv = std::fs::read_to_string(&csv_tpl).unwrap();
    rich_csv.push_str(
        "\r\n0x6000;VAR;0;UINT16;SensorValue;0x1234;m;;ro;tx;;;\r\n\
         0x7000;VAR;0;UINT16;ActuatorTarget;0x0000;m;;rw;rx;;;\r\n",
    );
    std::fs::write(&csv_tpl, rich_csv).unwrap();

    let od_out_src = tmp.join("od_src");
    let od_offline_xml = tmp.join("od_out").join("DemoAppObjects.xml");
    let od_rep = handle_ssc(&SscSubcommand::Od(SscOdSubcommand::Generate(
        SscOdGenerateArgs {
            inputs: vec![csv_tpl.clone()],
            worksheet: None,
            src_dir: Some(od_out_src.clone()),
            esi: None,
            offline_xml: Some(od_offline_xml.clone()),
            device_index: 0,
            overwrite_app: false,
        },
    )))
    .expect("standalone ssc od generate from csv");
    assert!(od_rep.json["object_count"].as_u64().unwrap_or(0) >= 5);
    assert!(od_offline_xml.is_file());
    let offline_str = std::fs::read_to_string(&od_offline_xml).unwrap();
    assert!(offline_str.contains("<EtherCATDict"));

    // 2. `ssc image-hex` on synthetic 16x14 24-bit BMP
    let bmp_path = tmp.join("icon16x14.bmp");
    let mut bmp = vec![0u8; 54 + 48 * 14];
    bmp[0..2].copy_from_slice(b"BM");
    let file_len = bmp.len() as u32;
    bmp[2..6].copy_from_slice(&file_len.to_le_bytes());
    bmp[10..14].copy_from_slice(&54u32.to_le_bytes());
    bmp[14..18].copy_from_slice(&40u32.to_le_bytes());
    bmp[18..22].copy_from_slice(&16i32.to_le_bytes());
    bmp[22..26].copy_from_slice(&14i32.to_le_bytes());
    bmp[26..28].copy_from_slice(&1u16.to_le_bytes());
    bmp[28..30].copy_from_slice(&24u16.to_le_bytes());
    std::fs::write(&bmp_path, &bmp).unwrap();
    let img_rep = handle_ssc(&SscSubcommand::ImageHex {
        image: bmp_path.clone(),
    })
    .expect("encode 16x14 bmp hex");
    assert!(img_rep.text.starts_with("424D"));

    // 3. `ssc patch` on synthetic C source with Doxygen `\version 5.13`
    let patch_dir = tmp.join("patch_src");
    std::fs::create_dir_all(&patch_dir).unwrap();
    let target_c = patch_dir.join("ecatslv.c");
    std::fs::write(
        &target_c,
        "/**\r\n * \\version 5.13\r\n */\r\nint status = 0;\r\n",
    )
    .unwrap();
    let patch_file = tmp.join("hotfix.patch");
    std::fs::write(
        &patch_file,
        "--- a/ecatslv.c\r\n+++ b/ecatslv.c\r\n@@ -4,1 +4,1 @@\r\n-int status = 0;\r\n+int status = 1;\r\n",
    )
    .unwrap();
    handle_ssc(&SscSubcommand::Patch {
        patch: patch_file.clone(),
        src_dir: patch_dir.clone(),
    })
    .expect("apply ssc unified patch");
    let patched_c = std::fs::read_to_string(&target_c).unwrap();
    assert!(patched_c.contains("\\version 5.13.1"));
    assert!(patched_c.contains("int status = 1;"));

    // 4. Synthetic minimal SSC configuration + `src/sample.c` -> `ssc generate`, `list-defines`, `check`, `export-config`, `import-header`, `update-esi`
    let ssc_root = tmp.join("synthetic_ssc");
    let ssc_cfg_dir = ssc_root.join("cfg");
    let ssc_src_dir = ssc_root.join("src");
    std::fs::create_dir_all(&ssc_cfg_dir).unwrap();
    std::fs::create_dir_all(&ssc_src_dir).unwrap();
    std::fs::write(
        ssc_src_dir.join("sample.c"),
        "/* sample */\r\n#if COE_SUPPORTED\r\nint coe_enabled = 1;\r\n#else\r\nint coe_enabled = 0;\r\n#endif\r\n/*CODE_INSERT_START (EEPROM_FILE)*/\r\n/*CODE_INSERT_END*/\r\n",
    )
    .unwrap();

    let cfg_xml = r##"<?xml version="1.0" encoding="utf-8"?>
<SlaveCodeConfigurations ToolVersion="1.5.3.0" SSCVersion="5.13">
  <Settings>
<Setting CodeDefine="VENDOR_ID" ValueType="hex" Value="0xE0000002" FileArea="Device">Vendor ID</Setting>
<Setting CodeDefine="VENDOR_NAME" ValueType="string" Value="Synthetic Vendor" FileArea="Device">Vendor Name</Setting>
<Setting CodeDefine="GROUP_NAME" ValueType="string" Value="Controllers" FileArea="Device">Group Name</Setting>
<Setting CodeDefine="DEVICE_NAME" ValueType="string" Value="SynthSlave" FileArea="Device">Device Name</Setting>
<Setting CodeDefine="PRODUCT_CODE" ValueType="hex" Value="0x00001001" FileArea="Device">Product Code</Setting>
<Setting CodeDefine="REVISION_NUMBER" ValueType="hex" Value="0x00010000" FileArea="Device">Revision</Setting>
<Setting CodeDefine="SERIAL_NUMBER" ValueType="hex" Value="0x00000000" FileArea="Device">Serial</Setting>
<Setting CodeDefine="DEVICE_HW_VERSION" ValueType="string" Value="1.0" FileArea="Device">HW Version</Setting>
<Setting CodeDefine="DEVICE_SW_VERSION" ValueType="string" Value="5.13" FileArea="Device">SW Version</Setting>
<Setting CodeDefine="ESC_EEPROM_SIZE" ValueType="hex" Value="0x800" FileArea="Hardware">EEPROM Size</Setting>
<Setting CodeDefine="CREATE_EEPROM_CONTENT" ValueType="bool" Value="0" FileArea="Hardware"><Flags Evaluate="True" /></Setting>
<Setting CodeDefine="EEPROM_FILE" ValueType="block"><DefaultValues default=""><Value Expression="CREATE_EEPROM_CONTENT" Value="#include &quot;eeprom.h&quot;" /></DefaultValues><Flags ReadOnly="True" Visible="False" Evaluate="True" /></Setting>
<Setting CodeDefine="MAILBOX_SUPPORTED" ValueType="bool" Value="1" FileArea="Mailbox"><Flags Evaluate="True" /></Setting>
<Setting CodeDefine="COE_SUPPORTED" ValueType="bool" Value="1" FileArea="CoE"><Flags Evaluate="True" /></Setting>
<Setting CodeDefine="MIN_MBX_SIZE" ValueType="hex" Value="0x0022" FileArea="Mailbox">Min Mbx</Setting>
<Setting CodeDefine="DEF_MBX_SIZE" ValueType="hex" Value="0x0080" FileArea="Mailbox">Def Mbx</Setting>
<Setting CodeDefine="MAX_MBX_SIZE" ValueType="hex" Value="0x0100" FileArea="Mailbox">Max Mbx</Setting>
<Setting CodeDefine="DEF_MBX_WRITE_ADDRESS" ValueType="hex" Value="0x1000" FileArea="Mailbox">Mbx Write Addr</Setting>
<Setting CodeDefine="DEF_MBX_READ_ADDRESS" ValueType="hex" Value="0x1100" FileArea="Mailbox">Mbx Read Addr</Setting>
<Setting CodeDefine="MIN_PD_WRITE_ADDRESS" ValueType="hex" Value="0x1200" FileArea="ProcessData">PD Write Addr</Setting>
<Setting CodeDefine="DEF_PD_READ_ADDRESS" ValueType="hex" Value="0x1400" FileArea="ProcessData">PD Read Addr</Setting>
<Setting CodeDefine="SAMPLE_APPLICATION" ValueType="bool" Value="1" FileArea="Application"><Flags Evaluate="True" /></Setting>
  </Settings>
  <Files>
<File Name="sample.c" Type="source" />
  </Files>
  <SettingConflicts>
<SettingConflict Type="error" Define="COE_SUPPORTED" LinkedExpression="&amp;&amp; !MAILBOX_SUPPORTED">CoE requires Mailbox</SettingConflict>
  </SettingConflicts>
</SlaveCodeConfigurations>"##;
    let cfg_file = ssc_cfg_dir.join("SlaveConfigFile.xml");
    std::fs::write(&cfg_file, cfg_xml).unwrap();

    let gen_out = tmp.join("gen_project");
    let sii_bin = gen_out.join("synth.bin");
    handle_ssc(&SscSubcommand::Generate(SscGenerateArgs {
        project: Some(cfg_file.clone()),
        ssc_dir: Some(ssc_root.clone()),
        output: Some(gen_out.clone()),
        src_dir: None,
        name: Some("SynthProj".to_string()),
        app: vec![],
        config: None,
        config_name: None,
        allow_file_import: false,
        patch: None,
        defines: vec![("CREATE_EEPROM_CONTENT".to_string(), "1".to_string())],
        use_gui_options: false,
        options_file: None,
        raw_files: false,
        delete_comments: false,
        no_esp: false,
        no_esi: false,
        sii_out: Some(sii_bin.clone()),
        strict_conflicts: true,
        ignore_errors: false,
    }))
    .expect("generate synthetic SSC project");

    let esp_out = gen_out.join("SynthProj.esp");
    let esi_out = gen_out.join("SynthProj.xml");
    let ecat_def_out = gen_out.join("src").join("ecat_def.h");
    let eeprom_h_out = gen_out.join("src").join("eeprom.h");
    let sample_c_out = gen_out.join("src").join("sample.c");
    assert!(esp_out.is_file() && esi_out.is_file() && ecat_def_out.is_file());
    assert!(eeprom_h_out.is_file() && sii_bin.is_file() && sample_c_out.is_file());
    sii_validate(&std::fs::read(&sii_bin).unwrap()).expect("compiled SII from SSC ESI valid");
    let gen_sample = std::fs::read_to_string(&sample_c_out).unwrap();
    assert!(gen_sample.contains("int coe_enabled = 1;") && !gen_sample.contains("coe_enabled = 0"));
    assert!(gen_sample.contains("#include \"eeprom.h\""));

    let defs_rep = handle_ssc(&SscSubcommand::ListDefines {
        project: Some(esp_out.clone()),
        ssc_dir: None,
        config: None,
        config_name: None,
        all: true,
        filter: Some("MBX".to_string()),
    })
    .expect("list-defines on .esp");
    assert!(defs_rep.json["count"].as_u64().unwrap_or(0) >= 3);

    let chk_rep = handle_ssc(&SscSubcommand::Check {
        project: Some(esp_out.clone()),
        ssc_dir: None,
        defines: vec![("MAILBOX_SUPPORTED".to_string(), "0".to_string())],
        issues_xml: None,
    })
    .expect("check setting conflicts");
    assert_eq!(
        chk_rep.json["active_conflicts"].as_array().unwrap().len(),
        1
    );

    let exported_cfg = tmp.join("exported_cfg.xml");
    handle_ssc(&SscSubcommand::ExportConfig {
        project: Some(esp_out.clone()),
        ssc_dir: None,
        defines: vec![("PRODUCT_CODE".to_string(), "0x00002222".to_string())],
        name: "CustomCfg".to_string(),
        info: "Test export".to_string(),
        output: exported_cfg.clone(),
    })
    .expect("export-config");
    assert!(exported_cfg.is_file());

    let imported_esp = tmp.join("imported_from_h.esp");
    handle_ssc(&SscSubcommand::ImportHeader {
        header: ecat_def_out.clone(),
        project: Some(cfg_file.clone()),
        ssc_dir: Some(ssc_root.clone()),
        output: imported_esp.clone(),
        ignore_errors: true,
    })
    .expect("import-header from ecat_def.h");
    assert!(imported_esp.is_file());

    handle_ssc(&SscSubcommand::UpdateEsi {
        esi: esi_out.clone(),
        od: vec![xlsx_tpl.clone()],
        device_index: 0,
    })
    .expect("update-esi in place");
    assert!(gen_out.join("SynthProj.xml.bak").is_file());

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn hardened_optimizations_and_edge_cases_regression() {
    use crate::cli::SscOdGenerateArgs;
    use ethercat_ssc::model::SlaveProject;
    use ethercat_ssc::od::builtin_ods::build_project_object_dictionary;
    use ethercat_ssc::od::types::resolve_data_type_name;
    use ethercat_wire::protocol::dissector::may_contain_ethercat;
    use ethercat_wire::types::{insert_bits_le, parse_u16, parse_u64};

    // 1. ETG.2000 `#x` / `#X` hex literals + BITARR / DWORD CoE types + bit-slice fast paths & overflow guards
    assert_eq!(parse_u64("#x1A2B_3C4D").unwrap(), 0x1A2B_3C4D);
    assert_eq!(parse_u16("#X1018").unwrap(), 0x1018);
    assert_eq!(
        DataTypeSpec::from_coe_datatype(0x001E, 8),
        Some(DataTypeSpec::U8)
    );
    assert_eq!(
        DataTypeSpec::from_coe_datatype(0x0020, 32),
        Some(DataTypeSpec::U32)
    );
    assert_eq!(
        DataTypeSpec::from_coe_datatype(0x002E, 16),
        Some(DataTypeSpec::U16)
    );
    assert_eq!(
        DataTypeSpec::parse_name("dword").unwrap(),
        DataTypeSpec::U32
    );
    assert_eq!(
        encode_typed_value("#xDEADBEEF", DataTypeSpec::U32).unwrap(),
        vec![0xEF, 0xBE, 0xAD, 0xDE]
    );
    assert_eq!(
        decode_typed_value(&[], DataTypeSpec::Auto, None).unwrap(),
        json!(null)
    );

    let mut bit_buf = vec![0x11, 0x22, 0x33, 0x44];
    insert_bits_le(&mut bit_buf, 8, 16, &[0xAB, 0xCD]).unwrap();
    assert_eq!(bit_buf, vec![0x11, 0xAB, 0xCD, 0x44]);
    let sliced = extract_bits_le(&bit_buf, 8, 16).unwrap();
    assert_eq!(sliced, vec![0xAB, 0xCD]);
    assert!(matches!(
        extract_bits_le(&[1, 2], usize::MAX, 8),
        Err(CliError::Format(_))
    ));

    // 2. Stacked QinQ VLAN (0x88A8 outer + 0x8100 inner + 0x88A4 EtherCAT) in dissector, pre-filter & sim
    let mut base_builder = EcatFrameBuilder::new();
    base_builder.add_datagram(RawDatagram::new_positioned(
        EcatCmd::Brd,
        0x09,
        0,
        0x0130,
        vec![0, 0],
    ));
    let base_eth = base_builder.build().unwrap();
    let mut qinq = Vec::new();
    qinq.extend_from_slice(&[0xFF; 6]);
    qinq.extend_from_slice(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    qinq.extend_from_slice(&0x88A8u16.to_be_bytes());
    qinq.extend_from_slice(&0x0064u16.to_be_bytes());
    qinq.extend_from_slice(&0x8100u16.to_be_bytes());
    qinq.extend_from_slice(&0x00C8u16.to_be_bytes());
    qinq.extend_from_slice(&base_eth[12..]); // 0x88A4 + ecatf header + DLPDU
    if qinq.len() < 60 {
        qinq.resize(60, 0);
    }
    assert!(may_contain_ethercat(&qinq, false));
    let qinq_df = dissect_frame(&qinq, &DissectOptions::default()).unwrap();
    assert_eq!(qinq_df.datagrams.len(), 1);
    let mut sim_bus = open_transport("sim", false).unwrap();
    let qinq_rx = sim_bus
        .transact_frame(&qinq, Some(0x09), Duration::from_millis(100))
        .unwrap();
    let qinq_rx_df = dissect_frame(&qinq_rx, &DissectOptions::default()).unwrap();
    assert_eq!(qinq_rx_df.datagrams[0].wkc, 2);

    // 3. PktMon / hexdump trailing ASCII column must NOT corrupt parsed hex bytes
    let tmp_hex = std::env::temp_dir().join(format!("ecat-hex-ascii-{}.txt", unique_temp_id()));
    let mut std_builder = EcatFrameBuilder::new();
    std_builder.add_datagram(RawDatagram::new_positioned(
        EcatCmd::Brd,
        1,
        0,
        0x0130,
        vec![0x01, 0x00],
    ));
    let mut std_eth = std_builder.build().unwrap();
    std_eth.truncate(30); // unpadded exact 30-byte frame (14 eth + 2 ecatf + 14 dg)
    let mut hex_dump = String::new();
    for (chunk_idx, chunk) in std_eth.chunks(16).enumerate() {
        let hex_cols: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
        // Deliberately place valid hex tokens ("dead", "EC", "0000") in trailing ASCII dump column!
        hex_dump.push_str(&format!(
            "0x{:04x}: {:<47}  deadEC0000beef\n",
            chunk_idx * 16,
            hex_cols.join(" ")
        ));
    }
    std::fs::write(&tmp_hex, hex_dump).unwrap();
    let auto_recs = load_frames_from_file(&tmp_hex, FrameInputKind::Auto, 5).unwrap();
    let hex_recs = load_frames_from_file(&tmp_hex, FrameInputKind::Hex, 5).unwrap();
    let _ = std::fs::remove_file(&tmp_hex);
    assert_eq!(auto_recs.len(), 1);
    assert_eq!(auto_recs[0].data, std_eth);
    assert_eq!(hex_recs.len(), 1);
    assert_eq!(hex_recs[0].data, std_eth);

    // 4. SimulatedBusTransport: unknown URI option rejection, SDO Complete Access subindex>=2 rejection,
    //    SDO Info OD browse, and partial FMMU sub-range logical LRW/LRD
    assert!(open_transport("sim://unknown_key=1", false).is_err());

    let timeout = Duration::from_millis(200);
    scan_bus(&mut *sim_bus, true, true, timeout).unwrap();
    write_al_state(&mut *sim_bus, 1, AlStateSpec::PreOp, true, false, timeout).unwrap();

    // SDO Complete Access with subindex = 2 must return CliError::Usage
    let bad_ca = sdo_read(
        &mut *sim_bus,
        &SdoReadParams {
            slave: 1,
            index: 0x1018,
            subindex: 2,
            complete_access: true,
            ty: DataTypeSpec::Hex,
            bit_offset: None,
            bit_length: None,
            auto_preop: false,
            timeout,
        },
    );
    assert!(matches!(bad_ca, Err(CliError::Usage(_))));

    let od_all = query_od_info(&mut *sim_bus, 1, None, true, false, timeout).unwrap();
    assert!(!od_all.is_empty());

    // Partial FMMU logical window: map 4 bytes at 0x0001_0000, then LRW 2 bytes at 0x0001_0001
    write_al_state(&mut *sim_bus, 1, AlStateSpec::SafeOp, false, false, timeout).unwrap();
    write_al_state(&mut *sim_bus, 1, AlStateSpec::Op, false, false, timeout).unwrap();
    let mut fmmu0 = [0u8; 16];
    fmmu0[0..4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fmmu0[4..6].copy_from_slice(&4u16.to_le_bytes());
    fmmu0[7] = 7; // end bit
    fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes()); // RxPDO physical SM2
    fmmu0[11] = 0x02; // write enable
    fmmu0[12] = 0x01; // FMMU enable
    let fmmu_hex = format_hex(&fmmu0);
    write_esc_register(
        Some(&mut *sim_bus),
        &RegWriteParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "0x0600",
            value_str: &fmmu_hex,
            ty: DataTypeSpec::Hex,
            dry_run: false,
            timeout,
        },
    )
    .unwrap();
    let partial_lrw = Cli::try_parse_from([
        "ethercat-cli",
        "-i",
        "sim",
        "-f",
        "value",
        "datagram",
        "--cmd",
        "lrw",
        "--logical-addr",
        "#x00010000",
        "--data",
        "1122",
        "--bit-offset",
        "4",
        "--bit-length",
        "8",
    ])
    .unwrap();
    let dg_rep = execute_cli(&partial_lrw).unwrap();
    let dg_sel = apply_field_selectors(&dg_rep.json, &["value".to_string()]).unwrap();
    assert!(!dg_sel.is_null());

    // Also verify partial FMMU write on already-configured `sim_bus` directly at offset +1 inside 4-byte FMMU
    let mut sub_builder = EcatFrameBuilder::new();
    sub_builder.add_datagram(RawDatagram::new_logical(
        EcatCmd::Lrw,
        0x21,
        0x0001_0001,
        vec![0xAA, 0xBB],
    ));
    let tx_sub = sub_builder.build().unwrap();
    let rx_sub = sim_bus
        .transact_frame(&tx_sub, Some(0x21), timeout)
        .unwrap();
    let sub_df = dissect_frame(&rx_sub, &DissectOptions::default()).unwrap();
    assert_eq!(sub_df.datagrams[0].wkc, 2); // write WKC weight = 2 for LRW write-only FMMU
    let sm2_readback = read_esc_register(
        &mut *sim_bus,
        &RegReadParams {
            slave: Some(1),
            config_addr: None,
            broadcast: false,
            reg_spec: "0x1100",
            length: Some(4),
            ty: DataTypeSpec::Hex,
            bit_offset: None,
            bit_length: None,
            timeout,
        },
    )
    .unwrap();
    assert_eq!(&sm2_readback.raw_hex[2..6], "aabb");

    // 5. Factory-blank (all 0xFF) EEPROM recovery via guarded `sii write`
    let tmp_blank = std::env::temp_dir().join(format!("ecat-blank-{}.bin", unique_temp_id()));
    let tmp_blank_bak =
        std::env::temp_dir().join(format!("ecat-blank-bak-{}.bin", unique_temp_id()));
    std::fs::write(&tmp_blank, vec![0xFFu8; 256]).unwrap();
    let _ = std::fs::remove_file(&tmp_blank_bak);
    let valid_sii = ethercat_master::sim::build_servo_402_sii();
    let mut blank_bus =
        open_transport(&format!("sim://eeprom={}", tmp_blank.display()), false).unwrap();
    let rec_rep = write_device_sii_guarded(
        &mut *blank_bus,
        &GuardedSiiWriteOptions {
            slave: 1,
            proposed: &valid_sii,
            execute: true,
            backup_path: Some(&tmp_blank_bak),
            confirm_token: Some("WRITE-SLAVE-1"),
            reload: true,
            timeout,
        },
    )
    .expect("factory-blank 0xFF EEPROM recovery must succeed");
    assert!(rec_rep.executed && rec_rep.verified);
    assert!(std::fs::read(&tmp_blank_bak)
        .unwrap()
        .iter()
        .all(|&b| b == 0xFF));
    let _ = std::fs::remove_file(&tmp_blank);
    let _ = std::fs::remove_file(&tmp_blank_bak);

    // 6. Non-ASCII UTF-8 safety in SSC + numeric SSC version "10.0" >= "4.42" + missing explicit --esi rejection
    assert!(resolve_data_type_name("äöü").is_err());
    assert!(resolve_data_type_name("äöü12345").is_err());
    let v10_cfg = std::env::temp_dir().join(format!("ssc-v10-{}.xml", unique_temp_id()));
    std::fs::write(
        &v10_cfg,
        r#"<?xml version="1.0" encoding="utf-8"?><SlaveCodeConfigurations ToolVersion="1.5.3.0" SSCVersion="10.0"><Settings/></SlaveCodeConfigurations>"#,
    )
    .unwrap();
    let proj_v10 = SlaveProject::load(Some(&v10_cfg), None).unwrap();
    let _ = std::fs::remove_file(&v10_cfg);
    build_project_object_dictionary(&proj_v10, None)
        .expect("numeric SSC version 10.0 must be accepted as >= 4.42");

    let missing_esi_path =
        std::env::temp_dir().join(format!("nonexistent-esi-{}.xml", unique_temp_id()));
    let csv_tmp = std::env::temp_dir().join(format!("od-miss-{}.csv", unique_temp_id()));
    handle_ssc(&SscSubcommand::Od(SscOdSubcommand::Template {
        output: csv_tmp.clone(),
        kind: Some(SscTemplateKind::Csv),
    }))
    .unwrap();
    let missing_esi_res = handle_ssc(&SscSubcommand::Od(SscOdSubcommand::Generate(
        SscOdGenerateArgs {
            inputs: vec![csv_tmp.clone()],
            worksheet: None,
            src_dir: None,
            esi: Some(missing_esi_path),
            offline_xml: None,
            device_index: 0,
            overwrite_app: false,
        },
    )));
    let _ = std::fs::remove_file(&csv_tmp);
    assert!(
        missing_esi_res.is_err(),
        "non-existent explicit --esi path must return an error"
    );

    // 7. New selectors (`[0].name` on array/object root, `fields --category codes` & `ssc`)
    let adapters_cli = Cli::try_parse_from(["ethercat-cli", "adapters"]).unwrap();
    let adapters_rep = execute_cli(&adapters_cli).unwrap();
    let first_name = apply_field_selectors(&adapters_rep.json, &["[0].name".to_string()]).unwrap();
    assert!(!first_name["[0].name"].as_str().unwrap_or("").is_empty());

    let codes_cli = Cli::try_parse_from(["ethercat-cli", "fields", "--category", "codes"]).unwrap();
    let codes_rep = execute_cli(&codes_cli).unwrap();
    assert!(codes_rep.text.contains("AL Status Codes"));
    assert!(!codes_rep.json["protocol_codes"]["al_status_codes"]
        .as_array()
        .unwrap()
        .is_empty());

    let ssc_fields_cli =
        Cli::try_parse_from(["ethercat-cli", "fields", "--category", "ssc"]).unwrap();
    let ssc_fields_rep = execute_cli(&ssc_fields_cli).unwrap();
    assert!(ssc_fields_rep.text.contains("ssc."));
    assert!(!ssc_fields_rep.json["wireshark_selectors"]
        .as_array()
        .unwrap()
        .is_empty());
}
