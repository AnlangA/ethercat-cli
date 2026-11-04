use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ethercat_dissector::{
    dissect_capture_file, dissect_frame, DissectOptions, DissectSession, XmlCatalog,
    ECAT_FRAME_TYPE_ADS, ECAT_FRAME_TYPE_MAILBOX, ECAT_FRAME_TYPE_RAW_IO, ESL_SIGNATURE,
    TCP_PORT_AMS, TCP_PORT_ECAT, UDP_PORT_AMS, WIRESHARK_PROTOCOLS,
};
use ethercat_wire::protocol::constants::{
    EcatCmd, ECAT_FRAME_TYPE_DLPDU, ECAT_FRAME_TYPE_NV, ETH_P_ECAT, UDP_PORT_ECAT,
};
use ethercat_wire::protocol::frame::{EcatFrameBuilder, RawDatagram};
use ethercat_wire::protocol::pcap_io::{write_pcap_file, FrameInputKind};

fn unique_test_id() -> String {
    static SEQ: AtomicUsize = AtomicUsize::new(1);
    format!(
        "{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn build_eth_ecat_frame(ecat_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    out.extend_from_slice(&[0x00, 0x01, 0x05, 0x10, 0x20, 0x30]);
    out.extend_from_slice(&ETH_P_ECAT.to_be_bytes());
    let hdr = ((body.len() as u16) & 0x07FF) | (((ecat_type as u16) & 0x0F) << 12);
    out.extend_from_slice(&hdr.to_le_bytes());
    out.extend_from_slice(body);
    if out.len() < 60 {
        out.resize(60, 0);
    }
    out
}

fn build_ipv4_udp_frame(src_port: u16, dst_port: u16, udp_payload: &[u8]) -> Vec<u8> {
    let udp_len = (8 + udp_payload.len()) as u16;
    let ip_len = (20 + udp_len as usize) as u16;
    let mut out = Vec::with_capacity(14 + ip_len as usize);
    out.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
    out.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header (20B, no checksum verification required by dissector/tshark default)
    out.push(0x45);
    out.push(0x00);
    out.extend_from_slice(&ip_len.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 64, 17, 0x00, 0x00]);
    out.extend_from_slice(&[192, 168, 1, 10]);
    out.extend_from_slice(&[192, 168, 1, 20]);
    // UDP header (8B)
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&udp_len.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(udp_payload);
    out
}

fn build_ipv4_tcp_frame(src_port: u16, dst_port: u16, tcp_payload: &[u8]) -> Vec<u8> {
    let ip_len = (20 + 20 + tcp_payload.len()) as u16;
    let mut out = Vec::with_capacity(14 + ip_len as usize);
    out.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
    out.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
    out.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header
    out.push(0x45);
    out.push(0x00);
    out.extend_from_slice(&ip_len.to_be_bytes());
    out.extend_from_slice(&[0x00, 0x02, 0x40, 0x00, 64, 6, 0x00, 0x00]);
    out.extend_from_slice(&[192, 168, 1, 10]);
    out.extend_from_slice(&[192, 168, 1, 20]);
    // TCP header (20B, data offset = 5 words = 20B, PSH+ACK = 0x18)
    out.extend_from_slice(&src_port.to_be_bytes());
    out.extend_from_slice(&dst_port.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.extend_from_slice(&1u32.to_be_bytes());
    out.push(0x50);
    out.push(0x18);
    out.extend_from_slice(&4096u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(tcp_payload);
    out
}

#[allow(clippy::too_many_arguments)]
fn build_ams_pdu(
    target_netid: [u8; 6],
    target_port: u16,
    sender_netid: [u8; 6],
    sender_port: u16,
    cmd_id: u16,
    state_flags: u16,
    error_code: u32,
    invoke_id: u32,
    ads_body: &[u8],
) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(32 + ads_body.len());
    pdu.extend_from_slice(&target_netid);
    pdu.extend_from_slice(&target_port.to_le_bytes());
    pdu.extend_from_slice(&sender_netid);
    pdu.extend_from_slice(&sender_port.to_le_bytes());
    pdu.extend_from_slice(&cmd_id.to_le_bytes());
    pdu.extend_from_slice(&state_flags.to_le_bytes());
    pdu.extend_from_slice(&(ads_body.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&error_code.to_le_bytes());
    pdu.extend_from_slice(&invoke_id.to_le_bytes());
    pdu.extend_from_slice(ads_body);
    pdu
}

#[allow(clippy::too_many_arguments)]
fn build_coe_sdo_mbx_frame(
    station: u16,
    ado: u16,
    wkc: u16,
    cnt: u8,
    sdo_hdr: u8,
    index: u16,
    subindex: u8,
    body_after_idx: &[u8],
) -> Vec<u8> {
    let coe_len = 2 + 1 + 2 + 1 + body_after_idx.len();
    let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
    mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
    mbx.extend_from_slice(&station.to_le_bytes());
    mbx.push(0x00);
    mbx.push(((cnt & 0x07) << 4) | 0x03); // CoE (0x03)
    mbx.extend_from_slice(&(0x2000u16).to_le_bytes()); // service = 0x02 (SDO Req) or 0x03 (SDO Resp)
    mbx.push(sdo_hdr);
    mbx.extend_from_slice(&index.to_le_bytes());
    mbx.push(subindex);
    mbx.extend_from_slice(body_after_idx);
    if mbx.len() < 16 {
        mbx.resize(16, 0);
    }
    let mut dg = RawDatagram::new_positioned(EcatCmd::Fpwr, cnt, station, ado, mbx);
    dg.wkc = wkc;
    let mut b = EcatFrameBuilder::new();
    b.pad_to_min_ethernet = true;
    b.add_datagram(dg);
    b.build().unwrap()
}

fn build_coe_sdo_resp_mbx_frame(
    station: u16,
    ado: u16,
    cnt: u8,
    sdo_hdr: u8,
    index: u16,
    subindex: u8,
    body_after_idx: &[u8],
) -> Vec<u8> {
    let coe_len = 2 + 1 + 2 + 1 + body_after_idx.len();
    let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
    mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
    mbx.extend_from_slice(&station.to_le_bytes());
    mbx.push(0x00);
    mbx.push(((cnt & 0x07) << 4) | 0x03);
    mbx.extend_from_slice(&(0x3000u16).to_le_bytes()); // service = 0x03 (SDO Response)
    mbx.push(sdo_hdr);
    mbx.extend_from_slice(&index.to_le_bytes());
    mbx.push(subindex);
    mbx.extend_from_slice(body_after_idx);
    if mbx.len() < 16 {
        mbx.resize(16, 0);
    }
    let mut dg = RawDatagram::new_positioned(EcatCmd::Fprd, cnt, station, ado, mbx);
    dg.wkc = 1;
    let mut b = EcatFrameBuilder::new();
    b.pad_to_min_ethernet = true;
    b.add_datagram(dg);
    b.build().unwrap()
}

#[test]
fn wireshark_46_all_protocols_and_live_tshark_parity() {
    assert_eq!(WIRESHARK_PROTOCOLS.len(), 7);

    // Frame 0: ET2000 ESL 16-byte prefix + 0x88A4 DLPDU with 3 chained subframes:
    //   sub0: ARMW 0x0910 (DC time = 100_000)
    //   sub1: FPWR 0x1001:0x0600 (16B FMMU0: lstart=0x00010000, llen=6, pstart=0x1100, write, active)
    //   sub2: FPWR 0x1001:0x0810 (8B SM2: pstart=0x1100, len=6, ctrl=0x24, stat=0x00, act=0x01)
    let mut f0_builder = EcatFrameBuilder::new();
    let mut dg_dc1 = RawDatagram::new_positioned(
        EcatCmd::Armw,
        1,
        0x0000,
        0x0910,
        100_000u32.to_le_bytes().to_vec(),
    );
    dg_dc1.wkc = 2;
    let mut fmmu0 = vec![0u8; 16];
    fmmu0[0..4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fmmu0[4..6].copy_from_slice(&6u16.to_le_bytes());
    fmmu0[6] = 0;
    fmmu0[7] = 7;
    fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu0[10] = 0;
    fmmu0[11] = 0x02; // write enable
    fmmu0[12] = 0x01; // active
    let mut dg_fmmu = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0600, fmmu0);
    dg_fmmu.wkc = 1;
    let mut sm2 = vec![0u8; 8];
    sm2[0..2].copy_from_slice(&0x1100u16.to_le_bytes());
    sm2[2..4].copy_from_slice(&6u16.to_le_bytes());
    sm2[4] = 0x24;
    sm2[5] = 0x00;
    sm2[6] = 0x01;
    sm2[7] = 0x00;
    let mut dg_sm = RawDatagram::new_positioned(EcatCmd::Fpwr, 3, 0x1001, 0x0810, sm2);
    dg_sm.wkc = 1;
    f0_builder.add_datagram(dg_dc1);
    f0_builder.add_datagram(dg_fmmu);
    f0_builder.add_datagram(dg_sm);
    let f0_inner = f0_builder.build().unwrap();
    let mut f0_esl_prefix = Vec::with_capacity(16 + f0_inner.len());
    f0_esl_prefix.extend_from_slice(&ESL_SIGNATURE);
    // ET2000 hardware port bitmask: 0x0020 => Port 2, crcerror=0x1000 (bit 12, without alignerror 0x0800), tsenable=0x2000
    let esl_flags: u16 = 0x0020 | 0x1000 | 0x2000;
    f0_esl_prefix.extend_from_slice(&esl_flags.to_le_bytes());
    f0_esl_prefix.extend_from_slice(&123_456_789_000u64.to_le_bytes());
    f0_esl_prefix.extend_from_slice(&f0_inner);

    // Frame 1: Second ARMW 0x0910 (DC time = 350_000 -> diff = 250_000 ns) + BRD 0x0900..0x090F DC port times + ESL trailer
    let mut f1_builder = EcatFrameBuilder::new();
    let mut dg_dc2 = RawDatagram::new_positioned(
        EcatCmd::Armw,
        4,
        0x0000,
        0x0910,
        350_000u32.to_le_bytes().to_vec(),
    );
    dg_dc2.wkc = 2;
    let mut dc_ports = Vec::with_capacity(16);
    dc_ports.extend_from_slice(&1000u32.to_le_bytes()); // Port A (0x0900)
    dc_ports.extend_from_slice(&1900u32.to_le_bytes()); // Port B (0x0904)
    dc_ports.extend_from_slice(&2500u32.to_le_bytes()); // Port C (0x0908)
    dc_ports.extend_from_slice(&1400u32.to_le_bytes()); // Port D (0x090C) -> da=400, bd=500, cb=600, ba=900
    let mut dg_dc_ports = RawDatagram::new_positioned(EcatCmd::Fprd, 5, 0x1001, 0x0900, dc_ports);
    dg_dc_ports.wkc = 1;
    f1_builder.add_datagram(dg_dc2);
    f1_builder.add_datagram(dg_dc_ports);
    let mut f1_esl_trailer = f1_builder.build().unwrap();
    f1_esl_trailer.extend_from_slice(&ESL_SIGNATURE);
    // ET2000 trailer: Port 1 (0x0040), alignerror=0x0800 (bit 11, without crcerror 0x1000), tsenable=0x2000
    f1_esl_trailer.extend_from_slice(&(0x0040u16 | 0x0800 | 0x2000).to_le_bytes());
    f1_esl_trailer.extend_from_slice(&123_457_039_000u64.to_le_bytes());

    // Frame 2: Direct AMS over 0x88A4 (`ecatf.type == 2`) — ADS Write (cmd=3)
    let mut ads_write = Vec::new();
    ads_write.extend_from_slice(&0x0000_4020u32.to_le_bytes()); // IndexGroup
    ads_write.extend_from_slice(&0x0000_0010u32.to_le_bytes()); // IndexOffset
    ads_write.extend_from_slice(&4u32.to_le_bytes()); // Length
    ads_write.extend_from_slice(&0x7856_3412u32.to_le_bytes());
    let ams_pdu = build_ams_pdu(
        [5, 12, 34, 56, 1, 1],
        851,
        [192, 168, 1, 10, 1, 1],
        32905,
        0x0003,
        0x0004,
        0,
        42,
        &ads_write,
    );
    let f2_direct_ams = build_eth_ecat_frame(ECAT_FRAME_TYPE_ADS, &ams_pdu);

    // Frame 3: Direct RAW-IO over 0x88A4 (`ecatf.type == 3`)
    let f3_ioraw = build_eth_ecat_frame(
        ECAT_FRAME_TYPE_RAW_IO,
        &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0x01, 0x02],
    );

    // Frame 4: TwinCAT Network Variables (`ecatf.type == 4`) with official 12-byte NvParserHDR + 2 variables
    let mut nv_body = Vec::new();
    nv_body.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]); // publisher MAC
    nv_body.extend_from_slice(&2u16.to_le_bytes()); // count = 2
    nv_body.extend_from_slice(&0x1234u16.to_le_bytes()); // cycleindex
    nv_body.extend_from_slice(&[0u8; 2]); // 2 reserved bytes in 12B tc_nv.header
                                          // Var 0: id=10, hash=0xABCD, len=4, quality=1, data=[0x11,0x22,0x33,0x44]
    nv_body.extend_from_slice(&10u16.to_le_bytes());
    nv_body.extend_from_slice(&0xABCDu16.to_le_bytes());
    nv_body.extend_from_slice(&4u16.to_le_bytes());
    nv_body.extend_from_slice(&1u16.to_le_bytes());
    nv_body.extend_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    // Var 1: id=11, hash=0xDCBA, len=2, quality=0, data=[0x55,0x66]
    nv_body.extend_from_slice(&11u16.to_le_bytes());
    nv_body.extend_from_slice(&0xDCBAu16.to_le_bytes());
    nv_body.extend_from_slice(&2u16.to_le_bytes());
    nv_body.extend_from_slice(&0u16.to_le_bytes());
    nv_body.extend_from_slice(&[0x55, 0x66]);
    let f4_tc_nv = build_eth_ecat_frame(ECAT_FRAME_TYPE_NV, &nv_body);

    // Frame 5 & 6: Direct Mailbox (`ecatf.type == 5`) FoE WRQ `drive.efw` followed by FoE DATA `.efw` block
    let fname = b"drive.efw";
    let mut foe_wrq = Vec::new();
    foe_wrq.extend_from_slice(&((6 + fname.len()) as u16).to_le_bytes());
    foe_wrq.extend_from_slice(&0x1001u16.to_le_bytes());
    foe_wrq.push(0x00);
    foe_wrq.push(0x14); // cnt=1, type=4 (FoE)
    foe_wrq.push(0x02); // WRQ
    foe_wrq.push(0x00);
    foe_wrq.extend_from_slice(&0x1122_3344u32.to_le_bytes()); // password
    foe_wrq.extend_from_slice(fname);
    let f5_foe_wrq = build_eth_ecat_frame(ECAT_FRAME_TYPE_MAILBOX, &foe_wrq);

    // Use cmd=0x0005 (outside heuristic `looks_like_efw_block` range) so ONLY stateful `.efw` WRQ tracking decodes it!
    let mut efw_block = Vec::new();
    efw_block.extend_from_slice(&5u16.to_le_bytes()); // EFW custom/stateful cmd = 5
    efw_block.extend_from_slice(&4u16.to_le_bytes()); // size = 4
    efw_block.extend_from_slice(&0x0800_1000u32.to_le_bytes()); // addresslw=0x1000, addresshw=0x0800
    efw_block.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // 4B firmware data
    let mut foe_data = Vec::new();
    foe_data.extend_from_slice(&((6 + efw_block.len()) as u16).to_le_bytes());
    foe_data.extend_from_slice(&0x1001u16.to_le_bytes());
    foe_data.push(0x00);
    foe_data.push(0x24); // cnt=2, type=4 (FoE)
    foe_data.push(0x03); // DATA
    foe_data.push(0x00);
    foe_data.extend_from_slice(&1u32.to_le_bytes()); // packet_no = 1
    foe_data.extend_from_slice(&efw_block);
    let f6_foe_efw_data = build_eth_ecat_frame(ECAT_FRAME_TYPE_MAILBOX, &foe_data);

    // Frame 7: EoE Set MAC Filter Request (`type=0x04`, `last_fragment=1`) inside Direct Mailbox (`ecatf.type == 5`)
    // Official Wireshark `packet-ecatmb.c` layout: 4B EoE header + 2B opts (`0x1500` => macfiltercount=1, maskcount=1, nobroadcasts=true)
    // + 16 * 6B filter slots + 4 * 6B mask slots = 126B EoE body.
    let mut eoe_mf = Vec::new();
    let eoe_body_len = 4 + 2 + 16 * 6 + 4 * 6;
    eoe_mf.extend_from_slice(&(eoe_body_len as u16).to_le_bytes());
    eoe_mf.extend_from_slice(&0x1001u16.to_le_bytes());
    eoe_mf.push(0x00);
    eoe_mf.push(0x32); // cnt=3, type=2 (EoE)
    eoe_mf.push(0x04); // Set MAC Filter Req
    eoe_mf.push(0x01); // last_fragment = 1
    eoe_mf.extend_from_slice(&0u16.to_le_bytes());
    eoe_mf.extend_from_slice(&0x1500u16.to_le_bytes()); // macfiltercount=1 (0xF000), maskcount=1 (0x0C00), nobroadcasts=1 (0x0100)
    eoe_mf.extend_from_slice(&[0x00, 0x01, 0x05, 0xDE, 0xAD, 0x01]);
    eoe_mf.extend_from_slice(&[0u8; 15 * 6]);
    eoe_mf.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00]);
    eoe_mf.extend_from_slice(&[0u8; 3 * 6]);
    let f7_eoe_macfilter = build_eth_ecat_frame(ECAT_FRAME_TYPE_MAILBOX, &eoe_mf);

    // Frame 8: IPv4/UDP port 34980 (`0x88A4`) encapsulating DLPDU BRD 0x0130
    let mut brd_dg = RawDatagram::new_positioned(EcatCmd::Brd, 9, 0x0000, 0x0130, vec![0x08, 0x00]);
    brd_dg.wkc = 3;
    let mut udp_ecat_builder = EcatFrameBuilder::new();
    udp_ecat_builder.add_datagram(brd_dg);
    let eth_brd = udp_ecat_builder.build().unwrap();
    let f8_udp_ecat = build_ipv4_udp_frame(UDP_PORT_ECAT, UDP_PORT_ECAT, &eth_brd[14..]);

    // Frame 9: Standalone AMS/UDP (`48899`) Read State Response (`cmd=4, state=0x0005`)
    let mut ads_state_resp = Vec::new();
    ads_state_resp.extend_from_slice(&0u32.to_le_bytes()); // result = 0
    ads_state_resp.extend_from_slice(&5u16.to_le_bytes()); // ADSState = RUN (5)
    ads_state_resp.extend_from_slice(&0u16.to_le_bytes()); // DeviceState = 0
    let ams_udp_pdu = build_ams_pdu(
        [192, 168, 1, 10, 1, 1],
        32905,
        [5, 12, 34, 56, 1, 1],
        851,
        0x0004,
        0x0005,
        0,
        99,
        &ads_state_resp,
    );
    let f9_ams_udp = build_ipv4_udp_frame(UDP_PORT_AMS, 55000, &ams_udp_pdu);

    // Frame 10: Standalone AMS/TCP (`48898`) carrying CoE-over-AoE (`IndexGroup=0xF302`, `IndexOffset=0x6040_0000`, `cmd=3` Write `0x000F`)
    let mut ads_coe_write = Vec::new();
    ads_coe_write.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    ads_coe_write.extend_from_slice(&0x6040_0000u32.to_le_bytes());
    ads_coe_write.extend_from_slice(&2u32.to_le_bytes());
    ads_coe_write.extend_from_slice(&0x000Fu16.to_le_bytes());
    let ams_tcp_inner = build_ams_pdu(
        [5, 12, 34, 56, 2, 1],
        0x1001,
        [192, 168, 1, 10, 1, 1],
        32905,
        0x0003,
        0x0004,
        0,
        101,
        &ads_coe_write,
    );
    let mut ams_tcp_payload = Vec::with_capacity(6 + ams_tcp_inner.len());
    ams_tcp_payload.extend_from_slice(&0u16.to_le_bytes());
    ams_tcp_payload.extend_from_slice(&(ams_tcp_inner.len() as u32).to_le_bytes());
    ams_tcp_payload.extend_from_slice(&ams_tcp_inner);
    let f10_ams_tcp = build_ipv4_tcp_frame(51234, TCP_PORT_AMS, &ams_tcp_payload);

    let frames = vec![
        (1_000u64, f0_esl_prefix),
        (2_000, f1_esl_trailer),
        (3_000, f2_direct_ams),
        (4_000, f3_ioraw),
        (5_000, f4_tc_nv),
        (6_000, f5_foe_wrq),
        (7_000, f6_foe_efw_data),
        (8_000, f7_eoe_macfilter),
        (9_000, f8_udp_ecat),
        (10_000, f9_ams_udp),
        (11_000, f10_ams_tcp),
    ];

    let pcap_path =
        std::env::temp_dir().join(format!("ethercat-dissector-ws46-{}.pcap", unique_test_id()));
    write_pcap_file(&pcap_path, &frames).unwrap();

    let mut dissected = Vec::new();
    dissect_capture_file(
        &pcap_path,
        FrameInputKind::Pcap,
        DissectOptions::default(),
        |_rec, df| {
            dissected.push(df);
            Ok(true)
        },
    )
    .unwrap();
    assert_eq!(dissected.len(), 11);

    // Verify Frame 0: ESL prefix + chained subframes + FMMU + SyncMan + initial DC diff = 0
    let d0 = &dissected[0];
    assert_eq!(d0.wireshark_fields["esl.port"], 2);
    assert_eq!(d0.wireshark_fields["esl.crcerror"], true);
    assert_eq!(d0.wireshark_fields["esl.alignerror"], false);
    assert_eq!(d0.wireshark_fields["esl.tsenable"], true);
    assert_eq!(d0.wireshark_fields["esl.timestamp"], 123_456_789_000u64);
    assert_eq!(d0.wireshark_fields["ecatf.type"], ECAT_FRAME_TYPE_DLPDU);
    assert_eq!(d0.wireshark_fields["ecat.sub1.cmd"], "ARMW");
    assert_eq!(d0.wireshark_fields["ecat.sub2.cmd"], "FPWR");
    assert_eq!(d0.wireshark_fields["ecat.sub3.cmd"], "FPWR");
    assert!(!d0.wireshark_fields.contains_key("ecat.dc.dif.curtime"));
    assert_eq!(d0.wireshark_fields["ecat.fmmu.lstart"], "0x00010000");
    assert_eq!(d0.wireshark_fields["ecat.fmmu.llen"], 6);
    assert_eq!(d0.wireshark_fields["ecat.fmmu.pstart"], "0x1100");
    assert_eq!(d0.wireshark_fields["ecat.fmmu.typewrite"], true);
    assert_eq!(d0.wireshark_fields["ecat.fmmu.activate"], "0x01");
    assert_eq!(d0.wireshark_fields["ecat.fmmu.activate0"], true);
    assert_eq!(d0.wireshark_fields["ecat.syncman.start"], "0x1100");
    assert_eq!(d0.wireshark_fields["ecat.syncman.len"], 6);

    // Verify Frame 1: Stateful DC 0x0910 diff = 250_000 + DC port diffs da=400, ba=900 + ESL trailer
    let d1 = &dissected[1];
    assert_eq!(d1.wireshark_fields["ecat.dc.dif.curtime"], 250_000);
    assert_eq!(d1.wireshark_fields["ecat.dc.dif.da"], 400);
    assert_eq!(d1.wireshark_fields["ecat.dc.dif.ba"], 900);
    assert_eq!(d1.wireshark_fields["esl.port"], 1);
    assert_eq!(d1.wireshark_fields["esl.crcerror"], false);
    assert_eq!(d1.wireshark_fields["esl.alignerror"], true);
    assert_eq!(d1.wireshark_fields["esl.timestamp"], 123_457_039_000u64);

    // Verify Frame 2: Direct AMS (`ecatf.type == 2`)
    let d2 = &dissected[2];
    assert_eq!(d2.wireshark_fields["ecatf.type"], ECAT_FRAME_TYPE_ADS);
    assert_eq!(d2.wireshark_fields["ams.targetnetid"], "5.12.34.56.1.1");
    assert_eq!(d2.wireshark_fields["ams.targetport"], 851);
    assert_eq!(d2.wireshark_fields["ams.sendernetid"], "192.168.1.10.1.1");
    assert_eq!(d2.wireshark_fields["ams.senderport"], 32905);
    assert_eq!(d2.wireshark_fields["ams.cmdid"], 3);
    assert_eq!(d2.wireshark_fields["ams.invokeid"], "0x0000002a");
    assert_eq!(d2.wireshark_fields["ams.ads_indexgroup"], "0x00004020");
    assert_eq!(d2.wireshark_fields["ams.ads_indexoffset"], "0x00000010");

    // Verify Frame 3: Direct RAW-IO (`ecatf.type == 3`)
    let d3 = &dissected[3];
    assert_eq!(d3.wireshark_fields["ecatf.type"], ECAT_FRAME_TYPE_RAW_IO);
    assert!(d3.raw_io.is_some());
    assert_eq!(d3.wireshark_fields["ioraw.header"], "deadbeef");
    assert_eq!(d3.wireshark_fields["ioraw.data"], "cafe0102");

    // Verify Frame 4: TwinCAT Network Variables (`ecatf.type == 4`) with 12-byte NvParserHDR
    let d4 = &dissected[4];
    assert_eq!(d4.wireshark_fields["ecatf.type"], ECAT_FRAME_TYPE_NV);
    assert_eq!(
        d4.wireshark_fields["tc_nv.header"].as_str().unwrap().len(),
        24
    );
    assert_eq!(d4.wireshark_fields["tc_nv.publisher"], "00:01:05:11:22:33");
    assert_eq!(d4.wireshark_fields["tc_nv.count"], 2);
    assert_eq!(d4.wireshark_fields["tc_nv.cycleindex"], 0x1234);
    assert_eq!(d4.wireshark_fields["tc_nv.id"], "0x000a");
    assert_eq!(d4.wireshark_fields["tc_nv.hash"], "0xabcd");
    assert_eq!(d4.wireshark_fields["tc_nv.length"], 4);
    assert_eq!(d4.wireshark_fields["tc_nv.quality"], "0x0001");
    assert_eq!(d4.wireshark_fields["tc_nv.data"], "11223344");
    assert_eq!(d4.wireshark_fields["tc_nv.var[1].id"], "0x000b");
    assert_eq!(d4.wireshark_fields["tc_nv.var[1].hash"], "0xdcba");
    assert_eq!(d4.wireshark_fields["tc_nv.var[1].length"], 2);
    assert_eq!(d4.wireshark_fields["tc_nv.var[1].quality"], "0x0000");
    assert_eq!(d4.wireshark_fields["tc_nv.var[1].data"], "5566");
    assert_eq!(
        d4.network_variables.as_ref().unwrap()["variables"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Verify Frame 5 & 6: FoE WRQ `.efw` + stateful FoE DATA `.efw` block decode
    let d5 = &dissected[5];
    assert_eq!(d5.wireshark_fields["ecat_mailbox.foe_opmode"], "0x02");
    assert_eq!(
        d5.wireshark_fields["ecat_mailbox.foe_filename"],
        "drive.efw"
    );
    let d6 = &dissected[6];
    assert_eq!(d6.wireshark_fields["ecat_mailbox.foe_opmode"], "0x03");
    assert_eq!(d6.wireshark_fields["ecat_mailbox.foe.efw.cmd"], "0x0005");
    assert_eq!(d6.wireshark_fields["ecat_mailbox.foe.efw.size"], 4);
    assert_eq!(
        d6.wireshark_fields["ecat_mailbox.foe.efw.addresslw"],
        "0x1000"
    );
    assert_eq!(
        d6.wireshark_fields["ecat_mailbox.foe.efw.addresshw"],
        "0x0800"
    );
    assert_eq!(d6.wireshark_fields["ecat_mailbox.foe.efw.data"], "aabbccdd");

    // Verify Frame 7: EoE MAC Filter
    let d7 = &dissected[7];
    assert_eq!(
        d7.wireshark_fields["ecat_mailbox.eoe.macfilter.macfiltercount"],
        1
    );
    assert_eq!(
        d7.wireshark_fields["ecat_mailbox.eoe.macfilter.maskcount"],
        1
    );
    assert_eq!(
        d7.wireshark_fields["ecat_mailbox.eoe.macfilter.nobroadcasts"],
        true
    );
    assert_eq!(
        d7.wireshark_fields["ecat_mailbox.eoe.macfilter.filter0"],
        "00:01:05:de:ad:01"
    );
    assert_eq!(
        d7.wireshark_fields["ecat_mailbox.eoe.macfilter.filtermask0"],
        "ff:ff:ff:00:00:00"
    );

    // Verify Frame 8: UDP/34980 EtherCAT
    let d8 = &dissected[8];
    assert_eq!(d8.wireshark_fields["udp.dstport"], 34980);
    assert_eq!(d8.wireshark_fields["ecat.cmd"], "BRD");
    assert_eq!(d8.wireshark_fields["ecat.reg.al_state"], "OP");

    // Verify Frame 9: Standalone AMS/UDP 48899
    let d9 = &dissected[9];
    assert_eq!(d9.wireshark_fields["ams.cmdid"], 4);
    assert_eq!(d9.wireshark_fields["ams.invokeid"], "0x00000063");
    assert_eq!(d9.wireshark_fields["ams.ads_state"], "0x0005");

    // Verify Frame 10: Standalone AMS/TCP 48898 + CoE-over-AoE 0xF302
    let d10 = &dissected[10];
    assert_eq!(d10.wireshark_fields["ams.cmdid"], 3);
    assert_eq!(d10.wireshark_fields["ams.invokeid"], "0x00000065");
    assert_eq!(d10.wireshark_fields["ams.ads_indexgroup"], "0x0000f302");
    assert!(d10.direct_ams_sdo_event.is_some());

    // Live cross-validation against installed Wireshark 4.6 (`tshark.exe`) when present on host
    let tshark_exe = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
    if tshark_exe.is_file() {
        let out = Command::new(tshark_exe)
            .args([
                "--enable-heuristic",
                "esl_eth",
                "-r",
                pcap_path.to_str().unwrap(),
                "-T",
                "fields",
                "-E",
                "separator=|",
                "-e",
                "ecatf.type", // 0
                "-e",
                "ecat.sub2.dc.dif.da", // 1
                "-e",
                "ams.targetnetid", // 2
                "-e",
                "ams.cmdid", // 3
                "-e",
                "ams.invokeid", // 4
                "-e",
                "tc_nv.publisher", // 5
                "-e",
                "tc_nv.count", // 6
                "-e",
                "tc_nv.cycleindex", // 7
                "-e",
                "ecat_mailbox.foe_opmode", // 8
                "-e",
                "ecat_mailbox.foe.efw.cmd", // 9
                "-e",
                "ecat_mailbox.foe.efw.size", // 10
                "-e",
                "ecat_mailbox.eoe.macfilter.macfiltercount", // 11
                "-e",
                "ecat_mailbox.eoe.macfilter.maskcount", // 12
                "-e",
                "esl.port", // 13
                "-e",
                "esl.crcerror", // 14
                "-e",
                "ams.ads_indexgroup", // 15
                "-e",
                "ams.ads_state", // 16
                "-e",
                "esl.alignerror", // 17
                "-e",
                "tc_nv.id", // 18
                "-e",
                "tc_nv.hash", // 19
                "-e",
                "tc_nv.length", // 20
                "-e",
                "tc_nv.quality", // 21
                "-e",
                "tc_nv.data", // 22
            ])
            .output()
            .expect("failed to execute local tshark.exe");
        assert!(
            out.status.success(),
            "tshark rejected Wireshark 4.6 fields: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let rows: Vec<&str> = stdout.lines().collect();
        assert_eq!(rows.len(), 11, "unexpected tshark row count: {stdout}");

        let parse_ws_num = |s: &str| -> u64 {
            let t = s.trim();
            if let Some(hx) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                u64::from_str_radix(hx, 16)
                    .unwrap_or_else(|e| panic!("bad hex `{s}`: {e}\n{stdout}"))
            } else {
                t.parse::<u64>()
                    .unwrap_or_else(|e| panic!("bad dec `{s}`: {e}\n{stdout}"))
            }
        };
        let parse_ws_bool = |s: &str| -> bool {
            let t = s.trim();
            if t.eq_ignore_ascii_case("true") || t == "1" {
                true
            } else if t.eq_ignore_ascii_case("false") || t == "0" {
                false
            } else {
                panic!("bad bool `{s}`\n{stdout}")
            }
        };

        // Packet 0 (index 0): ESL prefix port=2, crcerror=true, alignerror=false, DC port diff omitted
        let r0: Vec<&str> = rows[0].split('|').collect();
        assert_eq!(r0[1], "", "row0={}", rows[0]);
        assert_eq!(parse_ws_num(r0[13]), 2, "row0={}", rows[0]);
        assert!(parse_ws_bool(r0[14]), "row0={}", rows[0]);
        assert!(!parse_ws_bool(r0[17]), "row0={}", rows[0]);

        // Packet 1 (index 1): ecatf.type == 1, ecat.sub2.dc.dif.da == 400, ESL trailer port=1, crcerror=false, alignerror=true
        assert_eq!(d1.wireshark_fields["ecat.sub2.dc.dif.da"], 400);
        let r1: Vec<&str> = rows[1].split('|').collect();
        assert_eq!(parse_ws_num(r1[0]), 1, "row1={}", rows[1]);
        assert_eq!(parse_ws_num(r1[1]), 400, "row1={}", rows[1]);
        assert_eq!(parse_ws_num(r1[13]), 1, "row1={}", rows[1]);
        assert!(!parse_ws_bool(r1[14]), "row1={}", rows[1]);
        assert!(parse_ws_bool(r1[17]), "row1={}", rows[1]);

        // Packet 2 (index 2): Direct AMS (`ecatf.type == 2`), targetnetid=5.12.34.56.1.1, cmdid=3, invokeid=42, indexgroup=0x4020
        let r2: Vec<&str> = rows[2].split('|').collect();
        assert_eq!(parse_ws_num(r2[0]), 2, "row2={}", rows[2]);
        assert_eq!(
            r2[2],
            d2.wireshark_fields["ams.targetnetid"].as_str().unwrap()
        );
        assert_eq!(parse_ws_num(r2[3]), 3);
        assert_eq!(parse_ws_num(r2[4]), 42);
        assert_eq!(parse_ws_num(r2[15]), 0x4020);

        // Packet 3 (index 3): Direct RAW-IO (`ecatf.type == 3`)
        let r3: Vec<&str> = rows[3].split('|').collect();
        assert_eq!(parse_ws_num(r3[0]), 3, "row3={}", rows[3]);

        // Packet 4 (index 4): TwinCAT NV (`ecatf.type == 4`), publisher, count=2, cycleindex=0x1234 + variable fields
        let r4: Vec<&str> = rows[4].split('|').collect();
        assert_eq!(parse_ws_num(r4[0]), 4, "row4={}", rows[4]);
        let norm_pub = r4[5].replace(':', "").to_ascii_lowercase();
        assert_eq!(norm_pub, "000105112233", "row4={}", rows[4]);
        assert_eq!(parse_ws_num(r4[6]), 2);
        assert_eq!(parse_ws_num(r4[7]), 0x1234);
        let nv_ids: Vec<u64> = r4[18].split(',').map(parse_ws_num).collect();
        let nv_hashes: Vec<u64> = r4[19].split(',').map(parse_ws_num).collect();
        let nv_lens: Vec<u64> = r4[20].split(',').map(parse_ws_num).collect();
        let nv_quals: Vec<u64> = r4[21].split(',').map(parse_ws_num).collect();
        let nv_datas: Vec<String> = r4[22]
            .split(',')
            .map(|s| s.replace(':', "").trim().to_ascii_lowercase())
            .collect();
        assert_eq!(nv_ids, vec![10, 11], "row4={}", rows[4]);
        assert_eq!(nv_hashes, vec![0xabcd, 0xdcba], "row4={}", rows[4]);
        assert_eq!(nv_lens, vec![4, 2], "row4={}", rows[4]);
        assert_eq!(nv_quals, vec![1, 0], "row4={}", rows[4]);
        assert_eq!(nv_datas, vec!["11223344", "5566"], "row4={}", rows[4]);

        // Packet 6 (index 6): FoE DATA `.efw` block (`foe_opmode=3`, `efw.cmd=5`, `efw.size=4`)
        let r6: Vec<&str> = rows[6].split('|').collect();
        assert_eq!(parse_ws_num(r6[8]), 3, "row6={}", rows[6]);
        assert_eq!(parse_ws_num(r6[9]), 5, "row6={}", rows[6]);
        assert_eq!(parse_ws_num(r6[10]), 4, "row6={}", rows[6]);

        // Packet 7 (index 7): EoE MAC Filter (`macfiltercount=1`, `maskcount=1`)
        let r7: Vec<&str> = rows[7].split('|').collect();
        assert_eq!(parse_ws_num(r7[11]), 1, "row7={}", rows[7]);
        assert_eq!(parse_ws_num(r7[12]), 1, "row7={}", rows[7]);

        // Packet 8 (index 8): UDP/34980 EtherCAT (`ecatf.type == 1`)
        let r8: Vec<&str> = rows[8].split('|').collect();
        assert_eq!(parse_ws_num(r8[0]), 1, "row8={}", rows[8]);

        // Packet 10 (index 10): AMS/TCP (`cmdid=3`, `invokeid=101`, `ads_indexgroup=0xf302`)
        let r10: Vec<&str> = rows[10].split('|').collect();
        assert_eq!(parse_ws_num(r10[3]), 3, "row10={}", rows[10]);
        assert_eq!(parse_ws_num(r10[4]), 101, "row10={}", rows[10]);
        assert_eq!(parse_ws_num(r10[15]), 0xF302, "row10={}", rows[10]);
    }

    let _ = std::fs::remove_file(&pcap_path);
}

const SERVO_ESI_XML: &str = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor>
    <Id>#x00000002</Id>
    <Name>Beckhoff Automation</Name>
  </Vendor>
  <Descriptions>
    <Devices>
      <Device Physics="YY">
        <Type ProductCode="#x13ED3052" RevisionNo="#x00110000">AX5101-0000-0214</Type>
        <Name LcId="1033">AX5101 Servo Drive</Name>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x64" Enable="1">Outputs</Sm>
        <Sm StartAddress="#x1400" ControlByte="#x20" Enable="1">Inputs</Sm>
        <RxPdo Fixed="1" Sm="2">
          <Index>#x1600</Index>
          <Name>Position RxPDO</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>Controlword</Name>
            <DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x607A</Index>
            <SubIndex>0</SubIndex>
            <BitLen>32</BitLen>
            <Name>TargetPosition</Name>
            <DataType>DINT</DataType>
          </Entry>
        </RxPdo>
        <RxPdo Fixed="0">
          <Index>#x1601</Index>
          <Name>Velocity RxPDO</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>Controlword</Name>
            <DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x60FF</Index>
            <SubIndex>0</SubIndex>
            <BitLen>32</BitLen>
            <Name>TargetVelocity</Name>
            <DataType>DINT</DataType>
          </Entry>
        </RxPdo>
        <TxPdo Fixed="1" Sm="3">
          <Index>#x1A00</Index>
          <Name>Standard TxPDO</Name>
          <Entry>
            <Index>#x6041</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>Statusword</Name>
            <DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x6064</Index>
            <SubIndex>0</SubIndex>
            <BitLen>32</BitLen>
            <Name>ActualPosition</Name>
            <DataType>DINT</DataType>
          </Entry>
          <Entry>
            <Index>#x6077</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>ActualTorque</Name>
            <DataType>INT</DataType>
          </Entry>
        </TxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType>
                <Name>OpModeEnum</Name>
                <BaseType>SINT</BaseType>
                <BitSize>8</BitSize>
                <EnumInfo>
                  <Text>Profile Position (PP)</Text>
                  <Enum>1</Enum>
                </EnumInfo>
                <EnumInfo>
                  <Text>Cyclic Synchronous Position (CSP)</Text>
                  <Enum>8</Enum>
                </EnumInfo>
                <EnumInfo>
                  <Text>Cyclic Synchronous Velocity (CSV)</Text>
                  <Enum>9</Enum>
                </EnumInfo>
              </DataType>
              <DataType>
                <Name>DT2010Rec</Name>
                <BitSize>64</BitSize>
                <SubItem>
                  <SubIdx>0</SubIdx>
                  <Name>SubIndex 000</Name>
                  <Type>USINT</Type>
                  <BitSize>8</BitSize>
                  <BitOffs>0</BitOffs>
                </SubItem>
                <SubItem>
                  <SubIdx>1</SubIdx>
                  <Name>KpGain</Name>
                  <Type>REAL</Type>
                  <BitSize>32</BitSize>
                  <BitOffs>16</BitOffs>
                </SubItem>
                <SubItem>
                  <SubIdx>2</SubIdx>
                  <Name>FeedForward</Name>
                  <Type>INT</Type>
                  <BitSize>16</BitSize>
                  <BitOffs>48</BitOffs>
                </SubItem>
              </DataType>
              <DataType>
                <Name>LatchCmdRec</Name>
                <BitSize>24</BitSize>
                <SubItem>
                  <SubIdx>0</SubIdx>
                  <Name>Count</Name>
                  <Type>USINT</Type>
                  <BitSize>8</BitSize>
                  <BitOffs>0</BitOffs>
                </SubItem>
                <SubItem>
                  <SubIdx>1</SubIdx>
                  <Name>EnableLatch</Name>
                  <Type>BOOL</Type>
                  <BitSize>1</BitSize>
                  <BitOffs>16</BitOffs>
                </SubItem>
                <SubItem>
                  <SubIdx>2</SubIdx>
                  <Name>ResetFault</Name>
                  <Type>BOOL</Type>
                  <BitSize>1</BitSize>
                  <BitOffs>17</BitOffs>
                </SubItem>
              </DataType>
            </DataTypes>
            <Objects>
              <Object>
                <Index>#x1008</Index>
                <Name>Manufacturer Device Name</Name>
                <Type>STRING(16)</Type>
                <BitSize>128</BitSize>
              </Object>
              <Object>
                <Index>#x100A</Index>
                <Name>Manufacturer Software Version</Name>
                <Type>STRING(12)</Type>
                <BitSize>96</BitSize>
              </Object>
              <Object>
                <Index>#x2010</Index>
                <Name>Loop Tuning</Name>
                <Type>DT2010Rec</Type>
                <BitSize>64</BitSize>
              </Object>
              <Object>
                <Index>#x6040</Index>
                <Name>Controlword</Name>
                <Type>UINT</Type>
                <BitSize>16</BitSize>
              </Object>
              <Object>
                <Index>#x6041</Index>
                <Name>Statusword</Name>
                <Type>UINT</Type>
                <BitSize>16</BitSize>
              </Object>
              <Object>
                <Index>#x6060</Index>
                <Name>ModesOfOperation</Name>
                <Type>OpModeEnum</Type>
                <BitSize>8</BitSize>
              </Object>
              <Object>
                <Index>#x6061</Index>
                <Name>ModesOfOperationDisplay</Name>
                <Type>OpModeEnum</Type>
                <BitSize>8</BitSize>
              </Object>
              <Object>
                <Index>#x6064</Index>
                <Name>ActualPosition</Name>
                <Type>DINT</Type>
                <BitSize>32</BitSize>
              </Object>
              <Object>
                <Index>#x6077</Index>
                <Name>ActualTorque</Name>
                <Type>INT</Type>
                <BitSize>16</BitSize>
              </Object>
              <Object>
                <Index>#x607A</Index>
                <Name>TargetPosition</Name>
                <Type>DINT</Type>
                <BitSize>32</BitSize>
              </Object>
              <Object>
                <Index>#x60FF</Index>
                <Name>TargetVelocity</Name>
                <Type>DINT</Type>
                <BitSize>32</BitSize>
              </Object>
              <Object>
                <Index>#x7000</Index>
                <Name>Latch Control</Name>
                <Type>LatchCmdRec</Type>
                <BitSize>24</BitSize>
              </Object>
              <Object>
                <Index>#x7010</Index>
                <Name>DigitalOutputs</Name>
                <Type>UDINT</Type>
                <BitSize>32</BitSize>
              </Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>
"##;

#[test]
fn xml_sdo_dissection_esi_dict_eni_ca_enums_segmented_and_aoe() {
    let cat = Arc::new(XmlCatalog::parse_xml_str(SERVO_ESI_XML).unwrap());
    assert_eq!(cat.devices.len(), 1);

    let opts = DissectOptions {
        xml_catalog: Some(cat.clone()),
        ..Default::default()
    };
    let mut session = DissectSession::new(opts);

    // 1. Expedited SDO Download: 0x607A:00 = -125000 (DINT, 4B expedited: sdo_hdr = 0x23)
    let f_dl_exp = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        1,
        0x23,
        0x607A,
        0,
        &(-125_000i32).to_le_bytes(),
    );
    let d_exp = session.dissect_next(&f_dl_exp).unwrap();
    assert_eq!(
        d_exp.wireshark_fields["ecat_mailbox.coe.sdo.xml.entry_name"],
        "TargetPosition"
    );
    assert_eq!(
        d_exp.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        -125_000
    );

    // 2. Expedited SDO Upload Response with EnumInfo: 0x6061:00 = 8 (1B expedited: sdo_hdr = 0x4F)
    let f_ul_enum = build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 2, 0x4F, 0x6061, 0, &[8, 0, 0, 0]);
    let d_enum = session.dissect_next(&f_ul_enum).unwrap();
    assert_eq!(d_enum.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"], 8);
    assert_eq!(
        d_enum.wireshark_fields["ecat_mailbox.coe.sdo.xml.enum_text"],
        "Cyclic Synchronous Position (CSP)"
    );

    // 3. Complete Access (CA=1) Normal SDO Download on RECORD 0x2010 (sub0=2, pad, KpGain=2.5f32, FeedForward=-40i16)
    // sdo_hdr = 0x31 (cmd=1 Initiate Download, expedited=0, size_indicated=1, CA=1)
    let mut ca_payload = Vec::new();
    ca_payload.extend_from_slice(&8u32.to_le_bytes()); // indicated size = 8 bytes
    ca_payload.push(2u8); // sub0 = 2
    ca_payload.push(0u8); // 8-bit pad up to BitOffs=16
    ca_payload.extend_from_slice(&2.5f32.to_le_bytes()); // BitOffs=16: KpGain = 2.5
    ca_payload.extend_from_slice(&(-40i16).to_le_bytes()); // BitOffs=48: FeedForward = -40
    let f_ca = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 3, 0x31, 0x2010, 0, &ca_payload);
    let d_ca = session.dissect_next(&f_ca).unwrap();
    let subitems = d_ca.datagrams[0].mailbox.as_ref().unwrap().protocol["sdo_xml"]["subitems"]
        .as_array()
        .unwrap();
    assert_eq!(subitems.len(), 3);
    assert_eq!(subitems[1]["name"], "KpGain");
    assert_eq!(subitems[1]["value"], 2.5);
    assert_eq!(subitems[2]["name"], "FeedForward");
    assert_eq!(subitems[2]["value"], -40);

    // 4. Multi-packet Segmented SDO Download on 0x1008:00 ("AX5101-ServoDrv!", 16 bytes)
    //    Includes Master-NIC TX (wkc=0) + returning RX echo (wkc=1) duplicate protection!
    let init_dl = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        0,
        4,
        0x21, // Initiate Download, size_indicated=1
        0x1008,
        0,
        &16u32.to_le_bytes(),
    );
    let init_dl_echo =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 4, 0x21, 0x1008, 0, &16u32.to_le_bytes());
    assert!(session.dissect_next(&init_dl).is_ok());
    assert!(session.dissect_next(&init_dl_echo).is_ok());

    let make_dl_seg = |cnt: u8, wkc: u16, toggle: bool, last: bool, chunk: &[u8]| -> Vec<u8> {
        let unused = (7 - chunk.len()) as u8;
        let hdr = ((toggle as u8) << 4) | ((unused & 0x07) << 1) | (last as u8);
        let mut padded = [0u8; 7];
        padded[..chunk.len()].copy_from_slice(chunk);
        let coe_len = 2 + 1 + 7;
        let mut mbx = Vec::with_capacity(16);
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&(0x2000u16).to_le_bytes());
        mbx.push(hdr);
        mbx.extend_from_slice(&padded);
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fpwr, cnt, 0x1001, 0x1000, mbx);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    // Seg 1 (7B): "AX5101-" sent (wkc=0) + ring echo (wkc=1)
    let seg1_tx = make_dl_seg(5, 0, false, false, b"AX5101-");
    let seg1_rx = make_dl_seg(5, 1, false, false, b"AX5101-");
    session.dissect_next(&seg1_tx).unwrap();
    session.dissect_next(&seg1_rx).unwrap();
    // Seg 2 (7B): "ServoDr"
    let seg2_tx = make_dl_seg(6, 0, true, false, b"ServoDr");
    session.dissect_next(&seg2_tx).unwrap();
    // Seg 3 (2B, last=true): "v!"
    let seg3_tx = make_dl_seg(7, 0, false, true, b"v!");
    let d_seg_done = session.dissect_next(&seg3_tx).unwrap();
    assert_eq!(
        d_seg_done.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "AX5101-ServoDrv!"
    );

    // 5. Multi-packet Segmented SDO Upload on 0x100A:00 ("FW-v4.62.109", 12 bytes)
    let ul_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x40, 0x100A, 0, &[0; 4]);
    let ul_init_resp =
        build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 2, 0x41, 0x100A, 0, &12u32.to_le_bytes());
    session.dissect_next(&ul_req).unwrap();
    session.dissect_next(&ul_init_resp).unwrap();

    let make_ul_seg_resp = |cnt: u8, toggle: bool, last: bool, chunk: &[u8]| -> Vec<u8> {
        let unused = (7 - chunk.len()) as u8;
        let hdr = ((toggle as u8) << 4) | ((unused & 0x07) << 1) | (last as u8);
        let mut padded = [0u8; 7];
        padded[..chunk.len()].copy_from_slice(chunk);
        let coe_len = 2 + 1 + 7;
        let mut mbx = Vec::with_capacity(16);
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&(0x3000u16).to_le_bytes());
        mbx.push(hdr);
        mbx.extend_from_slice(&padded);
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fprd, cnt, 0x1001, 0x1080, mbx);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    session
        .dissect_next(&make_ul_seg_resp(3, false, false, b"FW-v4.6"))
        .unwrap();
    let d_ul_done = session
        .dissect_next(&make_ul_seg_resp(4, true, true, b"2.109"))
        .unwrap();
    assert_eq!(
        d_ul_done.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "FW-v4.62.109"
    );

    // 6. CoE-over-AoE (IndexGroup == 0xF302) XML SDO resolution inside AMS/TCP 48898
    let mut ads_coe = Vec::new();
    ads_coe.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    ads_coe.extend_from_slice(&0x6060_0000u32.to_le_bytes()); // index 0x6060, sub 0
    ads_coe.extend_from_slice(&1u32.to_le_bytes());
    ads_coe.push(9u8); // CSV (9)
    let ams_coe_inner = build_ams_pdu(
        [5, 12, 34, 56, 2, 1],
        0x1001,
        [192, 168, 1, 10, 1, 1],
        32905,
        0x0003,
        0x0004,
        0,
        202,
        &ads_coe,
    );
    let mut ams_tcp = Vec::new();
    ams_tcp.extend_from_slice(&0u16.to_le_bytes());
    ams_tcp.extend_from_slice(&(ams_coe_inner.len() as u32).to_le_bytes());
    ams_tcp.extend_from_slice(&ams_coe_inner);
    let f_aoe_coe = build_ipv4_tcp_frame(52000, TCP_PORT_AMS, &ams_tcp);
    let d_aoe_coe = session.dissect_next(&f_aoe_coe).unwrap();
    assert_eq!(
        d_aoe_coe.wireshark_fields["ams.coe.sdo.xml.entry_name"],
        "ModesOfOperation"
    );
    assert_eq!(
        d_aoe_coe.wireshark_fields["ams.coe.sdo.xml.enum_text"],
        "Cyclic Synchronous Velocity (CSV)"
    );

    // 7. Standalone `<EtherCATDict>` Offline OD XML parsing + UTF-16LE BOM decoding
    let dict_xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<EtherCATDict>
  <Dictionary>
    <DataTypes>
      <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
    </DataTypes>
    <Objects>
      <Object><Index>#x2200</Index><Name>BusVoltageMv</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
    </Objects>
  </Dictionary>
</EtherCATDict>"#;
    let mut utf16le_bytes = vec![0xFF, 0xFE];
    for u in dict_xml.encode_utf16() {
        utf16le_bytes.extend_from_slice(&u.to_le_bytes());
    }
    let dict_cat = Arc::new(XmlCatalog::parse_xml_bytes(&utf16le_bytes).unwrap());
    let f_dict = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        1,
        0x2B,
        0x2200,
        0,
        &24_000u16
            .to_le_bytes()
            .iter()
            .copied()
            .chain([0, 0])
            .collect::<Vec<_>>(),
    );
    let d_dict = dissect_frame(
        &f_dict,
        &DissectOptions {
            xml_catalog: Some(dict_cat),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        d_dict.wireshark_fields["ecat_mailbox.coe.sdo.xml.entry_name"],
        "BusVoltageMv"
    );
    assert_eq!(
        d_dict.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        24_000
    );
}

#[test]
fn temporal_stateful_xml_pdo_pre_config_post_config_fmmu_and_reconfig() {
    let cat = Arc::new(XmlCatalog::parse_xml_str(SERVO_ESI_XML).unwrap());
    let mut session = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });

    let make_lrw = |lad: u32, wkc: u16, payload: Vec<u8>| -> Vec<u8> {
        let mut dg = RawDatagram::new_logical(EcatCmd::Lrw, 10, lad, payload);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };
    let make_reg_write = |cmd: EcatCmd, adp: u16, ado: u16, data: Vec<u8>| -> Vec<u8> {
        let mut dg = RawDatagram::new_positioned(cmd, 1, adp, ado, data);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    // =========================================================================
    // PHASE 1: BEFORE PDO CONFIGURATION — ZERO XML PDO DECODING MUST OCCUR!
    // =========================================================================
    let pre_frames = [
        make_lrw(
            0x0001_0000,
            0,
            vec![0x0F, 0x00, 0x10, 0x27, 0x00, 0x00, 0x01, 0x08],
        ),
        make_lrw(
            0x0001_0000,
            3,
            vec![0x37, 0x16, 0x20, 0x4E, 0x00, 0x00, 0x5C, 0xFE],
        ),
        {
            let mut dg = RawDatagram::new_logical(EcatCmd::Lwr, 11, 0x0001_0000, vec![1; 8]);
            dg.wkc = 1;
            let mut b = EcatFrameBuilder::new();
            b.add_datagram(dg);
            b.build().unwrap()
        },
        {
            let mut dg = RawDatagram::new_logical(EcatCmd::Lrd, 12, 0x0001_0000, vec![2; 8]);
            dg.wkc = 1;
            let mut b = EcatFrameBuilder::new();
            b.add_datagram(dg);
            b.build().unwrap()
        },
        make_reg_write(EcatCmd::Fpwr, 0x1001, 0x1100, vec![0x0F, 0x00, 1, 2, 3, 4]),
        {
            let mut dg = RawDatagram::new_positioned(
                EcatCmd::Fprd,
                13,
                0x1001,
                0x1400,
                vec![0x37, 0x16, 0, 0, 0, 0, 0, 0],
            );
            dg.wkc = 1;
            let mut b = EcatFrameBuilder::new();
            b.add_datagram(dg);
            b.build().unwrap()
        },
    ];
    for (idx, raw) in pre_frames.iter().enumerate() {
        let df = session.dissect_next(raw).unwrap();
        assert!(
            df.datagrams[0].pdo_fields.is_none(),
            "Pre-configuration packet #{idx} MUST NOT decode XML PDO fields!"
        );
        assert!(
            !df.wireshark_fields.keys().any(|k| k.contains(".pdo.")),
            "Pre-configuration packet #{idx} leaked ecat.pdo.* field!"
        );
    }

    // =========================================================================
    // PHASE 2: TEMPORAL PDO CONFIGURATION SEQUENCE IN PACKET STREAM
    // =========================================================================
    // Assign Slave 1 Configured Station Address = 0x1001
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Apwr,
            0x0000,
            0x0010,
            0x1001u16.to_le_bytes().to_vec(),
        ))
        .unwrap();

    let sdo_u8 = |cnt: u8, idx: u16, sub: u8, v: u8| {
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, cnt, 0x2F, idx, sub, &[v, 0, 0, 0])
    };
    let sdo_u16 = |cnt: u8, idx: u16, sub: u8, v: u16| {
        let b = v.to_le_bytes();
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, cnt, 0x2B, idx, sub, &[b[0], b[1], 0, 0])
    };
    let sdo_u32 = |cnt: u8, idx: u16, sub: u8, v: u32| {
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, cnt, 0x23, idx, sub, &v.to_le_bytes())
    };

    // Clear 0x1C12 & 0x1600
    session.dissect_next(&sdo_u8(1, 0x1C12, 0, 0)).unwrap();
    session.dissect_next(&sdo_u8(2, 0x1600, 0, 0)).unwrap();

    // Cyclic LRW while 0x1C12:00 == 0 (in-progress configuration) MUST still NOT decode!
    let mid_cfg_df = session
        .dissect_next(&make_lrw(0x0001_0000, 0, vec![0xFF; 8]))
        .unwrap();
    assert!(mid_cfg_df.datagrams[0].pdo_fields.is_none());

    // Dynamically map 0x1600 (64 bits = 8 bytes):
    //   sub1: 0x6040:00 (16b Controlword)
    //   sub2: 0x607A:00 (32b TargetPosition, signed DINT)
    //   sub3: 0x7000:01 (1b EnableLatch BOOL at bit 48)
    //   sub4: 0x7000:02 (1b ResetFault BOOL at bit 49)
    //   sub5: 0x0000:00 (6b Padding at bits 50..55)
    //   sub6: 0x6060:00 (8b ModesOfOperation enum at bits 56..63)
    let map1 = session
        .dissect_next(&sdo_u32(3, 0x1600, 1, 0x6040_0010))
        .unwrap();
    // Verify PDO configuration SDO annotation is emitted!
    assert!(
        !map1.datagrams[0].mailbox.as_ref().unwrap().protocol["sdo_xml"]["pdo_annotations"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    session
        .dissect_next(&sdo_u32(4, 0x1600, 2, 0x607A_0020))
        .unwrap();
    session
        .dissect_next(&sdo_u32(5, 0x1600, 3, 0x7000_0101))
        .unwrap();
    session
        .dissect_next(&sdo_u32(6, 0x1600, 4, 0x7000_0201))
        .unwrap();
    session
        .dissect_next(&sdo_u32(7, 0x1600, 5, 0x0000_0006))
        .unwrap();
    session
        .dissect_next(&sdo_u32(1, 0x1600, 6, 0x6060_0008))
        .unwrap();
    session.dissect_next(&sdo_u8(2, 0x1600, 0, 6)).unwrap();

    // Commit RxPDO assignment 0x1C12 = [0x1600]
    session
        .dissect_next(&sdo_u16(3, 0x1C12, 1, 0x1600))
        .unwrap();
    session.dissect_next(&sdo_u8(4, 0x1C12, 0, 1)).unwrap();

    // Commit TxPDO assignment 0x1C13 = [0x1A00] via Complete Access (CA=1, sub0=1, sub1=0x1A00)
    let mut ca_1c13 = Vec::new();
    ca_1c13.extend_from_slice(&4u32.to_le_bytes()); // 4B payload
    ca_1c13.extend_from_slice(&1u16.to_le_bytes()); // count = 1 (padded to 16b in 0x1C13 CA)
    ca_1c13.extend_from_slice(&0x1A00u16.to_le_bytes());
    session
        .dissect_next(&build_coe_sdo_mbx_frame(
            0x1001, 0x1000, 1, 5, 0x31, 0x1C13, 0, &ca_1c13,
        ))
        .unwrap();

    // Configure ESC SM2 (0x0810), SM3 (0x0818), FMMU0 (0x0600), FMMU1 (0x0610),
    // AND TwinCAT FMMU2 (0x0620 -> 0x080D mailbox state polling, NOT process data!)
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0810,
            vec![0x00, 0x11, 8, 0, 0x64, 0x00, 0x01, 0x00],
        ))
        .unwrap();
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0818,
            vec![0x00, 0x14, 8, 0, 0x20, 0x00, 0x01, 0x00],
        ))
        .unwrap();
    let make_fmmu = |lstart: u32, llen: u16, pstart: u16, pbit: u8, rw: u8| -> Vec<u8> {
        let mut f = vec![0u8; 16];
        f[0..4].copy_from_slice(&lstart.to_le_bytes());
        f[4..6].copy_from_slice(&llen.to_le_bytes());
        f[6] = 0;
        f[7] = 7;
        f[8..10].copy_from_slice(&pstart.to_le_bytes());
        f[10] = pbit;
        f[11] = rw;
        f[12] = 0x01;
        f
    };
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0600,
            make_fmmu(0x0001_0000, 8, 0x1100, 0, 0x02),
        ))
        .unwrap();
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0610,
            make_fmmu(0x0001_0000, 8, 0x1400, 0, 0x01),
        ))
        .unwrap();
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0620,
            make_fmmu(0x0002_0000, 1, 0x080D, 3, 0x01),
        ))
        .unwrap();

    // =========================================================================
    // PHASE 3: AFTER PDO CONFIGURATION — FULL BIT-EXACT XML PDO DISSECTION!
    // =========================================================================
    // Outgoing LRW (`wkc == 0`) carries Master -> Slave RxPDO:
    //   Controlword = 0x000F, TargetPosition = -98_765, EnableLatch = true (bit 0),
    //   ResetFault = false (bit 1), 6b pad = 0, ModesOfOperation = 8 (CSP)
    let mut rx_payload = Vec::with_capacity(8);
    rx_payload.extend_from_slice(&0x000Fu16.to_le_bytes());
    rx_payload.extend_from_slice(&(-98_765i32).to_le_bytes());
    rx_payload.push(0x01); // bit0=1 (EnableLatch), bit1=0 (ResetFault), bits2..7=0 (6b pad)
    rx_payload.push(8u8); // ModesOfOperation = 8 (CSP)

    let df_rx = session
        .dissect_next(&make_lrw(0x0001_0000, 0, rx_payload))
        .unwrap();
    let rx_fields = df_rx.datagrams[0].pdo_fields.as_ref().unwrap();
    assert_eq!(rx_fields.len(), 5, "6-bit padding entry must be skipped!");
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.0x6040:00"], 0x000F);
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.Controlword"], 0x000F);
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.TargetPosition"], -98_765);
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.EnableLatch"], true);
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.ResetFault"], false);
    assert_eq!(df_rx.wireshark_fields["ecat.pdo.ModesOfOperation"], 8);
    assert_eq!(
        df_rx.wireshark_fields["ecat.pdo.ModesOfOperation.enum"],
        "Cyclic Synchronous Position (CSP)"
    );
    assert!(!df_rx.wireshark_fields.contains_key("ecat.pdo.Statusword"));

    // Returning LRW (`wkc == 3`) carries Slave -> Master TxPDO:
    //   Statusword = 0x1637, ActualPosition = -98_760, ActualTorque = -420
    let mut tx_payload = Vec::with_capacity(8);
    tx_payload.extend_from_slice(&0x1637u16.to_le_bytes());
    tx_payload.extend_from_slice(&(-98_760i32).to_le_bytes());
    tx_payload.extend_from_slice(&(-420i16).to_le_bytes());
    let df_tx = session
        .dissect_next(&make_lrw(0x0001_0000, 3, tx_payload))
        .unwrap();
    assert_eq!(df_tx.wireshark_fields["ecat.pdo.Statusword"], 0x1637);
    assert_eq!(df_tx.wireshark_fields["ecat.pdo.ActualPosition"], -98_760);
    assert_eq!(df_tx.wireshark_fields["ecat.pdo.ActualTorque"], -420);

    // Polling TwinCAT FMMU2 (`0x00020000` -> ESC `0x080D` mailbox state) MUST NOT decode as TxPDO!
    let mut lrd_mbx_poll = RawDatagram::new_logical(EcatCmd::Lrd, 20, 0x0002_0000, vec![0x01]);
    lrd_mbx_poll.wkc = 1;
    let mut b_poll = EcatFrameBuilder::new();
    b_poll.add_datagram(lrd_mbx_poll);
    let df_poll = session.dissect_next(&b_poll.build().unwrap()).unwrap();
    assert!(df_poll.datagrams[0].pdo_fields.is_none());

    // =========================================================================
    // PHASE 4: MID-STREAM RECONFIGURATION (`0x1600` -> `0x1601` Velocity RxPDO)
    //          + MULTI-SLAVE COMBINED LOGICAL WINDOW
    // =========================================================================
    // Clear Slave 1 RxPDO (`0x1C12:00 = 0`) -> LRW must temporarily stop decoding RxPDO!
    session.dissect_next(&sdo_u8(6, 0x1C12, 0, 0)).unwrap();
    let df_cleared = session
        .dissect_next(&make_lrw(0x0001_0000, 0, vec![0xAA; 8]))
        .unwrap();
    assert!(df_cleared.datagrams[0].pdo_fields.is_none());

    // Assign `0x1601` (Velocity RxPDO: Controlword 16b + TargetVelocity 32b = 6B) to Slave 1
    session
        .dissect_next(&sdo_u16(7, 0x1C12, 1, 0x1601))
        .unwrap();
    session.dissect_next(&sdo_u8(1, 0x1C12, 0, 1)).unwrap();
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1001,
            0x0600,
            make_fmmu(0x0001_0000, 6, 0x1100, 0, 0x02),
        ))
        .unwrap();

    // Configure Slave 2 (`station = 0x1002`) with `0x1602` -> `0x7010:00` (`DigitalOutputs: UDINT`, 4B) at `0x00010006`
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Apwr,
            0xFFFF,
            0x0010,
            0x1002u16.to_le_bytes().to_vec(),
        ))
        .unwrap();
    let sdo2_u8 = |cnt: u8, idx: u16, sub: u8, v: u8| {
        build_coe_sdo_mbx_frame(0x1002, 0x1000, 1, cnt, 0x2F, idx, sub, &[v, 0, 0, 0])
    };
    let sdo2_u16 = |cnt: u8, idx: u16, sub: u8, v: u16| {
        let b = v.to_le_bytes();
        build_coe_sdo_mbx_frame(0x1002, 0x1000, 1, cnt, 0x2B, idx, sub, &[b[0], b[1], 0, 0])
    };
    let sdo2_u32 = |cnt: u8, idx: u16, sub: u8, v: u32| {
        build_coe_sdo_mbx_frame(0x1002, 0x1000, 1, cnt, 0x23, idx, sub, &v.to_le_bytes())
    };
    session.dissect_next(&sdo2_u8(1, 0x1C12, 0, 0)).unwrap();
    session.dissect_next(&sdo2_u8(2, 0x1602, 0, 0)).unwrap();
    session
        .dissect_next(&sdo2_u32(3, 0x1602, 1, 0x7010_0020))
        .unwrap();
    session.dissect_next(&sdo2_u8(4, 0x1602, 0, 1)).unwrap();
    session
        .dissect_next(&sdo2_u16(5, 0x1C12, 1, 0x1602))
        .unwrap();
    session.dissect_next(&sdo2_u8(6, 0x1C12, 0, 1)).unwrap();
    session
        .dissect_next(&make_reg_write(
            EcatCmd::Fpwr,
            0x1002,
            0x0600,
            make_fmmu(0x0001_0006, 4, 0x1100, 0, 0x02),
        ))
        .unwrap();

    // Combined 10-byte LRW (`0x00010000..0x0001000A`):
    //   Bytes 0..6: Slave 1 `0x1601` (Controlword=0x001F, TargetVelocity=250_000)
    //   Bytes 6..10: Slave 2 `0x1602` (DigitalOutputs=0xCAFE_BABE)
    let mut combined_lrw = Vec::with_capacity(10);
    combined_lrw.extend_from_slice(&0x001Fu16.to_le_bytes());
    combined_lrw.extend_from_slice(&250_000i32.to_le_bytes());
    combined_lrw.extend_from_slice(&0xCAFE_BABEu32.to_le_bytes());
    let df_multi = session
        .dissect_next(&make_lrw(0x0001_0000, 0, combined_lrw))
        .unwrap();
    assert_eq!(df_multi.wireshark_fields["ecat.pdo.Controlword"], 0x001F);
    assert_eq!(
        df_multi.wireshark_fields["ecat.pdo.TargetVelocity"],
        250_000
    );
    assert_eq!(
        df_multi.wireshark_fields["ecat.pdo.DigitalOutputs"],
        0xCAFE_BABEu64
    );
    assert!(!df_multi
        .wireshark_fields
        .contains_key("ecat.pdo.TargetPosition"));
}

#[test]
fn edge_cases_malformed_truncated_stateless_and_eni_bootstrap() {
    // 1. Empty / truncated / non-EtherCAT boundary inputs
    assert!(dissect_frame(&[], &DissectOptions::default()).is_err());
    assert!(dissect_frame(&[0xFF; 13], &DissectOptions::default()).is_err());
    assert!(dissect_frame(
        &[0x00],
        &DissectOptions {
            bare_ecat: true,
            ..Default::default()
        }
    )
    .is_err());

    // Malformed mailbox header (`mbx_len = 500 > payload.len()`) sets `ecat_mailbox.invalid = true` without panicking
    let mut bad_mbx = vec![0u8; 16];
    bad_mbx[0..2].copy_from_slice(&500u16.to_le_bytes());
    bad_mbx[5] = 0x13;
    let f_bad_mbx = build_eth_ecat_frame(ECAT_FRAME_TYPE_MAILBOX, &bad_mbx);
    let d_bad = dissect_frame(&f_bad_mbx, &DissectOptions::default()).unwrap();
    assert_eq!(d_bad.wireshark_fields["ecat_mailbox.invalid"], true);

    // 2. Stateless `dissect_frame` with `xml_catalog`: enriches single-frame SDO, refuses unconfigured XML PDO
    let cat = Arc::new(XmlCatalog::parse_xml_str(SERVO_ESI_XML).unwrap());
    let stateless_opts = DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    };
    let sdo_pkt = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        1,
        0x2B,
        0x6040,
        0,
        &[0x0F, 0x00, 0x00, 0x00],
    );
    let df_sdo = dissect_frame(&sdo_pkt, &stateless_opts).unwrap();
    assert_eq!(
        df_sdo.wireshark_fields["ecat_mailbox.coe.sdo.xml.entry_name"],
        "Controlword"
    );
    assert_eq!(
        df_sdo.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        15
    );

    let mut lrw_dg = RawDatagram::new_logical(EcatCmd::Lrw, 1, 0x0001_0000, vec![0x0F; 8]);
    lrw_dg.wkc = 0;
    let mut b_lrw = EcatFrameBuilder::new();
    b_lrw.add_datagram(lrw_dg);
    let df_stateless_pdo = dissect_frame(&b_lrw.build().unwrap(), &stateless_opts).unwrap();
    assert!(df_stateless_pdo.datagrams[0].pdo_fields.is_none());

    // 3. ETG.2100 ENI `<EtherCATConfig>` temporal activation:
    //    Pre-activation LRW is NOT decoded; after ESC SM2 `0x0810` activation in the trace,
    //    fixed ENI `<ProcessData>` bit offsets are activated and decoded!
    let eni_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATConfig>
  <Config>
    <Slave>
      <Info>
        <Name>Drive1</Name>
        <PhysAddr>4097</PhysAddr>
        <VendorId>2</VendorId>
        <ProductCode>#x13ED3052</ProductCode>
      </Info>
      <ProcessData>
        <Send>
          <BitStart>16</BitStart>
          <BitLength>32</BitLength>
        </Send>
        <Sm2>
          <Type>Outputs</Type>
          <StartAddress>4352</StartAddress>
          <Pdo>
            <Index>#x1600</Index>
            <Name>EniOutputs</Name>
            <Entry>
              <Index>#x607A</Index>
              <SubIndex>0</SubIndex>
              <BitLen>32</BitLen>
              <Name>EniTargetPos</Name>
              <DataType>DINT</DataType>
            </Entry>
          </Pdo>
        </Sm2>
      </ProcessData>
    </Slave>
  </Config>
</EtherCATConfig>"#;
    let eni_cat = Arc::new(XmlCatalog::parse_xml_str(eni_xml).unwrap());
    let mut eni_session = DissectSession::new(DissectOptions {
        xml_catalog: Some(eni_cat),
        ..Default::default()
    });

    // Before SM2 config packet: LRW is NOT decoded
    let mut pre_eni_dg = RawDatagram::new_logical(EcatCmd::Lrw, 1, 0x0000_0000, vec![0xAA; 8]);
    pre_eni_dg.wkc = 0;
    let mut b_pre = EcatFrameBuilder::new();
    b_pre.add_datagram(pre_eni_dg);
    assert!(eni_session
        .dissect_next(&b_pre.build().unwrap())
        .unwrap()
        .datagrams[0]
        .pdo_fields
        .is_none());

    // Activate SM2 (`0x0810`) on station `4097` (`0x1001`)
    let mut sm2_dg = RawDatagram::new_positioned(
        EcatCmd::Fpwr,
        2,
        0x1001,
        0x0810,
        vec![0x00, 0x11, 4, 0, 0x64, 0x00, 0x01, 0x00],
    );
    sm2_dg.wkc = 1;
    let mut b_sm2 = EcatFrameBuilder::new();
    b_sm2.add_datagram(sm2_dg);
    eni_session.dissect_next(&b_sm2.build().unwrap()).unwrap();

    // Post-config LRW: ENI `<BitStart>16</BitStart>` decodes `EniTargetPos` starting at byte 2!
    let mut post_payload = vec![0xFF, 0xFF]; // 16-bit prefix before BitStart=16
    post_payload.extend_from_slice(&(-77_777i32).to_le_bytes());
    let mut post_eni_dg = RawDatagram::new_logical(EcatCmd::Lrw, 3, 0x0000_0000, post_payload);
    post_eni_dg.wkc = 0;
    let mut b_post = EcatFrameBuilder::new();
    b_post.add_datagram(post_eni_dg);
    let df_post_eni = eni_session.dissect_next(&b_post.build().unwrap()).unwrap();
    assert_eq!(
        df_post_eni.wireshark_fields["ecat.pdo.EniTargetPos"],
        -77_777
    );

    // 4. ESL 16-byte Trailer + 4-byte trailing Ethernet FCS:
    //    `padding_bytes` must NOT leak `ESL_SIGNATURE` bytes into `ecat.subframe.pad_bytes`!
    let mut b_esl_fcs = EcatFrameBuilder::new();
    b_esl_fcs.pad_to_min_ethernet = false;
    let mut dg_nop = RawDatagram::new_positioned(EcatCmd::Nop, 1, 0x0000, 0x0000, vec![0x11; 32]);
    dg_nop.wkc = 0;
    b_esl_fcs.add_datagram(dg_nop);
    let mut esl_trailer_fcs_pkt = b_esl_fcs.build().unwrap();
    esl_trailer_fcs_pkt.extend_from_slice(&ESL_SIGNATURE);
    esl_trailer_fcs_pkt.push(0x03); // port 0+1
    esl_trailer_fcs_pkt.push(0x00); // align error = false, crc error = false
    esl_trailer_fcs_pkt.extend_from_slice(&987_654_321u64.to_le_bytes());
    esl_trailer_fcs_pkt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // 4B Ethernet FCS
    let df_esl_fcs = dissect_frame(&esl_trailer_fcs_pkt, &DissectOptions::default()).unwrap();
    assert_eq!(df_esl_fcs.esl.as_ref().unwrap().position, "trailer");
    assert_eq!(df_esl_fcs.padding_bytes, 0);
    assert!(
        !df_esl_fcs
            .wireshark_fields
            .contains_key("ecat.subframe.pad_bytes"),
        "ESL signature bytes must never leak into ecat.subframe.pad_bytes"
    );

    // 5. CoE SDO Block Download (`ccs=6`/`scs=5`) & Block Upload (`ccs=5`/`scs=6`),
    //    including raw sub-block `0x81` (`seq=1, last=true` echoed TX `wkc=0` + RX `wkc=1`),
    //    `reassembled_data` without `--xml`, XML `sdo.xml.*` enrichment, and temporal PDO activation!
    let build_raw_coe_mbx = |cmd_op: EcatCmd,
                             station: u16,
                             ado: u16,
                             wkc: u16,
                             cnt: u8,
                             svc: u8,
                             coe_payload: &[u8]| {
        let coe_len = 2 + coe_payload.len();
        let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&station.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&(((svc as u16) & 0x0F) << 12).to_le_bytes());
        mbx.extend_from_slice(coe_payload);
        if mbx.len() < 16 {
            mbx.resize(16, 0);
        }
        let mut dg = RawDatagram::new_positioned(cmd_op, cnt, station, ado, mbx);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    let blk_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x22223052" RevisionNo="#x00010000">BlkDrive</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1" CompleteAccess="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x24" Enable="1">Outputs</Sm>
        <RxPdo Sm="2" Mandatory="1" Fixed="0">
          <Index>#x1600</Index>
          <Name>Outputs</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>BlkCtrl</Name>
            <DataType>UINT</DataType>
          </Entry>
        </RxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
              <DataType><Name>USINT</Name><BitSize>8</BitSize></DataType>
              <DataType><Name>STRING(16)</Name><BitSize>128</BitSize></DataType>
              <DataType>
                <Name>DT1C12</Name>
                <BitSize>32</BitSize>
                <SubItem><SubIdx>0</SubIdx><Name>Count</Name><Type>USINT</Type><BitSize>8</BitSize><BitOffs>0</BitOffs></SubItem>
                <SubItem><SubIdx>1</SubIdx><Name>Pdo1</Name><Type>UINT</Type><BitSize>16</BitSize><BitOffs>16</BitOffs></SubItem>
              </DataType>
            </DataTypes>
            <Objects>
              <Object>
                <Index>#x1008</Index>
                <Name>Device_Name</Name>
                <Type>STRING(16)</Type>
                <BitSize>128</BitSize>
              </Object>
              <Object>
                <Index>#x1C12</Index>
                <Name>RxPDO_Assign</Name>
                <Type>DT1C12</Type>
                <BitSize>32</BitSize>
              </Object>
              <Object>
                <Index>#x6040</Index>
                <Name>BlkCtrl</Name>
                <Type>UINT</Type>
                <BitSize>16</BitSize>
              </Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let blk_cat = Arc::new(XmlCatalog::parse_xml_str(blk_xml).unwrap());
    let mut blk_sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(blk_cat),
        ..Default::default()
    });
    let mut blk_no_xml_sess = DissectSession::new(DissectOptions::default());

    // Configure FMMU0 + SM2 on 0x1001, then Block Download CA `0x1C12:0` = `[0x01, 0x00, 0x00, 0x16]`
    let mut fmmu_blk = vec![0u8; 16];
    fmmu_blk[0..4].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    fmmu_blk[4..6].copy_from_slice(&2u16.to_le_bytes());
    fmmu_blk[7] = 7;
    fmmu_blk[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu_blk[11] = 0x02;
    fmmu_blk[12] = 0x01;
    let mut dg_fb = RawDatagram::new_positioned(EcatCmd::Fpwr, 1, 0x1001, 0x0600, fmmu_blk);
    dg_fb.wkc = 1;
    let mut sm2_blk = vec![0u8; 8];
    sm2_blk[0..2].copy_from_slice(&0x1100u16.to_le_bytes());
    sm2_blk[2..4].copy_from_slice(&2u16.to_le_bytes());
    sm2_blk[4] = 0x24;
    sm2_blk[6] = 0x01;
    let mut dg_sb = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0810, sm2_blk);
    dg_sb.wkc = 1;
    let mut b_cfg_blk = EcatFrameBuilder::new();
    b_cfg_blk.add_datagram(dg_fb);
    b_cfg_blk.add_datagram(dg_sb);
    let cfg_blk_pkt = b_cfg_blk.build().unwrap();
    blk_sess.dissect_next(&cfg_blk_pkt).unwrap();

    // Initiate Block Download CA (`cmd = 0xD6`: ccs=6, CA=1, CRC=1, size_ind=1, cs=0), size = 4
    let init_dl = build_raw_coe_mbx(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        1,
        0x02,
        &[0xD6, 0x12, 0x1C, 0x00, 4, 0, 0, 0],
    );
    let df_init_dl = blk_sess.dissect_next(&init_dl).unwrap();
    blk_no_xml_sess.dissect_next(&init_dl).unwrap();
    assert_eq!(
        df_init_dl.wireshark_fields["ecat_mailbox.coe.sdo.xml.object_name"],
        "RxPDO_Assign"
    );

    let init_dl_res = build_raw_coe_mbx(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        1,
        0x03,
        &[0xA4, 0x12, 0x1C, 0x00, 16],
    );
    blk_sess.dissect_next(&init_dl_res).unwrap();
    blk_no_xml_sess.dissect_next(&init_dl_res).unwrap();

    // Sub-block `0x81` (`seq=1, last=true`), echoed TX (`wkc=0`) then RX (`wkc=1`):
    // Previously `0x81` was misclassified as `Abort Transfer` (`(0x81 >> 5) & 7 == 4`)!
    let sub_dl_tx = build_raw_coe_mbx(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        0,
        2,
        0x02,
        &[0x81, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00],
    );
    let sub_dl_rx = build_raw_coe_mbx(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        2,
        0x02,
        &[0x81, 0x01, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00],
    );
    for pkt in [&sub_dl_tx, &sub_dl_rx] {
        let df_sub = blk_sess.dissect_next(pkt).unwrap();
        blk_no_xml_sess.dissect_next(pkt).unwrap();
        assert_eq!(df_sub.wireshark_fields["ecat_mailbox.coe.sdoblk.seqno"], 1);
        assert_eq!(
            df_sub.wireshark_fields["ecat_mailbox.coe.sdoblk.last"],
            true
        );
        assert!(!df_sub
            .wireshark_fields
            .contains_key("ecat_mailbox.coe.abortcode"));
    }

    let ack_dl = build_raw_coe_mbx(EcatCmd::Fprd, 0x1001, 0x1080, 1, 2, 0x03, &[0xA2, 1, 16]);
    blk_sess.dissect_next(&ack_dl).unwrap();
    blk_no_xml_sess.dissect_next(&ack_dl).unwrap();

    // End Block Download (`cmd = 0xCD`: ccs=6, unused=3, cs=1)
    let end_dl = build_raw_coe_mbx(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        3,
        0x02,
        &[0xCD, 0x34, 0x12],
    );
    let df_end_dl = blk_sess.dissect_next(&end_dl).unwrap();
    let df_end_no_xml = blk_no_xml_sess.dissect_next(&end_dl).unwrap();
    assert_eq!(
        df_end_no_xml.wireshark_fields["ecat_mailbox.coe.sdo.reassembled_data"],
        "01000016"
    );
    assert_eq!(
        df_end_dl.wireshark_fields["ecat_mailbox.coe.sdo.reassembled_data"],
        "01000016"
    );
    assert_eq!(
        df_end_dl.wireshark_fields["ecat_mailbox.coe.sdo.xml.device_name"],
        "BlkDrive"
    );
    assert_eq!(
        df_end_dl.wireshark_fields["ecat_mailbox.coe.sdo.xml.reassembled_len"],
        4
    );
    assert!(df_end_dl
        .wireshark_fields
        .contains_key("ecat_mailbox.coe.sdo.xml.subitems"));

    // Verify Block Download CA to `0x1C12` activated `0x1600` (`BlkCtrl`) temporally!
    let mut dg_blk_lrw = RawDatagram::new_logical(
        EcatCmd::Lrw,
        4,
        0x0002_0000,
        0x00AFu16.to_le_bytes().to_vec(),
    );
    dg_blk_lrw.wkc = 1;
    let mut b_blk_lrw = EcatFrameBuilder::new();
    b_blk_lrw.add_datagram(dg_blk_lrw);
    let df_blk_pdo = blk_sess.dissect_next(&b_blk_lrw.build().unwrap()).unwrap();
    assert_eq!(df_blk_pdo.wireshark_fields["ecat.pdo.BlkCtrl"], 0x00AF);

    // Also verify SDO Block Upload (`0x1008:0` -> `"Blocks-v4.6"`)
    let init_ul = build_raw_coe_mbx(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        4,
        0x02,
        &[0xA4, 0x08, 0x10, 0x00, 16, 0],
    );
    let init_ul_res = build_raw_coe_mbx(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        4,
        0x03,
        &[0xC6, 0x08, 0x10, 0x00, 11, 0, 0, 0],
    );
    let start_ul = build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, 5, 0x02, &[0xA3]);
    let sub_ul_1 = build_raw_coe_mbx(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        5,
        0x03,
        &[0x01, b'B', b'l', b'o', b'c', b'k', b's', b'-'],
    );
    let sub_ul_2 = build_raw_coe_mbx(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        6,
        0x03,
        &[0x82, b'v', b'4', b'.', b'6', 0, 0, 0],
    );
    let ack_ul = build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, 6, 0x02, &[0xA2, 2, 16]);
    let end_ul = build_raw_coe_mbx(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        7,
        0x03,
        &[0xCD, 0x78, 0x56],
    );
    for pkt in [
        &init_ul,
        &init_ul_res,
        &start_ul,
        &sub_ul_1,
        &sub_ul_2,
        &ack_ul,
    ] {
        blk_sess.dissect_next(pkt).unwrap();
    }
    let df_end_ul = blk_sess.dissect_next(&end_ul).unwrap();
    assert_eq!(
        df_end_ul.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "Blocks-v4.6"
    );

    // 6. Multi-channel non-CoE terminal (EL2004 4x1-bit) + Fixed read-only CoE ESI slave +
    //    sub-byte bit-level returning `LRW` (`wkc > 0`) + unanswered non-zero `FPRD` (`wkc == 0`) + `BWR` reset:
    let bit_pack_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x07D43052" RevisionNo="#x00100000">EL2004</Type>
        <Sm StartAddress="#x0F00" ControlByte="#x44" Enable="1">Outputs</Sm>
        <RxPdo Fixed="1" Sm="0"><Index>#x1600</Index><Name>Channel 1</Name><Entry><Index>#x7000</Index><SubIndex>1</SubIndex><BitLen>1</BitLen><Name>Ch1</Name><DataType>BOOL</DataType></Entry></RxPdo>
        <RxPdo Fixed="1" Sm="0"><Index>#x1601</Index><Name>Channel 2</Name><Entry><Index>#x7010</Index><SubIndex>1</SubIndex><BitLen>1</BitLen><Name>Ch2</Name><DataType>BOOL</DataType></Entry></RxPdo>
        <RxPdo Fixed="1" Sm="0"><Index>#x1602</Index><Name>Channel 3</Name><Entry><Index>#x7020</Index><SubIndex>1</SubIndex><BitLen>1</BitLen><Name>Ch3</Name><DataType>BOOL</DataType></Entry></RxPdo>
        <RxPdo Fixed="1" Sm="0"><Index>#x1603</Index><Name>Channel 4</Name><Entry><Index>#x7030</Index><SubIndex>1</SubIndex><BitLen>1</BitLen><Name>Ch4</Name><DataType>BOOL</DataType></Entry></RxPdo>
      </Device>
      <Device>
        <Type ProductCode="#x03EC3052" RevisionNo="#x00100000">FixedCoEIn</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="0" PdoConfig="0"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x20" Enable="1">Inputs</Sm>
        <TxPdo Fixed="1" Sm="2">
          <Index>#x1A00</Index>
          <Name>Inputs</Name>
          <Entry><Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>4</BitLen><Name>InNibble</Name><DataType>USINT</DataType></Entry>
        </TxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>USINT</Name><BitSize>8</BitSize></DataType>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
              <DataType><Name>UDINT</Name><BitSize>32</BitSize></DataType>
            </DataTypes>
            <Objects>
              <Object><Index>#x1C13</Index><Name>TxPDO Assign</Name><Type>UINT</Type><BitSize>16</BitSize><Flags><Access>ro</Access></Flags></Object>
              <Object><Index>#x1A00</Index><Name>TxPDO Map</Name><Type>UDINT</Type><BitSize>32</BitSize><Flags><Access>ro</Access></Flags></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let bit_cat = Arc::new(XmlCatalog::parse_xml_str(bit_pack_xml).unwrap());
    let mut bit_sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(bit_cat),
        ..Default::default()
    });

    // Discover station 0x1001 = EL2004 (`0x07D43052`) and station 0x1002 = FixedCoEIn (`0x03EC3052`) via SII EEPROM `0x0502..0x050F`!
    for (slot_auto, stadr, prod) in [
        (0u16, 0x1001u16, 0x07D4_3052u32),
        (1u16, 0x1002u16, 0x03EC_3052u32),
    ] {
        let adp = (0u16).wrapping_sub(slot_auto);
        let mut dg_st = RawDatagram::new_positioned(
            EcatCmd::Apwr,
            1,
            adp,
            0x0010,
            stadr.to_le_bytes().to_vec(),
        );
        dg_st.wkc = 1;
        let mut sii_cmd = vec![0x00, 0x01]; // read cmd (ctl = 0x0100)
        sii_cmd.extend_from_slice(&8u32.to_le_bytes()); // word 8 = VendorId + ProductCode (R64)
        let mut dg_sii_w = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, stadr, 0x0502, sii_cmd);
        dg_sii_w.wkc = 1;
        let mut sii_r = vec![0x40, 0x00, 0, 0, 0, 0]; // R64=1, busy=0 + 4B addr
        sii_r.extend_from_slice(&2u32.to_le_bytes()); // VendorId = 2
        sii_r.extend_from_slice(&prod.to_le_bytes()); // ProductCode
        let mut dg_sii_r = RawDatagram::new_positioned(EcatCmd::Fprd, 3, stadr, 0x0502, sii_r);
        dg_sii_r.wkc = 1;
        let mut b_id = EcatFrameBuilder::new();
        b_id.add_datagram(dg_st);
        b_id.add_datagram(dg_sii_w);
        b_id.add_datagram(dg_sii_r);
        bit_sess.dissect_next(&b_id.build().unwrap()).unwrap();
    }

    // Pre-FMMU LRW on 0x0001_0000 -> neither slave decoded!
    let mut dg_pre_bit = RawDatagram::new_logical(EcatCmd::Lrw, 1, 0x0001_0000, vec![0xA5]);
    dg_pre_bit.wkc = 3;
    let mut b_pre_bit = EcatFrameBuilder::new();
    b_pre_bit.add_datagram(dg_pre_bit);
    assert!(bit_sess
        .dissect_next(&b_pre_bit.build().unwrap())
        .unwrap()
        .datagrams[0]
        .pdo_fields
        .is_none());

    // Configure FMMU0 on 0x1001: logical `0x0001_0000` bits `0..=3` (write)
    // Configure FMMU0 on 0x1002: logical `0x0001_0000` bits `4..=7` (read)
    let mut fmmu_out = vec![0u8; 16];
    fmmu_out[0..4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fmmu_out[4..6].copy_from_slice(&1u16.to_le_bytes());
    fmmu_out[6] = 0; // start bit 0
    fmmu_out[7] = 3; // end bit 3
    fmmu_out[8..10].copy_from_slice(&0x0F00u16.to_le_bytes());
    fmmu_out[11] = 0x02; // write
    fmmu_out[12] = 0x01; // active
    let mut dg_fo = RawDatagram::new_positioned(EcatCmd::Fpwr, 1, 0x1001, 0x0600, fmmu_out);
    dg_fo.wkc = 1;

    let mut fmmu_in = vec![0u8; 16];
    fmmu_in[0..4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    fmmu_in[4..6].copy_from_slice(&1u16.to_le_bytes());
    fmmu_in[6] = 4; // start bit 4
    fmmu_in[7] = 7; // end bit 7
    fmmu_in[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu_in[11] = 0x01; // read
    fmmu_in[12] = 0x01; // active
    let mut dg_fi = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1002, 0x0600, fmmu_in);
    dg_fi.wkc = 1;
    let mut b_fcfg = EcatFrameBuilder::new();
    b_fcfg.add_datagram(dg_fo);
    b_fcfg.add_datagram(dg_fi);
    bit_sess.dissect_next(&b_fcfg.build().unwrap()).unwrap();

    // Unanswered `FPRD` (`wkc == 0`) at `0x0600` carrying non-zero stale TX buffer (`active = 0`)
    // MUST NOT clobber slave 0x1001's active FMMU shadow!
    let mut stale_fmmu = vec![0xFFu8; 16];
    stale_fmmu[12] = 0x00; // active = 0
    let mut dg_unans = RawDatagram::new_positioned(EcatCmd::Fprd, 3, 0x1001, 0x0600, stale_fmmu);
    dg_unans.wkc = 0;
    let mut b_unans = EcatFrameBuilder::new();
    b_unans.add_datagram(dg_unans);
    bit_sess.dissect_next(&b_unans.build().unwrap()).unwrap();

    // Returning `LRW` (`wkc = 3`) with byte `0xA5` (`0b1010_0101`):
    // Bits `0..=3` = `0b0101` (`Ch1=true, Ch2=false, Ch3=true, Ch4=false`) AND
    // Bits `4..=7` = `0x0A` (`InNibble = 10`) MUST BOTH decode without false byte-overlap suppression!
    let mut dg_post_bit = RawDatagram::new_logical(EcatCmd::Lrw, 4, 0x0001_0000, vec![0xA5]);
    dg_post_bit.wkc = 3;
    let mut b_post_bit = EcatFrameBuilder::new();
    b_post_bit.add_datagram(dg_post_bit);
    let df_post_bit = bit_sess.dissect_next(&b_post_bit.build().unwrap()).unwrap();
    assert_eq!(df_post_bit.wireshark_fields["ecat.pdo.Ch1"], true);
    assert_eq!(df_post_bit.wireshark_fields["ecat.pdo.Ch2"], false);
    assert_eq!(df_post_bit.wireshark_fields["ecat.pdo.Ch3"], true);
    assert_eq!(df_post_bit.wireshark_fields["ecat.pdo.Ch4"], false);
    assert_eq!(df_post_bit.wireshark_fields["ecat.pdo.InNibble"], 0x0A);

    // Broadcast `BWR` (`wkc = 2`) zeroing `0x0600` MUST deactivate both slaves' fixed PDO banks!
    let mut dg_bwr_clr =
        RawDatagram::new_positioned(EcatCmd::Bwr, 5, 0x0000, 0x0600, vec![0u8; 16]);
    dg_bwr_clr.wkc = 2;
    let mut b_bwr = EcatFrameBuilder::new();
    b_bwr.add_datagram(dg_bwr_clr);
    bit_sess.dissect_next(&b_bwr.build().unwrap()).unwrap();

    let mut dg_after_clr = RawDatagram::new_logical(EcatCmd::Lrw, 6, 0x0001_0000, vec![0xA5]);
    dg_after_clr.wkc = 3;
    let mut b_after_clr = EcatFrameBuilder::new();
    b_after_clr.add_datagram(dg_after_clr);
    assert!(bit_sess
        .dissect_next(&b_after_clr.build().unwrap())
        .unwrap()
        .datagrams[0]
        .pdo_fields
        .is_none());

    // 7. ENI `<Mailbox><CoE><InitCmds>` + `<ProcessData>` activation & real SOEM `sample-eni.xml`:
    let eni_coe_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATConfig>
  <Config>
    <Slave>
      <Info><Name>CoEDrive</Name><PhysAddr>4097</PhysAddr><VendorId>2</VendorId><ProductCode>#x44443052</ProductCode></Info>
      <Mailbox>
        <CoE>
          <InitCmds>
            <InitCmd><Index>32768</Index><SubIndex>1</SubIndex><Data>0100</Data></InitCmd>
          </InitCmds>
        </CoE>
      </Mailbox>
      <ProcessData>
        <Send><BitStart>0</BitStart><BitLength>16</BitLength></Send>
        <Sm2>
          <Type>Outputs</Type>
          <StartAddress>4352</StartAddress>
          <Pdo>
            <Index>#x1600</Index><Name>Out0</Name>
            <Entry><Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>8</BitLen><Name>EniCoeLo</Name><DataType>USINT</DataType></Entry>
          </Pdo>
          <Pdo>
            <Index>#x1601</Index><Name>Out1</Name>
            <Entry><Index>#x6041</Index><SubIndex>0</SubIndex><BitLen>8</BitLen><Name>EniCoeHi</Name><DataType>USINT</DataType></Entry>
          </Pdo>
        </Sm2>
      </ProcessData>
    </Slave>
  </Config>
</EtherCATConfig>"##;
    let eni_coe_cat = Arc::new(XmlCatalog::parse_xml_str(eni_coe_xml).unwrap());
    let mut eni_coe_sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(eni_coe_cat),
        ..Default::default()
    });
    let mut sm2_coe_dg = RawDatagram::new_positioned(
        EcatCmd::Fpwr,
        1,
        0x1001,
        0x0810,
        vec![0x00, 0x11, 2, 0, 0x64, 0x00, 0x01, 0x00],
    );
    sm2_coe_dg.wkc = 1;
    let mut b_sm2_coe = EcatFrameBuilder::new();
    b_sm2_coe.add_datagram(sm2_coe_dg);
    eni_coe_sess
        .dissect_next(&b_sm2_coe.build().unwrap())
        .unwrap();
    let mut lrw_coe_dg = RawDatagram::new_logical(EcatCmd::Lrw, 2, 0x0000_0000, vec![0x34, 0x12]);
    lrw_coe_dg.wkc = 1;
    let mut b_lrw_coe = EcatFrameBuilder::new();
    b_lrw_coe.add_datagram(lrw_coe_dg);
    let df_eni_coe = eni_coe_sess
        .dissect_next(&b_lrw_coe.build().unwrap())
        .unwrap();
    assert_eq!(df_eni_coe.wireshark_fields["ecat.pdo.EniCoeLo"], 0x34);
    assert_eq!(df_eni_coe.wireshark_fields["ecat.pdo.EniCoeHi"], 0x12);

    let soem_eni_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../esi-eeprom-source-v1.0.0/third_party/SOEM/samples/eni_test/sample-eni.xml");
    if soem_eni_path.exists() {
        let soem_cat = XmlCatalog::load_from_path(&soem_eni_path).unwrap();
        let has_multi_1c13 = soem_cat.devices.iter().any(|d| {
            d.objects
                .get(&0x1C13)
                .is_some_and(|o| o.subentries.contains_key(&0) && o.subentries.contains_key(&1))
        });
        assert!(
            has_multi_1c13,
            "SOEM sample-eni.xml must preserve both SubIndex 0 and SubIndex 1 on 0x1C13"
        );
    }

    // 8. XML `<DefaultValue>` BitSize width, sparse `<SubItem><SubIdx>`, and MDP `<Slots>`/`<Modules>` + dynamic `0xF030`:
    let mdp_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x99993052" RevisionNo="#x00010000">MdpCoupler</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" PdoConfig="0"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x20" Enable="1">Inputs</Sm>
        <Slots MaxSlotCount="2" SlotPdoIncrement="16" SlotIndexIncrement="256"/>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>USINT</Name><BitSize>8</BitSize></DataType>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
              <DataType>
                <Name>SPARSE_REC</Name>
                <BitSize>48</BitSize>
                <SubItem><SubIdx>0</SubIdx><Name>Count</Name><Type>USINT</Type><BitSize>8</BitSize><BitOffs>0</BitOffs></SubItem>
                <SubItem><SubIdx>2</SubIdx><Name>Val2</Name><Type>UINT</Type><BitSize>16</BitSize><BitOffs>16</BitOffs></SubItem>
              </DataType>
            </DataTypes>
            <Objects>
              <Object>
                <Index>#x1C12</Index>
                <Name>RxAssign</Name>
                <Type>UINT</Type>
                <BitSize>16</BitSize>
                <Info><DefaultValue>#x1600</DefaultValue></Info>
              </Object>
              <Object>
                <Index>#x2000</Index>
                <Name>SparseObj</Name>
                <Type>SPARSE_REC</Type>
                <BitSize>48</BitSize>
                <Info>
                  <SubItem><SubIdx>2</SubIdx><Info><DefaultValue>#xABCD</DefaultValue></Info></SubItem>
                </Info>
              </Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
    <Modules>
      <Module>
        <Type ModuleIdent="#x00000010">ModA</Type>
        <TxPdo Fixed="1" Sm="2">
          <Index>#x1A00</Index>
          <Name>ModAIn</Name>
          <Entry><Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>16</BitLen><Name>ModAVal</Name><DataType>UINT</DataType></Entry>
        </TxPdo>
      </Module>
      <Module>
        <Type ModuleIdent="#x00000020">ModB</Type>
        <TxPdo Fixed="1" Sm="2">
          <Index>#x1A00</Index>
          <Name>ModBIn</Name>
          <Entry><Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>16</BitLen><Name>ModBVal</Name><DataType>UINT</DataType></Entry>
        </TxPdo>
      </Module>
    </Modules>
  </Descriptions>
</EtherCATInfo>"##;
    let mdp_cat = Arc::new(XmlCatalog::parse_xml_str(mdp_xml).unwrap());
    let mdp_dev = &mdp_cat.devices[0];
    assert_eq!(
        mdp_dev.objects[&0x1C12].subentries[&0]
            .default_hex
            .as_deref(),
        Some("0016"),
        "16-bit UINT <DefaultValue> must encode 2 LE bytes, not 8"
    );
    assert!(
        mdp_dev.objects[&0x2000].subentries[&0]
            .default_hex
            .is_none(),
        "sparse <SubIdx>2</SubIdx> override must NOT overwrite SubIndex 0"
    );
    assert_eq!(
        mdp_dev.objects[&0x2000].subentries[&2]
            .default_hex
            .as_deref(),
        Some("cdab")
    );

    // Dynamic `0xF030` (`[0x10, 0x20]`) + `0x1C13` (`[0x1A00, 0x1A10]`) activates both MDP slots!
    let mut mdp_sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(mdp_cat),
        ..Default::default()
    });
    let mut fmmu_mdp = vec![0u8; 16];
    fmmu_mdp[0..4].copy_from_slice(&0x0003_0000u32.to_le_bytes());
    fmmu_mdp[4..6].copy_from_slice(&4u16.to_le_bytes());
    fmmu_mdp[7] = 7;
    fmmu_mdp[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu_mdp[11] = 0x01; // read
    fmmu_mdp[12] = 0x01; // active
    let mut dg_fmdp = RawDatagram::new_positioned(EcatCmd::Fpwr, 1, 0x1001, 0x0600, fmmu_mdp);
    dg_fmdp.wkc = 1;
    let mut b_fmdp = EcatFrameBuilder::new();
    b_fmdp.add_datagram(dg_fmdp);
    mdp_sess.dissect_next(&b_fmdp.build().unwrap()).unwrap();

    // Configure 0xF030:1 = 0x10 (ModA -> 0x1A00), 0xF030:2 = 0x20 (ModB -> 0x1A10), 0xF030:0 = 2
    for (cnt, sub, val4) in [(1u8, 1u8, 0x0000_0010u32), (2u8, 2u8, 0x0000_0020u32)] {
        let pkt = build_coe_sdo_mbx_frame(
            0x1001,
            0x1000,
            1,
            cnt,
            0x23,
            0xF030,
            sub,
            &val4.to_le_bytes(),
        );
        mdp_sess.dissect_next(&pkt).unwrap();
    }
    let pkt_f030_cnt =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 3, 0x2F, 0xF030, 0, &[2, 0, 0, 0]);
    mdp_sess.dissect_next(&pkt_f030_cnt).unwrap();

    for (cnt, sub, pdo_idx) in [(4u8, 1u8, 0x1A00u16), (5u8, 2u8, 0x1A10u16)] {
        let mut d4 = [0u8; 4];
        d4[..2].copy_from_slice(&pdo_idx.to_le_bytes());
        let pkt = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, cnt, 0x2B, 0x1C13, sub, &d4);
        mdp_sess.dissect_next(&pkt).unwrap();
    }
    let pkt_1c13_cnt =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 6, 0x2F, 0x1C13, 0, &[2, 0, 0, 0]);
    mdp_sess.dissect_next(&pkt_1c13_cnt).unwrap();

    let mut mdp_bytes = Vec::new();
    mdp_bytes.extend_from_slice(&0x1111u16.to_le_bytes());
    mdp_bytes.extend_from_slice(&0x2222u16.to_le_bytes());
    let mut dg_mdp_lrd = RawDatagram::new_logical(EcatCmd::Lrd, 7, 0x0003_0000, mdp_bytes);
    dg_mdp_lrd.wkc = 1;
    let mut b_mdp_lrd = EcatFrameBuilder::new();
    b_mdp_lrd.add_datagram(dg_mdp_lrd);
    let df_mdp = mdp_sess.dissect_next(&b_mdp_lrd.build().unwrap()).unwrap();
    assert_eq!(df_mdp.wireshark_fields["ecat.pdo.ModAVal"], 0x1111);
    assert_eq!(df_mdp.wireshark_fields["ecat.pdo.Slot2_ModBVal"], 0x2222);
}

#[test]
fn sdo_upload_od_scan_does_not_activate_pdo_until_sm_assign() {
    let od_scan_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x44443052" RevisionNo="#x00010000">OdScanDrive</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1" CompleteAccess="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x24" Enable="1">Outputs</Sm>
        <RxPdo Sm="2" Mandatory="0" Fixed="0">
          <Index>#x1600</Index>
          <Name>PosOutputs</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>CtrlWord</Name>
            <DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x607A</Index>
            <SubIndex>0</SubIndex>
            <BitLen>32</BitLen>
            <Name>TargetPos</Name>
            <DataType>DINT</DataType>
          </Entry>
        </RxPdo>
        <RxPdo Sm="2" Mandatory="0" Fixed="0">
          <Index>#x1601</Index>
          <Name>VelOutputs</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>CtrlWord</Name>
            <DataType>UINT</DataType>
          </Entry>
        </RxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
              <DataType><Name>DINT</Name><BitSize>32</BitSize></DataType>
            </DataTypes>
            <Objects>
              <Object><Index>#x6040</Index><Name>CtrlWord</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
              <Object><Index>#x607A</Index><Name>TargetPos</Name><Type>DINT</Type><BitSize>32</BitSize></Object>
              <Object><Index>#x60FF</Index><Name>TargetVel</Name><Type>DINT</Type><BitSize>32</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(od_scan_xml).unwrap());

    let build_cfg_pkt = |len_bytes: u16| {
        let mut fmmu0 = vec![0u8; 16];
        fmmu0[0..4].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        fmmu0[4..6].copy_from_slice(&len_bytes.to_le_bytes());
        fmmu0[7] = 7;
        fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
        fmmu0[11] = 0x02; // write enable
        fmmu0[12] = 0x01; // active
        let mut dg_f = RawDatagram::new_positioned(EcatCmd::Fpwr, 1, 0x1001, 0x0600, fmmu0);
        dg_f.wkc = 1;
        let mut sm2 = vec![0u8; 8];
        sm2[0..2].copy_from_slice(&0x1100u16.to_le_bytes());
        sm2[2..4].copy_from_slice(&len_bytes.to_le_bytes());
        sm2[4] = 0x24;
        sm2[6] = 0x01;
        let mut dg_s = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0810, sm2);
        dg_s.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg_f);
        b.add_datagram(dg_s);
        b.build().unwrap()
    };

    let build_lrw = |idx: u8, payload: &[u8]| {
        let mut dg = RawDatagram::new_logical(EcatCmd::Lrw, idx, 0x0001_0000, payload.to_vec());
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };

    // Case A: SDO Upload of `0x1600` + `0x1601` alone (OD scan without `0x1C12`) MUST NOT activate PDO decoding!
    let mut sess_ul = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });
    sess_ul.dissect_next(&build_cfg_pkt(6)).unwrap();

    // Upload `0x1600` via Complete Access (`sub0=2`, `0x60400010`, `0x607A0020`)
    let req_1600_ca = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x50, 0x1600, 0, &[0; 4]);
    let mut ca_1600_body = Vec::new();
    ca_1600_body.extend_from_slice(&10u32.to_le_bytes()); // indicated size = 10B (2B count + 2*4B entries)
    ca_1600_body.extend_from_slice(&2u16.to_le_bytes());
    ca_1600_body.extend_from_slice(&0x6040_0010u32.to_le_bytes());
    ca_1600_body.extend_from_slice(&0x607A_0020u32.to_le_bytes());
    let res_1600_ca =
        build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 1, 0x51, 0x1600, 0, &ca_1600_body);
    sess_ul.dissect_next(&req_1600_ca).unwrap();
    sess_ul.dissect_next(&res_1600_ca).unwrap();

    // Upload `0x1601` subindex-by-subindex with custom live slave mapping:
    // `sub0 = 2`, `sub1 = 0x6040:00 (16b)`, `sub2 = 0x60FF:00 (32b)` (differs from XML default 16b!)
    let ul_1601_s0_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 2, 0x40, 0x1601, 0, &[0; 4]);
    let ul_1601_s0_res =
        build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 2, 0x4F, 0x1601, 0, &[2, 0, 0, 0]);
    let ul_1601_s1_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 3, 0x40, 0x1601, 1, &[0; 4]);
    let ul_1601_s1_res = build_coe_sdo_resp_mbx_frame(
        0x1001,
        0x1080,
        3,
        0x43,
        0x1601,
        1,
        &0x6040_0010u32.to_le_bytes(),
    );
    let ul_1601_s2_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 4, 0x40, 0x1601, 2, &[0; 4]);
    let ul_1601_s2_res = build_coe_sdo_resp_mbx_frame(
        0x1001,
        0x1080,
        4,
        0x43,
        0x1601,
        2,
        &0x60FF_0020u32.to_le_bytes(),
    );
    for pkt in [
        &ul_1601_s0_req,
        &ul_1601_s0_res,
        &ul_1601_s1_req,
        &ul_1601_s1_res,
        &ul_1601_s2_req,
        &ul_1601_s2_res,
    ] {
        sess_ul.dissect_next(pkt).unwrap();
    }

    // Cyclic LRW after OD scan of `0x1600` + `0x1601` alone: PDO decoding MUST remain inactive!
    let mut cyc = Vec::new();
    cyc.extend_from_slice(&0x000Fu16.to_le_bytes());
    cyc.extend_from_slice(&123_456i32.to_le_bytes());
    let df_before_assign = sess_ul.dissect_next(&build_lrw(10, &cyc)).unwrap();
    assert!(
        df_before_assign.datagrams[0].pdo_fields.is_none(),
        "SDO Upload of 0x1600/0x1601 alone (OD scan) must NOT activate PDO decoding"
    );
    assert!(!df_before_assign
        .wireshark_fields
        .keys()
        .any(|k| k.starts_with("ecat.pdo.")));

    // Now SDO Upload `0x1C12:0 = 1` followed by `0x1C12:1 = 0x1601`:
    // Before `0x1C12:1` arrives, `0x1C12` is only partially uploaded and must not prematurely fail/commit;
    // once `0x1C12:1 = 0x1601` completes, `0x1601` activates with its uploaded live mapping (`CtrlWord` + `TargetVel`)!
    let ul_1c12_s0_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 5, 0x40, 0x1C12, 0, &[0; 4]);
    let ul_1c12_s0_res =
        build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 5, 0x4F, 0x1C12, 0, &[1, 0, 0, 0]);
    sess_ul.dissect_next(&ul_1c12_s0_req).unwrap();
    sess_ul.dissect_next(&ul_1c12_s0_res).unwrap();
    let df_mid_assign = sess_ul.dissect_next(&build_lrw(11, &cyc)).unwrap();
    assert!(df_mid_assign.datagrams[0].pdo_fields.is_none());

    let ul_1c12_s1_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 6, 0x40, 0x1C12, 1, &[0; 4]);
    let ul_1c12_s1_res =
        build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 6, 0x4B, 0x1C12, 1, &[0x01, 0x16, 0, 0]);
    sess_ul.dissect_next(&ul_1c12_s1_req).unwrap();
    sess_ul.dissect_next(&ul_1c12_s1_res).unwrap();

    let df_after_ul_assign = sess_ul.dissect_next(&build_lrw(12, &cyc)).unwrap();
    assert!(df_after_ul_assign.datagrams[0].pdo_fields.is_some());
    assert_eq!(df_after_ul_assign.wireshark_fields["ecat.pdo.CtrlWord"], 15);
    assert_eq!(
        df_after_ul_assign.wireshark_fields["ecat.pdo.TargetVel"],
        123_456
    );
    assert!(
        !df_after_ul_assign
            .wireshark_fields
            .contains_key("ecat.pdo.TargetPos"),
        "0x1600 was scanned via SDO Upload, not assigned in 0x1C12, so TargetPos must not appear"
    );

    // Case B: SDO Upload of `0x1600` + `0x1601` followed by SDO Download of `0x1C12` selecting `0x1601`
    let mut sess_dl_assign = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });
    sess_dl_assign.dissect_next(&build_cfg_pkt(6)).unwrap();
    for pkt in [
        &req_1600_ca,
        &res_1600_ca,
        &ul_1601_s0_req,
        &ul_1601_s0_res,
        &ul_1601_s1_req,
        &ul_1601_s1_res,
        &ul_1601_s2_req,
        &ul_1601_s2_res,
    ] {
        sess_dl_assign.dissect_next(pkt).unwrap();
    }
    assert!(sess_dl_assign
        .dissect_next(&build_lrw(1, &cyc))
        .unwrap()
        .datagrams[0]
        .pdo_fields
        .is_none());

    let dl_1c12_zero = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 7, 0x2F, 0x1C12, 0, &[0; 4]);
    let dl_1c12_s1 =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x2B, 0x1C12, 1, &[0x01, 0x16, 0, 0]);
    let dl_1c12_cnt1 =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 2, 0x2F, 0x1C12, 0, &[1, 0, 0, 0]);
    for pkt in [&dl_1c12_zero, &dl_1c12_s1, &dl_1c12_cnt1] {
        sess_dl_assign.dissect_next(pkt).unwrap();
    }
    let df_after_dl_assign = sess_dl_assign.dissect_next(&build_lrw(2, &cyc)).unwrap();
    assert_eq!(df_after_dl_assign.wireshark_fields["ecat.pdo.CtrlWord"], 15);
    assert_eq!(
        df_after_dl_assign.wireshark_fields["ecat.pdo.TargetVel"],
        123_456
    );
    assert!(!df_after_dl_assign
        .wireshark_fields
        .contains_key("ecat.pdo.TargetPos"));

    // Case C: SDO Download of `0x1601` alone (`explicitly_written == true`) DOES activate `0x1601`,
    // and SDO Download `0x1601:0 = 0` clears `explicitly_written` and deactivates it!
    let mut sess_dl_pdo = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });
    sess_dl_pdo.dissect_next(&build_cfg_pkt(6)).unwrap();
    let dl_1601_zero = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x2F, 0x1601, 0, &[0; 4]);
    let dl_1601_s1 = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        2,
        0x23,
        0x1601,
        1,
        &0x6040_0010u32.to_le_bytes(),
    );
    let dl_1601_s2 = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        3,
        0x23,
        0x1601,
        2,
        &0x60FF_0020u32.to_le_bytes(),
    );
    let dl_1601_cnt2 =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 4, 0x2F, 0x1601, 0, &[2, 0, 0, 0]);
    for pkt in [&dl_1601_zero, &dl_1601_s1, &dl_1601_s2, &dl_1601_cnt2] {
        sess_dl_pdo.dissect_next(pkt).unwrap();
    }
    let df_dl_only = sess_dl_pdo.dissect_next(&build_lrw(3, &cyc)).unwrap();
    assert_eq!(df_dl_only.wireshark_fields["ecat.pdo.CtrlWord"], 15);
    assert_eq!(df_dl_only.wireshark_fields["ecat.pdo.TargetVel"], 123_456);

    // Clearing `0x1601:0 = 0` via SDO Download deactivates PDO decoding immediately
    let dl_1601_clear = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 5, 0x2F, 0x1601, 0, &[0; 4]);
    sess_dl_pdo.dissect_next(&dl_1601_clear).unwrap();
    let df_cleared = sess_dl_pdo.dissect_next(&build_lrw(4, &cyc)).unwrap();
    assert!(df_cleared.datagrams[0].pdo_fields.is_none());
}

#[test]
fn coe_sdo_block_crc16_verification_download_and_upload() {
    // Canonical CCITT-FALSE / XMODEM (`poly=0x1021, init=0x0000`) CRC-16 check vectors
    assert_eq!(ethercat_dissector::sdo_block_crc16(&[]), 0x0000);
    assert_eq!(ethercat_dissector::sdo_block_crc16(b"123456789"), 0x31C3);

    let build_raw_coe_mbx = |cmd_op: EcatCmd,
                             station: u16,
                             ado: u16,
                             wkc: u16,
                             cnt: u8,
                             svc: u8,
                             coe_payload: &[u8]| {
        let coe_len = 2 + coe_payload.len();
        let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&station.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&(((svc as u16) & 0x0F) << 12).to_le_bytes());
        mbx.extend_from_slice(coe_payload);
        if mbx.len() < 16 {
            mbx.resize(16, 0);
        }
        let mut dg = RawDatagram::new_positioned(cmd_op, cnt, station, ado, mbx);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x55553052" RevisionNo="#x00010000">CrcDrive</Type>
        <Mailbox><CoE SdoInfo="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Profile>
          <Dictionary>
            <DataTypes><DataType><Name>STRING(16)</Name><BitSize>128</BitSize></DataType></DataTypes>
            <Objects>
              <Object><Index>#x1008</Index><Name>Device_Name</Name><Type>STRING(16)</Type><BitSize>128</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(xml).unwrap());
    let mut sess_xml = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });
    let mut sess_plain = DissectSession::new(DissectOptions::default());

    let run_block_download = |s1: &mut DissectSession,
                              s2: &mut DissectSession,
                              client_crc: bool,
                              server_crc: Option<bool>,
                              payload: &[u8],
                              wire_crc: u16| {
        // `cmd`: ccs=6 (`0xC0`), cc (`0x04`), s=1 (`0x02`), cs=0
        let init_hdr = 0xC2 | if client_crc { 0x04 } else { 0x00 };
        let mut init_body = vec![init_hdr, 0x08, 0x10, 0x00];
        init_body.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        let pkt_init = build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, 1, 0x02, &init_body);
        s1.dissect_next(&pkt_init).unwrap();
        s2.dissect_next(&pkt_init).unwrap();

        if let Some(sc) = server_crc {
            // `cmd`: scs=5 (`0xA0`), sc (`0x04`), ss=0
            let res_hdr = 0xA0 | if sc { 0x04 } else { 0x00 };
            let pkt_res = build_raw_coe_mbx(
                EcatCmd::Fprd,
                0x1001,
                0x1080,
                1,
                1,
                0x03,
                &[res_hdr, 0x08, 0x10, 0x00, 16],
            );
            s1.dissect_next(&pkt_res).unwrap();
            s2.dissect_next(&pkt_res).unwrap();
        }

        let chunks: Vec<&[u8]> = payload.chunks(7).collect();
        for (i, ch) in chunks.iter().enumerate() {
            let is_last = i + 1 == chunks.len();
            let seq = ((i + 1) as u8) | if is_last { 0x80 } else { 0x00 };
            let mut sub = vec![seq];
            sub.extend_from_slice(ch);
            while sub.len() < 8 {
                sub.push(0xAA); // padding bytes that MUST be stripped before CRC-16!
            }
            let pkt_sub =
                build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, (2 + i) as u8, 0x02, &sub);
            s1.dissect_next(&pkt_sub).unwrap();
            s2.dissect_next(&pkt_sub).unwrap();
        }

        let last_len = chunks.last().map(|c| c.len()).unwrap_or(7);
        let unused = (7 - last_len) as u8;
        // `cmd`: ccs=6 (`0xC0`), unused (`n << 2`), cs=1 (`0x01`)
        let end_hdr = 0xC1 | ((unused & 0x07) << 2);
        let crc_le = wire_crc.to_le_bytes();
        let pkt_end = build_raw_coe_mbx(
            EcatCmd::Fpwr,
            0x1001,
            0x1000,
            1,
            6,
            0x02,
            &[end_hdr, crc_le[0], crc_le[1]],
        );
        (
            s1.dissect_next(&pkt_end).unwrap(),
            s2.dissect_next(&pkt_end).unwrap(),
        )
    };

    // 1. Block Download with negotiated CRC (`cc=1, sc=1`) and VALID CRC-16 (`0x31C3` for `"123456789"`)
    let (df_dl_ok_xml, df_dl_ok_plain) = run_block_download(
        &mut sess_xml,
        &mut sess_plain,
        true,
        Some(true),
        b"123456789",
        0x31C3,
    );
    for df in [&df_dl_ok_xml, &df_dl_ok_plain] {
        assert_eq!(df.wireshark_fields["ecat_mailbox.coe.sdoblk.crc"], "0x31c3");
        assert_eq!(df.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"], true);
        assert_eq!(
            df.wireshark_fields["ecat_mailbox.coe.sdoblk.computed_crc"],
            "0x31c3"
        );
        let mbx_proto = &df.datagrams[0].mailbox.as_ref().unwrap().protocol;
        assert_eq!(mbx_proto["crc_ok"], true);
        assert_eq!(mbx_proto["computed_crc"], "0x31c3");
    }
    assert_eq!(
        df_dl_ok_xml.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "123456789"
    );

    // 2. Block Download with negotiated CRC (`cc=1, sc=1`) and INVALID CRC-16 (`0xDEAD != 0x31C3`)
    let (df_dl_bad_xml, df_dl_bad_plain) = run_block_download(
        &mut sess_xml,
        &mut sess_plain,
        true,
        Some(true),
        b"123456789",
        0xDEAD,
    );
    for df in [&df_dl_bad_xml, &df_dl_bad_plain] {
        assert_eq!(df.wireshark_fields["ecat_mailbox.coe.sdoblk.crc"], "0xdead");
        assert_eq!(df.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"], false);
        assert_eq!(
            df.wireshark_fields["ecat_mailbox.coe.sdoblk.computed_crc"],
            "0x31c3"
        );
        let mbx_proto = &df.datagrams[0].mailbox.as_ref().unwrap().protocol;
        assert_eq!(mbx_proto["crc_ok"], false);
    }

    // 3. Block Download when server disables CRC (`cc=1, sc=0`): `crc_ok` MUST NOT be emitted!
    let (df_dl_nocrc, _) = run_block_download(
        &mut sess_xml,
        &mut sess_plain,
        true,
        Some(false),
        b"123456789",
        0x0000,
    );
    assert!(!df_dl_nocrc
        .wireshark_fields
        .contains_key("ecat_mailbox.coe.sdoblk.crc_ok"));

    // 4. Block Download when `InitiateBlockDownloadRes` was missed (`cc=1, server_crc=None`): checks CRC!
    let (_, df_dl_nores) = run_block_download(
        &mut sess_xml,
        &mut sess_plain,
        true,
        None,
        b"123456789",
        0x31C3,
    );
    assert_eq!(
        df_dl_nores.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"],
        true
    );

    // 5. Block Upload with negotiated CRC (`cc=1, sc=1`): test both VALID and INVALID CRC-16!
    let ul_payload = b"Blocks-v4.6";
    let expected_ul_crc = ethercat_dissector::sdo_block_crc16(ul_payload);
    for (wire_crc, expect_ok) in [(expected_ul_crc, true), (expected_ul_crc ^ 0xFFFF, false)] {
        let init_ul = build_raw_coe_mbx(
            EcatCmd::Fpwr,
            0x1001,
            0x1000,
            1,
            1,
            0x02,
            &[0xA4, 0x08, 0x10, 0x00, 16, 0], // ccs=5, cc=1, sub=0
        );
        let init_ul_res = build_raw_coe_mbx(
            EcatCmd::Fprd,
            0x1001,
            0x1080,
            1,
            1,
            0x03,
            &[0xC6, 0x08, 0x10, 0x00, 11, 0, 0, 0], // scs=6, sc=1, s=1, ss=0, size=11
        );
        let start_ul = build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, 2, 0x02, &[0xA3]);
        let sub_ul_1 = build_raw_coe_mbx(
            EcatCmd::Fprd,
            0x1001,
            0x1080,
            1,
            2,
            0x03,
            &[0x01, b'B', b'l', b'o', b'c', b'k', b's', b'-'],
        );
        let sub_ul_2 = build_raw_coe_mbx(
            EcatCmd::Fprd,
            0x1001,
            0x1080,
            1,
            3,
            0x03,
            &[0x82, b'v', b'4', b'.', b'6', 0x55, 0x55, 0x55],
        );
        let ack_ul = build_raw_coe_mbx(EcatCmd::Fpwr, 0x1001, 0x1000, 1, 3, 0x02, &[0xA2, 2, 16]);
        let crc_le = wire_crc.to_le_bytes();
        let end_ul = build_raw_coe_mbx(
            EcatCmd::Fprd,
            0x1001,
            0x1080,
            1,
            4,
            0x03,
            &[0xCD, crc_le[0], crc_le[1]], // scs=6, unused=3, ss=1
        );
        for pkt in [
            &init_ul,
            &init_ul_res,
            &start_ul,
            &sub_ul_1,
            &sub_ul_2,
            &ack_ul,
        ] {
            sess_xml.dissect_next(pkt).unwrap();
            sess_plain.dissect_next(pkt).unwrap();
        }
        let df_ul_xml = sess_xml.dissect_next(&end_ul).unwrap();
        let df_ul_plain = sess_plain.dissect_next(&end_ul).unwrap();
        for df in [&df_ul_xml, &df_ul_plain] {
            assert_eq!(
                df.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"],
                expect_ok
            );
            assert_eq!(
                df.wireshark_fields["ecat_mailbox.coe.sdoblk.computed_crc"],
                format!("0x{expected_ul_crc:04x}")
            );
            let mbx_proto = &df.datagrams[0].mailbox.as_ref().unwrap().protocol;
            assert_eq!(mbx_proto["crc_ok"], expect_ok);
        }
        assert_eq!(
            df_ul_xml.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
            "Blocks-v4.6"
        );
    }
}

#[test]
fn eoe_inner_l2_l3_l4_and_multifragment_reassembly() {
    #[allow(clippy::too_many_arguments)]
    let build_eoe_mbx_pkt = |cmd_op: EcatCmd,
                             station: u16,
                             ado: u16,
                             wkc: u16,
                             cnt: u8,
                             port: u8,
                             last: bool,
                             time_appended: bool,
                             frag_no: u8,
                             offset_or_size: u8,
                             frame_no: u8,
                             frag_payload: &[u8],
                             timestamp_ns: Option<u32>| {
        let info1: u16 = (((port & 0x0F) as u16) << 4)
            | if last { 0x0100 } else { 0 }
            | if time_appended { 0x0200 } else { 0 };
        let info2: u16 = ((frag_no & 0x3F) as u16)
            | (((offset_or_size & 0x3F) as u16) << 6)
            | (((frame_no & 0x0F) as u16) << 12);
        let eoe_len = 4 + frag_payload.len() + if timestamp_ns.is_some() { 4 } else { 0 };
        let mut mbx = Vec::with_capacity(6 + eoe_len);
        mbx.extend_from_slice(&(eoe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&station.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x02); // EoE (0x02)
        mbx.extend_from_slice(&info1.to_le_bytes());
        mbx.extend_from_slice(&info2.to_le_bytes());
        mbx.extend_from_slice(frag_payload);
        if let Some(ts) = timestamp_ns {
            mbx.extend_from_slice(&ts.to_le_bytes());
        }
        let mut dg = RawDatagram::new_positioned(cmd_op, cnt, station, ado, mbx);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.pad_to_min_ethernet = true;
        b.add_datagram(dg);
        b.build().unwrap()
    };

    // 1. Single-fragment EoE carrying an ARP Request (`0x0806`)
    let mut arp_eth = Vec::new();
    arp_eth.extend_from_slice(&[0xFF; 6]); // dst broadcast
    arp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0x22, 0x33, 0x44]); // src MAC
    arp_eth.extend_from_slice(&0x0806u16.to_be_bytes());
    arp_eth.extend_from_slice(&1u16.to_be_bytes()); // Ethernet
    arp_eth.extend_from_slice(&0x0800u16.to_be_bytes()); // IPv4
    arp_eth.extend_from_slice(&[6, 4]);
    arp_eth.extend_from_slice(&1u16.to_be_bytes()); // ARP Request (1)
    arp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0x22, 0x33, 0x44]); // SHA
    arp_eth.extend_from_slice(&[192, 168, 100, 1]); // SPA
    arp_eth.extend_from_slice(&[0; 6]); // THA
    arp_eth.extend_from_slice(&[192, 168, 100, 42]); // TPA

    let pkt_arp = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        1,
        0,
        true,
        false,
        0,
        2,
        1,
        &arp_eth,
        None,
    );
    let default_opts = DissectOptions::default();
    let df_arp = dissect_frame(&pkt_arp, &default_opts).unwrap();
    assert_eq!(
        df_arp.wireshark_fields["ecat_mailbox.eoe.eth.type"],
        "0x0806"
    );
    assert_eq!(df_arp.wireshark_fields["ecat_mailbox.eoe.arp.opcode"], 1);
    assert_eq!(
        df_arp.wireshark_fields["ecat_mailbox.eoe.arp.src.proto_ipv4"],
        "192.168.100.1"
    );
    assert_eq!(
        df_arp.wireshark_fields["ecat_mailbox.eoe.arp.dst.proto_ipv4"],
        "192.168.100.42"
    );
    assert_eq!(
        df_arp.datagrams[0].mailbox.as_ref().unwrap().protocol["inner_packet"]["network_protocol"],
        "ARP"
    );

    // 2. Single-fragment EoE carrying IPv4 + ICMP Echo Request (`type=8, code=0`)
    let mut icmp_eth = Vec::new();
    icmp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
    icmp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
    icmp_eth.extend_from_slice(&0x0800u16.to_be_bytes());
    let icmp_body = [
        8u8, 0, 0x12, 0x34, 0x00, 0x01, 0x00, 0x07, b'P', b'I', b'N', b'G',
    ];
    let ip4_total = (20 + icmp_body.len()) as u16;
    icmp_eth.extend_from_slice(&[0x45, 0x00]);
    icmp_eth.extend_from_slice(&ip4_total.to_be_bytes());
    icmp_eth.extend_from_slice(&[0x00, 0x10, 0x40, 0x00, 64, 1, 0x00, 0x00]); // proto=1 (ICMP)
    icmp_eth.extend_from_slice(&[10, 20, 30, 1]);
    icmp_eth.extend_from_slice(&[10, 20, 30, 2]);
    icmp_eth.extend_from_slice(&icmp_body);

    let pkt_icmp = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        2,
        0,
        true,
        false,
        0,
        2,
        2,
        &icmp_eth,
        None,
    );
    let df_icmp = dissect_frame(&pkt_icmp, &default_opts).unwrap();
    assert_eq!(
        df_icmp.wireshark_fields["ecat_mailbox.eoe.ip.src"],
        "10.20.30.1"
    );
    assert_eq!(
        df_icmp.wireshark_fields["ecat_mailbox.eoe.ip.dst"],
        "10.20.30.2"
    );
    assert_eq!(df_icmp.wireshark_fields["ecat_mailbox.eoe.icmp.type"], 8);
    assert_eq!(df_icmp.wireshark_fields["ecat_mailbox.eoe.icmp.seq"], 7);

    // 3. Single-fragment EoE carrying IPv6 + TCP SYN (`0x86DD`, `dstport=502`)
    let mut ipv6_tcp_eth = Vec::new();
    ipv6_tcp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
    ipv6_tcp_eth.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
    ipv6_tcp_eth.extend_from_slice(&0x86DDu16.to_be_bytes());
    let mut tcp_hdr = Vec::new();
    tcp_hdr.extend_from_slice(&49152u16.to_be_bytes());
    tcp_hdr.extend_from_slice(&502u16.to_be_bytes());
    tcp_hdr.extend_from_slice(&1000u32.to_be_bytes());
    tcp_hdr.extend_from_slice(&0u32.to_be_bytes());
    tcp_hdr.extend_from_slice(&[0x50, 0x02]); // SYN
    tcp_hdr.extend_from_slice(&8192u16.to_be_bytes());
    tcp_hdr.extend_from_slice(&[0u8; 4]);
    tcp_hdr.extend_from_slice(&[0xAB, 0xCD]);
    ipv6_tcp_eth.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // IPv6 version=6
    ipv6_tcp_eth.extend_from_slice(&(tcp_hdr.len() as u16).to_be_bytes());
    ipv6_tcp_eth.push(6); // Next Header = TCP (6)
    ipv6_tcp_eth.push(64); // Hop Limit
    let mut v6_src = [0u8; 16];
    v6_src[0] = 0xFE;
    v6_src[1] = 0x80;
    v6_src[15] = 0x01;
    let mut v6_dst = [0u8; 16];
    v6_dst[0] = 0xFE;
    v6_dst[1] = 0x80;
    v6_dst[15] = 0x02;
    ipv6_tcp_eth.extend_from_slice(&v6_src);
    ipv6_tcp_eth.extend_from_slice(&v6_dst);
    ipv6_tcp_eth.extend_from_slice(&tcp_hdr);

    let pkt_v6 = build_eoe_mbx_pkt(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        3,
        0,
        true,
        false,
        0,
        3,
        3,
        &ipv6_tcp_eth,
        None,
    );
    let df_v6 = dissect_frame(&pkt_v6, &default_opts).unwrap();
    assert_eq!(
        df_v6.wireshark_fields["ecat_mailbox.eoe.eth.type"],
        "0x86dd"
    );
    assert_eq!(
        df_v6.wireshark_fields["ecat_mailbox.eoe.ipv6.src"],
        "fe80::1"
    );
    assert_eq!(
        df_v6.wireshark_fields["ecat_mailbox.eoe.ipv6.dst"],
        "fe80::2"
    );
    assert_eq!(
        df_v6.wireshark_fields["ecat_mailbox.eoe.tcp.srcport"],
        49152
    );
    assert_eq!(df_v6.wireshark_fields["ecat_mailbox.eoe.tcp.dstport"], 502);
    assert_eq!(
        df_v6.wireshark_fields["ecat_mailbox.eoe.tcp.payload"],
        "abcd"
    );

    // 4. Multi-fragment EoE reassembly across 3 fragments (`32B + 32B + remainder`, 802.1Q VLAN + IPv4 + UDP)
    //    Includes duplicate ring-echo (`wkc=0` then `wkc=1`) on fragment 1 and appended timestamp on final fragment!
    let udp_app_data: Vec<u8> = (0u8..44).map(|i| 0x20 + i).collect(); // 44B UDP payload -> total frame = 18 + 20 + 8 + 44 = 90B
    let udp_len = (8 + udp_app_data.len()) as u16;
    let ip_len = (20 + udp_len as usize) as u16;
    let mut full_vlan_udp = Vec::with_capacity(90);
    full_vlan_udp.extend_from_slice(&[0x00, 0x01, 0x05, 0x55, 0x66, 0x77]); // dst MAC
    full_vlan_udp.extend_from_slice(&[0x00, 0x01, 0x05, 0x88, 0x99, 0xAA]); // src MAC
    full_vlan_udp.extend_from_slice(&0x8100u16.to_be_bytes()); // 802.1Q VLAN
    full_vlan_udp.extend_from_slice(&((4u16 << 13) | 100u16).to_be_bytes()); // prio=4, vid=100
    full_vlan_udp.extend_from_slice(&0x0800u16.to_be_bytes()); // inner IPv4
    full_vlan_udp.extend_from_slice(&[0x45, 0x00]);
    full_vlan_udp.extend_from_slice(&ip_len.to_be_bytes());
    full_vlan_udp.extend_from_slice(&[0xAB, 0xCD, 0x40, 0x00, 64, 17, 0x00, 0x00]);
    full_vlan_udp.extend_from_slice(&[172, 16, 5, 10]);
    full_vlan_udp.extend_from_slice(&[172, 16, 5, 99]);
    full_vlan_udp.extend_from_slice(&8888u16.to_be_bytes());
    full_vlan_udp.extend_from_slice(&9999u16.to_be_bytes());
    full_vlan_udp.extend_from_slice(&udp_len.to_be_bytes());
    full_vlan_udp.extend_from_slice(&0u16.to_be_bytes());
    full_vlan_udp.extend_from_slice(&udp_app_data);
    assert_eq!(full_vlan_udp.len(), 90);

    let mut sess = DissectSession::new(DissectOptions::default());

    // Fragment 0 (`frag_no=0, last=false, offset_or_size=3` -> 3*32=96B total buffer hint, `frame_no=9`, bytes `0..32`)
    let f0 = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        4,
        0,
        false,
        false,
        0,
        3,
        9,
        &full_vlan_udp[0..32],
        None,
    );
    let df_f0 = sess.dissect_next(&f0).unwrap();
    // First non-final fragment parses L2 header only, not full reassembled L4 UDP payload yet!
    assert_eq!(df_f0.wireshark_fields["ecat_mailbox.eoe.vlan.id"], 100);
    assert!(!df_f0
        .wireshark_fields
        .contains_key("ecat_mailbox.eoe.reassembled_data"));
    assert!(!df_f0
        .wireshark_fields
        .contains_key("ecat_mailbox.eoe.udp.dstport"));

    // Fragment 1 (`frag_no=1, last=false, offset=1` -> byte offset `1 * 32 = 32`, bytes `32..64`)
    // Feed TX (`wkc=0`) followed by RX (`wkc=1`) to verify duplicate ring-echo protection!
    let f1_tx = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        0,
        5,
        0,
        false,
        false,
        1,
        1,
        9,
        &full_vlan_udp[32..64],
        None,
    );
    let f1_rx = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        5,
        0,
        false,
        false,
        1,
        1,
        9,
        &full_vlan_udp[32..64],
        None,
    );
    sess.dissect_next(&f1_tx).unwrap();
    let df_f1 = sess.dissect_next(&f1_rx).unwrap();
    assert!(!df_f1
        .wireshark_fields
        .contains_key("ecat_mailbox.eoe.reassembled_data"));

    // Fragment 2 (`frag_no=2, last=true, time_appended=true, offset=2` -> byte offset `2 * 32 = 64`, bytes `64..90`)
    let f2_last = build_eoe_mbx_pkt(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        6,
        0,
        true,
        true,
        2,
        2,
        9,
        &full_vlan_udp[64..90],
        Some(777_888_999),
    );
    let df_f2 = sess.dissect_next(&f2_last).unwrap();
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.timestamp"],
        777_888_999
    );
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.reassembled_length"],
        90
    );
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.reassembled_fragments"],
        3
    );
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.reassembled_data"],
        hex::encode(&full_vlan_udp)
    );
    assert_eq!(df_f2.wireshark_fields["ecat_mailbox.eoe.vlan.id"], 100);
    assert_eq!(df_f2.wireshark_fields["ecat_mailbox.eoe.vlan.prio"], 4);
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.ip.src"],
        "172.16.5.10"
    );
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.ip.dst"],
        "172.16.5.99"
    );
    assert_eq!(df_f2.wireshark_fields["ecat_mailbox.eoe.udp.srcport"], 8888);
    assert_eq!(df_f2.wireshark_fields["ecat_mailbox.eoe.udp.dstport"], 9999);
    assert_eq!(
        df_f2.wireshark_fields["ecat_mailbox.eoe.udp.payload"],
        hex::encode(&udp_app_data)
    );
    let proto_f2 = &df_f2.datagrams[0].mailbox.as_ref().unwrap().protocol;
    assert_eq!(proto_f2["reassembled_length"], 90);
    assert_eq!(proto_f2["inner_packet"]["transport_protocol"], "UDP");
    assert_eq!(proto_f2["inner_packet"]["dst_port"], 9999);
}

#[test]
fn ams_tcp_coalesced_pdus_and_multibuffer_stream_reassembly() {
    let build_ipv4_tcp_seq =
        |src_port: u16, dst_port: u16, seq: u32, tcp_flags: u8, tcp_payload: &[u8]| {
            let ip_len = (20 + 20 + tcp_payload.len()) as u16;
            let mut out = Vec::with_capacity(14 + ip_len as usize);
            out.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
            out.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
            out.extend_from_slice(&0x0800u16.to_be_bytes());
            out.push(0x45);
            out.push(0x00);
            out.extend_from_slice(&ip_len.to_be_bytes());
            out.extend_from_slice(&[0x00, 0x02, 0x40, 0x00, 64, 6, 0x00, 0x00]);
            out.extend_from_slice(&[192, 168, 1, 10]);
            out.extend_from_slice(&[192, 168, 1, 20]);
            out.extend_from_slice(&src_port.to_be_bytes());
            out.extend_from_slice(&dst_port.to_be_bytes());
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&1u32.to_be_bytes());
            out.push(0x50);
            out.push(tcp_flags);
            out.extend_from_slice(&4096u16.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(&0u16.to_be_bytes());
            out.extend_from_slice(tcp_payload);
            out
        };

    let build_ams_tcp_f302_write =
        |station_port: u16, invoke_id: u32, idx: u16, sub: u8, ca: bool, data: &[u8]| {
            let idx_off: u32 =
                ((idx as u32) << 16) | if ca { 0x0000_0100 } else { 0 } | (sub as u32);
            let mut ads_body = Vec::with_capacity(12 + data.len());
            ads_body.extend_from_slice(&0x0000_F302u32.to_le_bytes());
            ads_body.extend_from_slice(&idx_off.to_le_bytes());
            ads_body.extend_from_slice(&(data.len() as u32).to_le_bytes());
            ads_body.extend_from_slice(data);
            let pdu = build_ams_pdu(
                [5, 12, 34, 56, 2, 1],
                station_port,
                [192, 168, 1, 10, 1, 1],
                32905,
                0x0003, // ADS Write
                0x0004, // Request
                0,
                invoke_id,
                &ads_body,
            );
            let mut tcp_frame = Vec::with_capacity(6 + pdu.len());
            tcp_frame.extend_from_slice(&0u16.to_le_bytes());
            tcp_frame.extend_from_slice(&(pdu.len() as u32).to_le_bytes());
            tcp_frame.extend_from_slice(&pdu);
            tcp_frame
        };

    let aoe_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x66663052" RevisionNo="#x00010000">AoeDrive</Type>
        <Mailbox><AoE/><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1" CompleteAccess="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x24" Enable="1">Outputs</Sm>
        <RxPdo Sm="2" Mandatory="0" Fixed="0">
          <Index>#x1600</Index>
          <Name>Outputs</Name>
          <Entry>
            <Index>#x6040</Index>
            <SubIndex>0</SubIndex>
            <BitLen>16</BitLen>
            <Name>AoeCtrl</Name>
            <DataType>UINT</DataType>
          </Entry>
        </RxPdo>
        <Profile>
          <Dictionary>
            <DataTypes><DataType><Name>UINT</Name><BitSize>16</BitSize></DataType></DataTypes>
            <Objects>
              <Object><Index>#x6040</Index><Name>AoeCtrl</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(aoe_xml).unwrap());

    let build_hw_cfg = || {
        let mut fmmu0 = vec![0u8; 16];
        fmmu0[0..4].copy_from_slice(&0x0004_0000u32.to_le_bytes());
        fmmu0[4..6].copy_from_slice(&2u16.to_le_bytes());
        fmmu0[7] = 7;
        fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
        fmmu0[11] = 0x02;
        fmmu0[12] = 0x01;
        let mut dg_f = RawDatagram::new_positioned(EcatCmd::Fpwr, 1, 0x1001, 0x0600, fmmu0);
        dg_f.wkc = 1;
        let mut sm2 = vec![0u8; 8];
        sm2[0..2].copy_from_slice(&0x1100u16.to_le_bytes());
        sm2[2..4].copy_from_slice(&2u16.to_le_bytes());
        sm2[4] = 0x24;
        sm2[6] = 0x01;
        let mut dg_s = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0810, sm2);
        dg_s.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg_f);
        b.add_datagram(dg_s);
        b.build().unwrap()
    };

    // Part 1: Coalesced back-to-back AMS/TCP PDUs in a SINGLE TCP `48898` packet!
    // PDU 0 sets `0x1C12:1 = 0x1600`, PDU 1 commits `0x1C12:0 = 1` -> BOTH must be dissected & executed!
    let mut sess_coalesced = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });
    sess_coalesced.dissect_next(&build_hw_cfg()).unwrap();

    let pdu_clear = build_ams_tcp_f302_write(0x1001, 500, 0x1C12, 0, false, &[0]);
    sess_coalesced
        .dissect_next(&build_ipv4_tcp_seq(
            53001,
            TCP_PORT_AMS,
            100,
            0x18,
            &pdu_clear,
        ))
        .unwrap();

    let pdu_s1 = build_ams_tcp_f302_write(0x1001, 501, 0x1C12, 1, false, &0x1600u16.to_le_bytes());
    let pdu_cnt = build_ams_tcp_f302_write(0x1001, 502, 0x1C12, 0, false, &[1]);
    let mut coalesced = Vec::with_capacity(pdu_s1.len() + pdu_cnt.len());
    coalesced.extend_from_slice(&pdu_s1);
    coalesced.extend_from_slice(&pdu_cnt);
    let next_seq = 100 + pdu_clear.len() as u32;
    let df_coal = sess_coalesced
        .dissect_next(&build_ipv4_tcp_seq(
            53001,
            TCP_PORT_AMS,
            next_seq,
            0x18,
            &coalesced,
        ))
        .unwrap();
    assert_eq!(df_coal.wireshark_fields["ams.pdu_count"], 2);
    assert_eq!(df_coal.wireshark_fields["ams.invokeid"], "0x000001f5");
    assert_eq!(df_coal.wireshark_fields["ams[0].invokeid"], "0x000001f5");
    assert_eq!(df_coal.wireshark_fields["ams[1].invokeid"], "0x000001f6");
    assert_eq!(
        df_coal.direct_ams.as_ref().unwrap()["pdus"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let mut dg_lrw = RawDatagram::new_logical(
        EcatCmd::Lrw,
        3,
        0x0004_0000,
        0x007Fu16.to_le_bytes().to_vec(),
    );
    dg_lrw.wkc = 1;
    let mut b_lrw = EcatFrameBuilder::new();
    b_lrw.add_datagram(dg_lrw);
    let lrw_pkt = b_lrw.build().unwrap();
    let df_coal_lrw = sess_coalesced.dissect_next(&lrw_pkt).unwrap();
    assert_eq!(df_coal_lrw.wireshark_fields["ecat.pdo.AoeCtrl"], 0x007F);

    // Part 2: 2-segment split `AMS/TCP` (`48898`) carrying `0xF302` Complete Access `0x1C12:0 = [1, 0, 0x00, 0x16]`
    //         First TCP segment is only 15 bytes (`< 38` bytes, exercising `may_contain_ethercat` + partial header/body),
    //         followed by a duplicate TCP retransmission of segment 1, then completing segment 2!
    let mut sess_split = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });
    sess_split.dissect_next(&build_hw_cfg()).unwrap();

    let full_ca_pdu =
        build_ams_tcp_f302_write(0x1001, 601, 0x1C12, 0, true, &[0x01, 0x00, 0x00, 0x16]);
    let seg1 = &full_ca_pdu[..15]; // Only 15 bytes (< 38B)!
    let seg2 = &full_ca_pdu[15..];

    let pkt_seg1 = build_ipv4_tcp_seq(53002, TCP_PORT_AMS, 1000, 0x10, seg1);
    assert!(
        ethercat_dissector::may_contain_ethercat(&pkt_seg1, false),
        "short split AMS/TCP segment (< 38B) on port 48898 must pass may_contain_ethercat"
    );
    let df_seg1 = sess_split.dissect_next(&pkt_seg1).unwrap();
    assert_eq!(df_seg1.wireshark_fields["ams.reassembly_pending"], true);
    assert_eq!(df_seg1.direct_ams.as_ref().unwrap()["truncated"], true);

    // Duplicate TCP retransmission of `seg1` at `seq = 1000` must be flagged & ignored cleanly
    let df_retrans = sess_split.dissect_next(&pkt_seg1).unwrap();
    assert_eq!(df_retrans.wireshark_fields["ams.tcp_retransmission"], true);

    // Completing `seg2` at `seq = 1015` reassembles the full AMS/TCP PDU and activates `0x1600` (`AoeCtrl`)!
    let pkt_seg2 = build_ipv4_tcp_seq(53002, TCP_PORT_AMS, 1000 + seg1.len() as u32, 0x18, seg2);
    let df_seg2 = sess_split.dissect_next(&pkt_seg2).unwrap();
    assert_eq!(df_seg2.wireshark_fields["ams.reassembled"], true);
    assert_eq!(df_seg2.wireshark_fields["ams.invokeid"], "0x00000259");
    assert_eq!(df_seg2.wireshark_fields["ams.ads_indexgroup"], "0x0000f302");
    assert_eq!(df_seg2.wireshark_fields["ams.ads_cblength"], 4);
    // Wireshark 4.6 `ADSSRVID_WRITE`: `ams.ads_data` starts after IndexGroup/IndexOffset/Length (12 B).
    assert_eq!(df_seg2.wireshark_fields["ams.ads_data"], "01000016");
    assert_eq!(df_seg2.direct_ams.as_ref().unwrap().get("truncated"), None);

    let df_split_lrw = sess_split.dissect_next(&lrw_pkt).unwrap();
    assert_eq!(df_split_lrw.wireshark_fields["ecat.pdo.AoeCtrl"], 0x007F);

    // Part 3: Out-of-order TCP segments (`seg2` arrives BEFORE `seg1`, then `seg1` fills the gap)!
    let mut sess_ooo = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });
    sess_ooo.dissect_next(&build_hw_cfg()).unwrap();
    let pkt_ooo_2 = build_ipv4_tcp_seq(53003, TCP_PORT_AMS, 2000 + seg1.len() as u32, 0x18, seg2);
    let pkt_ooo_1 = build_ipv4_tcp_seq(53003, TCP_PORT_AMS, 2000, 0x10, seg1);
    // Establish initial sequence via a 1-PDU clear first so `expected_seq` is anchored at `2000`
    let init_seq_start = 2000 - pdu_clear.len() as u32;
    sess_ooo
        .dissect_next(&build_ipv4_tcp_seq(
            53003,
            TCP_PORT_AMS,
            init_seq_start,
            0x18,
            &pdu_clear,
        ))
        .unwrap();
    let df_ooo_2 = sess_ooo.dissect_next(&pkt_ooo_2).unwrap();
    assert_eq!(df_ooo_2.wireshark_fields["ams.reassembly_pending"], true);
    assert!(
        !df_ooo_2.wireshark_fields.contains_key("ams.targetnetid"),
        "out-of-order middle TCP segment must not emit bogus ams.targetnetid"
    );
    let df_ooo_1 = sess_ooo.dissect_next(&pkt_ooo_1).unwrap();
    assert_eq!(df_ooo_1.wireshark_fields["ams.reassembled"], true);
    assert_eq!(df_ooo_1.wireshark_fields["ams.invokeid"], "0x00000259");
    let df_ooo_lrw = sess_ooo.dissect_next(&lrw_pkt).unwrap();
    assert_eq!(df_ooo_lrw.wireshark_fields["ecat.pdo.AoeCtrl"], 0x007F);
}

#[test]
fn adversarial_pdo_upload_rescan_abort_and_xml_fallback_on_cnt_download() {
    let esi_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>#x00000002</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x22223333" RevisionNo="#x00010000">EL-AdvDrive</Type>
        <Name>Adv Servo Drive</Name>
        <Sm StartAddress="#x1000" DefaultSize="128" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" DefaultSize="128" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" DefaultSize="6" ControlByte="#x64" Enable="1">Outputs</Sm>
        <RxPdo Fixed="0" Sm="2">
          <Index>#x1600</Index>
          <Name>Position RxPDO</Name>
          <Entry>
            <Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen>
            <Name>CtrlWord</Name><DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x607A</Index><SubIndex>0</SubIndex><BitLen>32</BitLen>
            <Name>TargetPos</Name><DataType>DINT</DataType>
          </Entry>
        </RxPdo>
        <RxPdo Fixed="0">
          <Index>#x1601</Index>
          <Name>Velocity RxPDO</Name>
          <Entry>
            <Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen>
            <Name>CtrlWord</Name><DataType>UINT</DataType>
          </Entry>
          <Entry>
            <Index>#x60FF</Index><SubIndex>0</SubIndex><BitLen>32</BitLen>
            <Name>TargetVel</Name><DataType>DINT</DataType>
          </Entry>
        </RxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
              <DataType><Name>DINT</Name><BitSize>32</BitSize></DataType>
            </DataTypes>
            <Objects>
              <Object><Index>#x6040</Index><Name>CtrlWord</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
              <Object><Index>#x607A</Index><Name>TargetPos</Name><Type>DINT</Type><BitSize>32</BitSize></Object>
              <Object><Index>#x60FF</Index><Name>TargetVel</Name><Type>DINT</Type><BitSize>32</BitSize></Object>
              <Object><Index>#x2099</Index><Name>CustomFeed</Name><Type>DINT</Type><BitSize>32</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(esi_xml).unwrap());

    let build_hw = || {
        let mut dg_st = RawDatagram::new_positioned(EcatCmd::Apwr, 1, 0, 0x0010, vec![0x01, 0x10]);
        dg_st.wkc = 1;
        let mut fmmu0 = vec![0u8; 16];
        fmmu0[0..4].copy_from_slice(&0x0005_0000u32.to_le_bytes());
        fmmu0[4..6].copy_from_slice(&6u16.to_le_bytes());
        fmmu0[7] = 7;
        fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
        fmmu0[11] = 0x02;
        fmmu0[12] = 0x01;
        let mut dg_fmmu = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0600, fmmu0);
        dg_fmmu.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg_st).add_datagram(dg_fmmu);
        b.build().unwrap()
    };
    let build_lrw = |idx: u8, payload: &[u8]| {
        let mut dg = RawDatagram::new_logical(EcatCmd::Lrw, idx, 0x0005_0000, payload.to_vec());
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };
    let build_ul_res = |cnt: u8, cmd_byte: u8, idx: u16, sub: u8, data4: [u8; 4]| {
        let mut coe = vec![0x00, 0x30, cmd_byte];
        coe.extend_from_slice(&idx.to_le_bytes());
        coe.push(sub);
        coe.extend_from_slice(&data4);
        let mut mbx = Vec::with_capacity(6 + coe.len());
        mbx.extend_from_slice(&(coe.len() as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(0x03 | ((cnt & 0x07) << 4));
        mbx.extend_from_slice(&coe);
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fprd, cnt, 0x1001, 0x1080, mbx);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };
    let build_sdo_abort = |cnt: u8, idx: u16, sub: u8, abort_code: u32| {
        build_ul_res(cnt, 0x80, idx, sub, abort_code.to_le_bytes())
    };

    let mut cyc = Vec::new();
    cyc.extend_from_slice(&31u16.to_le_bytes());
    cyc.extend_from_slice(&(-987_654i32).to_le_bytes());

    // 1. Download `0x1601:00 = 2` WITHOUT writing `0x1601:01..02`: must fall back to XML `0x1601` entries!
    let mut sess_cnt_only = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });
    sess_cnt_only.dissect_next(&build_hw()).unwrap();
    let dl_cnt2 = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x2F, 0x1601, 0, &[2, 0, 0, 0]);
    sess_cnt_only.dissect_next(&dl_cnt2).unwrap();
    let df_cnt_only = sess_cnt_only.dissect_next(&build_lrw(2, &cyc)).unwrap();
    assert_eq!(df_cnt_only.wireshark_fields["ecat.pdo.CtrlWord"], 31);
    assert_eq!(
        df_cnt_only.wireshark_fields["ecat.pdo.TargetVel"], -987_654,
        "SDO Download of 0x1601:00=2 without sub1..sub2 must resolve entries from XML 0x1601"
    );

    // 2. Stale `staged` SDO Upload re-scan on `0x1C12` + aborted `0x1601` SDO Upload cleanup:
    let mut sess_rescan = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });
    sess_rescan.dissect_next(&build_hw()).unwrap();
    // Initial Download configuration: `0x1C12 = [0x1600]` (`TargetPos`)
    sess_rescan
        .dissect_next(&build_coe_sdo_mbx_frame(
            0x1001,
            0x1000,
            1,
            1,
            0x2B,
            0x1C12,
            1,
            &0x1600u16.to_le_bytes(),
        ))
        .unwrap();
    sess_rescan
        .dissect_next(&build_coe_sdo_mbx_frame(
            0x1001,
            0x1000,
            1,
            2,
            0x2F,
            0x1C12,
            0,
            &[1, 0, 0, 0],
        ))
        .unwrap();
    let df_init = sess_rescan.dissect_next(&build_lrw(3, &cyc)).unwrap();
    assert_eq!(df_init.wireshark_fields["ecat.pdo.TargetPos"], -987_654);

    // Partial SDO Upload of `0x1601` (`sub0=2`, `sub1=0x6040:00`, then `sub2` ABORTS with `0x2099` NOT read):
    // Actually test staging bogus `0x2099:00` on `sub1` then aborting `sub2` -> must discard partial upload!
    sess_rescan
        .dissect_next(&build_ul_res(3, 0x4F, 0x1601, 0, [2, 0, 0, 0]))
        .unwrap();
    sess_rescan
        .dissect_next(&build_ul_res(
            4,
            0x43,
            0x1601,
            1,
            0x2099_0020u32.to_le_bytes(),
        ))
        .unwrap();
    sess_rescan
        .dissect_next(&build_sdo_abort(5, 0x1601, 2, 0x0609_0011))
        .unwrap();

    // Now SDO Upload re-scans `0x1C12`: `0x1C12:00 -> 1`, then `0x1C12:01 -> 0x1601`!
    // While only `0x1C12:00 -> 1` has been read, active bank must remain `[0x1600]` (`TargetPos`),
    // and as soon as `0x1C12:01 -> 0x1601` arrives, it must switch to `[0x1601]` (`TargetVel`, XML fallback because `0x1601` upload aborted)!
    sess_rescan
        .dissect_next(&build_ul_res(6, 0x4F, 0x1C12, 0, [1, 0, 0, 0]))
        .unwrap();
    let df_during_rescan = sess_rescan.dissect_next(&build_lrw(7, &cyc)).unwrap();
    assert_eq!(
        df_during_rescan.wireshark_fields["ecat.pdo.TargetPos"], -987_654,
        "polling 0x1C12:00 via Upload must not prematurely clobber active 0x1600 bank"
    );

    sess_rescan
        .dissect_next(&build_ul_res(7, 0x4B, 0x1C12, 1, [0x01, 0x16, 0, 0]))
        .unwrap();
    let df_after_rescan = sess_rescan.dissect_next(&build_lrw(1, &cyc)).unwrap();
    assert_eq!(df_after_rescan.wireshark_fields["ecat.pdo.CtrlWord"], 31);
    assert_eq!(
        df_after_rescan.wireshark_fields["ecat.pdo.TargetVel"],
        -987_654,
        "SDO Upload re-scan of 0x1C12 must update stale staged 0x1600 -> 0x1601 and discard aborted partial 0x1601 upload"
    );
    assert!(!df_after_rescan
        .wireshark_fields
        .contains_key("ecat.pdo.CustomFeed"));
}

#[test]
fn adversarial_sdo_block_upload_missed_init_res_unpadded_tail_and_multisubframe() {
    let build_coe_dg = |cmd_op: EcatCmd,
                        station: u16,
                        ado: u16,
                        wkc: u16,
                        cnt: u8,
                        svc: u8,
                        coe_payload: &[u8]| {
        let mut coe = Vec::with_capacity(2 + coe_payload.len());
        coe.extend_from_slice(&((svc as u16) << 12).to_le_bytes());
        coe.extend_from_slice(coe_payload);
        let mut mbx = Vec::with_capacity(6 + coe.len());
        mbx.extend_from_slice(&(coe.len() as u16).to_le_bytes());
        mbx.extend_from_slice(&station.to_le_bytes());
        mbx.push(0x00);
        mbx.push(0x03 | ((cnt & 0x07) << 4));
        mbx.extend_from_slice(&coe);
        let mut dg = RawDatagram::new_positioned(cmd_op, cnt, station, ado, mbx);
        dg.wkc = wkc;
        dg
    };
    let single_pkt = |dg: RawDatagram| {
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };

    // 1. SDO Block Upload when `InitiateBlockUploadRes` was NOT captured AND final sub-block is unpadded (`len = 3, unused = 4`):
    //    Payload = `b"TenBytes!!"` (10 bytes: subblock 1 = 7B, subblock 2 = unpadded 3B with `unused_bytes = 4`).
    let ul_payload = b"TenBytes!!";
    let expected_crc = ethercat_dissector::sdo_block_crc16(ul_payload);

    let mut sess = DissectSession::new(DissectOptions::default());
    // Initiate Block Upload Request (`0xA4`: `ccs=5, cc=1`) — NO `InitiateBlockUploadRes` follows!
    let init_req = single_pkt(build_coe_dg(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        1,
        0x02,
        &[0xA4, 0x0A, 0x10, 0x00, 16, 0, 0, 0],
    ));
    let start_ul = single_pkt(build_coe_dg(
        EcatCmd::Fpwr,
        0x1001,
        0x1000,
        1,
        2,
        0x02,
        &[0xA3, 0, 0, 0, 0, 0, 0, 0],
    ));
    let mut sb1 = vec![0x01]; // seq = 1, more
    sb1.extend_from_slice(&ul_payload[0..7]);
    let sub1 = single_pkt(build_coe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        3,
        0x03,
        &sb1,
    ));
    let mut sb2_unpadded = vec![0x82]; // seq = 2, last=1, ONLY 3 bytes on wire (unpadded!)
    sb2_unpadded.extend_from_slice(&ul_payload[7..10]);
    let sub2 = single_pkt(build_coe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        4,
        0x03,
        &sb2_unpadded,
    ));

    // Multi-subframe EtherCAT frame: subframe 0 = dummy BRD, subframe 1 = EndBlockUpload (`unused=4`, valid CRC)
    let mut end_body = vec![0xC1 | (4 << 2)];
    end_body.extend_from_slice(&expected_crc.to_le_bytes());
    end_body.resize(8, 0);
    let mut dg_brd = RawDatagram::new_positioned(EcatCmd::Brd, 1, 0, 0x0130, vec![0x02, 0x00]);
    dg_brd.wkc = 1;
    let dg_end_ul = build_coe_dg(EcatCmd::Fprd, 0x1001, 0x1080, 1, 5, 0x03, &end_body);
    let mut multi_b = EcatFrameBuilder::new();
    multi_b.add_datagram(dg_brd).add_datagram(dg_end_ul);
    let multi_end_pkt = multi_b.build().unwrap();

    for p in [&init_req, &start_ul, &sub1, &sub2] {
        sess.dissect_next(p).unwrap();
    }
    let df_end = sess.dissect_next(&multi_end_pkt).unwrap();
    assert_eq!(
        df_end.wireshark_fields["ecat_mailbox[1].coe.sdo.reassembled_data"],
        hex::encode(ul_payload),
        "missed InitiateBlockUploadRes + unpadded 3B final sub-block must reassemble exact 10B without over-trimming"
    );
    assert_eq!(
        df_end.wireshark_fields["ecat_mailbox[1].coe.sdoblk.crc_ok"],
        true
    );
    assert_eq!(
        df_end.wireshark_fields["ecat[1].mailbox.coe.sdoblk.crc_ok"],
        true
    );
    assert_eq!(
        df_end.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"],
        true
    );
    assert_eq!(
        df_end.wireshark_fields["ecat[1].mailbox.coe.sdoblk.computed_crc"],
        format!("0x{expected_crc:04x}")
    );
}

#[test]
fn adversarial_eoe_interleaved_multislave_ipv6_ext_headers_and_gap_rejection() {
    let build_eoe_dg = |cmd_op: EcatCmd,
                        station: u16,
                        ado: u16,
                        cnt: u8,
                        last: bool,
                        frag_no: u8,
                        offset_or_size: u8,
                        frame_no: u8,
                        frag_payload: &[u8]| {
        let info1: u16 = if last { 0x0100 } else { 0 };
        let info2: u16 = ((frag_no & 0x3F) as u16)
            | (((offset_or_size & 0x3F) as u16) << 6)
            | (((frame_no & 0x0F) as u16) << 12);
        let mut eoe = Vec::with_capacity(4 + frag_payload.len());
        eoe.extend_from_slice(&info1.to_le_bytes());
        eoe.extend_from_slice(&info2.to_le_bytes());
        eoe.extend_from_slice(frag_payload);
        let mut mbx = Vec::with_capacity(6 + eoe.len());
        mbx.extend_from_slice(&(eoe.len() as u16).to_le_bytes());
        mbx.extend_from_slice(&station.to_le_bytes());
        mbx.push(0x00);
        mbx.push(0x02 | ((cnt & 0x07) << 4));
        mbx.extend_from_slice(&eoe);
        let mut dg = RawDatagram::new_positioned(cmd_op, cnt, station, ado, mbx);
        dg.wkc = 1;
        dg
    };

    // Build inner IPv6 frame with Hop-by-Hop (`nxt=0`, 8B) + Destination Options (`nxt=60`, 8B) + TCP (`nxt=6`, 24B) = 94B total!
    let mut ipv6_ext_tcp = Vec::new();
    ipv6_ext_tcp.extend_from_slice(&[0x00, 0x01, 0x05, 0x90, 0x91, 0x92]);
    ipv6_ext_tcp.extend_from_slice(&[0x00, 0x01, 0x05, 0x80, 0x81, 0x82]);
    ipv6_ext_tcp.extend_from_slice(&0x86DDu16.to_be_bytes());
    let tcp_payload = b"ABCD";
    let ip6_plen = (8 + 8 + 20 + tcp_payload.len()) as u16; // 40 bytes
    ipv6_ext_tcp.extend_from_slice(&0x6000_0000u32.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&ip6_plen.to_be_bytes());
    ipv6_ext_tcp.push(0); // Next Header = Hop-by-Hop (0)
    ipv6_ext_tcp.push(64); // Hop Limit
    ipv6_ext_tcp
        .extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10).octets());
    ipv6_ext_tcp
        .extend_from_slice(&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 20).octets());
    // Hop-by-Hop Options (8B): next = 60 (Destination Options), hdr_ext_len = 0 ((0+1)*8 = 8)
    ipv6_ext_tcp.extend_from_slice(&[60, 0, 1, 4, 0, 0, 0, 0]);
    // Destination Options (8B): next = 6 (TCP), hdr_ext_len = 0
    ipv6_ext_tcp.extend_from_slice(&[6, 0, 1, 4, 0, 0, 0, 0]);
    // TCP Header (20B) + 4B payload
    ipv6_ext_tcp.extend_from_slice(&4444u16.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&8443u16.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&9001u32.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&9002u32.to_be_bytes());
    ipv6_ext_tcp.push(0x50);
    ipv6_ext_tcp.push(0x18); // PSH|ACK
    ipv6_ext_tcp.extend_from_slice(&2048u16.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&0u16.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(&0u16.to_be_bytes());
    ipv6_ext_tcp.extend_from_slice(tcp_payload);
    assert_eq!(ipv6_ext_tcp.len(), 94);

    // Build inner ARP Reply (42B) for Slave `0x1002` using the SAME `frame_no = 3, port = 0`!
    let mut arp_reply = Vec::new();
    arp_reply.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x12, 0x13]);
    arp_reply.extend_from_slice(&[0x00, 0x01, 0x05, 0x21, 0x22, 0x23]);
    arp_reply.extend_from_slice(&0x0806u16.to_be_bytes());
    arp_reply.extend_from_slice(&1u16.to_be_bytes());
    arp_reply.extend_from_slice(&0x0800u16.to_be_bytes());
    arp_reply.push(6);
    arp_reply.push(4);
    arp_reply.extend_from_slice(&2u16.to_be_bytes()); // ARP Reply (2)
    arp_reply.extend_from_slice(&[0x00, 0x01, 0x05, 0x21, 0x22, 0x23]);
    arp_reply.extend_from_slice(&[10, 99, 0, 2]);
    arp_reply.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x12, 0x13]);
    arp_reply.extend_from_slice(&[10, 99, 0, 1]);
    assert_eq!(arp_reply.len(), 42);

    let mut sess = DissectSession::new(DissectOptions::default());

    // Packet 1: Multi-datagram frame starting BOTH Slave `0x1001` (`frag_no=0`, 64B) and Slave `0x1002` (`frag_no=0`, 32B) with identical `frame_no = 3`!
    let mut b1 = EcatFrameBuilder::new();
    b1.add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        1,
        false,
        0,
        3,
        3,
        &ipv6_ext_tcp[..64],
    ))
    .add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1002,
        0x1080,
        2,
        false,
        0,
        2,
        3,
        &arp_reply[..32],
    ));
    sess.dissect_next(&b1.build().unwrap()).unwrap();

    // Packet 2: Multi-datagram frame completing BOTH Slave `0x1001` (`frag_no=1, offset=2`, bytes `64..94`) and Slave `0x1002` (`frag_no=1, offset=1`, bytes `32..42`)!
    let mut b2 = EcatFrameBuilder::new();
    b2.add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        3,
        true,
        1,
        2,
        3,
        &ipv6_ext_tcp[64..],
    ))
    .add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1002,
        0x1080,
        4,
        true,
        1,
        1,
        3,
        &arp_reply[32..],
    ));
    let df_done = sess.dissect_next(&b2.build().unwrap()).unwrap();
    assert_eq!(
        df_done.wireshark_fields["ecat_mailbox[0].eoe.reassembled_length"],
        94
    );
    assert_eq!(
        df_done.wireshark_fields["ecat[0].mailbox.eoe.tcp.dstport"],
        8443,
        "IPv6 Hop-by-Hop + Destination Options extension headers must be skipped to dissect inner TCP"
    );
    assert_eq!(
        df_done.wireshark_fields["ecat[0].mailbox.eoe.tcp.payload"],
        "41424344"
    );
    assert_eq!(
        df_done.wireshark_fields["ecat_mailbox[1].eoe.reassembled_length"],
        42
    );
    assert_eq!(
        df_done.wireshark_fields["ecat[1].mailbox.eoe.arp.opcode"],
        2
    );
    assert_eq!(
        df_done.wireshark_fields["ecat[1].mailbox.eoe.arp.src.proto_ipv4"],
        "10.99.0.2"
    );

    // Packet 3 & 4: Dropped intermediate fragment (`frag_no=0` -> `frag_no=2` with `frag_no=1` missing) MUST be rejected, never zero-filled!
    let mut b_gap0 = EcatFrameBuilder::new();
    b_gap0.add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        5,
        false,
        0,
        3,
        4,
        &ipv6_ext_tcp[..32],
    ));
    sess.dissect_next(&b_gap0.build().unwrap()).unwrap();

    let mut b_gap2 = EcatFrameBuilder::new();
    b_gap2.add_datagram(build_eoe_dg(
        EcatCmd::Fprd,
        0x1001,
        0x1080,
        6,
        true,
        2, // Skipped frag_no = 1!
        2,
        4,
        &ipv6_ext_tcp[64..],
    ));
    let df_gap = sess.dissect_next(&b_gap2.build().unwrap()).unwrap();
    assert!(
        !df_gap
            .wireshark_fields
            .contains_key("ecat_mailbox.eoe.reassembled_data"),
        "missing intermediate EoE fragment must discard frame instead of zero-filling a hole"
    );
}

#[test]
fn adversarial_ams_tcp_continuation_clean_mixed_boundary_tso_and_f302_upload() {
    let build_ipv4_tcp_ex = |src_ip: [u8; 4],
                             dst_ip: [u8; 4],
                             src_port: u16,
                             dst_port: u16,
                             seq: u32,
                             tso_zero_ip_len: bool,
                             tcp_payload: &[u8]| {
        let ip_len = if tso_zero_ip_len {
            0u16
        } else {
            (20 + 20 + tcp_payload.len()) as u16
        };
        let mut out = Vec::with_capacity(54 + tcp_payload.len());
        out.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
        out.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
        out.extend_from_slice(&0x0800u16.to_be_bytes());
        out.push(0x45);
        out.push(0x00);
        out.extend_from_slice(&ip_len.to_be_bytes());
        out.extend_from_slice(&[0x00, 0x05, 0x40, 0x00, 64, 6, 0x00, 0x00]);
        out.extend_from_slice(&src_ip);
        out.extend_from_slice(&dst_ip);
        out.extend_from_slice(&src_port.to_be_bytes());
        out.extend_from_slice(&dst_port.to_be_bytes());
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.push(0x50);
        out.push(0x18);
        out.extend_from_slice(&4096u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(tcp_payload);
        out
    };
    let wrap_ams_tcp = |ams_pdu: &[u8]| {
        let mut v = Vec::with_capacity(6 + ams_pdu.len());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&(ams_pdu.len() as u32).to_le_bytes());
        v.extend_from_slice(ams_pdu);
        v
    };

    let esi_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>#x00000002</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x44445555" RevisionNo="#x00010000">EL-AoeAdv</Type>
        <Name>AoE Adv Drive</Name>
        <Sm StartAddress="#x1100" DefaultSize="2" ControlByte="#x64" Enable="1">Outputs</Sm>
        <RxPdo Fixed="0" Sm="2">
          <Index>#x1600</Index>
          <Name>CtrlPDO</Name>
          <Entry>
            <Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen>
            <Name>AoeCtrl</Name><DataType>UINT</DataType>
          </Entry>
        </RxPdo>
        <Profile>
          <Dictionary>
            <DataTypes>
              <DataType><Name>UINT</Name><BitSize>16</BitSize></DataType>
            </DataTypes>
            <Objects>
              <Object><Index>#x6040</Index><Name>AoeCtrl</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(esi_xml).unwrap());
    let mut sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(cat),
        ..Default::default()
    });

    // Bind station `0x1001` + FMMU0 -> `0x0006_0000` (2B)
    let mut dg_st = RawDatagram::new_positioned(EcatCmd::Apwr, 1, 0, 0x0010, vec![0x01, 0x10]);
    dg_st.wkc = 1;
    let mut fmmu0 = vec![0u8; 16];
    fmmu0[0..4].copy_from_slice(&0x0006_0000u32.to_le_bytes());
    fmmu0[4..6].copy_from_slice(&2u16.to_le_bytes());
    fmmu0[7] = 7;
    fmmu0[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu0[11] = 0x02;
    fmmu0[12] = 0x01;
    let mut dg_fmmu = RawDatagram::new_positioned(EcatCmd::Fpwr, 2, 0x1001, 0x0600, fmmu0);
    dg_fmmu.wkc = 1;
    let mut b_hw = EcatFrameBuilder::new();
    b_hw.add_datagram(dg_st).add_datagram(dg_fmmu);
    sess.dissect_next(&b_hw.build().unwrap()).unwrap();

    // 1. Mid-stream garbage with non-zero `tcp_reserved` (`[0xFF, 0xFF, 40, 0, 0, 0, ...]`) must NOT stall subsequent valid PDUs!
    let bogus_mid = vec![0xFF, 0xFF, 40, 0, 0, 0, 1, 2, 3, 4];
    sess.dissect_next(&build_ipv4_tcp_ex(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        54000,
        TCP_PORT_AMS,
        100,
        false,
        &bogus_mid,
    ))
    .unwrap();

    // 2. 3-segment split of a large ADS Write PDU (100B total) where `seg2` is 45 middle payload bytes (`>= 38B`):
    //    `df_seg2` MUST NOT emit bogus `ams.targetnetid` / `ams.cmdid` / `ams.tcp_length`!
    let mut big_ads = Vec::with_capacity(12 + 50);
    big_ads.extend_from_slice(&0x4020u32.to_le_bytes());
    big_ads.extend_from_slice(&0u32.to_le_bytes());
    big_ads.extend_from_slice(&50u32.to_le_bytes());
    big_ads.extend((0..50u8).map(|i| i.wrapping_mul(7).wrapping_add(3)));
    let pdu0 = wrap_ams_tcp(&build_ams_pdu(
        [5, 1, 2, 3, 1, 1],
        851,
        [10, 0, 0, 1, 1, 1],
        32905,
        0x0003,
        0x0004,
        0,
        700,
        &big_ads,
    ));
    assert_eq!(pdu0.len(), 100);

    // PDU 1: non-SDO `ADS Read State` request (`cmd=4`, `sdo_ev = None`)
    let pdu1_non_sdo = wrap_ams_tcp(&build_ams_pdu(
        [5, 1, 2, 3, 1, 1],
        851,
        [10, 0, 0, 1, 1, 1],
        32905,
        0x0004,
        0x0004,
        0,
        701,
        &[],
    ));
    // PDU 2: `0xF302` `ADS Read` Request (`cmd=2`, SDO Upload of `0x1C12:00` CA -> `0x1C12_0100`)
    let mut f302_rd_req_body = Vec::with_capacity(12);
    f302_rd_req_body.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    f302_rd_req_body.extend_from_slice(&0x1C12_0100u32.to_le_bytes()); // 0x1C12, CA=true, sub=0
    f302_rd_req_body.extend_from_slice(&4u32.to_le_bytes());
    let pdu2_f302_rd_req = wrap_ams_tcp(&build_ams_pdu(
        [5, 12, 34, 56, 2, 1],
        0x1001,
        [10, 0, 0, 1, 1, 1],
        32905,
        0x0002,
        0x0004,
        0,
        702,
        &f302_rd_req_body,
    ));

    let seg0_a = &pdu0[..20];
    let seg0_b = &pdu0[20..65]; // 45 middle bytes (>= 38B)!
    let mut seg_mixed = Vec::new();
    seg_mixed.extend_from_slice(&pdu0[65..]); // tail of PDU 0 (35B)
    seg_mixed.extend_from_slice(&pdu1_non_sdo); // complete non-SDO PDU 1
    seg_mixed.extend_from_slice(&pdu2_f302_rd_req[..22]); // head of PDU 2
    let seg2_tail = &pdu2_f302_rd_req[22..];

    let mut cur_seq = 110u32;
    let df_s0a = sess
        .dissect_next(&build_ipv4_tcp_ex(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54000,
            TCP_PORT_AMS,
            cur_seq,
            false,
            seg0_a,
        ))
        .unwrap();
    cur_seq += seg0_a.len() as u32;
    assert_eq!(df_s0a.wireshark_fields["ams.reassembly_pending"], true);

    let df_s0b = sess
        .dissect_next(&build_ipv4_tcp_ex(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54000,
            TCP_PORT_AMS,
            cur_seq,
            false,
            seg0_b,
        ))
        .unwrap();
    cur_seq += seg0_b.len() as u32;
    assert_eq!(df_s0b.wireshark_fields["ams.reassembly_pending"], true);
    assert!(
        !df_s0b.wireshark_fields.contains_key("ams.targetnetid")
            && !df_s0b.wireshark_fields.contains_key("ams.cmdid")
            && !df_s0b.wireshark_fields.contains_key("ams.tcp_length"),
        "middle continuation TCP segment must not emit bogus AMS header fields"
    );

    // Mixed boundary segment completes PDU 0 + PDU 1 while buffering head of PDU 2!
    let df_mix = sess
        .dissect_next(&build_ipv4_tcp_ex(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            54000,
            TCP_PORT_AMS,
            cur_seq,
            false,
            &seg_mixed,
        ))
        .unwrap();
    cur_seq += seg_mixed.len() as u32;
    assert_eq!(df_mix.wireshark_fields["ams.pdu_count"], 2);
    assert_eq!(df_mix.wireshark_fields["ams[0].invokeid"], "0x000002bc");
    assert_eq!(df_mix.wireshark_fields["ams[1].invokeid"], "0x000002bd");
    assert_eq!(
        df_mix.direct_ams.as_ref().unwrap()["trailing_buffered_bytes"],
        22
    );

    // Complete PDU 2 (`0xF302` ADS Read Request, `invoke_id = 702`, `pdu_idx = 0`) + second `0xF302` ADS Read Request (`0x6040:00`, `invoke_id = 703`, `pdu_idx = 1`) in a TSO (`ip.total_len == 0`) packet!
    let mut tail_plus_extra = seg2_tail.to_vec();
    let mut f302_rd_6040 = Vec::with_capacity(12);
    f302_rd_6040.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    f302_rd_6040.extend_from_slice(&0x6040_0000u32.to_le_bytes());
    f302_rd_6040.extend_from_slice(&2u32.to_le_bytes());
    tail_plus_extra.extend_from_slice(&wrap_ams_tcp(&build_ams_pdu(
        [5, 12, 34, 56, 2, 1],
        0x1001,
        [10, 0, 0, 1, 1, 1],
        32905,
        0x0002,
        0x0004,
        0,
        703,
        &f302_rd_6040,
    )));
    let pkt_tso = build_ipv4_tcp_ex(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        54000,
        TCP_PORT_AMS,
        cur_seq,
        true, // TSO ip.total_len == 0!
        &tail_plus_extra,
    );
    assert!(
        ethercat_dissector::may_contain_ethercat(&pkt_tso, false),
        "TSO TCP packet (ip.total_len == 0) on port 48898 must pass may_contain_ethercat"
    );
    let df_tso = sess.dissect_next(&pkt_tso).unwrap();
    assert_eq!(df_tso.wireshark_fields["ams.pdu_count"], 2);
    assert_eq!(
        df_tso.wireshark_fields["ams[1].coe.sdo.xml.object_name"],
        "AoeCtrl"
    );
    assert!(
        !df_tso
            .wireshark_fields
            .contains_key("ecat_mailbox.coe.sdo.xml.object_name"),
        "standalone AMS/TCP frame must not leak ecat_mailbox.coe.sdo.xml.* fields"
    );

    // 3. Server->Client `ADS Read Response` (`cmd=2, is_response=true`) for `invoke_id = 702` (`0x1C12:0` CA -> `[1, 0, 0x00, 0x16]`)
    //    coalesced AFTER a non-SDO `ADS Read State Response` (`pdu_idx = 0` has `sdo_ev = None`, `pdu_idx = 1` & `2` have `AoeReadRes`)!
    let pdu_state_res = wrap_ams_tcp(&build_ams_pdu(
        [10, 0, 0, 1, 1, 1],
        32905,
        [5, 1, 2, 3, 1, 1],
        851,
        0x0004,
        0x0005, // Response | AdsCmd
        0,
        701,
        &[0, 0, 0, 0, 5, 0, 0, 0],
    ));
    let mut rd_res_702_body = Vec::new();
    rd_res_702_body.extend_from_slice(&0u32.to_le_bytes()); // result = 0
    rd_res_702_body.extend_from_slice(&4u32.to_le_bytes()); // len = 4
    rd_res_702_body.extend_from_slice(&[0x01, 0x00, 0x00, 0x16]); // CA: count=1, sub1=0x1600
    let pdu_rd_res_702 = wrap_ams_tcp(&build_ams_pdu(
        [10, 0, 0, 1, 1, 1],
        32905, // client target_port (NOT 0x1001!)
        [5, 12, 34, 56, 2, 1],
        0x1001, // slave sender_port!
        0x0002,
        0x0005, // Response | AdsCmd
        0,
        702,
        &rd_res_702_body,
    ));
    let mut rd_res_703_body = Vec::new();
    rd_res_703_body.extend_from_slice(&0u32.to_le_bytes());
    rd_res_703_body.extend_from_slice(&2u32.to_le_bytes());
    rd_res_703_body.extend_from_slice(&0x000Fu16.to_le_bytes());
    let pdu_rd_res_703 = wrap_ams_tcp(&build_ams_pdu(
        [10, 0, 0, 1, 1, 1],
        32905,
        [5, 12, 34, 56, 2, 1],
        0x1001,
        0x0002,
        0x0005,
        0,
        703,
        &rd_res_703_body,
    ));
    let mut server_coalesced = Vec::new();
    server_coalesced.extend_from_slice(&pdu_state_res);
    server_coalesced.extend_from_slice(&pdu_rd_res_702);
    server_coalesced.extend_from_slice(&pdu_rd_res_703);

    let df_srv = sess
        .dissect_next(&build_ipv4_tcp_ex(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            TCP_PORT_AMS,
            54000,
            5000,
            false,
            &server_coalesced,
        ))
        .unwrap();
    // Verify `pdu_idx = 0` (`ADS Read State Res`) was NOT polluted by `pdu_idx = 1` or `2`'s `sdo_xml`,
    // and `pdu_idx = 2` (`invoke_id = 703`, `0x6040:00`) decoded `value == 15`!
    let srv_pdus = df_srv.direct_ams.as_ref().unwrap()["pdus"]
        .as_array()
        .unwrap();
    assert!(srv_pdus[0].get("sdo_xml").is_none());
    assert_eq!(df_srv.wireshark_fields["ams[2].coe.sdo.xml.value"], 15);

    // And `invoke_id = 702` (`0x1C12:0` CA SDO Upload over AoE) activated `0x1600` (`AoeCtrl`) on slave `0x1001`!
    let mut dg_lrw = RawDatagram::new_logical(
        EcatCmd::Lrw,
        9,
        0x0006_0000,
        0x00ABu16.to_le_bytes().to_vec(),
    );
    dg_lrw.wkc = 1;
    let mut b_lrw = EcatFrameBuilder::new();
    b_lrw.add_datagram(dg_lrw);
    let df_cyc = sess.dissect_next(&b_lrw.build().unwrap()).unwrap();
    assert_eq!(df_cyc.wireshark_fields["ecat.pdo.AoeCtrl"], 0x00AB);
}

#[test]
fn wireshark_46_complete_694_fields_ipv6_tcp34980_aprw_and_ca_fallback() {
    // 1. Verify `ecat.sub`, `ecat.fmmu`, `ecat.syncman`, and 1-byte `0x0500` `eeprom.assign.status`:
    let mut fmmu_bytes = vec![0u8; 16];
    fmmu_bytes[0..4].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    fmmu_bytes[4..6].copy_from_slice(&4u16.to_le_bytes());
    fmmu_bytes[7] = 7;
    fmmu_bytes[8..10].copy_from_slice(&0x1100u16.to_le_bytes());
    fmmu_bytes[11] = 0x02;
    fmmu_bytes[12] = 0x01;
    let mut dg_fmmu =
        RawDatagram::new_positioned(EcatCmd::Fpwr, 0x11, 0x1001, 0x0600, fmmu_bytes.clone());
    dg_fmmu.wkc = 1;

    let sm_bytes = vec![0x00, 0x11, 0x04, 0x00, 0x64, 0x00, 0x01, 0x00];
    let mut dg_sm =
        RawDatagram::new_positioned(EcatCmd::Fpwr, 0x12, 0x1001, 0x0810, sm_bytes.clone());
    dg_sm.wkc = 1;

    let mut dg_eep1 = RawDatagram::new_positioned(EcatCmd::Fprd, 0x13, 0x1001, 0x0500, vec![0x10]);
    dg_eep1.wkc = 1;

    let mut b_cont = EcatFrameBuilder::new();
    b_cont.add_datagram(dg_fmmu);
    b_cont.add_datagram(dg_sm);
    b_cont.add_datagram(dg_eep1);
    let raw_cont = b_cont.build().unwrap();
    let df_cont = dissect_frame(&raw_cont, &DissectOptions::default()).unwrap();
    assert_eq!(
        df_cont.wireshark_fields["ecat.fmmu"],
        "00000200040000070011000201000000"
    );
    assert_eq!(
        df_cont.wireshark_fields["ecat[1].syncman"],
        "0011040064000100"
    );
    assert_eq!(df_cont.wireshark_fields["ecat.syncman"], "0011040064000100");
    // `ecat.sub` = 10B datagram header + 16B FMMU payload + 2B WKC = 28 bytes = 56 hex chars
    assert_eq!(
        df_cont.wireshark_fields["ecat.sub"].as_str().unwrap().len(),
        56
    );
    assert_eq!(
        df_cont.wireshark_fields["ecat[1].sub"]
            .as_str()
            .unwrap()
            .len(),
        (10 + 8 + 2) * 2
    );
    assert_eq!(
        df_cont.wireshark_fields["ecat[2].reg.eeprom.assign.status"],
        true
    );

    // 2. Outer IPv4 TCP `34980` (`ecatf`) + Outer IPv6 (`0x86DD`, with & without Hop-by-Hop ext hdr)
    //    covering UDP/34980, TCP/34980, AMS/UDP 48899, and multi-segment AMS/TCP 48898:
    let build_ecat_pdu = |ado: u16, val: u16| -> Vec<u8> {
        let mut dg = RawDatagram::new_positioned(
            EcatCmd::Fprd,
            0x21,
            0x1001,
            ado,
            val.to_le_bytes().to_vec(),
        );
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        let eth = b.build().unwrap();
        eth[14..].to_vec() // strip 14B Ethernet header -> starts at 2B `ecatf` header
    };

    let build_ipv6_l4 = |src_ip: [u8; 16],
                         dst_ip: [u8; 16],
                         with_hbh_ext: bool,
                         next_proto: u8,
                         l4_bytes: &[u8]|
     -> Vec<u8> {
        let ext_len = if with_hbh_ext { 8usize } else { 0usize };
        let payload_len = (ext_len + l4_bytes.len()) as u16;
        let mut out = Vec::with_capacity(14 + 40 + payload_len as usize);
        out.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
        out.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
        out.extend_from_slice(&0x86DDu16.to_be_bytes());
        out.extend_from_slice(&[0x60, 0x00, 0x00, 0x00]); // IPv6 version 6
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.push(if with_hbh_ext { 0 } else { next_proto }); // Hop-by-Hop (0) or L4
        out.push(64); // Hop Limit
        out.extend_from_slice(&src_ip);
        out.extend_from_slice(&dst_ip);
        if with_hbh_ext {
            out.extend_from_slice(&[next_proto, 0, 1, 4, 0, 0, 0, 0]); // 8-byte PadN Hop-by-Hop option
        }
        out.extend_from_slice(l4_bytes);
        out
    };

    let wrap_udp = |sport: u16, dport: u16, body: &[u8]| -> Vec<u8> {
        let ulen = (8 + body.len()) as u16;
        let mut u = Vec::with_capacity(ulen as usize);
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&ulen.to_be_bytes());
        u.extend_from_slice(&0u16.to_be_bytes());
        u.extend_from_slice(body);
        u
    };

    let wrap_tcp = |sport: u16, dport: u16, seq: u32, body: &[u8]| -> Vec<u8> {
        let mut t = Vec::with_capacity(20 + body.len());
        t.extend_from_slice(&sport.to_be_bytes());
        t.extend_from_slice(&dport.to_be_bytes());
        t.extend_from_slice(&seq.to_be_bytes());
        t.extend_from_slice(&1u32.to_be_bytes());
        t.push(0x50); // data offset = 20B
        t.push(0x18); // PSH | ACK
        t.extend_from_slice(&4096u16.to_be_bytes());
        t.extend_from_slice(&0u16.to_be_bytes());
        t.extend_from_slice(&0u16.to_be_bytes());
        t.extend_from_slice(body);
        t
    };

    let ecat_al = build_ecat_pdu(0x0130, 0x0008); // AL Status = OP (8)
    let v4_tcp_ecat = {
        let tcp_seg = wrap_tcp(51000, TCP_PORT_ECAT, 100, &ecat_al);
        let ip_len = (20 + tcp_seg.len()) as u16;
        let mut p = Vec::with_capacity(14 + ip_len as usize);
        p.extend_from_slice(&[0x00, 0x01, 0x05, 0xAA, 0xBB, 0xCC]);
        p.extend_from_slice(&[0x00, 0x01, 0x05, 0x11, 0x22, 0x33]);
        p.extend_from_slice(&0x0800u16.to_be_bytes());
        p.extend_from_slice(&[0x45, 0x00]);
        p.extend_from_slice(&ip_len.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, 6, 0, 0]);
        p.extend_from_slice(&[192, 168, 1, 10, 192, 168, 1, 20]);
        p.extend_from_slice(&tcp_seg);
        p
    };
    let src_v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst_v6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let v6_udp_ecat = build_ipv6_l4(
        src_v6,
        dst_v6,
        false,
        17,
        &wrap_udp(52000, UDP_PORT_ECAT, &ecat_al),
    );
    let v6_hbh_tcp_ecat = build_ipv6_l4(
        src_v6,
        dst_v6,
        true,
        6,
        &wrap_tcp(52001, TCP_PORT_ECAT, 200, &ecat_al),
    );

    let mut ams_pdu = Vec::with_capacity(44);
    ams_pdu.extend_from_slice(&[5, 1, 2, 3, 1, 1]);
    ams_pdu.extend_from_slice(&851u16.to_le_bytes());
    ams_pdu.extend_from_slice(&[10, 0, 0, 1, 1, 1]);
    ams_pdu.extend_from_slice(&32905u16.to_le_bytes());
    ams_pdu.extend_from_slice(&0x0002u16.to_le_bytes()); // ADS Read
    ams_pdu.extend_from_slice(&0x0004u16.to_le_bytes()); // Request | AdsCmd
    ams_pdu.extend_from_slice(&12u32.to_le_bytes());
    ams_pdu.extend_from_slice(&0u32.to_le_bytes());
    ams_pdu.extend_from_slice(&888u32.to_le_bytes());
    ams_pdu.extend_from_slice(&0x4020u32.to_le_bytes());
    ams_pdu.extend_from_slice(&0x0010u32.to_le_bytes());
    ams_pdu.extend_from_slice(&4u32.to_le_bytes());

    let v6_udp_ams = build_ipv6_l4(
        src_v6,
        dst_v6,
        false,
        17,
        &wrap_udp(52002, UDP_PORT_AMS, &ams_pdu),
    );
    let mut ams_tcp_wire = Vec::with_capacity(6 + ams_pdu.len());
    ams_tcp_wire.extend_from_slice(&0u16.to_le_bytes());
    ams_tcp_wire.extend_from_slice(&(ams_pdu.len() as u32).to_le_bytes());
    ams_tcp_wire.extend_from_slice(&ams_pdu);
    let v6_tcp_ams_seg1 = build_ipv6_l4(
        src_v6,
        dst_v6,
        false,
        6,
        &wrap_tcp(52003, TCP_PORT_AMS, 1000, &ams_tcp_wire[..20]),
    );
    let v6_tcp_ams_seg2 = build_ipv6_l4(
        src_v6,
        dst_v6,
        false,
        6,
        &wrap_tcp(52003, TCP_PORT_AMS, 1020, &ams_tcp_wire[20..]),
    );
    let v6_tcp_ams_full = build_ipv6_l4(
        src_v6,
        dst_v6,
        false,
        6,
        &wrap_tcp(52004, TCP_PORT_AMS, 2000, &ams_tcp_wire),
    );

    let df_v4_tcp = dissect_frame(&v4_tcp_ecat, &DissectOptions::default()).unwrap();
    assert_eq!(df_v4_tcp.wireshark_fields["tcp.dstport"], TCP_PORT_ECAT);
    assert_eq!(df_v4_tcp.wireshark_fields["ecat.reg.al_state"], "OP");

    let df_v6_udp = dissect_frame(&v6_udp_ecat, &DissectOptions::default()).unwrap();
    assert_eq!(df_v6_udp.wireshark_fields["ipv6.src"], "fe80::1");
    assert_eq!(df_v6_udp.wireshark_fields["ipv6.dst"], "fe80::2");
    assert_eq!(df_v6_udp.wireshark_fields["ecat.reg.al_state"], "OP");

    let df_v6_hbh = dissect_frame(&v6_hbh_tcp_ecat, &DissectOptions::default()).unwrap();
    assert_eq!(df_v6_hbh.wireshark_fields["tcp.dstport"], TCP_PORT_ECAT);
    assert_eq!(df_v6_hbh.wireshark_fields["ecat.reg.al_state"], "OP");

    let df_v6_uams = dissect_frame(&v6_udp_ams, &DissectOptions::default()).unwrap();
    assert_eq!(df_v6_uams.wireshark_fields["ams.targetport"], 851);
    assert_eq!(
        df_v6_uams.wireshark_fields["ams.ads_indexgroup"],
        "0x00004020"
    );

    // Multi-segment AMS/TCP reassembly over IPv6:
    let mut v6_sess = DissectSession::new(DissectOptions::default());
    let df_s1 = v6_sess.dissect_next(&v6_tcp_ams_seg1).unwrap();
    assert_eq!(df_s1.wireshark_fields["ams.reassembly_pending"], true);
    let df_s2 = v6_sess.dissect_next(&v6_tcp_ams_seg2).unwrap();
    assert_eq!(df_s2.wireshark_fields["ams.reassembled"], true);
    assert_eq!(df_s2.wireshark_fields["ams.invokeid"], "0x00000378");

    // 3. Live `tshark.exe` 694-field registry audit + IPv4/IPv6/TCP34980 PCAP cross-check:
    let tshark_path = Path::new(r"C:\Program Files\Wireshark\tshark.exe");
    if tshark_path.exists() {
        let fields_out = Command::new(tshark_path)
            .arg("-G")
            .arg("fields")
            .output()
            .expect("run tshark -G fields");
        assert!(fields_out.status.success());
        let stdout = String::from_utf8_lossy(&fields_out.stdout);
        let official_protos: std::collections::HashSet<&str> =
            WIRESHARK_PROTOCOLS.iter().map(|(p, _)| *p).collect();
        let mut official_fields = Vec::new();
        for line in stdout.lines() {
            if !line.starts_with("F\t") {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 && official_protos.contains(cols[4]) {
                official_fields.push(cols[2].to_string());
            }
        }
        assert_eq!(
            official_fields.len(),
            694,
            "Wireshark 4.6 ethercat.dll registers exactly 694 hf_* fields across the 7 protocols"
        );
        // Runtime 694/694 field emission proof across all 7 official protocols:
        let mut emitted: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut collect_ws = |ws: &std::collections::BTreeMap<String, serde_json::Value>| {
            for k in ws.keys() {
                emitted.insert(k.clone());
            }
        };

        // (a) ESL + ecatf + 10 logical subframes + pad_bytes:
        let mut b_lad10 = EcatFrameBuilder::new();
        for i in 0..10u8 {
            let mut dg =
                RawDatagram::new_logical(EcatCmd::Lrw, i, 0x0001_0000 + i as u32 * 4, vec![1, 2]);
            dg.wkc = 1;
            b_lad10.add_datagram(dg);
        }
        let mut eth_lad10 = b_lad10.build().unwrap();
        eth_lad10.extend_from_slice(&[0, 0, 0, 0]);
        let mut esl_prefixed = Vec::with_capacity(16 + eth_lad10.len());
        esl_prefixed.extend_from_slice(&ESL_SIGNATURE);
        esl_prefixed.extend_from_slice(&0x3801u16.to_le_bytes());
        esl_prefixed.extend_from_slice(&123_456_789u64.to_le_bytes());
        esl_prefixed.extend_from_slice(&eth_lad10);
        collect_ws(
            &dissect_frame(&esl_prefixed, &DissectOptions::default())
                .unwrap()
                .wireshark_fields,
        );

        // (b) 10 physical DC receive-time subframes (`0x0900`, 24B each across Port B/D/C topologies) + stateful `ARMW 0x0910` (`dc.dif.curtime`):
        let mut dc_sess = DissectSession::new(DissectOptions::default());
        for topo_times in [
            [100u32, 300, 600, 200, 0, 0], // Port A/B/C/D open -> da, bd, cb, ba
            [100u32, 0, 600, 200, 0, 0],   // Port B closed -> cd
            [100u32, 0, 600, 0, 0, 0],     // Port B & D closed -> ca
        ] {
            let mut dc24 = Vec::with_capacity(24);
            for &t in &topo_times {
                dc24.extend_from_slice(&t.to_le_bytes());
            }
            let mut b_dc10 = EcatFrameBuilder::new();
            for i in 0..10u8 {
                let mut dg = RawDatagram::new_positioned(EcatCmd::Aprd, i, 0, 0x0900, dc24.clone());
                dg.wkc = 1;
                b_dc10.add_datagram(dg);
            }
            collect_ws(
                &dc_sess
                    .dissect_next(&b_dc10.build().unwrap())
                    .unwrap()
                    .wireshark_fields,
            );
        }
        for &ts in &[1_000u32, 2_500u32] {
            let mut b_cur = EcatFrameBuilder::new();
            let mut dg =
                RawDatagram::new_positioned(EcatCmd::Armw, 1, 0, 0x0910, ts.to_le_bytes().to_vec());
            dg.wkc = 1;
            b_cur.add_datagram(dg);
            collect_ws(
                &dc_sess
                    .dissect_next(&b_cur.build().unwrap())
                    .unwrap()
                    .wireshark_fields,
            );
        }

        // (c) Full ESC Register space `0x0000..0x0A00` across two frames (`0x0000..0x0600` & `0x0600..0x0A00`):
        for (ado, rlen) in [(0x0000u16, 0x0600usize), (0x0600, 0x0400)] {
            let mut b_regs = EcatFrameBuilder::new();
            let mut dg_r =
                RawDatagram::new_positioned(EcatCmd::Fprd, 1, 0x1001, ado, vec![0x55; rlen]);
            dg_r.wkc = 1;
            b_regs.add_datagram(dg_r);
            collect_ws(
                &dissect_frame(&b_regs.build().unwrap(), &DissectOptions::default())
                    .unwrap()
                    .wireshark_fields,
            );
        }

        // (d) `tc_nv` (type 4) and `ioraw` (type 3):
        let mut nv_body = vec![0x11; 12];
        nv_body.extend_from_slice(&1u16.to_le_bytes());
        nv_body.extend_from_slice(&7u16.to_le_bytes());
        nv_body.extend_from_slice(&1u16.to_le_bytes());
        nv_body.extend_from_slice(&2u16.to_le_bytes());
        nv_body.extend_from_slice(&4u16.to_le_bytes());
        nv_body.extend_from_slice(&0u16.to_le_bytes());
        nv_body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        collect_ws(
            &dissect_frame(
                &build_eth_ecat_frame(ECAT_FRAME_TYPE_NV, &nv_body),
                &DissectOptions::default(),
            )
            .unwrap()
            .wireshark_fields,
        );
        collect_ws(
            &dissect_frame(
                &build_eth_ecat_frame(ECAT_FRAME_TYPE_RAW_IO, &[1, 2, 3, 4, 5, 6, 7, 8]),
                &DissectOptions::default(),
            )
            .unwrap()
            .wireshark_fields,
        );

        // (e) `ams` (all ADS commands 1..=9 req/res + raw non-ADS data):
        let make_ams = |cmd: u16, state: u16, body: &[u8]| -> Vec<u8> {
            let mut p = Vec::with_capacity(32 + body.len());
            p.extend_from_slice(&[5, 1, 2, 3, 1, 1]);
            p.extend_from_slice(&851u16.to_le_bytes());
            p.extend_from_slice(&[10, 0, 0, 1, 1, 1]);
            p.extend_from_slice(&32905u16.to_le_bytes());
            p.extend_from_slice(&cmd.to_le_bytes());
            p.extend_from_slice(&state.to_le_bytes());
            p.extend_from_slice(&(body.len() as u32).to_le_bytes());
            p.extend_from_slice(&0u32.to_le_bytes());
            p.extend_from_slice(&1u32.to_le_bytes());
            p.extend_from_slice(body);
            p
        };
        let mut dn_body = Vec::new();
        dn_body.extend_from_slice(&28u32.to_le_bytes());
        dn_body.extend_from_slice(&1u32.to_le_bytes());
        dn_body.extend_from_slice(&0u64.to_le_bytes());
        dn_body.extend_from_slice(&1u32.to_le_bytes());
        dn_body.extend_from_slice(&99u32.to_le_bytes());
        dn_body.extend_from_slice(&4u32.to_le_bytes());
        dn_body.extend_from_slice(&[1, 2, 3, 4]);
        for (cmd, st, body) in [
            (1u16, 0x0004u16, vec![0u8; 4]),
            (1, 0x0005, vec![0u8; 24]),
            (2, 0x0004, vec![0u8; 12]),
            (2, 0x0005, vec![0, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]),
            (
                3,
                0x0004,
                vec![0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4],
            ),
            (3, 0x0005, vec![0u8; 4]),
            (4, 0x0004, vec![]),
            // Wireshark 4.6 only adds `ams.ads_invokeid` for a Read State request with cbData != 0.
            (4, 0x0004, vec![7, 0, 0, 0]),
            (4, 0x0005, vec![0u8; 8]),
            (5, 0x0004, vec![0, 0, 0, 0, 2, 0, 0, 0, 9, 9]),
            (5, 0x0005, vec![0u8; 4]),
            (6, 0x0004, vec![0u8; 40]),
            (6, 0x0005, vec![0u8; 8]),
            (7, 0x0004, vec![0u8; 4]),
            (7, 0x0005, vec![0u8; 4]),
            (8, 0x0004, dn_body),
            (
                9,
                0x0004,
                vec![0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0, 0, 0, 7, 8],
            ),
            (9, 0x0005, vec![0, 0, 0, 0, 2, 0, 0, 0, 7, 8]),
            (99, 0x0000, vec![1, 2, 3, 4]),
        ] {
            let mut ws_a = std::collections::BTreeMap::new();
            ethercat_dissector::dissect_ams_pdu(&make_ams(cmd, st, &body), &mut ws_a, None);
            collect_ws(&ws_a);
        }

        // (f) `ecat_mailbox` (valid + malformed EoE, CoE, FoE/.efw, SoE, VoE):
        let wrap_mbx = |mtype: u8, body: &[u8]| -> Vec<u8> {
            let mut m = Vec::with_capacity(6 + body.len());
            m.extend_from_slice(&(body.len() as u16).to_le_bytes());
            m.extend_from_slice(&0x1001u16.to_le_bytes());
            m.push(0x01);
            m.push((1 << 4) | (mtype & 0x0F));
            m.extend_from_slice(body);
            m
        };
        let mut ws_m = std::collections::BTreeMap::new();
        let _ = ethercat_dissector::dissect_mailbox(&[1, 2, 3], &mut ws_m, "ecat_mailbox");
        for mt in [2u8, 3, 4, 5] {
            let _ =
                ethercat_dissector::dissect_mailbox(&wrap_mbx(mt, &[]), &mut ws_m, "ecat_mailbox");
        }
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(0x0F, &[1, 2, 3, 4]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(2, &[0x00, 0x03, 0, 0, 1, 2, 3, 4, 0xAA, 0xBB, 0xCC, 0xDD]),
            &mut ws_m,
            "ecat_mailbox",
        );
        // Wireshark 4.6 only adds `eoe.timestampreq` when TimeStampRequested (0x0400) is set.
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(2, &[0x00, 0x05, 0, 0, 1, 2, 3, 4]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(2, &[0x01, 0x00, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let mut eoe_init = vec![0x02, 0x00, 0x00, 0x00];
        eoe_init.extend_from_slice(&0x0001_003Fu32.to_le_bytes());
        eoe_init.extend_from_slice(&[0u8; 6 + 4 + 4 + 4 + 4]);
        eoe_init.extend_from_slice(b"ecat-slave\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
        let _ =
            ethercat_dissector::dissect_mailbox(&wrap_mbx(2, &eoe_init), &mut ws_m, "ecat_mailbox");
        let mut eoe_mf = vec![0x04, 0x00, 0x00, 0x00];
        eoe_mf.extend_from_slice(&0xFFFFu16.to_le_bytes());
        eoe_mf.extend_from_slice(&[0x22u8; 16 * 6 + 4 * 6]);
        let _ =
            ethercat_dissector::dissect_mailbox(&wrap_mbx(2, &eoe_mf), &mut ws_m, "ecat_mailbox");
        for coe_body in [
            vec![0x00, 0x20, 0x23, 0x00, 0x20, 0x01, 1, 2, 3, 4],
            vec![0x00, 0x20, 0x21, 0x00, 0x20, 0x01, 4, 0, 0, 0, 9, 8, 7, 6],
            vec![0x00, 0x20, 0x01, 1, 2, 3, 4, 5, 6, 7],
            vec![0x00, 0x20, 0x40, 0x00, 0x20, 0x01, 0, 0, 0, 0],
            vec![0x00, 0x20, 0x60, 0, 0, 0, 0, 0, 0, 0],
            vec![0x00, 0x20, 0x80, 0x00, 0x20, 0x01, 0, 0, 2, 6],
            vec![0x00, 0x30, 0x43, 0x00, 0x20, 0x01, 1, 2, 3, 4],
            vec![0x00, 0x30, 0x20, 0, 0, 0, 0, 0, 0, 0],
            vec![0x00, 0x30, 0x01, 1, 2, 3, 4, 5, 6, 7],
            vec![0x00, 0x80, 0x01, 0, 0, 0, 0x01, 0x00],
            vec![0x00, 0x80, 0x02, 0, 0, 0, 0x01, 0x00, 0x00, 0x10],
            vec![
                0x00, 0x80, 0x04, 0, 0, 0, 0x00, 0x10, 0x07, 0x00, 2, 7, b'O', b'b',
            ],
            vec![
                0x00, 0x80, 0x06, 0, 0, 0, 0x40, 0x60, 0, 0x78, 0x06, 0x00, 0x10, 0x00, 0x3F, 0x00,
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, b'C', b't',
            ],
            vec![0x00, 0x80, 0x07, 0, 0, 0, 0, 0, 2, 6],
        ] {
            let _ = ethercat_dissector::dissect_mailbox(
                &wrap_mbx(3, &coe_body),
                &mut ws_m,
                "ecat_mailbox",
            );
        }
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(4, &[2, 0, 64, 0, 0, 0, b'f', b'w', b'.', b'e', b'f', b'w']),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox_ext(
            &wrap_mbx(
                4,
                &[
                    3, 0, 1, 0, 0, 0, 1, 0, 4, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD,
                ],
            ),
            &mut ws_m,
            "ecat_mailbox",
            true,
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(4, &[4, 0, 1, 0, 0, 0]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(4, &[5, 0, 1, 0, 0, 0, b'e', b'r', b'r']),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(4, &[6, 0, 10, 0, 100, 0, b'b', b'u', b's', b'y']),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(5, &[0x02, 0x40, 0x10, 0x00, 0x34, 0x12]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(5, &[0x0A, 0x40, 0x02, 0x00, 0x34, 0x12]),
            &mut ws_m,
            "ecat_mailbox",
        );
        let _ = ethercat_dissector::dissect_mailbox(
            &wrap_mbx(5, &[0x12, 0x40, 0x10, 0x00, 0x01, 0x70]),
            &mut ws_m,
            "ecat_mailbox",
        );
        collect_ws(&ws_m);

        let missing: Vec<String> = official_fields
            .iter()
            .filter(|f| !emitted.contains(*f))
            .cloned()
            .collect();
        assert!(
            missing.is_empty(),
            "missing runtime-emitted official Wireshark 4.6 EtherCAT fields ({}/694): {missing:?}",
            missing.len()
        );

        // Live `tshark.exe` PCAP parity check on IPv4 TCP/34980 + IPv6 UDP/34980 + IPv6 TCP/34980 + IPv6 AMS:
        let pcap_path = std::env::temp_dir().join(format!(
            "ecat_ipv6_tcp34980_parity_{}.pcap",
            unique_test_id()
        ));
        write_pcap_file(
            &pcap_path,
            &[
                (1_000, raw_cont.clone()),
                (2_000, v4_tcp_ecat.clone()),
                (3_000, v6_udp_ecat.clone()),
                (4_000, v6_hbh_tcp_ecat.clone()),
                (5_000, v6_udp_ams.clone()),
                (6_000, v6_tcp_ams_full.clone()),
            ],
        )
        .unwrap();
        let mut ours = Vec::new();
        dissect_capture_file(
            &pcap_path,
            FrameInputKind::Pcap,
            DissectOptions::default(),
            |_rec, df| {
                ours.push(df);
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(ours.len(), 6);

        let ts_out = Command::new(tshark_path)
            .args([
                "-r",
                pcap_path.to_str().unwrap(),
                "-T",
                "fields",
                "-e",
                "frame.protocols",
                "-e",
                "ecat.cmd",
                "-e",
                "ams.cmdid",
            ])
            .output()
            .expect("run tshark on IPv6/TCP34980 PCAP");
        let _ = std::fs::remove_file(&pcap_path);
        assert!(ts_out.status.success());
        let ts_lines: Vec<String> = String::from_utf8_lossy(&ts_out.stdout)
            .lines()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(ts_lines.len(), 6);
        assert!(ts_lines[1].contains("ip:tcp:ecatf:ecat"));
        assert!(ts_lines[2].contains("ipv6:udp:ecatf:ecat"));
        assert!(
            ts_lines[3].contains("ipv6:ipv6.hopopts:tcp:ecatf:ecat")
                || (ts_lines[3].contains("ipv6") && ts_lines[3].contains("ecatf:ecat"))
        );
        // Official `ethercat.dll` only registers `tcp.port == 48898` for `ams` (`udp.port == 48899` is our extra Beckhoff AMS/UDP enhancement)
        assert_eq!(ours[4].wireshark_fields["ams.cmdid"], 2);
        assert!(ts_lines[5].contains("ipv6:tcp:ams"));
    }

    // 4. CoE SDO Info `0x06` (`Get Entry Description Response`) 2-byte short-frame `UnitType` fallback
    //    AND full 4-byte ETG.1000.6 `UnitType` + `Default` + `Min` + `Max` + `EntryName`:
    let mut mbx_short_ut = vec![0u8; 6 + 2 + 4 + 10 + 2];
    mbx_short_ut[0..2].copy_from_slice(&18u16.to_le_bytes());
    mbx_short_ut[5] = 0x13;
    mbx_short_ut[6..8].copy_from_slice(&0x8000u16.to_le_bytes());
    mbx_short_ut[8] = 0x06;
    mbx_short_ut[12..14].copy_from_slice(&0x6040u16.to_le_bytes());
    mbx_short_ut[15] = 0x08; // unit_type present, 2 bytes remaining (Wireshark FT_UINT16 style)
    mbx_short_ut[16..18].copy_from_slice(&0x0006u16.to_le_bytes());
    mbx_short_ut[18..20].copy_from_slice(&16u16.to_le_bytes());
    mbx_short_ut[20..22].copy_from_slice(&0x003Fu16.to_le_bytes());
    mbx_short_ut[22..24].copy_from_slice(&0x1234u16.to_le_bytes());
    let mut ws_ut = std::collections::BTreeMap::new();
    ethercat_dissector::dissect_mailbox(&mbx_short_ut, &mut ws_ut, "ecat_mailbox").unwrap();
    assert_eq!(ws_ut["ecat_mailbox.coe.sdoinfounittype"], "0x1234");

    // 5. Stateful Temporal PDO over physical `APRW` & `FPRW` + Complete Access (`CA = 1`) fallback `subitems`:
    let min_esi = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#x77773052" RevisionNo="#x00010000">RwDrive</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x64" Enable="1">Outputs</Sm>
        <Sm StartAddress="#x1400" ControlByte="#x20" Enable="1">Inputs</Sm>
        <RxPdo Fixed="0">
          <Index>#x1600</Index><Name>Outputs</Name>
          <Entry><Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen><Name>RwCtrl</Name><DataType>UINT</DataType></Entry>
        </RxPdo>
        <TxPdo Fixed="0">
          <Index>#x1A00</Index><Name>Inputs</Name>
          <Entry><Index>#x6041</Index><SubIndex>0</SubIndex><BitLen>16</BitLen><Name>RwStat</Name><DataType>UINT</DataType></Entry>
        </TxPdo>
        <Profile>
          <Dictionary>
            <DataTypes><DataType><Name>UINT</Name><BitSize>16</BitSize></DataType></DataTypes>
            <Objects>
              <Object><Index>#x6040</Index><Name>RwCtrl</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
              <Object><Index>#x6041</Index><Name>RwStat</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let rw_cat = Arc::new(XmlCatalog::parse_xml_str(min_esi).unwrap());
    let mut rw_sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(rw_cat),
        ..Default::default()
    });

    // Bind station 0x1001 via `APWR 0x0010`:
    let mut dg_bind = RawDatagram::new_positioned(
        EcatCmd::Apwr,
        1,
        0x0000,
        0x0010,
        0x1001u16.to_le_bytes().to_vec(),
    );
    dg_bind.wkc = 1;
    let mut b_bind = EcatFrameBuilder::new();
    b_bind.add_datagram(dg_bind);
    rw_sess.dissect_next(&b_bind.build().unwrap()).unwrap();

    // Pre-config `FPRW` on `0x1100` (`wkc = 0`) and `0x1400` (`wkc = 2`) MUST NOT decode PDO fields!
    let dg_pre_fprw =
        RawDatagram::new_positioned(EcatCmd::Fprw, 2, 0x1001, 0x1100, vec![0x0F, 0x00]);
    let mut b_pre_rw = EcatFrameBuilder::new();
    b_pre_rw.add_datagram(dg_pre_fprw);
    assert!(rw_sess
        .dissect_next(&b_pre_rw.build().unwrap())
        .unwrap()
        .datagrams[0]
        .pdo_fields
        .is_none());

    // Configure `0x1C12` and `0x1C13` via Complete Access (`CA = 1`) SDO Download — note `<Objects>` omits `0x1C12`/`0x1C13`,
    // exercising `decode_fallback_complete_access_subitems`!
    let build_ca_dl = |idx: u16, pdo_idx: u16| -> Vec<u8> {
        let mut mbx = vec![0u8; 6 + 2 + 8 + 4];
        mbx[0..2].copy_from_slice(&14u16.to_le_bytes());
        mbx[2..4].copy_from_slice(&0x1001u16.to_le_bytes());
        mbx[5] = 0x13;
        mbx[6..8].copy_from_slice(&0x2000u16.to_le_bytes()); // SDO Req
        mbx[8] = 0x31; // Normal Download + Size Indicated + Complete Access (0x10)
        mbx[9..11].copy_from_slice(&idx.to_le_bytes());
        mbx[11] = 0x00;
        mbx[12..16].copy_from_slice(&4u32.to_le_bytes());
        mbx[16] = 1; // count = 1 (padded to 16b)
        mbx[18..20].copy_from_slice(&pdo_idx.to_le_bytes());
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fpwr, 3, 0x1001, 0x1000, mbx);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };

    let df_ca_1c12 = rw_sess.dissect_next(&build_ca_dl(0x1C12, 0x1600)).unwrap();
    let sdo_xml_1c12 = df_ca_1c12.datagrams[0].sdo_xml.as_ref().unwrap();
    assert_eq!(sdo_xml_1c12.subitems.len(), 2);
    assert_eq!(sdo_xml_1c12.subitems[0]["value"], 1);
    assert_eq!(sdo_xml_1c12.subitems[1]["value"], 0x1600);
    assert!(df_ca_1c12
        .wireshark_fields
        .contains_key("ecat_mailbox.coe.sdo.xml.subitems"));

    let df_ca_1c13 = rw_sess.dissect_next(&build_ca_dl(0x1C13, 0x1A00)).unwrap();
    assert_eq!(
        df_ca_1c13.datagrams[0].sdo_xml.as_ref().unwrap().subitems[1]["value"],
        0x1A00
    );

    // Post-config outbound `APRW` (`wkc = 0`) at `0x1100` -> decodes `RwCtrl = 0x000F`!
    let dg_post_aprw_tx =
        RawDatagram::new_positioned(EcatCmd::Aprw, 4, 0x0000, 0x1100, vec![0x0F, 0x00]);
    let mut b_post_aprw_tx = EcatFrameBuilder::new();
    b_post_aprw_tx.add_datagram(dg_post_aprw_tx);
    let df_aprw_tx = rw_sess
        .dissect_next(&b_post_aprw_tx.build().unwrap())
        .unwrap();
    assert_eq!(df_aprw_tx.wireshark_fields["ecat.pdo.RwCtrl"], 0x000F);

    // Post-config returning `FPRW` (`wkc = 2`) at `0x1400` -> decodes `RwStat = 0x1237`!
    let mut dg_post_fprw_rx =
        RawDatagram::new_positioned(EcatCmd::Fprw, 5, 0x1001, 0x1400, vec![0x37, 0x12]);
    dg_post_fprw_rx.wkc = 2;
    let mut b_post_fprw_rx = EcatFrameBuilder::new();
    b_post_fprw_rx.add_datagram(dg_post_fprw_rx);
    let df_fprw_rx = rw_sess
        .dissect_next(&b_post_fprw_rx.build().unwrap())
        .unwrap();
    assert_eq!(df_fprw_rx.wireshark_fields["ecat.pdo.RwStat"], 0x1237);
}

#[test]
fn audit_layers_register_bounds_irq_bits_sdo_info_reassembly_and_aoe_f302() {
    // 1. Partial 1-byte FMMU0 Activate (`0x060C`) & 1-byte SM0 Status (`0x0805`) + IRQ SM0/SM7 bits (`0x8100`)
    let mut dg_fmmu_act = RawDatagram::new_positioned(EcatCmd::Fprd, 1, 0x1001, 0x060C, vec![0x01]);
    dg_fmmu_act.wkc = 1;
    dg_fmmu_act.irq = 0x8100; // bit 8 = SM0_IRQ, bit 15 = SM7_IRQ
    let mut dg_sm0_stat = RawDatagram::new_positioned(EcatCmd::Fprd, 2, 0x1001, 0x0805, vec![0x08]);
    dg_sm0_stat.wkc = 1;
    let mut b_regs = EcatFrameBuilder::new();
    b_regs.add_datagram(dg_fmmu_act);
    b_regs.add_datagram(dg_sm0_stat);
    let df_regs = dissect_frame(&b_regs.build().unwrap(), &DissectOptions::default()).unwrap();
    assert_eq!(df_regs.wireshark_fields["ecat[0].fmmu.activate0"], true);
    assert_eq!(df_regs.wireshark_fields["ecat[0].fmmu"], "01");
    assert_eq!(df_regs.wireshark_fields["ecat[1].reg.sm0.mbx_full"], true);
    assert_eq!(df_regs.wireshark_fields["ecat[1].syncman.1bufstate"], true);
    assert_eq!(df_regs.wireshark_fields["ecat[1].syncman"], "08");
    let irq_flags = &df_regs.datagrams[0].irq_events;
    assert!(irq_flags.contains(&"SM0_IRQ"));
    assert!(irq_flags.contains(&"SM7_IRQ"));
    assert!(!irq_flags.contains(&"AL_EVENT"));

    // 2. Non-initial IPv4 fragment (`frag_off != 0`) on UDP/34980 must be rejected cleanly
    let mut bad_frag = build_ipv4_udp_frame(UDP_PORT_ECAT, UDP_PORT_ECAT, &[0x10, 0x10, 0, 0]);
    // Set IPv4 fragment offset = 0x0010 (128 bytes) at Ethernet offset 14 + 6 = 20..22
    bad_frag[20] = 0x00;
    bad_frag[21] = 0x10;
    assert!(!ethercat_dissector::may_contain_ethercat(&bad_frag, false));
    assert!(dissect_frame(&bad_frag, &DissectOptions::default()).is_err());

    // 3. Multi-fragment CoE SDO Information (`0x06` Entry Description) continuation reassembly
    let build_sdo_info_mbx = |cnt: u8, sdo_info_payload: &[u8]| -> Vec<u8> {
        let coe_len = 2 + sdo_info_payload.len();
        let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&0x8000u16.to_le_bytes()); // CoE service 0x08 = SDO Information
        mbx.extend_from_slice(sdo_info_payload);
        if mbx.len() < 16 {
            mbx.resize(16, 0);
        }
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fprd, cnt, 0x1001, 0x1080, mbx);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };

    let mut sess_info = DissectSession::new(DissectOptions::default());
    // Fragment 1: opcode=0x86 (incomplete=1, opcode=6), reserved=0, fragments_left=1,
    //             index=0x6040, sub=0, valueInfo=0x00, dataType=0x0006, bitLen=16, access=0x003F, name="Control"
    let mut frag1 = vec![0x86, 0x00, 0x01, 0x00];
    frag1.extend_from_slice(&0x6040u16.to_le_bytes());
    frag1.push(0x00);
    frag1.push(0x00);
    frag1.extend_from_slice(&0x0006u16.to_le_bytes());
    frag1.extend_from_slice(&16u16.to_le_bytes());
    frag1.extend_from_slice(&0x003Fu16.to_le_bytes());
    frag1.extend_from_slice(b"Control");
    let df_if1 = sess_info
        .dissect_next(&build_sdo_info_mbx(1, &frag1))
        .unwrap();
    assert_eq!(
        df_if1.wireshark_fields["ecat_mailbox.coe.sdoinfoname"],
        "Control"
    );

    // Fragment 2: opcode=0x06 (incomplete=0), reserved=0, fragments_left=0, continuation="word_402"
    let mut frag2 = vec![0x06, 0x00, 0x00, 0x00];
    frag2.extend_from_slice(b"word_402");
    let df_if2 = sess_info
        .dissect_next(&build_sdo_info_mbx(2, &frag2))
        .unwrap();
    assert_eq!(
        df_if2.wireshark_fields["ecat_mailbox.coe.sdoinfoname"],
        "Controlword_402"
    );
    assert_eq!(
        df_if2.wireshark_fields["ecat[0].mailbox.coe.sdoinfoname"],
        "Controlword_402"
    );
    assert_eq!(
        df_if2.wireshark_fields["ecat_mailbox.coe.sdoinfo.index"],
        "0x6040"
    );
    assert_eq!(
        df_if2.wireshark_fields["ecat_mailbox.coe.sdoinfo.reassembled_fragments"],
        2
    );

    // 4. Segmented SDO (`s=0` / `cmd=0x40` empty-inline InitiateUploadRes + toggle retransmit)
    //    AND Extended >7B mailbox sub-block Block SDO Download (`s=0`, 16B sub-blocks, `unused=5`)
    let xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions><Devices><Device>
    <Type ProductCode="#x12345678" RevisionNo="#x00010000">AuditDrive</Type>
    <Mailbox><AoE/><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1" CompleteAccess="1"/></Mailbox>
    <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
    <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
    <Sm StartAddress="#x1100" ControlByte="#x24" Enable="1">Outputs</Sm>
    <RxPdo Sm="2" Mandatory="0" Fixed="0">
      <Index>#x1600</Index>
      <Entry><Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen><Name>Controlword</Name><DataType>UINT</DataType></Entry>
    </RxPdo>
    <Profile><Dictionary>
      <DataTypes>
        <DataType><Name>STRING27</Name><BitSize>216</BitSize></DataType>
        <DataType><Name>OP_ENUM</Name><BaseType>SINT</BaseType><BitSize>8</BitSize>
          <EnumInfo><Text>CSP</Text><Enum>8</Enum></EnumInfo>
        </DataType>
      </DataTypes>
      <Objects>
        <Object><Index>#x1008</Index><Name>Device Name</Name><Type>STRING(10)</Type><BitSize>80</BitSize></Object>
        <Object><Index>#x1009</Index><Name>Hardware Version</Name><Type>STRING27</Type><BitSize>216</BitSize></Object>
        <Object><Index>#x6060</Index><Name>Modes of operation</Name><Type>OP_ENUM</Type><BitSize>8</BitSize></Object>
      </Objects>
    </Dictionary></Profile>
  </Device></Devices></Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(xml).unwrap());
    let mut sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });

    // Segmented Upload `0x1008:00` with `s=0` (`cmd=0x40`, 4 reserved zero bytes, empty inline data)
    let ul_req = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x40, 0x1008, 0x00, &[0, 0, 0, 0]);
    let ul_res = build_coe_sdo_resp_mbx_frame(0x1001, 0x1080, 1, 0x40, 0x1008, 0x00, &[0, 0, 0, 0]);
    let build_ul_seg = |cnt: u8, hdr: u8, seg: &[u8]| -> Vec<u8> {
        let coe_len = 2 + 1 + seg.len();
        let mut mbx = Vec::with_capacity(6 + coe_len.max(10));
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&0x3000u16.to_le_bytes());
        mbx.push(hdr);
        mbx.extend_from_slice(seg);
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fprd, cnt, 0x1001, 0x1080, mbx);
        dg.wkc = 1;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };
    sess.dissect_next(&ul_req).unwrap();
    let df_ul_init = sess.dissect_next(&ul_res).unwrap();
    assert!(
        !df_ul_init
            .wireshark_fields
            .contains_key("ecat_mailbox.coe.sdo.xml.value"),
        "s=0 InitiateUploadRes with empty inline data must await segments"
    );
    // Segment 1 (toggle=0, more=0 -> hdr=0x00) + retransmitted Segment 1 (same toggle=0) + Segment 2 (toggle=1, last=1 -> hdr=0x11)
    sess.dissect_next(&build_ul_seg(2, 0x00, b"Servo-"))
        .unwrap();
    sess.dissect_next(&build_ul_seg(3, 0x00, b"Servo-"))
        .unwrap();
    let df_ul_done = sess.dissect_next(&build_ul_seg(4, 0x11, b"X100")).unwrap();
    assert_eq!(
        df_ul_done.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "Servo-X100"
    );
    assert_eq!(
        df_ul_done.wireshark_fields["ecat_mailbox.coe.sdo.xml.reassembled_segments"],
        2
    );

    // Extended 16-byte sub-block Block Download on `0x1009:00` (`s=0`, 27-byte string, sub-block 2 has 16 bytes with `unused=5`)
    let hw_ver = b"HW-EXTENDED-SUBBLOCK-27BYTE";
    assert_eq!(hw_ver.len(), 27);
    let hw_crc = ethercat_dissector::sdo_block_crc16(hw_ver);
    let build_dl_coe = |cnt: u8, wkc: u16, coe_body: &[u8]| -> Vec<u8> {
        let coe_len = 2 + coe_body.len();
        let mut mbx = Vec::with_capacity(6 + coe_len);
        mbx.extend_from_slice(&(coe_len as u16).to_le_bytes());
        mbx.extend_from_slice(&0x1001u16.to_le_bytes());
        mbx.push(0x00);
        mbx.push(((cnt & 0x07) << 4) | 0x03);
        mbx.extend_from_slice(&0x2000u16.to_le_bytes());
        mbx.extend_from_slice(coe_body);
        let mut dg = RawDatagram::new_positioned(EcatCmd::Fpwr, cnt, 0x1001, 0x1000, mbx);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    };
    // InitiateBlockDownload: ccs=6, cc=1 (0x04), s=0 -> cmd=0xC4, index=0x1009, sub=0, size=0
    sess.dissect_next(&build_dl_coe(5, 1, &[0xC4, 0x09, 0x10, 0x00, 0, 0, 0, 0]))
        .unwrap();
    let mut sb1 = vec![0x01];
    sb1.extend_from_slice(&hw_ver[..16]);
    sess.dissect_next(&build_dl_coe(6, 1, &sb1)).unwrap();
    let mut sb2 = vec![0x82];
    sb2.extend_from_slice(&hw_ver[16..27]);
    sb2.extend_from_slice(&[0xAA; 5]); // 5 unused trailing pad bytes in 16B sub-block
    sess.dissect_next(&build_dl_coe(7, 1, &sb2)).unwrap();
    // EndBlockDownload (`wkc=0` TX followed by `wkc=1` RX echo!): ccs=6, unused=5 (`5 << 2 = 0x14`), end=1 -> 0xD5
    let crc_b = hw_crc.to_le_bytes();
    let end_tx = build_dl_coe(1, 0, &[0xD5, crc_b[0], crc_b[1]]);
    let end_rx = build_dl_coe(1, 1, &[0xD5, crc_b[0], crc_b[1]]);
    let df_blk_tx = sess.dissect_next(&end_tx).unwrap();
    let df_blk_rx = sess.dissect_next(&end_rx).unwrap();
    for df_blk in [&df_blk_tx, &df_blk_rx] {
        assert_eq!(
            df_blk.wireshark_fields["ecat_mailbox.coe.sdoblk.crc_ok"],
            true
        );
        assert_eq!(
            df_blk.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
            "HW-EXTENDED-SUBBLOCK-27BYTE"
        );
    }

    // 5. CoE-over-AoE (`0xF302`):
    //    (a) ADS Write (`cmd=3`) configuring `0x1C12` followed by ADS Write Error Response (`0x0704`) -> rolls back PDO!
    let mut ads_wr_body = Vec::new();
    ads_wr_body.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    ads_wr_body.extend_from_slice(&0x1C12_0100u32.to_le_bytes()); // CA=1 on 0x1C12:0
    ads_wr_body.extend_from_slice(&4u32.to_le_bytes());
    ads_wr_body.extend_from_slice(&[0x01, 0x00, 0x00, 0x16]); // count=1, 0x1600
    let wr_req_pdu = build_ams_pdu(
        [5, 1, 2, 3, 1, 1],
        0x1001,
        [192, 168, 1, 1, 1, 1],
        32905,
        3,
        0x0004,
        0,
        9001,
        &ads_wr_body,
    );
    let df_aoe_wr = sess
        .dissect_next(&build_ipv4_udp_frame(49152, UDP_PORT_AMS, &wr_req_pdu))
        .unwrap();
    assert_eq!(
        df_aoe_wr.wireshark_fields["ams.coe.sdo.xml.object_name"],
        "Sync Manager 2 RxPDO Assignment"
    );

    // ADS Write Response (`cmd=3, state_flags=0x0005`) with ADS error `0x0704` -> rollback!
    let wr_res_pdu = build_ams_pdu(
        [192, 168, 1, 1, 1, 1],
        32905,
        [5, 1, 2, 3, 1, 1],
        0x1001,
        3,
        0x0005,
        0,
        9001,
        &0x0704u32.to_le_bytes(),
    );
    let df_aoe_wr_err = sess
        .dissect_next(&build_ipv4_udp_frame(UDP_PORT_AMS, 49152, &wr_res_pdu))
        .unwrap();
    assert_eq!(
        df_aoe_wr_err.wireshark_fields["ams.coe.sdo.xml.abort_code"],
        "0x00000704"
    );
    // Verify Slave `0x1001` RxPDO was rolled back (LWR does NOT decode Controlword!)
    let mut b_lwr = EcatFrameBuilder::new();
    b_lwr.add_datagram(RawDatagram::new_logical(
        EcatCmd::Lwr,
        9,
        0,
        vec![0x0F, 0x00],
    ));
    let df_after_rollback = sess.dissect_next(&b_lwr.build().unwrap()).unwrap();
    assert!(df_after_rollback.datagrams[0].pdo_fields.is_none());

    //    (b) ADS ReadWrite (`cmd=9`) on `0xF302` (`0x6060:00`) -> enriches request & decodes enum response!
    let mut ads_rw_req_body = Vec::new();
    ads_rw_req_body.extend_from_slice(&0x0000_F302u32.to_le_bytes());
    ads_rw_req_body.extend_from_slice(&0x6060_0000u32.to_le_bytes());
    ads_rw_req_body.extend_from_slice(&1u32.to_le_bytes()); // read_len = 1
    ads_rw_req_body.extend_from_slice(&0u32.to_le_bytes()); // write_len = 0
    let rw_req_pdu = build_ams_pdu(
        [5, 1, 2, 3, 1, 1],
        0x1001,
        [192, 168, 1, 1, 1, 1],
        32905,
        9,
        0x0004,
        0,
        9002,
        &ads_rw_req_body,
    );
    let df_rw_req = sess
        .dissect_next(&build_ipv4_udp_frame(49152, UDP_PORT_AMS, &rw_req_pdu))
        .unwrap();
    assert_eq!(
        df_rw_req.wireshark_fields["ams.coe.sdo.xml.object_name"],
        "Modes of operation"
    );
    let mut ads_rw_res_body = Vec::new();
    ads_rw_res_body.extend_from_slice(&0u32.to_le_bytes()); // ads_result = 0
    ads_rw_res_body.extend_from_slice(&1u32.to_le_bytes()); // len = 1
    ads_rw_res_body.push(8); // CSP = 8
    let rw_res_pdu = build_ams_pdu(
        [192, 168, 1, 1, 1, 1],
        32905,
        [5, 1, 2, 3, 1, 1],
        0x1001,
        9,
        0x0005,
        0,
        9002,
        &ads_rw_res_body,
    );
    let df_rw_res = sess
        .dissect_next(&build_ipv4_udp_frame(UDP_PORT_AMS, 49152, &rw_res_pdu))
        .unwrap();
    assert_eq!(df_rw_res.wireshark_fields["ams.coe.sdo.xml.value"], 8);
    assert_eq!(
        df_rw_res.wireshark_fields["ams.coe.sdo.xml.enum_text"],
        "CSP"
    );
}

#[test]
fn audit_xml_types_ca_mdp_isolation_multislave_pdo_and_safeop_defaults() {
    // Part A: `<Elements>256`, `UNICODE_STRING`, `CA=1` trailing `BOOL`s, and custom signed/enum PDO `<Entry><DataType>`
    let rich_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#xAAAA0001" RevisionNo="#x00010000">RichSlave</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" PdoConfig="1" CompleteAccess="1"/></Mailbox>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1">MBoxIn</Sm>
        <Sm StartAddress="#x1100" ControlByte="#x24" Enable="1">Outputs</Sm>
        <Sm StartAddress="#x1400" ControlByte="#x20" Enable="1">Inputs</Sm>
        <RxPdo Sm="2" Mandatory="0" Fixed="0">
          <Index>#x1600</Index>
          <Entry>
            <Index>#x6040</Index><SubIndex>0</SubIndex><BitLen>16</BitLen>
            <Name>Controlword</Name><DataType>UINT</DataType>
          </Entry>
        </RxPdo>
        <TxPdo Sm="3" Mandatory="0" Fixed="0">
          <Index>#x1A00</Index>
          <Entry>
            <Index>#x7099</Index><SubIndex>1</SubIndex><BitLen>16</BitLen>
            <Name>SignedTorque</Name><DataType>TORQUE_I16</DataType><Unit>#x00A0</Unit>
          </Entry>
          <Entry>
            <Index>#x7099</Index><SubIndex>2</SubIndex><BitLen>8</BitLen>
            <Name>DriveMode</Name><DataType>MODE_ENUM</DataType>
          </Entry>
        </TxPdo>
        <Profile>
          <Dictionary>
            <UnitTypes>
              <UnitType><Notation>Nm</Notation><Index>#x00A0</Index></UnitType>
            </UnitTypes>
            <DataTypes>
              <DataType><Name>TORQUE_I16</Name><BaseType>INT</BaseType><BitSize>16</BitSize></DataType>
              <DataType>
                <Name>MODE_ENUM</Name><BaseType>USINT</BaseType><BitSize>8</BitSize>
                <EnumInfo><Text>TorqueLoop</Text><Enum>4</Enum></EnumInfo>
              </DataType>
              <DataType>
                <Name>ARR256</Name><BitSize>2056</BitSize><BaseType>USINT</BaseType>
                <ArrayInfo><LBound>1</LBound><Elements>256</Elements></ArrayInfo>
              </DataType>
              <DataType>
                <Name>REC_BOOL_TAIL</Name><BitSize>24</BitSize>
                <SubItem><SubIdx>0</SubIdx><Name>SubIndex 000</Name><Type>USINT</Type><BitSize>8</BitSize><BitOffs>0</BitOffs></SubItem>
                <SubItem><SubIdx>1</SubIdx><Name>EnableA</Name><Type>BOOL</Type><BitSize>1</BitSize><BitOffs>16</BitOffs></SubItem>
                <SubItem><SubIdx>2</SubIdx><Name>EnableB</Name><Type>BOOL</Type><BitSize>1</BitSize><BitOffs>17</BitOffs></SubItem>
              </DataType>
            </DataTypes>
            <Objects>
              <Object><Index>#x2000</Index><Name>BigArray</Name><Type>ARR256</Type><BitSize>2056</BitSize></Object>
              <Object><Index>#x2001</Index><Name>AxisLabel</Name><Type>UNICODE_STRING(6)</Type><BitSize>96</BitSize></Object>
              <Object><Index>#x2002</Index><Name>BoolRecord</Name><Type>REC_BOOL_TAIL</Type><BitSize>24</BitSize></Object>
              <Object><Index>#x6040</Index><Name>Controlword</Name><Type>UINT</Type><BitSize>16</BitSize></Object>
            </Objects>
          </Dictionary>
        </Profile>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
    let cat = Arc::new(XmlCatalog::parse_xml_str(rich_xml).unwrap());
    // `<Elements>256` -> subindex 255 must exist without `u8` loop overflow!
    let big_arr = cat.devices[0].objects.get(&0x2000).unwrap();
    assert!(big_arr.subentries.contains_key(&255));

    // UNICODE_STRING UTF-16LE SDO decode ("轴A1")
    let utf16_bytes: Vec<u8> = "轴A1"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let mut uni_body = Vec::with_capacity(4 + utf16_bytes.len());
    uni_body.extend_from_slice(&(utf16_bytes.len() as u32).to_le_bytes());
    uni_body.extend_from_slice(&utf16_bytes);
    let uni_frame = build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 1, 0x21, 0x2001, 0x00, &uni_body);
    let df_uni = dissect_frame(
        &uni_frame,
        &DissectOptions {
            xml_catalog: Some(Arc::clone(&cat)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        df_uni.wireshark_fields["ecat_mailbox.coe.sdo.xml.value"],
        "轴A1"
    );
    assert_eq!(
        df_uni.wireshark_fields["ecat_mailbox.coe.sdo.xml.bit_length"],
        96
    );

    // CA=1 RECORD with trailing 1-bit BOOL subitems in final byte (`[2, 0, 0x01]` -> EnableA=true, EnableB=false)
    let ca_bool_frame = build_coe_sdo_mbx_frame(
        0x1001,
        0x1000,
        1,
        2,
        0x31,
        0x2002,
        0x00,
        &[3, 0, 0, 0, 2, 0x00, 0x01],
    );
    let df_ca_bool = dissect_frame(
        &ca_bool_frame,
        &DissectOptions {
            xml_catalog: Some(Arc::clone(&cat)),
            ..Default::default()
        },
    )
    .unwrap();
    let subs = &df_ca_bool.datagrams[0].sdo_xml.as_ref().unwrap().subitems;
    assert_eq!(subs.len(), 3);
    assert_eq!(subs[1]["value"], true);
    assert_eq!(subs[2]["value"], false);

    // Part B: Two-slave (`0x1001`, `0x1002`) power-on default `Sm="2"`/`Sm="3"` activation in `OP`,
    //         custom signed/enum PDO `<Entry><DataType>`, multi-slave `LRW` non-clobbering,
    //         `Case C.1` unmapped `LRD` no-fallthrough, and `SDO Abort` PDO rollback!
    let mut sess = DissectSession::new(DissectOptions {
        xml_catalog: Some(Arc::clone(&cat)),
        ..Default::default()
    });

    // Bind station addresses `0x1001` (slot 0) and `0x1002` (slot 1) + SM2/SM3 + FMMU0/FMMU1
    let mk_fmmu = |lstart: u32, llen: u16, pstart: u16, rw_flags: u8| -> Vec<u8> {
        let mut f = vec![0u8; 16];
        f[0..4].copy_from_slice(&lstart.to_le_bytes());
        f[4..6].copy_from_slice(&llen.to_le_bytes());
        f[7] = 7;
        f[8..10].copy_from_slice(&pstart.to_le_bytes());
        f[11] = rw_flags;
        f[12] = 0x01;
        f
    };
    let mk_sm = |pstart: u16, slen: u16, ctrl: u8| -> Vec<u8> {
        let mut s = vec![0u8; 8];
        s[0..2].copy_from_slice(&pstart.to_le_bytes());
        s[2..4].copy_from_slice(&slen.to_le_bytes());
        s[4] = ctrl;
        s[6] = 0x01;
        s
    };

    let mut setup_b = EcatFrameBuilder::new();
    let mut d0 = RawDatagram::new_positioned(
        EcatCmd::Apwr,
        1,
        0x0000,
        0x0010,
        0x1001u16.to_le_bytes().to_vec(),
    );
    d0.wkc = 1;
    let mut d1 = RawDatagram::new_positioned(
        EcatCmd::Apwr,
        2,
        0xFFFF,
        0x0010,
        0x1002u16.to_le_bytes().to_vec(),
    );
    d1.wkc = 1;
    let mut d2 =
        RawDatagram::new_positioned(EcatCmd::Fpwr, 3, 0x1001, 0x0810, mk_sm(0x1100, 2, 0x24));
    d2.wkc = 1;
    let mut d3 =
        RawDatagram::new_positioned(EcatCmd::Fpwr, 4, 0x1001, 0x0818, mk_sm(0x1400, 3, 0x20));
    d3.wkc = 1;
    let mut d4 = RawDatagram::new_positioned(
        EcatCmd::Fpwr,
        5,
        0x1001,
        0x0600,
        mk_fmmu(0x0001_0000, 2, 0x1100, 0x02),
    );
    d4.wkc = 1;
    let mut d5 = RawDatagram::new_positioned(
        EcatCmd::Fpwr,
        6,
        0x1001,
        0x0610,
        mk_fmmu(0x0002_0000, 3, 0x1400, 0x01),
    );
    d5.wkc = 1;
    let mut d6 =
        RawDatagram::new_positioned(EcatCmd::Fpwr, 7, 0x1002, 0x0810, mk_sm(0x1100, 2, 0x24));
    d6.wkc = 1;
    let mut d7 = RawDatagram::new_positioned(
        EcatCmd::Fpwr,
        8,
        0x1002,
        0x0600,
        mk_fmmu(0x0001_0002, 2, 0x1100, 0x02),
    );
    d7.wkc = 1;
    for dg in [d0, d1, d2, d3, d4, d5, d6, d7] {
        setup_b.add_datagram(dg);
    }
    sess.dissect_next(&setup_b.build().unwrap()).unwrap();

    // Still in PRE-OP (`0x0120`/`0x0130` not SAFE-OP/OP yet) -> configurable CoE slave MUST NOT decode PDO yet!
    let mut preop_lwr = EcatFrameBuilder::new();
    preop_lwr.add_datagram(RawDatagram::new_logical(
        EcatCmd::Lwr,
        9,
        0x0001_0000,
        vec![0x0F, 0x00, 0x7F, 0x00],
    ));
    let df_preop = sess.dissect_next(&preop_lwr.build().unwrap()).unwrap();
    assert!(df_preop.datagrams[0].pdo_fields.is_none());

    // Transition to OP (`BWR 0x0120 = 0x0008`) without any SDO reassignment -> activates XML `Sm="2"`/`Sm="3"` defaults!
    let mut op_b = EcatFrameBuilder::new();
    let mut dg_op = RawDatagram::new_positioned(
        EcatCmd::Bwr,
        10,
        0,
        0x0120,
        0x0008u16.to_le_bytes().to_vec(),
    );
    dg_op.wkc = 2;
    op_b.add_datagram(dg_op);
    sess.dissect_next(&op_b.build().unwrap()).unwrap();

    // Multi-slave `LWR` at `0x0001_0000`: Slave 1 (`0x1001`) = `0x000F`, Slave 2 (`0x1002`) = `0x007F`
    let mut op_lwr = EcatFrameBuilder::new();
    let mut dg_lwr =
        RawDatagram::new_logical(EcatCmd::Lwr, 11, 0x0001_0000, vec![0x0F, 0x00, 0x7F, 0x00]);
    dg_lwr.wkc = 2;
    op_lwr.add_datagram(dg_lwr);
    let df_multi = sess.dissect_next(&op_lwr.build().unwrap()).unwrap();
    assert_eq!(df_multi.wireshark_fields["ecat.pdo.0x6040:00"], 0x000F);
    assert_eq!(df_multi.wireshark_fields["ecat[0].pdo.0x6040:00"], 0x000F);
    assert_eq!(
        df_multi.wireshark_fields["ecat.pdo.0x1001.0x6040:00"],
        0x000F
    );
    assert_eq!(
        df_multi.wireshark_fields["ecat.pdo.0x1002.0x6040:00"],
        0x007F
    );

    // Custom signed/enum TxPDO on `LRD` at `0x0002_0000` (`SignedTorque = -250` = `0xFF06`, `DriveMode = 4` = `TorqueLoop`)
    let mut op_lrd = EcatFrameBuilder::new();
    let mut dg_lrd =
        RawDatagram::new_logical(EcatCmd::Lrd, 12, 0x0002_0000, vec![0x06, 0xFF, 0x04]);
    dg_lrd.wkc = 1;
    op_lrd.add_datagram(dg_lrd);
    let df_txpdo = sess.dissect_next(&op_lrd.build().unwrap()).unwrap();
    assert_eq!(df_txpdo.wireshark_fields["ecat.pdo.SignedTorque"], -250);
    assert_eq!(
        df_txpdo.wireshark_fields["ecat.pdo.SignedTorque.unit"],
        "Nm"
    );
    assert_eq!(
        df_txpdo.wireshark_fields["ecat.pdo.DriveMode.enum"],
        "TorqueLoop"
    );

    // Unmapped logical address `0x0009_0000` in FMMU-configured session MUST NOT fall through to Case C.2!
    let mut unmapped_lrd = EcatFrameBuilder::new();
    let mut dg_unmapped =
        RawDatagram::new_logical(EcatCmd::Lrd, 13, 0x0009_0000, vec![0x06, 0xFF, 0x04]);
    dg_unmapped.wkc = 1;
    unmapped_lrd.add_datagram(dg_unmapped);
    let df_unmapped = sess.dissect_next(&unmapped_lrd.build().unwrap()).unwrap();
    assert!(df_unmapped.datagrams[0].pdo_fields.is_none());

    // Rejected SDO Download (`0x1C12:00 = 0` in OP -> Slave `0x1001` replies `SDO Abort 0x08000022`) -> rolls back cleanly!
    let clear_req =
        build_coe_sdo_mbx_frame(0x1001, 0x1000, 1, 3, 0x2F, 0x1C12, 0x00, &[0, 0, 0, 0]);
    let abort_res = build_coe_sdo_resp_mbx_frame(
        0x1001,
        0x1080,
        3,
        0x80,
        0x1C12,
        0x00,
        &0x0800_0022u32.to_le_bytes(),
    );
    sess.dissect_next(&clear_req).unwrap();
    sess.dissect_next(&abort_res).unwrap();
    let df_still_active = sess.dissect_next(&op_lwr.build().unwrap()).unwrap();
    assert_eq!(
        df_still_active.wireshark_fields["ecat.pdo.0x1001.0x6040:00"],
        0x000F
    );

    // Part C: MDP `<Modules>` isolation & clean `0xF030` re-instantiation without stale default slot bleed
    let mdp_xml = r##"<?xml version="1.0" encoding="UTF-8"?>
<EtherCATInfo>
  <Vendor><Id>2</Id></Vendor>
  <Descriptions>
    <Devices>
      <Device>
        <Type ProductCode="#xBBBB0001" RevisionNo="#x00010000">MdpCoupler</Type>
        <Mailbox><CoE SdoInfo="1" PdoAssign="1" CompleteAccess="1"/></Mailbox>
        <Slots MaxSlotCount="1" SlotPdoIncrement="16" SlotIndexIncrement="16">
          <Slot><SlotIndex>1</SlotIndex><Default>#x00001111</Default></Slot>
        </Slots>
      </Device>
      <Device>
        <Type ProductCode="#xBBBB0002" RevisionNo="#x00010000">PlainTerminal</Type>
      </Device>
    </Devices>
    <Modules>
      <Module>
        <Type ModuleIdent="#x00001111">ModA</Type>
        <TxPdo Fixed="1"><Index>#x1A00</Index><Entry><Index>#x6000</Index><SubIndex>1</SubIndex><BitLen>8</BitLen><Name>ModAIn</Name><DataType>USINT</DataType></Entry></TxPdo>
      </Module>
      <Module>
        <Type ModuleIdent="#x00002222">ModB</Type>
        <RxPdo Fixed="1"><Index>#x1600</Index><Entry><Index>#x7000</Index><SubIndex>1</SubIndex><BitLen>8</BitLen><Name>ModBOut</Name><DataType>USINT</DataType></Entry></RxPdo>
      </Module>
    </Modules>
  </Descriptions>
</EtherCATInfo>"##;
    let mdp_cat = Arc::new(XmlCatalog::parse_xml_str(mdp_xml).unwrap());
    assert_eq!(mdp_cat.devices[0].modules.len(), 2);
    assert!(
        mdp_cat.devices[1].modules.is_empty(),
        "Non-slot device must not inherit top-level <Modules>"
    );
    assert!(mdp_cat.devices[0].tx_pdos.contains_key(&0x1A00));
    let clean_coupler = mdp_cat.devices[0].clean_base_for_mdp();
    assert!(
        clean_coupler.tx_pdos.is_empty(),
        "clean_base_for_mdp() must strip default-instantiated ModA TxPdo before applying 0xF030"
    );
}

/// Regression suite pinned to Wireshark 4.6.8 (`tshark -T json`) output on real TwinCAT captures and
/// synthetic frames: register coverage / WKC gating, `ecat.data` extent, mailbox recognition, DC diffs,
/// and several mailbox field semantics.
#[test]
fn wireshark_46_tshark_verified_payload_register_and_mailbox_semantics() {
    fn one(cmd: EcatCmd, ado: u16, data: Vec<u8>, wkc: u16) -> Vec<u8> {
        let mut dg = RawDatagram::new_positioned(cmd, 1, 0x03E9, ado, data);
        dg.wkc = wkc;
        let mut b = EcatFrameBuilder::new();
        b.add_datagram(dg);
        b.build().unwrap()
    }
    fn mbx(mtype: u8, body: &[u8], length: Option<u16>, pad_to: usize) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&length.unwrap_or(body.len() as u16).to_le_bytes());
        m.extend_from_slice(&0u16.to_le_bytes());
        m.push(0x00);
        m.push((1 << 4) | (mtype & 0x0F));
        m.extend_from_slice(body);
        if m.len() < pad_to {
            m.resize(pad_to, 0);
        }
        m
    }
    let ws = |raw: &[u8]| {
        dissect_frame(raw, &DissectOptions::default())
            .unwrap()
            .wireshark_fields
    };

    // 1. BRD 0x0130 with WKC=0 (LAM.pcapng #5): registers hidden, no `ecat.data`; extension view stays.
    let f = ws(&one(EcatCmd::Brd, 0x0130, vec![0, 0], 0));
    assert!(!f.contains_key("ecat.reg.alstatus"));
    assert!(!f.contains_key("ecat.data"));
    assert!(!f.contains_key("ecat.sub1.data"));
    assert!(f.contains_key("ecat[0].reg.al_state"));
    // ...and with WKC>0 the official register fields appear.
    let f = ws(&one(EcatCmd::Brd, 0x0130, vec![0x08, 0], 2));
    assert_eq!(f["ecat.reg.alstatus"], "0x0008");
    assert!(!f.contains_key("ecat.data"));

    // 2. BWR 0x0500 with 1 byte (LAM.pcapng #35): the 2-byte register is not covered -> raw data only.
    let f = ws(&one(EcatCmd::Bwr, 0x0500, vec![0x00], 0));
    assert!(!f.contains_key("ecat.reg.eeprom.assign"));
    assert!(!f.contains_key("ecat.reg.eeprom.assign.ctrl"));
    assert_eq!(f["ecat.data"], "00");
    assert_eq!(f["ecat.sub1.data"], "00");

    // 3. FPRD 0x080D with 1 byte (LAM.pcapng #448): partial SyncManager -> no `ecat.syncman*`.
    let f = ws(&one(EcatCmd::Fprd, 0x080D, vec![0x00], 0));
    assert!(!f.contains_key("ecat.syncman"));
    assert!(!f.contains_key("ecat.syncman.irq.read"));
    assert_eq!(f["ecat.data"], "00");

    // 4. FPRD mailbox read (WKC=1) in a 128-byte SM window (LAM.pcapng #1688): `ecat.data` is the
    //    remainder after `Length + 6`; no `ecat_mailbox.data` for a dissected CoE mailbox.
    let mut coe = vec![0x00, 0x30, 0x60, 0x01, 0x1A, 0x00, 0, 0, 0, 0];
    let m = mbx(3, &coe, None, 128);
    let rest = ethercat_wire::types::format_hex(&m[16..]);
    let f = ws(&one(EcatCmd::Fprd, 0x1080, m.clone(), 1));
    assert_eq!(f["ecat_mailbox.coe.sdoidx"], "0x1a01");
    assert_eq!(f["ecat.data"], rest.as_str());
    assert_eq!(f["ecat.sub1.data"], rest.as_str());
    assert!(!f.contains_key("ecat_mailbox.data"));

    // 5. Same mailbox with WKC=0 or WKC=2: Wireshark does not dissect the mailbox at all.
    for wkc in [0u16, 2] {
        let f = ws(&one(EcatCmd::Fprd, 0x1080, m.clone(), wkc));
        assert!(!f.contains_key("ecat_mailbox.length"), "wkc={wkc}");
        assert_eq!(
            f["ecat.data"],
            ethercat_wire::types::format_hex(&m).as_str()
        );
    }
    // ...while APRW/FPWR are dissected regardless of WKC.
    coe[1] = 0x20;
    coe[2] = 0x40;
    let f = ws(&one(EcatCmd::Aprw, 0x1000, mbx(3, &coe, None, 16), 0));
    assert_eq!(f["ecat_mailbox.coe.sdoreq"], 2);

    // 6. Zero-length CoE mailbox (A01.pcapng #852): dissected, `coe` + `coe.invalid`.
    let f = ws(&one(EcatCmd::Fprd, 0x1080, mbx(3, &[], Some(0), 16), 1));
    assert_eq!(f["ecat_mailbox.length"], 0);
    assert!(f.contains_key("ecat_mailbox.coe"));
    assert!(f.contains_key("ecat_mailbox.coe.invalid"));

    // 7. DC receive times: Wireshark computes B-A even when port A is 0; only (A|F)PRD at 0x0900.
    let mut dc = Vec::new();
    for t in [0u32, 1900, 0, 0] {
        dc.extend_from_slice(&t.to_le_bytes());
    }
    let f = ws(&one(EcatCmd::Fprd, 0x0900, dc.clone(), 1));
    assert_eq!(f["ecat.dc.dif.ba"], 1900);
    assert!(!f.contains_key("ecat.dc.dif.da"));
    assert_eq!(
        f["ecat.sub1.data"],
        ethercat_wire::types::format_hex(&dc).as_str()
    );
    assert!(!f.contains_key("ecat.data"));
    let f = ws(&one(EcatCmd::Brd, 0x0900, dc, 1));
    assert!(!f.contains_key("ecat.dc.dif.ba"));
    assert!(f.contains_key("ecat.reg.dc.recv1"));

    // 8. CoE details: raw SDO-Info opcode byte, 4-byte `sdodata` for n=1, upload `complete` flag.
    let f = ws(&one(
        EcatCmd::Fprd,
        0x1080,
        mbx(
            3,
            &[0x00, 0x80, 0x82, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x10],
            None,
            16,
        ),
        1,
    ));
    assert_eq!(f["ecat_mailbox.coe.sdoinfoopcode"], 0x82);
    let f = ws(&one(
        EcatCmd::Fpwr,
        0x1000,
        mbx(
            3,
            &[0x00, 0x20, 0x27, 0x40, 0x60, 0x00, 1, 2, 3, 4],
            None,
            16,
        ),
        1,
    ));
    assert_eq!(f["ecat_mailbox.coe.sdodata"], "0x04030201");
    let f = ws(&one(
        EcatCmd::Fpwr,
        0x1000,
        mbx(
            3,
            &[0x00, 0x20, 0x50, 0x18, 0x10, 0x00, 0, 0, 0, 0],
            None,
            16,
        ),
        1,
    ));
    assert_eq!(f["ecat_mailbox.coe.sdoccsid.complete"], true);

    // 9. SoE error response: `soe_error` is read at the IDN offset (Wireshark), ETG code kept separately.
    let f = ws(&one(
        EcatCmd::Fprd,
        0x1080,
        mbx(5, &[0x14, 0x40, 0x01, 0x70, 0x01, 0x10], None, 16),
        1,
    ));
    assert_eq!(f["ecat_mailbox.soe_error"], "0x7001");
    assert_eq!(f["ecat_mailbox.soe.error_code"], "0x1001");
    assert!(!f.contains_key("ecat_mailbox.soe_data"));

    // 10. EoE: fragment offset in bytes (x32), header fields only for fragments, fixed init layout.
    let f = ws(&one(
        EcatCmd::Fpwr,
        0x1000,
        mbx(2, &[0x00, 0x00, 0xC0, 0x20, 1, 2, 3, 4], None, 16),
        1,
    ));
    assert_eq!(f["ecat_mailbox.eoe.offset"], 96);
    assert!(!f.contains_key("ecat_mailbox.eoe.timestampreq"));
    let mut init = vec![0x02, 0x01, 0x00, 0x00];
    init.extend_from_slice(&0x02u32.to_le_bytes()); // only "IP address" valid
    init.extend_from_slice(&[0xAA; 6]); // MAC slot (not valid, still occupies 6 bytes)
    init.extend_from_slice(&[50, 1, 168, 192]);
    init.resize(4 + 58, 0);
    let f = ws(&one(EcatCmd::Fpwr, 0x1000, mbx(2, &init, None, 16), 1));
    assert_eq!(f["ecat_mailbox.eoe.ip"], "192.168.1.50");
    assert_eq!(f["ecat_mailbox.eoe.init.ipaddr"], "192.168.1.50");
    assert!(!f.contains_key("ecat_mailbox.eoe.mac"));
    assert!(!f.contains_key("ecat_mailbox.eoe.fragno"));
}
