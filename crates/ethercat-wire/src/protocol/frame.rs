use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::protocol::constants::{
    EcatCmd, BROADCAST_MAC, DEFAULT_MASTER_MAC, ECAT_DATAGRAM_HEADER_LEN, ECAT_FRAME_HEADER_LEN,
    ECAT_FRAME_TYPE_DLPDU, ECAT_WKC_LEN, ETH_HEADER_LEN, ETH_P_ECAT, MIN_ETHERNET_FRAME_LEN,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawDatagram {
    pub cmd: u8,
    pub idx: u8,
    pub adp: u16,
    pub ado: u16,
    pub logical_addr: u32,
    pub circulating: bool,
    pub more: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub more_override: Option<bool>,
    pub irq: u16,
    pub data: Vec<u8>,
    pub wkc: u16,
}

impl RawDatagram {
    pub fn new_positioned(cmd: EcatCmd, idx: u8, adp: u16, ado: u16, data: Vec<u8>) -> Self {
        let logical_addr = (adp as u32) | ((ado as u32) << 16);
        Self {
            cmd: cmd.code(),
            idx,
            adp,
            ado,
            logical_addr,
            circulating: false,
            more: false,
            more_override: None,
            irq: 0,
            data,
            wkc: 0,
        }
    }

    pub fn new_logical(cmd: EcatCmd, idx: u8, logical_addr: u32, data: Vec<u8>) -> Self {
        let adp = (logical_addr & 0xFFFF) as u16;
        let ado = ((logical_addr >> 16) & 0xFFFF) as u16;
        Self {
            cmd: cmd.code(),
            idx,
            adp,
            ado,
            logical_addr,
            circulating: false,
            more: false,
            more_override: None,
            irq: 0,
            data,
            wkc: 0,
        }
    }

    #[allow(dead_code)]
    pub fn wire_len(&self) -> usize {
        ECAT_DATAGRAM_HEADER_LEN + self.data.len() + ECAT_WKC_LEN
    }

    pub fn write_to(&self, out: &mut Vec<u8>, force_more: bool) -> Result<()> {
        if self.data.len() > 0x07FF {
            return Err(CliError::Format(format!(
                "datagram data length {} exceeds 11-bit maximum (2047)",
                self.data.len()
            )));
        }
        out.push(self.cmd);
        out.push(self.idx);
        if matches!(
            EcatCmd::from_code(self.cmd),
            Some(EcatCmd::Lrd | EcatCmd::Lwr | EcatCmd::Lrw)
        ) {
            out.extend_from_slice(&self.logical_addr.to_le_bytes());
        } else {
            out.extend_from_slice(&self.adp.to_le_bytes());
            out.extend_from_slice(&self.ado.to_le_bytes());
        }
        let mut len_flags = (self.data.len() as u16) & 0x07FF;
        if self.circulating {
            len_flags |= 1 << 14;
        }
        if self.more_override.unwrap_or(force_more || self.more) {
            len_flags |= 1 << 15;
        }
        out.extend_from_slice(&len_flags.to_le_bytes());
        out.extend_from_slice(&self.irq.to_le_bytes());
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.wkc.to_le_bytes());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct EcatFrameBuilder {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub vlan_id: Option<u16>,
    pub frame_type: u8,
    pub datagrams: Vec<RawDatagram>,
    pub pad_to_min_ethernet: bool,
}

impl Default for EcatFrameBuilder {
    fn default() -> Self {
        Self {
            dst_mac: BROADCAST_MAC,
            src_mac: DEFAULT_MASTER_MAC,
            vlan_id: None,
            frame_type: ECAT_FRAME_TYPE_DLPDU,
            datagrams: Vec::new(),
            pad_to_min_ethernet: false,
        }
    }
}

impl EcatFrameBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_datagram(&mut self, dg: RawDatagram) -> &mut Self {
        self.datagrams.push(dg);
        self
    }

    pub fn build(&self) -> Result<Vec<u8>> {
        if self.datagrams.is_empty() {
            return Err(CliError::Format(
                "cannot build EtherCAT DLPDU frame with zero datagrams".into(),
            ));
        }
        let approx_len: usize = self.datagrams.iter().map(RawDatagram::wire_len).sum();
        let mut ecat_payload = Vec::with_capacity(approx_len);
        let last_idx = self.datagrams.len() - 1;
        for (i, dg) in self.datagrams.iter().enumerate() {
            dg.write_to(&mut ecat_payload, i < last_idx)?;
        }
        if ecat_payload.len() > 0x07FF {
            return Err(CliError::Format(format!(
                "EtherCAT frame payload {} bytes exceeds 11-bit maximum (2047)",
                ecat_payload.len()
            )));
        }
        let mut frame =
            Vec::with_capacity(ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN + ecat_payload.len() + 8);
        frame.extend_from_slice(&self.dst_mac);
        frame.extend_from_slice(&self.src_mac);
        if let Some(vid) = self.vlan_id {
            frame.extend_from_slice(&0x8100u16.to_be_bytes());
            frame.extend_from_slice(&(vid & 0x0FFF).to_be_bytes());
        }
        frame.extend_from_slice(&ETH_P_ECAT.to_be_bytes());
        let ecat_hdr: u16 =
            ((ecat_payload.len() as u16) & 0x07FF) | (((self.frame_type as u16) & 0x0F) << 12);
        frame.extend_from_slice(&ecat_hdr.to_le_bytes());
        frame.extend_from_slice(&ecat_payload);
        if self.pad_to_min_ethernet && frame.len() < MIN_ETHERNET_FRAME_LEN {
            frame.resize(MIN_ETHERNET_FRAME_LEN, 0);
        }
        Ok(frame)
    }
}

/// Skip Ethernet EtherType plus up to 4 stacked 802.1Q (`0x8100`) / 802.1ad (`0x88A8`) VLAN tags.
/// `offset` must point to the 2-byte EtherType field (byte 12 of an Ethernet II header).
/// Returns `(inner_ethertype, outer_or_last_vlan_id, payload_offset)`.
pub fn skip_ethernet_vlan_tags(eth: &[u8], mut offset: usize) -> Result<(u16, Option<u16>, usize)> {
    if eth.len() < offset + 2 {
        return Err(CliError::Format(
            "frame shorter than Ethernet header".into(),
        ));
    }
    let mut etype = u16::from_be_bytes([eth[offset], eth[offset + 1]]);
    offset += 2;
    let mut vlan_id = None;
    let mut tags = 0usize;
    while matches!(etype, 0x8100 | 0x88A8) && tags < 4 {
        if eth.len() < offset + 4 {
            return Err(CliError::Format("truncated 802.1Q/802.1ad VLAN tag".into()));
        }
        let tci = u16::from_be_bytes([eth[offset], eth[offset + 1]]);
        vlan_id = Some(tci & 0x0FFF);
        etype = u16::from_be_bytes([eth[offset + 2], eth[offset + 3]]);
        offset += 4;
        tags += 1;
    }
    Ok((etype, vlan_id, offset))
}

#[derive(Debug, Clone, Copy)]
pub struct RawDatagramRef<'a> {
    pub cmd: u8,
    pub idx: u8,
    pub adp: u16,
    pub ado: u16,
    pub logical_addr: u32,
    pub circulating: bool,
    pub more: bool,
    pub irq: u16,
    pub data: &'a [u8],
    pub wkc: u16,
}

/// Zero-copy Ethernet + `0x88A4` DLPDU datagram parser borrowing slices from `frame`.
pub fn parse_dlpdu_datagram_refs(frame: &[u8]) -> Result<Vec<RawDatagramRef<'_>>> {
    if frame.len() < ETH_HEADER_LEN + ECAT_FRAME_HEADER_LEN {
        return Err(CliError::Format(
            "frame shorter than Ethernet+EtherCAT header".into(),
        ));
    }
    let (etype, _vlan, mut offset) = skip_ethernet_vlan_tags(frame, 12)?;
    if etype != ETH_P_ECAT {
        return Err(CliError::Format(format!(
            "unexpected EtherType 0x{etype:04X}, expected 0x88A4"
        )));
    }
    if frame.len() < offset + ECAT_FRAME_HEADER_LEN {
        return Err(CliError::Format(
            "frame truncated before 2-byte EtherCAT header".into(),
        ));
    }
    let ecat_hdr = u16::from_le_bytes([frame[offset], frame[offset + 1]]);
    offset += 2;
    let body_len = (ecat_hdr & 0x07FF) as usize;
    let ftype = ((ecat_hdr >> 12) & 0x0F) as u8;
    if ftype != ECAT_FRAME_TYPE_DLPDU {
        return Err(CliError::Format(format!(
            "EtherCAT frame type 0x{ftype:X} is not DLPDU (0x1)"
        )));
    }
    if offset + body_len > frame.len() {
        return Err(CliError::Format(format!(
            "EtherCAT header declares {body_len} bytes, but frame only has {} remaining",
            frame.len() - offset
        )));
    }
    let end = offset + body_len;
    let mut pos = offset;
    let mut out = Vec::new();
    while pos < end {
        if pos + ECAT_DATAGRAM_HEADER_LEN + ECAT_WKC_LEN > end {
            return Err(CliError::Format(
                "truncated EtherCAT datagram header".into(),
            ));
        }
        let cmd = frame[pos];
        let idx = frame[pos + 1];
        let adp = u16::from_le_bytes([frame[pos + 2], frame[pos + 3]]);
        let ado = u16::from_le_bytes([frame[pos + 4], frame[pos + 5]]);
        let logical_addr = u32::from_le_bytes([
            frame[pos + 2],
            frame[pos + 3],
            frame[pos + 4],
            frame[pos + 5],
        ]);
        let len_flags = u16::from_le_bytes([frame[pos + 6], frame[pos + 7]]);
        let dlen = (len_flags & 0x07FF) as usize;
        let circulating = (len_flags & (1 << 14)) != 0;
        let more = (len_flags & (1 << 15)) != 0;
        let irq = u16::from_le_bytes([frame[pos + 8], frame[pos + 9]]);
        let data_start = pos + ECAT_DATAGRAM_HEADER_LEN;
        let data_end = data_start + dlen;
        if data_end + ECAT_WKC_LEN > end {
            return Err(CliError::Format(
                "datagram payload exceeds EtherCAT frame length".into(),
            ));
        }
        let data = &frame[data_start..data_end];
        let wkc = u16::from_le_bytes([frame[data_end], frame[data_end + 1]]);
        out.push(RawDatagramRef {
            cmd,
            idx,
            adp,
            ado,
            logical_addr,
            circulating,
            more,
            irq,
            data,
            wkc,
        });
        pos = data_end + ECAT_WKC_LEN;
        if !more {
            break;
        }
    }
    Ok(out)
}

/// Parse an Ethernet + 0x88A4 DLPDU frame into its raw datagrams (lightweight fast path for master RX).
pub fn parse_dlpdu_datagrams(frame: &[u8]) -> Result<Vec<RawDatagram>> {
    let refs = parse_dlpdu_datagram_refs(frame)?;
    Ok(refs
        .into_iter()
        .map(|r| RawDatagram {
            cmd: r.cmd,
            idx: r.idx,
            adp: r.adp,
            ado: r.ado,
            logical_addr: r.logical_addr,
            circulating: r.circulating,
            more: r.more,
            more_override: None,
            irq: r.irq,
            data: r.data.to_vec(),
            wkc: r.wkc,
        })
        .collect())
}
