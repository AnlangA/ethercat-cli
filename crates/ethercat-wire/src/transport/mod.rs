pub mod npcap;
pub mod udp;

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::protocol::constants::EcatCmd;
use crate::protocol::frame::{parse_dlpdu_datagram_refs, EcatFrameBuilder, RawDatagram};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdapterInfo {
    pub name: String,
    pub description: String,
    pub flags: u32,
    pub is_loopback: bool,
    pub is_up: bool,
    pub is_running: bool,
    pub virtual_sim: bool,
}

pub trait EthercatTransport {
    fn name(&self) -> &str;
    fn next_index(&mut self) -> u8;
    fn send_raw_frame(&mut self, frame: &[u8]) -> Result<()>;
    fn recv_raw_frame(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>>;
    fn transact_frame(
        &mut self,
        tx_frame: &[u8],
        expected_idx: Option<u8>,
        timeout: Duration,
    ) -> Result<Vec<u8>>;

    fn send_datagram(
        &mut self,
        cmd: EcatCmd,
        adp: u16,
        ado: u16,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let expected_len = data.len();
        let idx = self.next_index();
        let dg = RawDatagram::new_positioned(cmd, idx, adp, ado, data);
        let mut builder = EcatFrameBuilder::new();
        builder.add_datagram(dg);
        let tx = builder.build()?;
        let rx = self.transact_frame(&tx, Some(idx), timeout)?;
        let rxdgs = parse_dlpdu_datagram_refs(&rx)?;
        let Some(first) = rxdgs.first() else {
            return Err(CliError::Protocol("received empty DLPDU response".into()));
        };
        if first.cmd != cmd.code() {
            return Err(CliError::Protocol(format!(
                "DLPDU response command mismatch: got 0x{:02X}, expected {} (0x{:02X})",
                first.cmd,
                cmd.mnemonic(),
                cmd.code()
            )));
        }
        if first.data.len() < expected_len {
            return Err(CliError::Protocol(format!(
                "DLPDU {} response payload shorter than request ({} < {expected_len})",
                cmd.mnemonic(),
                first.data.len()
            )));
        }
        Ok((first.wkc, first.data.to_vec()))
    }

    fn send_logical_datagram(
        &mut self,
        cmd: EcatCmd,
        logical_addr: u32,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<(u16, Vec<u8>)> {
        let expected_len = data.len();
        let idx = self.next_index();
        let dg = RawDatagram::new_logical(cmd, idx, logical_addr, data);
        let mut builder = EcatFrameBuilder::new();
        builder.add_datagram(dg);
        let tx = builder.build()?;
        let rx = self.transact_frame(&tx, Some(idx), timeout)?;
        let rxdgs = parse_dlpdu_datagram_refs(&rx)?;
        let Some(first) = rxdgs.first() else {
            return Err(CliError::Protocol("received empty DLPDU response".into()));
        };
        if first.cmd != cmd.code() {
            return Err(CliError::Protocol(format!(
                "DLPDU response command mismatch: got 0x{:02X}, expected {} (0x{:02X})",
                first.cmd,
                cmd.mnemonic(),
                cmd.code()
            )));
        }
        if first.data.len() < expected_len {
            return Err(CliError::Protocol(format!(
                "DLPDU {} response payload shorter than request ({} < {expected_len})",
                cmd.mnemonic(),
                first.data.len()
            )));
        }
        Ok((first.wkc, first.data.to_vec()))
    }
}

/// Open a physical L2 Npcap/libpcap or `udp://` EtherCAT-over-UDP transport.
pub fn open_wire_transport(iface: &str, capture_local: bool) -> Result<Box<dyn EthercatTransport>> {
    let trimmed = iface.trim();
    if trimmed
        .get(..6)
        .is_some_and(|p| p.eq_ignore_ascii_case("udp://"))
        || trimmed
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("udp:"))
    {
        Ok(Box::new(udp::UdpEcatTransport::open(trimmed)?))
    } else {
        Ok(Box::new(npcap::NpcapTransport::open(
            trimmed,
            capture_local,
        )?))
    }
}

pub fn list_all_adapters(include_sim: bool) -> Result<Vec<AdapterInfo>> {
    let mut out = match npcap::list_npcap_adapters() {
        Ok(list) => list,
        Err(e) => {
            if !include_sim {
                return Err(e);
            }
            Vec::new()
        }
    };
    if include_sim {
        out.push(AdapterInfo {
            name: "sim".to_string(),
            description: "Built-in EtherCAT Virtual Ring Simulator (CiA-402 Servo + DIO slaves)"
                .to_string(),
            flags: 0x06,
            is_loopback: true,
            is_up: true,
            is_running: true,
            virtual_sim: true,
        });
    }
    Ok(out)
}
