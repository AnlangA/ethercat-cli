pub mod error;
pub mod pdo_codec;
pub mod protocol;
pub mod transport;
pub mod types;

#[cfg(test)]
mod tests {
    use crate::pdo_codec::{decode_pdo_payload, encode_pdo_assignments, PdoLayout};
    use crate::protocol::constants::EcatCmd;
    use crate::protocol::frame::{EcatFrameBuilder, RawDatagram};
    use crate::types::{extract_bits_le, insert_bits_le, parse_u64, DataTypeSpec};

    #[test]
    fn wire_frame_and_pdo_codec_roundtrip() {
        assert_eq!(parse_u64("#x08A4").unwrap(), 0x08A4);

        let layout = PdoLayout::parse_spec("ctrl:u16@0,target:i32@16").unwrap();
        let mut pdo_buf = vec![0u8; layout.total_bytes()];
        encode_pdo_assignments(
            &mut pdo_buf,
            &layout,
            &["ctrl=0x000F".into(), "target=-500".into()],
        )
        .unwrap();
        let decoded = decode_pdo_payload(&pdo_buf, &layout).unwrap();
        assert_eq!(decoded[0]["value"], 0x000F);
        assert_eq!(decoded[1]["value"], -500);

        let mut dg = RawDatagram::new_logical(EcatCmd::Lrw, 0x07, 0x0001_0000, pdo_buf);
        dg.wkc = 3;
        let mut builder = EcatFrameBuilder::new();
        builder.add_datagram(dg);
        let raw = builder.build().unwrap();
        assert_eq!(&raw[12..14], &[0x88, 0xA4]);
        let parsed = crate::protocol::frame::parse_dlpdu_datagrams(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].wkc, 3);

        let mut bits = [0x00u8, 0x00];
        insert_bits_le(&mut bits, 4, 8, &[0xAB]).unwrap();
        assert_eq!(extract_bits_le(&bits, 4, 8).unwrap(), vec![0xAB]);
        assert_eq!(
            DataTypeSpec::from_coe_datatype(0x0020, 32),
            Some(DataTypeSpec::U32)
        );
    }
}
