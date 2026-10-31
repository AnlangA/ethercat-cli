pub mod esi;
pub mod sii;

#[cfg(test)]
mod tests {
    use crate::esi::{
        compile_esi_device_to_sii, load_esi_catalog_from_bytes, select_esi_device,
        EsiCompileOptions,
    };
    use crate::sii::image::{patch_sii_image, sii_validate, SiiBuildProfile, SiiPatchSpec};
    use crate::sii::ops::inspect_sii_data;

    #[test]
    fn esi_xml_to_sii_compile_inspect_and_patch() {
        let xml = br##"<?xml version="1.0" encoding="utf-8"?>
<EtherCATInfo>
  <Vendor><Id>#x00000002</Id><Name>DemoVendor</Name></Vendor>
  <Descriptions>
    <Groups><Group><Type>IO</Type><Name>I/O Terminals</Name></Group></Groups>
    <Devices>
      <Device Physics="YY">
        <Type ProductCode="#x00001234" RevisionNo="#x00010000">DEMO-IO</Type>
        <Name>Demo 8ch Digital IO</Name>
        <GroupType>IO</GroupType>
        <Sm StartAddress="#x1000" ControlByte="#x26" Enable="1" DefaultSize="128">MBoxOut</Sm>
        <Sm StartAddress="#x1080" ControlByte="#x22" Enable="1" DefaultSize="128">MBoxIn</Sm>
        <Eeprom><ByteSize>2048</ByteSize><ConfigData>8003000000000000</ConfigData></Eeprom>
      </Device>
    </Devices>
  </Descriptions>
</EtherCATInfo>"##;
        let catalog = load_esi_catalog_from_bytes(xml, "demo.xml", None, 1033).unwrap();
        let dev = select_esi_device(&catalog.devices, Some("DEMO-IO"), None).unwrap();
        let compiled = compile_esi_device_to_sii(
            dev,
            &EsiCompileOptions {
                profile: SiiBuildProfile::Ssc,
                ..Default::default()
            },
        )
        .unwrap();
        sii_validate(&compiled.bytes).unwrap();

        let inspected = inspect_sii_data(&compiled.bytes).unwrap();
        assert_eq!(inspected.header.vendor_id, 2);
        assert_eq!(inspected.header.product_code, 0x1234);
        assert!(inspected.header.crc_ok);

        let patched = patch_sii_image(
            &compiled.bytes,
            &SiiPatchSpec {
                alias: Some(0x0015),
                ..Default::default()
            },
        )
        .unwrap();
        sii_validate(&patched).unwrap();
    }
}
