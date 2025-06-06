use super::align::*;
use super::ptr::*;
use binrw::prelude::*;

#[derive(Debug, PartialEq, Eq)]
pub struct NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    pub data: Vec<NdrAlign<E>>,
}

impl<E> BinRead for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Args<'a> = (u64,);

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        // First read: direct data (ptr refs)
        let count = args.0;
        let mut data = Vec::with_capacity(count as usize);
        for _ in 0..count {
            data.push(NdrAlign::<E>::read_options(reader, endian, (None,))?);
        }
        // Second read: ptr values
        let mut resolved = Vec::with_capacity(count as usize);
        for refs_only in &data {
            let ptr_value = NdrAlign::<E>::read_options(reader, endian, (Some(refs_only),))?;
            resolved.push(ptr_value);
        }
        Ok(Self { data: resolved })
    }
}

impl<E> BinWrite for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        // First write: direct data (ptr refs)
        for item in &self.data {
            item.write_options(writer, endian, (NdrPtrWriteStage::ArraySupportWriteRefId,))?;
        }
        // Second write: ptr values
        for item in &self.data {
            item.write_options(writer, endian, (NdrPtrWriteStage::ArraySupportWriteData,))?;
        }
        Ok(())
    }
}

impl<E> NdrAligned for NdrArray<E> where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static
{
}

impl<E> Into<NdrArray<E>> for Vec<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    fn into(self) -> NdrArray<E> {
        NdrArray {
            data: self.into_iter().map(NdrAlign::from).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use aead::rand_core::le;

    use crate::packets::dcerpc::ndr64::string::NdrString;

    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_write_structure_array_with_ptrs() {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        #[bw(import(stage: NdrPtrWriteStage))]
        #[br(import(prev: Option<&Self>))]
        struct InArrayElement {
            #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
            #[br(args(prev.map(|x| &x.ptr_to_value), NdrPtrReadMode::WithArraySupport, ()))]
            ptr_to_value: NdrPtr<u32>,
            #[bw(if(stage == NdrPtrWriteStage::ArraySupportWriteRefId))]
            random_byte: NdrAlign<u8>,
            #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
            #[br(args(prev.map(|x| &x.string_val), NdrPtrReadMode::WithArraySupport, ()))]
            string_val: NdrPtr<NdrString<u16>>,
        }

        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        struct WithArray {
            array: NdrArray<InArrayElement>,
        }

        let array = WithArray {
            array: vec![
                InArrayElement {
                    ptr_to_value: 42.into(),
                    random_byte: 0x01.into(),
                    string_val: "Hello".parse::<NdrString<u16>>().unwrap().into(),
                },
                InArrayElement {
                    ptr_to_value: 84.into(),
                    random_byte: 0x02.into(),
                    string_val: "World".parse::<NdrString<u16>>().unwrap().into(),
                },
            ]
            .into(),
        };
        let mut cursor = Cursor::new(vec![]);
        array.write_le(&mut cursor).unwrap();

        let (hello_data, world_data) = {
            let mut cursor = Cursor::new(vec![]);
            Into::<NdrAlign<NdrString<u16>>>::into("Hello".parse::<NdrString<u16>>().unwrap())
                .write_le(&mut cursor)
                .unwrap();
            let hello_data = cursor.into_inner();
            let mut cursor = Cursor::new(vec![]);
            Into::<NdrAlign<NdrString<u16>>>::into("World".parse::<NdrString<u16>>().unwrap())
                .write_le(&mut cursor)
                .unwrap();

            let world_data = cursor.into_inner();
            assert!(
                // sanity for this encoding
                hello_data.len() % NDR64_ALIGNMENT == 0 && world_data.len() % NDR64_ALIGNMENT == 0,
                "String data should be aligned to 8 bytes",
            );
            (hello_data, world_data)
        };

        assert_eq!(
            cursor.into_inner(),
            [
                // struct#1
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, // ptr ref to first element's dword ptr
                0x01, // random byte of first element
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // aligned to 8 bytes
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, // ptr ref to first element's string
                // struct#2
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, // ptr ref to second element's dword ptr
                0x02, // random byte of second element
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // aligned to 8 bytes
                0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
                0x00, // ptr ref to second element's string
                42, 0, 0, 0, // value of first element
                0, 0, 0, 0, // aligned to 8 bytes
            ]
            .into_iter()
            .chain(hello_data)
            .chain([
                84, 0, 0, 0, 0, 0, 0, 0, // aligned to 8 bytes
            ])
            .chain(world_data)
            .collect::<Vec<u8>>()
        );
    }
}
