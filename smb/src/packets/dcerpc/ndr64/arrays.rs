use std::ops::Deref;
use std::ops::DerefMut;

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
        // First read: direct data (ptr refs & actual data)
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
        _args: Self::Args<'_>,
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

impl<E> Deref for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    type Target = [NdrAlign<E>];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<E> DerefMut for NdrArray<E>
where
    for<'a> E:
        BinRead<Args<'a> = (Option<&'a E>,)> + BinWrite<Args<'a> = (NdrPtrWriteStage,)> + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

#[derive(Debug, PartialEq, Eq)]
struct NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + 'static,
{
    val: NdrAlign<T>,
}

impl<T> BinRead for NdrArrayStructureElement<T>
where
    T: BinRead<Args<'static> = ()> + BinWrite + Clone + 'static,
{
    type Args<'a> = (Option<&'a T>,);

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::endian::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        match args.0 {
            Some(prev) => Ok(Self {
                val: (*prev).clone().into(),
            }),
            None => {
                let val = NdrAlign::<T>::read_options(reader, endian, ())?;
                Ok(Self { val })
            }
        }
    }
}

impl<T> BinWrite for NdrArrayStructureElement<T>
where
    for<'a> T: BinWrite<Args<'a> = ()> + BinRead + Clone + 'static,
{
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::endian::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        self.val.write_options(writer, endian, ())
    }
}

impl<T> From<T> for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    fn from(value: T) -> Self {
        Self {
            val: NdrAlign::from(value),
        }
    }
}
impl<T> NdrAligned for NdrArrayStructureElement<T> where T: BinRead + BinWrite + Clone + 'static {}

impl<T> Deref for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    type Target = NdrAlign<T>;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T> DerefMut for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + 'static,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.val
    }
}

impl<T> Default for NdrArrayStructureElement<T>
where
    T: BinRead + BinWrite + Clone + Default + 'static,
{
    fn default() -> Self {
        Self {
            val: NdrAlign::from(T::default()),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::packets::dcerpc::ndr64::NdrString;

    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_array_structure_with_ptrs() {
        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        #[bw(import(stage: NdrPtrWriteStage))]
        #[br(import(prev: Option<&Self>))]
        struct InArrayElement {
            #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
            #[br(args(prev.map(|x| &x.ptr_to_value), NdrPtrReadMode::WithArraySupport, ()))]
            ptr_to_value: NdrPtr<u32>,
            #[bw(if(stage == NdrPtrWriteStage::ArraySupportWriteRefId))]
            #[br(args(prev.map(|x| &**x.random_byte)))]
            random_byte: NdrArrayStructureElement<u8>,
            #[bw(args_raw(NdrPtrWriteArgs(stage, ())))]
            #[br(args(prev.map(|x| &x.string_val), NdrPtrReadMode::WithArraySupport, ()))]
            string_val: NdrPtr<NdrString<u16>>,
        }

        #[binrw::binrw]
        #[derive(Debug, PartialEq, Eq)]
        struct WithArray {
            #[bw(calc = (array.len() as u32).into())]
            size: NdrAlign<u32>,
            #[br(args(*size as u64))] // TODO: prevent default to 0
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

        let exp_data = [
            // size
            0x02, 0x00, 0x00, 0x00, // size of array (2 elements)
            0x00, 0x00, 0x00, 0x00, // aligned to 8 bytes
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
        .collect::<Vec<u8>>();

        assert_eq!(cursor.into_inner(), exp_data);

        let mut cursor = Cursor::new(exp_data);
        let read_array: WithArray = BinRead::read_le(&mut cursor).unwrap();
        assert_eq!(read_array, array);
    }
}
