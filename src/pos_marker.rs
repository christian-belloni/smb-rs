use std::{fmt::Debug, io::SeekFrom};

use binrw::{error::CustomError, BinRead, BinResult, BinWrite, Endian};

/**
 * Source: https://github.com/jam1garner/binrw/discussions/229
 */
pub struct PosMarker<T> {
    pub pos: core::cell::Cell<u64>,
    pub value: T,
}

impl<T> PosMarker<T> where T: Into<u64> + Copy {
    /// This function assumes the PosMarker is used to describe an offset from it's location.
    /// You can use it to get a `SeekFrom` to seek to the position described by the PosMarker
    pub fn seek_relative(&self) -> SeekFrom {
        debug_assert!(self.pos.get() != u64::MAX); // sanity
        SeekFrom::Start(self.pos.get() + self.value.into())
    }
}

impl<T> BinRead for PosMarker<T>
where
    T: BinRead,
{
    type Args<'a> = T::Args<'a>;

    fn read_options<R: binrw::io::Read + binrw::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let pos = reader.stream_position()?;
        T::read_options(reader, endian, args).map(|value| Self {
            pos: core::cell::Cell::new(pos),
            value,
        })
    }
}

impl<T> BinWrite for PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + Default,
{
    type Args<'a> = ();

    fn write_options<W: binrw::io::Write + binrw::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        self.pos.set(writer.stream_position()?);
        T::default().write_options(writer, endian, args)
    }
}

impl<T> PosMarker<T>
where
    T: BinWrite<Args<'static> = ()> + TryFrom<u64>,
    T::Error: binrw::error::CustomError + 'static,
{
    /// Call this write to fill a PosMarker value to the position of the written value.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_start_offset<U>(value: &U, this: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        this.do_writeback_offset(writer, endian)?;
        value.write_options(writer, endian, ())?;
        Ok(())
    }

    // Move back the writer, update the written value and return to the end of the file.
    pub fn do_writeback<V, W>(&self, value: V, writer: &mut W, endian: Endian) -> BinResult<()>
    where
        V: TryInto<T>,
        W: binrw::io::Write + binrw::io::Seek,
    {
        let return_to = writer.stream_position()?;
        writer.seek(SeekFrom::Start(self.pos.get()))?;
        value
            .try_into()
            .map_err(|_| binrw::error::Error::Custom {
                pos: self.pos.get(),
                err: Box::new("Error converting value to T"),
            })?
            .write_options(writer, endian, ())?;
        writer.seek(SeekFrom::Start(return_to))?;
        Ok(())
    }

    // Write the current position, relative to the stream start, to the PosMarker.
    // Returns the written position.
    pub fn do_writeback_offset<W>(&self, writer: &mut W, endian: Endian) -> BinResult<u64>
    where
        W: binrw::io::Write + binrw::io::Seek,
    {
        let stream_position = writer.stream_position()?;
        self.do_writeback(stream_position, writer, endian)?;
        Ok(stream_position)
    }

    /// Call this write to fill a PosMarker value to the relative offset of the written value.
    /// The relative offset is calculated by subtracting the position of the PosMarker from the position of the written value.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_relative_offset<U>(value: &U, this: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let pos = writer.stream_position()?;
        let offset_value = pos - this.pos.get();
        this.do_writeback(offset_value, writer, endian)?;
        // Continue writing the real value this writer is specified for
        value.write_options(writer, endian, ())
    }

    // This is just like write_and_fill_relative_offset, but now it does not use
    // `this` position as the base to calculate the offset, but the `base` position.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_offset_with_base<U, B>(
        value: &U,
        this: &Self,
        base: &PosMarker<B>,
    ) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let pos = writer.stream_position()?;
        let offset_value = pos - base.pos.get();
        this.do_writeback(offset_value, writer, endian)?;
        // Continue writing the real value this writer is specified for
        value.write_options(writer, endian, ())
    }

    /// Call this write to fill a PosMarker value to the size of the wrapped object that was written.
    #[binrw::writer(writer, endian)]
    pub fn write_and_fill_size<U>(value: &U, this: &Self) -> BinResult<()>
    where
        U: BinWrite<Args<'static> = ()>,
    {
        let begin_offset = writer.stream_position()?;
        value.write_options(writer, endian, ())?;
        let end_offset = writer.stream_position()?;
        let size_written = end_offset - begin_offset;
        // do_writeback(...):
        this.do_writeback(size_written, writer, endian)?;
        Ok(())
    }
}

impl<T> Debug for PosMarker<T>
where
    T: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PosMarker")
            .field("pos", &self.pos)
            .field("value", &self.value)
            .finish()
    }
}

impl<T> Default for PosMarker<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            pos: core::cell::Cell::new(u64::MAX),
            value: T::default(),
        }
    }
}
