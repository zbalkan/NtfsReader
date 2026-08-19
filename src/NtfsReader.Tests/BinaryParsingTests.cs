using System.Buffers.Binary;
using System.IO.Filesystem.Ntfs;
using Reader = System.IO.Filesystem.Ntfs.NtfsReader;

namespace NtfsReader.Tests;

public sealed partial class BinaryParsingTests
{
    [Fact]
    public void SparseRunUsesAZeroWidthOffsetWithoutReadingBeforeTheBuffer()
    {
        byte[] runLengthBytes = [0x60];
        var index = 0;

        var runLength = Reader.ProcessRunLength(runLengthBytes, 1, ref index);
        var runOffset = Reader.ProcessRunOffset(runLengthBytes, 0, ref index);

        Assert.Equal<ulong>(0x60, runLength);
        Assert.Equal(0L, runOffset);
        Assert.Equal(1, index);
    }

    [Fact]
    public void NegativeRunOffsetIsSignExtendedFromItsEncodedWidth()
    {
        byte[] runOffsetBytes = [0xE0];
        var index = 0;

        var runOffset = Reader.ProcessRunOffset(runOffsetBytes, 1, ref index);

        Assert.Equal(-32L, runOffset);
        Assert.Equal(1, index);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(9)]
    public void InvalidRunLengthWidthIsRejected(int width)
    {
        byte[] bytes = new byte[9];
        var index = 0;

        Assert.Throws<NtfsException>(() => Reader.ProcessRunLength(bytes, width, ref index));
    }

    [Fact]
    public void TruncatedRunOffsetIsRejectedBeforeReadingPastTheRunArray()
    {
        byte[] bytes = [0x01];
        var index = 0;

        Assert.Throws<NtfsException>(() => Reader.ProcessRunOffset(bytes, 2, ref index));
    }

    [Fact]
    public void FixupRawMftdataReplacesValidatedSectorTrailers()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 3);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x30), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x32), 0x1122);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x34), 0x3344);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(510), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(1022), 0xA55A);

        Reader.FixupRawMftdata(record, 512);

        Assert.Equal((ushort)0x1122, BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(510)));
        Assert.Equal((ushort)0x3344, BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(1022)));
    }

    [Fact]
    public void FixupRawMftdataRejectsAnOutOfBoundsUpdateSequenceArray()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 1020, usaCount: 3);

        Assert.Throws<NtfsException>(() => Reader.FixupRawMftdata(record, 512));
    }

    [Fact]
    public void FixupRawMftdataRejectsAnUnexpectedSectorCount()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 2);

        Assert.Throws<NtfsException>(() => Reader.FixupRawMftdata(record, 512));
    }

    private static byte[] CreateTwoSectorFileRecord(ushort usaOffset, ushort usaCount)
    {
        var record = new byte[1024];
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(0), 0x454C4946); // FILE
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4), usaOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(6), usaCount);
        return record;
    }
}

public sealed partial class BinaryParsingTests
{
    [Theory]
    [InlineData((byte)0x03, (byte)0x02, true)]
    [InlineData((byte)0x01, (byte)0x02, true)]
    [InlineData((byte)0x02, (byte)0x01, false)]
    public void Win32CapableFilenameNamespaceIsPreferred(byte candidate, byte current, bool expected)
    {
        Assert.Equal(expected, Reader.IsPreferredFileName(candidate, current));
    }
}
