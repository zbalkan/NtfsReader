using System.Buffers.Binary;
using System.IO.Filesystem.Ntfs;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Reader = System.IO.Filesystem.Ntfs.NtfsReader;

namespace NtfsReader.Tests;

[TestClass]
public sealed class BinaryParsingTests
{
    [TestMethod]
    public void SparseRunUsesAZeroWidthOffsetWithoutReadingBeforeTheBuffer()
    {
        byte[] runLengthBytes = [0x60];
        var index = 0;

        var runLength = Reader.ProcessRunLength(runLengthBytes, 1, ref index);
        var runOffset = Reader.ProcessRunOffset(runLengthBytes, 0, ref index);

        Assert.AreEqual<ulong>(0x60, runLength);
        Assert.AreEqual(0L, runOffset);
        Assert.AreEqual(1, index);
    }

    [TestMethod]
    public void NegativeRunOffsetIsSignExtendedFromItsEncodedWidth()
    {
        byte[] runOffsetBytes = [0xE0];
        var index = 0;

        var runOffset = Reader.ProcessRunOffset(runOffsetBytes, 1, ref index);

        Assert.AreEqual(-32L, runOffset);
        Assert.AreEqual(1, index);
    }

    [TestMethod]
    [DataRow(1, 0x7FUL)]
    [DataRow(2, 0x1234UL)]
    [DataRow(3, 0x563412UL)]
    [DataRow(4, 0x78563412UL)]
    [DataRow(8, 0x1122334455667788UL)]
    public void RunLengthDecodesLittleEndianValuesAtEverySupportedWidth(int width, ulong expected)
    {
        var bytes = new byte[width];
        for (var byteIndex = 0; byteIndex < width; byteIndex++)
        {
            bytes[byteIndex] = (byte)(expected >> (byteIndex * 8));
        }

        var index = 0;
        var actual = Reader.ProcessRunLength(bytes, width, ref index);

        Assert.AreEqual(expected, actual);
        Assert.AreEqual(width, index);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(9)]
    public void InvalidRunLengthWidthIsRejected(int width)
    {
        byte[] bytes = new byte[9];
        var index = 0;

        Assert.ThrowsExactly<NtfsException>(() => Reader.ProcessRunLength(bytes, width, ref index));
        Assert.AreEqual(0, index);
    }

    [TestMethod]
    public void TruncatedRunLengthIsRejectedWithoutAdvancingTheBufferIndex()
    {
        byte[] bytes = [0x01];
        var index = 0;

        Assert.ThrowsExactly<NtfsException>(() => Reader.ProcessRunLength(bytes, 2, ref index));
        Assert.AreEqual(0, index);
    }

    [TestMethod]
    [DataRow(new byte[] { 0x34, 0x12 }, 2, 4660L)]
    [DataRow(new byte[] { 0x00, 0x80 }, 2, -32768L)]
    [DataRow(new byte[] { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, 8, -1L)]
    public void RunOffsetDecodesPositiveAndNegativeLittleEndianValues(byte[] bytes, int width, long expected)
    {
        var index = 0;

        var actual = Reader.ProcessRunOffset(bytes, width, ref index);

        Assert.AreEqual(expected, actual);
        Assert.AreEqual(width, index);
    }

    [TestMethod]
    public void InvalidRunOffsetWidthIsRejectedWithoutAdvancingTheBufferIndex()
    {
        byte[] bytes = new byte[9];
        var index = 0;

        Assert.ThrowsExactly<NtfsException>(() => Reader.ProcessRunOffset(bytes, 9, ref index));
        Assert.AreEqual(0, index);
    }

    [TestMethod]
    public void TruncatedRunOffsetIsRejectedBeforeReadingPastTheRunArray()
    {
        byte[] bytes = [0x01];
        var index = 0;

        Assert.ThrowsExactly<NtfsException>(() => Reader.ProcessRunOffset(bytes, 2, ref index));
        Assert.AreEqual(0, index);
    }

    [TestMethod]
    public void FixupRawMftdataReplacesValidatedSectorTrailers()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 3);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x30), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x32), 0x1122);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x34), 0x3344);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(510), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(1022), 0xA55A);

        Reader.FixupRawMftdata(record, 512);

        Assert.AreEqual((ushort)0x1122, BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(510)));
        Assert.AreEqual((ushort)0x3344, BinaryPrimitives.ReadUInt16LittleEndian(record.AsSpan(1022)));
    }

    [TestMethod]
    public void FixupRawMftdataRejectsAnOutOfBoundsUpdateSequenceArray()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 1020, usaCount: 3);

        Assert.ThrowsExactly<NtfsException>(() => Reader.FixupRawMftdata(record, 512));
    }

    [TestMethod]
    public void FixupRawMftdataRejectsAnUnexpectedSectorCount()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 2);

        Assert.ThrowsExactly<NtfsException>(() => Reader.FixupRawMftdata(record, 512));
    }

    [TestMethod]
    [DataRow((ushort)1)]
    [DataRow((ushort)513)]
    public void FixupRawMftdataRejectsInvalidSectorSizes(ushort bytesPerSector)
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 3);

        Assert.ThrowsExactly<NtfsException>(() => Reader.FixupRawMftdata(record, bytesPerSector));
    }

    [TestMethod]
    public void FixupRawMftdataRejectsAMismatchedUpdateSequenceNumber()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 3);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x30), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x32), 0x1122);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(0x34), 0x3344);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(510), 0xA55A);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(1022), 0xB55A);

        Assert.ThrowsExactly<NtfsException>(() => Reader.FixupRawMftdata(record, 512));
    }

    [TestMethod]
    public void FixupRawMftdataLeavesNonFileRecordsUntouched()
    {
        var record = CreateTwoSectorFileRecord(usaOffset: 0x30, usaCount: 3);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(0), 0x44414142); // BAAD
        var expected = (byte[])record.Clone();

        Reader.FixupRawMftdata(record, 512);

        CollectionAssert.AreEqual(expected, record);
    }

    [TestMethod]
    [DataRow((byte)0x03, (byte)0x02, true)]
    [DataRow((byte)0x01, (byte)0x02, true)]
    [DataRow((byte)0x03, (byte)0x00, true)]
    [DataRow((byte)0x02, (byte)0x01, false)]
    [DataRow((byte)0x03, (byte)0x03, false)]
    public void Win32CapableFilenameNamespaceIsPreferred(byte candidate, byte current, bool expected)
    {
        Assert.AreEqual(expected, Reader.IsPreferredFileName(candidate, current));
    }

    [TestMethod]
    public void AggregateByFragmentsGroupsOnlyEligibleNodesByTheirPrimaryStream()
    {
        var first = CreateNode(fragmentCounts: [3, 8]);
        var second = CreateNode(fragmentCounts: [3]);
        var belowThreshold = CreateNode(fragmentCounts: [2]);
        var noStreams = CreateNode(fragmentCounts: null);
        var emptyStreams = CreateNode(fragmentCounts: []);

        var aggregates = Algorithms.AggregateByFragments(
            [first, second, belowThreshold, noStreams, emptyStreams],
            minimumFragments: 3
        );

        Assert.AreEqual(1, aggregates.Count);
        Assert.IsTrue(aggregates.TryGetValue(3, out var nodes));
        CollectionAssert.AreEqual(new INode[] { first, second }, nodes);
    }

    [TestMethod]
    public void AggregateBySizeExcludesDirectoriesAndGroupsEligibleFilesByExactSize()
    {
        var first = CreateNode(size: 100, attributes: 0);
        var second = CreateNode(size: 100, attributes: 0);
        var larger = CreateNode(size: 200, attributes: 0);
        var directory = CreateNode(size: 200, attributes: Attributes.Directory);
        var belowThreshold = CreateNode(size: 99, attributes: 0);

        var aggregates = Algorithms.AggregateBySize(
            [first, second, larger, directory, belowThreshold],
            minimumSize: 100
        );

        Assert.AreEqual(2, aggregates.Count);
        Assert.IsTrue(aggregates.TryGetValue(100, out var oneHundredByteNodes));
        CollectionAssert.AreEqual(new INode[] { first, second }, oneHundredByteNodes);
        Assert.IsTrue(aggregates.TryGetValue(200, out var twoHundredByteNodes));
        CollectionAssert.AreEqual(new INode[] { larger }, twoHundredByteNodes);
    }

    private static byte[] CreateTwoSectorFileRecord(ushort usaOffset, ushort usaCount)
    {
        var record = new byte[1024];
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(0), 0x454C4946); // FILE
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(4), usaOffset);
        BinaryPrimitives.WriteUInt16LittleEndian(record.AsSpan(6), usaCount);
        return record;
    }

    private static TestNode CreateNode(
        ulong size = 0,
        Attributes attributes = 0,
        int[]? fragmentCounts = null)
    {
        List<IStream>? streams = null;
        if (fragmentCounts is not null)
        {
            streams = new List<IStream>(fragmentCounts.Length);
            foreach (var fragmentCount in fragmentCounts)
            {
                streams.Add(CreateStream(fragmentCount));
            }
        }

        return new TestNode
        {
            Attributes = attributes,
            Size = size,
            Streams = streams
        };
    }

    private static TestStream CreateStream(int fragmentCount)
    {
        var fragments = new List<IFragment>(fragmentCount);
        for (var index = 0; index < fragmentCount; index++)
        {
            fragments.Add(new TestFragment());
        }

        return new TestStream { Fragments = fragments };
    }

    private sealed class TestNode : INode
    {
        public Attributes Attributes { get; init; }
        public DateTime CreationTime => DateTime.UnixEpoch;
        public string FullName => Name ?? string.Empty;
        public DateTime LastAccessTime => DateTime.UnixEpoch;
        public DateTime LastChangeTime => DateTime.UnixEpoch;
        public string? Name => null;
        public uint NodeIndex => 0;
        public uint ParentNodeIndex => 0;
        public ulong Size { get; init; }
        public IList<IStream>? Streams { get; init; }
    }

    private sealed class TestStream : IStream
    {
        public IList<IFragment>? Fragments { get; init; }
        public string? Name => null;
        public ulong Size => 0;
    }

    private sealed class TestFragment : IFragment
    {
        public ulong Lcn => 0;
        public ulong NextVcn => 0;
    }
}
