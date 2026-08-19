using System.Buffers.Binary;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: InternalsVisibleTo("NtfsReader.Tests")]

namespace System.IO.Filesystem.Ntfs
{
    public sealed partial class NtfsReader
    {
        private const int AttributeHeaderSize = 16;
        private const int FileNameFixedValueSize = 66;
        private const int NonResidentAttributeMinimumSize = 64;
        private const int AttributeListEntryMinimumSize = 26;
        private const int MaximumMftRecordSize = 1024 * 1024;

        private static T ReadStruct<T>(ReadOnlySpan<byte> source, string field)
            where T : unmanaged
        {
            var size = Unsafe.SizeOf<T>();
            if (source.Length < size)
            {
                throw new NtfsException($"{field} is truncated.");
            }

            return MemoryMarshal.Read<T>(source);
        }

        private static ReadOnlySpan<byte> SliceChecked(
            ReadOnlySpan<byte> source,
            int offset,
            int length,
            string field)
        {
            if (offset < 0 || length < 0 || offset > source.Length || length > source.Length - offset)
            {
                throw new NtfsException($"{field} lies outside the containing record.");
            }

            return source.Slice(offset, length);
        }

        private static Span<byte> SliceChecked(
            Span<byte> source,
            int offset,
            int length,
            string field)
        {
            if (offset < 0 || length < 0 || offset > source.Length || length > source.Length - offset)
            {
                throw new NtfsException($"{field} lies outside the containing record.");
            }

            return source.Slice(offset, length);
        }

        private static int CheckedByteLength(ulong length, string field)
        {
            if (length > int.MaxValue)
            {
                throw new NtfsException($"{field} is too large to buffer safely.");
            }

            return checked((int)length);
        }

        private static int CheckedUtf16ByteLength(int characterCount, string field)
        {
            if (characterCount < 0 || characterCount > int.MaxValue / sizeof(char))
            {
                throw new NtfsException($"{field} has an invalid UTF-16 length.");
            }

            return checked(characterCount * sizeof(char));
        }

        private static ulong CheckedMultiply(ulong left, ulong right, string field)
        {
            try
            {
                return checked(left * right);
            }
            catch (OverflowException exception)
            {
                throw new NtfsException($"{field} overflows the supported address range.", exception);
            }
        }

        private static ulong CheckedAdd(ulong left, ulong right, string field)
        {
            try
            {
                return checked(left + right);
            }
            catch (OverflowException exception)
            {
                throw new NtfsException($"{field} overflows the supported address range.", exception);
            }
        }

        private static ulong ReadUInt48LittleEndian(ReadOnlySpan<byte> source, string field)
        {
            var bytes = SliceChecked(source, 0, 6, field);
            return (ulong)bytes[0] |
                ((ulong)bytes[1] << 8) |
                ((ulong)bytes[2] << 16) |
                ((ulong)bytes[3] << 24) |
                ((ulong)bytes[4] << 32) |
                ((ulong)bytes[5] << 40);
        }

        private static ushort ReadUInt16LittleEndian(ReadOnlySpan<byte> source, int offset, string field) =>
            BinaryPrimitives.ReadUInt16LittleEndian(SliceChecked(source, offset, sizeof(ushort), field));

        private static uint ReadUInt32LittleEndian(ReadOnlySpan<byte> source, int offset, string field) =>
            BinaryPrimitives.ReadUInt32LittleEndian(SliceChecked(source, offset, sizeof(uint), field));

        private static ulong ReadUInt64LittleEndian(ReadOnlySpan<byte> source, int offset, string field) =>
            BinaryPrimitives.ReadUInt64LittleEndian(SliceChecked(source, offset, sizeof(ulong), field));

        private static void WriteUInt16LittleEndian(Span<byte> destination, int offset, ushort value, string field) =>
            BinaryPrimitives.WriteUInt16LittleEndian(SliceChecked(destination, offset, sizeof(ushort), field), value);
    }
}

namespace System.IO.Filesystem.Ntfs
{
    public sealed partial class NtfsReader
    {
        private void CollectAttributeListReferences(
            ReadOnlySpan<byte> attributeData,
            Attribute attribute,
            List<AttributeListReference> references)
        {
            ReadOnlySpan<byte> value;
            if (attribute.Nonresident == 0)
            {
                var residentAttribute = ReadStruct<ResidentAttribute>(
                    attributeData,
                    "The resident $ATTRIBUTE_LIST header"
                );
                value = SliceChecked(
                    attributeData,
                    residentAttribute.ValueOffset,
                    CheckedByteLength(residentAttribute.ValueLength, "The $ATTRIBUTE_LIST value length"),
                    "The resident $ATTRIBUTE_LIST value"
                );
            }
            else
            {
                var nonResidentAttribute = ReadStruct<NonResidentAttribute>(
                    attributeData,
                    "The non-resident $ATTRIBUTE_LIST header"
                );
                var runData = SliceChecked(
                    attributeData,
                    nonResidentAttribute.RunArrayOffset,
                    attributeData.Length - nonResidentAttribute.RunArrayOffset,
                    "The non-resident $ATTRIBUTE_LIST data-run array"
                );
                var data = ProcessNonResidentData(runData, 0, nonResidentAttribute.DataSize);
                value = data.AsSpan(0, CheckedByteLength(nonResidentAttribute.DataSize, "The $ATTRIBUTE_LIST value length"));
            }

            var offset = 0;
            while (offset < value.Length)
            {
                var remaining = value[offset..];
                if (remaining.Length < AttributeListEntryMinimumSize)
                {
                    throw new NtfsException("The $ATTRIBUTE_LIST contains a truncated entry.");
                }

                var entryLength = ReadUInt16LittleEndian(remaining, 4, "The $ATTRIBUTE_LIST entry length");
                if (entryLength < AttributeListEntryMinimumSize || entryLength % 8 != 0)
                {
                    throw new NtfsException("The $ATTRIBUTE_LIST contains an invalid entry length.");
                }

                var entry = SliceChecked(remaining, 0, entryLength, "The $ATTRIBUTE_LIST entry");
                var nameLength = entry[6];
                var nameByteLength = CheckedUtf16ByteLength(nameLength, "The $ATTRIBUTE_LIST entry name");
                if (nameLength > 0)
                {
                    _ = SliceChecked(entry, entry[7], nameByteLength, "The $ATTRIBUTE_LIST entry name");
                }

                var fileRecordNumber = ReadUInt48LittleEndian(entry[16..], "The $ATTRIBUTE_LIST file reference");
                if (fileRecordNumber > uint.MaxValue)
                {
                    throw new NotSupportedException("48-bit MFT references are not supported by the current node model.");
                }

                references.Add(new AttributeListReference(
                    (AttributeType)ReadUInt32LittleEndian(entry, 0, "The $ATTRIBUTE_LIST attribute type"),
                    ReadUInt64LittleEndian(entry, 8, "The $ATTRIBUTE_LIST lowest VCN"),
                    checked((uint)fileRecordNumber),
                    ReadUInt16LittleEndian(entry, 22, "The $ATTRIBUTE_LIST sequence number"),
                    ReadUInt16LittleEndian(entry, 24, "The $ATTRIBUTE_LIST attribute identifier")
                ));
                offset = checked(offset + entryLength);
            }
        }
    }
}

namespace System.IO.Filesystem.Ntfs
{
    public sealed partial class NtfsReader
    {
        private void ResolveAttributeListReferences(
            ref Node node,
            uint baseNodeIndex,
            IReadOnlyList<AttributeListReference> references,
            List<Stream>? streams,
            bool isMftNode,
            Stream mftDataStream)
        {
            if (references.Count == 0)
            {
                return;
            }

            var recordCache = new Dictionary<uint, byte[]>();
            var processedAttributes = new HashSet<(uint RecordNumber, ushort AttributeNumber)>();
            foreach (var reference in references)
            {
                if (reference.FileRecordNumber == baseNodeIndex)
                {
                    continue;
                }

                if (!processedAttributes.Add((reference.FileRecordNumber, reference.AttributeNumber)))
                {
                    continue;
                }

                if (!recordCache.TryGetValue(reference.FileRecordNumber, out var extensionRecord))
                {
                    extensionRecord = ReadMftRecord(mftDataStream, reference.FileRecordNumber);
                    recordCache.Add(reference.FileRecordNumber, extensionRecord);
                }

                ProcessExtensionRecord(
                    ref node,
                    baseNodeIndex,
                    extensionRecord,
                    reference,
                    streams,
                    isMftNode
                );
            }
        }

        private unsafe byte[] ReadMftRecord(Stream mftDataStream, uint recordNumber)
        {
            var recordLength = CheckedByteLength(_diskInfo.BytesPerMftRecord, "The MFT record size");
            var recordOffset = CheckedMultiply(recordNumber, _diskInfo.BytesPerMftRecord, "The MFT record offset");
            if (recordOffset > mftDataStream.Size ||
                _diskInfo.BytesPerMftRecord > mftDataStream.Size - recordOffset)
            {
                throw new NtfsException("An $ATTRIBUTE_LIST reference points outside the $MFT data stream.");
            }

            var record = new byte[recordLength];
            var requestedEnd = CheckedAdd(recordOffset, _diskInfo.BytesPerMftRecord, "The requested MFT record range");
            var previousVcn = 0UL;
            var bytesCopied = 0UL;

            fixed (byte* recordPointer = record)
            {
                foreach (var fragment in mftDataStream.Fragments)
                {
                    if (fragment.NextVcn <= previousVcn)
                    {
                        throw new NtfsException("The $MFT data stream contains an invalid fragment range.");
                    }

                    var fragmentStart = CheckedMultiply(previousVcn, _diskInfo.BytesPerCluster, "The $MFT fragment start");
                    var fragmentEnd = CheckedMultiply(fragment.NextVcn, _diskInfo.BytesPerCluster, "The $MFT fragment end");
                    previousVcn = fragment.NextVcn;

                    if (recordOffset >= fragmentEnd || requestedEnd <= fragmentStart)
                    {
                        continue;
                    }

                    if (fragment.Lcn == VIRTUAL_FRAGMENT)
                    {
                        throw new NtfsException("The $MFT data stream contains a sparse range.");
                    }

                    var readStart = Math.Max(recordOffset, fragmentStart);
                    var readEnd = Math.Min(requestedEnd, fragmentEnd);
                    var readLength = readEnd - readStart;
                    var physicalOffset = CheckedAdd(
                        CheckedMultiply(fragment.Lcn, _diskInfo.BytesPerCluster, "The $MFT fragment physical offset"),
                        readStart - fragmentStart,
                        "The $MFT record physical offset"
                    );
                    var destinationOffset = CheckedByteLength(readStart - recordOffset, "The $MFT record buffer offset");
                    ReadFile(recordPointer + destinationOffset, readLength, physicalOffset);
                    bytesCopied = CheckedAdd(bytesCopied, readLength, "The copied MFT record length");
                }
            }

            if (bytesCopied != _diskInfo.BytesPerMftRecord)
            {
                throw new NtfsException("The $MFT data stream does not fully cover an $ATTRIBUTE_LIST reference.");
            }

            FixupRawMftdata(record);
            return record;
        }

        private void ProcessExtensionRecord(
            ref Node node,
            uint baseNodeIndex,
            ReadOnlySpan<byte> extensionRecord,
            AttributeListReference reference,
            List<Stream>? streams,
            bool isMftNode)
        {
            var header = ReadStruct<FileRecordHeader>(extensionRecord, "The extension MFT record header");
            if (header.RecordHeader.Type != RecordType.File || (header.Flags & 1) == 0)
            {
                throw new NtfsException("An $ATTRIBUTE_LIST reference does not point to an in-use FILE record.");
            }

            var referencedBaseRecord = ((ulong)header.BaseFileRecord.InodeNumberHighPart << 32) +
                header.BaseFileRecord.InodeNumberLowPart;
            if (referencedBaseRecord != baseNodeIndex || header.SequenceNumber != reference.SequenceNumber)
            {
                throw new NtfsException("An $ATTRIBUTE_LIST reference does not match its extension MFT record.");
            }

            if (header.BytesInUse < Unsafe.SizeOf<FileRecordHeader>() ||
                header.BytesInUse > extensionRecord.Length ||
                header.AttributeOffset >= header.BytesInUse)
            {
                throw new NtfsException("The extension MFT record declares an invalid attribute area.");
            }

            var attributes = SliceChecked(
                extensionRecord,
                header.AttributeOffset,
                checked((int)header.BytesInUse - header.AttributeOffset),
                "The extension MFT attribute area"
            );
            ProcessAttributes(
                ref node,
                baseNodeIndex,
                attributes,
                reference.AttributeNumber,
                streams,
                isMftNode,
                expectedType: reference.Type
            );
        }
    }
}
