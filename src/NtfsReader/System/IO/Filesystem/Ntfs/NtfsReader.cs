/*
    The NtfsReader library.

    Copyright (C) 2008 Danny Couture

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

    For the full text of the license see the "License.txt" file.

    This library is based on the work of Jeroen Kessels, Author of JkDefrag.
    http://www.kessels.com/Jkdefrag/

    Special thanks goes to him.

    Danny Couture
    Software Architect
*/

using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Filesystem.Ntfs
{
    public sealed partial class NtfsReader : IDisposable
    {
        #region Ntfs Structures

        private enum AttributeType : uint
        {
            AttributeInvalid = 0x00,         /* Not defined by Windows */
            AttributeStandardInformation = 0x10,
            AttributeAttributeList = 0x20,
            AttributeFileName = 0x30,
            AttributeObjectId = 0x40,
            AttributeSecurityDescriptor = 0x50,
            AttributeVolumeName = 0x60,
            AttributeVolumeInformation = 0x70,
            AttributeData = 0x80,
            AttributeIndexRoot = 0x90,
            AttributeIndexAllocation = 0xA0,
            AttributeBitmap = 0xB0,
            AttributeReparsePoint = 0xC0,         /* Reparse Point = Symbolic link */
            AttributeEAInformation = 0xD0,
            AttributeEA = 0xE0,
            AttributePropertySet = 0xF0,
            AttributeLoggedUtilityStream = 0x100
        };

        private enum RecordType : uint
        {
            File = 0x454c4946,  //'FILE' in ASCII
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct Attribute
        {
            public AttributeType AttributeType;
            public uint Length;
            public byte Nonresident;
            public byte NameLength;
            public ushort NameOffset;
            public ushort Flags;              /* 0x0001 = Compressed, 0x4000 = Encrypted, 0x8000 = Sparse */
            public ushort AttributeNumber;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct AttributeFileName
        {
            public INodeReference ParentDirectory;
            public ulong CreationTime;
            public ulong ChangeTime;
            public ulong LastWriteTime;
            public ulong LastAccessTime;
            public ulong AllocatedSize;
            public ulong DataSize;
            public uint FileAttributes;
            public uint AlignmentOrReserved;
            public byte NameLength;
            public byte NameType;                 /* NTFS=0x01, DOS=0x02 */
            public char Name;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private unsafe struct AttributeList
        {
            public AttributeType AttributeType;
            public ushort Length;
            public byte NameLength;
            public byte NameOffset;
            public ulong LowestVcn;
            public INodeReference FileReferenceNumber;
            public ushort Instance;
            public fixed ushort AlignmentOrReserved[3];
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct AttributeStandardInformation
        {
            public ulong CreationTime;
            public ulong FileChangeTime;
            public ulong MftChangeTime;
            public ulong LastAccessTime;
            public uint FileAttributes;       /* READ_ONLY=0x01, HIDDEN=0x02, SYSTEM=0x04, VOLUME_ID=0x08, ARCHIVE=0x20, DEVICE=0x40 */
            public uint MaximumVersions;
            public uint VersionNumber;
            public uint ClassId;
            public uint OwnerId;                        // NTFS 3.0 only
            public uint SecurityId;                     // NTFS 3.0 only
            public ulong QuotaCharge;                // NTFS 3.0 only
            public ulong Usn;                              // NTFS 3.0 only
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private unsafe struct BootSector
        {
            public fixed byte AlignmentOrReserved1[3];
            public ulong Signature;
            public ushort BytesPerSector;
            public byte SectorsPerCluster;
            public fixed byte AlignmentOrReserved2[26];
            public ulong TotalSectors;
            public ulong MftStartLcn;
            public ulong Mft2StartLcn;
            public uint ClustersPerMftRecord;
            public uint ClustersPerIndexRecord;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct FileRecordHeader
        {
            public RecordHeader RecordHeader;
            public ushort SequenceNumber;        /* Sequence number */
            public ushort LinkCount;             /* Hard link count */
            public ushort AttributeOffset;       /* Offset to the first Attribute */
            public ushort Flags;                 /* Flags. bit 1 = in use, bit 2 = directory, bit 4 & 8 = unknown. */
            public uint BytesInUse;             /* Real size of the FILE record */
            public uint BytesAllocated;         /* Allocated size of the FILE record */
            public INodeReference BaseFileRecord;     /* File reference to the base FILE record */
            public ushort NextAttributeNumber;   /* Next Attribute Id */
            public ushort Padding;               /* Align to 4 UCHAR boundary (XP) */
            public uint MFTRecordNumber;        /* Number of this MFT Record (XP) */
            public ushort UpdateSeqNum;          /*  */
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct Fragment
        {
            public ulong Lcn;                // Logical cluster number, location on disk.
            public ulong NextVcn;            // Virtual cluster number of next fragment.

            public Fragment(ulong lcn, ulong nextVcn)
            {
                Lcn = lcn;
                NextVcn = nextVcn;
            }
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct INodeReference
        {
            public uint InodeNumberLowPart;
            public ushort InodeNumberHighPart;
            public ushort SequenceNumber;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private unsafe struct NonResidentAttribute
        {
            public Attribute Attribute;
            public ulong StartingVcn;
            public ulong LastVcn;
            public ushort RunArrayOffset;
            public byte CompressionUnit;
            public fixed byte AlignmentOrReserved[5];
            public ulong AllocatedSize;
            public ulong DataSize;
            public ulong InitializedSize;
            public ulong CompressedSize;    // Only when compressed
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct RecordHeader
        {
            public RecordType Type;                  /* File type, for example 'FILE' */
            public ushort UsaOffset;             /* Offset to the Update Sequence Array */
            public ushort UsaCount;              /* Size in words of Update Sequence Array */
            public ulong Lsn;                   /* $LogFile Sequence Number (LSN) */
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct ResidentAttribute
        {
            public Attribute Attribute;
            public uint ValueLength;
            public ushort ValueOffset;
            public ushort Flags;               // 0x0001 = Indexed
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct VolumeData
        {
            public ulong VolumeSerialNumber;
            public ulong NumberSectors;
            public ulong TotalClusters;
            public ulong FreeClusters;
            public ulong TotalReserved;
            public uint BytesPerSector;
            public uint BytesPerCluster;
            public uint BytesPerFileRecordSegment;
            public uint ClustersPerFileRecordSegment;
            public ulong MftValidDataLength;
            public ulong MftStartLcn;
            public ulong Mft2StartLcn;
            public ulong MftZoneStart;
            public ulong MftZoneEnd;
        }

        #endregion Ntfs Structures

        #region Private Classes

        /// <summary>
        /// Node struct for file and directory entries
        /// </summary>
        /// <remarks>
        /// We keep this as small as possible to reduce footprint for large volume.
        /// </remarks>
        private struct Node
        {
            public Attributes Attributes;
            public int NameIndex;
            public uint ParentNodeIndex;
            public ulong Size;
        }

        private readonly record struct StreamKey(AttributeType Type, int NameIndex);

        private readonly record struct AttributeListReference(
            AttributeType Type,
            ulong LowestVcn,
            uint FileRecordNumber,
            ushort SequenceNumber,
            ushort AttributeNumber
        );

        private struct MftReadCursor
        {
            public int FragmentIndex;
            public ulong RealVcn;
            public ulong Vcn;
        }

        /// <summary>
        /// Contains extra information not required for basic purposes.
        /// </summary>
        private struct StandardInformation
        {
            public ulong CreationTime;
            public ulong LastAccessTime;
            public ulong LastChangeTime;

            public StandardInformation(
                ulong creationTime,
                ulong lastAccessTime,
                ulong lastChangeTime
                )
            {
                CreationTime = creationTime;
                LastAccessTime = lastAccessTime;
                LastChangeTime = lastChangeTime;
            }
        }

        /// <summary>
        /// Simple structure of available disk informations.
        /// </summary>
        private sealed class DiskInfoWrapper : IDiskInfo
        {
            public ulong BytesPerCluster;
            public ulong BytesPerMftRecord;
            public ushort BytesPerSector;
            public uint ClustersPerIndexRecord;
            public uint ClustersPerMftRecord;
            public ulong Mft2StartLcn;
            public ulong MftStartLcn;
            public byte SectorsPerCluster;
            public ulong TotalClusters;
            public ulong TotalSectors;

            #region IDiskInfo Members

            ulong IDiskInfo.BytesPerCluster => BytesPerCluster;
            ulong IDiskInfo.BytesPerMftRecord => BytesPerMftRecord;
            ushort IDiskInfo.BytesPerSector => BytesPerSector;

            uint IDiskInfo.ClustersPerIndexRecord => ClustersPerIndexRecord;
            uint IDiskInfo.ClustersPerMftRecord => ClustersPerMftRecord;
            ulong IDiskInfo.Mft2StartLcn => Mft2StartLcn;
            ulong IDiskInfo.MftStartLcn => MftStartLcn;
            byte IDiskInfo.SectorsPerCluster => SectorsPerCluster;

            ulong IDiskInfo.TotalClusters => TotalClusters;
            ulong IDiskInfo.TotalSectors => TotalSectors;

            #endregion IDiskInfo Members
        }

        /// <summary>
        /// Add some functionality to the basic stream
        /// </summary>
        private sealed class FragmentWrapper : IFragment
        {
            private readonly StreamWrapper _owner;
            private Fragment _fragment;

            public FragmentWrapper(StreamWrapper owner, Fragment fragment)
            {
                _owner = owner;
                _fragment = fragment;
            }

            #region IFragment Members

            public ulong Lcn => _fragment.Lcn;

            public ulong NextVcn => _fragment.NextVcn;

            #endregion IFragment Members
        }

        /// <summary>
        /// Add some functionality to the basic node
        /// </summary>
        private sealed class NodeWrapper : INode
        {
            private readonly NtfsReader _reader;
            private Node _node;
            private IList<IStream>? _streamView;

            public NodeWrapper(NtfsReader reader, uint nodeIndex, Node node)
            {
                _reader = reader;
                NodeIndex = nodeIndex;
                _node = node;
            }

            public Attributes Attributes => _node.Attributes;

            public string FullName {
                get => _reader.GetNodeFullNameCore(NodeIndex);
            }

            public string? Name => _reader.GetNameFromIndex(_node.NameIndex);
            public uint NodeIndex { get; }

            public uint ParentNodeIndex => _node.ParentNodeIndex;
            public ulong Size => _node.Size;

            public IList<IStream>? Streams {
                get {
                    if (_reader._streams == null)
                    {
                        throw new NotSupportedException("The streams haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    if (_streamView != null)
                    {
                        return _streamView;
                    }

                    var streams = _reader._streams[NodeIndex];
                    if (streams == null)
                    {
                        return null;
                    }

                    var newStreams = new IStream[streams.Length];
                    for (var i = 0; i < streams.Length; ++i)
                    {
                        newStreams[i] = new StreamWrapper(_reader, this, i);
                    }

                    var view = Array.AsReadOnly(newStreams);
                    Interlocked.CompareExchange(ref _streamView, view, null);
                    return _streamView;
                }
            }

            #region INode Members

            public DateTime CreationTime {
                get {
                    if (_reader._standardInformations == null)
                    {
                        throw new NotSupportedException("The StandardInformation haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    return DateTime.FromFileTimeUtc((long)_reader._standardInformations[NodeIndex].CreationTime);
                }
            }

            public DateTime LastAccessTime {
                get {
                    if (_reader._standardInformations == null)
                    {
                        throw new NotSupportedException("The StandardInformation haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    return DateTime.FromFileTimeUtc((long)_reader._standardInformations[NodeIndex].LastAccessTime);
                }
            }

            public DateTime LastChangeTime {
                get {
                    if (_reader._standardInformations == null)
                    {
                        throw new NotSupportedException("The StandardInformation haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    return DateTime.FromFileTimeUtc((long)_reader._standardInformations[NodeIndex].LastChangeTime);
                }
            }

            #endregion INode Members
        }

        private sealed class Stream
        {
            public ulong Clusters;                      // Total number of clusters.
            public int NameIndex;
            public ulong Size;                          // Total number of bytes.
            public AttributeType Type;
            private List<Fragment>? _fragments;

            public Stream(int nameIndex, AttributeType type, ulong size)
            {
                NameIndex = nameIndex;
                Type = type;
                Size = size;
            }

            public List<Fragment> Fragments => _fragments ??= new List<Fragment>(5);
        }

        /// <summary>
        /// Add some functionality to the basic stream
        /// </summary>
        private sealed class StreamWrapper : IStream
        {
            private readonly NodeWrapper _parentNode;
            private readonly NtfsReader _reader;
            private readonly int _streamIndex;
            private IList<IFragment>? _fragmentView;

            public StreamWrapper(NtfsReader reader, NodeWrapper parentNode, int streamIndex)
            {
                _reader = reader;
                _parentNode = parentNode;
                _streamIndex = streamIndex;
            }

            #region IStream Members

            public int FragmentCount =>
                _reader._streams![_parentNode.NodeIndex][_streamIndex].Fragments.Count;

            public IList<IFragment>? Fragments {
                get {
                    if (_fragmentView != null)
                    {
                        return _fragmentView;
                    }

                    IList<Fragment> fragments =
                        _reader._streams![_parentNode.NodeIndex][_streamIndex].Fragments;

                    if (fragments == null || fragments.Count == 0)
                    {
                        return null;
                    }

                    var newFragments = new IFragment[fragments.Count];
                    for (var i = 0; i < fragments.Count; i++)
                    {
                        newFragments[i] = new FragmentWrapper(this, fragments[i]);
                    }

                    var view = Array.AsReadOnly(newFragments);
                    Interlocked.CompareExchange(ref _fragmentView, view, null);
                    return _fragmentView;
                }
            }

            public string? Name => _reader.GetNameFromIndex(_reader._streams![_parentNode.NodeIndex][_streamIndex].NameIndex);

            public ulong Size => _reader._streams![_parentNode.NodeIndex][_streamIndex].Size;

            #endregion IStream Members
        }

        #endregion Private Classes

        #region Constants

        private const long DEFAULT_NTFS_BOOT_SIGNATURE = 0x202020205346544E;
        private const uint END_MARKER = 0xFFFFFFFF;
        private const uint ROOT_DIRECTORY = 5;
        private const ulong VIRTUAL_FRAGMENT = 18446744073709551615; // _UI64_MAX - 1 */
        #endregion Constants

        private readonly DriveInfo _driveInfo;

        // This index only lives while the MFT is being read. Do not eagerly reserve a
        // large table: that made even small-volume scans allocate arrays for 131,072
        // entries. The dictionary grows with the actual number of distinct names.
        private readonly Dictionary<string, int>? _nameIndex = new(StringComparer.Ordinal);

        private readonly List<string> _names = [];
        private readonly Node[] _nodes;
        private readonly RetrieveMode _retrieveMode;
        private byte[]? _bitmapData;
        private readonly DiskInfoWrapper _diskInfo;
        private StandardInformation[]? _standardInformations;
        private Stream[][]? _streams;
        private SafeFileHandle? _volumeHandle;
        private string?[] _fullPathCache = [];
        private readonly object _fullPathCacheLock = new();
        private uint[] _childOffsets = [];
        private uint[] _children = [];
        private Dictionary<ChildKey, uint> _childLookup = [];

        #region Events

        /// <summary>
        /// Raised once the bitmap data has been read.
        /// </summary>
        public event EventHandler? BitmapDataAvailable;

        private void OnBitmapDataAvailable() => BitmapDataAvailable?.Invoke(this, EventArgs.Empty);

        #endregion Events

        #region Helpers

        /// <summary>
        /// Get the string from our stringtable from the given index.
        /// </summary>
        private string? GetNameFromIndex(int nameIndex) => nameIndex == 0 ? null : _names[nameIndex];

        /// <summary>
        /// Allocate or retrieve an existing index for the particular string.
        /// </summary>
        ///<remarks>
        /// In order to mimize memory usage, we reuse string as much as possible.
        ///</remarks>
        private int GetNameIndex(ReadOnlySpan<char> name)
        {
            // NTFS names already reside in the current MFT record buffer. Use the
            // dictionary's span-based alternate lookup so repeated names can be
            // found without first allocating a temporary string that immediately
            // becomes garbage.
            var lookup = _nameIndex!.GetAlternateLookup<ReadOnlySpan<char>>();
            if (lookup.TryGetValue(name, out var existingIndex))
            {
                return existingIndex;
            }

            var retainedName = new string(name);
            _names.Add(retainedName);
            _nameIndex[retainedName] = _names.Count - 1;

            return _names.Count - 1;
        }

        private Stream? SearchStream(List<Stream> streams, AttributeType streamType)
        {
            //since the number of stream is usually small, we can afford O(n)
            foreach (var stream in streams)
            {
                if (stream.Type == streamType)
                {
                    return stream;
                }
            }

            return null;
        }

        private Stream? SearchStream(List<Stream> streams, AttributeType streamType, int streamNameIndex)
        {
            //since the number of stream is usually small, we can afford O(n)
            foreach (var stream in streams)
            {
                if (stream.Type == streamType &&
                    stream.NameIndex == streamNameIndex)
                {
                    return stream;
                }
            }

            return null;
        }

        #endregion Helpers

        #region File Reading Wrappers

        private unsafe void ReadFile(byte* buffer, int len, ulong absolutePosition) => ReadFile(buffer, (ulong)len, absolutePosition);

        private unsafe void ReadFile(byte* buffer, uint len, ulong absolutePosition) => ReadFile(buffer, (ulong)len, absolutePosition);

        private unsafe void ReadFile(byte* buffer, ulong len, ulong absolutePosition)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            if (len > uint.MaxValue)
            {
                throw new NtfsException("A single raw-volume read cannot exceed UInt32.MaxValue bytes.");
            }

            var bytesToRead = checked((uint)len);
            var overlapped = new NativeOverlapped(absolutePosition);

            if (!ReadFile(_volumeHandle!, (IntPtr)buffer, bytesToRead, out var read, ref overlapped))
            {
                throw new NtfsException("Unable to read volume information");
            }

            if (read != bytesToRead)
            {
                throw new NtfsException("Unable to read the requested volume data.");
            }
        }

        #endregion File Reading Wrappers

        #region Ntfs Interpretor

        /// <summary>
        /// Decode the unsigned RunLength value.
        /// </summary>
        internal static ulong ProcessRunLength(ReadOnlySpan<byte> runData, int runLengthSize, ref int index)
        {
            if ((uint)(runLengthSize - 1) >= sizeof(ulong))
            {
                throw new NtfsException("The data-run length width is invalid.");
            }

            var encodedLength = SliceChecked(runData, index, runLengthSize, "The data-run length");
            index += runLengthSize;

            ulong runLength = 0;
            for (var i = 0; i < encodedLength.Length; i++)
            {
                runLength |= (ulong)encodedLength[i] << (i * 8);
            }

            if (runLength == 0)
            {
                throw new NtfsException("A non-terminal data run cannot have a zero length.");
            }

            return runLength;
        }

        /// <summary>
        /// Decode the signed RunOffset value. A zero-width offset represents a sparse run.
        /// </summary>
        internal static long ProcessRunOffset(ReadOnlySpan<byte> runData, int runOffsetSize, ref int index)
        {
            if (runOffsetSize == 0)
            {
                return 0;
            }

            if (runOffsetSize > sizeof(long))
            {
                throw new NtfsException("The data-run offset width is invalid.");
            }

            var encodedOffset = SliceChecked(runData, index, runOffsetSize, "The data-run offset");
            index += runOffsetSize;

            long runOffset = 0;
            for (var i = 0; i < encodedOffset.Length; i++)
            {
                runOffset |= (long)encodedOffset[i] << (i * 8);
            }

            if (runOffsetSize < sizeof(long) && (encodedOffset[^1] & 0x80) != 0)
            {
                runOffset |= -1L << (runOffsetSize * 8);
            }

            return runOffset;
        }

        /// <summary>
        /// Validate and apply the NTFS update sequence array before interpreting an MFT record.
        /// </summary>
        private void FixupRawMftdata(Span<byte> buffer) => FixupRawMftdata(buffer, _diskInfo.BytesPerSector);

        internal static void FixupRawMftdata(Span<byte> buffer, ushort bytesPerSector)
        {
            var fileRecordHeader = ReadStruct<FileRecordHeader>(buffer, "The MFT record header");
            if (fileRecordHeader.RecordHeader.Type != RecordType.File)
            {
                return;
            }

            if (bytesPerSector < sizeof(ushort) || bytesPerSector % sizeof(ushort) != 0)
            {
                throw new NtfsException("The NTFS bytes-per-sector value is invalid.");
            }

            if (buffer.Length % bytesPerSector != 0)
            {
                throw new NtfsException("The MFT record does not contain complete sectors.");
            }

            var sectorCount = buffer.Length / bytesPerSector;
            var usaCount = fileRecordHeader.RecordHeader.UsaCount;
            if (usaCount != sectorCount + 1)
            {
                throw new NtfsException("The MFT update sequence array count does not match the record sector count.");
            }

            var usaByteLength = checked(usaCount * sizeof(ushort));
            var usa = SliceChecked(buffer, fileRecordHeader.RecordHeader.UsaOffset, usaByteLength, "The MFT update sequence array");
            var updateSequenceNumber = ReadUInt16LittleEndian(usa, 0, "The MFT update sequence number");

            for (var sectorIndex = 1; sectorIndex <= sectorCount; sectorIndex++)
            {
                var sectorTrailerOffset = checked((sectorIndex * bytesPerSector) - sizeof(ushort));
                if (ReadUInt16LittleEndian(buffer, sectorTrailerOffset, "An MFT sector trailer") != updateSequenceNumber)
                {
                    throw new NtfsException("USA fixup word is not equal to the Update Sequence Number, the MFT may be corrupt.");
                }

                WriteUInt16LittleEndian(
                    buffer,
                    sectorTrailerOffset,
                    ReadUInt16LittleEndian(usa, sectorIndex * sizeof(ushort), "An MFT update sequence array entry"),
                    "An MFT sector trailer"
                );
            }
        }

        /// <summary>
        /// Gather basic disk information we need to interpret data
        /// </summary>
        private unsafe DiskInfoWrapper InitializeDiskInfo()
        {
            var volumeData = new byte[512];
            fixed (byte* ptr = volumeData)
            {
                ReadFile(ptr, volumeData.Length, 0);
            }

            var bootSector = ReadStruct<BootSector>(volumeData, "The NTFS boot sector");
            if (bootSector.Signature != DEFAULT_NTFS_BOOT_SIGNATURE)
            {
                throw new NtfsException("This is not an NTFS disk.");
            }

            if (bootSector.BytesPerSector < 512 ||
                !BitOperations.IsPow2(bootSector.BytesPerSector) ||
                bootSector.SectorsPerCluster == 0 ||
                !BitOperations.IsPow2(bootSector.SectorsPerCluster) ||
                bootSector.TotalSectors == 0)
            {
                throw new NtfsException("The NTFS boot sector contains invalid geometry.");
            }

            var diskInfo = new DiskInfoWrapper
            {
                BytesPerSector = bootSector.BytesPerSector,
                SectorsPerCluster = bootSector.SectorsPerCluster,
                TotalSectors = bootSector.TotalSectors,
                MftStartLcn = bootSector.MftStartLcn,
                Mft2StartLcn = bootSector.Mft2StartLcn,
                ClustersPerMftRecord = bootSector.ClustersPerMftRecord,
                ClustersPerIndexRecord = bootSector.ClustersPerIndexRecord
            };

            diskInfo.BytesPerCluster = CheckedMultiply(
                diskInfo.BytesPerSector,
                diskInfo.SectorsPerCluster,
                "The bytes-per-cluster value"
            );

            if (bootSector.ClustersPerMftRecord >= 128)
            {
                diskInfo.BytesPerMftRecord = 1UL << (256 - (byte)bootSector.ClustersPerMftRecord);
            }
            else
            {
                diskInfo.BytesPerMftRecord = CheckedMultiply(
                    diskInfo.ClustersPerMftRecord,
                    diskInfo.BytesPerCluster,
                    "The bytes-per-MFT-record value"
                );
            }

            if (diskInfo.BytesPerMftRecord < (ulong)Unsafe.SizeOf<FileRecordHeader>() ||
                diskInfo.BytesPerMftRecord > MaximumMftRecordSize ||
                diskInfo.BytesPerMftRecord % diskInfo.BytesPerSector != 0)
            {
                throw new NtfsException("The NTFS MFT record size is invalid.");
            }

            diskInfo.TotalClusters = diskInfo.TotalSectors / diskInfo.SectorsPerCluster;
            if (diskInfo.MftStartLcn >= diskInfo.TotalClusters)
            {
                throw new NtfsException("The MFT start cluster lies outside the NTFS volume.");
            }

            return diskInfo;
        }

        /// <summary>
        /// Process validated attributes from a single MFT record.
        /// </summary>
        private void ProcessAttributes(
            ref Node node,
            uint nodeIndex,
            ReadOnlySpan<byte> attributes,
            ushort instance,
            List<Stream>? streams,
            bool isMftNode,
            List<AttributeListReference>? attributeListReferences = null,
            AttributeType? expectedType = null)
        {
            var attributeOffset = 0;
            while (attributeOffset < attributes.Length)
            {
                var remaining = attributes[attributeOffset..];
                if (remaining.Length < sizeof(uint))
                {
                    throw new NtfsException("An MFT attribute is truncated before its type marker.");
                }

                if (ReadUInt32LittleEndian(remaining, 0, "The MFT attribute type") == END_MARKER)
                {
                    return;
                }

                var attribute = ReadStruct<Attribute>(remaining, "The MFT attribute header");
                if (attribute.Length < AttributeHeaderSize)
                {
                    throw new NtfsException("An MFT attribute has an invalid length.");
                }

                var attributeLength = CheckedByteLength(attribute.Length, "The MFT attribute length");
                var attributeData = SliceChecked(remaining, 0, attributeLength, "The MFT attribute");
                attributeOffset = checked(attributeOffset + attributeLength);

                if (attribute.Nonresident is not 0 and not 1)
                {
                    throw new NtfsException("An MFT attribute has an invalid resident flag.");
                }

                var attributeNameByteLength = CheckedUtf16ByteLength(attribute.NameLength, "The MFT attribute name");
                var attributeNameBytes = attribute.NameLength == 0
                    ? ReadOnlySpan<byte>.Empty
                    : SliceChecked(attributeData, attribute.NameOffset, attributeNameByteLength, "The MFT attribute name");
                var streamNameIndex = attribute.NameLength == 0
                    ? 0
                    : GetNameIndex(MemoryMarshal.Cast<byte, char>(attributeNameBytes));

                if (attribute.AttributeType == AttributeType.AttributeAttributeList)
                {
                    if (attributeListReferences != null)
                    {
                        CollectAttributeListReferences(attributeData, attribute, attributeListReferences);
                    }

                    continue;
                }

                if (instance != ushort.MaxValue &&
                    (instance != attribute.AttributeNumber || expectedType != attribute.AttributeType))
                {
                    continue;
                }

                if (attribute.Nonresident == 0)
                {
                    ProcessResidentAttribute(
                        ref node,
                        nodeIndex,
                        attribute,
                        attributeData,
                        streamNameIndex,
                        streams,
                        isMftNode
                    );
                }
                else
                {
                    ProcessNonResidentAttribute(
                        ref node,
                        attribute,
                        attributeData,
                        streamNameIndex,
                        streams,
                        isMftNode
                    );
                }
            }

            throw new NtfsException("The MFT attribute sequence is missing its end marker.");
        }

        private void ProcessResidentAttribute(
            ref Node node,
            uint nodeIndex,
            Attribute attribute,
            ReadOnlySpan<byte> attributeData,
            int streamNameIndex,
            List<Stream>? streams,
            bool isMftNode)
        {
            var residentAttribute = ReadStruct<ResidentAttribute>(attributeData, "The resident MFT attribute header");
            var valueLength = CheckedByteLength(residentAttribute.ValueLength, "The resident MFT attribute value length");
            var value = SliceChecked(attributeData, residentAttribute.ValueOffset, valueLength, "The resident MFT attribute value");

            switch (attribute.AttributeType)
            {
                case AttributeType.AttributeFileName:
                    ProcessFileNameAttribute(ref node, value);
                    break;

                case AttributeType.AttributeStandardInformation:
                    ProcessStandardInformationAttribute(ref node, nodeIndex, value);
                    break;

                case AttributeType.AttributeData:
                    if (streamNameIndex == 0)
                    {
                        node.Size = residentAttribute.ValueLength;
                    }

                    if (streams != null && (isMftNode || attribute.AttributeType == AttributeType.AttributeData))
                    {
                        _ = GetOrCreateStream(streams, attribute.AttributeType, streamNameIndex, residentAttribute.ValueLength);
                    }

                    break;
            }
        }

        private void ProcessNonResidentAttribute(
            ref Node node,
            Attribute attribute,
            ReadOnlySpan<byte> attributeData,
            int streamNameIndex,
            List<Stream>? streams,
            bool isMftNode)
        {
            if (attributeData.Length < NonResidentAttributeMinimumSize)
            {
                throw new NtfsException("The non-resident MFT attribute header is truncated.");
            }

            var nonResidentAttribute = ReadStruct<NonResidentAttribute>(attributeData, "The non-resident MFT attribute header");
            if (nonResidentAttribute.LastVcn < nonResidentAttribute.StartingVcn)
            {
                throw new NtfsException("The non-resident MFT attribute has an invalid VCN range.");
            }

            var runData = SliceChecked(
                attributeData,
                nonResidentAttribute.RunArrayOffset,
                attributeData.Length - nonResidentAttribute.RunArrayOffset,
                "The non-resident MFT data-run array"
            );

            if (attribute.AttributeType == AttributeType.AttributeData && streamNameIndex == 0)
            {
                node.Size = nonResidentAttribute.DataSize;
            }

            if (streams == null || (!isMftNode && attribute.AttributeType != AttributeType.AttributeData))
            {
                return;
            }

            var stream = GetOrCreateStream(
                streams,
                attribute.AttributeType,
                streamNameIndex,
                nonResidentAttribute.DataSize
            );

            if (isMftNode || (_retrieveMode & RetrieveMode.Fragments) == RetrieveMode.Fragments)
            {
                ProcessFragments(stream, runData, nonResidentAttribute.StartingVcn);
            }
        }

        private void ProcessFileNameAttribute(ref Node node, ReadOnlySpan<byte> value)
        {
            SliceChecked(value, 0, FileNameFixedValueSize, "The $FILE_NAME value");
            var parentNodeIndex = ReadUInt48LittleEndian(value, "The $FILE_NAME parent reference");
            if (parentNodeIndex > uint.MaxValue)
            {
                throw new NotSupportedException("48-bit MFT references are not supported by the current node model.");
            }

            var nameLength = value[64];
            var nameByteLength = CheckedUtf16ByteLength(nameLength, "The $FILE_NAME value");
            var nameBytes = SliceChecked(value, FileNameFixedValueSize, nameByteLength, "The $FILE_NAME name");

            node.ParentNodeIndex = checked((uint)parentNodeIndex);
            if (value[65] == 1 || node.NameIndex == 0)
            {
                node.NameIndex = GetNameIndex(MemoryMarshal.Cast<byte, char>(nameBytes));
            }
        }

        private void ProcessStandardInformationAttribute(ref Node node, uint nodeIndex, ReadOnlySpan<byte> value)
        {
            SliceChecked(value, 0, 36, "The $STANDARD_INFORMATION value");
            node.Attributes |= (Attributes)ReadUInt32LittleEndian(value, 32, "The $STANDARD_INFORMATION file attributes");

            if ((_retrieveMode & RetrieveMode.StandardInformations) == RetrieveMode.StandardInformations)
            {
                _standardInformations![nodeIndex] = new StandardInformation(
                    ReadUInt64LittleEndian(value, 0, "The $STANDARD_INFORMATION creation time"),
                    ReadUInt64LittleEndian(value, 24, "The $STANDARD_INFORMATION last access time"),
                    ReadUInt64LittleEndian(value, 8, "The $STANDARD_INFORMATION last change time")
                );
            }
        }

        private static Stream GetOrCreateStream(
            List<Stream> streams,
            AttributeType streamType,
            int streamNameIndex,
            ulong size)
        {
            var stream = streams.Find(existing =>
                existing.Type == streamType && existing.NameIndex == streamNameIndex
            );

            if (stream == null)
            {
                stream = new Stream(streamNameIndex, streamType, size);
                streams.Add(stream);
            }
            else if (stream.Size == 0)
            {
                stream.Size = size;
            }

            return stream;
        }

        /// <summary>
        /// Process the bitmap data that contains information on inode usage.
        /// </summary>
        private unsafe byte[] ProcessBitmapData(List<Stream> streams)
        {
            ulong Vcn = 0;
            ulong MaxMftBitmapBytes = 0;

            var bitmapStream = SearchStream(streams, AttributeType.AttributeBitmap) ?? throw new NtfsException("No Bitmap Data");
            foreach (var fragment in bitmapStream.Fragments)
            {
                if (fragment.Lcn != VIRTUAL_FRAGMENT)
                {
                    MaxMftBitmapBytes += (fragment.NextVcn - Vcn) * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster;
                }

                Vcn = fragment.NextVcn;
            }

            var bitmapData = new byte[MaxMftBitmapBytes];

            fixed (byte* bitmapDataPtr = bitmapData)
            {
                Vcn = 0;
                ulong RealVcn = 0;

                foreach (var fragment in bitmapStream.Fragments)
                {
                    if (fragment.Lcn != VIRTUAL_FRAGMENT)
                    {
                        ReadFile(
                            bitmapDataPtr + (RealVcn * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster),
                            (fragment.NextVcn - Vcn) * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster,
                            fragment.Lcn * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster
                            );

                        RealVcn = RealVcn + fragment.NextVcn - Vcn;
                    }

                    Vcn = fragment.NextVcn;
                }
            }

            return bitmapData;
        }

        /// <summary>
        /// Process validated data runs and record their physical or sparse fragments.
        /// </summary>
        private static void ProcessFragments(
            Stream stream,
            ReadOnlySpan<byte> runData,
            ulong startingVcn)
        {
            var index = 0;
            var lcn = 0L;
            var vcn = startingVcn;
            var sawTerminator = false;

            while (index < runData.Length)
            {
                var header = runData[index++];
                if (header == 0)
                {
                    sawTerminator = true;
                    break;
                }

                var runLengthSize = header & 0x0F;
                var runOffsetSize = header >> 4;
                var runLength = ProcessRunLength(runData, runLengthSize, ref index);
                var runOffset = ProcessRunOffset(runData, runOffsetSize, ref index);

                try
                {
                    vcn = checked(vcn + runLength);
                    if (runOffset != 0)
                    {
                        lcn = checked(lcn + runOffset);
                        if (lcn < 0)
                        {
                            throw new NtfsException("A data-run resolves to a negative logical cluster number.");
                        }

                        stream.Clusters = checked(stream.Clusters + runLength);
                    }
                }
                catch (OverflowException exception)
                {
                    throw new NtfsException("A data-run exceeds the supported NTFS address range.", exception);
                }

                stream.Fragments.Add(new Fragment(
                    runOffset == 0 ? VIRTUAL_FRAGMENT : checked((ulong)lcn),
                    vcn
                ));
            }

            if (!sawTerminator)
            {
                throw new NtfsException("The data-run array is not terminated within the attribute.");
            }
        }

        /// <summary>
        /// Begin the process of interpreting MFT data
        /// </summary>
        private unsafe Node[] ProcessMft()
        {
            // 64 KB was optimal for Windows XP; newer systems are happier with 256 KB.
            var bufferSize = (Environment.OSVersion.Version.Major >= 6 ? 256u : 64u) * 1024;
            var recordLength = CheckedByteLength(_diskInfo.BytesPerMftRecord, "The MFT record size");
            if (recordLength > bufferSize)
            {
                throw new NtfsException("The MFT record is larger than the scan buffer.");
            }

            var data = new byte[bufferSize];
            fixed (byte* buffer = data)
            {
                // Read the $MFT record, which is always the first MFT record.
                ReadFile(
                    buffer,
                    _diskInfo.BytesPerMftRecord,
                    CheckedMultiply(_diskInfo.MftStartLcn, _diskInfo.BytesPerCluster, "The MFT byte offset")
                );

                var mftRecord = data.AsSpan(0, recordLength);
                FixupRawMftdata(mftRecord);

                var mftStreams = new List<Stream>();
                if ((_retrieveMode & RetrieveMode.StandardInformations) == RetrieveMode.StandardInformations)
                {
                    _standardInformations = new StandardInformation[1];
                }

                if (!ProcessMftRecord(mftRecord, 0, out var mftNode, mftStreams, true, out var mftAttributeListReferences))
                {
                    throw new NtfsException("Cannot interpret the $MFT record.");
                }

                var dataStream = SearchStream(mftStreams, AttributeType.AttributeData) ??
                    throw new NtfsException("The $MFT data stream is missing.");
                ResolveAttributeListReferences(
                    ref mftNode,
                    0,
                    mftAttributeListReferences,
                    mftStreams,
                    true,
                    dataStream
                );

                _bitmapData = ProcessBitmapData(mftStreams);
                OnBitmapDataAvailable();
                var maxInode = checked((uint)_bitmapData.Length * 8);
                var recordCount = dataStream.Size / _diskInfo.BytesPerMftRecord;
                if (recordCount > uint.MaxValue)
                {
                    throw new NtfsException("The MFT contains more records than this reader can index.");
                }

                if (maxInode > (uint)recordCount)
                {
                    maxInode = (uint)recordCount;
                }

                if (maxInode == 0)
                {
                    throw new NtfsException("The MFT does not contain its required first record.");
                }

                var nodes = new Node[maxInode];
                nodes[0] = mftNode;

                if ((_retrieveMode & RetrieveMode.StandardInformations) == RetrieveMode.StandardInformations)
                {
                    var mftRecordInformation = _standardInformations![0];
                    _standardInformations = new StandardInformation[maxInode];
                    _standardInformations[0] = mftRecordInformation;
                }

                if ((_retrieveMode & RetrieveMode.Streams) == RetrieveMode.Streams)
                {
                    _streams = new Stream[maxInode][];
                }

                ulong blockStart = 0;
                ulong blockEnd = 0;
                var readCursor = new MftReadCursor();
                var stopwatch = Stopwatch.StartNew();
                ulong totalBytesRead = 0;

                foreach (var nodeIndex in EnumerateOccupiedNodes(_bitmapData, maxInode))
                {
                    if (nodeIndex == 0)
                    {
                        continue;
                    }

                    if (nodeIndex >= blockEnd)
                    {
                        if (!ReadNextChunk(
                                buffer,
                                bufferSize,
                                nodeIndex,
                                dataStream,
                                ref blockStart,
                                ref blockEnd,
                                ref readCursor))
                        {
                            break;
                        }

                        totalBytesRead = CheckedAdd(
                            totalBytesRead,
                            CheckedMultiply(blockEnd - blockStart, _diskInfo.BytesPerMftRecord, "The MFT chunk length"),
                            "The total MFT bytes read"
                        );
                    }

                    var recordOffset = CheckedByteLength(
                        CheckedMultiply(nodeIndex - blockStart, _diskInfo.BytesPerMftRecord, "The MFT record buffer offset"),
                        "The MFT record buffer offset"
                    );
                    var record = data.AsSpan(recordOffset, recordLength);
                    FixupRawMftdata(record);

                    List<Stream>? streams = null;
                    if ((_retrieveMode & RetrieveMode.Streams) == RetrieveMode.Streams)
                    {
                        streams = [];
                    }

                    if (!ProcessMftRecord(record, nodeIndex, out var newNode, streams, false, out var attributeListReferences))
                    {
                        continue;
                    }

                    ResolveAttributeListReferences(
                        ref newNode,
                        nodeIndex,
                        attributeListReferences,
                        streams,
                        false,
                        dataStream
                    );
                    nodes[nodeIndex] = newNode;
                    if (streams != null)
                    {
                        _streams![nodeIndex] = streams.ToArray();
                    }
                }

                stopwatch.Stop();
                if (stopwatch.Elapsed.TotalSeconds > 0)
                {
                    Trace.WriteLine(
                        $"{totalBytesRead / (1024d * 1024):F3} MB of volume metadata has been read in " +
                        $"{stopwatch.Elapsed.TotalSeconds:F3} s at " +
                        $"{totalBytesRead / (1024d * 1024) / stopwatch.Elapsed.TotalSeconds:F3} MB/s"
                    );
                }

                return nodes;
            }
        }

        /// <summary>
        /// Process an actual MFT record from a bounded, already-fixup-applied buffer.
        /// </summary>
        private bool ProcessMftRecord(
            ReadOnlySpan<byte> record,
            uint nodeIndex,
            out Node node,
            List<Stream>? streams,
            bool isMftNode,
            out List<AttributeListReference> attributeListReferences)
        {
            node = default;
            attributeListReferences = [];
            var fileRecordHeader = ReadStruct<FileRecordHeader>(record, "The MFT record header");
            if (fileRecordHeader.RecordHeader.Type != RecordType.File || (fileRecordHeader.Flags & 1) == 0)
            {
                return false;
            }

            var baseInode = ((ulong)fileRecordHeader.BaseFileRecord.InodeNumberHighPart << 32) +
                fileRecordHeader.BaseFileRecord.InodeNumberLowPart;
            if (baseInode != 0)
            {
                return false;
            }

            if (fileRecordHeader.BytesInUse < Unsafe.SizeOf<FileRecordHeader>() ||
                fileRecordHeader.BytesInUse > record.Length ||
                fileRecordHeader.AttributeOffset >= fileRecordHeader.BytesInUse)
            {
                throw new NtfsException("The MFT record declares an invalid attribute area.");
            }

            node.ParentNodeIndex = ROOT_DIRECTORY;
            if ((fileRecordHeader.Flags & 2) != 0)
            {
                node.Attributes |= Attributes.Directory;
            }

            var attributes = SliceChecked(
                record,
                fileRecordHeader.AttributeOffset,
                checked((int)fileRecordHeader.BytesInUse - fileRecordHeader.AttributeOffset),
                "The MFT attribute area"
            );
            ProcessAttributes(
                ref node,
                nodeIndex,
                attributes,
                ushort.MaxValue,
                streams,
                isMftNode,
                attributeListReferences
            );
            return true;
        }

        /// <summary>
        /// Read non-resident data described by a validated data-run array. Sparse regions are retained as zero-filled bytes.
        /// </summary>
        private unsafe byte[] ProcessNonResidentData(
            ReadOnlySpan<byte> runData,
            ulong offset,
            ulong wantedLength)
        {
            if (runData.IsEmpty)
            {
                throw new NtfsException("The non-resident data-run array is empty.");
            }

            if (wantedLength == 0)
            {
                return [];
            }

            var bytesPerSector = (ulong)_diskInfo.BytesPerSector;
            var roundedLength = CheckedAdd(
                wantedLength,
                (bytesPerSector - (wantedLength % bytesPerSector)) % bytesPerSector,
                "The rounded non-resident read length"
            );
            var buffer = new byte[CheckedByteLength(roundedLength, "The non-resident read length")];
            var requestedEnd = CheckedAdd(offset, roundedLength, "The non-resident read range");
            var bytesPerCluster = _diskInfo.BytesPerCluster;
            var index = 0;
            var lcn = 0L;
            ulong vcn = 0;
            var sawTerminator = false;

            fixed (byte* bufferPointer = buffer)
            {
                while (index < runData.Length)
                {
                    var header = runData[index++];
                    if (header == 0)
                    {
                        sawTerminator = true;
                        break;
                    }

                    var runLength = ProcessRunLength(runData, header & 0x0F, ref index);
                    var runOffset = ProcessRunOffset(runData, header >> 4, ref index);
                    var extentOffset = CheckedMultiply(vcn, bytesPerCluster, "The non-resident extent offset");
                    var extentLength = CheckedMultiply(runLength, bytesPerCluster, "The non-resident extent length");
                    var extentEnd = CheckedAdd(extentOffset, extentLength, "The non-resident extent end");
                    vcn = checked(vcn + runLength);

                    if (runOffset != 0)
                    {
                        try
                        {
                            lcn = checked(lcn + runOffset);
                        }
                        catch (OverflowException exception)
                        {
                            throw new NtfsException("A non-resident data run exceeds the supported address range.", exception);
                        }

                        if (lcn < 0)
                        {
                            throw new NtfsException("A non-resident data run resolves to a negative logical cluster number.");
                        }
                    }

                    if (runOffset == 0 || offset >= extentEnd || requestedEnd <= extentOffset)
                    {
                        continue;
                    }

                    var readStart = Math.Max(offset, extentOffset);
                    var readEnd = Math.Min(requestedEnd, extentEnd);
                    var length = readEnd - readStart;
                    var logicalClusterOffset = CheckedMultiply(checked((ulong)lcn), bytesPerCluster, "The non-resident logical cluster offset");
                    var physicalOffset = CheckedAdd(
                        logicalClusterOffset,
                        readStart - extentOffset,
                        "The non-resident physical read offset"
                    );
                    var destinationOffset = CheckedByteLength(readStart - offset, "The non-resident buffer offset");
                    ReadFile(bufferPointer + destinationOffset, length, physicalOffset);
                }
            }

            if (!sawTerminator)
            {
                throw new NtfsException("The non-resident data-run array is not terminated.");
            }

            return buffer;
        }

        /// <summary>
        /// Read the next contiguous block of information on disk
        /// </summary>
        private unsafe bool ReadNextChunk(
            byte* buffer,
            uint bufferSize,
            uint nodeIndex,
            Stream dataStream,
            ref ulong BlockStart,
            ref ulong BlockEnd,
            ref MftReadCursor cursor
            )
        {
            BlockStart = nodeIndex;
            BlockEnd = BlockStart + (bufferSize / _diskInfo.BytesPerMftRecord);
            if (BlockEnd > dataStream.Size * 8)
            {
                BlockEnd = dataStream.Size * 8;
            }

            ulong u1 = 0;

            var fragmentCount = dataStream.Fragments.Count;
            while (cursor.FragmentIndex < fragmentCount)
            {
                var fragment = dataStream.Fragments[cursor.FragmentIndex];

                /* Calculate Inode at the end of the fragment. */
                u1 = (cursor.RealVcn + (fragment.Lcn == VIRTUAL_FRAGMENT ? 0 : fragment.NextVcn - cursor.Vcn)) *
                    _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster / _diskInfo.BytesPerMftRecord;

                if (u1 > nodeIndex)
                {
                    break;
                }

                while (cursor.FragmentIndex < fragmentCount && u1 <= nodeIndex)
                {
                    fragment = dataStream.Fragments[cursor.FragmentIndex];
                    if (fragment.Lcn != VIRTUAL_FRAGMENT)
                    {
                        cursor.RealVcn += fragment.NextVcn - cursor.Vcn;
                    }

                    cursor.Vcn = fragment.NextVcn;
                    cursor.FragmentIndex++;

                    if (cursor.FragmentIndex >= fragmentCount)
                    {
                        break;
                    }

                    fragment = dataStream.Fragments[cursor.FragmentIndex];
                    u1 = (cursor.RealVcn + (fragment.Lcn == VIRTUAL_FRAGMENT ? 0 : fragment.NextVcn - cursor.Vcn)) *
                        _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster / _diskInfo.BytesPerMftRecord;
                }
            }

            if (cursor.FragmentIndex >= fragmentCount)
            {
                return false;
            }

            if (BlockEnd >= u1)
            {
                BlockEnd = u1;
            }

            var position =
                ((dataStream.Fragments[cursor.FragmentIndex].Lcn - cursor.RealVcn) * _diskInfo.BytesPerSector *
                    _diskInfo.SectorsPerCluster) + (BlockStart * _diskInfo.BytesPerMftRecord);

            ReadFile(buffer, (BlockEnd - BlockStart) * _diskInfo.BytesPerMftRecord, position);

            return true;
        }

        private static IEnumerable<uint> EnumerateOccupiedNodes(byte[] bitmap, uint maxInode)
        {
            for (var byteIndex = 0; byteIndex < bitmap.Length; byteIndex++)
            {
                var occupied = (uint)bitmap[byteIndex];
                while (occupied != 0)
                {
                    var nodeIndex = ((uint)byteIndex << 3) + (uint)BitOperations.TrailingZeroCount(occupied);
                    if (nodeIndex >= maxInode)
                    {
                        yield break;
                    }

                    yield return nodeIndex;
                    occupied &= occupied - 1;
                }
            }
        }

        #endregion Ntfs Interpretor
    }
}
