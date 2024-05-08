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
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;

namespace System.IO.Filesystem.Ntfs
{
    public sealed partial class NtfsReader : IDisposable
    {
        #region Ntfs Structures

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

        private enum RecordType : uint
        {
            File = 0x454c4946,  //'FILE' in ASCII
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct RecordHeader
        {
            public RecordType Type;                  /* File type, for example 'FILE' */
            public ushort UsaOffset;             /* Offset to the Update Sequence Array */
            public ushort UsaCount;              /* Size in words of Update Sequence Array */
            public ulong Lsn;                   /* $LogFile Sequence Number (LSN) */
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct INodeReference
        {
            public uint InodeNumberLowPart;
            public ushort InodeNumberHighPart;
            public ushort SequenceNumber;
        };

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
        private struct ResidentAttribute
        {
            public Attribute Attribute;
            public uint ValueLength;
            public ushort ValueOffset;
            public ushort Flags;               // 0x0001 = Indexed
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

        #endregion

        #region Private Classes

        private sealed class Stream
        {
            public ulong Clusters;                      // Total number of clusters.
            public ulong Size;                          // Total number of bytes.
            public AttributeType Type;
            public int NameIndex;
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
        /// Node struct for file and directory entries
        /// </summary>
        /// <remarks>
        /// We keep this as small as possible to reduce footprint for large volume.
        /// </remarks>
        private struct Node
        {
            public Attributes Attributes;
            public uint ParentNodeIndex;
            public ulong Size;
            public int NameIndex;
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

            #endregion
        }

        /// <summary>
        /// Add some functionality to the basic stream
        /// </summary>
        private sealed class StreamWrapper : IStream
        {
            private readonly NtfsReader _reader;
            private readonly NodeWrapper _parentNode;
            private readonly int _streamIndex;

            public StreamWrapper(NtfsReader reader, NodeWrapper parentNode, int streamIndex)
            {
                _reader = reader;
                _parentNode = parentNode;
                _streamIndex = streamIndex;
            }

            #region IStream Members

            public string? Name => _reader.GetNameFromIndex(_reader._streams![_parentNode.NodeIndex][_streamIndex].NameIndex);

            public ulong Size => _reader._streams![_parentNode.NodeIndex][_streamIndex].Size;

            public IList<IFragment>? Fragments {
                get {
                    IList<Fragment> fragments =
                        _reader._streams![_parentNode.NodeIndex][_streamIndex].Fragments;

                    if (fragments == null || fragments.Count == 0)
                    {
                        return null;
                    }

                    var newFragments = new List<IFragment>();
                    foreach (var fragment in fragments)
                    {
                        newFragments.Add(new FragmentWrapper(this, fragment));
                    }

                    return newFragments;
                }
            }

            #endregion
        }

        /// <summary>
        /// Add some functionality to the basic node
        /// </summary>
        private sealed class NodeWrapper : INode
        {
            private readonly NtfsReader _reader;
            private Node _node;
            private string? _fullName;

            public NodeWrapper(NtfsReader reader, uint nodeIndex, Node node)
            {
                _reader = reader;
                NodeIndex = nodeIndex;
                _node = node;
            }

            public uint NodeIndex { get; }

            public uint ParentNodeIndex => _node.ParentNodeIndex;

            public Attributes Attributes => _node.Attributes;

            public string? Name => _reader.GetNameFromIndex(_node.NameIndex);

            public ulong Size => _node.Size;

            public string FullName {
                get {
                    _fullName ??= _reader.GetNodeFullNameCore(NodeIndex);

                    return _fullName;
                }
            }

            public IList<IStream>? Streams {
                get {
                    if (_reader._streams == null)
                    {
                        throw new NotSupportedException("The streams haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    var streams = _reader._streams[NodeIndex];
                    if (streams == null)
                    {
                        return null;
                    }

                    var newStreams = new List<IStream>();
                    for (var i = 0; i < streams.Length; ++i)
                    {
                        newStreams.Add(new StreamWrapper(_reader, this, i));
                    }

                    return newStreams;
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

            public DateTime LastChangeTime {
                get {
                    if (_reader._standardInformations == null)
                    {
                        throw new NotSupportedException("The StandardInformation haven't been retrieved. Make sure to use the proper RetrieveMode.");
                    }

                    return DateTime.FromFileTimeUtc((long)_reader._standardInformations[NodeIndex].LastChangeTime);
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

            #endregion
        }

        /// <summary>
        /// Simple structure of available disk informations.
        /// </summary>
        private sealed class DiskInfoWrapper : IDiskInfo
        {
            public ushort BytesPerSector;
            public byte SectorsPerCluster;
            public ulong TotalSectors;
            public ulong MftStartLcn;
            public ulong Mft2StartLcn;
            public uint ClustersPerMftRecord;
            public uint ClustersPerIndexRecord;
            public ulong BytesPerMftRecord;
            public ulong BytesPerCluster;
            public ulong TotalClusters;

            #region IDiskInfo Members

            ushort IDiskInfo.BytesPerSector => BytesPerSector;

            byte IDiskInfo.SectorsPerCluster => SectorsPerCluster;

            ulong IDiskInfo.TotalSectors => TotalSectors;

            ulong IDiskInfo.MftStartLcn => MftStartLcn;

            ulong IDiskInfo.Mft2StartLcn => Mft2StartLcn;

            uint IDiskInfo.ClustersPerMftRecord => ClustersPerMftRecord;

            uint IDiskInfo.ClustersPerIndexRecord => ClustersPerIndexRecord;

            ulong IDiskInfo.BytesPerMftRecord => BytesPerMftRecord;

            ulong IDiskInfo.BytesPerCluster => BytesPerCluster;

            ulong IDiskInfo.TotalClusters => TotalClusters;

            #endregion
        }

        #endregion

        #region Constants

        private const ulong VIRTUAL_FRAGMENT = 18446744073709551615; // _UI64_MAX - 1 */
        private const uint ROOT_DIRECTORY = 5;
        private const long DEFAULT_NTFS_BOOT_SIGNATURE = 0x202020205346544E;
        private const uint END_MARKER = 0xFFFFFFFF;
        private readonly byte[] BitmapMasks = [1, 2, 4, 8, 16, 32, 64, 128];

        #endregion

        private SafeFileHandle? _volumeHandle;
        private DiskInfoWrapper _diskInfo;
        private readonly Node[] _nodes;
        private StandardInformation[]? _standardInformations;
        private Stream[][]? _streams;
        private readonly DriveInfo _driveInfo;
        private readonly List<string> _names = [];
        private readonly RetrieveMode _retrieveMode;
        private byte[]? _bitmapData;

        //preallocate a lot of space for the strings to avoid too much dictionary resizing
        //use ordinal comparison to improve performance
        //this will be deallocated once the MFT reading is finished
        private readonly Dictionary<string, int>? _nameIndex = new Dictionary<string, int>(128 * 1024, StringComparer.Ordinal);

        #region Events

        /// <summary>
        /// Raised once the bitmap data has been read.
        /// </summary>
        public event EventHandler? BitmapDataAvailable;

        private void OnBitmapDataAvailable() => BitmapDataAvailable?.Invoke(this, EventArgs.Empty);

        #endregion

        #region Helpers

        /// <summary>
        /// Allocate or retrieve an existing index for the particular string.
        /// </summary>
        ///<remarks>
        /// In order to mimize memory usage, we reuse string as much as possible.
        ///</remarks>
        private int GetNameIndex(string name)
        {
            if (_nameIndex!.TryGetValue(name, out var existingIndex))
            {
                return existingIndex;
            }

            _names.Add(name);
            _nameIndex[name] = _names.Count - 1;

            return _names.Count - 1;
        }

        /// <summary>
        /// Get the string from our stringtable from the given index.
        /// </summary>
        private string? GetNameFromIndex(int nameIndex) => nameIndex == 0 ? null : _names[nameIndex];

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

        #endregion

        #region File Reading Wrappers

        private unsafe void ReadFile(byte* buffer, int len, ulong absolutePosition) => ReadFile(buffer, (ulong)len, absolutePosition);

        private unsafe void ReadFile(byte* buffer, uint len, ulong absolutePosition) => ReadFile(buffer, (ulong)len, absolutePosition);

        private unsafe void ReadFile(byte* buffer, ulong len, ulong absolutePosition)
        {
            var overlapped = new NativeOverlapped(absolutePosition);

            if (!ReadFile(_volumeHandle!, (IntPtr)buffer, (uint)len, out var read, ref overlapped))
            {
                throw new NtfsException("Unable to read volume information");
            }

            if (read != (uint)len)
            {
                throw new NtfsException("Unable to read volume information");
            }
        }

        #endregion

        #region Ntfs Interpretor

        /// <summary>
        /// Read the next contiguous block of information on disk
        /// </summary>
        private unsafe bool ReadNextChunk(
            byte* buffer,
            uint bufferSize,
            uint nodeIndex,
            int fragmentIndex,
            Stream dataStream,
            ref ulong BlockStart,
            ref ulong BlockEnd,
            ref ulong Vcn,
            ref ulong RealVcn
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
            while (fragmentIndex < fragmentCount)
            {
                var fragment = dataStream.Fragments[fragmentIndex];

                /* Calculate Inode at the end of the fragment. */
                u1 = (RealVcn + fragment.NextVcn - Vcn) * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster / _diskInfo.BytesPerMftRecord;

                if (u1 > nodeIndex)
                {
                    break;
                }

                do
                {
                    if (fragment.Lcn != VIRTUAL_FRAGMENT)
                    {
                        RealVcn = RealVcn + fragment.NextVcn - Vcn;
                    }

                    Vcn = fragment.NextVcn;

                    if (++fragmentIndex >= fragmentCount)
                    {
                        break;
                    }
                } while (fragment.Lcn == VIRTUAL_FRAGMENT);
            }

            if (fragmentIndex >= fragmentCount)
            {
                return false;
            }

            if (BlockEnd >= u1)
            {
                BlockEnd = u1;
            }

            var position =
                ((dataStream.Fragments[fragmentIndex].Lcn - RealVcn) * _diskInfo.BytesPerSector *
                    _diskInfo.SectorsPerCluster) + (BlockStart * _diskInfo.BytesPerMftRecord);

            ReadFile(buffer, (BlockEnd - BlockStart) * _diskInfo.BytesPerMftRecord, position);

            return true;
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

                var bootSector = (BootSector*)ptr;

                if (bootSector->Signature != DEFAULT_NTFS_BOOT_SIGNATURE)
                {
                    throw new NtfsException("This is not an NTFS disk.");
                }

                var diskInfo = new DiskInfoWrapper
                {
                    BytesPerSector = bootSector->BytesPerSector,
                    SectorsPerCluster = bootSector->SectorsPerCluster,
                    TotalSectors = bootSector->TotalSectors,
                    MftStartLcn = bootSector->MftStartLcn,
                    Mft2StartLcn = bootSector->Mft2StartLcn,
                    ClustersPerMftRecord = bootSector->ClustersPerMftRecord,
                    ClustersPerIndexRecord = bootSector->ClustersPerIndexRecord
                };

                if (bootSector->ClustersPerMftRecord >= 128)
                {
                    diskInfo.BytesPerMftRecord = ((ulong)1 << (byte)(256 - (byte)bootSector->ClustersPerMftRecord));
                }
                else
                {
                    diskInfo.BytesPerMftRecord = diskInfo.ClustersPerMftRecord * diskInfo.BytesPerSector * diskInfo.SectorsPerCluster;
                }

                diskInfo.BytesPerCluster = diskInfo.BytesPerSector * (ulong)diskInfo.SectorsPerCluster;

                if (diskInfo.SectorsPerCluster > 0)
                {
                    diskInfo.TotalClusters = diskInfo.TotalSectors / diskInfo.SectorsPerCluster;
                }

                return diskInfo;
            }
        }

        /// <summary>
        /// Used to check/adjust data before we begin to interpret it
        /// </summary>
        private unsafe void FixupRawMftdata(byte* buffer, ulong len)
        {
            var ntfsFileRecordHeader = (FileRecordHeader*)buffer;

            if (ntfsFileRecordHeader->RecordHeader.Type != RecordType.File)
            {
                return;
            }

            var wordBuffer = (ushort*)buffer;

            var UpdateSequenceArray = (ushort*)(buffer + ntfsFileRecordHeader->RecordHeader.UsaOffset);
            var increment = (uint)_diskInfo.BytesPerSector / sizeof(ushort);

            var Index = increment - 1;

            for (var i = 1; i < ntfsFileRecordHeader->RecordHeader.UsaCount; i++)
            {
                /* Check if we are inside the buffer. */
                if (Index * sizeof(ushort) >= len)
                {
                    throw new NtfsException("USA data indicates that data is missing, the MFT may be corrupt.");
                }

                // Check if the last 2 bytes of the sector contain the Update Sequence Number.
                if (wordBuffer[Index] != UpdateSequenceArray[0])
                {
                    throw new NtfsException("USA fixup word is not equal to the Update Sequence Number, the MFT may be corrupt.");
                }

                /* Replace the last 2 bytes in the sector with the value from the Usa array. */
                wordBuffer[Index] = UpdateSequenceArray[i];
                Index += increment;
            }
        }

        /// <summary>
        /// Decode the RunLength value.
        /// </summary>
        private static unsafe long ProcessRunLength(byte* runData, uint runDataLength, int runLengthSize, ref uint index)
        {
            long runLength = 0;
            var runLengthBytes = (byte*)&runLength;
            for (var i = 0; i < runLengthSize; i++)
            {
                runLengthBytes[i] = runData[index];
                if (++index >= runDataLength)
                {
                    throw new NtfsException("Datarun is longer than buffer, the MFT may be corrupt.");
                }
            }
            return runLength;
        }

        /// <summary>
        /// Decode the RunOffset value.
        /// </summary>
        private static unsafe long ProcessRunOffset(byte* runData, uint runDataLength, int runOffsetSize, ref uint index)
        {
            long runOffset = 0;
            var runOffsetBytes = (byte*)&runOffset;

            int i;
            for (i = 0; i < runOffsetSize; i++)
            {
                runOffsetBytes[i] = runData[index];
                if (++index >= runDataLength)
                {
                    throw new NtfsException("Datarun is longer than buffer, the MFT may be corrupt.");
                }
            }

            //process negative values
            if (runOffsetBytes[i - 1] >= 0x80)
            {
                while (i < 8)
                {
                    runOffsetBytes[i++] = 0xFF;
                }
            }

            return runOffset;
        }

        /// <summary>
        /// Read the data that is specified in a RunData list from disk into memory,
        /// skipping the first Offset bytes.
        /// </summary>
        private unsafe byte[] ProcessNonResidentData(
            byte* RunData,
            uint RunDataLength,
            ulong Offset,         /* Bytes to skip from begin of data. */
            ulong WantedLength    /* Number of bytes to read. */
            )
        {
            /* Sanity check. */
            if (RunData == null || RunDataLength == 0)
            {
                throw new NtfsException("nothing to read");
            }

            if (WantedLength >= uint.MaxValue)
            {
                throw new NtfsException("too many bytes to read");
            }

            /* We have to round up the WantedLength to the nearest sector. For some
               reason or other Microsoft has decided that raw reading from disk can
               only be done by whole sector, even though ReadFile() accepts it's
               parameters in bytes. */
            if (WantedLength % _diskInfo.BytesPerSector > 0)
            {
                WantedLength += _diskInfo.BytesPerSector - (WantedLength % _diskInfo.BytesPerSector);
            }

            /* Walk through the RunData and read the requested data from disk. */
            uint Index = 0;
            long Lcn = 0;
            long Vcn = 0;

            var buffer = new byte[WantedLength];

            fixed (byte* bufPtr = buffer)
            {
                while (RunData[Index] != 0)
                {
                    /* Decode the RunData and calculate the next Lcn. */
                    var RunLengthSize = (RunData[Index] & 0x0F);
                    var RunOffsetSize = ((RunData[Index] & 0xF0) >> 4);

                    if (++Index >= RunDataLength)
                    {
                        throw new NtfsException("Error: datarun is longer than buffer, the MFT may be corrupt.");
                    }

                    var RunLength =
                        ProcessRunLength(RunData, RunDataLength, RunLengthSize, ref Index);

                    var RunOffset =
                        ProcessRunOffset(RunData, RunDataLength, RunOffsetSize, ref Index);

                    // Ignore virtual extents.
                    if (RunOffset == 0 || RunLength == 0)
                    {
                        continue;
                    }

                    Lcn += RunOffset;
                    Vcn += RunLength;

                    /* Determine how many and which bytes we want to read. If we don't need
                       any bytes from this extent then loop. */
                    var ExtentVcn = (ulong)((Vcn - RunLength) * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster);
                    var ExtentLcn = (ulong)(Lcn * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster);
                    var ExtentLength = (ulong)(RunLength * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster);

                    if (Offset >= ExtentVcn + ExtentLength)
                    {
                        continue;
                    }

                    if (Offset > ExtentVcn)
                    {
                        ExtentLcn = ExtentLcn + Offset - ExtentVcn;
                        ExtentLength -= (Offset - ExtentVcn);
                        ExtentVcn = Offset;
                    }

                    if (Offset + WantedLength <= ExtentVcn)
                    {
                        continue;
                    }

                    if (Offset + WantedLength < ExtentVcn + ExtentLength)
                    {
                        ExtentLength = Offset + WantedLength - ExtentVcn;
                    }

                    if (ExtentLength == 0)
                    {
                        continue;
                    }

                    ReadFile(bufPtr + ExtentVcn - Offset, ExtentLength, ExtentLcn);
                }
            }

            return buffer;
        }

        /// <summary>
        /// Process each attributes and gather information when necessary
        /// </summary>
        private unsafe void ProcessAttributes(ref Node node, uint nodeIndex, byte* ptr, ulong BufLength, ushort instance, int depth, List<Stream>? streams, bool isMftNode)
        {
            Attribute* attribute = null;
            for (uint AttributeOffset = 0; AttributeOffset < BufLength; AttributeOffset += attribute->Length)
            {
                attribute = (Attribute*)(ptr + AttributeOffset);

                // exit the loop if end-marker.
                if ((AttributeOffset + 4 <= BufLength) &&
                    (*(uint*)attribute == END_MARKER))
                {
                    break;
                }

                //make sure we did read the data correctly
                if ((AttributeOffset + 4 > BufLength) || attribute->Length < 3 ||
                    (AttributeOffset + attribute->Length > BufLength))
                {
                    throw new NtfsException("Error: attribute in Inode %I64u is bigger than the data, the MFT may be corrupt.");
                }

                //attributes list needs to be processed at the end
                if (attribute->AttributeType == AttributeType.AttributeAttributeList)
                {
                    continue;
                }

                /* If the Instance does not equal the AttributeNumber then ignore the attribute.
                   This is used when an AttributeList is being processed and we only want a specific
                   instance. */
                if ((instance != 65535) && (instance != attribute->AttributeNumber))
                {
                    continue;
                }

                if (attribute->Nonresident == 0)
                {
                    var residentAttribute = (ResidentAttribute*)attribute;

                    switch (attribute->AttributeType)
                    {
                        case AttributeType.AttributeFileName:
                            var attributeFileName = (AttributeFileName*)(ptr + AttributeOffset + residentAttribute->ValueOffset);

                            if (attributeFileName->ParentDirectory.InodeNumberHighPart > 0)
                            {
                                throw new NotSupportedException("48 bits inode are not supported to reduce memory footprint.");
                            }

                            node.ParentNodeIndex = attributeFileName->ParentDirectory.InodeNumberLowPart;

                            if (attributeFileName->NameType == 1 || node.NameIndex == 0)
                            {
                                node.NameIndex = GetNameIndex(new string(&attributeFileName->Name, 0, attributeFileName->NameLength));
                            }

                            break;

                        case AttributeType.AttributeStandardInformation:
                            var attributeStandardInformation = (AttributeStandardInformation*)(ptr + AttributeOffset + residentAttribute->ValueOffset);

                            node.Attributes |= (Attributes)attributeStandardInformation->FileAttributes;

                            if ((_retrieveMode & RetrieveMode.StandardInformations) == RetrieveMode.StandardInformations)
                            {
                                _standardInformations![nodeIndex] =
                                    new StandardInformation(
                                        attributeStandardInformation->CreationTime,
                                        attributeStandardInformation->FileChangeTime,
                                        attributeStandardInformation->LastAccessTime
                                    );
                            }

                            break;

                        case AttributeType.AttributeData:
                            node.Size = residentAttribute->ValueLength;
                            break;
                    }
                }
                else
                {
                    var nonResidentAttribute = (NonResidentAttribute*)attribute;

                    //save the length (number of bytes) of the data.
                    if (attribute->AttributeType == AttributeType.AttributeData && node.Size == 0)
                    {
                        node.Size = nonResidentAttribute->DataSize;
                    }

                    if (streams != null)
                    {
                        //extract the stream name
                        var streamNameIndex = 0;
                        if (attribute->NameLength > 0)
                        {
                            streamNameIndex = GetNameIndex(new string((char*)(ptr + AttributeOffset + attribute->NameOffset), 0, attribute->NameLength));
                        }

                        //find or create the stream
                        var stream =
                            SearchStream(streams, attribute->AttributeType, streamNameIndex);

                        if (stream == null)
                        {
                            stream = new Stream(streamNameIndex, attribute->AttributeType, nonResidentAttribute->DataSize);
                            streams.Add(stream);
                        }
                        else if (stream.Size == 0)
                        {
                            stream.Size = nonResidentAttribute->DataSize;
                        }

                        //we need the fragment of the MFTNode so retrieve them this time
                        //even if fragments aren't normally read
                        if (isMftNode || (_retrieveMode & RetrieveMode.Fragments) == RetrieveMode.Fragments)
                        {
                            ProcessFragments(
                                ref node,
                                stream,
                                ptr + AttributeOffset + nonResidentAttribute->RunArrayOffset,
                                attribute->Length - nonResidentAttribute->RunArrayOffset,
                                nonResidentAttribute->StartingVcn
                            );
                        }
                    }
                }
            }

            if (streams?.Count > 0)
            {
                node.Size = streams[0].Size;
            }
        }

        /// <summary>
        /// Process fragments for streams
        /// </summary>
        private unsafe void ProcessFragments(
            ref Node node,
            Stream stream,
            byte* runData,
            uint runDataLength,
            ulong StartingVcn)
        {
            if (runData == null)
            {
                return;
            }

            /* Walk through the RunData and add the extents. */
            uint index = 0;
            long lcn = 0;
            var vcn = (long)StartingVcn;
            var runOffsetSize = 0;
            var runLengthSize = 0;

            while (runData[index] != 0)
            {
                /* Decode the RunData and calculate the next Lcn. */
                runLengthSize = (runData[index] & 0x0F);
                runOffsetSize = ((runData[index] & 0xF0) >> 4);

                if (++index >= runDataLength)
                {
                    throw new NtfsException("Error: datarun is longer than buffer, the MFT may be corrupt.");
                }

                var runLength =
                    ProcessRunLength(runData, runDataLength, runLengthSize, ref index);

                var runOffset =
                    ProcessRunOffset(runData, runDataLength, runOffsetSize, ref index);

                lcn += runOffset;
                vcn += runLength;

                /* Add the size of the fragment to the total number of clusters.
                   There are two kinds of fragments: real and virtual. The latter do not
                   occupy clusters on disk, but are information used by compressed
                   and sparse files. */
                if (runOffset != 0)
                {
                    stream.Clusters += (ulong)runLength;
                }

                stream.Fragments.Add(
                    new Fragment(
                        runOffset == 0 ? VIRTUAL_FRAGMENT : (ulong)lcn,
                        (ulong)vcn
                    )
                );
            }
        }

        /// <summary>
        /// Process an actual MFT record from the buffer
        /// </summary>
        private unsafe bool ProcessMftRecord(byte* buffer, ulong length, uint nodeIndex, out Node node, List<Stream>? streams, bool isMftNode)
        {
            node = new Node();

            var ntfsFileRecordHeader = (FileRecordHeader*)buffer;

            if (ntfsFileRecordHeader->RecordHeader.Type != RecordType.File)
            {
                return false;
            }

            //the inode is not in use
            if ((ntfsFileRecordHeader->Flags & 1) != 1)
            {
                return false;
            }

            var baseInode = ((ulong)ntfsFileRecordHeader->BaseFileRecord.InodeNumberHighPart << 32) + ntfsFileRecordHeader->BaseFileRecord.InodeNumberLowPart;

            //This is an inode extension used in an AttributeAttributeList of another inode, don't parse it
            if (baseInode != 0)
            {
                return false;
            }

            if (ntfsFileRecordHeader->AttributeOffset >= length)
            {
                throw new NtfsException("Error: attributes in Inode %I64u are outside the FILE record, the MFT may be corrupt.");
            }

            if (ntfsFileRecordHeader->BytesInUse > length)
            {
                throw new NtfsException("Error: in Inode %I64u the record is bigger than the size of the buffer, the MFT may be corrupt.");
            }

            //make the file appear in the rootdirectory by default
            node.ParentNodeIndex = ROOT_DIRECTORY;

            if ((ntfsFileRecordHeader->Flags & 2) == 2)
            {
                node.Attributes |= Attributes.Directory;
            }

            ProcessAttributes(ref node, nodeIndex, buffer + ntfsFileRecordHeader->AttributeOffset, length - ntfsFileRecordHeader->AttributeOffset, 65535, 0, streams, isMftNode);

            return true;
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
        /// Begin the process of interpreting MFT data
        /// </summary>
        private unsafe Node[] ProcessMft()
        {
            //64 KB seems to be optimal for Windows XP, Vista is happier with 256KB...
            var bufferSize =
                (Environment.OSVersion.Version.Major >= 6 ? 256u : 64u) * 1024;

            var data = new byte[bufferSize];

            fixed (byte* buffer = data)
            {
                //Read the $MFT record from disk into memory, which is always the first record in the MFT.
                ReadFile(buffer, _diskInfo.BytesPerMftRecord, _diskInfo.MftStartLcn * _diskInfo.BytesPerSector * _diskInfo.SectorsPerCluster);

                //Fixup the raw data from disk. This will also test if it's a valid $MFT record.
                FixupRawMftdata(buffer, _diskInfo.BytesPerMftRecord);

                var mftStreams = new List<Stream>();

                if ((_retrieveMode & RetrieveMode.StandardInformations) == RetrieveMode.StandardInformations)
                {
                    _standardInformations = new StandardInformation[1]; //allocate some space for $MFT record
                }

                if (!ProcessMftRecord(buffer, _diskInfo.BytesPerMftRecord, 0, out var mftNode, mftStreams, true))
                {
                    throw new NtfsException("Can't interpret Mft Record");
                }

                //the bitmap data contains all used inodes on the disk
                _bitmapData =
                    ProcessBitmapData(mftStreams);

                OnBitmapDataAvailable();

                var dataStream = SearchStream(mftStreams, AttributeType.AttributeData) ?? throw new NtfsException("MFT stream cannot be null");
                var maxInode = (uint)_bitmapData.Length * 8;
                if (maxInode > (uint)(dataStream.Size / _diskInfo.BytesPerMftRecord))
                {
                    maxInode = (uint)(dataStream.Size / _diskInfo.BytesPerMftRecord);
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

                /* Read and process all the records in the MFT. The records are read into a
                   buffer and then given one by one to the InterpretMftRecord() subroutine. */

                ulong BlockStart = 0, BlockEnd = 0;
                ulong RealVcn = 0, Vcn = 0;

                var stopwatch = new Stopwatch();
                stopwatch.Start();

                ulong totalBytesRead = 0;
                const int fragmentIndex = 0;
                var fragmentCount = dataStream.Fragments.Count;
                for (uint nodeIndex = 1; nodeIndex < maxInode; nodeIndex++)
                {
                    // Ignore the Inode if the bitmap says it's not in use.
                    if ((_bitmapData[nodeIndex >> 3] & BitmapMasks[nodeIndex % 8]) == 0)
                    {
                        continue;
                    }

                    if (nodeIndex >= BlockEnd)
                    {
                        if (!ReadNextChunk(
                                buffer,
                                bufferSize,
                                nodeIndex,
                                fragmentIndex,
                                dataStream,
                                ref BlockStart,
                                ref BlockEnd,
                                ref Vcn,
                                ref RealVcn))
                        {
                            break;
                        }

                        totalBytesRead += (BlockEnd - BlockStart) * _diskInfo.BytesPerMftRecord;
                    }

                    FixupRawMftdata(
                            buffer + ((nodeIndex - BlockStart) * _diskInfo.BytesPerMftRecord),
                            _diskInfo.BytesPerMftRecord
                        );

                    List<Stream>? streams = null;
                    if ((_retrieveMode & RetrieveMode.Streams) == RetrieveMode.Streams)
                    {
                        streams = [];
                    }

                    if (!ProcessMftRecord(
                            buffer + ((nodeIndex - BlockStart) * _diskInfo.BytesPerMftRecord),
                            _diskInfo.BytesPerMftRecord,
                            nodeIndex,
                            out var newNode,
                            streams,
                            false))
                    {
                        continue;
                    }

                    nodes[nodeIndex] = newNode;

                    if (streams != null)
                    {
                        _streams![nodeIndex] = streams.ToArray();
                    }
                }

                stopwatch.Stop();

                Trace.WriteLine(
                    string.Format(
                        "{0:F3} MB of volume metadata has been read in {1:F3} s at {2:F3} MB/s",
                        (float)totalBytesRead / (1024 * 1024),
                        (float)stopwatch.Elapsed.TotalSeconds,
                        (float)totalBytesRead / (1024 * 1024) / stopwatch.Elapsed.TotalSeconds
                    )
                );

                return nodes;
            }
        }

        #endregion
    }
}
