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
using System.Runtime.InteropServices;

namespace System.IO.Filesystem.Ntfs
{
    /// <summary>
    /// <para>Ntfs metadata reader.</para>
    /// <para>
    /// This class is used to get files & directories information of an NTFS volume.
    /// This is a lot faster than using conventional directory browsing method
    /// particularly when browsing really big directories.
    /// </para>
    /// </summary>
    /// <remarks>Admnistrator rights are required in order to use this method.</remarks>
    public partial class NtfsReader
    {
        private static readonly char[] trimChars = ['\\'];

        /// <summary>
        /// Initializes the reader from a mounted live volume.
        /// </summary>
        /// <param name="driveInfo">The drive whose metadata will be read.</param>
        /// <param name="retrieveMode">Information to retrieve from each node while scanning the disk. StandardInformation is the default.</param>
        /// <param name="consistency">
        /// Controls sharing of the raw volume handle. Neither option creates a point-in-time snapshot;
        /// use the device-path overload with a VSS snapshot for forensic or backup-grade consistency.
        /// </param>
        /// <remarks>Streams & Fragments are expensive to store in memory, if you don't need them, don't retrieve them.</remarks>
        public NtfsReader(
            DriveInfo driveInfo,
            RetrieveMode retrieveMode = RetrieveMode.StandardInformations,
            VolumeReadConsistency consistency = VolumeReadConsistency.BestEffort)
            : this(ResolveVolumeDevicePath(driveInfo), driveInfo?.Name ?? throw new ArgumentNullException(nameof(driveInfo)), retrieveMode, consistency)
        {
        }

        /// <summary>
        /// Initializes the reader from a raw volume device path.
        /// </summary>
        /// <param name="volumeDevicePath">
        /// A Win32 volume-device path, such as a volume GUID path, <c>\\.\C:</c>, or a VSS
        /// <c>SnapshotDeviceObject</c>. A VSS snapshot device path has no trailing backslash.
        /// </param>
        /// <param name="logicalDriveRoot">
        /// The root used in returned node paths and query paths, for example <c>C:</c>. This is
        /// independent of <paramref name="volumeDevicePath"/> so callers can preserve normal path
        /// semantics while reading an immutable VSS snapshot.
        /// </param>
        /// <param name="retrieveMode">Information to retrieve from each node while scanning the disk. StandardInformation is the default.</param>
        /// <param name="consistency">Controls sharing of the raw volume handle.</param>
        public NtfsReader(
            string volumeDevicePath,
            string logicalDriveRoot,
            RetrieveMode retrieveMode = RetrieveMode.StandardInformations,
            VolumeReadConsistency consistency = VolumeReadConsistency.BestEffort)
        {
            if (!Enum.IsDefined(consistency))
            {
                throw new ArgumentOutOfRangeException(nameof(consistency));
            }

            _driveRoot = NormalizeLogicalDriveRoot(logicalDriveRoot);
            _retrieveMode = retrieveMode;

            var normalizedVolumeDevicePath = NormalizeVolumeDevicePath(volumeDevicePath);
            var fileShare = consistency == VolumeReadConsistency.DenyConcurrentWrites
                ? FileShare.Read
                : FileShare.All;

            _volumeHandle =
                CreateFile(
                    normalizedVolumeDevicePath,
                    FileAccess.Read,
                    fileShare,
                    IntPtr.Zero,
                    FileMode.Open,
                    0,
                    IntPtr.Zero
                    );

            if (_volumeHandle?.IsInvalid != false)
            {
                throw new IOException(
                    $"Unable to open volume device '{normalizedVolumeDevicePath}'. " +
                    $"Make sure it exists and that the process has Administrator or backup privileges. " +
                    $"Win32 error: {Marshal.GetLastPInvokeError()}."
                );
            }

            using (_volumeHandle)
            {
                _diskInfo = InitializeDiskInfo();
                _nodes = ProcessMft();
            }

            BuildHierarchyIndexes();

            // Cleanup state only used while reading the MFT. Do not force collection in the host process.
            _nameIndex = null;
            _volumeHandle = null;
        }

        private static string ResolveVolumeDevicePath(DriveInfo driveInfo)
        {
            ArgumentNullException.ThrowIfNull(driveInfo);

            Span<char> volumeNameBuffer = stackalloc char[1024];
            if (!GetVolumeNameForVolumeMountPoint(driveInfo.RootDirectory.Name, volumeNameBuffer))
            {
                throw new IOException(
                    $"Unable to resolve the volume name for {driveInfo}. Win32 error: {Marshal.GetLastPInvokeError()}."
                );
            }

            var volumeNameLength = volumeNameBuffer.IndexOf('\0');
            if (volumeNameLength <= 0)
            {
                throw new IOException($"The resolved volume name for {driveInfo} is empty or unterminated.");
            }

            return new string(
                volumeNameBuffer[..(volumeNameBuffer[volumeNameLength - 1] == '\\'
                    ? volumeNameLength - 1
                    : volumeNameLength)]
            );
        }

        internal static string NormalizeVolumeDevicePath(string volumeDevicePath)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(volumeDevicePath);

            var normalized = volumeDevicePath.AsSpan().TrimEnd('\\').ToString();
            if (normalized.Length == 0 ||
                (!normalized.StartsWith(@"\\?\", StringComparison.Ordinal) &&
                 !normalized.StartsWith(@"\\.\", StringComparison.Ordinal)))
            {
                throw new ArgumentException(
                    "The volume device path must use the Win32 device namespace (for example \\\\?\\Volume{GUID}, \\\\.\\C:, or a VSS SnapshotDeviceObject).",
                    nameof(volumeDevicePath)
                );
            }

            return normalized;
        }

        internal static string NormalizeLogicalDriveRoot(string logicalDriveRoot)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(logicalDriveRoot);

            var normalized = logicalDriveRoot.AsSpan().TrimEnd('\\').ToString();
            if (normalized.Length == 0)
            {
                throw new ArgumentException("The logical drive root must contain at least one non-separator character.", nameof(logicalDriveRoot));
            }

            return normalized;
        }

        public IDiskInfo DiskInfo => _diskInfo;

        public byte[]? VolumeBitmap => _bitmapData;

        /// <summary>
        /// Gets every path recorded for an MFT node, including hard-link paths represented by
        /// multiple <c>$FILE_NAME</c> attributes. The existing <see cref="INode.FullName"/>
        /// remains the primary path selected during parsing.
        /// </summary>
        /// <param name="nodeIndex">The MFT node index.</param>
        public IReadOnlyList<string> GetNodePaths(uint nodeIndex)
        {
            if (nodeIndex >= _nodes.Length)
            {
                throw new ArgumentOutOfRangeException(nameof(nodeIndex));
            }

            if (!_fileNameLinks.TryGetValue(nodeIndex, out var links))
            {
                return [GetNodeFullNameCore(nodeIndex)];
            }

            var paths = new string[links.Count];
            for (var index = 0; index < links.Count; index++)
            {
                var link = links[index];
                var parentPath = link.ParentNodeIndex == ROOT_DIRECTORY
                    ? _driveRoot
                    : GetNodeFullNameCore(link.ParentNodeIndex);
                paths[index] = $"{parentPath}\\{GetNameFromIndex(link.NameIndex)}";
            }

            return Array.AsReadOnly(paths);
        }

        /// <summary>
        /// Get all nodes under the specified rootPath.
        /// </summary>
        /// <param name="rootPath">The rootPath must at least contains the drive and may include any number of subdirectories. Wildcards aren't supported.</param>
        public List<INode> GetNodes(string rootPath)
        {
            ArgumentNullException.ThrowIfNull(rootPath);
            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var nodes = new List<INode>();
            if (TryResolveRootPath(rootPath, out var rootNodeIndex))
            {
                foreach (var i in EnumerateSubtree(rootNodeIndex))
                {
                    if (_nodes[i].NameIndex != 0)
                    {
                        nodes.Add(new NodeWrapper(this, i, _nodes[i]));
                    }
                }
            }

            stopwatch.Stop();

            Trace.WriteLine(
                string.Format(
                    "{0} node{1} have been retrieved in {2} ms",
                    nodes.Count,
                    nodes.Count > 1 ? "s" : string.Empty,
                    (float)stopwatch.ElapsedTicks / TimeSpan.TicksPerMillisecond
                )
            );

            return nodes;
        }

        /// <summary>
        /// Gets all nodes under the specified root path. This compatibility API now preserves the
        /// deterministic traversal order and avoids parallel scheduling overhead for lightweight wrappers.
        /// </summary>
        /// <param name="rootPath">The root path must contain the drive and may include subdirectories. Wildcards are not supported.</param>
        [Obsolete("GetNodesParallel no longer provides a performance benefit. Use GetNodes instead.")]
        public List<INode> GetNodesParallel(string rootPath) => GetNodes(rootPath);

        #region IDisposable Members

        public void Dispose()
        {
            _volumeHandle?.Dispose();
            _volumeHandle = null;
        }

        #endregion IDisposable Members
    }
}
