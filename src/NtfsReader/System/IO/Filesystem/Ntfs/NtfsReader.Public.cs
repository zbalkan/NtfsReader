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
using System.Text;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Threading.Tasks;
using System.Linq;

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
        public IDiskInfo DiskInfo => _diskInfo;

        public byte[]? VolumeBitmap => _bitmapData;

        private static readonly char[] trimChars = ['\\'];

        /// <summary>
        /// NtfsReader constructor.
        /// </summary>
        /// <param name="driveInfo">The drive you want to read metadata from.</param>
        /// <param name="retrieveMode">Information to retrieve from each node while scanning the disk</param>
        /// <remarks>Streams & Fragments are expensive to store in memory, if you don't need them, don't retrieve them.</remarks>
        public NtfsReader(DriveInfo driveInfo, RetrieveMode retrieveMode)
        {
            ArgumentNullException.ThrowIfNull(driveInfo);

            _driveInfo = driveInfo;
            _retrieveMode = retrieveMode;

            var builder = new StringBuilder(1024);
            GetVolumeNameForVolumeMountPoint(_driveInfo.RootDirectory.Name, builder, builder.Capacity);

            var volume = builder.ToString().TrimEnd(trimChars);

            _volumeHandle =
                CreateFile(
                    volume,
                    FileAccess.Read,
                    FileShare.All,
                    IntPtr.Zero,
                    FileMode.Open,
                    0,
                    IntPtr.Zero
                    );

            if (_volumeHandle?.IsInvalid != false)
            {
                throw new IOException(
                    string.Format(
                        "Unable to open volume {0}. Make sure it exists and that you have Administrator privileges.",
                        driveInfo
                    )
                );
            }

            using (_volumeHandle)
            {
                _diskInfo = InitializeDiskInfo();

                _nodes = ProcessMft();
            }

            //cleanup anything that isn't used anymore
            _nameIndex = null;
            _volumeHandle = null;

            GC.Collect();
        }
        /// <summary>
        /// Get all nodes under the specified rootPath.
        /// </summary>
        /// <param name="rootPath">The rootPath must at least contains the drive and may include any number of subdirectories. Wildcards aren't supported.</param>
        public List<INode> GetNodes(string rootPath)
        {
            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var nodes = new List<INode>();

            var nodeCount = (uint)_nodes.Length;
            for (uint i = 0; i < nodeCount; ++i)
            {
                if (_nodes[i].NameIndex != 0 && GetNodeFullNameCore(i).StartsWith(rootPath, StringComparison.InvariantCultureIgnoreCase))
                {
                    nodes.Add(new NodeWrapper(this, i, _nodes[i]));
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
        /// Get all nodes under the specified rootPath in parallel.
        /// </summary>
        /// <param name="rootPath">The rootPath must at least contains the drive and may include any number of subdirectories. Wildcards aren't supported.</param>
        /// <exception cref="AggregateException"></exception>
        public List<INode> GetNodesParallel(string rootPath)
        {
            var stopwatch = new Stopwatch();
            stopwatch.Start();

            var nodes = new ConcurrentBag<INode>();
            var nodeCount = (uint)_nodes.Length;
            _ = Parallel.For(0,
                nodeCount,
                index => {
                    var i = Convert.ToUInt32(index);
                    if (_nodes[i].NameIndex != 0 && GetNodeFullNameCore(i)
                            .StartsWith(rootPath, StringComparison.InvariantCultureIgnoreCase))
                    {
                        nodes.Add(new NodeWrapper(this, i, _nodes[i]));
                    }
                });

            stopwatch.Stop();

            Trace.WriteLine(
                $"{nodes.Count} node{(nodes.Count > 1 ? "s" : string.Empty)} have been retrieved in {(float)stopwatch.ElapsedTicks / TimeSpan.TicksPerMillisecond} ms"
            );

            return nodes.ToList();
        }
        #region IDisposable Members

        public void Dispose()
        {
            if (_volumeHandle != null)
            {
                _volumeHandle.Dispose();
                _volumeHandle = null;
            }
        }

        #endregion
    }
}
