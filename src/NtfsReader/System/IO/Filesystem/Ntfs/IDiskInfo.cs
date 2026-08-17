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

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace System.IO.Filesystem.Ntfs
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Disk information
    /// </summary>
    public interface IDiskInfo
    {
        ulong BytesPerCluster { get; }
        ulong BytesPerMftRecord { get; }
        ushort BytesPerSector { get; }
        uint ClustersPerIndexRecord { get; }
        uint ClustersPerMftRecord { get; }
        ulong Mft2StartLcn { get; }
        ulong MftStartLcn { get; }
        byte SectorsPerCluster { get; }
        ulong TotalClusters { get; }
        ulong TotalSectors { get; }
    }
}
