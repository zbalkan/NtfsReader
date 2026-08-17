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
    /// Node attributes.
    /// </summary>
    [Flags]
#pragma warning disable RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
    public enum Attributes : uint
#pragma warning restore RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
    {
        /// <summary>
        /// The file is read-only.
        /// </summary>
        ReadOnly = 1,

        /// <summary>
        /// The file is hidden, and thus is not included in an ordinary directory listing.
        /// </summary>
        Hidden = 1 << 1,

        /// <summary>
        /// The file is a system file. The file is part of the operating system or is
        /// used exclusively by the operating system.
        /// </summary>
        System = 1 << 2,

        /// <summary>
        /// The file is a directory.
        /// </summary>
        Directory = 1 << 4,

        /// <summary>
        /// The file's archive status. Applications use this attribute to mark files
        /// for backup or removal.
        /// </summary>
        Archive = 1 << 5,

        /// <summary>
        /// Reserved for future use.
        /// </summary>
        Device = 1 << 6,

        /// <summary>
        /// The file is normal and has no other attributes set. This attribute is valid
        /// only if used alone.
        /// </summary>
        Normal = 1 << 7,

        /// <summary>
        /// The file is temporary. File systems attempt to keep all of the data in memory
        /// for quicker access rather than flushing the data back to mass storage. A
        /// temporary file should be deleted by the application as soon as it is no longer
        /// needed.
        /// </summary>
        Temporary = 1 << 8,

        /// <summary>
        /// The file is a sparse file. Sparse files are typically large files whose data
        /// are mostly zeros.
        /// </summary>
        SparseFile = 1 << 9,

        /// <summary>
        /// The file contains a reparse point, which is a block of user-defined data
        /// associated with a file or a directory.
        /// </summary>
        ReparsePoint = 1 << 10,

        /// <summary>
        /// The file is compressed.
        /// </summary>
        Compressed = 1 << 11,

        /// <summary>
        /// The file is offline. The data of the file is not immediately available.
        /// </summary>
        Offline = 1 << 12,

        /// <summary>
        /// The file will not be indexed by the operating system's content indexing service.
        /// </summary>
        NotContentIndexed = 1 << 13,

        /// <summary>
        /// The file or directory is encrypted. For a file, this means that all data
        /// in the file is encrypted. For a directory, this means that encryption is
        /// the default for newly created files and directories.
        /// </summary>
        Encrypted = 1 << 14,
    }
}
