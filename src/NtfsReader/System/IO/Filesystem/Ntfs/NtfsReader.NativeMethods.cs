using System.Runtime.InteropServices;

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

using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.IO.Filesystem.Ntfs
{
    public partial class NtfsReader
    {
        [Serializable, Flags]
#pragma warning disable RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
        private enum FileAccess : int
#pragma warning restore RCS1135 // Declare enum member with zero value (when enum has FlagsAttribute)
        {
            Read = 1,
            ReadWrite = Read | Write,
            Write = 1 << 1
        }

        [Serializable]
        private enum FileMode : int
        {
            CreateNew = 1,
            Create = 2,
            Open = 3,
            OpenOrCreate = 4,
            Truncate = 5,
            Append = 6
        }

        [Serializable, Flags]
        private enum FileShare : int
        {
            None = 0,
            Read = 1,
            Write = 1 << 1,
            Delete = 1 << 2,
            All = Read | Write | Delete
        }

        [LibraryImport("kernel32", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        private static partial SafeFileHandle CreateFile(string lpFileName, FileAccess fileAccess, FileShare fileShare, IntPtr lpSecurityAttributes, FileMode fileMode, int dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32", CharSet = CharSet.Auto, BestFitMapping = false, SetLastError = true)]
        private static extern bool GetVolumeNameForVolumeMountPoint(string volumeName, StringBuilder uniqueVolumeName, int uniqueNameBufferCapacity);

        [LibraryImport("kernel32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static partial bool ReadFile(SafeFileHandle hFile, IntPtr lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, ref NativeOverlapped lpOverlapped);

        [StructLayout(LayoutKind.Sequential)]
        private struct NativeOverlapped
        {
            public IntPtr privateLow;
            public IntPtr privateHigh;
            public ulong Offset;
            public IntPtr EventHandle;

            public NativeOverlapped(ulong offset)
            {
                Offset = offset;
                EventHandle = IntPtr.Zero;
                privateLow = IntPtr.Zero;
                privateHigh = IntPtr.Zero;
            }
        }
    }
}
