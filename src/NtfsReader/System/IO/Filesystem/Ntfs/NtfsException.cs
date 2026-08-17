#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace System.IO.Filesystem.Ntfs
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    internal class NtfsException : Exception
    {
        public NtfsException() : base()
        {
        }

        public NtfsException(string message) : base(message)
        {
        }

        public NtfsException(string message, Exception innerException) : base(message, innerException)
        {
        }
    }
}
