namespace System.IO.Filesystem.Ntfs
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
