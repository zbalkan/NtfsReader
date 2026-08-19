#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace System.IO.Filesystem.Ntfs
#pragma warning restore IDE0130 // Namespace does not match folder structure
{
    /// <summary>
    /// Controls how the raw volume handle is shared while NTFS metadata is scanned.
    /// </summary>
    public enum VolumeReadConsistency
    {
        /// <summary>
        /// Preserve the historic behavior: permit concurrent reads, writes, and deletes.
        /// Results are a best-effort view and are not a point-in-time snapshot.
        /// </summary>
        BestEffort = 0,

        /// <summary>
        /// Permit only concurrent readers after the handle is opened. This may fail if a writer
        /// already holds an incompatible handle and still does not replace a VSS snapshot for
        /// forensic or backup-grade point-in-time consistency.
        /// </summary>
        DenyConcurrentWrites = 1,
    }
}
