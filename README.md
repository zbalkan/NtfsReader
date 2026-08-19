# NtfsReader

NtfsReader is a Windows-focused .NET library for reading NTFS volume metadata directly from the Master File Table (MFT). It is intended for personal projects and should be evaluated carefully before use in production or distribution.

> This fork tries to update the NtfsReader project for personal projects. It is not meant for distribution.

## Fork changes from the original project

The original text at the end of this file describes a small `netstandard2.0`-oriented update. It no longer represents the current codebase. This fork is now a Windows-targeting .NET 10 library with substantial correctness, reliability, performance, testing, and automation work beyond the original implementation.

| Area | Changes in this fork |
|---|---|
| **Platform and project system** | The library and test project target `net10.0-windows10.0.17763.0`, use nullable reference types, and the library is marked AOT-compatible. The repository uses an SDK-style `.slnx` solution and .NET 10 automation. [1] [2] [3] [4] [6] |
| **NTFS parsing correctness** | Binary parsing now uses checked span-based reads. The fork validates update-sequence-array bounds, handles sparse runs safely, resolves `$ATTRIBUTE_LIST` extension records, and applies the correct default-stream size semantics. [5] |
| **Paths and hard links** | Path matching is deterministic and ordinal; duplicate children are detected; full paths are cached; and `GetNodePaths` exposes every path associated with hard-linked nodes. The retained `GetNodesParallel` API now provides deterministic compatibility behavior and is obsolete in favor of `GetNodes`. [6] |
| **Volume access and diagnostics** | Callers can explicitly select volume-handle sharing behavior through `VolumeReadConsistency` or supply a Win32 raw-volume device path directly. This supports reading a VSS `SnapshotDeviceObject` without resolving the live drive. The raw-volume open path reports useful Win32 diagnostics and the library no longer forces garbage collection in the host process. [6] |
| **Memory and traversal performance** | The fork reduces temporary allocations by using stack-backed spans for volume names, exact-length string creation for full paths, pooled traversal storage, cached drive roots, and span-based segment comparisons. [7] |
| **Tests and continuous integration** | The repository includes an MSTest project with focused binary-parsing and compatibility coverage, plus a modernized .NET 10 workflow for build, test, and package publication. [6] [8] |

> **Compatibility note.** Applications consuming this fork must target Windows and be compatible with `net10.0-windows10.0.17763.0`; the `netstandard2.0` reference in the historical README is retained only as part of the original text.

## Requirements

| Requirement | Details |
|---|---|
| Operating system | Windows, because the reader opens a raw volume through Win32 APIs. |
| File system | An NTFS volume. |
| SDK for development | .NET 10 SDK, matching the library and test project target framework. |
| Permissions for volume scans | Run with Administrator privileges. The library opens the volume directly and will throw an `IOException` if it cannot do so. |
| Consistency expectations | The reader does not create or manage a point-in-time snapshot. Create a VSS snapshot with a requester, then pass its `SnapshotDeviceObject` to the device-path constructor when forensic or backup-grade consistency is required. [10] |

## Repository layout

| Path | Purpose |
|---|---|
| `src/NtfsReader/NtfsReader.csproj` | The `NtfsReader` library, targeting `net10.0-windows10.0.17763.0`. |
| `src/NtfsReader.Tests/NtfsReader.Tests.csproj` | MSTest-based test project. |
| `src/NtfsReader.slnx` | Solution containing the library and its tests. |
| `LICENSE` | GNU Lesser General Public License, version 2.1 or later. |

## Build and test

Restore, build, and test the solution from the repository root:

```powershell
dotnet restore src/NtfsReader.slnx
dotnet build src/NtfsReader.slnx --configuration Release
dotnet test src/NtfsReader.slnx --configuration Release
```

The test project targets Windows. Run these commands on a Windows system with the .NET 10 SDK installed.

## Use the library

Reference the library project from a compatible Windows-targeting application:

```xml
<ItemGroup>
  <ProjectReference Include="..\NtfsReader\src\NtfsReader\NtfsReader.csproj" />
</ItemGroup>
```

The example below creates a reader for `C:\`, retrieves standard file information, and prints every node under `C:\Data`. Start the host process with Administrator privileges when scanning an actual volume.

```csharp
using System;
using System.IO;
using System.IO.Filesystem.Ntfs;

var reader = new NtfsReader(
    new DriveInfo(@"C:\"),
    RetrieveMode.StandardInformations);

foreach (INode node in reader.GetNodes(@"C:\Data"))
{
    Console.WriteLine($"{node.FullName} - {node.Size:N0} bytes");
}
```

`GetNodes` accepts a drive root or a path below it. Wildcards are not supported. `GetNodesParallel` is retained only for compatibility and is obsolete; use `GetNodes` instead.

### Select the metadata to retrieve

`RetrieveMode` controls the amount of data retained for each node. Request only the information your application needs, because streams and fragments can increase memory use substantially.

| Mode | Metadata included |
|---|---|
| `Minimal` | Name, size, attributes, and hierarchy data. |
| `StandardInformations` | `Minimal` metadata plus creation, access, and change times. This is the default. |
| `Streams` | File stream information. |
| `Fragments` | File-fragment information. |
| `All` | Standard information, streams, and fragments. |

The enum is flagged, so the optional data modes can be combined when a full scan is unnecessary:

```csharp
var retrieveMode = RetrieveMode.StandardInformations | RetrieveMode.Streams;
var reader = new NtfsReader(new DriveInfo(@"C:\"), retrieveMode);
```

### Choose the volume-handle sharing behavior

The constructor's `consistency` argument controls the sharing mode requested when opening the raw volume handle. It does **not** create a snapshot.

| Option | Requested sharing mode | Intended use |
|---|---|---|
| `VolumeReadConsistency.BestEffort` | Allows normal sharing (`FileShare.All`). | Default behavior for ordinary scans. |
| `VolumeReadConsistency.DenyConcurrentWrites` | Requests read-only sharing (`FileShare.Read`). | Use when the reader should request that concurrent writers not share the new volume handle. |

For a VSS-backed workflow, create and scan the snapshot outside this library; passing `DenyConcurrentWrites` alone cannot provide point-in-time consistency.

### Read a VSS snapshot

`NtfsReader` does not create, retain, or delete a VSS snapshot. After a VSS requester has created one, pass its `SnapshotDeviceObject` to the device-path constructor rather than creating the reader from `new DriveInfo(@"C:\")`. Microsoft documents this device object as the root for the shadow-copied volume; it has no trailing backslash. [10]

```csharp
// snapshotProperties is returned by the VSS requester after snapshot creation.
var reader = new NtfsReader(
    snapshotProperties.SnapshotDeviceObject,
    logicalDriveRoot: "C:",
    retrieveMode: RetrieveMode.StandardInformations);

foreach (INode node in reader.GetNodes(@"C:\Data"))
{
    Console.WriteLine($"{node.FullName} - {node.Size:N0} bytes");
}
```

| Constructor argument | VSS usage |
|---|---|
| `volumeDevicePath` | Pass the VSS `SnapshotDeviceObject`, such as `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy42`. Do not append a trailing backslash. |
| `logicalDriveRoot` | Pass the source drive root, such as `C:`. The reader uses it for returned `INode.FullName` values and `GetNodes` query paths; it does not determine the raw source being read. |

The reader performs its raw-volume reads while its constructor runs. Keep the VSS snapshot alive until construction completes, then complete and dispose the VSS requester according to its lifecycle. Do not resolve ordinary files, MFT data, or volume metadata from the live volume during a scan that you intend to represent the snapshot.

### Work with nodes and hard links

Each `INode` exposes its full path, name, size, attributes, timestamps, streams (when requested), and MFT node indexes. When a node has hard links, `GetNodePaths` returns every path represented by its `$FILE_NAME` attributes:

```csharp
foreach (INode node in reader.GetNodes(@"C:\Data"))
{
    foreach (string path in reader.GetNodePaths(node.NodeIndex))
    {
        Console.WriteLine(path);
    }
}
```

## Licensing and provenance

The library is licensed under **LGPL-2.1-or-later**; see [LICENSE](LICENSE) for the complete terms. The source files retain the original copyright notices for Danny Couture. The project's historical description identifies the [SourceForge NtfsReader project][9] as its upstream origin.

## References

[1]: https://github.com/zbalkan/NtfsReader/commit/60c2037 "Migrate to the .slnx solution format"
[2]: https://github.com/zbalkan/NtfsReader/commit/01f511b "Update to .NET 10"
[3]: https://github.com/zbalkan/NtfsReader/commit/22a4dc3 "Enable nullable reference types"
[4]: https://github.com/zbalkan/NtfsReader/commit/bb17834 "Mark the library AOT-compatible"
[5]: https://github.com/zbalkan/NtfsReader/commit/1b23bce "Harden binary parsing and NTFS attribute handling"
[6]: https://github.com/zbalkan/NtfsReader/commit/b1b0dff "Improve paths, hard links, consistency controls, diagnostics, CI, and publication"
[7]: https://github.com/zbalkan/NtfsReader/commit/9efac4b "Reduce raw-volume and traversal allocations"
[8]: https://github.com/zbalkan/NtfsReader/commit/d9cd0cb "Add unit-test coverage"
[9]: https://sourceforge.net/projects/ntfsreader/ "NtfsReader - SourceForge"
[10]: https://learn.microsoft.com/en-us/windows/win32/vss/requestor-access-to-shadow-copied-data "Microsoft: Requestor Access to Shadow-Copied Data"

## Original README (verbatim)

```text
# NtfsReader

Modifications:
- source on Github instead of sourceforge
- netstandard2.0 targetting project file added to allow library to be consumed from .NET Core

Original description from https://sourceforge.net/projects/ntfsreader/ :

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

```
