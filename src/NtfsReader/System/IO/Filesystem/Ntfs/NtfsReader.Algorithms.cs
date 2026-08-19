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

using System.Buffers;
using System.Collections.Generic;
using System.Threading;

namespace System.IO.Filesystem.Ntfs
{
    public partial class NtfsReader
    {
        private readonly record struct ChildKey(uint ParentNodeIndex, string Name);

        private readonly ref struct ChildPathKey(uint parentNodeIndex, ReadOnlySpan<char> name)
        {
            public uint ParentNodeIndex { get; } = parentNodeIndex;
            public ReadOnlySpan<char> Name { get; } = name;
        }

        private sealed class ChildKeyComparer :
            IEqualityComparer<ChildKey>,
            IAlternateEqualityComparer<ChildPathKey, ChildKey>
        {
            public static ChildKeyComparer Instance { get; } = new();

            public bool Equals(ChildKey x, ChildKey y) =>
                x.ParentNodeIndex == y.ParentNodeIndex &&
                StringComparer.OrdinalIgnoreCase.Equals(x.Name, y.Name);

            public int GetHashCode(ChildKey obj) =>
                HashCode.Combine(obj.ParentNodeIndex, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Name));

            public bool Equals(ChildPathKey alternate, ChildKey other) =>
                alternate.ParentNodeIndex == other.ParentNodeIndex &&
                alternate.Name.Equals(other.Name.AsSpan(), StringComparison.OrdinalIgnoreCase);

            public int GetHashCode(ChildPathKey alternate) =>
                HashCode.Combine(
                    alternate.ParentNodeIndex,
                    string.GetHashCode(alternate.Name, StringComparison.OrdinalIgnoreCase)
                );

            public ChildKey Create(ChildPathKey alternate) =>
                new(alternate.ParentNodeIndex, alternate.Name.ToString());
        }

        /// <summary>
        /// Constructs and caches a full path with one exact-length string allocation. Traversal
        /// storage is rented only while the cache miss is being resolved.
        /// </summary>
        private string GetNodeFullNameCore(uint nodeIndex)
        {
            if (nodeIndex >= _nodes.Length)
            {
                throw new InvalidDataException($"Node index {nodeIndex} is outside the MFT.");
            }

            var cachedPath = Volatile.Read(ref _fullPathCache[nodeIndex]);
            if (cachedPath != null)
            {
                return cachedPath;
            }

            var node = nodeIndex;
            var prefix = _driveRoot;
            var pathNodes = ArrayPool<uint>.Shared.Rent(8);
            var pathNodeCount = 0;

            try
            {
                while (true)
                {
                    cachedPath = Volatile.Read(ref _fullPathCache[node]);
                    if (cachedPath != null)
                    {
                        prefix = cachedPath;
                        break;
                    }

                    if (pathNodes.AsSpan(0, pathNodeCount).Contains(node))
                    {
                        throw new InvalidDataException($"Detected a parent cycle while resolving node {nodeIndex}.");
                    }

                    if (pathNodeCount == pathNodes.Length)
                    {
                        var expandedPathNodes = ArrayPool<uint>.Shared.Rent(checked(pathNodes.Length * 2));
                        pathNodes.AsSpan(0, pathNodeCount).CopyTo(expandedPathNodes);
                        ArrayPool<uint>.Shared.Return(pathNodes);
                        pathNodes = expandedPathNodes;
                    }

                    pathNodes[pathNodeCount++] = node;
                    var parent = _nodes[node].ParentNodeIndex;
                    if (parent == ROOT_DIRECTORY)
                    {
                        break;
                    }

                    if (parent >= _nodes.Length)
                    {
                        throw new InvalidDataException($"Parent node index {parent} for node {node} is outside the MFT.");
                    }

                    node = parent;
                }

                var fullPathLength = checked(prefix.Length + pathNodeCount);
                for (var index = 0; index < pathNodeCount; index++)
                {
                    fullPathLength = checked(fullPathLength + (GetNameFromIndex(_nodes[pathNodes[index]].NameIndex)?.Length ?? 0));
                }

                var computedPath = string.Create(
                    fullPathLength,
                    (Reader: this, Prefix: prefix, Nodes: pathNodes, Count: pathNodeCount),
                    static (destination, state) =>
                    {
                        var destinationOffset = state.Prefix.Length;
                        state.Prefix.AsSpan().CopyTo(destination);

                        for (var index = state.Count - 1; index >= 0; index--)
                        {
                            destination[destinationOffset++] = '\\';
                            var name = state.Reader.GetNameFromIndex(state.Reader._nodes[state.Nodes[index]].NameIndex);
                            if (name != null)
                            {
                                name.AsSpan().CopyTo(destination[destinationOffset..]);
                                destinationOffset += name.Length;
                            }
                        }
                    }
                );
                return Interlocked.CompareExchange(ref _fullPathCache[nodeIndex], computedPath, null) ?? computedPath;
            }
            finally
            {
                ArrayPool<uint>.Shared.Return(pathNodes);
            }
        }

        private void BuildHierarchyIndexes()
        {
            _fullPathCache = new string?[_nodes.Length];
            var childCounts = new uint[_nodes.Length];
            _childLookup = new Dictionary<ChildKey, uint>(ChildKeyComparer.Instance);

            for (uint nodeIndex = 0; nodeIndex < _nodes.Length; nodeIndex++)
            {
                ref readonly var node = ref _nodes[nodeIndex];
                if (node.NameIndex == 0 || node.ParentNodeIndex >= _nodes.Length || node.ParentNodeIndex == nodeIndex)
                {
                    continue;
                }

                childCounts[node.ParentNodeIndex] = checked(childCounts[node.ParentNodeIndex] + 1);
                var key = new ChildKey(node.ParentNodeIndex, GetNameFromIndex(node.NameIndex)!);
                if (!_childLookup.TryAdd(key, nodeIndex))
                {
                    throw new InvalidDataException(
                        $"The MFT contains duplicate child names for parent {node.ParentNodeIndex}: {key.Name}."
                    );
                }
            }

            _childOffsets = new uint[_nodes.Length + 1];
            for (var i = 0; i < childCounts.Length; i++)
            {
                _childOffsets[i + 1] = checked(_childOffsets[i] + childCounts[i]);
            }

            _children = new uint[_childOffsets[^1]];
            var nextChild = (uint[])_childOffsets.Clone();
            for (uint nodeIndex = 0; nodeIndex < _nodes.Length; nodeIndex++)
            {
                var node = _nodes[nodeIndex];
                if (node.NameIndex != 0 && node.ParentNodeIndex < _nodes.Length && node.ParentNodeIndex != nodeIndex)
                {
                    _children[nextChild[node.ParentNodeIndex]++] = nodeIndex;
                }
            }
        }

        private bool TryResolveRootPath(string rootPath, out uint nodeIndex)
        {
            var driveRoot = _driveRoot;
            var normalizedPath = rootPath.Contains('/')
                ? rootPath.Replace('/', '\\').AsSpan().TrimEnd('\\')
                : rootPath.AsSpan().TrimEnd('\\');
            if (!normalizedPath.StartsWith(driveRoot, StringComparison.OrdinalIgnoreCase) ||
                (normalizedPath.Length > driveRoot.Length && normalizedPath[driveRoot.Length] != '\\'))
            {
                nodeIndex = 0;
                return false;
            }

            nodeIndex = ROOT_DIRECTORY;
            var relativePath = normalizedPath[driveRoot.Length..].TrimStart('\\');
            foreach (var segmentRange in relativePath.Split('\\'))
            {
                var segment = relativePath[segmentRange];
                if (segment.IsEmpty ||
                    !_childLookup.GetAlternateLookup<ChildPathKey>()
                        .TryGetValue(new ChildPathKey(nodeIndex, segment), out nodeIndex))
                {
                    nodeIndex = 0;
                    return false;
                }
            }

            return true;
        }

        private IEnumerable<uint> EnumerateSubtree(uint rootNodeIndex)
        {
            var pending = new Stack<uint>();
            pending.Push(rootNodeIndex);
            while (pending.Count > 0)
            {
                var nodeIndex = pending.Pop();
                yield return nodeIndex;

                for (var i = _childOffsets[nodeIndex + 1]; i > _childOffsets[nodeIndex]; i--)
                {
                    pending.Push(_children[i - 1]);
                }
            }
        }
    }
}
