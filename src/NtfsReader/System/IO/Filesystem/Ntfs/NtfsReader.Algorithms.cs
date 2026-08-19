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
using System.Threading;

namespace System.IO.Filesystem.Ntfs
{
    public partial class NtfsReader
    {
        private readonly record struct ChildKey(uint ParentNodeIndex, string Name);

        private sealed class ChildKeyComparer : IEqualityComparer<ChildKey>
        {
            public static ChildKeyComparer Instance { get; } = new();

            public bool Equals(ChildKey x, ChildKey y) =>
                x.ParentNodeIndex == y.ParentNodeIndex &&
                StringComparer.OrdinalIgnoreCase.Equals(x.Name, y.Name);

            public int GetHashCode(ChildKey obj) =>
                HashCode.Combine(obj.ParentNodeIndex, StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Name));
        }

        /// <summary>
        /// Construct the full path while publishing immutable cache entries without serializing concurrent callers.
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
            var prefix = _driveInfo.Name.TrimEnd(trimChars);
            var fullPathNodes = new Stack<uint>();
            var visitedNodes = new HashSet<uint>();

            while (true)
            {
                cachedPath = Volatile.Read(ref _fullPathCache[node]);
                if (cachedPath != null)
                {
                    prefix = cachedPath;
                    break;
                }

                if (!visitedNodes.Add(node))
                {
                    throw new InvalidDataException($"Detected a parent cycle while resolving node {nodeIndex}.");
                }

                fullPathNodes.Push(node);
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

            var fullPath = new StringBuilder(prefix);
            while (fullPathNodes.Count > 0)
            {
                node = fullPathNodes.Pop();
                fullPath.Append('\\');
                fullPath.Append(GetNameFromIndex(_nodes[node].NameIndex));
            }

            var computedPath = fullPath.ToString();
            return Interlocked.CompareExchange(ref _fullPathCache[nodeIndex], computedPath, null) ?? computedPath;
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
            var driveRoot = _driveInfo.Name.TrimEnd(trimChars);
            var normalizedPath = rootPath.Replace('/', '\\').TrimEnd(trimChars);
            if (!normalizedPath.StartsWith(driveRoot, StringComparison.OrdinalIgnoreCase) ||
                (normalizedPath.Length > driveRoot.Length && normalizedPath[driveRoot.Length] != '\\'))
            {
                nodeIndex = 0;
                return false;
            }

            nodeIndex = ROOT_DIRECTORY;
            var relativePath = normalizedPath.AsSpan(driveRoot.Length).TrimStart('\\');
            foreach (var segmentRange in relativePath.Split('\\'))
            {
                var segment = relativePath[segmentRange];
                if (segment.IsEmpty || !_childLookup.TryGetValue(new ChildKey(nodeIndex, segment.ToString()), out nodeIndex))
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
