using System;
using System.IO;
using CygnusAgent.Core.Security;

namespace CygnusAgent.Infrastructure.Storage
{
    /// <summary>Persists the last-issued sequence number to a small local file
    /// so a service restart can't reissue a sequence number the backend has
    /// already seen (which it would otherwise reject as a possible replay).</summary>
    public sealed class FileSequenceStore : ISequenceStore
    {
        private readonly string _path;
        private readonly object _lock = new();

        public FileSequenceStore(string path) => _path = path;

        public long NextSequence(string deviceId)
        {
            lock (_lock)
            {
                long current = 0;
                if (File.Exists(_path) && long.TryParse(File.ReadAllText(_path), out var parsed))
                    current = parsed;

                var next = current + 1;
                var tmp = _path + ".tmp";
                File.WriteAllText(tmp, next.ToString());
                File.Move(tmp, _path, overwrite: true);
                return next;
            }
        }
    }
}
