using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using CygnusAgent.Core.Interfaces;

namespace CygnusAgent.Infrastructure.Storage
{
    /// <summary>
    /// Persists pending outbound items (results, evidence) to a directory as
    /// one JSON file per item, named by a monotonically increasing counter
    /// so FIFO order survives a service restart. Bounded: once at capacity,
    /// new items are rejected rather than silently dropping old ones or
    /// growing unbounded (spec §12).
    ///
    /// Submission (Dequeue) only ever removes an item AFTER the caller has
    /// confirmed it was accepted by the backend — see AgentWorker — which is
    /// what makes retries idempotent-safe from this queue's side: a crash
    /// between "sent" and "dequeued" just means we send it again, and the
    /// backend's sequence-number dedupe (once implemented) absorbs that.
    /// </summary>
    public sealed class FileOfflineQueue<T> : IOfflineQueue<T>
    {
        private readonly string _directory;
        private readonly int _maxItems;
        private readonly object _lock = new();

        public FileOfflineQueue(string directory, int maxItems)
        {
            _directory = directory;
            _maxItems = maxItems;
            Directory.CreateDirectory(_directory);
        }

        public int Count
        {
            get { lock (_lock) return Files().Length; }
        }

        public bool TryEnqueue(T item)
        {
            lock (_lock)
            {
                if (Files().Length >= _maxItems) return false;

                var seq = NextSeq();
                var path = Path.Combine(_directory, $"{seq:D12}.json");
                var tmp = path + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(item));
                File.Move(tmp, path); // atomic-ish rename avoids a torn read of a half-written file
                return true;
            }
        }

        public bool TryPeek(out T item)
        {
            lock (_lock)
            {
                var first = Files().FirstOrDefault();
                if (first == null) { item = default!; return false; }
                item = JsonSerializer.Deserialize<T>(File.ReadAllText(first))!;
                return true;
            }
        }

        public void Dequeue()
        {
            lock (_lock)
            {
                var first = Files().FirstOrDefault();
                if (first != null) File.Delete(first);
            }
        }

        private string[] Files() =>
            Directory.GetFiles(_directory, "*.json").OrderBy(f => f).ToArray();

        private long NextSeq()
        {
            var last = Files().LastOrDefault();
            if (last == null) return 1;
            var name = Path.GetFileNameWithoutExtension(last);
            return long.TryParse(name, out var n) ? n + 1 : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        }
    }
}
