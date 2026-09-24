using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Security
{
    /// <summary>
    /// Builds AgentResultEnvelope&lt;T&gt; instances with the fields the backend
    /// needs for replay protection (nonce, sequence, payload hash) — see
    /// THREAT_MODEL.md "Replay". Sequence numbers are per-device and
    /// monotonic, persisted locally so a service restart doesn't reset them
    /// to a value the backend has already seen.
    /// </summary>
    public sealed class ResultEnvelopeFactory
    {
        private readonly DeviceIdentityProvider _identity;
        private readonly ISequenceStore _sequenceStore;

        public ResultEnvelopeFactory(DeviceIdentityProvider identity, ISequenceStore sequenceStore)
        {
            _identity = identity;
            _sequenceStore = sequenceStore;
        }

        public AgentResultEnvelope<T> Wrap<T>(string deviceId, string jobId, T payload)
        {
            var json = JsonSerializer.Serialize(payload);
            var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json)));

            return new AgentResultEnvelope<T>
            {
                DeviceId = deviceId,
                JobId = jobId,
                ResultId = Guid.NewGuid().ToString("N"),
                Timestamp = DateTimeOffset.UtcNow,
                Nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
                Sequence = _sequenceStore.NextSequence(deviceId),
                PayloadHash = hash,
                Payload = payload
            };
        }
    }

    /// <summary>Persists the last-used sequence number per device so it survives
    /// a service restart without going backwards (which would look like a replay
    /// to the backend).</summary>
    public interface ISequenceStore
    {
        long NextSequence(string deviceId);
    }
}
