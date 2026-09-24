using System;
using System.Collections.Generic;

namespace CygnusAgent.Core.Models
{
    public enum EvidenceCollectionStatus
    {
        Collected,
        Skipped,
        Failed
    }

    /// <summary>
    /// Metadata + hash for a piece of evidence. This Agent does not upload
    /// raw file bytes by default (matches the existing backend's Evidence.gs
    /// design) — only what the job's checks explicitly asked for.
    /// </summary>
    public sealed class EvidenceRecord
    {
        public string EvidenceId { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string JobId { get; set; } = "";
        public string CheckId { get; set; } = "";
        public DateTimeOffset Timestamp { get; set; }
        public string EvidenceType { get; set; } = "";
        public Dictionary<string, string> Metadata { get; set; } = new();
        public string Sha256Hash { get; set; } = "";
        public long SizeBytes { get; set; }
        public EvidenceCollectionStatus CollectionStatus { get; set; }
    }

    /// <summary>
    /// Wraps any outbound result (verification or remediation) with the
    /// fields the backend needs for replay protection: which device, which
    /// job, a fresh nonce, a monotonic per-device sequence number, and a
    /// hash of the payload itself. See THREAT_MODEL.md "Replay".
    /// </summary>
    public sealed class AgentResultEnvelope<T>
    {
        public string DeviceId { get; set; } = "";
        public string JobId { get; set; } = "";
        public string ResultId { get; set; } = "";
        public DateTimeOffset Timestamp { get; set; }
        public string Nonce { get; set; } = "";
        public long Sequence { get; set; }
        public string PayloadHash { get; set; } = "";
        public T Payload { get; set; } = default!;
    }
}
