using System;
using System.Collections.Generic;

namespace CygnusAgent.Core.Models
{
    /// <summary>
    /// A verification job as received from the backend. Never trust this
    /// blindly — validate expiresAt and that every check's Type is in the
    /// allowlist before dispatching anything (see CheckEngine).
    /// </summary>
    public sealed class VerificationJob
    {
        public string JobId { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string PolicyId { get; set; } = "";
        public string Objective { get; set; } = "";
        public List<CheckRequest> Checks { get; set; } = new();
        public DateTimeOffset RequestedAt { get; set; }
        public DateTimeOffset ExpiresAt { get; set; }

        public bool IsExpired(DateTimeOffset now) => now > ExpiresAt;
    }

    public sealed class CheckRequest
    {
        public string CheckId { get; set; } = "";
        /// <summary>Must match a key in CheckEngine's allowlisted registry.</summary>
        public string Type { get; set; } = "";
        public Dictionary<string, string> Parameters { get; set; } = new();
    }

    public enum CheckStatus
    {
        Pass,
        Fail,
        Error,
        NotApplicable
    }

    public sealed class CheckResult
    {
        public string CheckId { get; set; } = "";
        public CheckStatus Status { get; set; }
        public Dictionary<string, object> ObservedState { get; set; } = new();
        public List<EvidenceRecord> Evidence { get; set; } = new();
        public DateTimeOffset StartedAt { get; set; }
        public DateTimeOffset CompletedAt { get; set; }
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// A remediation instruction. ActionType must resolve against
    /// RemediationEngine's closed registry — an unrecognized type is a hard
    /// error, never a fallback to shell execution.
    /// </summary>
    public sealed class RemediationAction
    {
        public string ActionId { get; set; } = "";
        public string JobId { get; set; } = "";
        public string ActionType { get; set; } = "";
        public Dictionary<string, string> Parameters { get; set; } = new();
    }

    public enum RemediationOutcome
    {
        Succeeded,
        Failed,
        Skipped
    }

    public sealed class RemediationResult
    {
        public string ActionId { get; set; } = "";
        public string JobId { get; set; } = "";
        public DateTimeOffset StartedAt { get; set; }
        public DateTimeOffset CompletedAt { get; set; }
        public RemediationOutcome Result { get; set; }
        public string? ErrorCode { get; set; }
        public string AffectedResource { get; set; } = "";
    }
}
