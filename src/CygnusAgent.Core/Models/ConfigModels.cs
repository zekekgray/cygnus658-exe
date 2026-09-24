using System;

namespace CygnusAgent.Core.Models
{
    /// <summary>
    /// Non-secret configuration. The credential itself is NEVER part of
    /// this object — it lives only in ICredentialStore (DPAPI-backed).
    /// </summary>
    public sealed class AgentConfig
    {
        /// <summary>e.g. https://script.google.com/macros/s/XXXX/exec — set per
        /// deployment, never committed to source control with a real value.</summary>
        public string ApiBaseUrl { get; set; } = "";
        public string DeviceId { get; set; } = "";
        public string AgentVersion { get; set; } = "1.0.0";
        public TimeSpan HeartbeatInterval { get; set; } = TimeSpan.FromSeconds(60);
        public TimeSpan JobPollInterval { get; set; } = TimeSpan.FromSeconds(30);
        public string LogLevel { get; set; } = "INFO";
        public int OfflineQueueMaxItems { get; set; } = 500;
        public TimeSpan RetryInitialBackoff { get; set; } = TimeSpan.FromSeconds(5);
        public TimeSpan RetryMaxBackoff { get; set; } = TimeSpan.FromMinutes(10);
    }

    /// <summary>
    /// Exactly the lifecycle states in ARCHITECTURE.md §3 — deliberately
    /// does NOT include anything resembling "Certified". Certification is a
    /// backend-only concept.
    /// </summary>
    public enum AgentState
    {
        Uninstalled,
        Installed,
        EnrollmentPending,
        Enrolled,
        Online,
        JobReceived,
        Collecting,
        ResultSubmitted,
        Waiting,
        RemediationRequested,
        RemediationExecuted,
        ReVerification
    }
}
