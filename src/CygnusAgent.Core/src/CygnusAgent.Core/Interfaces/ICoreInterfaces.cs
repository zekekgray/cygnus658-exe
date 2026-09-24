using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Interfaces
{
    /// <summary>
    /// One allowlisted verification check. Implementations are registered by
    /// a fixed "Type" string in CheckEngine's registry — there is no path
    /// from network input to arbitrary code execution.
    /// </summary>
    public interface IVerificationCheck
    {
        /// <summary>The Type string this check answers to, e.g. "OS_INFO".</summary>
        string Type { get; }

        Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct);
    }

    /// <summary>
    /// One allowlisted remediation action. Same closed-registry pattern as
    /// IVerificationCheck. Every implementation MUST validate its own
    /// parameters (e.g. path prefixes) before touching the system.
    /// </summary>
    public interface IRemediationAction
    {
        string ActionType { get; }

        Task<RemediationResult> ExecuteAsync(RemediationAction action, CancellationToken ct);
    }

    /// <summary>
    /// The only door to the network. Every method maps to an endpoint in
    /// docs/API_CONTRACT.md.
    /// </summary>
    public interface IApiClient
    {
        Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct);
        Task HeartbeatAsync(HeartbeatRequest request, CancellationToken ct);
        Task<VerificationJob?> PollJobAsync(CancellationToken ct);
        Task SubmitResultAsync(AgentResultEnvelope<CheckResult[]> envelope, CancellationToken ct);
        Task SubmitEvidenceAsync(EvidenceRecord evidence, CancellationToken ct);
        Task SubmitRemediationResultAsync(AgentResultEnvelope<RemediationResult> envelope, CancellationToken ct);
    }

    public sealed class EnrollRequest
    {
        public string EnrollToken { get; set; } = "";
        public string Hostname { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string AgentVersion { get; set; } = "";
        public string PublicKeyBase64 { get; set; } = "";
    }

    public sealed class EnrollResponse
    {
        public string DeviceId { get; set; } = "";
        public string Credential { get; set; } = "";
    }

    public sealed class HeartbeatRequest
    {
        public string DeviceId { get; set; } = "";
        public string AgentVersion { get; set; } = "";
        public string OsVersion { get; set; } = "";
        public string LastJobState { get; set; } = "";
    }

    /// <summary>
    /// DPAPI-backed (or platform equivalent) storage for the one secret this
    /// Agent holds long-term: its credential. Never backed by plaintext
    /// config files.
    /// </summary>
    public interface ICredentialStore
    {
        bool TryLoad(out string credential);
        void Save(string credential);
        void Clear();
    }

    /// <summary>Bounded, persisted queue for results pending submission while offline.</summary>
    public interface IOfflineQueue<T>
    {
        bool TryEnqueue(T item);
        bool TryPeek(out T item);
        void Dequeue();
        int Count { get; }
    }

    public interface IAgentLogger
    {
        void Trace(string evt, object? data = null);
        void Debug(string evt, object? data = null);
        void Info(string evt, object? data = null);
        void Warn(string evt, object? data = null);
        void Error(string evt, object? data = null);
        void Critical(string evt, object? data = null);
    }
}
