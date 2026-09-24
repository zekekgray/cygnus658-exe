using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Infrastructure.Networking
{
    /// <summary>
    /// Talks to CYGNUS over HTTPS. Today's backend is a single Apps Script
    /// Web App with one {action, ...} JSON body shape (see
    /// docs/API_CONTRACT.md) — AgentEndpoints below is the one place that
    /// maps the conceptual /agent/* endpoints onto that router's `action`
    /// strings, so swapping to a dedicated REST backend later only touches
    /// this file.
    ///
    /// TODO: CONNECT TO BACKEND — set the real deployed Apps Script Web App
    /// URL via AgentConfig.ApiBaseUrl at deploy time. Never hardcode it here.
    /// </summary>
    public sealed class CygnusApiClient : IApiClient
    {
        private readonly HttpClient _http;
        private readonly ICredentialStore _credentialStore;
        private readonly IAgentLogger _logger;
        private readonly RetryPolicy _retry;

        public CygnusApiClient(HttpClient http, ICredentialStore credentialStore, IAgentLogger logger, RetryPolicy retry)
        {
            _http = http; // HttpClient.BaseAddress must be set to AgentConfig.ApiBaseUrl by the composition root.
            _credentialStore = credentialStore;
            _logger = logger;
            _retry = retry;
        }

        public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct)
        {
            // Maps to agent.enroll (new action — see API_CONTRACT.md gap notes).
            var body = new
            {
                action = "agent.enroll",
                enrollToken = request.EnrollToken,
                hostname = request.Hostname,
                osVersion = request.OsVersion,
                agentVersion = request.AgentVersion,
                publicKey = request.PublicKeyBase64
            };

            var data = await PostAsync<EnrollResponse>(body, includeCredential: false, ct);
            return data ?? throw new InvalidOperationException("Enrollment returned no data.");
        }

        public async Task HeartbeatAsync(HeartbeatRequest request, CancellationToken ct)
        {
            var body = new
            {
                action = "agent.heartbeat",
                deviceId = request.DeviceId,
                agentVersion = request.AgentVersion,
                osVersion = request.OsVersion,
                lastJobState = request.LastJobState
            };
            await PostAsync<JsonElement?>(body, includeCredential: true, ct);
        }

        public async Task<VerificationJob?> PollJobAsync(CancellationToken ct)
        {
            var body = new { action = "agent.checkCommands" };
            var data = await PostAsync<PollJobResponse>(body, includeCredential: true, ct);
            return data?.Job;
        }

        public async Task SubmitResultAsync(AgentResultEnvelope<CheckResult[]> envelope, CancellationToken ct)
        {
            var body = new { action = "agent.submitScanResult", envelope };
            await PostAsync<JsonElement?>(body, includeCredential: true, ct);
        }

        public async Task SubmitEvidenceAsync(EvidenceRecord evidence, CancellationToken ct)
        {
            var body = new { action = "agent.submitEvidence", evidence };
            await PostAsync<JsonElement?>(body, includeCredential: true, ct);
        }

        public async Task SubmitRemediationResultAsync(AgentResultEnvelope<RemediationResult> envelope, CancellationToken ct)
        {
            var body = new { action = "agent.remediationResult", envelope }; // new action — see API_CONTRACT.md
            await PostAsync<JsonElement?>(body, includeCredential: true, ct);
        }

        private async Task<T?> PostAsync<T>(object body, bool includeCredential, CancellationToken ct)
        {
            return await _retry.RunAsync(async () =>
            {
                // credential is attached by an outgoing-request hook (see
                // CredentialAttachingHandler) rather than merged into `body`
                // here, so every call path gets it uniformly and it's never
                // accidentally logged as part of a request-body dump.
                using var response = await _http.PostAsJsonAsync("", body, ct);
                response.EnsureSuccessStatusCode();

                var envelope = await response.Content.ReadFromJsonAsync<ApiEnvelope<T>>(cancellationToken: ct);
                if (envelope is null) throw new InvalidOperationException("Empty response from backend.");
                if (!envelope.Ok) throw new CygnusApiException(envelope.Error ?? "Unknown backend error.");
                return envelope.Data;
            }, ct);
        }

        private sealed class ApiEnvelope<T>
        {
            public bool Ok { get; set; }
            public T? Data { get; set; }
            public string? Error { get; set; }
        }

        private sealed class PollJobResponse
        {
            public VerificationJob? Job { get; set; }
        }
    }

    public sealed class CygnusApiException : Exception
    {
        public CygnusApiException(string message) : base(message) { }
    }
}
