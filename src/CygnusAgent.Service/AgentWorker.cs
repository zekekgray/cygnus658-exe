using System;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;
using CygnusAgent.Core.Remediation;
using CygnusAgent.Core.Security;
using CygnusAgent.Core.Verification;
using Microsoft.Extensions.Hosting;

namespace CygnusAgent.Service
{
    /// <summary>
    /// Drives the lifecycle described in docs/ARCHITECTURE.md §3. This class
    /// owns state transitions; it never itself decides pass/fail policy or
    /// certification — those results are just forwarded to the backend.
    /// </summary>
    public sealed class AgentWorker : BackgroundService
    {
        private readonly AgentConfig _config;
        private readonly IApiClient _api;
        private readonly ICredentialStore _credentialStore;
        private readonly DeviceIdentityProvider _identity;
        private readonly ResultEnvelopeFactory _envelopeFactory;
        private readonly IOfflineQueue<AgentResultEnvelope<CheckResult[]>> _resultQueue;
        private readonly CheckEngine _checkEngine;
        private readonly RemediationEngine _remediationEngine;
        private readonly IAgentLogger _logger;

        private AgentState _state = AgentState.Installed;

        public AgentWorker(
            AgentConfig config,
            IApiClient api,
            ICredentialStore credentialStore,
            DeviceIdentityProvider identity,
            ResultEnvelopeFactory envelopeFactory,
            IOfflineQueue<AgentResultEnvelope<CheckResult[]>> resultQueue,
            CheckEngine checkEngine,
            RemediationEngine remediationEngine,
            IAgentLogger logger)
        {
            _config = config;
            _api = api;
            _credentialStore = credentialStore;
            _identity = identity;
            _envelopeFactory = envelopeFactory;
            _resultQueue = resultQueue;
            _checkEngine = checkEngine;
            _remediationEngine = remediationEngine;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            await EnsureEnrolledAsync(stoppingToken);

            var lastHeartbeat = DateTimeOffset.MinValue;
            var lastPoll = DateTimeOffset.MinValue;

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await DrainOfflineQueueAsync(stoppingToken);

                    var now = DateTimeOffset.UtcNow;
                    if (now - lastHeartbeat >= _config.HeartbeatInterval)
                    {
                        await SendHeartbeatAsync(stoppingToken);
                        lastHeartbeat = now;
                    }

                    if (now - lastPoll >= _config.JobPollInterval)
                    {
                        await PollAndRunJobAsync(stoppingToken);
                        lastPoll = now;
                    }
                }
                catch (Exception ex)
                {
                    _logger.Error("worker.loop_error", new { error = ex.Message });
                }

                await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken);
            }
        }

        private async Task EnsureEnrolledAsync(CancellationToken ct)
        {
            if (_credentialStore.TryLoad(out _))
            {
                _state = AgentState.Enrolled;
                return;
            }

            var enrollToken = Environment.GetEnvironmentVariable("CYGNUS_ENROLL_TOKEN");
            if (string.IsNullOrWhiteSpace(enrollToken))
            {
                _logger.Critical("enrollment.missing_token",
                    new { message = "No stored credential and no enrollment token provided. Run the installer with /enroll:<token>." });
                return; // stays in Installed state; loop above will keep retrying enrollment on restart
            }

            _state = AgentState.EnrollmentPending;
            var publicKey = _identity.GetOrCreatePublicKey();

            try
            {
                var response = await _api.EnrollAsync(new EnrollRequest
                {
                    EnrollToken = enrollToken,
                    Hostname = Environment.MachineName,
                    OsVersion = Environment.OSVersion.VersionString,
                    AgentVersion = _config.AgentVersion,
                    PublicKeyBase64 = publicKey
                }, ct);

                _credentialStore.Save(response.Credential);
                _config.DeviceId = response.DeviceId;
                // Enrollment token is intentionally never persisted anywhere —
                // it only ever existed in the environment variable / installer
                // argument that supplied it, and is discarded here.
                _state = AgentState.Enrolled;
                _logger.Info("enrollment.completed", new { deviceId = response.DeviceId });
            }
            catch (Exception ex)
            {
                _logger.Error("enrollment.failed", new { error = ex.Message });
            }
        }

        private async Task SendHeartbeatAsync(CancellationToken ct)
        {
            try
            {
                await _api.HeartbeatAsync(new HeartbeatRequest
                {
                    DeviceId = _config.DeviceId,
                    AgentVersion = _config.AgentVersion,
                    OsVersion = Environment.OSVersion.VersionString,
                    LastJobState = _state.ToString()
                }, ct);
                if (_state == AgentState.Enrolled) _state = AgentState.Online;
            }
            catch (Exception ex)
            {
                _logger.Warn("heartbeat.failed", new { error = ex.Message });
            }
        }

        private async Task PollAndRunJobAsync(CancellationToken ct)
        {
            VerificationJob? job;
            try
            {
                job = await _api.PollJobAsync(ct);
            }
            catch (Exception ex)
            {
                _logger.Warn("job.poll_failed", new { error = ex.Message });
                return;
            }

            if (job is null) return;

            if (job.IsExpired(DateTimeOffset.UtcNow))
            {
                _logger.Warn("job.expired", new { job.JobId, job.ExpiresAt });
                return;
            }

            _state = AgentState.JobReceived;
            await RunVerificationAsync(job, ct);
        }

        private async Task RunVerificationAsync(VerificationJob job, CancellationToken ct)
        {
            _state = AgentState.Collecting;
            var results = await _checkEngine.RunJobAsync(job, ct);

            var envelope = _envelopeFactory.Wrap(job.DeviceId, job.JobId, results.ToArray());
            await SubmitOrQueueAsync(envelope, ct);
            _state = AgentState.ResultSubmitted;

            // NOTE: remediation is driven by a subsequent job the backend
            // sends (RemediationRequested), not decided here — the Agent
            // reports what it observed and waits. When a remediation job
            // arrives via the same PollAndRunJobAsync path in a future poll,
            // route it to RunRemediationAsync instead of RunVerificationAsync
            // based on the job's Objective/shape (left as an extension point:
            // the current VerificationJob model covers checks only, per the
            // spec's example payload — extend with an optional
            // RemediationAction[] field when the backend starts sending them).

            _state = AgentState.Waiting;
        }

        private async Task RunRemediationAsync(RemediationAction action, CancellationToken ct)
        {
            _state = AgentState.RemediationRequested;
            var result = await _remediationEngine.ExecuteAsync(action, ct);
            _state = AgentState.RemediationExecuted;

            var envelope = _envelopeFactory.Wrap(action.JobId.Split(':')[0], action.JobId, result);
            try { await _api.SubmitRemediationResultAsync(envelope, ct); }
            catch (Exception ex) { _logger.Error("remediation.submit_failed", new { error = ex.Message }); }

            _state = AgentState.ReVerification;
            // Re-verification: caller should re-invoke RunVerificationAsync
            // with the original job's checks once this returns.
        }

        private async Task SubmitOrQueueAsync(AgentResultEnvelope<CheckResult[]> envelope, CancellationToken ct)
        {
            try
            {
                await _api.SubmitResultAsync(envelope, ct);
            }
            catch (Exception ex)
            {
                _logger.Warn("result.submit_failed_queuing", new { error = ex.Message });
                if (!_resultQueue.TryEnqueue(envelope))
                    _logger.Error("result.queue_full_dropping", new { envelope.ResultId });
            }
        }

        private async Task DrainOfflineQueueAsync(CancellationToken ct)
        {
            while (_resultQueue.TryPeek(out var envelope))
            {
                try
                {
                    await _api.SubmitResultAsync(envelope, ct);
                    _resultQueue.Dequeue(); // only remove after confirmed acceptance
                }
                catch
                {
                    break; // still offline — stop draining, try again next loop
                }
            }
        }
    }
}
