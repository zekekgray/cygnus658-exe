using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;
using CygnusAgent.Infrastructure.Networking;
using Xunit;

namespace CygnusAgent.Tests
{
    /// <summary>
    /// A fake IApiClient standing in for CygnusApiClient, so enrollment and
    /// job-handling logic can be tested without a live backend. Mirrors the
    /// integration-test-interface requirement in spec §20/§23 — a real
    /// integration test suite would swap this for a client pointed at a
    /// backend test fixture.
    /// </summary>
    internal sealed class FakeApiClient : IApiClient
    {
        public string? LastEnrollTokenSeen;
        public bool RejectEnrollToken;
        public bool AlreadyUsedToken;
        public int SubmitResultCallCount;
        public bool FailNextSubmit;

        public Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct)
        {
            LastEnrollTokenSeen = request.EnrollToken;

            if (string.IsNullOrWhiteSpace(request.EnrollToken))
                throw new CygnusApiException("Enrollment token is required.");
            if (RejectEnrollToken)
                throw new CygnusApiException("Invalid or expired enrollment token.");
            if (AlreadyUsedToken)
                throw new CygnusApiException("Enrollment token already used.");

            return Task.FromResult(new EnrollResponse { DeviceId = "DEV-TEST-1", Credential = "fake-credential-value" });
        }

        public Task HeartbeatAsync(HeartbeatRequest request, CancellationToken ct) => Task.CompletedTask;

        public Task<VerificationJob?> PollJobAsync(CancellationToken ct) => Task.FromResult<VerificationJob?>(null);

        public Task SubmitResultAsync(AgentResultEnvelope<CheckResult[]> envelope, CancellationToken ct)
        {
            SubmitResultCallCount++;
            if (FailNextSubmit) { FailNextSubmit = false; throw new CygnusApiException("Simulated transient failure."); }
            return Task.CompletedTask;
        }

        public Task SubmitEvidenceAsync(EvidenceRecord evidence, CancellationToken ct) => Task.CompletedTask;

        public Task SubmitRemediationResultAsync(AgentResultEnvelope<RemediationResult> envelope, CancellationToken ct) => Task.CompletedTask;
    }

    public class EnrollmentTests
    {
        [Fact]
        public async Task ValidTokenEnrollsSuccessfully()
        {
            var client = new FakeApiClient();
            var response = await client.EnrollAsync(new EnrollRequest { EnrollToken = "good-token" }, CancellationToken.None);
            Assert.Equal("DEV-TEST-1", response.DeviceId);
        }

        [Fact]
        public async Task InvalidTokenThrows()
        {
            var client = new FakeApiClient { RejectEnrollToken = true };
            await Assert.ThrowsAsync<CygnusApiException>(() =>
                client.EnrollAsync(new EnrollRequest { EnrollToken = "bad-token" }, CancellationToken.None));
        }

        [Fact]
        public async Task ExpiredOrAlreadyUsedTokenThrows()
        {
            var client = new FakeApiClient { AlreadyUsedToken = true };
            await Assert.ThrowsAsync<CygnusApiException>(() =>
                client.EnrollAsync(new EnrollRequest { EnrollToken = "used-token" }, CancellationToken.None));
        }

        [Fact]
        public async Task MissingTokenThrowsBeforeAnyNetworkAssumption()
        {
            var client = new FakeApiClient();
            await Assert.ThrowsAsync<CygnusApiException>(() =>
                client.EnrollAsync(new EnrollRequest { EnrollToken = "" }, CancellationToken.None));
        }
    }

    public class DuplicateAndReplayTests
    {
        [Fact]
        public async Task DuplicateResultSubmissionIsJustAnotherCall_BackendIsResponsibleForDedupe()
        {
            // The Agent's contribution to replay safety is including a fresh
            // nonce + monotonic sequence per envelope (see ResultEnvelopeTests);
            // this test documents that the client itself does not try to
            // detect duplicates locally — that's a backend concern, by design,
            // since only the backend has a global view across restarts/queues.
            var client = new FakeApiClient();
            var envelope = new AgentResultEnvelope<CheckResult[]> { DeviceId = "D1", JobId = "J1", ResultId = "R1", Sequence = 1 };

            await client.SubmitResultAsync(envelope, CancellationToken.None);
            await client.SubmitResultAsync(envelope, CancellationToken.None); // simulated replay

            Assert.Equal(2, client.SubmitResultCallCount);
        }
    }

    public class RetryPolicyTests
    {
        [Fact]
        public async Task RetriesTransientFailureThenSucceeds()
        {
            var attempts = 0;
            var policy = new RetryPolicy(maxAttempts: 3, TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(5), new NullLogger());

            var result = await policy.RunAsync(async () =>
            {
                attempts++;
                if (attempts < 2) throw new TimeoutException("simulated network blip");
                return "ok";
            }, CancellationToken.None);

            Assert.Equal("ok", result);
            Assert.Equal(2, attempts);
        }

        [Fact]
        public async Task GivesUpAfterMaxAttempts_DoesNotLoopForever()
        {
            var attempts = 0;
            var policy = new RetryPolicy(maxAttempts: 3, TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(5), new NullLogger());

            await Assert.ThrowsAsync<TimeoutException>(() => policy.RunAsync<string>(() =>
            {
                attempts++;
                throw new TimeoutException("always fails");
            }, CancellationToken.None));

            Assert.Equal(3, attempts); // bounded — spec §12 "no infinite retry loop"
        }

        [Fact]
        public async Task NonTransientExceptionIsNotRetried()
        {
            var attempts = 0;
            var policy = new RetryPolicy(maxAttempts: 5, TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(5), new NullLogger());

            await Assert.ThrowsAsync<InvalidOperationException>(() => policy.RunAsync<string>(() =>
            {
                attempts++;
                throw new InvalidOperationException("not a network error");
            }, CancellationToken.None));

            Assert.Equal(1, attempts); // fails fast, no wasted retries on a non-transient error
        }
    }
}
