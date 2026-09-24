using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;
using CygnusAgent.Core.Remediation;
using CygnusAgent.Core.Remediation.Actions;
using CygnusAgent.Core.Security;
using CygnusAgent.Core.Verification;
using CygnusAgent.Core.Verification.Checks;
using CygnusAgent.Infrastructure.Storage;
using Xunit;

namespace CygnusAgent.Tests
{
    // A minimal in-memory logger + credential store so Core can be tested
    // without touching the filesystem or Windows APIs.
    internal sealed class NullLogger : IAgentLogger
    {
        public void Trace(string e, object? d = null) { }
        public void Debug(string e, object? d = null) { }
        public void Info(string e, object? d = null) { }
        public void Warn(string e, object? d = null) { }
        public void Error(string e, object? d = null) { }
        public void Critical(string e, object? d = null) { }
    }

    internal sealed class InMemoryCredentialStore : ICredentialStore
    {
        private string? _value;
        public bool TryLoad(out string credential) { credential = _value ?? ""; return _value != null; }
        public void Save(string credential) => _value = credential;
        public void Clear() => _value = null;
    }

    public class CheckEngineTests
    {
        [Fact]
        public async Task RunsRegisteredCheckAndReturnsPass()
        {
            var engine = new CheckEngine(new[] { new OsInfoCheck() }, new NullLogger());
            var job = new VerificationJob
            {
                JobId = "J1", DeviceId = "D1", Checks = { new CheckRequest { CheckId = "C1", Type = "OS_INFO" } }
            };

            var results = await engine.RunJobAsync(job, CancellationToken.None);

            Assert.Single(results);
            Assert.Equal(CheckStatus.Pass, results[0].Status);
        }

        [Fact]
        public async Task UnsupportedCheckTypeProducesErrorNotException()
        {
            var engine = new CheckEngine(Array.Empty<IVerificationCheck>(), new NullLogger());
            var job = new VerificationJob
            {
                JobId = "J1", DeviceId = "D1",
                Checks = { new CheckRequest { CheckId = "C1", Type = "SOMETHING_NOT_ALLOWLISTED" } }
            };

            var results = await engine.RunJobAsync(job, CancellationToken.None);

            Assert.Single(results);
            Assert.Equal(CheckStatus.Error, results[0].Status);
            Assert.Contains("Unsupported", results[0].ErrorMessage);
        }

        [Fact]
        public async Task MalformedJobWithMissingParameterIsErrorNotCrash()
        {
            var engine = new CheckEngine(new IVerificationCheck[] { new FileStateCheck() }, new NullLogger());
            var job = new VerificationJob
            {
                JobId = "J1", DeviceId = "D1",
                Checks = { new CheckRequest { CheckId = "C1", Type = "FILE_STATE" /* no "path" param */ } }
            };

            var results = await engine.RunJobAsync(job, CancellationToken.None);
            Assert.Equal(CheckStatus.Error, results[0].Status);
        }

        [Fact]
        public void JobPastExpiresAtIsExpired()
        {
            var job = new VerificationJob { ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(-1) };
            Assert.True(job.IsExpired(DateTimeOffset.UtcNow));
        }
    }

    public class RemediationEngineTests
    {
        [Fact]
        public async Task UnsupportedActionTypeFailsHard()
        {
            var engine = new RemediationEngine(Array.Empty<IRemediationAction>(), new NullLogger());
            var result = await engine.ExecuteAsync(
                new RemediationAction { ActionId = "A1", JobId = "J1", ActionType = "RUN_ARBITRARY_SHELL" },
                CancellationToken.None);

            Assert.Equal(RemediationOutcome.Failed, result.Result);
            Assert.Equal("UNSUPPORTED_ACTION_TYPE", result.ErrorCode);
        }

        [Fact]
        public async Task DeleteApprovedPath_RejectsPathOutsideAllowlist()
        {
            var action = new DeleteApprovedPathAction(new[] { @"C:\CygnusApproved\Quarantine" });
            var engine = new RemediationEngine(new[] { (IRemediationAction)action }, new NullLogger());

            var result = await engine.ExecuteAsync(new RemediationAction
            {
                ActionId = "A1", JobId = "J1", ActionType = "DELETE_APPROVED_PATH",
                Parameters = { ["path"] = @"C:\Windows\System32\config\SAM" } // classic traversal target
            }, CancellationToken.None);

            Assert.Equal(RemediationOutcome.Failed, result.Result);
            Assert.Equal("PATH_NOT_APPROVED", result.ErrorCode);
        }

        [Fact]
        public async Task DeleteApprovedPath_AllowsPathInsideAllowlist_ButMissingFileIsSkippedNotFailed()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "CygnusApproved_" + Guid.NewGuid());
            Directory.CreateDirectory(tempDir);
            try
            {
                var action = new DeleteApprovedPathAction(new[] { tempDir });
                var result = await action.ExecuteAsync(new RemediationAction
                {
                    ActionId = "A1", JobId = "J1", ActionType = "DELETE_APPROVED_PATH",
                    Parameters = { ["path"] = Path.Combine(tempDir, "does-not-exist.txt") }
                }, CancellationToken.None);

                Assert.Equal(RemediationOutcome.Skipped, result.Result);
            }
            finally { Directory.Delete(tempDir, true); }
        }
    }

    public class OfflineQueueTests
    {
        [Fact]
        public void EnqueueRespectsBoundedCapacity()
        {
            var dir = Path.Combine(Path.GetTempPath(), "CygnusQueueTest_" + Guid.NewGuid());
            var queue = new FileOfflineQueue<string>(dir, maxItems: 2);
            try
            {
                Assert.True(queue.TryEnqueue("a"));
                Assert.True(queue.TryEnqueue("b"));
                Assert.False(queue.TryEnqueue("c")); // at capacity — must reject, not grow unbounded
                Assert.Equal(2, queue.Count);
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void DequeueOnlyRemovesOldestAfterExplicitCall()
        {
            var dir = Path.Combine(Path.GetTempPath(), "CygnusQueueTest_" + Guid.NewGuid());
            var queue = new FileOfflineQueue<string>(dir, maxItems: 10);
            try
            {
                queue.TryEnqueue("first");
                queue.TryEnqueue("second");

                Assert.True(queue.TryPeek(out var peeked));
                Assert.Equal("first", peeked);
                Assert.Equal(2, queue.Count); // peek must not remove

                queue.Dequeue();
                Assert.Equal(1, queue.Count);
                Assert.True(queue.TryPeek(out var next));
                Assert.Equal("second", next);
            }
            finally { Directory.Delete(dir, true); }
        }

        [Fact]
        public void QueueSurvivesRecreation_SimulatingServiceRestart()
        {
            var dir = Path.Combine(Path.GetTempPath(), "CygnusQueueTest_" + Guid.NewGuid());
            try
            {
                var queue1 = new FileOfflineQueue<string>(dir, maxItems: 10);
                queue1.TryEnqueue("persisted-item");

                var queue2 = new FileOfflineQueue<string>(dir, maxItems: 10); // fresh instance, same dir
                Assert.Equal(1, queue2.Count);
                Assert.True(queue2.TryPeek(out var item));
                Assert.Equal("persisted-item", item);
            }
            finally { Directory.Delete(dir, true); }
        }
    }

    public class SequenceStoreTests
    {
        [Fact]
        public void SequenceNeverGoesBackwardsAcrossRestart()
        {
            var path = Path.Combine(Path.GetTempPath(), "seq_" + Guid.NewGuid() + ".txt");
            try
            {
                var store1 = new FileSequenceStore(path);
                var s1 = store1.NextSequence("D1");
                var s2 = store1.NextSequence("D1");

                var store2 = new FileSequenceStore(path); // simulates restart
                var s3 = store2.NextSequence("D1");

                Assert.True(s2 > s1);
                Assert.True(s3 > s2); // must not reset to 1 after "restart"
            }
            finally { if (File.Exists(path)) File.Delete(path); }
        }
    }

    public class ResultEnvelopeTests
    {
        [Fact]
        public void EnvelopeIncludesReplayProtectionFields()
        {
            var credStore = new InMemoryCredentialStore();
            var identity = new DeviceIdentityProvider(credStore);
            identity.GetOrCreatePublicKey(); // ensures a keypair exists

            var seqPath = Path.Combine(Path.GetTempPath(), "seq_" + Guid.NewGuid() + ".txt");
            var factory = new ResultEnvelopeFactory(identity, new FileSequenceStore(seqPath));

            var envelope = factory.Wrap("D1", "J1", new[] { new CheckResult { CheckId = "C1", Status = CheckStatus.Pass } });

            Assert.Equal("D1", envelope.DeviceId);
            Assert.Equal("J1", envelope.JobId);
            Assert.False(string.IsNullOrEmpty(envelope.Nonce));
            Assert.True(envelope.Sequence > 0);
            Assert.False(string.IsNullOrEmpty(envelope.PayloadHash));

            if (File.Exists(seqPath)) File.Delete(seqPath);
        }

        [Fact]
        public void TwoEnvelopesForSameJobHaveDifferentNoncesAndIncreasingSequence()
        {
            var credStore = new InMemoryCredentialStore();
            var identity = new DeviceIdentityProvider(credStore);
            identity.GetOrCreatePublicKey();

            var seqPath = Path.Combine(Path.GetTempPath(), "seq_" + Guid.NewGuid() + ".txt");
            var factory = new ResultEnvelopeFactory(identity, new FileSequenceStore(seqPath));

            var e1 = factory.Wrap("D1", "J1", "payload-a");
            var e2 = factory.Wrap("D1", "J1", "payload-a"); // a naive replay attempt of the same payload

            Assert.NotEqual(e1.Nonce, e2.Nonce);
            Assert.True(e2.Sequence > e1.Sequence);

            if (File.Exists(seqPath)) File.Delete(seqPath);
        }
    }

    public class DeviceIdentityTests
    {
        [Fact]
        public void PublicKeyIsStableAcrossCalls_PrivateKeyNeverExposed()
        {
            var store = new InMemoryCredentialStore();
            var identity = new DeviceIdentityProvider(store);

            var pk1 = identity.GetOrCreatePublicKey();
            var pk2 = identity.GetOrCreatePublicKey();

            Assert.Equal(pk1, pk2); // same identity on repeated calls, not regenerated each time
            Assert.True(store.TryLoad(out var stored));
            Assert.Contains("PRIVATE KEY", stored); // the store holds the private key material...
            Assert.DoesNotContain(pk1, stored);      // ...which is a different value than the public key returned to callers
        }

        [Fact]
        public void SigningFailsCleanlyBeforeIdentityExists()
        {
            var store = new InMemoryCredentialStore();
            var identity = new DeviceIdentityProvider(store);
            Assert.Throws<InvalidOperationException>(() => identity.SignHash(new byte[32]));
        }
    }
}
