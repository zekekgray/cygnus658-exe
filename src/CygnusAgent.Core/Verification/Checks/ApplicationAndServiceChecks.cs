using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Verification.Checks
{
    /// <summary>
    /// Reports whether a named application appears installed. The real
    /// enumeration (Windows Installer / registry Uninstall keys) belongs in
    /// Infrastructure (Windows-specific); this class takes an injected
    /// lookup function so Core stays platform-agnostic and testable.
    /// </summary>
    public sealed class ApplicationStateCheck : IVerificationCheck
    {
        private readonly Func<string, bool> _isInstalledLookup;

        public ApplicationStateCheck(Func<string, bool> isInstalledLookup) => _isInstalledLookup = isInstalledLookup;

        public string Type => "APPLICATION_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            if (!request.Parameters.TryGetValue("applicationName", out var appName) || string.IsNullOrWhiteSpace(appName))
            {
                return Task.FromResult(new CheckResult
                {
                    CheckId = request.CheckId,
                    Status = CheckStatus.Error,
                    ErrorMessage = "Missing required parameter: applicationName",
                    StartedAt = started,
                    CompletedAt = DateTimeOffset.UtcNow
                });
            }

            var installed = _isInstalledLookup(appName);
            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = installed ? CheckStatus.Pass : CheckStatus.Fail,
                ObservedState = new Dictionary<string, object> { ["applicationName"] = appName, ["installed"] = installed },
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }

    /// <summary>Reports a Windows service's running state. Real service-control
    /// queries live in Infrastructure; injected here as a lookup for testability.</summary>
    public sealed class ServiceStateCheck : IVerificationCheck
    {
        private readonly Func<string, string?> _serviceStatusLookup; // returns e.g. "Running"/"Stopped"/null if absent

        public ServiceStateCheck(Func<string, string?> serviceStatusLookup) => _serviceStatusLookup = serviceStatusLookup;

        public string Type => "SERVICE_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            if (!request.Parameters.TryGetValue("serviceName", out var svc) || string.IsNullOrWhiteSpace(svc))
            {
                return Task.FromResult(new CheckResult
                {
                    CheckId = request.CheckId, Status = CheckStatus.Error,
                    ErrorMessage = "Missing required parameter: serviceName",
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow
                });
            }

            var status = _serviceStatusLookup(svc);
            var checkStatus = status == null ? CheckStatus.NotApplicable
                : request.Parameters.TryGetValue("expectedStatus", out var expected) && !string.Equals(expected, status, StringComparison.OrdinalIgnoreCase)
                    ? CheckStatus.Fail
                    : CheckStatus.Pass;

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = checkStatus,
                ObservedState = new Dictionary<string, object> { ["serviceName"] = svc, ["status"] = status ?? "NOT_FOUND" },
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }

    /// <summary>
    /// Reports whether a specific file exists / matches an expected hash.
    /// Only paths explicitly named by the job are touched — this check never
    /// enumerates arbitrary directories on its own initiative.
    /// </summary>
    public sealed class FileStateCheck : IVerificationCheck
    {
        public string Type => "FILE_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            if (!request.Parameters.TryGetValue("path", out var path) || string.IsNullOrWhiteSpace(path))
            {
                return Task.FromResult(new CheckResult
                {
                    CheckId = request.CheckId, Status = CheckStatus.Error,
                    ErrorMessage = "Missing required parameter: path",
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow
                });
            }

            var observed = new Dictionary<string, object> { ["path"] = path };
            var exists = File.Exists(path);
            observed["exists"] = exists;

            var status = CheckStatus.Pass;

            if (exists && request.Parameters.TryGetValue("expectedSha256", out var expectedHash) && !string.IsNullOrWhiteSpace(expectedHash))
            {
                using var stream = File.OpenRead(path);
                var actualHash = Convert.ToHexString(SHA256.HashData(stream));
                observed["sha256"] = actualHash;
                status = string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase) ? CheckStatus.Pass : CheckStatus.Fail;
            }
            else if (request.Parameters.TryGetValue("expectedExists", out var expectedExistsRaw)
                     && bool.TryParse(expectedExistsRaw, out var expectedExists))
            {
                status = exists == expectedExists ? CheckStatus.Pass : CheckStatus.Fail;
            }

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = status,
                ObservedState = observed,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }

    /// <summary>Reports whether a directory exists and, optionally, whether it's empty.</summary>
    public sealed class DirectoryStateCheck : IVerificationCheck
    {
        public string Type => "DIRECTORY_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            if (!request.Parameters.TryGetValue("path", out var path) || string.IsNullOrWhiteSpace(path))
            {
                return Task.FromResult(new CheckResult
                {
                    CheckId = request.CheckId, Status = CheckStatus.Error,
                    ErrorMessage = "Missing required parameter: path",
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow
                });
            }

            var exists = Directory.Exists(path);
            var observed = new Dictionary<string, object> { ["path"] = path, ["exists"] = exists };
            var status = CheckStatus.Pass;

            if (exists && request.Parameters.TryGetValue("expectEmpty", out var expectEmptyRaw)
                       && bool.TryParse(expectEmptyRaw, out var expectEmpty))
            {
                var isEmpty = !Directory.EnumerateFileSystemEntries(path).Any();
                observed["isEmpty"] = isEmpty;
                status = isEmpty == expectEmpty ? CheckStatus.Pass : CheckStatus.Fail;
            }

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = exists ? status : CheckStatus.NotApplicable,
                ObservedState = observed,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }
}
