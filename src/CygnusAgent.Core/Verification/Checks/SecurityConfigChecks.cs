using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Verification.Checks
{
    /// <summary>
    /// Reports whether the system/boot volume is encrypted (e.g. BitLocker).
    /// The real query (WMI Win32_EncryptableVolume, or `manage-bde -status`)
    /// is Windows-specific and lives behind this injected lookup so Core
    /// stays testable without a live Windows box.
    /// </summary>
    public sealed class DiskEncryptionCheck : IVerificationCheck
    {
        private readonly Func<string, string?> _encryptionStatusLookup; // volume -> "Encrypted"/"NotEncrypted"/null=unsupported

        public DiskEncryptionCheck(Func<string, string?> encryptionStatusLookup) => _encryptionStatusLookup = encryptionStatusLookup;

        public string Type => "DISK_ENCRYPTION_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            var volume = request.Parameters.GetValueOrDefault("volume", "C:");
            var status = _encryptionStatusLookup(volume);

            var checkStatus = status switch
            {
                null => CheckStatus.NotApplicable,
                "Encrypted" => CheckStatus.Pass,
                _ => CheckStatus.Fail
            };

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = checkStatus,
                ObservedState = new Dictionary<string, object> { ["volume"] = volume, ["status"] = status ?? "UNSUPPORTED" },
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }

    /// <summary>
    /// Generic "selected security configuration state" check — e.g. firewall
    /// enabled, a specific registry value, screen-lock timeout. Takes a
    /// settingKey/expectedValue pair and an injected reader so the actual
    /// Windows API surface (registry, firewall API, GPO state) can be swapped
    /// in per-deployment without touching Core.
    /// </summary>
    public sealed class SecurityConfigurationStateCheck : IVerificationCheck
    {
        private readonly Func<string, string?> _settingReader;

        public SecurityConfigurationStateCheck(Func<string, string?> settingReader) => _settingReader = settingReader;

        public string Type => "SECURITY_CONFIGURATION_STATE";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            if (!request.Parameters.TryGetValue("settingKey", out var key) || string.IsNullOrWhiteSpace(key))
            {
                return Task.FromResult(new CheckResult
                {
                    CheckId = request.CheckId, Status = CheckStatus.Error,
                    ErrorMessage = "Missing required parameter: settingKey",
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow
                });
            }

            var observedValue = _settingReader(key);
            var status = CheckStatus.Pass;
            if (request.Parameters.TryGetValue("expectedValue", out var expected))
                status = string.Equals(observedValue, expected, StringComparison.OrdinalIgnoreCase) ? CheckStatus.Pass : CheckStatus.Fail;

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = observedValue == null ? CheckStatus.NotApplicable : status,
                ObservedState = new Dictionary<string, object> { ["settingKey"] = key, ["value"] = observedValue ?? "UNAVAILABLE" },
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }
}
