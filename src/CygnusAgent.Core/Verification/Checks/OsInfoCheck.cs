using System;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Verification.Checks
{
    /// <summary>Reports OS name/version/architecture. Read-only, no evidence
    /// beyond the observed values themselves.</summary>
    public sealed class OsInfoCheck : IVerificationCheck
    {
        public string Type => "OS_INFO";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            var observed = new System.Collections.Generic.Dictionary<string, object>
            {
                ["osDescription"] = System.Runtime.InteropServices.RuntimeInformation.OSDescription,
                ["osArchitecture"] = System.Runtime.InteropServices.RuntimeInformation.OSArchitecture.ToString(),
                ["frameworkDescription"] = System.Runtime.InteropServices.RuntimeInformation.FrameworkDescription
            };

            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = CheckStatus.Pass,
                ObservedState = observed,
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }

    /// <summary>Reports the machine's stable device identity (the CYGNUS
    /// deviceId assigned at enrollment) alongside the hostname, purely as
    /// observed state for audit purposes — hostname is never used AS the
    /// identity (see DeviceIdentityProvider).</summary>
    public sealed class DeviceIdentityCheck : IVerificationCheck
    {
        private readonly string _deviceId;

        public DeviceIdentityCheck(string deviceId) => _deviceId = deviceId;

        public string Type => "DEVICE_IDENTITY";

        public Task<CheckResult> RunAsync(CheckRequest request, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            return Task.FromResult(new CheckResult
            {
                CheckId = request.CheckId,
                Status = CheckStatus.Pass,
                ObservedState = new System.Collections.Generic.Dictionary<string, object>
                {
                    ["deviceId"] = _deviceId,
                    ["hostname"] = Environment.MachineName
                },
                StartedAt = started,
                CompletedAt = DateTimeOffset.UtcNow
            });
        }
    }
}
