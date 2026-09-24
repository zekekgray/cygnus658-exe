using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Remediation.Actions
{
    /// <summary>
    /// Deletes a single file at an explicit path, but ONLY if that path
    /// falls under one of the operator-configured approved prefixes. This is
    /// the concrete implementation of the "allowlisted, not arbitrary" rule
    /// for remediation — see spec §9 and THREAT_MODEL.md "path traversal".
    /// </summary>
    public sealed class DeleteApprovedPathAction : IRemediationAction
    {
        private readonly string[] _approvedPathPrefixes;

        public DeleteApprovedPathAction(string[] approvedPathPrefixes)
        {
            _approvedPathPrefixes = approvedPathPrefixes
                .Select(p => Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar))
                .ToArray();
        }

        public string ActionType => "DELETE_APPROVED_PATH";

        public Task<RemediationResult> ExecuteAsync(RemediationAction action, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;

            if (!action.Parameters.TryGetValue("path", out var rawPath) || string.IsNullOrWhiteSpace(rawPath))
            {
                return Task.FromResult(Fail(action, started, "MISSING_PATH", ""));
            }

            string fullPath;
            try { fullPath = Path.GetFullPath(rawPath); }
            catch { return Task.FromResult(Fail(action, started, "INVALID_PATH", rawPath)); }

            var isApproved = _approvedPathPrefixes.Any(prefix =>
                fullPath.StartsWith(prefix + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
                || string.Equals(fullPath, prefix, StringComparison.OrdinalIgnoreCase));

            if (!isApproved)
            {
                // This is the load-bearing check. Do not relax it, e.g. by
                // trusting a "force" parameter from the job — the allowlist
                // is operator-configured locally, not server-supplied.
                return Task.FromResult(Fail(action, started, "PATH_NOT_APPROVED", fullPath));
            }

            try
            {
                if (File.Exists(fullPath)) File.Delete(fullPath);
                else return Task.FromResult(new RemediationResult
                {
                    ActionId = action.ActionId, JobId = action.JobId,
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow,
                    Result = RemediationOutcome.Skipped, AffectedResource = fullPath,
                    ErrorCode = "FILE_NOT_FOUND"
                });

                return Task.FromResult(new RemediationResult
                {
                    ActionId = action.ActionId, JobId = action.JobId,
                    StartedAt = started, CompletedAt = DateTimeOffset.UtcNow,
                    Result = RemediationOutcome.Succeeded, AffectedResource = fullPath
                });
            }
            catch (Exception ex)
            {
                return Task.FromResult(Fail(action, started, "DELETE_FAILED:" + ex.GetType().Name, fullPath));
            }
        }

        private static RemediationResult Fail(RemediationAction action, DateTimeOffset started, string code, string resource) =>
            new()
            {
                ActionId = action.ActionId, JobId = action.JobId,
                StartedAt = started, CompletedAt = DateTimeOffset.UtcNow,
                Result = RemediationOutcome.Failed, ErrorCode = code, AffectedResource = resource
            };
    }

    /// <summary>
    /// Sets a named Windows service's start mode / running state to one of a
    /// fixed set of allowed target states (never an arbitrary command). The
    /// actual Service Control Manager call is injected so Core stays
    /// testable off-Windows.
    /// </summary>
    public sealed class SetServiceStateAction : IRemediationAction
    {
        private static readonly string[] AllowedTargetStates = { "Running", "Stopped", "Disabled" };
        private readonly string[] _approvedServiceNames;
        private readonly Func<string, string, bool> _applyServiceState; // (serviceName, targetState) -> success

        public SetServiceStateAction(string[] approvedServiceNames, Func<string, string, bool> applyServiceState)
        {
            _approvedServiceNames = approvedServiceNames;
            _applyServiceState = applyServiceState;
        }

        public string ActionType => "SET_SERVICE_STATE";

        public Task<RemediationResult> ExecuteAsync(RemediationAction action, CancellationToken ct)
        {
            var started = DateTimeOffset.UtcNow;
            action.Parameters.TryGetValue("serviceName", out var serviceName);
            action.Parameters.TryGetValue("targetState", out var targetState);

            if (string.IsNullOrWhiteSpace(serviceName) || string.IsNullOrWhiteSpace(targetState))
                return Task.FromResult(Fail(action, started, "MISSING_PARAMETERS", serviceName ?? ""));

            if (!_approvedServiceNames.Contains(serviceName, StringComparer.OrdinalIgnoreCase))
                return Task.FromResult(Fail(action, started, "SERVICE_NOT_APPROVED", serviceName));

            if (!AllowedTargetStates.Contains(targetState, StringComparer.OrdinalIgnoreCase))
                return Task.FromResult(Fail(action, started, "TARGET_STATE_NOT_ALLOWED", serviceName));

            var ok = _applyServiceState(serviceName, targetState);
            return Task.FromResult(new RemediationResult
            {
                ActionId = action.ActionId, JobId = action.JobId,
                StartedAt = started, CompletedAt = DateTimeOffset.UtcNow,
                Result = ok ? RemediationOutcome.Succeeded : RemediationOutcome.Failed,
                ErrorCode = ok ? null : "SCM_CALL_FAILED",
                AffectedResource = serviceName
            });
        }

        private static RemediationResult Fail(RemediationAction action, DateTimeOffset started, string code, string resource) =>
            new()
            {
                ActionId = action.ActionId, JobId = action.JobId,
                StartedAt = started, CompletedAt = DateTimeOffset.UtcNow,
                Result = RemediationOutcome.Failed, ErrorCode = code, AffectedResource = resource
            };
    }
}
