using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Remediation
{
    /// <summary>
    /// Same closed-registry pattern as CheckEngine, deliberately duplicated
    /// rather than shared: remediation is more consequential than a
    /// read-only check, so its dispatcher is kept simple and easy to audit
    /// on its own, with no shared abstraction that a future change to
    /// CheckEngine could accidentally loosen for both.
    ///
    /// An ActionType with no registered handler is a hard failure. There is
    /// no generic "else, shell out" branch anywhere in this class or in any
    /// IRemediationAction implementation — see THREAT_MODEL.md "Elevation of
    /// privilege".
    /// </summary>
    public sealed class RemediationEngine
    {
        private readonly Dictionary<string, IRemediationAction> _registry;
        private readonly IAgentLogger _logger;

        public RemediationEngine(IEnumerable<IRemediationAction> actions, IAgentLogger logger)
        {
            _registry = actions.ToDictionary(a => a.ActionType, StringComparer.Ordinal);
            _logger = logger;
        }

        public async Task<RemediationResult> ExecuteAsync(RemediationAction action, CancellationToken ct)
        {
            if (!_registry.TryGetValue(action.ActionType, out var handler))
            {
                _logger.Error("remediation.unsupported_type", new { action.ActionId, action.ActionType });
                return new RemediationResult
                {
                    ActionId = action.ActionId,
                    JobId = action.JobId,
                    StartedAt = DateTimeOffset.UtcNow,
                    CompletedAt = DateTimeOffset.UtcNow,
                    Result = RemediationOutcome.Failed,
                    ErrorCode = "UNSUPPORTED_ACTION_TYPE",
                    AffectedResource = ""
                };
            }

            try
            {
                return await handler.ExecuteAsync(action, ct);
            }
            catch (Exception ex)
            {
                _logger.Error("remediation.threw", new { action.ActionId, action.ActionType, error = ex.Message });
                return new RemediationResult
                {
                    ActionId = action.ActionId,
                    JobId = action.JobId,
                    StartedAt = DateTimeOffset.UtcNow,
                    CompletedAt = DateTimeOffset.UtcNow,
                    Result = RemediationOutcome.Failed,
                    ErrorCode = "EXCEPTION",
                    AffectedResource = ""
                };
            }
        }
    }
}
