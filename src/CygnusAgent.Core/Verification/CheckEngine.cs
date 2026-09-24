using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;

namespace CygnusAgent.Core.Verification
{
    /// <summary>
    /// Dispatches each CheckRequest in a job to the matching IVerificationCheck
    /// by its Type string. This is a CLOSED registry, built once at startup
    /// from DI — there is no code path here that takes a string off the wire
    /// and does anything other than a dictionary lookup with it. An unknown
    /// Type produces a CheckStatus.Error result; it never falls through to
    /// executing anything.
    /// </summary>
    public sealed class CheckEngine
    {
        private readonly Dictionary<string, IVerificationCheck> _registry;
        private readonly IAgentLogger _logger;

        public CheckEngine(IEnumerable<IVerificationCheck> checks, IAgentLogger logger)
        {
            _registry = checks.ToDictionary(c => c.Type, StringComparer.Ordinal);
            _logger = logger;
        }

        public async Task<List<CheckResult>> RunJobAsync(VerificationJob job, CancellationToken ct)
        {
            var results = new List<CheckResult>();

            foreach (var request in job.Checks)
            {
                ct.ThrowIfCancellationRequested();

                if (!_registry.TryGetValue(request.Type, out var check))
                {
                    _logger.Warn("check.unsupported_type", new { request.CheckId, request.Type });
                    results.Add(new CheckResult
                    {
                        CheckId = request.CheckId,
                        Status = CheckStatus.Error,
                        ErrorMessage = $"Unsupported check type: {request.Type}",
                        StartedAt = DateTimeOffset.UtcNow,
                        CompletedAt = DateTimeOffset.UtcNow
                    });
                    continue;
                }

                try
                {
                    var result = await check.RunAsync(request, ct);
                    results.Add(result);
                }
                catch (Exception ex)
                {
                    _logger.Error("check.threw", new { request.CheckId, request.Type, error = ex.Message });
                    results.Add(new CheckResult
                    {
                        CheckId = request.CheckId,
                        Status = CheckStatus.Error,
                        ErrorMessage = ex.Message,
                        StartedAt = DateTimeOffset.UtcNow,
                        CompletedAt = DateTimeOffset.UtcNow
                    });
                }
            }

            return results;
        }
    }
}
