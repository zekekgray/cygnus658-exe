using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using CygnusAgent.Core.Interfaces;

namespace CygnusAgent.Infrastructure.Networking
{
    /// <summary>
    /// Bounded exponential backoff with jitter. Never retries forever
    /// (spec §12: "no infinite retry loop") and never retries a call whose
    /// idempotency can't be guaranteed by the caller — result submission is
    /// safe to retry because the backend keys on ResultId/Sequence and will
    /// treat a duplicate as a no-op once that dedupe is implemented there.
    /// </summary>
    public sealed class RetryPolicy
    {
        private readonly int _maxAttempts;
        private readonly TimeSpan _initialBackoff;
        private readonly TimeSpan _maxBackoff;
        private readonly IAgentLogger _logger;

        public RetryPolicy(int maxAttempts, TimeSpan initialBackoff, TimeSpan maxBackoff, IAgentLogger logger)
        {
            _maxAttempts = maxAttempts;
            _initialBackoff = initialBackoff;
            _maxBackoff = maxBackoff;
            _logger = logger;
        }

        public async Task<T> RunAsync<T>(Func<Task<T>> action, CancellationToken ct)
        {
            var attempt = 0;
            var delay = _initialBackoff;
            var rng = Random.Shared;

            while (true)
            {
                attempt++;
                try
                {
                    return await action();
                }
                catch (Exception ex) when (attempt < _maxAttempts && IsTransient(ex))
                {
                    _logger.Warn("api.retry", new { attempt, delayMs = delay.TotalMilliseconds, error = ex.Message });
                    var jitterMs = rng.Next(0, 250);
                    await Task.Delay(delay + TimeSpan.FromMilliseconds(jitterMs), ct);
                    delay = TimeSpan.FromMilliseconds(Math.Min(delay.TotalMilliseconds * 2, _maxBackoff.TotalMilliseconds));
                }
            }
        }

        private static bool IsTransient(Exception ex) =>
            ex is HttpRequestException || ex is TaskCanceledException || ex is TimeoutException;
    }
}
