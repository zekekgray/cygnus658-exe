using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text.Json;
using CygnusAgent.Core.Interfaces;

namespace CygnusAgent.Infrastructure.Logging
{
    /// <summary>
    /// JSON-structured logging. Any property on the `data` object whose name
    /// matches a known-sensitive pattern is redacted BEFORE serialization —
    /// this is a safety net, not a substitute for simply not passing secrets
    /// in, but it means a future contributor accidentally logging a
    /// `credential` field doesn't leak it.
    /// </summary>
    public sealed class StructuredLogger : IAgentLogger
    {
        private static readonly string[] SensitiveFieldNames =
        {
            "password", "token", "credential", "privatekey", "apikey", "secret", "sessiontoken"
        };

        private readonly Action<string> _sink; // e.g. Windows Event Log write, or file append
        private readonly LogLevel _minLevel;

        public StructuredLogger(Action<string> sink, LogLevel minLevel)
        {
            _sink = sink;
            _minLevel = minLevel;
        }

        public void Trace(string evt, object? data = null) => Write(LogLevel.Trace, evt, data);
        public void Debug(string evt, object? data = null) => Write(LogLevel.Debug, evt, data);
        public void Info(string evt, object? data = null) => Write(LogLevel.Info, evt, data);
        public void Warn(string evt, object? data = null) => Write(LogLevel.Warn, evt, data);
        public void Error(string evt, object? data = null) => Write(LogLevel.Error, evt, data);
        public void Critical(string evt, object? data = null) => Write(LogLevel.Critical, evt, data);

        private void Write(LogLevel level, string evt, object? data)
        {
            if (level < _minLevel) return;

            var redacted = Redact(data);
            var line = JsonSerializer.Serialize(new
            {
                timestamp = DateTimeOffset.UtcNow.ToString("o"),
                level = level.ToString().ToUpperInvariant(),
                @event = evt,
                data = redacted
            });
            _sink(line);
        }

        private static Dictionary<string, object?>? Redact(object? data)
        {
            if (data == null) return null;
            var dict = new Dictionary<string, object?>();
            foreach (var prop in data.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                var isSensitive = Array.Exists(SensitiveFieldNames,
                    s => prop.Name.Contains(s, StringComparison.OrdinalIgnoreCase));
                dict[prop.Name] = isSensitive ? "[REDACTED]" : prop.GetValue(data);
            }
            return dict;
        }
    }

    public enum LogLevel { Trace, Debug, Info, Warn, Error, Critical }
}
