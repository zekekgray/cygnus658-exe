using System;
using System.IO;
using System.Net.Http;
using CygnusAgent.Core.Interfaces;
using CygnusAgent.Core.Models;
using CygnusAgent.Core.Remediation;
using CygnusAgent.Core.Remediation.Actions;
using CygnusAgent.Core.Security;
using CygnusAgent.Core.Verification;
using CygnusAgent.Core.Verification.Checks;
using CygnusAgent.Infrastructure.Logging;
using CygnusAgent.Infrastructure.Networking;
using CygnusAgent.Infrastructure.Storage;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
// === START: LOGLEVEL ALIAS EDIT ===
using LogLevel = CygnusAgent.Infrastructure.Logging.LogLevel;
// === END: LOGLEVEL ALIAS EDIT ===

namespace CygnusAgent.Service
namespace CygnusAgent.Service
{
    /// <summary>
    /// Composition root. This is the only file that wires concrete
    /// implementations to interfaces — everything else in Core only knows
    /// about interfaces, which is what keeps the check/remediation
    /// allowlists closed and testable.
    ///
    /// TODO: CONNECT TO BACKEND — ApiBaseUrl below must be set to your
    /// deployed Apps Script Web App URL (see docs/DEPLOYMENT.md). It is read
    /// from local configuration, never hardcoded here.
    /// </summary>
    public static class Program
    {
        public static void Main(string[] args)
        {
            var config = LoadConfig();
            var dataDir = Environment.ExpandEnvironmentVariables(@"%ProgramData%\CygnusAgent");
            Directory.CreateDirectory(dataDir);

            var host = Host.CreateDefaultBuilder(args)
                .UseWindowsService(options => options.ServiceName = "CygnusAgent")
                .ConfigureServices(services =>
                {
                    services.AddSingleton(config);

                    services.AddSingleton<IAgentLogger>(_ => new StructuredLogger(
                        sink: line => WindowsEventLogSink.Write(line), // falls back to file if Event Log source isn't registered
                        minLevel: Enum.TryParse<LogLevel>(config.LogLevel, true, out var lvl) ? lvl : LogLevel.Info));

                    services.AddSingleton<ICredentialStore>(_ =>
                        new DpapiCredentialStore(Path.Combine(dataDir, "device.cred")));

                    services.AddSingleton<DeviceIdentityProvider>();

                    services.AddSingleton<ISequenceStore>(_ =>
                        new FileSequenceStore(Path.Combine(dataDir, "sequence.txt")));
                    services.AddSingleton<ResultEnvelopeFactory>();

                    services.AddSingleton<IOfflineQueue<AgentResultEnvelope<CheckResult[]>>>(_ =>
                        new FileOfflineQueue<AgentResultEnvelope<CheckResult[]>>(
                            Path.Combine(dataDir, "queue", "results"), config.OfflineQueueMaxItems));

                    services.AddHttpClient<IApiClient, CygnusApiClient>(client =>
                    {
                        if (!string.IsNullOrWhiteSpace(config.ApiBaseUrl))
                            client.BaseAddress = new Uri(config.ApiBaseUrl);
                        client.Timeout = TimeSpan.FromSeconds(30);
                    });
                    // NOTE: attach the device credential to outgoing requests via a
                    // DelegatingHandler (CredentialAttachingHandler, not included in
                    // this delivery) registered on the HttpClient above, once the
                    // backend's real auth header shape is finalized — see
                    // API_CONTRACT.md "Common envelope fields".

                    services.AddSingleton(sp => new RetryPolicy(
                        maxAttempts: 6,
                        initialBackoff: config.RetryInitialBackoff,
                        maxBackoff: config.RetryMaxBackoff,
                        logger: sp.GetRequiredService<IAgentLogger>()));

                    // --- Allowlisted verification checks (register every supported type here) ---
                    services.AddSingleton<IVerificationCheck, OsInfoCheck>();
                    services.AddSingleton<IVerificationCheck>(_ => new DeviceIdentityCheck(config.DeviceId));
                    services.AddSingleton<IVerificationCheck>(_ => new ApplicationStateCheck(WindowsLookups.IsApplicationInstalled));
                    services.AddSingleton<IVerificationCheck>(_ => new ServiceStateCheck(WindowsLookups.GetServiceStatus));
                    services.AddSingleton<IVerificationCheck, FileStateCheck>();
                    services.AddSingleton<IVerificationCheck, DirectoryStateCheck>();
                    services.AddSingleton<IVerificationCheck>(_ => new Core.Verification.Checks.DiskEncryptionCheck(WindowsLookups.GetVolumeEncryptionStatus));
                    services.AddSingleton<IVerificationCheck>(_ => new SecurityConfigurationStateCheck(WindowsLookups.ReadSecuritySetting));
                    services.AddSingleton<CheckEngine>();

                    // --- Allowlisted remediation actions (operator-configured scope) ---
                    services.AddSingleton<IRemediationAction>(_ => new DeleteApprovedPathAction(
                        approvedPathPrefixes: new[] { @"C:\CygnusApproved\Quarantine" })); // TODO: set real approved paths
                    services.AddSingleton<IRemediationAction>(_ => new SetServiceStateAction(
                        approvedServiceNames: Array.Empty<string>(), // TODO: set real approved service names
                        applyServiceState: WindowsLookups.ApplyServiceState));
                    services.AddSingleton<RemediationEngine>();

                    services.AddHostedService<AgentWorker>();
                })
                .Build();

            host.Run();
        }

        private static AgentConfig LoadConfig()
        {
            // In production, bind this from appsettings.json (see
            // appsettings.template.json) via Microsoft.Extensions.Configuration.
            // Kept as a simple explicit object here so this file has no hidden
            // dependency on a config file existing at a specific path.
            return new AgentConfig
            {
                ApiBaseUrl = Environment.GetEnvironmentVariable("CYGNUS_API_BASE_URL") ?? "",
                DeviceId = Environment.GetEnvironmentVariable("CYGNUS_DEVICE_ID") ?? "",
                AgentVersion = "1.0.0"
            };
        }
    }
}
