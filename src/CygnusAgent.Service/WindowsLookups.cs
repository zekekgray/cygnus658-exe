using System;
using System.IO;

namespace CygnusAgent.Service
{
    /// <summary>
    /// Thin wrappers around the actual Windows APIs (registry, Service
    /// Control Manager, WMI/BitLocker) that the verification checks and
    /// remediation actions need. Kept together and clearly marked so a
    /// reviewer can audit every place this Agent touches the OS in one file.
    ///
    /// TODO: IMPLEMENT — these are safe, conservative stubs (read-only
    /// lookups return "not available" rather than guessing) so the rest of
    /// the codebase compiles and is testable before you wire in
    /// System.ServiceProcess / System.Management for the real Windows calls.
    /// </summary>
    internal static class WindowsLookups
    {
        public static bool IsApplicationInstalled(string applicationName)
        {
            // TODO: query the registry Uninstall keys
            // (HKLM/HKCU\...\Windows\CurrentVersion\Uninstall) for a
            // DisplayName match, via Microsoft.Win32.Registry.
            return false;
        }

        public static string? GetServiceStatus(string serviceName)
        {
            // TODO: use System.ServiceProcess.ServiceController(serviceName).Status
            return null;
        }

        public static bool ApplyServiceState(string serviceName, string targetState)
        {
            // TODO: use System.ServiceProcess.ServiceController to
            // Start()/Stop() or set the start mode via WMI
            // (Win32_Service.ChangeStartMode) for "Disabled".
            return false;
        }

        public static string? GetVolumeEncryptionStatus(string volume)
        {
            // TODO: query Win32_EncryptableVolume via
            // System.Management, or shell out to `manage-bde -status`
            // and parse output (prefer WMI — no process spawn needed).
            return null;
        }

        public static string? ReadSecuritySetting(string settingKey)
        {
            // TODO: dispatch on settingKey to the right read (registry
            // value, firewall profile state via COM interop, etc.)
            return null;
        }
    }

    /// <summary>Writes to the Windows Event Log source "CygnusAgent" if
    /// registered at install time; falls back to a rolling local file so
    /// logging never throws and never blocks the service.</summary>
    internal static class WindowsEventLogSink
    {
        private static readonly string FallbackLogPath =
            Environment.ExpandEnvironmentVariables(@"%ProgramData%\CygnusAgent\logs\agent.log");

        public static void Write(string jsonLine)
        {
            try
            {
                // TODO: System.Diagnostics.EventLog.WriteEntry("CygnusAgent", jsonLine)
                // once the event source is registered by the installer
                // (EventLog.CreateEventSource requires admin at registration
                // time, which the installer already has).
                Directory.CreateDirectory(Path.GetDirectoryName(FallbackLogPath)!);
                File.AppendAllText(FallbackLogPath, jsonLine + Environment.NewLine);
            }
            catch
            {
                // Logging must never crash the Agent.
            }
        }
    }
}
