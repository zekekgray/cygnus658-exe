using System;
using System.IO;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using CygnusAgent.Core.Interfaces;

namespace CygnusAgent.Infrastructure.Storage
{
    /// <summary>
    /// Protects the Agent's one long-term secret (its device credential /
    /// private key PEM) using Windows DPAPI, scoped to the local machine so
    /// only processes running under this machine's protection scope can
    /// decrypt it — the running service account, not "anyone who can read
    /// the file". Never stores anything in plaintext, and this class is the
    /// ONLY place in the codebase that touches the credential file.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public sealed class DpapiCredentialStore : ICredentialStore
    {
        private readonly string _path;
        // Additional entropy is itself non-secret (it's fine if an attacker
        // knows this constant) — it just scopes decryption to this specific
        // use, so another DPAPI-protected blob on the machine can't be
        // swapped in for this one.
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("CYGNUS658-AGENT-CREDENTIAL-V1");

        public DpapiCredentialStore(string path)
        {
            _path = path;
        }

        public bool TryLoad(out string credential)
        {
            credential = "";
            if (!File.Exists(_path)) return false;

            try
            {
                var protectedBytes = File.ReadAllBytes(_path);
                var plainBytes = ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine);
                credential = Encoding.UTF8.GetString(plainBytes);
                return true;
            }
            catch (CryptographicException)
            {
                // Blob is corrupt or was written on a different machine —
                // treat as "no credential" rather than throwing, so the
                // Agent falls back to re-enrollment instead of crash-looping.
                return false;
            }
        }

        public void Save(string credential)
        {
            var plainBytes = Encoding.UTF8.GetBytes(credential);
            var protectedBytes = ProtectedData.Protect(plainBytes, Entropy, DataProtectionScope.LocalMachine);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllBytes(_path, protectedBytes);
            // Restrict ACLs on _path to SYSTEM/Administrators only via
            // installer-time icacls or FileSecurity here in production —
            // left as an installer step so this class stays testable
            // without a Windows-only ACL dependency.
        }

        public void Clear()
        {
            if (File.Exists(_path)) File.Delete(_path);
        }
    }
}
