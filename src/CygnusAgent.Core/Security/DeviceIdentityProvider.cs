using System;
using System.Security.Cryptography;
using CygnusAgent.Core.Interfaces;

namespace CygnusAgent.Core.Security
{
    /// <summary>
    /// The device's real identity is an ECDSA keypair generated once,
    /// on-device, at enrollment time — never derived from hostname/MAC/IP,
    /// which are all spoofable and can change without the device changing.
    ///
    /// The private key is handed to ICredentialStore for DPAPI-protected
    /// persistence (see Infrastructure/Storage/DpapiCredentialStore.cs) and
    /// is NEVER sent to the backend. Only the public key travels over the
    /// wire, at enrollment.
    /// </summary>
    public sealed class DeviceIdentityProvider
    {
        private readonly ICredentialStore _keyStore;

        public DeviceIdentityProvider(ICredentialStore keyStore)
        {
            _keyStore = keyStore;
        }

        /// <summary>
        /// Loads the existing device keypair, or generates a new one if this
        /// is a fresh install. Returns the public key (base64 SubjectPublicKeyInfo)
        /// to send at enrollment.
        /// </summary>
        public string GetOrCreatePublicKey()
        {
            if (_keyStore.TryLoad(out var existingPrivateKeyPem))
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportFromPem(existingPrivateKeyPem);
                return Convert.ToBase64String(ecdsa.ExportSubjectPublicKeyInfo());
            }

            using var fresh = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var privateKeyPem = fresh.ExportECPrivateKeyPem();
            _keyStore.Save(privateKeyPem);
            return Convert.ToBase64String(fresh.ExportSubjectPublicKeyInfo());
        }

        /// <summary>Signs a payload hash with the device's private key. Used by
        /// ResultSigner so every submitted result is attributable to this device
        /// without the private key ever leaving the machine.</summary>
        public byte[] SignHash(byte[] hash)
        {
            if (!_keyStore.TryLoad(out var privateKeyPem))
                throw new InvalidOperationException("Device has no identity yet — enroll before signing.");

            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromPem(privateKeyPem);
            return ecdsa.SignHash(hash);
        }
    }
}
