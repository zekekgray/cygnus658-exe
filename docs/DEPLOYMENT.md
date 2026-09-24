# CYGNUS 658 Agent — Deployment

## Enrollment token

Generate a short-lived, single-use, org-scoped token on the backend (this is
a backend feature to add — see `API_CONTRACT.md`, `/agent/enroll` gap). Hand
it to whoever is installing the Agent out-of-band (not embedded in a script
committed anywhere).

## Interactive install

```
CygnusAgentSetup.exe /enroll:<token>
```

## Silent install (for mass deployment via GPO/RMM)

```
CygnusAgentSetup.exe /quiet /enroll:<token>
```

The token is passed at install time only, used once over HTTPS, and never
written to disk as a permanent credential — see `ARCHITECTURE.md` §4. Do not
bake a token into a golden image or shared install script; generate one per
device (or a small batch with a short TTL) instead.

## What the installer does

1. Installs the `CygnusAgent` Windows Service (auto-start, recovery-on-crash
   configured).
2. Starts the service, which immediately attempts `/agent/enroll`.
3. On success, the service holds a DPAPI-protected credential under the
   service account and moves to `ONLINE`.
4. On failure (bad/expired/reused token), the service logs the failure to
   the Windows Event Log and retries with backoff — it does not silently
   fall back to any default/dev credential (there isn't one).

## Verifying a successful install

Check Windows Event Log (`Applications and Services Logs > CygnusAgent`) for
an `enrollment.completed` event, or confirm the device appears in the
CYGNUS Console (`console.listDevices`).

## Rotation

Once `/agent/credential/rotate` exists on the backend (see gap in
`API_CONTRACT.md`), the Agent should be configured with a rotation interval;
until then, rotation means re-enrollment.

## Revocation / decommission

Preferred: call `/agent/uninstall/revoke` (once implemented) before removing
the service, so the backend invalidates the credential immediately rather
than relying on the Agent being cooperative. Today, the closest equivalent
is manually clearing the device's `apiKey` cell in the `Devices` sheet.

## Uninstall

Standard Windows Service removal (`sc.exe delete CygnusAgent` or via the
installer's uninstall path) plus deletion of the DPAPI-protected credential
blob under the service account's profile.
