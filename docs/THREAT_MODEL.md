# CYGNUS 658 Agent — Threat Model

Scope: the Windows Service agent only (`src/CygnusAgent.*`). Backend threats
are out of scope here except where the Agent's design assumes something of
the backend.

## Assets

1. The device's long-term credential (private key / DPAPI blob).
2. The enrollment token (short-lived, but a window of misuse exists).
3. Evidence content collected from the endpoint.
4. The integrity of verification/remediation results.
5. The Agent's own execution privileges (it will often run as SYSTEM or an
   admin service account).

## Threats and mitigations (STRIDE)

| Threat | Scenario | Mitigation |
|---|---|---|
| **Spoofing** | Attacker impersonates a device to submit fake "PASS" results | Device identity is an asymmetric keypair generated on-device; backend only accepts results signed/authenticated with the credential issued at enrollment, tied to one `deviceId` |
| **Spoofing** | Attacker impersonates the backend to feed the Agent a malicious job | `CygnusApiClient` validates the backend TLS certificate; job payloads are only ever interpreted through the fixed `VerificationJob`/`RemediationAction` schemas — an attacker who MITMs anyway still can't get arbitrary code to run, only allowlisted checks/actions |
| **Tampering** | Enrollment token intercepted and reused | Token is single-use and short-lived server-side; even if intercepted, a race for first-use is the only window, and the legitimate device's enrollment attempt failing is a detectable signal (should alert) |
| **Tampering** | Evidence or result modified in transit | SHA-256 hash of the payload is included in the envelope; TLS protects transit; backend re-verifies the hash |
| **Tampering** | Attacker with local admin edits the Agent's on-disk queue/config to inject a fake job | Long-term credential is DPAPI-protected under the service account, not the queue file; queued *results* are outbound data the Agent itself produced, not inbound jobs — jobs are only ever accepted fresh from an authenticated backend response, never read back from local storage as if new |
| **Repudiation** | Device denies it submitted a given result | Every result envelope includes deviceId + sequence + payloadHash; backend's existing hash-chained `AuditLog` (see `AuditLog.gs`) already gives non-repudiation on the backend side once these are logged there |
| **Information disclosure** | Evidence content leaks endpoint PII | Agent collects only what the job's checks explicitly request (allowlisted check types); `docs/ARCHITECTURE.md` §5; logger redacts secrets; evidence content is metadata + hash by default, not raw file uploads, matching the existing backend's `submitEvidence` design |
| **Information disclosure** | Long-term credential exfiltrated from disk | DPAPI-scoped to the machine/service account; private key never transmitted; consider a TPM-backed key on hardware that supports it |
| **Information disclosure** | Secrets in logs | `StructuredLogger` redacts known-sensitive field names (`token`, `credential`, `password`, `key`) before writing any log line, on top of never passing those fields to the logger in the first place |
| **Denial of service** | Backend is unreachable | `OfflineQueue` with bounded size and exponential backoff; Agent degrades to local operation, never blocks indefinitely, never crashes the service |
| **Denial of service** | Malformed/oversized job payload | Strict schema validation before dispatch to CheckEngine; jobs with unknown check/action types are rejected (`NOT_APPLICABLE`/error), not partially executed |
| **Elevation of privilege** | Remediation job attempts to run something outside the allowlist | `RemediationEngine` resolves `actionType` against a closed registry of `IRemediationAction` implementations; there is no "else, run this as a shell command" fallback anywhere in the codebase — an unrecognized `actionType` is a hard error, by construction, not by convention |
| **Elevation of privilege** | A compromised job attempts path traversal in `DELETE_APPROVED_PATH` | Each remediation action validates its `path` parameter against an explicit allowlist/prefix check before touching the filesystem (see `DeleteApprovedPathAction.cs`) |
| **Replay** | Captured result replayed to fake a later re-verification | Sequence number + nonce + `expiresAt` on the originating job are all checked server-side; a replayed envelope reuses an already-consumed sequence and is rejected |

## Explicit non-goals (by design, not oversight)

The Agent will never implement, and no future job type should be accepted
that would require:

- Arbitrary PowerShell/CMD/shell execution
- Arbitrary registry modification
- Arbitrary process launch
- Keylogging, screen capture, or credential harvesting
- Real-time/behavioral malware detection (that's an EDR's job, not
  CYGNUS's)
- Silent/stealth persistence beyond the normal, visible Windows Service
  registration

If a future requirement seems to need one of these, that's a signal the
requirement belongs in a different product, not a reason to add an escape
hatch here.

## Residual risk accepted for v1

- No signed self-update mechanism yet (section 17 of the spec) — updates
  must be manual/reinstall until that's built.
- No credential rotation endpoint on the backend yet (see
  `API_CONTRACT.md`) — v1 credentials are long-lived until that ships.
- Single-platform (Windows) — Linux/macOS agents are out of scope for this
  delivery; the `Core` layer is deliberately Windows-agnostic so those can
  be added later without redesign.
