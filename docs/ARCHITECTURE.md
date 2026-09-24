# CYGNUS 658 Agent — Architecture

## 1. Where the Agent sits

```
 ┌─────────────────┐        HTTPS/JSON        ┌──────────────────────────┐
 │  CYGNUS Console  │ ───── console.* ───────► │  CYGNUS Backend           │
 │  (web, Sheets)   │ ◄──── responses ──────── │  (Apps Script router      │
 └─────────────────┘                           │   already in this repo:   │
                                                │   Code.gs / Auth.gs /     │
 ┌─────────────────┐        HTTPS/JSON         │   Findings.gs / Evidence  │
 │  CYGNUS Agent    │ ───── agent.* ──────────►│   .gs / AuditLog.gs)      │
 │  (this project,  │ ◄──── jobs / commands ── │                           │
 │   Windows Service)│                          └──────────────────────────┘
 └─────────────────┘
        │
        ▼
 Local Windows endpoint state
 (OS info, installed apps, services, files, disk encryption, ...)
```

The Agent talks **only** to the backend. It never talks to the Console
directly, and the Console never talks to an Agent directly — every scan or
remediation command is a row the Agent polls for (mirroring
`console.sendScanCommand` / `agent.checkCommands` already in Code.gs).

## 2. Component responsibilities

| Component | Responsibility | Must NOT do |
|---|---|---|
| **AgentWorker** (Windows Service host) | Owns the lifecycle loop: heartbeat, job poll, dispatch to CheckEngine/RemediationEngine, submit results | Make policy/certification decisions |
| **CygnusApiClient** | HTTPS calls, TLS validation, retry/backoff, idempotency keys | Retry destructive actions blindly |
| **DeviceIdentityProvider** | Generates/loads a stable device identity + long-term credential, DPAPI-protected | Send the private key/credential to the backend |
| **CredentialStore** | DPAPI-wrapped storage of the long-term credential and the last-used token | Store anything in plaintext config |
| **CheckEngine** | Loads the job's requested `IVerificationCheck` implementations from an allowlist, runs them, collects evidence | Execute a check type it doesn't recognize |
| **RemediationEngine** | Loads the job's requested `IRemediationAction` implementations from an allowlist, executes with least privilege | Run arbitrary shell/PowerShell/registry edits |
| **OfflineQueue** | Persists pending results/evidence submissions when offline, retries with bounded exponential backoff | Grow unbounded, double-submit on reconnect |
| **StructuredLogger** | JSON logs to Windows Event Log / file, secret redaction | Log tokens, keys, evidence content |
| **ResultSigner** | Hashes/signs job results so the backend can detect tampering, replay, wrong-device, wrong-job, expired-job | Decide whether a result "passes" |

## 3. Lifecycle (as specified)

```
UNINSTALLED
  → INSTALLED
  → ENROLLMENT_PENDING      (installer ran with /enroll:TOKEN, first call in flight)
  → ENROLLED                (device identity + long-term credential established, token invalidated)
  → ONLINE                  (heartbeat succeeding, no job in flight)
  → JOB_RECEIVED             (agent.checkCommands / job poll returned a job)
  → COLLECTING                (CheckEngine running the job's checks)
  → RESULT_SUBMITTED           (agent.submitScanResult / verify result posted)
  → WAITING                     (job accepted, remediation may or may not be requested)
  → REMEDIATION_REQUESTED         (backend returned an allowlisted remediation job)
  → REMEDIATION_EXECUTED            (RemediationEngine ran it, produced a result record)
  → RE-VERIFICATION                  (CheckEngine re-runs the original checks)
  → RESULT_SUBMITTED                   (second result posted)
  → ONLINE                               (back to steady state)
```

The Agent's local state machine only ever reaches `ONLINE`/`WAITING`-type
states — it never sets or reports a `CERTIFIED` state. `AgentState.cs`
enumerates exactly the states above and nothing else.

## 4. Enrollment flow

```
operator runs:  CygnusAgentSetup.exe /enroll:<short-lived-single-use-token> [/quiet]
        │
        ▼
Agent installs as a Windows Service, starts in ENROLLMENT_PENDING
        │
        ▼
POST /agent/enroll  { enrollToken, hostname, osVersion, agentVersion, publicKey }
        │  (token is used ONCE; token itself is never persisted after this call)
        ▼
Backend validates token → scoped org → issues { deviceId, longTermCredential }
        │
        ▼
Agent stores longTermCredential via DPAPI (CredentialStore), discards the enroll token,
moves to ENROLLED, then ONLINE once the first heartbeat succeeds.
```

Today's backend (`Code.gs`) implements the equivalent shape as
`console.addDevice` (pre-invite, issues a per-device API key) +
`agent.register` (Agent fills in agentVersion, flips device to `clean`). The
enrollment flow above is written to be a drop-in replacement: swap the
pre-shared `apiKey` model for a real short-lived enrollment token when you're
ready to harden the backend to match (see `docs/API_CONTRACT.md`, section
"Migrating the existing backend").

## 5. Security model (summary — full detail in THREAT_MODEL.md)

- **Identity**: a locally generated asymmetric keypair is the device's real
  identity; the public key is registered with the backend at enrollment; the
  private key never leaves the device and is DPAPI-protected (or a TPM-backed
  key/certificate where available).
- **Transport**: HTTPS only, backend certificate validated, no plaintext
  fallback.
- **Authorization boundary**: identical shape to the existing backend — every
  privileged action is checked server-side (`requirePerm` in `Code.gs`); the
  Agent has no analogous concept of "roles" because it has exactly one
  identity (its own device) and one counterparty (the backend).
- **Replay protection**: every result payload carries a request ID (nonce), a
  monotonic sequence number, the job ID, the device ID, and a hash of its own
  payload, so a captured-and-replayed result is rejected server-side.
- **Allowlisting**: `IVerificationCheck` and `IRemediationAction` are both
  closed sets, resolved by a switch/registry keyed on a fixed `type` string —
  there is no code path that takes a string from the network and executes it
  as a command.
- **No dev backdoor**: unlike the prototype console HTML (which has a
  `DEV_MODE_CREDENTIALS` block — flagged for removal there), this Agent has
  no hardcoded credentials, no debug auth bypass, and no shortcut login path
  of any kind.

## 6. Data model summary

See `Core/Models/` for the actual C# types. At a glance:

- `VerificationJob` — jobId, deviceId, policyId, objective, checks[], requestedAt, expiresAt
- `CheckResult` — checkId, status (PASS/FAIL/ERROR/NOT_APPLICABLE), observedState, evidence[], startedAt, completedAt
- `EvidenceRecord` — evidenceId, deviceId, jobId, checkId, timestamp, evidenceType, metadata, sha256Hash, sizeBytes, collectionStatus
- `RemediationAction` / `RemediationResult` — actionId, jobId, actionType, parameters, startedAt, completedAt, result, errorCode, affectedResource
- `AgentResultEnvelope` — wraps any result (verification or remediation) with deviceId, jobId, resultId, timestamp, nonce, sequence, payloadHash

## 7. Project tree

See `README.md` — the tree there is authoritative and matches what's on
disk in this delivery.
