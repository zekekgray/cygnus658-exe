# CYGNUS 658 — Agent ⇄ Backend API Contract

All endpoints are conceptual (`/agent/...`) so the Agent's `CygnusApiClient`
has a clean interface to code against. **None of these exist on the current
Apps Script backend yet** — that backend instead exposes a single
`doGet`/`doPost` router with `action` strings (`agent.register`,
`agent.heartbeat`, etc., see `Code.gs`). Every endpoint below states which
existing `action` it maps to today, and what would need to change to reach
the hardened version this Agent expects. Nothing in `CygnusApiClient.cs`
assumes a specific transport shape beyond "HTTPS POST, JSON in, JSON out" —
mapping to the single-endpoint Apps Script router is a one-file change
(`AgentEndpoints.cs`).

## POST /agent/enroll
Maps to: `agent.register` today (pre-req: `console.addDevice` created the row).
**Gap**: today's backend hands the permanent `apiKey` to a human at
`console.addDevice` time and bakes it into the installer command
(`CygnusAgentSetup.exe /device:X /key:Y`), which is exactly what section 4
of the build spec says not to do. To close this gap: add an
`agent.enroll {enrollToken, hostname, osVersion, agentVersion, publicKey}`
action that (a) looks up a short-lived single-use token instead of a
permanent key, (b) generates the permanent credential server-side at this
point instead of at `console.addDevice` time, (c) invalidates the token.

Request:
```json
{ "action": "agent.enroll", "enrollToken": "...", "hostname": "...", "osVersion": "...", "agentVersion": "1.0.0", "publicKey": "base64..." }
```
Response:
```json
{ "ok": true, "data": { "deviceId": "DEV-...", "credential": "..." } }
```

## POST /agent/heartbeat
Maps to: `agent.heartbeat` (implemented — `recordHeartbeat` in Devices.gs).
Request: `{ "action":"agent.heartbeat", "apiKey":"...", "deviceId":"...", "agentVersion":"...", "osVersion":"...", "lastJobState":"ONLINE" }`
Response: `{ "ok": true, "data": {} }`

## POST /agent/jobs/poll
Maps to: `agent.checkCommands` (implemented — `popPendingScanCommand`).
**Gap**: today this only returns a boolean ("a scan is pending"); it doesn't
return a structured `VerificationJob`. Extend `popPendingScanCommand` to
store and return the job shape in section 7 of `ARCHITECTURE.md` instead of
just a timestamp string.
Response: `{ "ok": true, "data": { "job": { ...VerificationJob... } | null } }`

## POST /agent/jobs/{jobId}/result
Maps to: `agent.submitScanResult` (implemented — `submitScanResult` in
Findings.gs), which currently accepts a flatter `{findings:[...]}` shape.
The envelope this Agent sends (`AgentResultEnvelope` wrapping a
`CheckResult[]`) is a superset — the extra replay-protection fields
(nonce, sequence, payloadHash) can be stored alongside the existing
`Findings` sheet columns without breaking today's console UI.

## POST /agent/evidence
Maps to: `agent.submitEvidence` (implemented — Evidence.gs). Matches the
existing shape closely: `{caseId, acquisitionMethod, evidenceType, source}`
plus this Agent's `sha256Hash` and `sizeBytes`.

## POST /agent/remediation/result
**New** — not yet implemented on the backend. Should append to `Findings`
(status transition) the same way `console.remediate`/`console.markReviewed`
do today, but triggered by the Agent rather than a human console action.
Suggested shape: `{ actionId, jobId, actionType, startedAt, completedAt, result, errorCode, affectedResource }`.

## POST /agent/verify/result
**New** — the re-verification step's result. Same envelope as
`/agent/jobs/{jobId}/result`, posted a second time after remediation, with
`objective` unchanged and a reference to the original `jobId`.

## POST /agent/credential/rotate
**New** — not yet implemented. Needed before production use: the Agent's
long-term credential should be rotatable without re-enrollment. Suggested:
`{ apiKey (current), deviceId }` → `{ newApiKey }`, with the old key
invalidated only after the Agent confirms receipt (avoid locking a device
out on a dropped response).

## POST /agent/uninstall/revoke
**New** — lets an admin (or the Agent itself, on clean uninstall) invalidate
its credential immediately, independent of the normal 8-hour session expiry
that `Sessions` already uses for console users (`authenticateConsole` in
Auth.gs). Today there is no equivalent for device API keys — they don't
expire at all. This is the highest-priority backend gap to close before
production rollout.

## Common envelope fields (all POSTs from the Agent)

Every request includes, in addition to action-specific fields:
- `deviceId` — which device this is
- `credential` — the DPAPI-protected long-term credential (sent as its
  cleartext token value over TLS; the *private key* backing it never leaves
  the device)
- `agentVersion`
- `requestId` — a fresh GUID per HTTP call, for idempotency on the
  backend if you add a dedupe table

## Errors

Every response is `{ok:true, data:...}` or `{ok:false, error:"...", code?}`
— matching `jsonOut()` in `Code.gs` exactly, so no client-side change is
needed to parse errors.
