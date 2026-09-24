# CYGNUS 658 — Endpoint Agent

The Agent is the endpoint-side component of CYGNUS 658. It does **not** decide
compliance. It:

1. Enrolls a device using a short-lived, single-use token.
2. Establishes a device identity and a long-term credential (DPAPI-protected).
3. Polls the CYGNUS backend for verification jobs.
4. Runs allowlisted checks and produces evidence + hashes.
5. Executes allowlisted remediation actions (never arbitrary commands).
6. Re-verifies after remediation.
7. Reports signed, replay-protected results back to the backend.

The backend (today: the Apps Script router already in this codebase) is the
**only** authority that can call something "CERTIFIED". The Agent never makes
that call locally.

## What this is not

Not an antivirus. Not an EDR. Not a remote-shell tool. No keylogging, no
screen capture, no stealth persistence, no arbitrary command execution. See
`docs/THREAT_MODEL.md` for the boundary and why it's enforced structurally
(allowlists), not just by policy.

## Project layout

```
CygnusAgent/
  docs/
    ARCHITECTURE.md       component responsibilities, lifecycle, diagrams (text form)
    API_CONTRACT.md        every Agent<->backend endpoint, request/response shapes
    THREAT_MODEL.md         STRIDE-style pass over the Agent's attack surface
    DEPLOYMENT.md           enrollment, install, silent install, rotation, revocation
  src/
    CygnusAgent.Core/               platform-independent domain logic
      Models/                        job, check, evidence, config, result models
      Interfaces/                    IVerificationCheck, IRemediationAction, IApiClient, ICredentialStore
      Security/                      device identity, result signing/hashing
      Verification/                  CheckEngine + individual IVerificationCheck implementations
      Remediation/                   RemediationEngine + individual IRemediationAction implementations
    CygnusAgent.Infrastructure/      Windows-specific / networked implementations
      Networking/                    CygnusApiClient (HTTPS, retry, backoff)
      Storage/                       DPAPI credential store, on-disk offline queue
      Logging/                       structured JSON logger, secret redaction
    CygnusAgent.Service/             the actual Windows Service host
      Program.cs, AgentWorker.cs, appsettings.template.json
    CygnusAgent.Tests/               unit tests per docs/DEPLOYMENT.md test list
  installer/
    README.md               how CygnusAgentSetup.exe should be built (WiX/Inno) and invoked
```

## Status of this delivery

This is a working first version of the architecture and core logic, in
source form, ready to drop into a .NET solution. It is **not** wired to a
live CYGNUS backend URL — every place that needs your deployed Apps Script
Web App URL is marked `TODO: CONNECT TO BACKEND` and documented in
`docs/API_CONTRACT.md`. There are no credentials, tokens, org IDs, or
backend URLs hardcoded anywhere in this tree — that was a hard requirement
and it's honored throughout.

## Build

This is plain C#/.NET source (no `.csproj`/`.sln` generated here, since this
environment can't run `dotnet` — add one with `dotnet new worker` in
`src/CygnusAgent.Service` and reference the other two projects as class
libraries, or open the tree directly in Visual Studio and create the
projects around the existing files).
