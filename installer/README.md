# CygnusAgentSetup.exe

Not built in this delivery (no Windows packaging toolchain available in the
environment this was generated in). This is the spec for whoever builds it,
using WiX Toolset (recommended, produces a real MSI) or Inno Setup
(simpler, produces an .exe):

## Command line

```
CygnusAgentSetup.exe /enroll:<token>          interactive install
CygnusAgentSetup.exe /quiet /enroll:<token>   silent install for GPO/RMM
```

## What it must do, in order

1. Copy the published `CygnusAgent.Service` output to
   `%ProgramFiles%\CygnusAgent\`.
2. Register the Windows Event Log source `CygnusAgent` (requires the
   installer's admin context — the running service can't do this for
   itself with a least-privileged service account).
3. Create the `%ProgramData%\CygnusAgent\` data directory and lock its ACLs
   to SYSTEM + Administrators (this is where the DPAPI-protected credential
   blob, offline queue, and logs live).
4. Register the `CygnusAgent` Windows Service, set it to auto-start with
   failure recovery (restart on crash, with a backoff — `sc.exe failure`
   or the WiX `ServiceConfig` element).
5. Pass the `/enroll:<token>` value to the service's first run **only** as
   an environment variable or a one-time command-line argument read at
   first start — never write it to a file, the registry, or a log. The
   service reads `CYGNUS_ENROLL_TOKEN` once (see `AgentWorker.EnsureEnrolledAsync`)
   and never persists it.
6. Start the service.
7. On `/quiet`, suppress all UI and exit with a standard installer exit
   code; on failure, exit non-zero so RMM tooling can detect it — do not
   silently succeed if enrollment fails.

## What it must never do

- Never embed a permanent API key or credential in the install command
  (that's exactly what the current prototype frontend's
  `CygnusAgentSetup.exe /device:X /key:Y` pattern does — this Agent
  replaces that with the short-lived-token flow in `ARCHITECTURE.md` §4).
- Never write the enrollment token to disk.
- Never install with a
