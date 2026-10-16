# LaneFlow Free

**Route selected Windows applications through a dedicated network exit — while leaving everything else alone.**

Pick an application. Set an exit. Run it.
Everything else keeps its original route.

LaneFlow Free is a lightweight Windows desktop tool for process-level traffic routing. It works on top of an existing TUN/VPN or proxy setup and binds one chosen application to a configured exit endpoint, while every unbound application stays on its original network path.

## Quick start

1. Run LaneFlow Free as Administrator.
2. Enter a proxy endpoint (server address, port, and credentials if required).
3. Select an application from the running-process list.
4. Enable interception — the selected application is now routed through the dedicated exit.
5. Done. Everything else keeps its original route.

Disable interception at any time and the system DNS / routing state is restored automatically.

## Why LaneFlow?

Traditional proxy configuration operates at the device, browser, or domain level.
LaneFlow operates at the process level:

```
Existing network / VPN setup
            │
            ▼
      LaneFlow Free
            │
   ┌───────┴───────┐
   │               │
   ▼               ▼
Bound process   Other processes
   │               │
   ▼               ▼
Dedicated exit  Original route
```

One machine. Multiple network paths. Application-level control.
This makes LaneFlow useful when you need one particular application to use a different network exit without moving the rest of the system onto that route.

## Features

**Process-level routing**
Bind a selected Windows process to a configured proxy exit.

**TCP traffic splitting**
The free edition currently focuses on process-level TCP routing.
Bound-process UDP/QUIC traffic is rejected rather than silently treated as supported.
UDP/QUIC support is intentionally not claimed in this release.

**TUN-based interception**
LaneFlow uses a bundled sing-box core in TUN mode with fakeip routing and DNS interception.

**Fail-closed behavior**
The routing rules distinguish between:

- bound process → configured proxy exit;
- bound process UDP/QUIC → reject;
- unbound processes → direct/original route.

**DNS restoration**
LaneFlow restores the system DNS state when interception is disabled.
It also detects stale DNS takeover after restart and attempts automatic recovery.

**Crash / forced-termination recovery**
If the underlying routing process terminates unexpectedly, LaneFlow attempts to restore the affected network state.

**English + Chinese UI**
English is the default UI language, with Chinese localization available.

**No telemetry**
LaneFlow does not include telemetry, data collection, or automatic network updates.

## Verification

LaneFlow is not considered validated merely because the UI appears to work.
The project includes:

- 100-assertion SelfTest
- a dedicated real-machine verification tool
- strict exit-IP matching
- DNS takeover / restoration checks
- bound-process verification
- unbound-process comparison
- forced termination testing
- restart testing
- CI scanning and packaging gates

The key invariant is deliberately strict:
**The reported exit must exactly match the expected proxy exit IP.**

- A response containing the correct IP as a substring is not considered a match.
- JSON wrappers, HTML responses, decorated tokens, or partial matches are rejected.

This same matching rule is exercised by both the SelfTest suite and the real-machine verification path.

### Current Verification Status

Real-machine full-chain verification — **ALL GREEN**

Verified scenarios include:

```
Baseline
   ↓
LaneFlow startup
   ↓
DNS takeover
   ↓
Bound-process TCP routing
   ↓
Exact proxy-exit verification
   ↓
Unbound-process route verification
   ↓
Routing / adapter verification
   ↓
Forced termination
   ↓
Restart
   ↓
DNS restoration
```

The 2026-10-16 verification confirmed:

- bound processes reached the configured proxy exit;
- unbound processes retained the underlying route;
- routing survived restart;
- closing / forced termination restored the affected state.

## Philosophy

LaneFlow follows a simple engineering principle:
**If a behavior matters, define how it is measured.**

The project therefore prefers:

- explicit invariants over visual confirmation;
- reproducible tests over screenshots;
- failure disclosure over optimistic claims;
- recovery testing over happy-path testing;
- pinned dependencies over ambiguous environments.

The result is intentionally modest in scope:
a small tool with a clearly defined job, explicit boundaries, and evidence that the job actually works.

## Architecture

LaneFlow is built with:

| Layer | Technology |
|---|---|
| Desktop UI | .NET 8 / WPF |
| Privileges | Windows Administrator |
| Network core | sing-box v1.14.3 |
| Routing | TUN + fakeip |
| Configuration | Local JSON → runtime sing-box configuration |
| Testing | SelfTest + real-machine verification |
| CI | GitHub Actions |
| Packaging | Automated package gate + SHA-256 manifest |

The repository also pins the bundled sing-box version and records its checksum, while keeping the project and dependency licenses explicit.

## Security & Trust Model

LaneFlow is designed for use on a trusted local machine.
Proxy credentials are stored locally in the user's settings file. This is an explicit design trade-off rather than something the project attempts to hide.

LaneFlow does **not**:

- collect telemetry;
- upload user data;
- automatically update itself;
- provide a remote proxy service.

The only network component supplied by the application is the locally bundled routing core.

See [`SECURITY.md`](SECURITY.md) for the security policy and known limitations.

## Limitations

LaneFlow Free deliberately does not claim to solve every network-routing problem.
Current limitations include:

- Windows only;
- process-level TCP routing;
- UDP/QUIC is not supported in the free edition and is rejected for bound processes;
- enabling/disabling interception may cause a short connection interruption;
- the application requires administrator privileges.

These limitations are documented rather than hidden.

## Project Structure

```
src/LaneFlow/
  App.xaml(.cs)          Startup and crash recovery
  MainWindow.xaml(.cs)   UI and process binding
  Config.cs              Configuration and sing-box rendering
  Settings.cs            Persistent settings
  DnsOverride.cs         DNS takeover / restoration
  SandboxRunner.cs       Process and routing lifecycle
  ComboTagMatcher.cs     Process selection matching
  L10n.cs                Localization

tests/LaneFlow.SelfTest/
  ExitHitMatcher.cs      Strict exit-IP invariant

tools/
  cjk-scan.ps1           Repository content gate
  package.ps1            Packaging gate
```

## License

LaneFlow Free is released under the MIT License.
The bundled sing-box component is separately licensed under GPL-3.0.
See the `LICENSE/` directory for the applicable license texts.
