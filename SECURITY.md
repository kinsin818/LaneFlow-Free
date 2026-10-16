# Security Policy

## Credential handling

LaneFlow Free stores proxy credentials in **plaintext** on this machine at `%APPDATA%\LaneFlow\settings.json`.
This is a known design trade-off of the free edition (see the capability-boundary disclosure in the
README), premised on the software only running on machines the user trusts.
Do not save exit configurations containing credentials on shared / public machines.

## Data collection

This software **collects no data**, contains no telemetry, and does not self-update over the
network. It only invokes the bundled sing-box kernel locally, routing the chosen processes'
traffic to the proxy you configured.

## Reporting vulnerabilities

If you find an issue, please submit it through the feedback channel on the project homepage,
including: reproduction steps, environment (Windows version, .NET 8 runtime), the configuration
file (with credentials redacted first), and logs. Issues involving credential leakage must be
submitted privately.

## Kernel supply chain

The bundled sing-box binary is locked to v1.14.3; sha256 values are in `core/SHA256SUMS.txt`.
Release packages must be reproducible from a clean commit with matching binary checksums; any
checksum mismatch counts as a failure and must not be released.
