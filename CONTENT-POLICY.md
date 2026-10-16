# Content Policy (Public-Facing Wording Red Lines)

Status: governance doc for all public-facing text of LaneFlow Free
Applies to: README.md, README.zh.md, SECURITY.md, release notes, GitHub repo description/topics,
landing page, storefront copy, and any future public communication about this project.

## 1. Positioning (what this project is)

LaneFlow Free is a **process-level traffic routing tool for Windows**. It performs
second-stage traffic splitting on top of an existing TUN/VPN or proxy setup:
a chosen process's traffic is routed to a configured exit endpoint; everything else
keeps its original path. It is a routing/control layer for the local machine only.

Allowed primary descriptors:

- process-level traffic routing
- second-stage traffic splitting
- per-process routing / application-level traffic control
- routing on top of an existing TUN/VPN or proxy setup
- configured exit endpoint / dedicated exit

The word "proxy" is allowed **only as a technical noun** (e.g. proxy endpoint,
proxy credentials, configured proxy exit). It must never be used to **self-describe
the product** (e.g. "LaneFlow is a proxy", "a proxy tool").

## 2. Prohibited categories (red lines)

Never use any of the following to describe LaneFlow or its purpose.
Items are defined by category, not by enumerating example words:

| Category | What is prohibited |
|---|---|
| Self-claim as VPN / proxy service | Any wording that labels the product itself as a VPN, a proxy service, a proxy provider, or a circumvention client. |
| Circumvention framing | Any claim that the tool bypasses a firewall, unblocks websites, or provides access to restricted content. |
| Region-specific access claims | Any promise that region-restricted content becomes reachable through this tool. |
| Colloquial network slang | Circumvention- or VPN-flavored slang in any language (English, Chinese, or otherwise) used to describe the product. |
| Content-access guarantees | Any statement implying the product guarantees access to specific services or content. |

Rationale: the project is a local routing control tool; its legitimate technical
scope is routing a process's traffic to a user-supplied endpoint. It does not
provide proxy service, node pools, or content access guarantees. Public copy must
describe what the software does, never suggest what it enables.

## 3. Rules for all public text

1. Describe function neutrally; never hint at use cases involving restricted access.
2. "proxy" appears only as a technical term, never as a product label.
3. Chinese and English versions share the same neutral wording (no stronger claims
   in the Chinese edition).
4. No real IPs, base-product names, internal codenames, or workflow traces in any
   public text (see also the repository redaction gate).
5. No telemetry / data-collection / auto-update claims beyond what SECURITY.md states.
6. Capability boundaries (UDP/QUIC not supported, TCP-only splitting, credentials
   stored locally) are stated plainly and never overstated.

## 4. Enforcement

- Before any public release, run the repository word-scan gate (see `.github/workflows/scan.yml`
  and `tools/`) with the red-line categories included.
- Any public-facing text containing a prohibited expression is a release blocker.
- When in doubt, prefer the neutral technical descriptor over a colloquial one.

## 5. Dual-language note (README.zh)

The Chinese edition is preserved for bilingual readers but must carry the same
neutral wording as the English edition — no additional "access" or "VPN" framing.
