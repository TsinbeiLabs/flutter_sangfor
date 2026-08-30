# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| 0.0.x | security fixes only |

## Reporting a Vulnerability

Report vulnerabilities privately to `team@tsinbei.com`. Include a
description of the issue, affected code paths, and reproduction steps or
a proof of concept if available.

Please do not open public issues for security problems. We will respond
within 72 hours and credit reporters in the fix's changelog entry unless
anonymity is requested.

## Scope

This project is a clean-room reimplementation of publicly observed wire
behavior for Sangfor remote-access VPNs (aTrust and Easy Connect). It
contains no Sangfor SDK binaries, proprietary code, or credentials.

In scope:

- Anything in this repository (Dart, Kotlin, Swift, CI workflow).

Out of scope:

- Vulnerabilities in Sangfor server software (report to Sangfor).
- Vulnerabilities in dependencies (report upstream; we will track and
  bump versions).
- Active attacks against production VPN deployments you do not own or
  are not authorized to test.
