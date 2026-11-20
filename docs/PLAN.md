[object Object]

- [x] Preserve leading-compression IPv6 destinations (including `::/0`) when validating colon-delimited route journal keys; retain canonical address-family and prefix checks.
- [x] Treat a process that vanishes between procfs identity inspection and pidfd opening as stale during restart recovery, while preserving hard failures for non-absence inspection errors and rejecting live PID reuse.

These are regression fixes to offline validation and restart classification only. Local tests, formatting, Clippy, and release checks must be rerun; TUN activation remains disabled.


- [x] Add draft unified TUN orchestrator monitoring entrypoint, strict activation/recovery UUID checks, interface validation, allocation-floor validation, and focused request validation tests. Document the integration state in README and TUN design/plan documents.
- [ ] Resolve core attachment to the broker-owned exclusive TUN descriptor; interface-name configuration alone is not evidence of attachment.
- [ ] Connect public activation, launch, readiness/traffic checks, stop, and CLI-independent supervisor; retain fail-closed activation gating until this is verified.
