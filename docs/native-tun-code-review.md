# Native TUN lifecycle code review

## Scope and workflow
- Review the Linux managed TUN lifecycle, persistent interface ownership, broker authorization/framing, journal/manifest persistence, recovery, process identity, and systemd supervision.
- Review live `main` source, apply code and necessary regression-test source changes, and commit review improvements directly.
- Do not run tests, formatting, CI, or activate/change host TUN/network state in this review phase. The maintainer will run local formatting and tests afterward.
- Review prioritizes fail-closed behavior, identity binding, race resistance, durable recovery, bounded resources, separation of responsibilities, and SOLID design.
- Keep this record current as the review proceeds; findings are not marked resolved without a code change or documented reason.

## Applied fixes
- `src/tun/native_core_launcher.rs`: require systemd ActiveState=active and SubState=running before capturing the service MainPID.
- `src/tun/process.rs`: treat pidfd_open file descriptor 0 as a valid success, not as a failure/special case. (The syscall returns any nonnegative descriptor.)

## Deferred verification
- Tests, formatting, and CI are intentionally not executed during this phase.
- Regression tests will be added or updated in source where practical; they remain unexecuted until maintainer validation.
- No host networking or TUN state has been activated or changed by this review.

## Maintainer validation feedback and compile fixes

The maintainer ran `cargo fmt --all -- --check`, `cargo test --all-targets`, and `cargo clippy --all-targets --all-features -- -D warnings` on 2026-11-21. Formatting emitted no diagnostics; test and Clippy compilation failed before tests executed.

Applied source corrections for the reported diagnostics:
- Corrected the Unix `AsRawFd` import path and removed unused `AsFd` / `Context` imports.
- Corrected adapter contract test references to the parent `adapters` module.
- Routed Xray end-to-end activation through the core-dispatch method, propagated runtime-directory errors correctly, and corrected route-policy references in request tests.
- Added an IPv4/IPv6-aware link-local predicate for readiness target validation.
- Avoided accessing libc's private `sockaddr_nl` padding field while retaining kernel family, PID, group, and sockaddr-length validation.
- Fixed the netlink test's overlapping mutable/immutable borrow and the descriptor-transfer test's mutable stream binding.
- Fixed the moved-error handling in managed activation and removed unused variables/mutability.
- Removed unreachable code after the pidfd signal retry loop and corrected the Xray socket file-type extension import and attachment-wait error handling.

## Verification status

- `cargo fmt --all -- --check`: no diagnostics in the maintainer-provided run.
- `cargo test --all-targets`: compilation failed before test execution; the single native-adapter integration test was reported ignored because all three managed core binaries were unavailable.
- `cargo clippy --all-targets --all-features -- -D warnings`: compilation failed on the same diagnostics.
- The above compile fixes have been committed to `main`, but they are **not verified** until the maintainer reruns formatting, tests, and Clippy against the latest commit.
- No tests, formatting, Clippy, CI, or host TUN/network mutations were run by this review pass.
