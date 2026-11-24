# Development and verification policy

## Strict rule: verification is local only

Proxyctl does not use GitHub Actions for continuous integration. All formatting, linting, tests, packaging checks, and release-readiness verification are performed locally by the maintainer.

- Do not create, restore, enable, dispatch, trigger, or run GitHub Actions workflows for CI.
- Do not inspect, poll, monitor, or report GitHub Actions run/job/check results as part of development work.
- Do not add CI workflows or CI triggers for pushes, pull requests, schedules, or manual dispatch.
- Do not make a source change contingent on a GitHub-hosted CI result. The maintainer runs the checks locally and reports the results.
- Keep release automation separate from CI. The release workflow may package and publish an explicitly tagged release, but must not run formatting, Clippy, tests, or other CI/quality gates on GitHub.
- When documenting verification, distinguish checks actually run locally by the maintainer from checks not yet run. Never imply that a remote workflow passed.

This is a project-level, strict instruction and takes precedence over generic repository automation conventions.

## Local verification

Run the relevant checks from the repository root on the maintainer's machine. The standard Rust quality checks are:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --bins
```

Run packaging and privileged/network namespace checks locally when the change affects those areas. TUN activation must remain gated unless its specific safety and host-validation requirements are satisfied. Do not substitute a successful compile or unit-test run for privileged integration or real-host validation.
