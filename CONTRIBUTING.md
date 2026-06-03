# Contributing

Thanks for improving CloseEnv.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo run -- scan . --no-fail
```

## Detector Rules

- Do not print matched secret values in text, JSON, SARIF, test failures, or
  debug output.
- Prefer high-confidence patterns over broad regex-like matching.
- Add tests for both detection and no-value-output behavior.
- Keep filesystem reads capped and skip generated dependency/build directories
  by default.

## Pull Requests

Small PRs are preferred. Include a short description of the detector or workflow
being changed and the validation commands you ran.
