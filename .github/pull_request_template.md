## Summary

Describe the change and why it is needed.

## Validation

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo run -- scan . --no-fail`

## Secret Safety

- [ ] This PR does not add live secrets, tokens, private keys, or credential files.
- [ ] Any detector fixtures are fake values and are not printed in reports.
