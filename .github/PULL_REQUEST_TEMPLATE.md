## Description

Please include a summary of the changes and the related issue(s) this PR resolves. Mention any architectural impacts or API modifications.

Fixes # (issue number)

## Type of Change

Please delete options that are not relevant:

- [ ] **Bug fix** (non-breaking change which fixes an issue)
- [ ] **New feature** (non-breaking change which adds functionality)
- [ ] **Breaking change** (fix or feature that would cause existing functionality to not work as expected)
- [ ] **Documentation Update** (documentation only changes)
- [ ] **Optimization / Refactoring** (performance improvements, cargo lint cleanups, etc.)

## Checklist

Before submitting this PR, please check off all completed tasks:

- [ ] My code follows the code style guidelines in `CONTRIBUTING.md`.
- [ ] I have run `cargo fmt` to format my changes.
- [ ] I have run `cargo clippy --workspace --all-targets -- -D warnings` and resolved all warnings.
- [ ] I have added unit or integration tests for my changes.
- [ ] I have verified that all existing tests pass: `cargo test --workspace`.
- [ ] I have updated the documentation or specification (RFC) if necessary.
- [ ] If this touches cryptography or parsing, I have considered fuzzing or property-based testing.
- [ ] I have verified that memory zeroization (`Zeroize` implementation) is maintained for private secrets.

## Additional Notes

Add any other details, diagrams, benchmark results, or screenshots showing verification.
