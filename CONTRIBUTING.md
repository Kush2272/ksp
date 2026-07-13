# Contributing to Kush Secure Protocol (KSP)

Thank you for your interest in contributing to KSP! We welcome contributions to improve performance, hardening, documentation, and tooling. 

By contributing, you agree that your code will be licensed under the project's [MIT License](LICENSE).

---

## 🏗️ Development Setup

1. **Install Rust**: You will need the latest stable version of Rust (1.96+). Install it via [rustup.rs](https://rustup.rs/).
2. **Clone the Repo**:
   ```bash
   git clone https://github.com/Kush2272/ksp.git
   cd ksp
   ```
3. **Compile the Workspace**:
   ```bash
   cargo build --workspace --all-targets
   ```
4. **Run Unit & Integration Tests**:
   ```bash
   cargo test --workspace
   ```

---

## 🎨 Quality Standards & Linting

We enforce strict quality guidelines to ensure protocol safety and codebase maintainability:

* **Formatting**: Code must pass `cargo fmt`. Always run formatting before committing:
  ```bash
  cargo fmt --all -- --check
  ```
* **Lints**: Code must be free of warnings and compile successfully. We run Clippy with strict flags:
  ```bash
  cargo clippy --workspace --all-targets -- -D warnings
  ```
* **Documentation**: All public APIs must have thorough documentation comments (`///`) detailing parameters, return types, and safety/panic conditions.
* **Testing**:
  * Every new feature or bug fix must include corresponding tests.
  * For serialization / parsing logic, we encourage property-based testing (using the `proptest` crate).
  * For untrusted packet parsers, implement a fuzz target under `crates/ksp-fuzz` using `cargo-fuzz`.

---

## 📝 Commit Conventions

We strictly follow the [Conventional Commits](https://www.conventionalcommits.org/) specification. This automates our CHANGELOG generation and release notes.

Format: `<type>(<scope>): <short description>`

* **`feat`**: A new feature (e.g., `feat(crypto): add post-quantum hybrid handshake`)
* **`fix`**: A bug fix (e.g., `fix(transport): correct sliding window bitmap shift logic`)
* **`docs`**: Documentation updates (e.g., `docs(readme): correct setup CLI parameters`)
* **`test`**: Adding or correcting tests (e.g., `test(handshake): add invalid signature test case`)
* **`chore`**: Maintenance work (e.g., `chore(deps): update tokio to v1.38`)

---

## 🚀 Pull Request Workflow

1. **Branch Naming**: Use descriptive branch names (e.g., `feature/hybrid-pqc` or `bugfix/replay-window-shift`).
2. **Open a PR**: Fill out the provided pull request template fully.
3. **Continuous Integration**: Ensure that the CI checks pass. All checks (`fmt`, `clippy`, `test`, `audit`) are required to pass before merge.
4. **Review & Approval**: High-sensitivity crates (`ksp-crypto` and `ksp-handshake`) require approval from at least one core maintainer before merging.
