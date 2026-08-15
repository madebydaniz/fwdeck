## What does this PR do?

<!-- A short description. Link the issue if one exists. -->

## Checklist

- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, …) — releases and the changelog are generated from them
- [ ] `cargo fmt --all -- --check` passes
- [ ] `cargo clippy --all-targets -- -D warnings` passes (and with `--features dbus`)
- [ ] `cargo test` passes
- [ ] Mutation-path changes keep the safety invariants: validation → confirmation → honest result (see [ARCHITECTURE.md](../ARCHITECTURE.md))
