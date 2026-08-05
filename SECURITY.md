# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub security advisories on
[github.com/madebydaniz/fwdeck](https://github.com/madebydaniz/fwdeck)
(Security → Report a vulnerability). Do not open public issues for security
reports. You should receive a response within a few days.

## Security model

FWDeck is firewall-management software; its security posture:

- **No shell, ever.** Commands are spawned via `Command::new` with typed
  argument vectors. There is no string interpolation into commands anywhere.
- **Validation at the boundary.** Every user- or backend-supplied value passes
  a validating constructor (charset, length, structure) before it can reach an
  argument vector.
- **Least privilege.** FWDeck never re-executes itself with sudo. Without
  privileges it degrades to read-only with a visible explanation
  (polkit denials are detected and surfaced).
- **Read-only is enforced in the application layer**, not the UI: in
  `--read-only` mode no code path can reach a mutating command.
- **Explicit, confirmed mutations.** Every change states the exact resource,
  zone, configuration target, and connectivity risk before applying, and
  partial failures are reported loudly with per-step diagnostics.
- **No secrets in logs.** The file log records commands, exit codes, and
  durations — not environment dumps.

## Scope notes

- The `firewall-cmd` CLI is trusted as the system's firewalld interface;
  FWDeck parses its output defensively (typed parsers, descriptive errors).
- Log entries shown in the Logs view come from the kernel ring buffer and are
  displayed as data, never interpreted.

## Verifying release artifacts

Every GitHub Release ships `checksums.txt` plus a keyless Cosign signature
(`checksums.txt.sig`, `checksums.txt.pem`, `checksums.txt.bundle`) produced by
the `release-binaries` GitHub Actions workflow via Sigstore. Verify before
installing:

```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "^https://github.com/madebydaniz/fwdeck/\\.github/workflows/release-binaries\\.yml@refs/tags/v[0-9]+\\.[0-9]+\\.[0-9]+$" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
sha256sum -c checksums.txt --ignore-missing
```

The certificate identity pins the artifact to this repository's release
workflow — a signature from any other source fails verification. The install
script (`scripts/install.sh`) performs both checks automatically.

Manual recovery builds must run from the exact release tag so they produce the
same certificate identity as an automatic release:

```bash
gh workflow run release-binaries.yml --ref vX.Y.Z -f release_tag=vX.Y.Z
```
