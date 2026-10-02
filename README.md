
# GOSE - JOSE and friends for the Go developer

[![Go Reference](https://pkg.go.dev/badge/github.com/eclipse-keypont/gose.svg)](https://pkg.go.dev/github.com/eclipse-keypont/gose)
[![Build](https://github.com/eclipse-keypont/gose/actions/workflows/ci.yml/badge.svg)](https://github.com/eclipse-keypont/gose/actions/workflows/ci.yml)
[![Lint](https://github.com/eclipse-keypont/gose/actions/workflows/lint.yml/badge.svg)](https://github.com/eclipse-keypont/gose/actions/workflows/lint.yml)
[![Secret Scan](https://github.com/eclipse-keypont/gose/actions/workflows/secret-scan.yml/badge.svg)](https://github.com/eclipse-keypont/gose/actions/workflows/secret-scan.yml)
[![Release](https://github.com/eclipse-keypont/gose/actions/workflows/release.yml/badge.svg)](https://github.com/eclipse-keypont/gose/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/eclipse-keypont/gose/badge)](https://scorecard.dev/viewer/?uri=github.com/eclipse-keypont/gose)
[![GitHub release](https://img.shields.io/github/v/release/eclipse-keypont/gose)](https://github.com/eclipse-keypont/gose/releases/latest)
[![Changelog](https://img.shields.io/badge/changelog-v0.x%20%E2%86%92%20v1.0.0-blue)](./CHANGELOG.md)

## Overview

GOSE is JOSE/JWT/JWK/JWS/JWKS implemented in Go with Helpers, and examples.

It contains implementations of the JOSE suite of types and helpers for many different use cases.

This repository is built with a hardened GitHub Actions pipeline: golangci-lint, govulncheck, CodeQL, secret
scanning, dependency review, and an OpenSSF Scorecard rating gate every push, and tagged releases are signed
and SLSA3-attested rather than just pushed — see [Releases & verification](#releases--verification) below for
what ships and how to check it.

Upgrading from a pre-1.0 release? See [CHANGELOG.md](./CHANGELOG.md) for the breaking changes and
what's new in v1.0.0.

## Part of Eclipse Keypont

gose is part of [Eclipse Keypont](https://projects.eclipse.org/projects/technology.keypont), alongside
[crypto11](https://github.com/eclipse-keypont/crypto11) and [pkcs11-go](https://github.com/eclipse-keypont/pkcs11-go).
*Keypont* — "key" plus the French *pont* ("bridge") — reflects the project's goal: bridging Go
applications to cryptographic keys held in HSMs and other PKCS#11-backed hardware.

## Known Issues

* Direct encryption with AEAD mechanisms is not completely following [RFC 7516](https://tools.ietf.org/html/rfc7516)

## Mission

- Simple
- Compliant
- Safe
- Efficient
- Extensible

## Examples

Examples are provided under the `/examples` folder to illustrate correct use of this package.

## Releases & verification

As a Go library, integrity for `go get` consumers is already provided by the Go module ecosystem: `go.sum`
pins content hashes and the public checksum database [`sum.golang.org`][sumdb] — a tamper-evident transparency
log — is checked on every fetch. You do not need to configure anything for that.

On top of that, each release is independently signed and attested:

- **Signed tags.** Release tags are GPG/SSH-signed (`git tag -s`, via `make release VERSION=x.y.z`). Verify with:
  ```bash
  git verify-tag vX.Y.Z
  ```
- **Signed source archive + SLSA3 provenance.** Pushing a `v*` tag runs
  [`release.yml`](.github/workflows/release.yml), which attaches to the GitHub Release a source archive
  (`gose-<tag>.tar.gz`), its SHA-256, a keyless [cosign][cosign] signature bundle, and a [SLSA3][slsa]
  provenance (`*.intoto.jsonl`). These serve auditors and OpenSSF Scorecard; `go get` does not use them.
  Verify a downloaded archive with:
  ```bash
  # cosign signature (keyless, GitHub OIDC identity):
  cosign verify-blob \
    --bundle gose-vX.Y.Z.tar.gz.cosign.bundle \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity-regexp '^https://github.com/eclipse-keypont/gose/.github/workflows/release.yml@refs/tags/vX.Y.Z$' \
    gose-vX.Y.Z.tar.gz

  # SLSA provenance:
  slsa-verifier verify-artifact \
    --provenance-path gose-vX.Y.Z.tar.gz.intoto.jsonl \
    --source-uri github.com/eclipse-keypont/gose \
    --source-tag vX.Y.Z \
    gose-vX.Y.Z.tar.gz
  ```

[sumdb]: https://sum.golang.org
[cosign]: https://github.com/sigstore/cosign
[slsa]: https://slsa.dev

## Third-party notices

[`NOTICES.md`](./NOTICES.md) lists all third-party dependency licenses and is auto-generated via `make notices` (requires [`go-licenses`](https://github.com/google/go-licenses)).

## Vulnerability check

```sh
$ govulncheck ./...

Scanning your code and 139 packages across 9 dependent modules for known vulnerabilities...

No vulnerabilities found.
```
