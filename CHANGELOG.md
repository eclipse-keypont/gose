# Changelog

All notable changes to gose are documented in this file. For the full commit-level history see
[GitHub Releases](https://github.com/eclipse-keypont/gose/releases).

## v1.0.0 — first stable release: pkcs11-go, crypto11/v2 and a hardened JOSE core

gose has been on `v0.x` since its start, with no stability contract. v1.0.0 is its first stable
release, marking the move to the `pkcs11-go`/`crypto11/v2` stack (the same PKCS#11 binding swap as
[crypto11](https://github.com/eclipse-keypont/crypto11) and [pkcs11-go](https://github.com/eclipse-keypont/pkcs11-go))
plus a round of correctness and API fixes to the JOSE core. The module path stays
`github.com/eclipse-keypont/gose` (no `/v2` suffix — that convention only applies from a library's
second major version onward).

### Breaking changes (relative to the last v0.x release)

- **PKCS#11 binding replaced**: `miekg/pkcs11` is out, [`eclipse-keypont/pkcs11-go`](https://pkg.go.dev/github.com/eclipse-keypont/pkcs11-go)
  is in, via the move to `crypto11/v2`.
- Repository moved from `github.com/ThalesGroup/gose` to `github.com/eclipse-keypont/gose`.
- **ML-KEM support removed.** `draft-ietf-jose-pqc-kem-06` dropped JOSE from its scope (retitled
  "PQ KEMs for COSE"), leaving no standards-track way to express ML-KEM in JWE. Rather than ship a
  bespoke, non-interoperable envelope, `mlkem_private.go`, `mlkem_public.go`,
  `jwe_mlkem_encryptor.go`, `jwe_mlkem_decryptor.go`, `hsm/mlkem_key.go`, `hsm/mlkem_key_store.go`
  and the `EncapsPubMlKemKey` / `DecapsPrivMlKemKey` / `DecapsPrivMlKemKeyStore` interfaces are gone
  pending a JOSE-side draft.
- **`jose.AlgRSAOAEPSHA2` is now `"RSA-OAEP-256"`, not `"RSA-OAEP"`.** It previously shared a value
  with `AlgRSAOAEP` and `AlgRSAOAEPSHA1`, so the SHA-256 variant went out on the wire under the
  name RFC 7518 §4.3 reserves for the SHA-1 variant. JWEs produced with `crypto.SHA256` now carry
  `"alg":"RSA-OAEP-256"` and are readable by other RFC 7518 implementations. Peers pinned to the old
  mislabelled output will not interoperate until they are updated; see *Fixed* for reading
  previously written data.
- `TrustStore.Get` and `JwksTrustStore` now take a `context.Context`
  (`Get(issuer, kid string)` → `Get(ctx context.Context, issuer, kid string)`); the underlying
  `httpClient` interface moved from `Get(url)` to `Do(req *http.Request)`.
- Logging no longer goes through `logrus`; internal panics on malformed input were converted to
  returned errors, and remaining logging uses the standard `log/slog`.

### Fixed

- **RSAES-OAEP JWEs advertised the wrong `alg`.** RFC 7518 §4.3 defines `RSA-OAEP` as OAEP with
  SHA-1 and `RSA-OAEP-256` as the SHA-256 variant, but gose emitted `RSA-OAEP` for both: the three
  constants `AlgRSAOAEP`, `AlgRSAOAEPSHA1` and `AlgRSAOAEPSHA2` all held `"RSA-OAEP"`. The output
  round-tripped against itself but a conformant recipient would derive SHA-1 and fail to unwrap the
  CEK, so these JWEs were not portable. The header now names the digest actually used, and
  `JweRsaKeyEncryptionEncryptorImpl.Encrypt` rejects digests RFC 7518 registers no OAEP algorithm
  for (previously e.g. SHA-512 was accepted and labelled `RSA-OAEP`).
  `JweRsaKeyEncryptionDecryptorImpl.Decrypt` now derives the OAEP digest from the header when
  passed `crypto.Hash(0)`. Passing a non-zero `crypto.Hash` still overrides the header, which is how
  JWEs written by earlier versions — `RSA-OAEP` in the header, SHA-256 on the wire — stay readable;
  data at rest does not need re-encrypting. `hsm.AsymmetricDecryptionKey` and generated JWKs keep
  `RSA-OAEP` as their `alg`, naming the OAEP family: the per-message digest comes from the JWE
  header, so one key still serves both variants (SoftHSMv2 implements only SHA-1).
- **AES-CBC + HMAC integrity bug**: `HmacShaCryptor.Hash` called `hash.Sum(input)`, which appends
  the digest to `input` instead of hashing it — since `Write` was never called, this computed the
  HMAC of the empty string rather than of the message. Masked by a PKCS#11 binding that silently
  accepted it; a stricter binding surfaced it as decrypt-time integrity failures.
- **AES-CBC + HMAC AAD mismatch**: `JweDirectEncryptorBlock.Encrypt` marshalled the protected header
  for the HMAC before setting `OtherAad` to the plaintext length, so the encrypted JWE and the
  HMAC'd header disagreed on `OtherAad`. `OtherAad` is now set before marshalling.
- JWK `UnmarshalJSON` (`PublicRsaKey`, `PrivateRsaKey`, `PublicEcKey`, `PrivateEcKey`,
  `OctSecretKey`) silently discarded a genuine `kty` type-mismatch error whenever
  `CheckConsistency()` happened to pass afterwards, instead of propagating it.
- Denial-of-service fix equivalent to CVE-2025-27144: compact-encoded JWTs/JWEs with excessive
  `.` separators could cause excessive memory use via unbounded `strings.Split`; the internal JWKS
  fetcher also gained a request timeout instead of relying on the Go default HTTP client's
  unbounded one.

### Added

- RSA-OAEP support for asymmetric encryption and decryption (SHA-1 and SHA-2 variants).
- AES-CBC-then-HMAC direct encryption support.
- A Cryptography Bill of Materials (CBOM) under `assets/cbom/`.
- `make release VERSION=x.y.z`, `make lint`, `make lint-fix`, `make notices`, `make version` and
  `make govulncheck` Makefile targets.
- `go-licenses`-generated `NOTICES.md` third-party license report.

### Changed

- `JweHeader` and `Jwe` are marked `// Deprecated` in favor of `JweProtectedHeader` and
  `JweRfc7516Compact`.
- Full `golangci-lint` cleanup across the codebase (`gofmt`/`goimports` comment conventions,
  ineffassign, and related findings).

### CI/CD & supply chain

- Unified security/quality pipeline shared across the pkcs11-go / crypto11 / gose projects:
  CodeQL, govulncheck, Gitleaks secret scanning, OpenSSF Scorecard, dependency review, and
  golangci-lint gate every push (replacing Travis CI).
- All third-party GitHub Actions pinned to commit SHAs.
- Tagged releases now produce a signed, **SLSA level 3**-attested source archive
  (via [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) and
  keyless [cosign](https://github.com/sigstore/cosign)) — see
  [Releases & verification](./README.md#releases--verification) in the README.

## Pre-1.0 (ThalesGroup/ThalesIgnite era, v0.x)

Originally maintained at `github.com/ThalesIgnite/gose`, later `github.com/ThalesGroup/gose`, built
on `miekg/pkcs11` and `crypto11` v1, and released as `v0.7.3` – `v0.13.0-rc1` with no stability
guarantee. Notable milestones:

- Core JOSE/JWT/JWK/JWS/JWKS implementation with HSM-backed keys via `crypto11`.
- Context support added to `TrustStore.Get` and the JWKS HTTP client.
- RSA-OAEP encryption/decryption, AES-CBC+HMAC direct encryption.
- CVE-2025-27144-equivalent DoS fix (unbounded compact-JWT/JWE splitting, unbounded JWKS fetch
  timeout).
- `logrus` removed in favor of the standard library and `log/slog`.
- Repository moved to `github.com/eclipse-keypont/gose`.
- Experimental ML-KEM (post-quantum) support was added against `draft-ietf-jose-pqc-kem-05`, then
  removed in v1.0.0 once the draft dropped JOSE from its scope.

Full commit history for this era is available via `git log v0.7.3..v0.13.0-rc1` or the
[GitHub Releases](https://github.com/eclipse-keypont/gose/releases) page.
