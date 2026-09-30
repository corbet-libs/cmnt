# cmnt

**Community facade of cvld: membership, gatekeeping and policy per community.**

Part of `cvld`, the permanent door of the cmtymeet trust stack. Native Rust,
development API; no registry publication. [Implemented contract](docs/CONTRACT.md).

`Community::begin` reserves a single-use BBS passport presentation request.
`Community::finish` verifies it with `cpsd`, uses the verified community pseudonym
as the member ID, loads membership, runs community gates and the legal veto,
asks `crbk`, commits admission through membership, and requests an Ed25519
COSE_Sign1 credential from the policy facade. The result is a credential, a
rulebook refusal with missing requirements, or a legal veto.

New members receive at most one day; established members at most 30 days.
Passport, community gates, policy freshness and signer limits can shorten this.
Renewal does not establish standing. Credentials, presentations, login dates,
request history, raw gates, profile values and pin salts are never stored here.

## Integration

- Implement `ports::Membership`, `Gatekeeping` and `Policy` over `cmbr`, `cgts`
  and `cplc`. Their main branches were scaffolds at the initial survey; do not
  substitute a permissive production adapter. Membership owns enrolment,
  passkeys, handles, pins, standing and coarse leases. Policy owns schema and keys.
- Supply authenticated issuer keys, policy/epoch snapshots and authoritative
  Unix seconds. Use an immutable UTF-8 community ID. Bind the holder exchange
  to the authenticated community session at the service boundary; rate-limit it.
- Keep the opaque `Challenge` on the server until completion; send only
  `challenge.request().to_bytes()` to the holder. It has no member identifier.
  A restart requires a fresh challenge. Call `prune` for expired challenges.
- Compose one `crlt::Db` per community, append `storage::SCHEMA` once to the
  complete service migration history, and construct `storage::LibsqlStorage`.
  `MemoryStorage` supplies the same leaf semantics for development/tests.
- `Policy::sign` delegates to `csgn::PersistentSigner` through `cplc`, checks
  the expected revision/key and signs JSON `CredentialClaims`. This facade
  verifies the returned signature, payload, key ID and protected times.

The admission action is always `community.admit`. Global proof metadata uses
provider label `cpsd`; the rulebook must enable that gate/provider explicitly.
Global provider verification remains the global issuer's responsibility. No
individual global expiry or provider identifier is disclosed by the passport.

## Dependency survey

Checked crates.io documentation and GitHub sources before implementation on
2026-09-30. Every cvld Git dependency is pinned by full revision in Cargo.toml.

| Candidate | Choice and reason |
|---|---|
| [cmbr](https://github.com/corbet-libs/cmbr), [cgts](https://github.com/corbet-libs/cgts), [cplc](https://github.com/corbet-libs/cplc) | Intended composition owners. Initially no callable implementation or contract on main; narrow local ports document their exact obligations. No placeholder Git dependencies. |
| [cpsd](https://github.com/corbet-foss/cpsd) | Selected BBS passport verification, pseudonyms and atomic replay protection; use its shared-epoch profile and existing storage implementations. No crypto or challenge algorithms copied. |
| [crlt](https://github.com/corbet-foss/crlt), [official libsql](https://docs.rs/libsql/) | crlt already supplies scoped transactions, migrations and index enforcement. Use its ready Git API, not the direct-driver fallback. Pin `9c076b1` to match cpsd/crbk types; the subsequent main commit `6b94dac` changes only a query-plan test. |
| [crbk](https://github.com/corbet-foss/crbk) | Selected rulebook snapshot/types/evaluation behind the policy port; no local all/any/threshold or provider-switch engine. |
| [csgn](https://github.com/corbet-foss/csgn) | Selected verification of policy-issued COSE credentials. Production signing remains behind `Policy`; the real persistent signer is used in integration tests. |
| [Casbin](https://github.com/apache/casbin-rs), [Cedar](https://github.com/cedar-policy/cedar) | Maintained general authorization engines; unnecessary beside the already implemented crbk vocabulary, and do not compose anonymous passports or community enrolment. |
| [coset](https://github.com/google/coset), [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | Maintained COSE/Ed25519 primitives already owned by csgn. No direct dependency or parallel signing implementation. |
| [cvch](https://github.com/corbet-foss/cvch) | Existing voucher library belongs behind cgts. Surveyed main has no Rust Cargo.toml or docs/CONTRACT.md; cmnt does not invent voucher execution. A development-only test gate lives in the test harness. |

Serde/serde_json supply the versioned payload, thiserror static errors, and
Tokio/tempfile the test runner and real local databases. Leaves retain their
LGPL linking exception; other dependencies use permissive alternatives. No
GPL-only or AGPL-only dependency is intentionally selected.

## Validation

GitHub Actions runs stable Rust `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`. Cargo must not run
on the workstation. Integration tests use real BBS issuance/presentation,
rulebook decisions, COSE signatures and local libSQL storage; no cmnt decision
or cryptographic path is mocked. The development gate is compiled only in tests.

The optional Turso test returns without connecting unless both `TURSO_URL` and
`TURSO_TOKEN` are nonempty. Supply only a disposable test database on an
authorized runner; credentials belong neither in this repository nor in CI.

## Current limits

Facade-port adapters remain required until cmbr/cgts/cplc expose compatible APIs.
The host serializes membership/policy changes with issuance; the ports must
compare revisions, and admission plus signing is not a distributed transaction.
An ambiguous failure releases no credential; obtain a new challenge and reconcile
membership state. Individual early global revocation awaits cpsd accumulators;
current protection is authenticated epochs and expiry. No browser requirement
applies to this server facade.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
