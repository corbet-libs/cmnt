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

Use `adapters::CplcPolicy` for the actual cplc rulebook/schema/durable issuer.
Implement `ports::Membership` and `Gatekeeping` over the service's membership
and gate runners. cmbr/cgts landed APIs during this work, but they cannot yet
coexist with cpsd in a Cargo graph: cpsd pins zeroize `=1.8.2`, while cpns beneath
both facades requires `^1.9`. CI confirmed this resolver conflict. These local
ports are the authorized interim boundary; no leaf logic is reimplemented.
Trusted port inputs must never be deserialized straight from an HTTP request.

The service supplies canonical community routing, authenticated issuer keys,
global epoch policy, a trusted clock, rate limits and session/device authorization.
Keep `Challenge` on the server; send only `challenge.request().to_bytes()` to the
holder. On restart obtain a new challenge. Call `prune` for expired challenges.
The admission action is always `community.admit`; configure cmbr/cplc with that
same action. Enable global gate provider `cpsd` explicitly in the rulebook.

Compose one physical database per community. Append `storage::SCHEMA` once,
plus the sibling facade schemas, to the service's complete migration history.
Run that complete history with `Db::migrate` on every opened `crlt` handle,
including after a restart, to initialize its in-memory schema registry.
`LibsqlStorage` and `MemoryStorage` delegate challenge operations to cpsd.
The membership adapter supplies current enrolment, pins, reserved handle, standing
and authorized device keys; none is chosen by the presentation. It must revalidate
state and delegate admission/coarse lease extension, while the service serializes
membership, policy and gate changes across the complete issuance operation.

`CplcPolicy` uses the same rulebook store as its inner cplc instance. It checks
current epoch/schema/key again under its writer mutex, then calls `cplc::issue`.
cmnt verifies the returned COSE and matches its cplc payload and protected
metadata. `CredentialClaims` is a convenient verified view, not a second wire
format. The wire payload is `cplc::Credential`; issued/expiry/key ID are protected
COSE headers. No arbitrary-payload signing endpoint is exposed by cmnt.

## Dependency survey

Checked crates.io documentation and GitHub sources on 2026-09-30 before writing.
Every direct cvld Git dependency is pinned by full revision in Cargo.toml.

| Candidate | Choice and reason |
|---|---|
| [cmbr](https://github.com/corbet-libs/cmbr), [cgts](https://github.com/corbet-libs/cgts), [cplc](https://github.com/corbet-libs/cplc) | APIs landed during implementation. cplc is integrated by pinned revision; cmbr/cgts require local ports until their cpns zeroize requirement is compatible with cpsd. |
| [cpsd](https://github.com/corbet-foss/cpsd) | Selected BBS verification, community pseudonyms and atomic replay protection. Use its shared-epoch profile and storage, without copying challenge/crypto logic. |
| [crlt](https://github.com/corbet-foss/crlt), [official libsql](https://docs.rs/libsql/) | crlt already supplies scoped transactions, migrations and index enforcement. No direct-driver fallback. Match cpsd/crbk's `9c076b1` type; newer facades use `6b94dac`, whose source difference is a query-plan test. |
| [crbk](https://github.com/corbet-foss/crbk), [csgn](https://github.com/corbet-foss/csgn) | Reuse policy types/evaluation and COSE verification. No local policy evaluator, signature engine or key store. |
| [Casbin](https://github.com/apache/casbin-rs), [Cedar](https://github.com/cedar-policy/cedar) | Maintained general authorization engines; redundant with crbk and do not supply passport/community composition. |
| [coset](https://github.com/google/coset), [ed25519-dalek](https://github.com/dalek-cryptography/curve25519-dalek) | Maintained primitives already owned by csgn. No parallel signing implementation. |
| [cvch](https://github.com/corbet-foss/cvch) | Existing voucher execution belongs behind the cgts port; no second voucher implementation. Its standalone contract file is absent at the surveyed revision. |

Serde/serde_json supply typed views, thiserror redacted errors, Tokio serialization,
chrono calendar conversion, and tempfile real database fixtures. Tests use the
real crgs register as well. cplc retains FSL; selected leaves retain their LGPL
linking exception. Third-party dependencies have permissive alternatives.
The CI-resolved Cargo.lock fixes the complete dependency graph; no leaf code is copied.

## Validation

GitHub Actions runs stable `cargo fmt --check`,
`cargo clippy --all-targets -- -D warnings`, and `cargo test`. No Cargo command
runs on the workstation. Tests use real BBS issuance/presentation, crgs,
crbk, COSE, the actual cplc adapter and local libSQL. Failure fixtures exercise external
ports; cmnt decisions, cryptography and database operations are never mocked.
Always-pass gates exist only in test binaries.

The optional Turso test returns without connecting unless both `TURSO_URL` and
`TURSO_TOKEN` are nonempty. Supply only a disposable test database on an
authorized runner; credentials belong neither in this repository nor in CI.

## Current limits

- cmbr/cgts concrete adapters are blocked by the incompatible upstream zeroize
  requirements described above. The local ports require trusted service adapters.
- cplc currently has no explicit issuance-expiry ceiling. `CplcPolicy` requires
  at least one verified global gate and conservatively shortens that transient
  assertion to the community lifetime bound. It never fabricates a gate or
  extends an expiry. A gate-free passport policy is refused by this adapter.
- Upstream crlt pins differ, so cpsd/crbk and newer facade concrete stores need
  matching Rust handles to the **same physical database**. Align upstream pins
  before claiming one shared pool for every leaf.
- Membership plus signing is not one transaction. Serialize service writers.
  Failure may leave a committed lease but never returns an unverified credential;
  obtain a new challenge and reconcile. cmbr's crash recovery contract still applies.
- Session expiry/device authorization, establishment policy, fresh revocation
  distribution and immediate individual global revocation remain upstream duties.
  cpsd currently provides authenticated epochs and expiry, not accumulators.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).
