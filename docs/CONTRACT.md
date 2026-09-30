# cmnt implemented contract

Community facade of cvld v0.4: compose cmbr (membership), cgts (community gates)
and cplc (rulebook, schema, community signing). Verify member passport
presentations with cpsd; the community pseudonym is the member ID. Issue an
Ed25519 COSE_Sign1 community credential with a one-day cap for new members and
a 30-day cap for established members, shortened by gate expiries.

Rust native server library, FSL-1.1-ALv2. No own crypto, login dates, request
logs, raw gate evidence, profile values, salts or stored credentials. One
database per community through crlt; the global service's database is separate.
Every table has a community key and every application query is index-backed.
No registry publication. Maintained dependency survey is in the README.

## Composition boundary

At the initial survey, cmbr main was `d76cff03`, cgts `5eb1fa4c`, cplc
`bb602939`: scaffolds without usable APIs/contracts. Local `Membership`,
`Gatekeeping` and `Policy` ports are the explicitly permitted interim boundary.
They are trusted server capabilities, not member-supplied implementations.
There is no reimplementation of their leaves in cmnt.

`Membership::member` resolves a verified pseudonym into an existing enrolment,
handle, cnrl state, pins, standing and revision. `admit` compares that revision,
commits admission/renewal and extends the coarse lease. It refuses released or
concurrently changed membership and never promotes standing just because a
credential was requested. The host decides establishment through cmbr policy;
cmnt neither stores admission dates nor implements a probation clock.

`Gatekeeping::run` executes community gates and the legal veto. It takes a
trusted member, returns only verified results, and keeps raw inputs in leaf
sessions. cmnt rejects global results from this port, foreign subjects/scopes,
expired/future/invalid metadata and duplicate gate/provider pairs. Gates must
omit failed or expired proofs so the rulebook can return missing requirements.
The legal veto always prevents credential issuance.

`Policy::snapshot` returns an effective crbk snapshot, schema version,
authenticated global epoch/common-expiry/required gates, freshness deadline and
authenticated csgn public ring. Community and global epochs remain distinct.
`Policy::sign` uses cplc/csgn persistent signing and checks the expected policy,
schema and key before signing. Its JSON payload and protected headers must agree.

## Admission and lifetime

1. `Community::new` checks fixed community scope across all capabilities and a
   nonempty trusted global issuer key ring. Scope is canonical immutable UTF-8,
   bounded to csgn's issuer limit. Challenge lifetime is explicit, 1–300 seconds.
2. `begin` loads policy and registers a cpsd common-expiry request. Its deadline
   cannot reach the policy or passport expiry. The opaque `Challenge` stays in
   server memory; only its cpsd request is sent to the holder. There is no API
   for restoring this object from untrusted JSON.
3. `finish` reloads and compares policy, checks authoritative time and scope,
   verifies the BBS proof, and atomically consumes the nonce through cpsd before
   looking up a member. Member ID is exactly `Pseudonym::to_hex()`; no caller
   chooses or overrides it. Invalid proofs do not consume their challenge.
4. It loads membership and runs community gates. Only verified global gate
   names from the passport request are rebound to this pseudonym, using provider
   label `cpsd`. No raw global provider data or holder identifier is propagated.
5. `crbk::Snapshot::may` evaluates the fixed `community.admit` action. Missing
   or disabled actions/gates/providers fail closed under crbk rules. Maximum
   proof age cannot be satisfied by global proofs, which have no disclosed
   proof issuance time. Missing requirements go back to the lobby.
6. Expiry is the minimum of the standing cap, signer maximum validity, passport
   common expiry, policy freshness and every returned gate expiry. Community
   expiry is exclusive (`issued <= now < valid_until`), conservatively stricter
   than cpsd's inclusive expiry. Credentials cannot outlive their passport.
7. Membership commits before signing. Policy is rechecked, cplc signs, and cmnt
   verifies the COSE signature, kind, issuer, key ID, payload and protected times
   before returning the credential. No returned claim comes from client JSON.

The host authenticates and binds the holder exchange to the member session,
throttles before expensive proof verification, supplies a trusted clock and
serializes relevant membership/gate/policy changes with issuance. Calls use an
authoritative time snapshot; this library does not read a clock or promise a
distributed transaction. A revision check detects intervening changes, but is
not a substitute for the service's writer discipline. A signing failure may
leave admission/lease already committed; no credential escapes. Replay after a
successful proof verification fails even after a downstream denial/error.
Retry with a fresh challenge; never persist signed responses for idempotency.

## Credential format

Tagged COSE_Sign1, Ed25519, csgn kind `Credential`, issuer `cmnt:<community>`.
JSON payload version 1, unknown fields denied:

`version`, `community`, `member_id`, `handle`, `gates` (gate, provider,
valid_until; implicitly community level and this member), `pins` (field to
32-byte fingerprint), `schema_version`, `policy_epoch`, `issued`, `valid_until`,
`key_id` (32-byte COSE thumbprint). Community gates are sorted by gate/provider.
Global gate disclosures and transient proof times are not copied into payloads.
Issued/expiry/key ID also occur in csgn's protected headers and must match.
Public rings arrive over an authenticated channel; COSE decoding cannot create
trust in an arbitrary key. Early revocation/epoch distribution belongs upstream.

## Storage and validation

`storage::Storage` supplies an existing shared `ChallengeStore` capability.
`MemoryStorage` and `LibsqlStorage` are thin wrappers over cpsd's actual
implementations, not duplicate replay logic. Clones share nonce state.
`storage::SCHEMA` is cpsd's schema; append it once to the service migration list.
Its composite primary key and expiry index start with community_id, encoded by
cpsd as `cpsd/<hex canonical community bytes>`. crlt owns execution and enforces
query plans. No extra cmnt table is necessary.

Only outstanding random nonces, request digests and deadlines persist. Successful
consumption deletes them atomically; `prune` removes expired rows. Capacity is
bounded. Storage loss rejects outstanding proofs. After a remote timeout the
outcome may be uncertain; fail closed and request a new challenge. Backups/WAL
retention and disabling dependency SQL/HTTP debug tracing are host duties.

Validation runs only on GitHub Actions: stable formatting, strict all-target
Clippy and real tests. Tests exercise BBS passports, rulebook decisions, COSE,
memory and local libSQL, failures, scope/epoch changes, lifetimes, replay,
concurrency, persistence and indexed query plans. The always-passing development
gate exists only inside tests. Live Turso is optional and skipped unless both
environment credentials are nonempty; no credentials are supplied by CI.

This is not a completed cvld service or an independent cryptographic audit.
Facade adapters, authentication/passkeys/enrolment UI, immediate individual
global revocation and operational retention remain outside this crate.
