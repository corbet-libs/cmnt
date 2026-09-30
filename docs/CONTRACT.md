# cmnt implemented contract

Community facade of cvld v0.4: compose cmbr (membership), cgts (community gates)
and cplc (rulebook, schema, community signing). Verify passport presentations
with cpsd; the community pseudonym is the member ID. Issue an Ed25519 COSE_Sign1
credential, at most one day for new members and 30 days for established members,
shortened by gate expiries and other authoritative validity bounds.

Rust native server library, FSL-1.1-ALv2. No own crypto, login dates, request logs,
raw evidence, profile values, pin salts or stored member credentials. One physical
database per community through crlt, with a community key in every table and
indexed application queries. Global data/keys/databases remain separate.
No registry publication; Rust validation runs only on GitHub Actions.

## Composition

`Community<S, M, G, P>` consumes fixed community capabilities through small
Storage, Membership, Gatekeeping and Policy traits. cmbr/cgts/cplc initially had
no usable APIs; after they landed, concrete adapters were added and their
revisions pinned. These ports are trusted Rust interfaces, not public RPC bodies.

`CmbrMembership` binds a real cmbr passkey authentication receipt to the verified
pseudonym. It resumes enrolment, reads current authorized pin fields, obtains
state/revision, compares the complete member before admission and calls cmbr's
fresh admission evaluation and coarse lease extension. Handles come from trusted
reserved-handle metadata, standing from membership policy, and authorized public
device keys from the service's pairing protocol. Renewals never establish standing.
All writers share its supplied mutex and the service serializes complete issuance
across processes. No per-member admission or login timestamp is introduced.

`CgtsGatekeeping` delegates typed gate execution through its existing gatekeeper,
collects enabled retained facts, validates attached transient CheckedGate values
against exact member/action/revision/epoch/time through cgts, and always enforces
the legal veto. Raw inputs remain with typed leaf sessions. cmnt rejects global
results from this port, foreign bindings, expired/future/invalid metadata and
duplicate gate/provider pairs. Failed/expired checks should be omitted so crbk
can return missing requirements. A legal veto overrides any permissive policy.

`CplcPolicy` owns serialized access to the real cplc issuer. It loads an effective
crbk revision from the same rulebook store used by cplc, obtains current schema,
effective epoch and public keys, and combines them with an authenticated global
passport schedule and explicit freshness deadline. Global/community epochs remain
distinct. On issuance it rechecks expected policy/schema/key under the same mutex
and calls cplc::issue, which evaluates policy again and durably delegates signing
to csgn. cmnt implements no signing or retention engine.

## Admission sequence

1. `new` checks component scopes, canonical UTF-8 community, a nonempty trusted
   global issuer key ring and an explicit challenge lifetime of 1–300 seconds.
2. `begin` loads effective policy and reserves a cpsd common-expiry request. The
   deadline is strictly before passport/policy expiry. An opaque Challenge stays
   in server memory; only its cpsd request goes to the holder. The service binds
   that exchange to its authenticated community session and limits capacity/rate.
3. `finish` checks time/scope and policy freshness, verifies the BBS proof and
   atomically consumes its nonce through cpsd. Only then does it use exactly
   Pseudonym::to_hex() as the member ID. Invalid proofs consume nothing.
4. Membership is loaded, gates run and legal veto checked. Only global gate names
   proved by the registered passport request are rebound to that pseudonym, with
   provider label `cpsd`. No global holder ID or raw provider evidence is exposed.
5. crbk evaluates only `community.admit`; members cannot select an easier action.
   Missing/disabled actions, gates and providers fail closed. Configure cmbr and
   cplc with the same action. Missing requirements return to the lobby. Global
   proofs disclose no proof issuance time, so cannot satisfy maximum-proof-age
   requirements by inventing a check/login time.
6. The expiry ceiling is the minimum of standing cap, signer maximum validity,
   passport expiry, policy freshness and every returned gate expiry. cplc can
   shorten further for proof age or scheduled policy activation. Community expiry
   is exclusive, conservatively stricter than cpsd's inclusive expiry.
7. Membership admission/lease commits before cplc issuance. Policy is checked again.
   cmnt verifies the returned COSE signature, kind, community issuer, active key,
   payload and protected times. Only a matching credential within the expiry
   ceiling is returned. No signed response or proof is cached.

The current cplc API has no explicit expiry-ceiling argument. Its adapter requires
at least one proved global gate, shortening that transient assertion's validity
before calling cplc. Shortening is conservative; no gate is fabricated, no expiry
extended, and community gate expiries remain intact. A gate-free global policy is
refused until an upstream explicit ceiling API is available.

A valid consumed proof cannot be reused after denial, downstream failure or lost
response. Request a new challenge. Losing the server-held Challenge on restart
also requires a new request. Errors expose fixed categories without input values.
Time is a service-supplied snapshot, not a library clock. The service owns session
expiry/device removal, authenticated policy/key distribution and serialization of
membership/gate/policy changes with complete issuance. There is no distributed
transaction: a signing failure may leave admission/lease committed, but no
credential is returned. Reconcile uncertain remote outcomes; do not blindly retry
mutations or bypass cmbr's recovery procedure.

## Credential wire format

Use cplc::Credential inside csgn's tagged COSE_Sign1, kind Credential, issuer equal
to the canonical community. JSON fields are community, member (the pseudonym),
handle, schema_version, policy_epoch, community gates (gate/provider/valid_until),
pins (field/fingerprint) and authorized public device keys. Protected COSE headers
supply issued time, exclusive expiry and key ID. Global gate disclosures and
transient proof times are omitted. cplc owns validation and serialization.

CredentialClaims is a verified convenience view combining that payload and COSE
headers; its version field describes this view and is not an extra wire field.
Consumers must verify signatures with authenticated keys and fresh policy epochs;
parsing a key ring cannot establish trust. Individual early global revocation is
not implemented by cpsd v1; epoch and expiry limits continue to apply.

## Storage

`Storage::challenges` supplies shared atomic leaf state. MemoryStorage and
LibsqlStorage wrap cpsd's real implementations, not duplicate replay logic.
SCHEMA is the cpsd challenge DDL; append it once to the service migration list.
Only outstanding random nonces, request digests and deadlines persist. The primary
key and expiry index lead with community_id, scoped as cpsd/<hex community bytes>.
Successful consumption deletes the row; prune removes expired rows. Capacity is
bounded, storage loss fails closed, and check_indexes exercises every leaf plan.
No extra cmnt table is necessary. Sibling facades retain only their own current
state under their respective contracts.

Upstream crlt pins currently differ: cpsd/crbk use 9c076b1, newer facades 6b94dac.
Concrete adapters therefore require matching Rust handles to one physical DB.
Align upstream pins for one shared pool; no leaf source is vendored or patched.
Backups/WAL retention and disabling SQL/HTTP/request-body tracing belong to the
service. Global issuer storage never shares the community database.

## Validation and boundaries

Stable formatting, strict all-target Clippy and real tests run on GitHub Actions.
Tests cover BBS passports, crgs register operations, crbk decisions, COSE, actual
cgts/cplc adapters, replay/concurrency, scope/epoch/lifetime boundaries, failures,
libSQL persistence/isolation/capacity/indexes and optional Turso. Development gates
exist only in tests. Fault fixtures exercise external ports without replacing
cmnt or leaf cryptographic/storage logic. Live Turso skips unless both environment
credentials are nonempty; public CI contains neither credential.

This crate does not supply the cvld transport, registration UI, pairing protocol,
establishment policy, global suspension accumulator or distributed writer lock.
The service must provide those boundaries; the selected leaves are not a claim
of independent cryptographic audit or production certification.
