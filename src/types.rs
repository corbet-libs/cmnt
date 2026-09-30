//! Proof-level inputs and the versioned community credential payload.

use std::collections::{BTreeMap, BTreeSet};

use cpsd::{CommunityId, GateId};
use serde::{Deserialize, Serialize};

/// The only action that authorizes community credential issuance.
pub const ADMISSION_ACTION: &str = "community.admit";
/// Provider label for globally verified proof metadata, not a raw gate provider.
pub const PASSPORT_PROVIDER: &str = "cpsd";
/// Maximum lifetime for a new member, in seconds.
pub const NEW_MEMBER_LIFETIME: u64 = 86_400;
/// Maximum lifetime for an established member, in seconds.
pub const ESTABLISHED_MEMBER_LIFETIME: u64 = 30 * NEW_MEMBER_LIFETIME;

/// Standing supplied by membership policy, never inferred from renewal count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Probationary or otherwise not established.
    New,
    /// Established according to the trusted membership facade.
    Established,
}

/// Current membership state. No admission/login dates or history.
#[derive(Clone, PartialEq, Eq)]
pub struct Member {
    /// Exact lowercase hexadecimal `cpsd::Pseudonym::to_hex()` value.
    pub id: String,
    /// Handle already validated/reserved by membership leaves.
    pub handle: String,
    /// State resolved by `cmbr`/`cnrl`.
    pub state: crbk::MembershipState,
    /// Trusted standing; renewal alone never changes it.
    pub standing: Standing,
    /// Opaque revision for atomic admission against unchanged membership.
    pub revision: u64,
    /// Sealed field fingerprints only; never values or salts.
    pub pins: BTreeMap<String, [u8; 32]>,
}

/// Authenticated common-expiry passport policy from the global level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassportPolicy {
    /// Required global policy epoch, distinct from the community policy epoch.
    pub epoch: u64,
    /// Common passport/gate expiry authenticated from the issuer schedule.
    pub valid_until: u64,
    /// Gates the holder must disclose for admission.
    pub gates: BTreeSet<GateId>,
}

/// Effective state from the policy facade; never accept this from an HTTP client.
#[derive(Clone)]
pub struct PolicySnapshot {
    /// Resolved rulebook. Its community must be the canonical UTF-8 scope.
    pub rules: crbk::Snapshot,
    /// Current profile schema version.
    pub schema_version: u64,
    /// Authenticated global policy cohort.
    pub passport: PassportPolicy,
    /// Freshness deadline for these settings/schema, exclusive.
    pub valid_until: u64,
    /// Trusted community ring; issuer must be `cmnt:<community>`.
    pub signing_keys: csgn::KeyRing,
}

impl PolicySnapshot {
    pub(crate) fn unchanged(&self, other: &Self) -> bool {
        self.rules.community == other.rules.community
            && self.rules.revision == other.rules.revision
            && self.rules.policy_epoch == other.rules.policy_epoch
            && self.rules.content == other.rules.content
            && self.schema_version == other.schema_version
            && self.passport == other.passport
            && self.valid_until == other.valid_until
            && self.signing_keys.to_cbor() == other.signing_keys.to_cbor()
    }
}

/// Community gate results plus an unconditional legal veto.
#[derive(Clone, Default)]
pub struct GateReport {
    /// Already verified metadata, bound to this member and community.
    pub results: Vec<crbk::GateResult>,
    /// A verified legal order prohibits admission regardless of rulebook policy.
    pub veto: bool,
}

/// A community gate recorded in the credential. Proof time is deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialGate {
    /// Gate name.
    pub gate: String,
    /// Community-level provider name.
    pub provider: String,
    /// Exclusive expiry.
    pub valid_until: u64,
}

/// Version-one JSON payload inside Ed25519 COSE_Sign1 from `cplc`/`csgn`.
/// Issuer, key ID and times must agree with the protected COSE metadata.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialClaims {
    /// Payload format version (1).
    pub version: u8,
    /// Canonical community, never a mutable display name.
    pub community: String,
    /// Community pseudonym; never a global holder identifier.
    pub member_id: String,
    /// Membership-owned handle.
    pub handle: String,
    /// Community proof metadata; global gate disclosures are not copied here.
    pub gates: Vec<CredentialGate>,
    /// Sealed field fingerprints only.
    pub pins: BTreeMap<String, [u8; 32]>,
    /// Schema version.
    pub schema_version: u64,
    /// Community policy epoch.
    pub policy_epoch: u64,
    /// Issuance in unsigned Unix seconds; returned, never persisted by cmnt.
    pub issued: u64,
    /// Exclusive expiry.
    pub valid_until: u64,
    /// Active community COSE key thumbprint.
    pub key_id: Vec<u8>,
}

/// A successful issuance. This value must not be stored as a request log.
pub struct IssuedCredential {
    /// Authenticated credential claims.
    pub claims: CredentialClaims,
    /// Tagged Ed25519 COSE_Sign1 bytes.
    pub cose: Vec<u8>,
}

/// Gate/rulebook refusal, or a signed credential.
pub enum Outcome {
    /// Resume the lobby with the rulebook's missing requirements.
    Missing(crbk::Decision),
    /// Unconditional legal veto; no authority/order data is exposed.
    Vetoed,
    /// Credential issued after admission was committed.
    Issued(Box<IssuedCredential>),
}

pub(crate) fn community_text(community: &CommunityId) -> crate::Result<&str> {
    let value = std::str::from_utf8(community.as_bytes()).map_err(|_| crate::Error::Scope)?;
    if value.contains('\0') || value.len() + "cmnt:".len() > csgn::MAX_ISSUER_LEN {
        return Err(crate::Error::Scope);
    }
    Ok(value)
}
