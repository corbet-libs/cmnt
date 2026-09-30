//! Narrow trusted composition ports; ready facade adapters live in `adapters`.

use std::future::Future;

use crate::{CredentialClaims, GateReport, Member, PolicySnapshot, Result};
use cpsd::CommunityId;

/// Trusted membership facade (`cmbr`), never implemented by a member request.
pub trait Membership: Send + Sync {
    /// Immutable service-selected community.
    fn community(&self) -> &CommunityId;

    /// Resolve only the ID returned by successful passport verification. Missing
    /// enrolment is an error; handle/passkey/pin management remains in `cmbr`.
    fn member(&self, member_id: &str) -> impl Future<Output = Result<Member>> + Send;

    /// Commit admission/renewal and extend the coarse lease. Revalidate the
    /// supplied member under the service's writer serialization; refuse release
    /// or changed pins. The service must serialize across instances as well.
    /// Idempotent retries must not promote a new member to established standing.
    fn admit(
        &self,
        member: &Member,
        policy: &PolicySnapshot,
        results: &[crbk::GateResult],
        valid_until: u64,
    ) -> impl Future<Output = Result<()>> + Send;
}

/// Trusted gate runner (`cgts`). Raw gate input stays inside each leaf/session.
pub trait Gatekeeping: Send + Sync {
    /// Immutable service-selected community.
    fn community(&self) -> &CommunityId;

    /// Run community checks, including the community legal veto, for this member.
    /// Return only authenticated proof metadata. Failure must not become a pass.
    fn run(
        &self,
        member: &Member,
        policy: &PolicySnapshot,
        now: u64,
    ) -> impl Future<Output = Result<GateReport>> + Send;
}

/// Trusted policy/signing facade (`cplc`). It owns `crbk`, `cshm` and signing keys.
pub trait Policy: Send + Sync {
    /// Immutable service-selected community.
    fn community(&self) -> &CommunityId;

    /// Load effective rulebook/schema/passport policy and authenticated community
    /// public keys. A scheduled revision must not be returned before activation.
    fn snapshot(&self, now: u64) -> impl Future<Output = Result<PolicySnapshot>> + Send;

    /// Issue a cplc credential with these authenticated inputs. Expiry may be
    /// shorter than claims.valid_until, never longer. cplc owns JSON/signing and
    /// durable key retention. Fail on a changed policy/schema revision or key.
    fn sign(
        &self,
        expected: &PolicySnapshot,
        member: &Member,
        results: &[crbk::GateResult],
        claims: &CredentialClaims,
    ) -> impl Future<Output = Result<Vec<u8>>> + Send;
}
