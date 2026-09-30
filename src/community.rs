use std::collections::BTreeSet;

use cpsd::{
    ChallengeStore, CommunityId, IssuerPublicKey, Presentation, PresentationRequest, Verifier,
    rand::{CryptoRng, RngCore},
};

use crate::{
    ports::{Gatekeeping, Membership, Policy},
    storage::Storage,
    *,
};

/// Server-held admission challenge. Only [`Self::request`] travels to the holder.
/// Private fields prevent substituting policy or an arbitrary permissive action.
/// Losing this transient value requires a fresh challenge, not reconstruction
/// from untrusted client fields. No member ID or proof is retained here.
pub struct Challenge {
    request: PresentationRequest,
    policy: PolicySnapshot,
    not_before: u64,
}

impl Challenge {
    /// The holder's serializable `cpsd` request; the service retains this handle.
    pub fn request(&self) -> &PresentationRequest {
        &self.request
    }
}

/// Community facade with fixed, service-authorized component capabilities.
/// Membership and gatekeeping use ports while upstream dependency pins align;
/// the ready cplc adapter is provided in `adapters`.
pub struct Community<S: Storage, M, G, P> {
    community: CommunityId,
    verifier: Verifier<S::Challenges>,
    membership: M,
    gates: G,
    policy: P,
    challenge_lifetime: u64,
}

impl<S: Storage, M: Membership, G: Gatekeeping, P: Policy> Community<S, M, G, P> {
    /// Compose one community. `challenge_lifetime` is explicit server policy and
    /// must be positive and at most five minutes. Keys are authenticated global
    /// issuer keys; none may come from the member's presentation.
    pub fn new(
        storage: S,
        issuer_keys: Vec<IssuerPublicKey>,
        membership: M,
        gates: G,
        policy: P,
        challenge_lifetime: u64,
    ) -> Result<Self> {
        let store = storage.challenges();
        let community = store.community().clone();
        community_text(&community)?;
        if membership.community() != &community
            || gates.community() != &community
            || policy.community() != &community
        {
            return Err(Error::Scope);
        }
        if challenge_lifetime == 0 || challenge_lifetime > 300 {
            return Err(Error::Time);
        }
        if issuer_keys.is_empty() {
            return Err(Error::Passport);
        }
        Ok(Self {
            community,
            verifier: Verifier::new(store, issuer_keys)?,
            membership,
            gates,
            policy,
            challenge_lifetime,
        })
    }

    /// Immutable community identity used for pseudonym derivation and every port.
    pub fn community(&self) -> &CommunityId {
        &self.community
    }

    /// Reserve a single-use passport request under effective admission policy.
    /// Rate-limit before invoking this operation. The shared-epoch profile avoids
    /// revealing individual global gate expiry dates.
    pub async fn begin<R: RngCore + CryptoRng>(&self, rng: &mut R, now: u64) -> Result<Challenge> {
        check_time(now)?;
        let policy = self.policy.snapshot(now).await?;
        self.validate_policy(&policy, now)?;
        let deadline = now
            .checked_add(self.challenge_lifetime)
            .ok_or(Error::Time)?
            .min(policy.passport.valid_until - 1)
            .min(policy.valid_until - 1);
        if deadline <= now {
            return Err(Error::Time);
        }
        let request = self
            .verifier
            .request_for_epoch(
                rng,
                policy.passport.epoch,
                policy.passport.gates.iter().cloned(),
                deadline,
                policy.passport.valid_until,
            )
            .await?;
        Ok(Challenge {
            request,
            policy,
            not_before: now,
        })
    }

    /// Verify a passport, consume its challenge, consult membership and community
    /// gates, ask the rulebook, commit admission, and sign a bounded credential.
    /// Any attempt after successful verification needs a new challenge, including
    /// denials, downstream failures and lost responses. No credential is cached.
    pub async fn finish<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        challenge: &Challenge,
        presentation: &Presentation,
        now: u64,
    ) -> Result<Outcome> {
        check_time(now)?;
        if now < challenge.not_before || challenge.request.community() != &self.community {
            return Err(Error::Passport);
        }
        let policy = self.policy.snapshot(now).await?;
        self.validate_policy(&policy, now)?;
        if !policy.unchanged(&challenge.policy) {
            return Err(Error::Policy);
        }
        let pseudonym = self
            .verifier
            .verify(
                rng,
                &challenge.request,
                presentation,
                policy.passport.epoch,
                now,
            )
            .await?;
        let member_id = pseudonym.to_hex();
        let member = self.membership.member(&member_id).await?;
        if member.id != member_id
            || member.handle.is_empty()
            || member.revision == 0
            || member.state == crbk::MembershipState::Released
        {
            return Err(Error::Membership);
        }
        let report = self.gates.run(&member, &policy, now).await?;
        if report.veto {
            return Ok(Outcome::Vetoed);
        }
        let mut results = report.results;
        self.validate_gates(&results, &member_id, now)?;
        // These subjects are bound only after the BBS proof and single-use
        // consumption succeed. No global holder identifier crosses the boundary.
        results.extend(policy.passport.gates.iter().map(|gate| crbk::GateResult {
            gate: gate.to_string(),
            level: crbk::GateLevel::Global,
            subject: member_id.clone(),
            community: None,
            provider: PASSPORT_PROVIDER.into(),
            valid_until: policy.passport.valid_until as i64,
            proven_at: None,
        }));
        let decision = policy
            .rules
            .may(
                crbk::Subject {
                    id: &member_id,
                    membership: member.state,
                },
                ADMISSION_ACTION,
                &results,
                now as i64,
            )
            .map_err(|_| Error::Policy)?;
        if !decision.allowed {
            return Ok(Outcome::Missing(decision));
        }
        let mut claims = self.claims(&policy, &member, &results, now)?;
        // Commit before publication. On signing failure the lease may already be
        // extended; no credential escapes and standing must remain unchanged.
        self.membership
            .admit(&member, &policy, &results, claims.valid_until)
            .await?;
        let current = self.policy.snapshot(now).await?;
        self.validate_policy(&current, now)?;
        if !policy.unchanged(&current) {
            return Err(Error::Policy);
        }
        let cose = self
            .policy
            .sign(&policy, &member, &results, &claims)
            .await?;
        let verified = policy
            .signing_keys
            .verify(&cose, csgn::Kind::Credential, now)
            .map_err(|_| Error::Signing)?;
        let signed: cplc::Credential =
            serde_json::from_slice(verified.payload()).map_err(|_| Error::Signing)?;
        if signed != claims.payload()?
            || verified.key_id().as_bytes().as_slice() != claims.key_id
            || verified.issued_at() != claims.issued
            || verified.valid_until() > claims.valid_until
        {
            return Err(Error::Signing);
        }
        claims.valid_until = verified.valid_until();
        Ok(Outcome::Issued(Box::new(IssuedCredential { claims, cose })))
    }

    /// Delete expired, outstanding anonymous challenges; never a member history.
    pub async fn prune(&self, now: u64) -> Result<u64> {
        check_time(now)?;
        Ok(self.verifier.prune(now).await?)
    }

    fn validate_policy(&self, policy: &PolicySnapshot, now: u64) -> Result<()> {
        let community = community_text(&self.community)?;
        if policy.rules.community != community || policy.signing_keys.issuer() != community {
            return Err(Error::Scope);
        }
        if policy.rules.revision == 0
            || policy.schema_version == 0
            || policy.rules.issued < 0
            || policy.rules.issued > now as i64
            || policy.valid_until <= now
            || policy.valid_until >= cpsd::TIME_LIMIT
            || policy.passport.valid_until <= now
            || policy.passport.valid_until >= cpsd::TIME_LIMIT
            || policy.signing_keys.active().is_none()
        {
            return Err(Error::Policy);
        }
        Ok(())
    }

    fn validate_gates(&self, results: &[crbk::GateResult], subject: &str, now: u64) -> Result<()> {
        let community = community_text(&self.community)?;
        let mut seen = BTreeSet::new();
        for result in results {
            if result.level != crbk::GateLevel::Community
                || result.subject != subject
                || result.community.as_deref() != Some(community)
                || result.gate.is_empty()
                || result.provider.is_empty()
                || result.valid_until <= now as i64
                || result.valid_until >= cpsd::TIME_LIMIT as i64
                || result
                    .proven_at
                    .is_some_and(|time| time < 0 || time > now as i64)
                || !seen.insert((&result.gate, &result.provider))
            {
                return Err(Error::Gate);
            }
        }
        Ok(())
    }

    fn claims(
        &self,
        policy: &PolicySnapshot,
        member: &Member,
        results: &[crbk::GateResult],
        now: u64,
    ) -> Result<CredentialClaims> {
        let cap = match member.standing {
            Standing::New => NEW_MEMBER_LIFETIME,
            Standing::Established => ESTABLISHED_MEMBER_LIFETIME,
        };
        let mut valid_until = now
            .checked_add(cap.min(policy.signing_keys.max_validity()))
            .ok_or(Error::Time)?
            .min(policy.valid_until)
            .min(policy.passport.valid_until);
        let mut gates = Vec::new();
        for result in results {
            valid_until = valid_until.min(result.valid_until as u64);
            if result.level == crbk::GateLevel::Community {
                gates.push(CredentialGate {
                    gate: result.gate.clone(),
                    provider: result.provider.clone(),
                    valid_until: result.valid_until as u64,
                });
            }
        }
        if valid_until <= now {
            return Err(Error::Time);
        }
        gates.sort_by(|a, b| (&a.gate, &a.provider).cmp(&(&b.gate, &b.provider)));
        let key = policy.signing_keys.active().ok_or(Error::Signing)?;
        Ok(CredentialClaims {
            version: 1,
            community: community_text(&self.community)?.into(),
            member_id: member.id.clone(),
            handle: member.handle.clone(),
            gates,
            pins: member.pins.clone(),
            devices: member.devices.clone(),
            schema_version: policy.schema_version,
            policy_epoch: policy.rules.policy_epoch,
            issued: now,
            valid_until,
            key_id: key.key_id().as_bytes().to_vec(),
        })
    }
}

fn check_time(now: u64) -> Result<()> {
    if now == 0 || now >= cpsd::TIME_LIMIT {
        return Err(Error::Time);
    }
    Ok(())
}
