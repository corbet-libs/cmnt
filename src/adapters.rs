//! Adapter for the ready cplc policy facade. Execution stays
//! upstream; the service supplies authenticated configuration and session inputs.

use cpsd::CommunityId;
use tokio::sync::Mutex;

use crate::{ports, *};

/// Policy adapter over cplc's actual durable issuer. The rulebook handle must
/// share the exact state used by the inner cplc policy, not an independent copy.
pub struct CplcPolicy<R, S, K> {
    community: CommunityId,
    policy: Mutex<cplc::Policy<R, S, K>>,
    rules: R,
    passport: PassportPolicy,
    valid_until: u64,
}

impl<R: crbk::Storage, S: cplc::Storage, K: csgn::Store> CplcPolicy<R, S, K> {
    /// Bind authenticated passport policy and a settings freshness deadline.
    /// Reconstruct the adapter when that global schedule changes. The current
    /// cplc API has no explicit issuance-expiry ceiling, so at least one verified
    /// global gate is required to carry the conservative passport expiry bound.
    pub fn new(
        community: CommunityId,
        policy: cplc::Policy<R, S, K>,
        rules: R,
        passport: PassportPolicy,
        valid_until: u64,
    ) -> Result<Self> {
        let name = community_text(&community)?;
        if policy.key_ring().map_err(|_| Error::Policy)?.issuer() != name {
            return Err(Error::Scope);
        }
        if passport.gates.is_empty() {
            return Err(Error::Policy);
        }
        Ok(Self {
            community,
            policy: Mutex::new(policy),
            rules,
            passport,
            valid_until,
        })
    }

    /// Serialized administration/key publication through the same cplc instance.
    pub fn policy(&self) -> &Mutex<cplc::Policy<R, S, K>> {
        &self.policy
    }

    async fn snapshot_locked(
        &self,
        policy: &cplc::Policy<R, S, K>,
        now: u64,
    ) -> Result<PolicySnapshot> {
        let at = i64::try_from(now).map_err(|_| Error::Time)?;
        let name = community_text(&self.community)?;
        let active = self
            .rules
            .load(name, crbk::Selection::At(at))
            .await
            .map_err(|_| Error::Policy)?
            .ok_or(Error::Policy)?;
        let mut rules = active.snapshot(name, at).map_err(|_| Error::Policy)?;
        rules.policy_epoch = policy.epoch(now).await.map_err(|_| Error::Policy)?;
        Ok(PolicySnapshot {
            rules,
            schema_version: policy
                .schema()
                .map_err(|_| Error::Policy)?
                .ok_or(Error::Policy)?
                .version
                .into(),
            passport: self.passport.clone(),
            valid_until: self.valid_until,
            signing_keys: policy.key_ring().map_err(|_| Error::Policy)?.clone(),
        })
    }
}

impl<R: crbk::Storage, S: cplc::Storage, K: csgn::Store> ports::Policy for CplcPolicy<R, S, K> {
    fn community(&self) -> &CommunityId {
        &self.community
    }

    async fn snapshot(&self, now: u64) -> Result<PolicySnapshot> {
        let policy = self.policy.lock().await;
        self.snapshot_locked(&policy, now).await
    }

    async fn sign(
        &self,
        expected: &PolicySnapshot,
        member: &Member,
        results: &[crbk::GateResult],
        claims: &CredentialClaims,
    ) -> Result<Vec<u8>> {
        let mut policy = self.policy.lock().await;
        if !expected.unchanged(&self.snapshot_locked(&policy, claims.issued).await?) {
            return Err(Error::Policy);
        }
        let mut gates = results.to_vec();
        let mut bounded = false;
        for gate in &mut gates {
            if gate.level == crbk::GateLevel::Global {
                // A verified proof can conservatively be treated as valid for
                // less time. Never extend or fabricate a global assertion.
                gate.valid_until = gate.valid_until.min(claims.valid_until as i64);
                bounded = true;
            }
        }
        if !bounded {
            return Err(Error::Policy);
        }
        gates.sort_by(|a, b| (&a.gate, &a.provider).cmp(&(&b.gate, &b.provider)));
        let pins: Vec<_> = member
            .pins
            .iter()
            .map(|(field, fingerprint)| cplc::Pin {
                field: field.clone(),
                fingerprint: *fingerprint,
            })
            .collect();
        policy
            .issue(
                cplc::CredentialRequest {
                    subject: crbk::Subject {
                        id: &member.id,
                        membership: member.state,
                    },
                    handle: &member.handle,
                    schema_version: claims
                        .schema_version
                        .try_into()
                        .map_err(|_| Error::Policy)?,
                    class: match member.standing {
                        Standing::New => cplc::MemberClass::New,
                        Standing::Established => cplc::MemberClass::Established,
                    },
                    gates: &gates,
                    pins: &pins,
                    devices: &member.devices,
                },
                claims.issued,
            )
            .await
            .map_err(|_| Error::Signing)
    }
}
