//! Adapters for the ready membership, policy and gatekeeping facades. Execution stays
//! upstream; the service supplies authenticated configuration and session inputs.

use cpsd::CommunityId;
use tokio::sync::Mutex;

use crate::{ports, *};

/// Session metadata authorized by the service, never deserialized from a member
/// request. Handle comes from the reserved cgrd/crgs result, standing from
/// membership policy, fields from schema, and public devices from pairing.
pub struct SessionMetadata {
    /// Already validated and reserved canonical handle and skeleton.
    pub handle: cmbr::crgs::Handle,
    /// Explicit trusted classification; no credential counter or login clock.
    pub standing: Standing,
    /// Restricted fields whose current fingerprints must be loaded from cmbr.
    pub fields: Vec<String>,
    /// Public device keys authorized by the member's pairing protocol.
    pub devices: Vec<[u8; 32]>,
}

/// One authenticated community session over the real cmbr facade. All writers
/// in this process must share the supplied mutex; service-wide serialization is
/// still required across processes and across the complete issuance operation.
pub struct CmbrMembership<S, V, L, C> {
    community: CommunityId,
    membership: std::sync::Arc<Mutex<cmbr::Membership<S, V, L, C>>>,
    authentication: cmbr::cpky::Authentication,
    metadata: SessionMetadata,
}

impl<S, V, L, C> CmbrMembership<S, V, L, C>
where
    S: cmbr::Storage,
    V: cmbr::cpns::server::ChangeTokenVerifier,
    L: cmbr::clbs::Verifier,
    C: cmbr::clbs::Clock,
{
    /// Bind a real passkey authentication receipt and service-approved metadata.
    /// cmbr validates receipt scope/identity on each operation. Keep the session
    /// short-lived and invalidate it on device removal; receipts are not tokens.
    pub fn new(
        community: CommunityId,
        membership: std::sync::Arc<Mutex<cmbr::Membership<S, V, L, C>>>,
        authentication: cmbr::cpky::Authentication,
        metadata: SessionMetadata,
    ) -> Result<Self> {
        community_text(&community)?;
        if metadata.devices.is_empty() {
            return Err(Error::Membership);
        }
        Ok(Self {
            community,
            membership,
            authentication,
            metadata,
        })
    }

    async fn load(&self, membership: &cmbr::Membership<S, V, L, C>, id: &str) -> Result<Member> {
        let row = membership
            .resume(&self.authentication)
            .await
            .map_err(|_| Error::Membership)?;
        if row.community() != community_text(&self.community)? || row.subject() != id {
            return Err(Error::Membership);
        }
        let state = match row.state() {
            cmbr::cnrl::State::Admitted => crbk::MembershipState::Admitted,
            cmbr::cnrl::State::Lapsed => crbk::MembershipState::Lapsed,
            state if state.is_terminal() => crbk::MembershipState::Released,
            _ => crbk::MembershipState::Pending,
        };
        let mut pins = std::collections::BTreeMap::new();
        for field in &self.metadata.fields {
            let pin = membership
                .get_pin(&self.authentication, field)
                .await
                .map_err(|_| Error::Membership)?
                .ok_or(Error::Membership)?;
            if pins
                .insert(field.clone(), *pin.fingerprint.as_bytes())
                .is_some()
            {
                return Err(Error::Membership);
            }
        }
        Ok(Member {
            id: id.into(),
            handle: self.metadata.handle.display().into(),
            state,
            standing: self.metadata.standing,
            revision: row.revision(),
            pins,
            devices: self.metadata.devices.clone(),
        })
    }
}

impl<S, V, L, C> ports::Membership for CmbrMembership<S, V, L, C>
where
    S: cmbr::Storage,
    V: cmbr::cpns::server::ChangeTokenVerifier,
    L: cmbr::clbs::Verifier,
    C: cmbr::clbs::Clock,
{
    fn community(&self) -> &CommunityId {
        &self.community
    }

    async fn member(&self, member_id: &str) -> Result<Member> {
        self.load(&*self.membership.lock().await, member_id).await
    }

    async fn admit(
        &self,
        member: &Member,
        policy: &PolicySnapshot,
        results: &[crbk::GateResult],
        valid_until: u64,
    ) -> Result<()> {
        use chrono::Datelike;
        let membership = self.membership.lock().await;
        if self.load(&membership, &member.id).await? != *member {
            return Err(Error::Membership);
        }
        let end = chrono::DateTime::from_timestamp(
            i64::try_from(valid_until).map_err(|_| Error::Time)?,
            0,
        )
        .ok_or(Error::Time)?;
        let lease = cmbr::crgs::YearMonth::new(
            end.year().try_into().map_err(|_| Error::Time)?,
            end.month() as u8,
        )
        .map_err(|_| Error::Time)?;
        membership
            .admit(
                &self.authentication,
                &policy.rules,
                results,
                self.metadata.handle.clone(),
                lease,
            )
            .await
            .map_err(|_| Error::Membership)?;
        Ok(())
    }
}

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

/// Gatekeeping adapter over cgts. Use [`Self::gatekeeper`] to run typed leaf
/// gates; retained facts and explicitly attached transient checks are collected
/// during admission. The mandatory cgts/clbs veto remains active.
pub struct CgtsGatekeeping<S, L> {
    community: CommunityId,
    gatekeeper: cgts::Gatekeeper<S, L>,
    checks: Vec<cgts::CheckedGate>,
}

impl<S: cgts::Storage, L: cgts::LegalVeto> CgtsGatekeeping<S, L> {
    /// Bind the service's canonical scope. cgts validates its actual store scope
    /// on each operation and refuses any mismatch before returning evidence.
    pub fn new(community: CommunityId, gatekeeper: cgts::Gatekeeper<S, L>) -> Self {
        Self {
            community,
            gatekeeper,
            checks: Vec::new(),
        }
    }

    /// Existing typed gate runner; no raw input envelope is defined in cmnt.
    pub fn gatekeeper(&self) -> &cgts::Gatekeeper<S, L> {
        &self.gatekeeper
    }

    /// Attach checks returned by real cgts gate execution. cgts verifies their
    /// exact action, member, revision, epoch and evaluation time during admission.
    pub fn with_checks(mut self, checks: Vec<cgts::CheckedGate>) -> Self {
        self.checks = checks;
        self
    }
}

impl<S: cgts::Storage, L: cgts::LegalVeto> ports::Gatekeeping for CgtsGatekeeping<S, L> {
    fn community(&self) -> &CommunityId {
        &self.community
    }

    async fn run(&self, member: &Member, policy: &PolicySnapshot, now: u64) -> Result<GateReport> {
        let context = cgts::Context {
            snapshot: &policy.rules,
            subject: &member.id,
            action: ADMISSION_ACTION,
            now: now.try_into().map_err(|_| Error::Time)?,
        };
        // cgts validates transient checks here. Its partial rulebook verdict may
        // lack global gates; cmnt subsequently supplies the verified passport.
        let decision = self
            .gatekeeper
            .decide(context, member.state, &self.checks)
            .await
            .map_err(|_| Error::Gate)?;
        if decision.legal_veto {
            return Ok(GateReport {
                results: Vec::new(),
                veto: true,
            });
        }
        let mut results = match self.gatekeeper.collect(context).await {
            Ok(results) => results,
            Err(cgts::Error::Vetoed) => {
                return Ok(GateReport {
                    results: Vec::new(),
                    veto: true,
                });
            }
            Err(_) => return Err(Error::Gate),
        };
        for check in &self.checks {
            let result = check.result();
            results.retain(|old| old.gate != result.gate || old.provider != result.provider);
            results.push(result.clone());
        }
        Ok(GateReport {
            results: results
                .into_iter()
                .map(|gate| crbk::GateResult {
                    gate: gate.gate,
                    level: gate.level,
                    subject: gate.subject,
                    community: Some(policy.rules.community.clone()),
                    provider: gate.provider,
                    valid_until: gate.valid_until,
                    proven_at: None,
                })
                .collect(),
            veto: false,
        })
    }
}
