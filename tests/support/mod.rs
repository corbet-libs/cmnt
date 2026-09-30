use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};

use chrono::{DateTime, Datelike, Utc};
use cmnt::{
    ports::{Gatekeeping, Membership, Policy},
    storage::Storage,
    *,
};
use cpsd::{
    rand::{SeedableRng, rngs::StdRng},
    *,
};
use tokio::sync::Mutex;

pub const NOW: u64 = 1_800_000_000;
pub const EXPIRY: u64 = NOW + 90 * 86_400;

pub fn scope() -> CommunityId {
    CommunityId::new("example").unwrap()
}

pub type Engine<S> = Community<S, Members, DevelopmentGate, Policies>;

pub struct Fixture<S: Storage> {
    pub engine: Engine<S>,
    pub passport: Passport,
    pub rng: StdRng,
    pub members: Members,
    pub gates: DevelopmentGate,
    pub policies: Policies,
    pub rules: crbk::Rulebook,
}

impl<S: Storage> Fixture<S> {
    pub async fn proof(&mut self) -> (Challenge, Presentation) {
        let challenge = self.engine.begin(&mut self.rng, NOW).await.unwrap();
        let proof = self
            .passport
            .present(&mut self.rng, challenge.request())
            .unwrap();
        (challenge, proof)
    }

    pub async fn issue(&mut self) -> Outcome {
        let (challenge, proof) = self.proof().await;
        self.engine
            .finish(&mut self.rng, &challenge, &proof, NOW)
            .await
            .unwrap()
    }
}

#[derive(Clone)]
pub struct Members {
    pub scope: CommunityId,
    register: Arc<crgs::Register<crgs::MemoryStorage>>,
    pub record: Arc<Mutex<Member>>,
    pub fail_commit: Arc<AtomicBool>,
    pub commits: Arc<AtomicUsize>,
}

impl Membership for Members {
    fn community(&self) -> &CommunityId {
        &self.scope
    }

    async fn member(&self, id: &str) -> cmnt::Result<Member> {
        let stored = self
            .register
            .member(&crgs::MemberId::new(id.as_bytes().to_vec()).unwrap())
            .await
            .map_err(|_| cmnt::Error::Membership)?
            .ok_or(cmnt::Error::Membership)?;
        let mut result = self.record.lock().await.clone();
        result.handle = stored
            .handle
            .ok_or(cmnt::Error::Membership)?
            .display()
            .into();
        Ok(result)
    }

    async fn admit(
        &self,
        member: &Member,
        _: &PolicySnapshot,
        _: &[crbk::GateResult],
        until: u64,
    ) -> cmnt::Result<()> {
        let mut current = self.record.lock().await;
        if self.fail_commit.load(Ordering::SeqCst) || current.revision != member.revision {
            return Err(cmnt::Error::Membership);
        }
        let end = DateTime::from_timestamp(until as i64, 0).unwrap();
        self.register
            .extend_lease(
                &crgs::MemberId::new(member.id.as_bytes().to_vec()).unwrap(),
                crgs::YearMonth::new(end.year() as u16, end.month() as u8).unwrap(),
                DateTime::from_timestamp(NOW as i64, 0).unwrap(),
            )
            .await
            .map_err(|_| cmnt::Error::Membership)?;
        current.state = crbk::MembershipState::Admitted;
        current.revision += 1;
        self.commits.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// Development-only gate: this module is compiled by integration tests, never
// exported or linked into the production library. Faults exercise port boundaries.
#[derive(Clone)]
pub struct DevelopmentGate {
    pub scope: CommunityId,
    pub report: Arc<Mutex<GateReport>>,
    pub fail: Arc<AtomicBool>,
}

impl Gatekeeping for DevelopmentGate {
    fn community(&self) -> &CommunityId {
        &self.scope
    }

    async fn run(&self, _: &Member, _: &PolicySnapshot, _: u64) -> cmnt::Result<GateReport> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(cmnt::Error::Gate);
        }
        Ok(self.report.lock().await.clone())
    }
}

#[derive(Clone)]
pub struct Policies {
    pub scope: CommunityId,
    pub snapshot: Arc<Mutex<PolicySnapshot>>,
    signer: Arc<Mutex<csgn::PersistentSigner<csgn::MemoryStore>>>,
    pub fault: Arc<AtomicU8>,
    pub signatures: Arc<AtomicUsize>,
}

impl Policy for Policies {
    fn community(&self) -> &CommunityId {
        &self.scope
    }

    async fn snapshot(&self, _: u64) -> cmnt::Result<PolicySnapshot> {
        Ok(self.snapshot.lock().await.clone())
    }

    async fn sign(
        &self,
        expected: &PolicySnapshot,
        _: &Member,
        _: &[crbk::GateResult],
        claims: &CredentialClaims,
    ) -> cmnt::Result<Vec<u8>> {
        if expected.rules.revision != self.snapshot.lock().await.rules.revision {
            return Err(cmnt::Error::Policy);
        }
        let fault = self.fault.load(Ordering::SeqCst);
        if fault == 1 {
            return Err(cmnt::Error::Signing);
        }
        let mut payload = claims.payload().unwrap();
        if fault == 2 {
            payload.member = "wrong-member".into();
        }
        let expiry = claims.valid_until + u64::from(fault == 3);
        let kind = if fault == 4 {
            csgn::Kind::SettingsSnapshot
        } else {
            csgn::Kind::Credential
        };
        let mut cose = self
            .signer
            .lock()
            .await
            .sign(
                kind,
                &serde_json::to_vec(&payload).unwrap(),
                claims.issued,
                expiry,
            )
            .await
            .map_err(|_| cmnt::Error::Signing)?;
        if fault == 5 {
            let last = cose.len() - 1;
            cose[last] ^= 1;
        }
        self.signatures.fetch_add(1, Ordering::SeqCst);
        Ok(cose)
    }
}

pub async fn fixture<S: Storage>(storage: S) -> Fixture<S> {
    let mut rng = StdRng::seed_from_u64(42);
    let gate = GateId::new("global-test").unwrap();
    let issuer = IssuerKey::generate(
        &mut rng,
        KeyId::new("shared-issuer").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let secret = HolderSecret::generate(&mut rng);
    let challenge = IssuanceChallenge::generate(&mut rng);
    let (request, pending) =
        request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let attributes = PassportAttributes::new(EXPIRY, 7).with_gate(gate.clone(), EXPIRY);
    let blind = issuer
        .issue_blind(&mut rng, &request, &challenge, &attributes)
        .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let id = passport.pseudonym(&scope()).to_hex();
    let register = crgs::Register::new(
        crgs::MemoryStorage::default(),
        crgs::ReleasePeriod::default(),
    );
    let now: DateTime<Utc> = DateTime::from_timestamp(NOW as i64, 0).unwrap();
    let member_id = crgs::MemberId::new(id.as_bytes().to_vec()).unwrap();
    let handle = crgs::Handle::new("test_member", "test_member").unwrap();
    register
        .reserve_handle(
            crgs::Reservation {
                member_id: member_id.clone(),
                handle: handle.clone(),
                expires_at: now + chrono::Duration::hours(1),
            },
            now,
        )
        .await
        .unwrap();
    register
        .admit(
            crgs::Admission {
                id: member_id,
                handle,
                role: crgs::Role::Member,
                lease_end: crgs::YearMonth::new(now.year() as u16, now.month() as u8).unwrap(),
            },
            now,
        )
        .await
        .unwrap();
    let members = Members {
        scope: scope(),
        register: Arc::new(register),
        record: Arc::new(Mutex::new(Member {
            id: id.clone(),
            handle: "test_member".into(),
            state: crbk::MembershipState::Pending,
            standing: Standing::New,
            revision: 1,
            pins: [("restricted-field".into(), [11; 32])].into(),
            devices: vec![[13; 32]],
        })),
        fail_commit: Arc::default(),
        commits: Arc::default(),
    };
    let gates = DevelopmentGate {
        scope: scope(),
        fail: Arc::default(),
        report: Arc::new(Mutex::new(GateReport {
            results: vec![crbk::GateResult {
                gate: "dev-test".into(),
                level: crbk::GateLevel::Community,
                subject: id,
                community: Some("example".into()),
                provider: "test-only".into(),
                valid_until: EXPIRY as i64,
                proven_at: None,
            }],
            veto: false,
        })),
    };
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "example",
        csgn::SecretKey::from_seed(&mut [1; 32]),
        NOW,
        ESTABLISHED_MEMBER_LIFETIME,
    )
    .await
    .unwrap();
    let mut rules = crbk::Rulebook::default();
    for (level, name, provider) in [
        (crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
        (crbk::GateLevel::Community, "dev-test", "test-only"),
    ] {
        for key in [
            crbk::gate_key(level, name),
            crbk::provider_key(level, name, provider),
        ] {
            rules
                .define(
                    key,
                    crbk::Setting {
                        value_type: crbk::SettingType::Boolean,
                        nullable: false,
                        default: true.into(),
                        bounds: crbk::Bounds::default(),
                        lowest_layer: crbk::Layer::Community,
                        kind: crbk::SettingKind::Technical,
                    },
                )
                .unwrap();
        }
    }
    let action = crbk::ActionPolicy {
        all_of: vec![
            crbk::Requirement {
                gate: "global-test".into(),
                level: crbk::GateLevel::Global,
                provider: None,
            },
            crbk::Requirement {
                gate: "dev-test".into(),
                level: crbk::GateLevel::Community,
                provider: None,
            },
        ],
        ..Default::default()
    };
    rules
        .define(
            crbk::action_key(ADMISSION_ACTION),
            crbk::Setting {
                value_type: crbk::SettingType::Policy,
                nullable: false,
                default: serde_json::to_value(action).unwrap(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let revision = crbk::Revision {
        revision: 1,
        change: crbk::Change {
            rulebook: rules.clone(),
            announced_at: NOW as i64,
            effective_at: NOW as i64,
            notice_seconds: 0,
            policy_epoch: 19,
        },
    };
    let policies = Policies {
        scope: scope(),
        snapshot: Arc::new(Mutex::new(PolicySnapshot {
            rules: revision.snapshot("example", NOW as i64).unwrap(),
            schema_version: 3,
            passport: PassportPolicy {
                epoch: 7,
                valid_until: EXPIRY,
                gates: [gate].into(),
            },
            valid_until: EXPIRY,
            signing_keys: signer.key_ring().unwrap().clone(),
        })),
        signer: Arc::new(Mutex::new(signer)),
        fault: Arc::default(),
        signatures: Arc::default(),
    };
    let engine = Community::new(
        storage,
        vec![issuer.public_key().clone()],
        members.clone(),
        gates.clone(),
        policies.clone(),
        60,
    )
    .unwrap();
    Fixture {
        engine,
        passport,
        rng,
        members,
        gates,
        policies,
        rules,
    }
}
