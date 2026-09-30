mod support;

use std::sync::atomic::Ordering;

use cmnt::{storage::MemoryStorage, *};
use cpsd::rand::{SeedableRng, rngs::StdRng};
use support::*;

async fn memory() -> Fixture<MemoryStorage> {
    fixture(MemoryStorage::new(scope(), 32).unwrap()).await
}

fn issued(outcome: Outcome) -> Box<IssuedCredential> {
    match outcome {
        Outcome::Issued(value) => value,
        _ => panic!("expected credential"),
    }
}

#[tokio::test]
async fn real_passport_rulebook_register_and_cose_roundtrip() {
    let mut f = memory().await;
    let result = issued(f.issue().await);
    assert_eq!(
        result.claims.member_id,
        f.passport.pseudonym(&scope()).to_hex()
    );
    assert_eq!(result.claims.handle, "test_member");
    assert_eq!(result.claims.policy_epoch, 19);
    assert_eq!(result.claims.schema_version, 3);
    assert_eq!(result.claims.valid_until, NOW + NEW_MEMBER_LIFETIME);
    assert_eq!(result.claims.gates.len(), 1);
    assert_eq!(result.claims.gates[0].gate, "dev-test");
    assert_eq!(result.claims.pins["restricted-field"], [11; 32]);
    let policy = f.policies.snapshot.lock().await;
    let verified = policy
        .signing_keys
        .verify(&result.cose, csgn::Kind::Credential, NOW)
        .unwrap();
    assert_eq!(verified.valid_until(), result.claims.valid_until);
    assert!(
        policy
            .signing_keys
            .verify(
                &result.cose,
                csgn::Kind::Credential,
                result.claims.valid_until
            )
            .is_err()
    );
    assert_eq!(f.members.commits.load(Ordering::SeqCst), 1);
    assert_eq!(f.policies.signatures.load(Ordering::SeqCst), 1);
    let payload = String::from_utf8(verified.payload().to_vec()).unwrap();
    for forbidden in [
        "global-test",
        "proven_at",
        "last_login",
        "salt",
        "holder_secret",
    ] {
        assert!(!payload.contains(forbidden));
    }
}

#[tokio::test]
async fn established_cap_and_repeated_renewal_do_not_establish_new_members() {
    let mut f = memory().await;
    for _ in 0..3 {
        assert_eq!(
            issued(f.issue().await).claims.valid_until,
            NOW + NEW_MEMBER_LIFETIME
        );
    }
    f.members.record.lock().await.standing = Standing::Established;
    assert_eq!(
        issued(f.issue().await).claims.valid_until,
        NOW + ESTABLISHED_MEMBER_LIFETIME
    );
}

#[tokio::test]
async fn lifetime_adapts_to_gate_policy_and_passport_expiry() {
    let mut f = memory().await;
    f.members.record.lock().await.standing = Standing::Established;
    f.gates.report.lock().await.results[0].valid_until = (NOW + 600) as i64;
    assert_eq!(issued(f.issue().await).claims.valid_until, NOW + 600);
    f.policies.snapshot.lock().await.valid_until = NOW + 300;
    assert_eq!(issued(f.issue().await).claims.valid_until, NOW + 300);
    // A different common expiry cannot be asserted without a matching passport.
    f.policies.snapshot.lock().await.passport.valid_until = NOW + 200;
    let challenge = f.engine.begin(&mut f.rng, NOW).await.unwrap();
    assert!(f.passport.present(&mut f.rng, challenge.request()).is_err());
}

#[tokio::test]
async fn authentic_short_passport_caps_credential_and_tightens_challenge() {
    let mut f = fixture_with_expiry(MemoryStorage::new(scope(), 8).unwrap(), NOW + 40).await;
    let (challenge, proof) = f.proof().await;
    assert_eq!(challenge.request().now(), NOW + 39);
    let outcome = f
        .engine
        .finish(&mut f.rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    assert_eq!(issued(outcome).claims.valid_until, NOW + 40);

    let mut f = fixture_with_expiry(MemoryStorage::new(scope(), 8).unwrap(), NOW + 1).await;
    assert!(matches!(
        f.engine.begin(&mut f.rng, NOW).await,
        Err(Error::Time)
    ));
    f.policies.snapshot.lock().await.valid_until = NOW;
    assert!(matches!(
        f.engine.begin(&mut f.rng, NOW).await,
        Err(Error::Policy)
    ));
}

#[tokio::test]
async fn missing_gate_disabled_provider_and_unknown_action_return_lobby_reasons() {
    let mut f = memory().await;
    f.gates.report.lock().await.results.clear();
    match f.issue().await {
        Outcome::Missing(decision) => assert!(!decision.allowed && !decision.missing.is_empty()),
        _ => panic!("missing gate must deny"),
    }
    f.policies.snapshot.lock().await.rules.content.insert(
        crbk::provider_key(crbk::GateLevel::Global, "global-test", PASSPORT_PROVIDER),
        false.into(),
    );
    assert!(matches!(f.issue().await, Outcome::Missing(_)));
    f.policies
        .snapshot
        .lock()
        .await
        .rules
        .content
        .remove(&crbk::action_key(ADMISSION_ACTION));
    assert!(matches!(f.issue().await, Outcome::Missing(_)));
    assert_eq!(f.members.commits.load(Ordering::SeqCst), 0);
    assert_eq!(f.policies.signatures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn legal_veto_overrides_an_explicitly_permissive_rulebook() {
    let mut f = memory().await;
    f.policies.snapshot.lock().await.rules.content.insert(
        crbk::action_key(ADMISSION_ACTION),
        serde_json::to_value(crbk::ActionPolicy::default()).unwrap(),
    );
    f.gates.report.lock().await.veto = true;
    assert!(matches!(f.issue().await, Outcome::Vetoed));
    assert_eq!(f.members.commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn replay_and_concurrent_submissions_return_at_most_one_credential() {
    let mut f = memory().await;
    let (challenge, proof) = f.proof().await;
    let mut a = StdRng::seed_from_u64(1);
    let mut b = StdRng::seed_from_u64(2);
    let (first, second) = tokio::join!(
        f.engine.finish(&mut a, &challenge, &proof, NOW),
        f.engine.finish(&mut b, &challenge, &proof, NOW),
    );
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    assert!(matches!(first, Err(Error::Passport)) || matches!(second, Err(Error::Passport)));
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
    assert_eq!(f.policies.signatures.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn wrong_challenge_does_not_consume_valid_challenge() {
    let mut f = memory().await;
    let (challenge, proof) = f.proof().await;
    let another = f.engine.begin(&mut f.rng, NOW).await.unwrap();
    assert!(matches!(
        f.engine.finish(&mut f.rng, &another, &proof, NOW).await,
        Err(Error::Passport)
    ));
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Ok(Outcome::Issued(_))
    ));
}

#[tokio::test]
async fn wrong_community_proof_and_expired_or_regressed_time_fail_closed() {
    let mut f = memory().await;
    let (challenge, proof) = f.proof().await;
    let foreign = cpsd::PresentationRequest::for_epoch(
        &mut f.rng,
        cpsd::CommunityId::new("elsewhere").unwrap(),
        7,
        [cpsd::GateId::new("global-test").unwrap()],
        NOW + 60,
        EXPIRY,
    )
    .unwrap();
    let foreign_proof = f.passport.present(&mut f.rng, &foreign).unwrap();
    assert!(matches!(
        f.engine
            .finish(&mut f.rng, &challenge, &foreign_proof, NOW)
            .await,
        Err(Error::Passport)
    ));
    assert!(matches!(
        f.engine
            .finish(&mut f.rng, &challenge, &proof, NOW - 1)
            .await,
        Err(Error::Passport)
    ));
    assert!(matches!(
        f.engine
            .finish(&mut f.rng, &challenge, &proof, NOW + 61)
            .await,
        Err(Error::Passport)
    ));
    assert_eq!(f.engine.prune(NOW + 61).await.unwrap(), 1);
    assert!(matches!(
        f.engine.begin(&mut f.rng, 0).await,
        Err(Error::Time)
    ));
    assert!(matches!(
        f.engine.begin(&mut f.rng, u64::MAX).await,
        Err(Error::Time)
    ));
}

#[tokio::test]
async fn challenge_deadline_is_inclusive_but_credential_expiry_is_exclusive() {
    let mut f = memory().await;
    let (challenge, proof) = f.proof().await;
    let result = f
        .engine
        .finish(&mut f.rng, &challenge, &proof, NOW + 60)
        .await
        .unwrap();
    assert_eq!(issued(result).claims.issued, NOW + 60);
}

#[tokio::test]
async fn changed_epoch_schema_and_rulebook_require_a_new_challenge() {
    let mut f = memory().await;
    for change in 0..4 {
        let (challenge, proof) = f.proof().await;
        let previous = f.policies.snapshot.lock().await.clone();
        {
            let mut policy = f.policies.snapshot.lock().await;
            match change {
                0 => policy.passport.epoch += 1,
                1 => policy.rules.policy_epoch += 1,
                2 => policy.schema_version += 1,
                _ => policy.rules.revision += 1,
            }
        }
        assert!(matches!(
            f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
            Err(Error::Policy)
        ));
        *f.policies.snapshot.lock().await = previous;
    }
    assert_eq!(f.members.commits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn malformed_gate_bindings_expiries_and_duplicates_are_rejected() {
    let mut f = memory().await;
    let valid = f.gates.report.lock().await.clone();
    for fault in 0..7 {
        let (challenge, proof) = f.proof().await;
        {
            let mut report = f.gates.report.lock().await;
            *report = valid.clone();
            let result = &mut report.results[0];
            match fault {
                0 => result.subject = "foreign".into(),
                1 => result.community = Some("foreign".into()),
                2 => result.level = crbk::GateLevel::Global,
                3 => result.valid_until = NOW as i64,
                4 => result.valid_until = -1,
                5 => result.proven_at = Some((NOW + 1) as i64),
                _ => {
                    let duplicate = result.clone();
                    report.results.push(duplicate);
                }
            }
        }
        assert!(matches!(
            f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
            Err(Error::Gate)
        ));
    }
    assert_eq!(f.policies.signatures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn released_or_foreign_members_are_never_admitted() {
    let mut f = memory().await;
    f.members.record.lock().await.state = crbk::MembershipState::Released;
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Membership)
    ));
    f.members.record.lock().await.state = crbk::MembershipState::Pending;
    f.members.record.lock().await.id = "another-subject".into();
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Membership)
    ));
}

#[tokio::test]
async fn failed_commit_or_gate_never_calls_signer_and_consumes_proof() {
    let mut f = memory().await;
    f.members.fail_commit.store(true, Ordering::SeqCst);
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Membership)
    ));
    f.members.fail_commit.store(false, Ordering::SeqCst);
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
    f.gates.fail.store(true, Ordering::SeqCst);
    let (challenge, proof) = f.proof().await;
    assert!(matches!(
        f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Gate)
    ));
    assert_eq!(f.policies.signatures.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn signer_errors_wrong_payload_headers_kind_and_tampering_fail_closed() {
    let mut f = memory().await;
    for fault in 1..=5 {
        f.policies.fault.store(fault, Ordering::SeqCst);
        let (challenge, proof) = f.proof().await;
        assert!(matches!(
            f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
            Err(Error::Signing)
        ));
        assert!(matches!(
            f.engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
            Err(Error::Passport)
        ));
    }
}

#[tokio::test]
async fn scope_and_key_configuration_fail_before_issuance() {
    let mut f = memory().await;
    f.policies.snapshot.lock().await.rules.community = "elsewhere".into();
    assert!(matches!(
        f.engine.begin(&mut f.rng, NOW).await,
        Err(Error::Scope)
    ));
    let keys = vec![f.passport.issuer().clone()];
    f.gates.scope = cpsd::CommunityId::new("elsewhere").unwrap();
    assert!(matches!(
        Community::new(
            MemoryStorage::new(scope(), 4).unwrap(),
            keys,
            f.members.clone(),
            f.gates.clone(),
            f.policies.clone(),
            60,
        ),
        Err(Error::Scope)
    ));
    f.gates.scope = scope();
    assert!(matches!(
        Community::new(
            MemoryStorage::new(scope(), 4).unwrap(),
            vec![],
            f.members,
            f.gates,
            f.policies,
            60,
        ),
        Err(Error::Passport)
    ));
}

#[tokio::test]
async fn global_maximum_proof_age_cannot_invent_an_issuance_time() {
    let mut f = memory().await;
    {
        let mut policy = f.policies.snapshot.lock().await;
        let action = policy
            .rules
            .content
            .get_mut(&crbk::action_key(ADMISSION_ACTION))
            .unwrap();
        action["maximum_proof_age"] = serde_json::json!(600);
    }
    assert!(matches!(f.issue().await, Outcome::Missing(_)));
}

#[tokio::test]
async fn real_libsql_runs_the_same_admission_and_rejects_replay_after_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("community.db").display());
    let db = crlt::Db::open(crlt::Config::new(url.clone(), ""))
        .await
        .unwrap();
    db.migrate(&[crlt::Migration::new(1, "challenges", storage::SCHEMA)])
        .await
        .unwrap();
    let store = storage::LibsqlStorage::new(&db, scope(), 32).unwrap();
    store.check_indexes().await.unwrap();
    let mut f = fixture(store).await;
    let (challenge, proof) = f.proof().await;
    let result = f
        .engine
        .finish(&mut f.rng, &challenge, &proof, NOW)
        .await
        .unwrap();
    assert_eq!(issued(result).claims.valid_until, NOW + NEW_MEMBER_LIFETIME);
    drop(f.engine);
    drop(db);
    let db = crlt::Db::open(crlt::Config::new(url, "")).await.unwrap();
    let engine = Community::new(
        storage::LibsqlStorage::new(&db, scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
        f.members,
        f.gates,
        f.policies,
        60,
    )
    .unwrap();
    assert!(matches!(
        engine.finish(&mut f.rng, &challenge, &proof, NOW).await,
        Err(Error::Passport)
    ));
}

#[tokio::test]
async fn ready_cplc_issues_real_credentials_and_caps_at_policy_freshness() {
    use cmnt::ports::Policy;
    let mut f = memory().await;
    let rules = adapters::SharedRulebook::new(crbk::MemoryStore::default());
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "example",
        csgn::SecretKey::from_seed(&mut [8; 32]),
        NOW,
        ESTABLISHED_MEMBER_LIFETIME,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        rules.clone(),
        cplc::MemoryStore::new("example").unwrap(),
        signer,
        cplc::Config {
            credential_action: ADMISSION_ACTION.into(),
            snapshot_validity: 86_400,
        },
    )
    .await
    .unwrap();
    policy
        .schedule_rules(
            None,
            crbk::Change {
                rulebook: f.rules.clone(),
                announced_at: NOW as i64,
                effective_at: NOW as i64,
                notice_seconds: 0,
                policy_epoch: 19,
            },
        )
        .await
        .unwrap();
    policy.set_schema(serde_json::from_value(serde_json::json!({
        "community":"example", "version":3,
        "public":[{"id":"restricted-field","label":"Restricted field", "kind":{"type":"yes_no"},
        "required":false,"filterable":false,"change_preset":"stable","no_contact_details":false}],
        "private":[]
    })).unwrap()).await.unwrap();
    let adapter = adapters::CplcPolicy::new(
        scope(),
        policy,
        rules,
        f.policies.snapshot.lock().await.passport.clone(),
        NOW + 600,
    )
    .unwrap();
    let keys = adapter.snapshot(NOW).await.unwrap().signing_keys;
    let engine = Community::new(
        MemoryStorage::new(scope(), 32).unwrap(),
        vec![f.passport.issuer().clone()],
        f.members,
        f.gates,
        adapter,
        60,
    )
    .unwrap();
    let challenge = engine.begin(&mut f.rng, NOW).await.unwrap();
    let proof = f.passport.present(&mut f.rng, challenge.request()).unwrap();
    let value = issued(
        engine
            .finish(&mut f.rng, &challenge, &proof, NOW)
            .await
            .unwrap(),
    );
    assert_eq!(value.claims.valid_until, NOW + 600);
    let verified = keys
        .verify(&value.cose, csgn::Kind::Credential, NOW)
        .unwrap();
    let wire: cplc::Credential = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(wire.member, f.passport.pseudonym(&scope()).to_hex());
    assert_eq!(wire.pins[0].fingerprint, [11; 32]);
    assert_eq!(wire.devices, vec![[13; 32]]);
}
