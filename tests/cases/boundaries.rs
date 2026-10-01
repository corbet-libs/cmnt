//! Boundary tests compose actual stores and owners without issuing fake grants.
use super::*;
use std::sync::{Arc, atomic::AtomicI64};

#[tokio::test(flavor = "multi_thread")]
async fn construction_refuses_inconsistent_authenticated_configuration() {
    let mut rng = StdRng::seed_from_u64(103);
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("boundary-issuer").unwrap(),
        vec![cpsd::GateId::new("global-test").unwrap()],
    ).unwrap();
    for case in 0..9 {
        let directory = tempfile::tempdir().unwrap();
        let db = open(
            &format!("file://{}", directory.path().join("community.db").display()),
            "",
        ).await;
        let (policy, _) = policies(&db, rulebook()).await;
        let mut configuration = config(EXPIRY, EXPIRY);
        let mut keys = vec![issuer.public_key().clone()];
        let mut community = scope();
        let expected = match case {
            0 => { configuration.challenge_lifetime = 0; Error::Time }
            1 => { configuration.challenge_lifetime = 301; Error::Time }
            2 => { keys.clear(); Error::Passport }
            3 => { configuration.passport.gates.clear(); Error::Policy }
            4 => { configuration.passport.valid_until += 1; Error::Policy }
            5 => { community = cpsd::CommunityId::new("foreign").unwrap(); Error::Scope }
            6 => { community = cpsd::CommunityId::new([0xff]).unwrap(); Error::Scope }
            7 => { community = cpsd::CommunityId::new(b"nul\0scope").unwrap(); Error::Scope }
            8 => {
                community = cpsd::CommunityId::new(vec![b'a'; cpsd::MAX_COMMUNITY_ID_LEN]).unwrap();
                Error::Scope
            }
            _ => unreachable!(),
        };
        let result: Result<Engine<MemoryStorage>> = Community::new(
            MemoryStorage::new(community, 8).unwrap(),
            keys,
            Parts {
                membership: members(&db, Clock(Arc::new(AtomicI64::new(NOW as i64)))),
                gates: gates(&db),
                policy,
            },
            configuration,
        );
        assert!(matches!(result, Err(error) if error == expected), "case {case}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_policy_refresh_never_changes_the_installed_configuration() {
    let f = fixture(EXPIRY, EXPIRY).await;
    let original = f.engine.snapshot(NOW).await.unwrap();
    for case in 0..7 {
        let mut passport = original.passport.clone();
        let mut freshness = EXPIRY;
        match case {
            0 => freshness = NOW,
            1 => freshness = cpsd::TIME_LIMIT,
            2 => passport.valid_until = NOW,
            3 => passport.valid_until = cpsd::TIME_LIMIT,
            4 => passport.valid_until += 1,
            5 => passport.gates.clear(),
            6 => passport.epoch -= 1,
            _ => unreachable!(),
        }
        assert_eq!(f.engine.refresh_passport_policy(passport, freshness, NOW).await, Err(Error::Policy));
        let installed = f.engine.snapshot(NOW).await.unwrap();
        assert_eq!(installed.passport, original.passport);
        assert_eq!(installed.valid_until, original.valid_until);
    }
    for case in 0..4 {
        let mut passport = original.passport.clone();
        match case {
            0 => passport.epoch -= 1,
            1 => passport.gates.clear(),
            2 => passport.valid_until += 1,
            3 => passport.valid_until = cpsd::TIME_LIMIT.div_ceil(86_400) * 86_400,
            _ => unreachable!(),
        }
        assert_eq!(f.engine.update_passport_policy(passport).await, Err(Error::Policy));
        assert_eq!(f.engine.snapshot(NOW).await.unwrap().passport, original.passport);
    }
    for now in [0, cpsd::TIME_LIMIT, 253_402_300_800] {
        assert!(matches!(f.engine.snapshot(now).await, Err(Error::Time)));
        assert_eq!(f.engine.prune(now).await, Err(Error::Time));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn last_fresh_second_cannot_reserve_an_already_expired_challenge() {
    let mut f = fixture(EXPIRY, NOW + 2).await;
    assert!(matches!(f.engine.begin(&mut f.rng, NOW + 1).await, Err(Error::Time)));
    assert!(matches!(f.engine.snapshot(NOW + 2).await, Err(Error::Policy)));
    let mut f = fixture(EXPIRY, EXPIRY + 100).await;
    assert!(matches!(f.engine.begin(&mut f.rng, EXPIRY - 1).await, Err(Error::Time)));
    assert!(matches!(f.engine.snapshot(EXPIRY).await, Err(Error::Policy)));
}

#[tokio::test(flavor = "multi_thread")]
async fn oversized_claim_schema_cannot_be_projected_into_an_owner_payload() {
    let mut f = fixture(EXPIRY, EXPIRY).await;
    let mut claims = issued(f.issue().await).claims;
    claims.schema_version = u64::MAX;
    assert!(matches!(claims.payload(), Err(Error::Policy)));
}
