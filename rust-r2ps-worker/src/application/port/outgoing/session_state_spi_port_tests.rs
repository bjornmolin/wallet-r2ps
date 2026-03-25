use crate::application::port::outgoing::session_state_spi_port::{
    OngoingOperation, PendingLoginState, SessionData, SessionKey, SessionState, SessionStateError,
    SessionStateSpiPort, SessionTransition,
};
use crate::domain::SessionId;
use crate::infrastructure::adapters::outgoing::session_state_memory_cache::SessionStateMemoryCache;

type CacheFactory = fn() -> (SessionStateMemoryCache, SessionId);
type ValidCase = (
    &'static str,
    CacheFactory,
    SessionTransition,
    Box<dyn Fn(Option<SessionState>)>,
);
type InvalidCase = (&'static str, CacheFactory, SessionTransition);

fn create_pending_auth() -> SessionTransition {
    SessionTransition::CreatePendingAuth {
        pending_state: PendingLoginState::new(vec![1, 2]),
        purpose: None,
    }
}

fn authenticate() -> SessionTransition {
    SessionTransition::Authenticate {
        session_key: SessionKey::new(vec![3, 4]),
    }
}

/// Seed the cache into PendingAuth state
fn seeded_pending_auth() -> (SessionStateMemoryCache, SessionId) {
    let cache = SessionStateMemoryCache::new();
    let id = SessionId::new();
    cache
        .apply_transition(Some(&id), Some(&create_pending_auth()))
        .unwrap();
    (cache, id)
}

/// Seed the cache into Active state
fn seeded_active() -> (SessionStateMemoryCache, SessionId) {
    let (cache, id) = seeded_pending_auth();
    cache
        .apply_transition(Some(&id), Some(&authenticate()))
        .unwrap();
    (cache, id)
}

/// Seed the cache into Active(ChangingPin) state
fn seeded_active_changing_pin() -> (SessionStateMemoryCache, SessionId) {
    let (cache, id) = seeded_active();
    cache
        .apply_transition(Some(&id), Some(&SessionTransition::BeginChangingPin))
        .unwrap();
    (cache, id)
}

#[test]
fn valid_transitions() {
    let cases: &[ValidCase] = &[
        (
            "None + CreatePendingAuth → PendingAuth",
            || (SessionStateMemoryCache::new(), SessionId::new()),
            create_pending_auth(),
            Box::new(|s| assert!(matches!(s, Some(SessionState::PendingAuth(_))))),
        ),
        (
            "PendingAuth + Authenticate → Active",
            seeded_pending_auth,
            authenticate(),
            Box::new(|s| {
                assert!(matches!(
                    s,
                    Some(SessionState::Active(SessionData {
                        operation: None,
                        ..
                    }))
                ))
            }),
        ),
        (
            "Active + BeginChangingPin → Active(ChangingPin)",
            seeded_active,
            SessionTransition::BeginChangingPin,
            Box::new(|s| {
                assert!(matches!(
                    s,
                    Some(SessionState::Active(SessionData {
                        operation: Some(OngoingOperation::ChangingPin),
                        ..
                    }))
                ))
            }),
        ),
        (
            "Active + End → None",
            seeded_active,
            SessionTransition::End,
            Box::new(|s| assert!(s.is_none())),
        ),
        (
            "Active(ChangingPin) + End → None",
            seeded_active_changing_pin,
            SessionTransition::End,
            Box::new(|s| assert!(s.is_none())),
        ),
    ];

    for (name, setup, transition, assert_state) in cases {
        let (cache, id) = setup();
        assert!(
            cache.apply_transition(Some(&id), Some(transition)).is_ok(),
            "{name}"
        );
        assert_state(cache.get(&id));
    }
}

#[test]
fn invalid_transitions() {
    let cases: &[InvalidCase] = &[
        // CreatePendingAuth requires no existing session
        (
            "PendingAuth + CreatePendingAuth",
            seeded_pending_auth,
            create_pending_auth(),
        ),
        (
            "Active + CreatePendingAuth",
            seeded_active,
            create_pending_auth(),
        ),
        (
            "Active(ChangingPin) + CreatePendingAuth",
            seeded_active_changing_pin,
            create_pending_auth(),
        ),
        // Authenticate requires PendingAuth
        (
            "None + Authenticate",
            || (SessionStateMemoryCache::new(), SessionId::new()),
            authenticate(),
        ),
        ("Active + Authenticate", seeded_active, authenticate()),
        (
            "Active(ChangingPin) + Authenticate",
            seeded_active_changing_pin,
            authenticate(),
        ),
        // BeginChangingPin requires Active with no ongoing operation
        (
            "None + BeginChangingPin",
            || (SessionStateMemoryCache::new(), SessionId::new()),
            SessionTransition::BeginChangingPin,
        ),
        (
            "PendingAuth + BeginChangingPin",
            seeded_pending_auth,
            SessionTransition::BeginChangingPin,
        ),
        (
            "Active(ChangingPin) + BeginChangingPin",
            seeded_active_changing_pin,
            SessionTransition::BeginChangingPin,
        ),
        // End requires Active
        (
            "None + End",
            || (SessionStateMemoryCache::new(), SessionId::new()),
            SessionTransition::End,
        ),
        (
            "PendingAuth + End",
            seeded_pending_auth,
            SessionTransition::End,
        ),
    ];

    for (name, setup, transition) in cases {
        let (cache, id) = setup();
        let result = cache.apply_transition(Some(&id), Some(transition));
        assert!(
            matches!(result, Err(SessionStateError::InvalidTransition)),
            "{name}: expected InvalidTransition, got {result:?}",
        );
    }
}
