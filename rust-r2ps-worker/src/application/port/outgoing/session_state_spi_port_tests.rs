use crate::application::port::outgoing::session_state_spi_port::{
    OngoingOperation, PendingLoginState, SessionData, SessionKey, SessionState, SessionStateError,
    SessionStateSpiPort, SessionTransition,
};
use crate::domain::SessionId;
use crate::infrastructure::adapters::outgoing::session_state_memory_cache::SessionStateMemoryCache;

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

/// Seed the cache into Active(has_performed_hsm_operation: true) state (HSM op already done)
fn seeded_active_hsm_op_done() -> (SessionStateMemoryCache, SessionId) {
    let (cache, id) = seeded_active();
    cache
        .apply_transition(
            Some(&id),
            Some(&SessionTransition::MarkHsmOperationPerformed),
        )
        .unwrap();
    (cache, id)
}

#[test]
fn valid_transitions() {
    let cases: &[(
        &str,
        fn() -> (SessionStateMemoryCache, SessionId),
        SessionTransition,
        Box<dyn Fn(Option<SessionState>)>,
    )] = &[
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
            "Active + MarkHsmOperationPerformed → Active(hsm_op: true)",
            seeded_active,
            SessionTransition::MarkHsmOperationPerformed,
            Box::new(|s| {
                assert!(matches!(
                    s,
                    Some(SessionState::Active(SessionData {
                        has_performed_hsm_operation: true,
                        operation: None,
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
            "Active(hsm_op: true) + End → None",
            seeded_active_hsm_op_done,
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
    let cases: &[(
        &str,
        fn() -> (SessionStateMemoryCache, SessionId),
        SessionTransition,
    )] = &[
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
        // MarkHsmOperationPerformed requires Active with no ongoing operation and no prior HSM op
        (
            "None + MarkHsmOperationPerformed",
            || (SessionStateMemoryCache::new(), SessionId::new()),
            SessionTransition::MarkHsmOperationPerformed,
        ),
        (
            "PendingAuth + MarkHsmOperationPerformed",
            seeded_pending_auth,
            SessionTransition::MarkHsmOperationPerformed,
        ),
        (
            "Active(ChangingPin) + MarkHsmOperationPerformed",
            seeded_active_changing_pin,
            SessionTransition::MarkHsmOperationPerformed,
        ),
        (
            "Active(hsm_op: true) + MarkHsmOperationPerformed",
            seeded_active_hsm_op_done,
            SessionTransition::MarkHsmOperationPerformed,
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
