use super::*;

fn refresh(state: &mut UiState, snapshot: FirewallSnapshot) -> Vec<Effect> {
    let generation = state
        .traffic_observation
        .as_ref()
        .map_or(1, |o| o.identity().generation().get() + 1);
    let id = RefreshId::new(generation);
    update(
        state,
        UiAction::RefreshStarted {
            id,
            trigger: RefreshTrigger::Periodic,
        },
    );
    update(
        state,
        UiAction::RefreshCompleted {
            schedule: RefreshScheduleObservation {
                id,
                trigger: RefreshTrigger::Periodic,
                merged_manual_requests: 0,
                coalesced_periodic_ticks: 0,
            },
            result: Ok(ObservedSnapshot::new(
                SnapshotIdentity::new(
                    id,
                    SnapshotGeneration::new(std::num::NonZeroU64::new(generation).unwrap()),
                ),
                Arc::new(snapshot),
            )),
            observation: RefreshObservation::total_only(std::time::Duration::from_millis(20)),
        },
    )
}

#[tokio::test]
async fn traffic_preview_after_unchanged_refresh_uses_latest_observation() {
    for plan in [false, true] {
        let mut state = review();
        if plan {
            state.overlays = vec![Overlay::Confirm(Confirmation {
                title: "Plan".into(),
                body: vec![],
                on_confirm: UiAction::ApplyPlanConfirmed(MutationPlan::new(
                    PlanId::new(47),
                    vec![operation()],
                    state.snapshot.clone().unwrap(),
                )),
            })];
        }
        let parent = state.overlays.clone();
        let reviewed = state.snapshot.clone().unwrap();
        let old_identity = state.traffic_observation.as_ref().unwrap().identity();
        let mut shell = TrafficShell::new(Some(storage(Some(suite()), false)));
        let effects = refresh(&mut state, (*reviewed).clone());
        route(&mut shell, &mut state, effects);
        let latest = state.traffic_observation.clone().unwrap();
        assert_ne!(old_identity, latest.identity());
        assert!(!Arc::ptr_eq(&reviewed, latest.snapshot_arc()));

        let effects = update(&mut state, UiAction::PreviewTraffic);
        assert!(matches!(&effects[..], [Effect::TrafficPreview(_)]));
        let request = preview(&state).request.clone();
        assert_eq!(request.operations, vec![operation()]);
        assert_eq!(request.plan_id, plan.then(|| PlanId::new(47)));
        assert_eq!(request.observation.identity(), latest.identity());
        assert!(Arc::ptr_eq(
            request.observation.snapshot_arc(),
            latest.snapshot_arc()
        ));
        route(&mut shell, &mut state, effects);
        completed(&mut shell, &mut state).await;
        assert!(preview(&state).current());
        assert_eq!(
            preview(&state)
                .publication
                .state
                .evidence()
                .unwrap()
                .pairs
                .len(),
            2
        );

        let effects = update(&mut state, UiAction::CloseOverlay);
        route(&mut shell, &mut state, effects);
        assert_eq!(state.overlays, parent);
        shell.shutdown().await.unwrap();
    }
}

#[test]
fn traffic_preview_after_changed_refresh_requires_new_review() {
    let mut state = review();
    let parent = state.overlays.clone();
    let mut changed = (**state.snapshot.as_ref().unwrap()).clone();
    changed.default_zone = ZoneName::parse("drop").unwrap();
    refresh(&mut state, changed);

    assert!(update(&mut state, UiAction::PreviewTraffic).is_empty());
    assert_eq!(state.overlays, parent);
}

#[tokio::test]
async fn traffic_preview_unchanged_refresh_retains_completed_details() {
    let mut state = review();
    let mut shell = TrafficShell::new(Some(storage(Some(suite()), false)));
    let effects = update(&mut state, UiAction::PreviewTraffic);
    route(&mut shell, &mut state, effects);
    completed(&mut shell, &mut state).await;
    let request = preview(&state).request.clone();
    let evidence = preview(&state)
        .publication
        .state
        .evidence()
        .unwrap()
        .clone();
    update(&mut state, UiAction::PreviewDetails);
    let details = state.overlays.last().unwrap().clone();

    for _ in 0..3 {
        let identical = (**state.snapshot.as_ref().unwrap()).clone();
        let effects = refresh(&mut state, identical);
        assert!(matches!(&effects[..], [Effect::TrafficObserve(Some(_))]));
        route(&mut shell, &mut state, effects);
        assert!(preview(&state).current());
        assert!(Arc::ptr_eq(&preview(&state).request, &request));
        assert!(Arc::ptr_eq(
            preview(&state).publication.state.evidence().unwrap(),
            &evidence
        ));
        assert_eq!(state.overlays.last(), Some(&details));
    }

    let mut changed = (**state.snapshot.as_ref().unwrap()).clone();
    changed.default_zone = ZoneName::parse("drop").unwrap();
    let effects = refresh(&mut state, changed);
    assert!(matches!(
        effects.first(),
        Some(Effect::TrafficPreviewCancel)
    ));
    route(&mut shell, &mut state, effects);
    assert!(!preview(&state).current());
    assert!(
        matches!(state.overlays.last(), Some(Overlay::TrafficPreviewDetails(d)) if d.lines[0].1.contains("Stale"))
    );
    let effects = refresh(&mut state, request.observation.snapshot().clone());
    route(&mut shell, &mut state, effects);
    assert!(
        !preview(&state).current(),
        "changed evidence must not revive"
    );
    shell.shutdown().await.unwrap();
}

#[test]
fn traffic_preview_reused_identity_and_older_observation_cancel() {
    for older in [false, true] {
        let mut state = review();
        let old = state.traffic_observation.clone().unwrap();
        refresh(&mut state, old.snapshot().clone());
        update(&mut state, UiAction::PreviewTraffic);
        let captured = preview(&state).request.observation.clone();
        let invalid = if older {
            old
        } else {
            ObservedSnapshot::new(captured.identity(), Arc::new(captured.snapshot().clone()))
        };
        state.snapshot = Some(invalid.snapshot_arc().clone());
        state.traffic_observation = Some(invalid);

        assert_eq!(
            update(&mut state, UiAction::Tick),
            vec![Effect::TrafficPreviewCancel]
        );
        assert!(preview(&state).invalidated);
    }
}
