use super::*;

#[tokio::test]
async fn traffic_preview_unchanged_refresh_preserves_active_and_completed_batch() {
    for stage in 0..3 {
        let mut service = ready().await;
        service
            .try_preview(request(&service, ConfigurationTarget::RuntimeAndPermanent))
            .unwrap();
        let captured = service.preview_state().evidence().unwrap().clone();
        if stage == 1 {
            while !matches!(service.preview_state(), TrafficPreviewState::Running(_)) {
                service.next_event().await.unwrap();
            }
        } else if stage == 2 {
            complete(&mut service).await;
        }
        assert!(service.observe(observation(2)).unwrap());
        assert!(!matches!(
            service.preview_state(),
            TrafficPreviewState::Stale(_)
        ));
        complete(&mut service).await;
        let TrafficPreviewState::Completed(completed) = service.preview_state().clone() else {
            panic!("unchanged refresh must preserve completion");
        };
        for (before, after) in captured.pairs.iter().zip(&completed.pairs) {
            assert_eq!(before.before_context, after.before_context);
            assert_eq!(before.after_context, after.after_context);
            assert!(after.before.is_some() && after.after.is_some() && after.counts.is_some());
        }
        assert!(Arc::ptr_eq(&captured.request, &completed.request));
        assert!(service.observe(observation(3)).unwrap());
        assert!(Arc::ptr_eq(
            service.preview_state().evidence().unwrap(),
            &completed
        ));
        assert!(!service.observe(observation(2)).unwrap());
        assert!(matches!(
            service.preview_state(),
            TrafficPreviewState::Completed(_)
        ));

        let mut changed = observation(4).snapshot().clone();
        changed.default_zone = ZoneName::parse("drop").unwrap();
        service
            .observe(ObservedSnapshot::new(
                observation(4).identity(),
                Arc::new(changed),
            ))
            .unwrap();
        assert!(matches!(
            service.preview_state(),
            TrafficPreviewState::Stale(_)
        ));
        service.observe(observation(5)).unwrap();
        assert!(matches!(
            service.preview_state(),
            TrafficPreviewState::Stale(_)
        ));
        service.shutdown().await.unwrap();
    }
}
