# Phase 5C3 Staged Refresh and Lazy Detail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Render an identity-safe zone overview before unrelated service and policy details finish, then hydrate one authoritative snapshot with selected-zone detail priority without weakening mutation or rollback safety.

**Architecture:** The engine keeps one backend-owned refresh future but drives two explicit backend stages. A latest-value priority source reorders only detail work that has not started; the UI stores the overview separately from `FirewallSnapshot`, and only the final hydrated result becomes authoritative.

**Tech Stack:** Rust 1.88, Tokio `watch` and bounded `mpsc`, async trait return-position futures, ratatui TEA reducer, fake `CommandRunner`, paused Tokio time, cargo llvm-cov, disposable real-firewalld containers.

---

## File Structure

- `src/application/api.rs`: public staged-refresh values, priority publisher/source, engine events, and handle wiring.
- `src/application/ports.rs`: default staged backend methods and stage result types.
- `src/domain/observation.rs`: deterministic observation merge for sequential stages.
- `src/infrastructure/firewalld/detail_priority.rs`: pure pending-detail ordering; no I/O or Tokio task ownership.
- `src/infrastructure/firewalld/mod.rs`: CLI overview/hydration implementation, recorder scopes, cache integration, and bounded batch execution.
- `src/application/engine.rs`: one cancellable staged read lifecycle and overview event delivery.
- `src/ui/action.rs`: overview action.
- `src/ui/state.rs`: identity-bearing preview state and pure priority derivation.
- `src/ui/views.rs`: overview-only row extraction for zone-backed views.
- `src/ui/update/mod.rs`: stale-event-safe preview reducer transitions.
- `src/ui/mod.rs`: event mapping and non-blocking latest-priority publication.
- `src/ui/components.rs`: visible loading-details state.
- `tests/backend.rs`: exact CLI command order, early overview, hydration equality, and degradation evidence.
- `scripts/check-critical-coverage.sh`: fail-closed floor for the pure detail-priority policy.
- `site/docs/index.html`: concise operator semantics for staged refresh.

## Task 1: Define staged refresh contracts and merge observations

**Files:**

- Modify: `src/application/api.rs:100-270`
- Modify: `src/application/mod.rs:10-30`
- Modify: `src/application/ports.rs:200-250`
- Modify: `src/domain/observation.rs:41-90`
- Test: `src/application/api.rs`
- Test: `src/domain/observation.rs`

- [ ] **Step 1: Add RED tests for latest-value priority and observation merging.**

Add these exact behavioral tests:

```rust
#[test]
fn refresh_priority_source_keeps_only_the_latest_value() {
    let (publisher, source) = refresh_priority_channel();
    let public = ZoneName::parse("public").unwrap();
    let work = ZoneName::parse("work").unwrap();

    publisher.publish(RefreshPriority {
        zone: Some(public),
        service: None,
        policy: None,
    });
    publisher.publish(RefreshPriority {
        zone: Some(work.clone()),
        service: None,
        policy: None,
    });

    assert_eq!(source.latest().zone, Some(work));
}

#[test]
fn sequential_refresh_observations_merge_counts_and_sections() {
    let overview = RefreshObservation::new(
        Duration::from_millis(12),
        3,
        vec![RefreshSectionObservation {
            section: RefreshSection::Services,
            elapsed: Duration::from_millis(4),
            process_count: 1,
        }],
    );
    let hydration = RefreshObservation::new(
        Duration::from_millis(20),
        5,
        vec![RefreshSectionObservation {
            section: RefreshSection::Services,
            elapsed: Duration::from_millis(7),
            process_count: 2,
        }],
    );

    let merged = overview.merge_sequential(hydration);
    assert_eq!(merged.elapsed, Duration::from_millis(32));
    assert_eq!(merged.process_count, Some(8));
    assert_eq!(merged.sections[0].elapsed, Duration::from_millis(11));
    assert_eq!(merged.sections[0].process_count, 3);
}
```

- [ ] **Step 2: Run RED and record the missing contracts.**

Run:

```bash
rtk cargo test --locked refresh_priority_source_keeps_only_the_latest_value
rtk cargo test --locked sequential_refresh_observations_merge_counts_and_sections
```

Expected: compile failure for missing `RefreshPriority`, `refresh_priority_channel`, and `merge_sequential`.

- [ ] **Step 3: Implement the pure/application contracts.**

Add the following public shapes in `application::api`:

```rust
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RefreshPriority {
    pub zone: Option<ZoneName>,
    pub service: Option<ServiceName>,
    pub policy: Option<PolicyName>,
}

#[derive(Clone)]
pub struct RefreshPriorityPublisher(watch::Sender<RefreshPriority>);

#[derive(Clone)]
pub struct RefreshPrioritySource(watch::Receiver<RefreshPriority>);

pub fn refresh_priority_channel() -> (RefreshPriorityPublisher, RefreshPrioritySource) {
    let (publisher, source) = watch::channel(RefreshPriority::default());
    (RefreshPriorityPublisher(publisher), RefreshPrioritySource(source))
}

impl RefreshPriorityPublisher {
    pub fn publish(&self, priority: RefreshPriority) {
        self.0.send_replace(priority);
    }
}

impl RefreshPrioritySource {
    #[must_use]
    pub fn latest(&self) -> RefreshPriority {
        self.0.borrow().clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOverview {
    pub status: FirewallStatus,
    pub default_zone: ZoneName,
    pub active: BTreeMap<ZoneName, ActiveZone>,
    pub runtime: BTreeMap<ZoneName, ZoneDetails>,
    pub permanent: BTreeMap<ZoneName, ZoneDetails>,
    pub available_services: Vec<ServiceName>,
    pub policy_names: Scoped<Vec<PolicyName>>,
    pub degraded: Vec<DegradedSection>,
}
```

Add `RefreshOverview::referenced_services()` with the same sort/deduplicate semantics as `FirewallSnapshot::referenced_services()`.

Add stage results and default port methods:

```rust
pub struct OverviewRead {
    pub result: Result<Option<Arc<RefreshOverview>>, FirewallError>,
    pub observation: RefreshObservation,
}

fn snapshot_overview(
    &self,
    _priority: &RefreshPrioritySource,
) -> impl Future<Output = OverviewRead> + Send {
    async {
        OverviewRead {
            result: Ok(None),
            observation: RefreshObservation::total_only(Duration::ZERO),
        }
    }
}

fn snapshot_hydrated(
    &self,
    _overview: Option<Arc<RefreshOverview>>,
    _priority: &RefreshPrioritySource,
) -> impl Future<Output = SnapshotRead> + Send {
    self.snapshot_observed()
}
```

Implement `RefreshObservation::merge_sequential` by merging equal
`RefreshSection` keys through a `BTreeMap`, summing durations and process
counts, and returning `process_count: None` if either stage lacks a count.

- [ ] **Step 4: Run GREEN and static checks.**

```bash
rtk cargo test --locked refresh_priority_source_keeps_only_the_latest_value
rtk cargo test --locked sequential_refresh_observations_merge_counts_and_sections
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

Expected: both focused tests pass; Clippy and fmt exit zero.

- [ ] **Step 5: Commit Task 1.**

```bash
rtk git add src/application/api.rs src/application/mod.rs src/application/ports.rs src/domain/observation.rs
rtk git commit -m "feat(refresh): define staged snapshot contracts"
```

## Task 2: Split the CLI read into overview and authoritative hydration

**Files:**

- Modify: `src/infrastructure/firewalld/mod.rs:136-802`
- Test: `tests/backend.rs`

- [ ] **Step 1: Add a RED backend test proving early overview and final equality.**

Create a controlled runner that records argv, returns the existing fixture
responses, and blocks `--info-service=background` on a semaphore. The test must
drive the two port methods directly:

```rust
#[tokio::test]
async fn staged_cli_read_returns_zone_overview_before_background_details() {
    let (backend, control) = staged_backend_fixture();
    let (_publisher, priority) = refresh_priority_channel();

    let overview = backend.snapshot_overview(&priority).await;
    let overview = overview.result.unwrap().unwrap();
    assert_eq!(overview.default_zone.as_str(), "public");
    assert!(overview.runtime.contains_key(&ZoneName::parse("public").unwrap()));
    assert!(!control.background_detail_started());

    let hydration = backend.snapshot_hydrated(Some(overview), &priority);
    tokio::pin!(hydration);
    control.wait_for_background_detail().await;
    assert!(futures_util::poll!(&mut hydration).is_pending());
    control.release_background_detail();
    assert!(hydration.await.result.is_ok());
}
```

Add a second test that compares the final staged result to the existing
complete fixture snapshot field-for-field.

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked --test backend staged_cli_read_returns_zone_overview_before_background_details -- --exact
rtk cargo test --locked --test backend staged_cli_final_snapshot_matches_complete_snapshot -- --exact
```

Expected: the default backend returns `None`, so the first test fails before
any production CLI split exists.

- [ ] **Step 3: Implement CLI overview collection.**

Extract the existing status, default-zone, zone-section, available-service,
and policy-name listing commands into:

```rust
async fn refresh_overview(&self) -> Result<RefreshOverview, FirewallError> {
    let status = observe_section(RefreshSection::Status, self.probe()).await?;
    if !status.daemon_running && !self.is_offline() {
        return Err(FirewallError::DaemonNotRunning);
    }
    let (default_zone, active, runtime, permanent, mut degraded) =
        self.fetch_zone_overview().await?;
    let (available_services, service_error) =
        observe_section(RefreshSection::Services, self.available_services()).await;
    degraded.extend(service_error);
    let (policy_names, policy_errors) =
        observe_section(RefreshSection::Policies, self.policy_names()).await;
    degraded.extend(policy_errors);
    Ok(RefreshOverview {
        status,
        default_zone,
        active,
        runtime,
        permanent,
        available_services,
        policy_names,
        degraded,
    })
}
```

Override `snapshot_overview` with a fresh `RefreshRecorder` scope and return
`Some(Arc<RefreshOverview>)`. Do not populate a `FirewallSnapshot` in this
method.

- [ ] **Step 4: Implement authoritative hydration.**

Refactor policy listing from detail fetch so `policies_for` accepts the exact
names captured by the overview. Build the final snapshot only after IP sets,
direct rules, policy details, and referenced service definitions finish:

```rust
async fn hydrate_overview(
    &self,
    overview: Arc<RefreshOverview>,
    priority: &RefreshPrioritySource,
) -> Result<FirewallSnapshot, FirewallError> {
    let (ipsets, policies, direct_rules, mut degraded) =
        self.fetch_hydrated_sections(&overview, priority).await;
    let (service_definitions, service_degraded) = self
        .service_definitions_prioritized(
            overview.referenced_services(),
            &overview,
            priority,
        )
        .await;
    degraded.extend(service_degraded);
    degraded.extend(overview.degraded.clone());
    Ok(FirewallSnapshot {
        status: overview.status.clone(),
        default_zone: overview.default_zone.clone(),
        active: overview.active.clone(),
        runtime: overview.runtime.clone(),
        permanent: overview.permanent.clone(),
        ipsets,
        service_definitions,
        available_services: overview.available_services.clone(),
        policies,
        direct_rules,
        degraded,
    })
}
```

Override `snapshot_hydrated` with its own recorder scope. If `overview` is
`None`, delegate to `snapshot_observed`. Keep `snapshot_fresh` on the current
complete eager path and force the heavy cache age to `None` before reading.

- [ ] **Step 5: Run GREEN and backend regressions.**

```bash
rtk cargo test --locked --test backend staged_cli_read_returns_zone_overview_before_background_details -- --exact
rtk cargo test --locked --test backend staged_cli_final_snapshot_matches_complete_snapshot -- --exact
rtk cargo test --locked --test backend
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

Expected: early overview and equality tests pass; all backend tests remain
green.

- [ ] **Step 6: Commit Task 2.**

```bash
rtk git add src/infrastructure/firewalld/mod.rs tests/backend.rs
rtk git commit -m "feat(refresh): publish CLI overview before hydration"
```

## Task 3: Add pure selected-detail priority and bounded batch hydration

**Files:**

- Create: `src/infrastructure/firewalld/detail_priority.rs`
- Modify: `src/infrastructure/firewalld/mod.rs`
- Test: `src/infrastructure/firewalld/detail_priority.rs`
- Test: `tests/backend.rs`

- [ ] **Step 1: Write RED pure ordering tests.**

```rust
#[test]
fn preferred_zone_services_then_selected_policy_then_stable_background() {
    let overview = fixture_overview();
    let priority = RefreshPriority {
        zone: Some(ZoneName::parse("work").unwrap()),
        service: None,
        policy: Some(PolicyName::parse("allow-work").unwrap()),
    };
    let ordered = order_pending(fixture_work(), &overview, &priority);

    assert!(matches!(&ordered[0], DetailWork::Service(name) if name.as_str() == "ssh"));
    assert!(matches!(&ordered[1], DetailWork::Policy { name, .. } if name.as_str() == "allow-work"));
    assert!(ordered[2..].windows(2).all(|pair| pair[0].stable_key() <= pair[1].stable_key()));
}

#[test]
fn a_new_hint_reorders_only_work_not_already_taken() {
    let overview = fixture_overview();
    let mut queue = DetailQueue::new(fixture_work());
    let first = queue.take_batch(8, &overview, &RefreshPriority::default());
    let updated = RefreshPriority {
        zone: None,
        service: Some(ServiceName::parse("https").unwrap()),
        policy: None,
    };
    let second = queue.take_batch(8, &overview, &updated);

    assert!(first.iter().all(|work| !second.contains(work)));
    assert!(matches!(&second[0], DetailWork::Service(name) if name.as_str() == "https"));
}
```

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked infrastructure::firewalld::detail_priority::tests
```

Expected: compile failure because `DetailWork`, `DetailQueue`, and
`order_pending` do not exist.

- [ ] **Step 3: Implement the pure queue.**

Use one owned pending vector and stable keys; never store historical priority
hints:

```rust
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum DetailWork {
    Service(ServiceName),
    Policy {
        target: ConfigurationTarget,
        name: PolicyName,
    },
}

pub(super) struct DetailQueue {
    pending: Vec<DetailWork>,
}

impl DetailQueue {
    pub(super) fn new(mut pending: Vec<DetailWork>) -> Self {
        pending.sort_by_key(DetailWork::stable_key);
        pending.dedup();
        Self { pending }
    }

    pub(super) fn take_batch(
        &mut self,
        limit: usize,
        overview: &RefreshOverview,
        priority: &RefreshPriority,
    ) -> Vec<DetailWork> {
        self.pending.sort_by_key(|work| work.priority_key(overview, priority));
        let count = limit.min(self.pending.len());
        self.pending.drain(..count).collect()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}
```

`priority_key` must use `(class, stable_key)` where preferred-zone services
are class 0, explicitly selected service/policy class 1, and background work
class 2.

- [ ] **Step 4: Integrate bounded batches with the live priority source.**

Replace one all-at-once detail iterator with a loop that reads only the latest
hint before each batch:

```rust
while !queue.is_empty() {
    let batch = queue.take_batch(8, overview, &priority.latest());
    let completed = bounded_fan_out(
        batch.into_iter().map(|work| self.fetch_detail(work)),
    )
    .await;
    accumulator.extend(completed);
}
```

An active batch is never restarted. Add a controlled-runner test that changes
the watch value while batch one is blocked and asserts the selected detail is
the first command in batch two.

- [ ] **Step 5: Run GREEN and stress ordering.**

```bash
rtk cargo test --locked infrastructure::firewalld::detail_priority::tests
rtk cargo test --locked --test backend staged_priority_changes_only_reorder_unstarted_details -- --exact
rtk cargo test --locked --test backend staged_priority_changes_only_reorder_unstarted_details -- --exact --test-threads=1
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

Expected: pure and controlled-runner tests pass without retries or sleeps.

- [ ] **Step 6: Commit Task 3.**

```bash
rtk git add src/infrastructure/firewalld/detail_priority.rs src/infrastructure/firewalld/mod.rs tests/backend.rs
rtk git commit -m "perf(refresh): prioritize selected firewall details"
```

## Task 4: Drive both stages inside one cancellable engine lifecycle

**Files:**

- Modify: `src/application/api.rs:180-270`
- Modify: `src/application/engine.rs:210-650`
- Test: `src/application/engine.rs`

- [ ] **Step 1: Add RED engine lifecycle tests.**

Extend `ControlledSnapshotBackend` with separate overview and hydration
semaphores. Add these exact scenarios:

```rust
#[tokio::test(start_paused = true)]
async fn overview_event_arrives_before_hydration_finishes() {
    let harness = StagedEngineHarness::new();
    harness.release_overview();
    let event = harness.recv_event().await;
    assert!(matches!(event, EngineEvent::RefreshOverviewReady { id, .. } if id.get() == 1));
    assert_eq!(harness.hydration_completions(), 0);
}

#[tokio::test(start_paused = true)]
async fn mutation_cancels_hydration_before_apply() {
    let harness = StagedEngineHarness::blocked_in_hydration();
    harness.send_normal_mutation().await;
    harness.expect_cancelled(RefreshCancellationReason::MutationPreempted).await;
    assert_eq!(harness.active_hydrations_during_apply(), 0);
    assert_eq!(harness.applied_count(), 1);
}

#[tokio::test(start_paused = true)]
async fn rollback_preempts_mandatory_hydration_and_restarts_it() {
    let harness = StagedEngineHarness::blocked_in_post_mutation_hydration();
    harness.send_rollback().await;
    harness.expect_cancelled(RefreshCancellationReason::RollbackPreempted).await;
    assert_eq!(harness.rollback_count(), 1);
    assert_eq!(harness.post_mutation_starts(), 2);
}
```

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked overview_event_arrives_before_hydration_finishes
rtk cargo test --locked mutation_cancels_hydration_before_apply
rtk cargo test --locked rollback_preempts_mandatory_hydration_and_restarts_it
```

Expected: compile failure for the new engine event and staged backend calls.

- [ ] **Step 3: Wire the latest-value priority channel into the engine.**

Create the priority channel in `application::spawn`, store the publisher on
`EngineHandle`, and pass the source into `engine::run`:

```rust
pub struct EngineHandle {
    pub requests: mpsc::Sender<EngineRequest>,
    pub manual_refreshes: mpsc::Sender<ManualRefreshRequest>,
    pub rollbacks: mpsc::Sender<RollbackRequest>,
    pub events: mpsc::Receiver<EngineEvent>,
    pub refresh_priority: RefreshPriorityPublisher,
}
```

Add the event:

```rust
RefreshOverviewReady {
    id: RefreshId,
    overview: Arc<RefreshOverview>,
},
```

- [ ] **Step 4: Implement one staged read future used by both drivers.**

Add a helper that returns one final `SnapshotRead` or shutdown:

```rust
async fn read_staged_snapshot<B: FirewallBackend>(
    backend: &B,
    priority: &RefreshPrioritySource,
    events: &mpsc::Sender<EngineEvent>,
    id: RefreshId,
) -> Option<SnapshotRead> {
    let OverviewRead {
        result,
        observation: overview_observation,
    } = backend.snapshot_overview(priority).await;
    let overview = match result {
        Ok(overview) => overview,
        Err(error) => {
            return Some(SnapshotRead {
                result: Err(error),
                observation: overview_observation,
            });
        }
    };
    if let Some(value) = overview.as_ref()
        && events
            .send(EngineEvent::RefreshOverviewReady {
                id,
                overview: Arc::clone(value),
            })
            .await
            .is_err()
    {
        return None;
    }
    let hydration = backend.snapshot_hydrated(overview, priority).await;
    Some(SnapshotRead {
        result: hydration.result,
        observation: overview_observation.merge_sequential(hydration.observation),
    })
}
```

Pin this helper instead of `backend.snapshot_observed()` in both
`drive_ordinary_refresh` and `drive_mandatory_refresh`. Preserve their existing
request, rollback, manual, periodic, closure, and boundary-drain select arms.
Returning `None` maps to the existing `Shutdown` outcome.

- [ ] **Step 5: Run GREEN and complete engine regression.**

```bash
rtk cargo test --locked overview_event_arrives_before_hydration_finishes
rtk cargo test --locked mutation_cancels_hydration_before_apply
rtk cargo test --locked rollback_preempts_mandatory_hydration_and_restarts_it
rtk cargo test --locked application::engine::tests
rtk cargo test --locked application::refresh_scheduler::tests
rtk cargo clippy --locked --lib -- -D warnings
rtk cargo fmt --all -- --check
```

Expected: all staged and existing scheduler/engine tests pass.

- [ ] **Step 6: Commit Task 4.**

```bash
rtk git add src/application/api.rs src/application/engine.rs
rtk git commit -m "feat(refresh): drive staged snapshot lifecycles"
```

## Task 5: Render identity-safe previews and publish UI priority

**Files:**

- Modify: `src/ui/action.rs:210-250`
- Modify: `src/ui/state.rs:126-360`
- Modify: `src/ui/views.rs:1-760`
- Modify: `src/ui/update/mod.rs:40-180`
- Modify: `src/ui/mod.rs:80-300`
- Modify: `src/ui/components.rs`
- Test: `src/ui/update/mod.rs`
- Test: `src/ui/mod.rs`

- [ ] **Step 1: Add RED reducer and shell tests.**

```rust
#[test]
fn matching_overview_is_visible_and_stale_overview_is_ignored() {
    let mut state = state_with_snapshot();
    update(&mut state, UiAction::RefreshStarted {
        id: RefreshId::new(9),
        trigger: RefreshTrigger::Periodic,
    });
    update(&mut state, UiAction::RefreshOverviewReady {
        id: RefreshId::new(8),
        overview: Arc::new(fixture_overview()),
    });
    assert!(state.refresh_overview.is_none());
    update(&mut state, UiAction::RefreshOverviewReady {
        id: RefreshId::new(9),
        overview: Arc::new(fixture_overview()),
    });
    assert_eq!(state.refresh_overview.as_ref().unwrap().id, RefreshId::new(9));
}

#[test]
fn authoritative_snapshot_keeps_mutation_available_during_overview() {
    let mut state = state_with_snapshot();
    state.active_refresh = Some(RefreshId::new(3));
    state.refresh_overview = Some(RefreshOverviewState {
        id: RefreshId::new(3),
        overview: Arc::new(fixture_overview()),
    });
    assert!(update(&mut state, UiAction::ToggleMasqueradeRequested).is_empty());
    let effects = update(&mut state, UiAction::ConfirmAccept);
    assert!(effects.iter().any(|effect| matches!(effect, Effect::Apply(_))));
}

#[tokio::test]
async fn selection_updates_replace_the_engine_priority_without_queueing() {
    let handle = test_engine_handle();
    publish_priority(&handle, public_service_priority());
    publish_priority(&handle, work_policy_priority());
    assert_eq!(handle.observed_priority(), work_policy_priority());
}
```

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked matching_overview_is_visible_and_stale_overview_is_ignored
rtk cargo test --locked authoritative_snapshot_keeps_mutation_available_during_overview
rtk cargo test --locked selection_updates_replace_the_engine_priority_without_queueing
```

Expected: compile failure for preview state/action and priority publication.

- [ ] **Step 3: Add preview state and identity-aware reducer transitions.**

```rust
#[derive(Debug, Clone)]
pub struct RefreshOverviewState {
    pub id: RefreshId,
    pub overview: Arc<RefreshOverview>,
}
```

Add `refresh_overview: Option<RefreshOverviewState>` to `UiState`. Accept an
overview only when `active_refresh == Some(id)`. Clear the matching preview on
`RefreshCancelled` and every final completion; a stale completion must not
clear a newer preview.

Add `UiState::refresh_priority()` that returns the effective zone plus the
selected `RowId::Service` or `RowId::Policy` when the current row has one of
those identities.

- [ ] **Step 4: Render overview rows without constructing a partial snapshot.**

Add a separate zone-only extraction entry point:

```rust
pub fn overview_rows(
    view: ViewId,
    overview: &RefreshOverview,
    zone: &ZoneName,
    target: ConfigurationTarget,
) -> Option<Vec<ViewRow>> {
    match view {
        ViewId::Zones
        | ViewId::Services
        | ViewId::Ports
        | ViewId::Forwarding
        | ViewId::RichRules
        | ViewId::Interfaces
        | ViewId::Sources => Some(zone_rows_from_parts(
            view,
            &overview.active,
            &overview.runtime,
            &overview.permanent,
            zone,
            target,
        )),
        ViewId::IpSets | ViewId::Direct | ViewId::Logs | ViewId::Policies => None,
    }
}
```

Refactor the existing zone-backed row construction into
`zone_rows_from_parts`; do not create a temporary `FirewallSnapshot`.
`UiState::all_rows` uses matching overview rows when available and falls back
to the authoritative snapshot for unsupported views.

Render `loading details` beside the refresh spinner whenever a matching
overview exists.

- [ ] **Step 5: Publish priority after each completed reducer worklist.**

Map `EngineEvent::RefreshOverviewReady` to the UI action. At event-loop startup
and after every `process_action_worklist`, publish only when the derived value
changed:

```rust
fn publish_refresh_priority(
    engine: &EngineHandle,
    state: &UiState,
    published: &mut RefreshPriority,
) {
    let next = state.refresh_priority();
    if next != *published {
        engine.refresh_priority.publish(next.clone());
        *published = next;
    }
}
```

This call is synchronous latest-value replacement; it must never enter the
bounded `EngineOutbox` or await engine capacity.

- [ ] **Step 6: Run GREEN and UI regressions.**

```bash
rtk cargo test --locked matching_overview_is_visible_and_stale_overview_is_ignored
rtk cargo test --locked authoritative_snapshot_keeps_mutation_available_during_overview
rtk cargo test --locked selection_updates_replace_the_engine_priority_without_queueing
rtk cargo test --locked ui::update::tests
rtk cargo test --locked ui::tests
rtk cargo clippy --locked --all-targets -- -D warnings
rtk cargo fmt --all -- --check
```

Expected: preview identity, mutation preemption, and latest-value tests pass;
the complete reducer and shell suites remain green.

- [ ] **Step 7: Commit Task 5.**

```bash
rtk git add src/ui/action.rs src/ui/state.rs src/ui/views.rs src/ui/update/mod.rs src/ui/mod.rs src/ui/components.rs
rtk git commit -m "feat(ui): render prioritized refresh overviews"
```

## Task 6: Prove degradation, load bounds, coverage, and operator semantics

**Files:**

- Modify: `src/domain/mock.rs`
- Modify: `src/application/engine.rs`
- Modify: `tests/backend.rs`
- Modify: `scripts/check-critical-coverage.sh`
- Modify: `site/docs/index.html`

- [ ] **Step 1: Add RED safety and load assertions.**

Add a backend test where one selected service detail fails and assert the final
snapshot contains exactly one `DegradedSection` with section
`ServiceDefinitions` and that service name. Add a paused-time engine test that
cancels during overview, then during hydration, and asserts neither stale
overview reaches the next refresh ID.

Extend the existing large fixture test with:

```rust
assert!(overview_reducer_elapsed < Duration::from_millis(50));
assert_eq!(priority_source_buffered_generations, 1);
assert_eq!(max_active_snapshots, 1);
assert_eq!(final_snapshot.service_definitions.len(), expected_service_count);
```

- [ ] **Step 2: Run RED.**

```bash
rtk cargo test --locked staged_service_failure_is_exactly_degraded
rtk cargo test --locked cancelled_staged_refresh_cannot_publish_stale_overview
rtk cargo test --locked --release performance_budget -- --test-threads=1
```

Expected: focused tests fail until the exact degraded record, lifecycle
clearing, and performance evidence are complete.

- [ ] **Step 3: Complete tracing and coverage enforcement.**

Emit structured fields `overview_elapsed_ms`, `hydration_elapsed_ms`,
`preferred_details`, `background_details`, and `cancellation_stage` from the
engine/CLI boundaries. Add a critical coverage floor:

```bash
check_file "src/infrastructure/firewalld/detail_priority.rs" 95 "detail priority policy"
```

Add an operator paragraph directly below the refresh interval documentation:

```html
<p>FWDeck shows status and zone data as soon as the overview stage completes.
Service and policy details continue loading in the same cancellable refresh;
only the final complete or explicitly degraded snapshot becomes authoritative
for validation, snapshots, and exports.</p>
```

- [ ] **Step 4: Run GREEN and complete local validation.**

```bash
rtk cargo fmt --all -- --check
rtk cargo clippy --locked --all-targets -- -D warnings
rtk cargo clippy --locked --all-targets --features dbus -- -D warnings
rtk cargo test --locked --all-features
rtk cargo test --locked --release performance_budget -- --test-threads=1
rtk cargo +1.88.0 check --all-targets --locked
rtk cargo llvm-cov --locked --all-features --fail-under-lines 75 --json --summary-only --output-path target/coverage-summary.json
rtk proxy ./scripts/check-critical-coverage.sh target/coverage-summary.json
rtk bash -n scripts/check-critical-coverage.sh
rtk shellcheck scripts/check-critical-coverage.sh
```

Expected: every installed gate exits zero. If local ShellCheck is unavailable,
record that exact environmental limitation and leave its validation claim to
required CI.

- [ ] **Step 5: Run the disposable real-firewalld matrix.**

```bash
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev-debian cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
rtk docker compose -p fwdeck -f docker-compose.yml run --rm -v /Users/daniz/.cargo/registry:/root/.cargo/registry dev-el9 cargo test --offline --locked --features dbus --test real_firewalld -- --ignored --test-threads=1
```

Expected: all 14 ignored integration scenarios pass serially in each
disposable container. Never run them against the host firewall.

- [ ] **Step 6: Commit Task 6.**

```bash
rtk git add src/domain/mock.rs src/application/engine.rs tests/backend.rs scripts/check-critical-coverage.sh site/docs/index.html
rtk git commit -m "test(refresh): prove staged hydration under load"
```

## Task 7: Whole-range review and protected publication

**Files:** None unless review proves a genuine defect.

- [ ] **Step 1: Audit the exact branch range.**

```bash
rtk git diff --check develop...HEAD
rtk git status --short --branch
rtk git diff --cached --name-status
rtk git ls-files --others --exclude-standard
```

Confirm no coverage output, container target, `.agents`, `.forge`, `.idea`, or
`skills-lock.json` is tracked or staged.

- [ ] **Step 2: Request one fresh whole-range safety review.**

The review must verify single backend ownership, cancellation during both
stages, rollback priority, latest-value bounded selection, no partial
`FirewallSnapshot`, exact degradation, UI lifecycle identity, and proof that
ordinary mutations still preempt staged refreshes.

- [ ] **Step 3: Push and open the protected PR.**

```bash
rtk git push -u origin feat/phase5c3-staged-refresh
rtk gh pr create --base develop --head feat/phase5c3-staged-refresh --title "perf(refresh): stage prioritized firewall details" --body "Publish zone overviews before heavy service and policy hydration while preserving one authoritative snapshot, mutation preemption, and rollback priority. Detail work uses latest-value selected-zone priority with bounded batches. Full local, performance, coverage, MSRV, and three-distribution real-firewalld validation is included."
```

- [ ] **Step 4: Wait for required checks and merge through the PR.**

Do not bypass the solo-safe ruleset or merge with pending/failing checks. After
merge, verify the exact merge commit on `origin/develop`, wait for post-merge
CI, CodeQL, and release-canary success, then fast-forward local `develop`.
