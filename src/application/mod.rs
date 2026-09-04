//! Application layer: the backend port (trait + error contract) and the engine
//! task that owns the backend and feeds the UI through bounded channels.

pub mod api;
pub mod engine;
mod observation;
pub mod ports;
mod refresh_scheduler;
mod traffic_test;

pub use api::{
    EngineEvent, EngineHandle, EngineRequest, ManualRefreshRequest, MutationPlan, MutationRequest,
    OperationResult, PlanId, RefreshCancellationReason, RefreshId, RefreshOverview,
    RefreshPriority, RefreshPriorityPublisher, RefreshPrioritySource, RefreshScheduleObservation,
    RefreshTrigger, RollbackRegistration, RollbackRequest, refresh_priority_channel,
};
pub use observation::{ObservedSnapshot, SnapshotGeneration, SnapshotIdentity};
pub use ports::{
    FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardError,
    RollbackGuardId, StepReport,
};
pub use traffic_test::{
    TRAFFIC_TEST_CANCELLATION_INTERVAL, TRAFFIC_TEST_EVALUATION_DEADLINE,
    TRAFFIC_TEST_EVENT_CAPACITY, TRAFFIC_TEST_PENDING_CONTEXT_CAPACITY,
    TRAFFIC_TEST_REQUEST_CAPACITY, TRAFFIC_TEST_SHUTDOWN_DEADLINE, TrafficScenarioEvaluator,
    TrafficTestCancellationReason, TrafficTestCoordinator, TrafficTestEvaluationRequest,
    TrafficTestEvent, TrafficTestFailureReason, TrafficTestRequestError, TrafficTestShutdownError,
    TrafficTestSubmissionError,
};
