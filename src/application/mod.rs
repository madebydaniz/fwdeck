//! Application layer: the backend port (trait + error contract) and the engine
//! task that owns the backend and feeds the UI through bounded channels.

pub mod api;
pub mod engine;
pub mod ports;
mod refresh_scheduler;

pub use api::{
    EngineEvent, EngineHandle, EngineRequest, ManualRefreshRequest, MutationPlan, MutationRequest,
    OperationResult, RefreshCancellationReason, RefreshId, RefreshScheduleObservation,
    RefreshTrigger, RollbackRegistration, RollbackRequest,
};
pub use ports::{
    FirewallBackend, FirewallError, OperationOutcome, RollbackGuard, RollbackGuardError,
    RollbackGuardId, StepReport,
};
