//! Pure domain types for firewalld state. No I/O, no async, no UI dependencies.

pub mod address;
pub mod capability;
pub mod dependency;
pub mod direct_migration;
pub mod explain;
pub mod ids;
#[cfg(test)]
pub mod mock;
pub mod observation;
pub mod operation;
pub mod policy;
pub mod policy_set;
pub mod port;
pub mod proposal;
pub mod restore;
pub mod rich_rule;
pub mod snapshot;
pub mod zone;

pub use address::{AddressFamily, IpSetEntry, SourceAddress};
pub use capability::{FeatureSupport, FirewalldFeature};
pub use dependency::{PolicyDependency, PolicyDependencyGraph, PolicyDependencyResource};
pub use direct_migration::{
    DirectChain, DirectMigrationError, DirectPolicyMigration, DirectRuleTranslation,
    translate_direct_rule,
};
pub use ids::{
    IcmpType, InterfaceName, IpProtocol, IpSetName, PolicyName, PolicySetName, ServiceName,
    ValidationError, ZoneName,
};
pub use observation::{
    ChainCounter, LogAction, LogEntry, RefreshObservation, RefreshSection,
    RefreshSectionObservation,
};
pub use operation::{FirewallOperation, OperationError};
pub use policy::{PolicyDetails, PolicyTarget};
pub use policy_set::{PolicySetDetails, PolicySetScope, PolicySetState};
pub use port::{ForwardPort, PortNumber, PortRange, PortSelector, PortSpec, Protocol};
pub use proposal::{DeniedFlow, ProposalError};
pub use rich_rule::RichRule;
pub use snapshot::{
    ConfigurationTarget, DegradedSection, FirewallSnapshot, FirewallStatus, IpSetInfo, LogDenied,
    NetfilterBackend, Scoped, ServiceDefinition, SnapshotSection,
};
pub use zone::{ActiveZone, ZoneDetails, ZoneTarget};
