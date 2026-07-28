//! Pure domain types for firewalld state. No I/O, no async, no UI dependencies.

pub mod address;
pub mod explain;
pub mod ids;
#[cfg(test)]
pub mod mock;
pub mod observation;
pub mod operation;
pub mod policy;
pub mod port;
pub mod proposal;
pub mod restore;
pub mod rich_rule;
pub mod snapshot;
pub mod zone;

pub use address::{AddressFamily, IpSetEntry, SourceAddress};
pub use ids::{
    IcmpType, InterfaceName, IpProtocol, IpSetName, PolicyName, ServiceName, ValidationError,
    ZoneName,
};
pub use observation::{ChainCounter, LogAction, LogEntry};
pub use operation::{FirewallOperation, OperationError};
pub use policy::{PolicyDetails, PolicyTarget};
pub use port::{ForwardPort, PortNumber, PortRange, PortSelector, PortSpec, Protocol};
pub use proposal::{DeniedFlow, ProposalError};
pub use rich_rule::RichRule;
pub use snapshot::{
    ConfigurationTarget, FirewallSnapshot, FirewallStatus, IpSetInfo, LogDenied, NetfilterBackend,
    ServiceDefinition,
};
pub use zone::{ActiveZone, ZoneDetails, ZoneTarget};
