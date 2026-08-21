//! Firewalld service definitions and deterministic include resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{AddressFamily, IpProtocol, PortSpec, ServiceName, SourceAddress, ValidationError};

/// Maximum supported nesting below a root service.
pub const MAX_SERVICE_INCLUDE_DEPTH: usize = 16;

/// A validated legacy service module name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct ServiceModuleName(String);

impl ServiceModuleName {
    /// Validates a module as one safe firewalld token.
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(ValidationError::Empty {
                kind: "service module name",
            });
        }
        if trimmed.len() > 64 {
            return Err(ValidationError::TooLong {
                kind: "service module name",
                value: raw.to_owned(),
                max: 64,
            });
        }
        if let Some(ch) = trimmed
            .chars()
            .find(|ch| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-' | '.'))
        {
            return Err(ValidationError::InvalidChar {
                kind: "service module name",
                value: raw.to_owned(),
                ch,
            });
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The validated module name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ServiceModuleName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for ServiceModuleName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

/// One family-specific service destination.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ServiceDestination {
    /// Address family declared by firewalld.
    pub family: AddressFamily,
    /// Validated IP address or CIDR.
    pub address: SourceAddress,
}

/// Complete static definition returned by `--info-service`.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ServiceDefinition {
    /// Destination ports opened by the service.
    #[serde(default)]
    pub ports: Vec<PortSpec>,
    /// Raw IP protocols beyond port-based rules.
    #[serde(default)]
    pub protocols: Vec<IpProtocol>,
    /// Source ports constrained by the service.
    #[serde(default)]
    pub source_ports: Vec<PortSpec>,
    /// Family-specific destination restrictions.
    #[serde(default)]
    pub destinations: Vec<ServiceDestination>,
    /// Other service definitions included by this service.
    #[serde(default)]
    pub includes: Vec<ServiceName>,
    /// Connection-tracking helpers requested by the service.
    #[serde(default)]
    pub helpers: Vec<ServiceName>,
    /// Deprecated kernel modules retained as evidence.
    #[serde(default)]
    pub modules: Vec<ServiceModuleName>,
}

/// A deterministic, typed failure while expanding includes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceResolutionFailure {
    /// An included service definition was absent.
    MissingInclude {
        /// Definition that referenced the missing service.
        referenced_by: ServiceName,
        /// Missing service identity.
        service: ServiceName,
    },
    /// Include graph revisited an active path.
    Cycle {
        /// Exact path including the repeated service.
        path: Vec<ServiceName>,
    },
    /// Include nesting exceeded the documented finite limit.
    DepthLimit {
        /// Configured maximum depth.
        limit: usize,
        /// Exact path that exceeded the limit.
        path: Vec<ServiceName>,
    },
}

impl fmt::Display for ServiceResolutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingInclude {
                referenced_by,
                service,
            } => write!(
                formatter,
                "service `{referenced_by}` includes missing definition `{service}`"
            ),
            Self::Cycle { path } => {
                write!(formatter, "service include cycle: {}", format_path(path))
            }
            Self::DepthLimit { limit, path } => write!(
                formatter,
                "service include depth exceeds {limit}: {}",
                format_path(path)
            ),
        }
    }
}

/// Expanded evidence for one root service.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ServiceResolution {
    /// Definitions visited in deterministic preorder.
    pub services: Vec<ServiceName>,
    /// Unique effective fields from the visited definitions.
    pub effective: ServiceDefinition,
    /// Typed resolution failures. Any entry makes the result incomplete.
    pub failures: Vec<ServiceResolutionFailure>,
}

/// Resolves one service include graph in stable declaration order.
#[must_use]
pub fn resolve_service_includes(
    root: &ServiceName,
    definitions: &BTreeMap<ServiceName, ServiceDefinition>,
) -> ServiceResolution {
    let mut result = ServiceResolution::default();
    let mut visited = BTreeSet::new();
    let mut active = Vec::new();
    visit_service(
        root,
        root,
        0,
        definitions,
        &mut visited,
        &mut active,
        &mut result,
    );
    result
}

fn visit_service(
    name: &ServiceName,
    referenced_by: &ServiceName,
    depth: usize,
    definitions: &BTreeMap<ServiceName, ServiceDefinition>,
    visited: &mut BTreeSet<ServiceName>,
    active: &mut Vec<ServiceName>,
    result: &mut ServiceResolution,
) {
    if let Some(index) = active.iter().position(|entry| entry == name) {
        let mut path = active[index..].to_vec();
        path.push(name.clone());
        result
            .failures
            .push(ServiceResolutionFailure::Cycle { path });
        return;
    }
    if depth > MAX_SERVICE_INCLUDE_DEPTH {
        let mut path = active.clone();
        path.push(name.clone());
        result.failures.push(ServiceResolutionFailure::DepthLimit {
            limit: MAX_SERVICE_INCLUDE_DEPTH,
            path,
        });
        return;
    }
    if visited.contains(name) {
        return;
    }
    let Some(definition) = definitions.get(name) else {
        result
            .failures
            .push(ServiceResolutionFailure::MissingInclude {
                referenced_by: referenced_by.clone(),
                service: name.clone(),
            });
        return;
    };

    visited.insert(name.clone());
    active.push(name.clone());
    result.services.push(name.clone());
    merge_definition(&mut result.effective, definition);
    for included in &definition.includes {
        visit_service(
            included,
            name,
            depth + 1,
            definitions,
            visited,
            active,
            result,
        );
    }
    active.pop();
}

fn merge_definition(target: &mut ServiceDefinition, source: &ServiceDefinition) {
    extend_unique(&mut target.ports, &source.ports);
    extend_unique(&mut target.protocols, &source.protocols);
    extend_unique(&mut target.source_ports, &source.source_ports);
    extend_unique(&mut target.destinations, &source.destinations);
    extend_unique(&mut target.helpers, &source.helpers);
    extend_unique(&mut target.modules, &source.modules);
}

fn extend_unique<T: Clone + PartialEq>(target: &mut Vec<T>, source: &[T]) {
    for item in source {
        if !target.contains(item) {
            target.push(item.clone());
        }
    }
}

fn format_path(path: &[ServiceName]) -> String {
    path.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" -> ")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::domain::{PortSpec, ServiceName};

    fn name(raw: &str) -> ServiceName {
        ServiceName::parse(raw).unwrap()
    }

    fn definition(includes: &[&str], port: &str) -> ServiceDefinition {
        ServiceDefinition {
            ports: vec![port.parse::<PortSpec>().unwrap()],
            includes: includes.iter().map(|raw| name(raw)).collect(),
            ..ServiceDefinition::default()
        }
    }

    #[test]
    fn include_chain_resolves_in_deterministic_preorder() {
        let definitions = BTreeMap::from([
            (name("root"), definition(&["middle"], "1000/tcp")),
            (name("middle"), definition(&["leaf"], "2000/tcp")),
            (name("leaf"), definition(&[], "3000/tcp")),
        ]);

        let resolved = resolve_service_includes(&name("root"), &definitions);

        assert_eq!(
            resolved.services,
            vec![name("root"), name("middle"), name("leaf")]
        );
        assert_eq!(resolved.effective.ports.len(), 3);
        assert!(resolved.failures.is_empty());
    }

    #[test]
    fn diamond_dependency_is_visited_once_in_stable_order() {
        let definitions = BTreeMap::from([
            (name("root"), definition(&["left", "right"], "1000/tcp")),
            (name("left"), definition(&["shared"], "2000/tcp")),
            (name("right"), definition(&["shared"], "3000/tcp")),
            (name("shared"), definition(&[], "4000/tcp")),
        ]);

        let resolved = resolve_service_includes(&name("root"), &definitions);

        assert_eq!(
            resolved.services,
            vec![name("root"), name("left"), name("shared"), name("right")]
        );
        assert_eq!(resolved.effective.ports.len(), 4);
        assert!(resolved.failures.is_empty());
    }

    #[test]
    fn missing_include_keeps_typed_parent_and_child_identity() {
        let definitions = BTreeMap::from([(name("root"), definition(&["missing"], "1000/tcp"))]);

        let resolved = resolve_service_includes(&name("root"), &definitions);

        assert!(matches!(
            resolved.failures.as_slice(),
            [ServiceResolutionFailure::MissingInclude {
                referenced_by,
                service,
            }] if referenced_by == &name("root") && service == &name("missing")
        ));
    }

    #[test]
    fn include_cycle_reports_the_exact_path() {
        let definitions = BTreeMap::from([
            (name("alpha"), definition(&["bravo"], "1000/tcp")),
            (name("bravo"), definition(&["alpha"], "2000/tcp")),
        ]);

        let resolved = resolve_service_includes(&name("alpha"), &definitions);

        assert!(matches!(
            resolved.failures.as_slice(),
            [ServiceResolutionFailure::Cycle { path }]
                if path == &vec![name("alpha"), name("bravo"), name("alpha")]
        ));
    }

    #[test]
    fn include_depth_limit_fails_closed_with_the_path() {
        let mut definitions = BTreeMap::new();
        for index in 0..=MAX_SERVICE_INCLUDE_DEPTH {
            let current = name(&format!("service-{index}"));
            let next = format!("service-{}", index + 1);
            definitions.insert(current, definition(&[&next], "1000/tcp"));
        }
        definitions.insert(
            name(&format!("service-{}", MAX_SERVICE_INCLUDE_DEPTH + 1)),
            definition(&[], "2000/tcp"),
        );

        let resolved = resolve_service_includes(&name("service-0"), &definitions);

        assert!(matches!(
            resolved.failures.as_slice(),
            [ServiceResolutionFailure::DepthLimit { limit, path }]
                if *limit == MAX_SERVICE_INCLUDE_DEPTH
                    && path.first() == Some(&name("service-0"))
                    && path.last() == Some(&name(&format!(
                        "service-{}",
                        MAX_SERVICE_INCLUDE_DEPTH + 1
                    )))
        ));
    }
}
