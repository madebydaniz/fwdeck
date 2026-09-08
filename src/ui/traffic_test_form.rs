//! Pure, bounded local scenario drafts. No filesystem or firewall access.

use crate::domain::{
    IcmpType, InterfaceName, IpProtocol, MAX_SCENARIOS_PER_SUITE, MAX_TRAFFIC_NAME_BYTES,
    MAX_TRAFFIC_NOTE_BYTES, PortSelector, SourceAddress, TrafficConnectionState,
    TrafficDestination, TrafficDirection, TrafficExpectation, TrafficScenario, TrafficScenarioId,
    TrafficSeverity, TrafficSuite, TrafficTransport, ZoneName,
};
use std::sync::Arc;
pub(super) mod render;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditAction {
    New(Template),
    Edit,
    Delete,
    Toggle,
    Move(i32),
    Cycle(i32),
    Input(char),
    Backspace,
    Review,
    Save,
    Cancel,
    Discard,
    Keep,
    Scroll(i32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Draft,
    Review,
    Pending,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditKind {
    Form,
    Delete,
    Toggle,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Editor {
    pub base: Arc<TrafficSuite>,
    pub creating_suite: bool,
    pub draft: Draft,
    pub stage: Stage,
    pub kind: EditKind,
    pub candidate: Option<Arc<TrafficSuite>>,
    pub dirty: bool,
    pub accepted: bool,
    pub error: Option<String>,
    pub discard: Option<Box<super::action::UiAction>>,
    pub scroll: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Template {
    Ssh,
    AllowService,
    BlockAccess,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Name,
    Source,
    Ingress,
    IngressValue,
    Transport,
    DestinationPort,
    SourcePort,
    Icmp,
    Protocol,
    Expectation,
    Severity,
    Enabled,
    Note,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Draft {
    pub name: String,
    pub source: String,
    pub ingress: usize,
    pub ingress_value: String,
    pub transport: usize,
    pub destination_port: String,
    pub source_port: String,
    pub icmp: String,
    pub protocol: String,
    pub expectation: TrafficExpectation,
    pub severity: TrafficSeverity,
    pub enabled: bool,
    pub note: String,
    pub original: Option<TrafficScenario>,
    pub focus: usize,
}

impl Draft {
    pub fn edit(scenario: &TrafficScenario) -> Self {
        let mut draft = Self::template(Template::Custom);
        draft.name.clone_from(&scenario.name);
        draft.source = scenario.source.to_string();
        if let Some(zone) = &scenario.ingress_zone {
            draft.ingress = 1;
            draft.ingress_value = zone.to_string();
        }
        if let Some(interface) = &scenario.ingress_interface {
            draft.ingress = 2;
            draft.ingress_value = interface.to_string();
        }
        draft.transport = match &scenario.transport {
            TrafficTransport::Tcp => 0,
            TrafficTransport::Udp => 1,
            TrafficTransport::Icmp { icmp_type } => {
                draft.icmp = icmp_type.to_string();
                2
            }
            TrafficTransport::RawProtocol { protocol } => {
                draft.protocol = protocol.to_string();
                3
            }
        };
        draft.destination_port = scenario
            .destination_port
            .map_or_else(String::new, |port| port.to_string());
        draft.source_port = scenario
            .source_port
            .map_or_else(String::new, |port| port.to_string());
        draft.expectation = scenario.expectation;
        draft.severity = scenario.severity;
        draft.enabled = scenario.enabled;
        draft.note = scenario.note.clone().unwrap_or_default();
        draft.original = Some(scenario.clone());
        draft
    }
    #[must_use]
    pub fn metadata_only(&self) -> bool {
        self.original.as_ref().is_some_and(|scenario| {
            scenario.direction != TrafficDirection::ToHost
                || scenario.connection_state != TrafficConnectionState::New
                || scenario.destination != TrafficDestination::LocalHost
                || scenario.egress_interface.is_some()
                || scenario.egress_zone.is_some()
        })
    }
    #[must_use]
    pub fn fields(&self) -> Vec<Field> {
        let mut fields = vec![Field::Name];
        if !self.metadata_only() {
            fields.extend([Field::Source, Field::Ingress]);
            if self.ingress != 0 {
                fields.push(Field::IngressValue);
            }
            fields.push(Field::Transport);
            match self.transport {
                0 | 1 => fields.extend([Field::DestinationPort, Field::SourcePort]),
                2 => fields.push(Field::Icmp),
                _ => fields.push(Field::Protocol),
            }
            fields.push(Field::Expectation);
        }
        fields.extend([Field::Severity, Field::Enabled, Field::Note]);
        fields
    }
    fn buffer(&mut self) -> Option<(&mut String, usize)> {
        Some(match self.fields().get(self.focus)? {
            Field::Name => (&mut self.name, MAX_TRAFFIC_NAME_BYTES),
            Field::Note => (&mut self.note, MAX_TRAFFIC_NOTE_BYTES),
            Field::Source => (&mut self.source, 128),
            Field::IngressValue => (&mut self.ingress_value, 128),
            Field::DestinationPort => (&mut self.destination_port, 128),
            Field::SourcePort => (&mut self.source_port, 128),
            Field::Icmp => (&mut self.icmp, 128),
            Field::Protocol => (&mut self.protocol, 128),
            _ => return None,
        })
    }
    pub fn input(&mut self, character: char) {
        if let Some((buffer, limit)) = self.buffer()
            && !character.is_control()
            && buffer.len() + character.len_utf8() <= limit
        {
            buffer.push(character);
        }
    }
    pub fn backspace(&mut self) {
        if let Some((buffer, _)) = self.buffer() {
            buffer.pop();
        }
    }
    pub fn cycle(&mut self, delta: i32) {
        match self.fields().get(self.focus) {
            Some(Field::Ingress) => {
                self.ingress = cycle(self.ingress, delta, 3);
                self.ingress_value.clear();
            }
            Some(Field::Transport) => {
                self.transport = cycle(self.transport, delta, 4);
                if self.transport > 1 {
                    self.destination_port.clear();
                    self.source_port.clear();
                }
                if self.transport != 2 {
                    self.icmp.clear();
                }
                if self.transport != 3 {
                    self.protocol.clear();
                }
            }
            Some(Field::Expectation) => {
                self.expectation = if self.expectation == TrafficExpectation::Allow {
                    TrafficExpectation::Block
                } else {
                    TrafficExpectation::Allow
                }
            }
            Some(Field::Severity) => {
                self.severity = if self.severity == TrafficSeverity::Critical {
                    TrafficSeverity::Advisory
                } else {
                    TrafficSeverity::Critical
                }
            }
            Some(Field::Enabled) => self.enabled = !self.enabled,
            _ => {}
        }
    }
    #[must_use]
    pub fn template(template: Template) -> Self {
        let (name, port, expectation, severity) = match template {
            Template::Ssh => (
                "Keep SSH access",
                "22",
                TrafficExpectation::Allow,
                TrafficSeverity::Critical,
            ),
            Template::AllowService => (
                "Allow service exposure",
                "",
                TrafficExpectation::Allow,
                TrafficSeverity::Advisory,
            ),
            Template::BlockAccess => (
                "Block unwanted access",
                "",
                TrafficExpectation::Block,
                TrafficSeverity::Advisory,
            ),
            Template::Custom => ("", "", TrafficExpectation::Allow, TrafficSeverity::Advisory),
        };
        Self {
            name: name.into(),
            source: String::new(),
            ingress: 0,
            ingress_value: String::new(),
            transport: 0,
            destination_port: port.into(),
            source_port: String::new(),
            icmp: String::new(),
            protocol: String::new(),
            expectation,
            severity,
            enabled: true,
            note: String::new(),
            original: None,
            focus: 0,
        }
    }

    pub fn scenario(&self, id: TrafficScenarioId) -> Result<TrafficScenario, String> {
        if self.metadata_only()
            && let Some(original) = &self.original
        {
            let mut scenario = original.clone();
            scenario.name.clone_from(&self.name);
            scenario.enabled = self.enabled;
            scenario.severity = self.severity;
            scenario.note = (!self.note.is_empty()).then(|| self.note.clone());
            scenario.validate().map_err(|error| error.to_string())?;
            return Ok(scenario);
        }
        let source = SourceAddress::parse(&self.source)
            .map_err(|error| format!("Source IP/CIDR: {error}"))?;
        if source.family().is_none() {
            return Err("Source must be an explicit IP address or CIDR".into());
        }
        let scenario = TrafficScenario {
            id,
            name: self.name.clone(),
            enabled: self.enabled,
            direction: TrafficDirection::ToHost,
            source,
            ingress_interface: if self.ingress == 2 {
                Some(
                    InterfaceName::parse(&self.ingress_value)
                        .map_err(|error| format!("Ingress interface: {error}"))?,
                )
            } else {
                None
            },
            ingress_zone: if self.ingress == 1 {
                Some(
                    ZoneName::parse(&self.ingress_value)
                        .map_err(|error| format!("Ingress zone: {error}"))?,
                )
            } else {
                None
            },
            destination: TrafficDestination::LocalHost,
            egress_interface: None,
            egress_zone: None,
            transport: match self.transport {
                0 => TrafficTransport::Tcp,
                1 => TrafficTransport::Udp,
                2 => TrafficTransport::Icmp {
                    icmp_type: IcmpType::parse(&self.icmp)
                        .map_err(|error| format!("ICMP type: {error}"))?,
                },
                3 => TrafficTransport::RawProtocol {
                    protocol: IpProtocol::parse(&self.protocol)
                        .map_err(|error| format!("Protocol: {error}"))?,
                },
                _ => return Err("Invalid transport".into()),
            },
            destination_port: if self.destination_port.is_empty() {
                None
            } else {
                Some(
                    self.destination_port
                        .parse::<PortSelector>()
                        .map_err(|error| format!("Destination port: {error}"))?,
                )
            },
            source_port: if self.source_port.is_empty() {
                None
            } else {
                Some(
                    self.source_port
                        .parse::<PortSelector>()
                        .map_err(|error| format!("Source port: {error}"))?,
                )
            },
            connection_state: TrafficConnectionState::New,
            expectation: self.expectation,
            severity: self.severity,
            required_safety_gate: self
                .original
                .as_ref()
                .is_some_and(|original| original.required_safety_gate),
            note: (!self.note.is_empty()).then(|| self.note.clone()),
        };
        scenario.validate().map_err(|error| error.to_string())?;
        Ok(scenario)
    }
}

pub fn prepare(base: &TrafficSuite, draft: &Draft) -> Result<TrafficSuite, String> {
    let mut candidate = base.clone();
    if let Some(original) = &draft.original {
        let slot = candidate
            .scenarios
            .iter_mut()
            .find(|scenario| scenario.id == original.id)
            .ok_or("Scenario no longer exists; reload required")?;
        *slot = draft.scenario(original.id.clone())?;
    } else {
        if candidate.scenarios.len() >= MAX_SCENARIOS_PER_SUITE {
            return Err("Suite already contains 1000 scenarios".into());
        }
        let id = (1..=MAX_SCENARIOS_PER_SUITE + 1)
            .map(|index| format!("scenario-{index}"))
            .find(|id| {
                candidate
                    .scenarios
                    .iter()
                    .all(|scenario| scenario.id.as_str() != id)
            })
            .ok_or("No scenario ID available")?;
        candidate.scenarios.push(
            draft.scenario(TrafficScenarioId::parse(&id).map_err(|error| error.to_string())?)?,
        );
    }
    candidate.validate().map_err(|error| error.to_string())?;
    Ok(candidate)
}

fn cycle(value: usize, delta: i32, count: usize) -> usize {
    if delta < 0 {
        (value + count - 1) % count
    } else {
        (value + 1) % count
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests;
