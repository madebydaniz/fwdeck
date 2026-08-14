use crate::application::{RefreshOverview, RefreshPriority};
use crate::domain::{ConfigurationTarget, PolicyName, ServiceName};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DetailWork {
    Service(ServiceName),
    Policy {
        target: ConfigurationTarget,
        name: PolicyName,
    },
}

impl DetailWork {
    pub(super) fn stable_key(&self) -> (&str, u8, u8) {
        match self {
            Self::Service(name) => (name.as_str(), 0, 0),
            Self::Policy { target, name } => (name.as_str(), 1, target_order(*target)),
        }
    }

    fn priority_key(
        &self,
        overview: &RefreshOverview,
        priority: &RefreshPriority,
    ) -> (u8, (&str, u8, u8)) {
        let class = match self {
            Self::Service(name) if preferred_zone_has_service(overview, priority, name) => 0,
            Self::Service(name) if priority.service.as_ref() == Some(name) => 1,
            Self::Policy { name, .. } if priority.policy.as_ref() == Some(name) => 1,
            Self::Service(_) | Self::Policy { .. } => 2,
        };
        (class, self.stable_key())
    }
}

pub(super) struct DetailQueue {
    pending: Vec<DetailWork>,
}

impl DetailQueue {
    pub(super) fn new(mut pending: Vec<DetailWork>) -> Self {
        pending.sort_by(|left, right| left.stable_key().cmp(&right.stable_key()));
        pending.dedup();
        Self { pending }
    }

    pub(super) fn take_batch(
        &mut self,
        limit: usize,
        overview: &RefreshOverview,
        priority: &RefreshPriority,
    ) -> Vec<DetailWork> {
        self.pending.sort_by(|left, right| {
            left.priority_key(overview, priority)
                .cmp(&right.priority_key(overview, priority))
        });
        let count = limit.min(self.pending.len());
        self.pending.drain(..count).collect()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
fn order_pending(
    pending: Vec<DetailWork>,
    overview: &RefreshOverview,
    priority: &RefreshPriority,
) -> Vec<DetailWork> {
    let mut queue = DetailQueue::new(pending);
    queue.take_batch(usize::MAX, overview, priority)
}

fn preferred_zone_has_service(
    overview: &RefreshOverview,
    priority: &RefreshPriority,
    service: &ServiceName,
) -> bool {
    priority.zone.as_ref().is_some_and(|zone| {
        overview
            .runtime
            .get(zone)
            .into_iter()
            .chain(overview.permanent.get(zone))
            .any(|details| details.services.contains(service))
    })
}

const fn target_order(target: ConfigurationTarget) -> u8 {
    match target {
        ConfigurationTarget::Runtime => 0,
        ConfigurationTarget::Permanent => 1,
        ConfigurationTarget::RuntimeAndPermanent => 2,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::collections::BTreeMap;

    use crate::application::{RefreshOverview, RefreshPriority};
    use crate::domain::{
        ConfigurationTarget, FirewallStatus, LogDenied, NetfilterBackend, PolicyName, Scoped,
        ServiceName, ZoneDetails, ZoneName,
    };

    use super::{DetailQueue, DetailWork, order_pending};

    fn service(name: &str) -> ServiceName {
        ServiceName::parse(name).unwrap()
    }

    fn policy(name: &str) -> PolicyName {
        PolicyName::parse(name).unwrap()
    }

    fn fixture_overview() -> RefreshOverview {
        let work = ZoneName::parse("work").unwrap();
        let mut work_details = ZoneDetails::empty(work.clone());
        work_details.services.push(service("ssh"));
        RefreshOverview {
            status: FirewallStatus {
                daemon_running: true,
                version: None,
                backend: NetfilterBackend::Unknown,
                log_denied: LogDenied::Off,
                panic_mode: false,
            },
            default_zone: work.clone(),
            active: BTreeMap::new(),
            runtime: BTreeMap::from([(work, work_details)]),
            permanent: BTreeMap::new(),
            available_services: Vec::new(),
            policy_names: Scoped::default(),
            degraded: Vec::new(),
        }
    }

    fn fixture_work() -> Vec<DetailWork> {
        [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "https",
            "ssh",
        ]
        .into_iter()
        .map(|name| DetailWork::Service(service(name)))
        .chain([
            DetailWork::Policy {
                target: ConfigurationTarget::Runtime,
                name: policy("allow-work"),
            },
            DetailWork::Policy {
                target: ConfigurationTarget::Permanent,
                name: policy("aardvark-policy"),
            },
            DetailWork::Policy {
                target: ConfigurationTarget::Runtime,
                name: policy("zulu-policy"),
            },
        ])
        .collect()
    }

    #[test]
    fn preferred_zone_services_then_selected_policy_then_stable_background() {
        let overview = fixture_overview();
        let priority = RefreshPriority {
            zone: Some(ZoneName::parse("work").unwrap()),
            service: None,
            policy: Some(policy("allow-work")),
        };

        let ordered = order_pending(fixture_work(), &overview, &priority);

        assert!(matches!(&ordered[0], DetailWork::Service(name) if name.as_str() == "ssh"));
        assert!(
            matches!(&ordered[1], DetailWork::Policy { name, .. } if name.as_str() == "allow-work")
        );
        assert!(matches!(
            &ordered[2],
            DetailWork::Policy {
                target: ConfigurationTarget::Permanent,
                name,
            } if name.as_str() == "aardvark-policy"
        ));
        assert!(matches!(
            ordered.last(),
            Some(DetailWork::Policy {
                target: ConfigurationTarget::Runtime,
                name,
            }) if name.as_str() == "zulu-policy"
        ));
        assert!(
            ordered[2..]
                .windows(2)
                .all(|pair| pair[0].stable_key() <= pair[1].stable_key())
        );
    }

    #[test]
    fn a_new_hint_reorders_only_work_not_already_taken() {
        let overview = fixture_overview();
        let mut queue = DetailQueue::new(fixture_work());
        let first = queue.take_batch(8, &overview, &RefreshPriority::default());
        let updated = RefreshPriority {
            zone: None,
            service: Some(service("https")),
            policy: None,
        };

        let second = queue.take_batch(8, &overview, &updated);

        assert!(first.iter().all(|work| !second.contains(work)));
        assert!(matches!(&second[0], DetailWork::Service(name) if name.as_str() == "https"));
    }

    #[test]
    fn queue_deduplicates_work_without_collapsing_policy_targets() {
        let runtime = DetailWork::Policy {
            target: ConfigurationTarget::Runtime,
            name: policy("allow-work"),
        };
        let permanent = DetailWork::Policy {
            target: ConfigurationTarget::Permanent,
            name: policy("allow-work"),
        };
        let mut queue = DetailQueue::new(vec![runtime.clone(), runtime.clone(), permanent.clone()]);

        let batch = queue.take_batch(8, &fixture_overview(), &RefreshPriority::default());

        assert_eq!(batch, vec![runtime, permanent]);
        assert!(queue.is_empty());
    }
}
