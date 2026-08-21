//! Native firewalld D-Bus backend (feature `dbus`). A second implementation of
//! the same `FirewallBackend` port — proof that the trait boundary holds: the
//! domain, application, and UI layers are untouched.
//!
//! Method names are pinned to firewalld's D-Bus API, verified by introspecting
//! a live daemon (`busctl introspect org.fedoraproject.FirewallD1 …`).
//!
//! Coverage: `probe()` and `snapshot()` (runtime + permanent core zone
//! attributes) and the common zone mutations. IP sets, policies, direct rules,
//! and permanent-only object lifecycle (create zone/service/ipset/policy) route
//! through the CLI backend for now; the D-Bus backend reports them as
//! unsupported rather than failing silently. See `CONTRIBUTING.md`.

use std::collections::{BTreeMap, HashMap};

use zbus::zvariant::OwnedValue;
use zbus::{Connection, proxy};

use crate::application::ports::{FirewallBackend, FirewallError, OperationOutcome, StepReport};
use crate::domain::{
    ConfigurationTarget, DegradedSection, FeatureSupport, FirewallOperation, FirewallSnapshot,
    FirewallStatus, FirewalldFeature, ForwardPort, IcmpType, InterfaceName, LogDenied, PortSpec,
    RichRule, RulePriority, ServiceName, SnapshotSection, SourceAddress, ZoneDetails, ZoneName,
    ZoneTarget,
};

fn incomplete_service_definitions() -> DegradedSection {
    DegradedSection::new(
        SnapshotSection::ServiceDefinitions,
        None,
        "not fetched by the D-Bus backend yet",
    )
}

/// firewalld's main interface.
#[proxy(
    interface = "org.fedoraproject.FirewallD1",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1"
)]
trait FirewallD1 {
    #[zbus(property, name = "version")]
    fn version(&self) -> zbus::Result<String>;
    #[zbus(name = "getDefaultZone")]
    fn get_default_zone(&self) -> zbus::Result<String>;
    #[zbus(name = "getLogDenied")]
    fn get_log_denied(&self) -> zbus::Result<String>;
    #[zbus(name = "queryPanicMode")]
    fn query_panic_mode(&self) -> zbus::Result<bool>;
    #[zbus(name = "listServices")]
    fn list_services(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "reload")]
    fn reload(&self) -> zbus::Result<()>;
    #[zbus(name = "runtimeToPermanent")]
    fn runtime_to_permanent(&self) -> zbus::Result<()>;
    #[zbus(name = "enablePanicMode")]
    fn enable_panic_mode(&self) -> zbus::Result<()>;
    #[zbus(name = "disablePanicMode")]
    fn disable_panic_mode(&self) -> zbus::Result<()>;
    #[zbus(name = "setDefaultZone")]
    fn set_default_zone(&self, zone: &str) -> zbus::Result<()>;
    #[zbus(name = "setLogDenied")]
    fn set_log_denied(&self, value: &str) -> zbus::Result<()>;
}

/// Runtime zone interface — every getter takes the zone name.
#[proxy(
    interface = "org.fedoraproject.FirewallD1.zone",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1"
)]
trait Zone {
    #[zbus(name = "getZones")]
    fn get_zones(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getActiveZones")]
    fn get_active_zones(&self) -> zbus::Result<HashMap<String, HashMap<String, Vec<String>>>>;
    #[zbus(name = "getServices")]
    fn get_services(&self, zone: &str) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getPorts")]
    fn get_ports(&self, zone: &str) -> zbus::Result<Vec<Vec<String>>>;
    #[zbus(name = "getForwardPorts")]
    fn get_forward_ports(&self, zone: &str) -> zbus::Result<Vec<Vec<String>>>;
    #[zbus(name = "getRichRules")]
    fn get_rich_rules(&self, zone: &str) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getInterfaces")]
    fn get_interfaces(&self, zone: &str) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getSources")]
    fn get_sources(&self, zone: &str) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getIcmpBlocks")]
    fn get_icmp_blocks(&self, zone: &str) -> zbus::Result<Vec<String>>;
    #[zbus(name = "queryMasquerade")]
    fn query_masquerade(&self, zone: &str) -> zbus::Result<bool>;
    #[zbus(name = "getZoneSettings2")]
    fn get_zone_settings2(&self, zone: &str) -> zbus::Result<HashMap<String, OwnedValue>>;

    #[zbus(name = "addService")]
    fn add_service(&self, zone: &str, service: &str, timeout: i32) -> zbus::Result<String>;
    #[zbus(name = "removeService")]
    fn remove_service(&self, zone: &str, service: &str) -> zbus::Result<String>;
    #[zbus(name = "addPort")]
    fn add_port(
        &self,
        zone: &str,
        port: &str,
        protocol: &str,
        timeout: i32,
    ) -> zbus::Result<String>;
    #[zbus(name = "removePort")]
    fn remove_port(&self, zone: &str, port: &str, protocol: &str) -> zbus::Result<String>;
    #[zbus(name = "addMasquerade")]
    fn add_masquerade(&self, zone: &str, timeout: i32) -> zbus::Result<String>;
    #[zbus(name = "removeMasquerade")]
    fn remove_masquerade(&self, zone: &str) -> zbus::Result<String>;
    #[zbus(name = "addRichRule")]
    fn add_rich_rule(&self, zone: &str, rule: &str, timeout: i32) -> zbus::Result<String>;
    #[zbus(name = "removeRichRule")]
    fn remove_rich_rule(&self, zone: &str, rule: &str) -> zbus::Result<String>;
    #[zbus(name = "addInterface")]
    fn add_interface(&self, zone: &str, interface: &str) -> zbus::Result<String>;
    #[zbus(name = "removeInterface")]
    fn remove_interface(&self, zone: &str, interface: &str) -> zbus::Result<String>;
    #[zbus(name = "addSource")]
    fn add_source(&self, zone: &str, source: &str) -> zbus::Result<String>;
    #[zbus(name = "removeSource")]
    fn remove_source(&self, zone: &str, source: &str) -> zbus::Result<String>;
    #[zbus(name = "addIcmpBlock")]
    fn add_icmp_block(&self, zone: &str, icmp: &str, timeout: i32) -> zbus::Result<String>;
    #[zbus(name = "removeIcmpBlock")]
    fn remove_icmp_block(&self, zone: &str, icmp: &str) -> zbus::Result<String>;
}

/// Permanent config interface: resolve a zone name to its config object path.
#[proxy(
    interface = "org.fedoraproject.FirewallD1.config",
    default_service = "org.fedoraproject.FirewallD1",
    default_path = "/org/fedoraproject/FirewallD1/config"
)]
trait Config {
    #[zbus(name = "getZoneNames")]
    fn get_zone_names(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getZoneByName")]
    fn get_zone_by_name(&self, name: &str) -> zbus::Result<zbus::zvariant::OwnedObjectPath>;
}

/// A permanent zone config object (path resolved via `Config::getZoneByName`).
#[proxy(
    interface = "org.fedoraproject.FirewallD1.config.zone",
    default_service = "org.fedoraproject.FirewallD1"
)]
trait ConfigZone {
    #[zbus(name = "getSettings2")]
    fn get_settings2(&self) -> zbus::Result<HashMap<String, OwnedValue>>;
    #[zbus(name = "getTarget")]
    fn get_target(&self) -> zbus::Result<String>;
    #[zbus(name = "getServices")]
    fn get_services(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getPorts")]
    fn get_ports(&self) -> zbus::Result<Vec<(String, String)>>;
    #[zbus(name = "getForwardPorts")]
    fn get_forward_ports(&self) -> zbus::Result<Vec<(String, String, String, String)>>;
    #[zbus(name = "getRichRules")]
    fn get_rich_rules(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getInterfaces")]
    fn get_interfaces(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getSources")]
    fn get_sources(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getIcmpBlocks")]
    fn get_icmp_blocks(&self) -> zbus::Result<Vec<String>>;
    #[zbus(name = "getMasquerade")]
    fn get_masquerade(&self) -> zbus::Result<bool>;
}

/// `FirewallBackend` implementation over firewalld's system-bus D-Bus API.
/// Zone getters run concurrently on the single multiplexed connection.
/// Mutations are runtime-scoped only; wider targets and unsupported
/// operations fail loudly with a pointer to the CLI backend.
pub struct DbusBackend {
    connection: Connection,
}

#[derive(Debug, Default)]
struct ObservedZoneSettings {
    target: ZoneTarget,
    ingress_priority: RulePriority,
    egress_priority: RulePriority,
    incomplete: Vec<String>,
}

fn observe_zone_settings(
    settings: &HashMap<String, OwnedValue>,
    priority_support: FeatureSupport,
) -> ObservedZoneSettings {
    let target = settings
        .get("target")
        .and_then(|value| String::try_from(value.clone()).ok())
        .and_then(|value| value.parse().ok())
        .unwrap_or(ZoneTarget::Default);
    let (ingress_priority, ingress_incomplete) = observe_priority(
        settings,
        "ingress_priority",
        "ingress-priority",
        priority_support,
    );
    let (egress_priority, egress_incomplete) = observe_priority(
        settings,
        "egress_priority",
        "egress-priority",
        priority_support,
    );
    let incomplete = ingress_incomplete
        .into_iter()
        .chain(egress_incomplete)
        .collect();
    ObservedZoneSettings {
        target,
        ingress_priority,
        egress_priority,
        incomplete,
    }
}

fn observe_priority(
    settings: &HashMap<String, OwnedValue>,
    key: &'static str,
    legacy_key: &'static str,
    support: FeatureSupport,
) -> (RulePriority, Option<String>) {
    let Some(value) = settings.get(key).or_else(|| settings.get(legacy_key)) else {
        return if support == FeatureSupport::Supported {
            (
                RulePriority::default(),
                Some(format!("D-Bus settings omitted `{key}`")),
            )
        } else {
            (RulePriority::default(), None)
        };
    };
    match i32::try_from(value.clone())
        .map_err(|_| format!("D-Bus `{key}` is not a signed integer"))
        .and_then(|raw| RulePriority::new(raw).map_err(|err| err.to_string()))
    {
        Ok(priority) => (priority, None),
        Err(reason) => (RulePriority::default(), Some(reason)),
    }
}

fn zone_priority_degradations(
    zone: &ZoneName,
    target: ConfigurationTarget,
    reasons: Vec<String>,
) -> Vec<crate::domain::DegradedSection> {
    reasons
        .into_iter()
        .map(|reason| {
            crate::domain::DegradedSection::new(
                crate::domain::SnapshotSection::Zones,
                Some(target),
                reason,
            )
            .with_object(zone.to_string())
        })
        .collect()
}

impl DbusBackend {
    /// Connects to the system bus. Fails cleanly if D-Bus or firewalld is absent.
    pub async fn connect() -> Result<Self, FirewallError> {
        let connection = Connection::system()
            .await
            .map_err(|err| FirewallError::Process(format!("D-Bus connection failed: {err}")))?;
        Ok(Self { connection })
    }

    async fn main(&self) -> Result<FirewallD1Proxy<'_>, FirewallError> {
        FirewallD1Proxy::new(&self.connection)
            .await
            .map_err(dbus_err)
    }

    async fn zone(&self) -> Result<ZoneProxy<'_>, FirewallError> {
        ZoneProxy::new(&self.connection).await.map_err(dbus_err)
    }

    /// One zone's runtime attributes. Errors propagate — a half-read zone
    /// rendered as empty would misstate live firewall policy. The getters are
    /// independent, so they run concurrently on the multiplexed connection.
    async fn runtime_zone(
        &self,
        zone: &ZoneProxy<'_>,
        name: &ZoneName,
        priority_support: FeatureSupport,
    ) -> Result<(ZoneDetails, Vec<String>), FirewallError> {
        let n = name.as_str();
        let (settings, services, ports, forwards, rich, interfaces, sources, icmp, masquerade) = tokio::join!(
            zone.get_zone_settings2(n),
            zone.get_services(n),
            zone.get_ports(n),
            zone.get_forward_ports(n),
            zone.get_rich_rules(n),
            zone.get_interfaces(n),
            zone.get_sources(n),
            zone.get_icmp_blocks(n),
            zone.query_masquerade(n),
        );
        let settings = settings.map_err(dbus_err)?;
        let observed = observe_zone_settings(&settings, priority_support);
        let mut details = ZoneDetails::empty(name.clone());
        details.target = observed.target;
        details.ingress_priority = observed.ingress_priority;
        details.egress_priority = observed.egress_priority;
        details.services = parsed(&services.map_err(dbus_err)?, ServiceName::parse);
        details.ports = ports
            .map_err(dbus_err)?
            .iter()
            .filter_map(|pair| pair_to_port(pair.first()?, pair.get(1)?))
            .collect();
        details.forward_ports = forwards
            .map_err(dbus_err)?
            .iter()
            .filter_map(|f| ForwardPort::from_parts(f.first()?, f.get(1)?, f.get(2)?, f.get(3)?))
            .collect();
        details.rich_rules = parsed(&rich.map_err(dbus_err)?, RichRule::parse);
        details.interfaces = parsed(&interfaces.map_err(dbus_err)?, InterfaceName::parse);
        details.sources = parsed(&sources.map_err(dbus_err)?, SourceAddress::parse);
        details.icmp_blocks = parsed(&icmp.map_err(dbus_err)?, IcmpType::parse);
        details.masquerade = masquerade.map_err(dbus_err)?;
        Ok((details, observed.incomplete))
    }

    /// One zone's permanent config object. Errors propagate (e.g. a polkit
    /// denial on the config interface must not masquerade as an empty config).
    async fn permanent_zone(
        &self,
        config: &ConfigProxy<'_>,
        raw: &str,
        priority_support: FeatureSupport,
    ) -> Result<Option<(ZoneName, ZoneDetails, Vec<String>)>, FirewallError> {
        // Unparseable zone names are skipped, not fatal (forward compatibility).
        let Ok(name) = ZoneName::parse(raw) else {
            return Ok(None);
        };
        let path = config.get_zone_by_name(raw).await.map_err(dbus_err)?;
        let proxy = ConfigZoneProxy::builder(&self.connection)
            .path(path)
            .map_err(dbus_err)?
            .build()
            .await
            .map_err(dbus_err)?;
        let (
            settings,
            target,
            services,
            ports,
            forwards,
            rich,
            interfaces,
            sources,
            icmp,
            masquerade,
        ) = tokio::join!(
            proxy.get_settings2(),
            proxy.get_target(),
            proxy.get_services(),
            proxy.get_ports(),
            proxy.get_forward_ports(),
            proxy.get_rich_rules(),
            proxy.get_interfaces(),
            proxy.get_sources(),
            proxy.get_icmp_blocks(),
            proxy.get_masquerade(),
        );
        let mut details = ZoneDetails::empty(name.clone());
        details.target = target
            .map_err(dbus_err)?
            .parse()
            .unwrap_or(ZoneTarget::Default);
        details.services = parsed(&services.map_err(dbus_err)?, ServiceName::parse);
        details.ports = ports
            .map_err(dbus_err)?
            .iter()
            .filter_map(|(port, proto)| pair_to_port(port, proto))
            .collect();
        details.forward_ports = forwards
            .map_err(dbus_err)?
            .iter()
            .filter_map(|(p, proto, tp, ta)| ForwardPort::from_parts(p, proto, tp, ta))
            .collect();
        details.rich_rules = parsed(&rich.map_err(dbus_err)?, RichRule::parse);
        details.interfaces = parsed(&interfaces.map_err(dbus_err)?, InterfaceName::parse);
        details.sources = parsed(&sources.map_err(dbus_err)?, SourceAddress::parse);
        details.icmp_blocks = parsed(&icmp.map_err(dbus_err)?, IcmpType::parse);
        details.masquerade = masquerade.map_err(dbus_err)?;
        let incomplete = match settings {
            Ok(settings) => {
                let observed = observe_zone_settings(&settings, priority_support);
                details.ingress_priority = observed.ingress_priority;
                details.egress_priority = observed.egress_priority;
                observed.incomplete
            }
            Err(err) if priority_support == FeatureSupport::Supported => vec![format!(
                "D-Bus getSettings2 failed while reading zone priorities: {}",
                dbus_err(err)
            )],
            Err(_) => Vec::new(),
        };
        Ok(Some((name, details, incomplete)))
    }

    async fn permanent_zones(
        &self,
        priority_support: FeatureSupport,
    ) -> Result<
        (
            BTreeMap<ZoneName, ZoneDetails>,
            Vec<crate::domain::DegradedSection>,
        ),
        FirewallError,
    > {
        let config = ConfigProxy::new(&self.connection).await.map_err(dbus_err)?;
        let names = config.get_zone_names().await.map_err(dbus_err)?;
        let fetched = futures_util::future::join_all(
            names
                .iter()
                .map(|raw| self.permanent_zone(&config, raw, priority_support)),
        )
        .await;
        let mut zones = BTreeMap::new();
        let mut degraded = Vec::new();
        for result in fetched {
            if let Some((name, details, incomplete)) = result? {
                degraded.extend(zone_priority_degradations(
                    &name,
                    ConfigurationTarget::Permanent,
                    incomplete,
                ));
                zones.insert(name, details);
            }
        }
        Ok((zones, degraded))
    }
}

impl FirewallBackend for DbusBackend {
    async fn probe(&self) -> Result<FirewallStatus, FirewallError> {
        let main = self.main().await?;
        // Only a missing bus name means "daemon not running" — authorization
        // and transport failures must surface as themselves, not as a
        // misleading "start firewalld" hint.
        let daemon_running = match main.get_default_zone().await {
            Ok(_) => true,
            Err(err) => match dbus_err(err) {
                FirewallError::DaemonNotRunning => false,
                other => return Err(other),
            },
        };
        let (log_denied, panic_mode) = if daemon_running {
            let raw = main.get_log_denied().await.map_err(dbus_err)?;
            let log_denied = raw
                .parse()
                .map_err(|err| FirewallError::Parse(format!("log-denied `{raw}`: {err}")))?;
            (log_denied, main.query_panic_mode().await.map_err(dbus_err)?)
        } else {
            (LogDenied::Off, false)
        };
        Ok(FirewallStatus {
            daemon_running,
            version: main.version().await.ok(),
            backend: super::netfilter_backend(),
            log_denied,
            panic_mode,
        })
    }

    async fn snapshot(&self) -> Result<FirewallSnapshot, FirewallError> {
        let status = self.probe().await?;
        if !status.daemon_running {
            return Err(FirewallError::DaemonNotRunning);
        }
        let main = self.main().await?;
        let zone = self.zone().await?;
        let priority_support =
            FirewalldFeature::ZonePriorities.support_for(status.version.as_deref());

        let default_zone = ZoneName::parse(&main.get_default_zone().await.map_err(dbus_err)?)
            .map_err(|e| FirewallError::Parse(e.to_string()))?;

        let mut active = BTreeMap::new();
        for (name, sections) in zone.get_active_zones().await.map_err(dbus_err)? {
            if let Ok(zone_name) = ZoneName::parse(&name) {
                active.insert(
                    zone_name,
                    crate::domain::ActiveZone {
                        interfaces: sections
                            .get("interfaces")
                            .map(|v| parsed(v, InterfaceName::parse))
                            .unwrap_or_default(),
                        sources: sections
                            .get("sources")
                            .map(|v| parsed(v, SourceAddress::parse))
                            .unwrap_or_default(),
                    },
                );
            }
        }

        let names: Vec<ZoneName> = zone
            .get_zones()
            .await
            .map_err(dbus_err)?
            .iter()
            .filter_map(|raw| ZoneName::parse(raw).ok())
            .collect();
        let fetched = futures_util::future::join_all(names.into_iter().map(|name| {
            let zone = &zone;
            async move {
                let (details, incomplete) =
                    self.runtime_zone(zone, &name, priority_support).await?;
                Ok::<_, FirewallError>((name, details, incomplete))
            }
        }))
        .await;
        let mut runtime = BTreeMap::new();
        let mut degraded = Vec::new();
        for result in fetched {
            let (name, details, incomplete) = result?;
            degraded.extend(zone_priority_degradations(
                &name,
                ConfigurationTarget::Runtime,
                incomplete,
            ));
            runtime.insert(name, details);
        }
        let (permanent, permanent_degraded) = self.permanent_zones(priority_support).await?;
        degraded.extend(permanent_degraded);
        let available_services = parsed(
            &main.list_services().await.map_err(dbus_err)?,
            ServiceName::parse,
        );

        Ok(FirewallSnapshot {
            status,
            default_zone,
            active,
            runtime,
            permanent,
            // Not yet fetched via D-Bus — the CLI backend is the full-featured
            // reference. Declared degraded so the UI shows "unknown", not "none".
            ipsets: crate::domain::Scoped::default(),
            service_definitions: BTreeMap::new(),
            available_services,
            policies: crate::domain::Scoped::default(),
            direct_rules: Vec::new(),
            degraded: {
                degraded.extend([
                    crate::domain::DegradedSection::new(
                        crate::domain::SnapshotSection::IpSets,
                        None,
                        "not fetched by the D-Bus backend yet",
                    ),
                    crate::domain::DegradedSection::new(
                        crate::domain::SnapshotSection::Policies,
                        None,
                        "not fetched by the D-Bus backend yet",
                    ),
                    crate::domain::DegradedSection::new(
                        crate::domain::SnapshotSection::DirectRules,
                        Some(crate::domain::ConfigurationTarget::Runtime),
                        "not fetched by the D-Bus backend yet",
                    ),
                    incomplete_service_definitions(),
                ]);
                degraded
            },
        })
    }

    async fn apply(&self, operation: &FirewallOperation) -> OperationOutcome {
        match self.dispatch(operation).await {
            Ok(steps) => OperationOutcome::Applied {
                operation: operation.clone(),
                steps,
            },
            Err(failed) => OperationOutcome::Failed {
                operation: operation.clone(),
                steps: vec![StepReport {
                    target: "runtime",
                    invocation: failed.invocation,
                    result: Err(failed.error),
                }],
            },
        }
    }
}

/// A dispatch failure carrying the D-Bus method invocation that failed, so the
/// audit trail and step display name the exact call (ports.rs contract).
struct FailedStep {
    invocation: Vec<String>,
    error: FirewallError,
}

impl DbusBackend {
    /// Executes an operation over D-Bus. Runtime-scoped only for now (the
    /// permanent config-object mutation path is a documented follow-up).
    #[allow(clippy::too_many_lines)] // one arm per supported operation
    async fn dispatch(&self, operation: &FirewallOperation) -> Result<Vec<StepReport>, FailedStep> {
        let connect = |error| FailedStep {
            invocation: Vec::new(),
            error,
        };
        let main = self.main().await.map_err(connect)?;
        let zone = self.zone().await.map_err(connect)?;
        let step = |invocation: Vec<String>| StepReport {
            target: "runtime",
            invocation,
            result: Ok(()),
        };
        // Attaches the invocation to a failing D-Bus call.
        let fail = |invocation: &[String]| {
            let invocation = invocation.to_vec();
            move |err: zbus::Error| FailedStep {
                invocation,
                error: dbus_err(err),
            }
        };

        match operation {
            FirewallOperation::Reload => {
                let inv = vec!["reload".to_owned()];
                main.reload().await.map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::RuntimeToPermanent => {
                let inv = vec!["runtimeToPermanent".to_owned()];
                main.runtime_to_permanent().await.map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::SetPanicMode { enabled } => {
                let inv = vec![if *enabled {
                    "enablePanicMode".to_owned()
                } else {
                    "disablePanicMode".to_owned()
                }];
                if *enabled {
                    main.enable_panic_mode().await.map_err(fail(&inv))?;
                } else {
                    main.disable_panic_mode().await.map_err(fail(&inv))?;
                }
                Ok(vec![step(inv)])
            }
            FirewallOperation::SetDefaultZone { zone: name } => {
                let inv = vec!["setDefaultZone".to_owned(), name.to_string()];
                main.set_default_zone(name.as_str())
                    .await
                    .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::SetLogDenied { value } => {
                let inv = vec!["setLogDenied".to_owned(), value.as_str().to_owned()];
                main.set_log_denied(value.as_str())
                    .await
                    .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::AddService {
                zone: z,
                service,
                target,
            } => {
                let inv = vec!["addService".to_owned(), service.to_string()];
                runtime_only(*target, &inv)?;
                zone.add_service(z.as_str(), service.as_str(), 0)
                    .await
                    .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::RemoveService {
                zone: z,
                service,
                target,
            } => {
                let inv = vec!["removeService".to_owned(), service.to_string()];
                runtime_only(*target, &inv)?;
                zone.remove_service(z.as_str(), service.as_str())
                    .await
                    .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::AddPort {
                zone: z,
                port,
                target,
            } => {
                let inv = vec!["addPort".to_owned(), port.to_string()];
                runtime_only(*target, &inv)?;
                zone.add_port(
                    z.as_str(),
                    &port.port.to_string(),
                    port.protocol.as_str(),
                    0,
                )
                .await
                .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::RemovePort {
                zone: z,
                port,
                target,
            } => {
                let inv = vec!["removePort".to_owned(), port.to_string()];
                runtime_only(*target, &inv)?;
                zone.remove_port(z.as_str(), &port.port.to_string(), port.protocol.as_str())
                    .await
                    .map_err(fail(&inv))?;
                Ok(vec![step(inv)])
            }
            FirewallOperation::SetMasquerade {
                zone: z,
                enabled,
                target,
            } => {
                let inv = vec![if *enabled {
                    "addMasquerade".to_owned()
                } else {
                    "removeMasquerade".to_owned()
                }];
                runtime_only(*target, &inv)?;
                if *enabled {
                    zone.add_masquerade(z.as_str(), 0)
                        .await
                        .map_err(fail(&inv))?;
                } else {
                    zone.remove_masquerade(z.as_str())
                        .await
                        .map_err(fail(&inv))?;
                }
                Ok(vec![step(inv)])
            }
            other => Err(FailedStep {
                invocation: Vec::new(),
                error: FirewallError::Process(format!(
                    "operation `{}` is not yet supported by the D-Bus backend — use the CLI backend",
                    other.describe()
                )),
            }),
        }
    }
}

/// The D-Bus zone methods mutate runtime state only. Anything wider must fail
/// loudly — accepting `RuntimeAndPermanent` here would apply the runtime half,
/// report full success, and silently lose the permanent half on reload.
fn runtime_only(target: ConfigurationTarget, invocation: &[String]) -> Result<(), FailedStep> {
    if target == ConfigurationTarget::Runtime {
        return Ok(());
    }
    Err(FailedStep {
        invocation: invocation.to_vec(),
        error: FirewallError::Process(
            "the D-Bus backend applies runtime-only changes for now — \
             use the CLI backend for permanent scope"
                .to_owned(),
        ),
    })
}

fn map_method_error(name: &str, detail: &str, rendered: String) -> FirewallError {
    if name == "org.freedesktop.DBus.Error.AccessDenied"
        || name.contains("NotAuthorized")
        || detail.starts_with("NOT_AUTHORIZED")
    {
        FirewallError::PermissionDenied { detail: rendered }
    } else if name == "org.freedesktop.DBus.Error.ServiceUnknown"
        || name == "org.freedesktop.DBus.Error.NameHasNoOwner"
    {
        FirewallError::DaemonNotRunning
    } else {
        FirewallError::Process(rendered)
    }
}

// Owned by value so it can be used directly as a `map_err` function pointer.
#[allow(clippy::needless_pass_by_value)]
fn dbus_err(err: zbus::Error) -> FirewallError {
    // Method errors carry a structured D-Bus error name — match on it, not on
    // rendered text. firewalld raises polkit denials under
    // `…slip.dbus.service.PolKit.NotAuthorizedException…` and its own errors as
    // `org.fedoraproject.FirewallD1.Exception` with a `NOT_AUTHORIZED:` detail.
    if let zbus::Error::MethodError(name, detail, _) = &err {
        return map_method_error(
            name.as_str(),
            detail.as_deref().unwrap_or_default(),
            err.to_string(),
        );
    }
    // Transport-level errors (connection refused, disconnects, …).
    FirewallError::Process(err.to_string())
}

/// Parses each item with `parse`, dropping anything invalid (defensive: the
/// daemon is trusted, but a newer firewalld could return an unfamiliar token).
fn parsed<T, E>(items: &[String], parse: impl Fn(&str) -> Result<T, E>) -> Vec<T> {
    items.iter().filter_map(|item| parse(item).ok()).collect()
}

/// Joins D-Bus `(port, protocol)` pairs into the domain's `port/proto` spec.
fn pair_to_port(port: &str, protocol: &str) -> Option<PortSpec> {
    format!("{port}/{protocol}").parse().ok()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn zone_settings_observe_validated_priorities() {
        let settings = HashMap::from([
            ("ingress_priority".to_owned(), OwnedValue::from(-120_i32)),
            ("egress_priority".to_owned(), OwnedValue::from(240_i32)),
        ]);

        let observed = observe_zone_settings(&settings, FeatureSupport::Supported);

        assert_eq!(observed.target, ZoneTarget::Default);
        assert_eq!(observed.ingress_priority.get(), -120);
        assert_eq!(observed.egress_priority.get(), 240);
        assert!(observed.incomplete.is_empty());
    }

    #[test]
    fn dbus_never_presents_empty_service_definitions_as_complete() {
        let degraded = incomplete_service_definitions();

        assert_eq!(degraded.section, SnapshotSection::ServiceDefinitions);
        assert_eq!(degraded.target, None);
        assert_eq!(degraded.object, None);
        assert!(degraded.reason.contains("not fetched"));
    }

    #[test]
    fn supported_zone_priorities_require_complete_dbus_evidence() {
        let settings = HashMap::new();

        let observed = observe_zone_settings(&settings, FeatureSupport::Supported);

        assert_eq!(observed.ingress_priority.get(), 0);
        assert_eq!(observed.egress_priority.get(), 0);
        assert_eq!(observed.incomplete.len(), 2);
        assert!(
            observed
                .incomplete
                .iter()
                .any(|reason| reason.contains("ingress"))
        );
        assert!(
            observed
                .incomplete
                .iter()
                .any(|reason| reason.contains("egress"))
        );
    }

    #[test]
    fn unsupported_zone_priorities_do_not_fabricate_degradation() {
        let observed = observe_zone_settings(&HashMap::new(), FeatureSupport::Unsupported);

        assert_eq!(observed.ingress_priority.get(), 0);
        assert_eq!(observed.egress_priority.get(), 0);
        assert!(observed.incomplete.is_empty());
    }

    #[test]
    fn invalid_dbus_priorities_remain_explicitly_incomplete() {
        let settings = HashMap::from([
            ("ingress_priority".to_owned(), OwnedValue::from(true)),
            ("egress_priority".to_owned(), OwnedValue::from(40_000_i32)),
        ]);

        let observed = observe_zone_settings(&settings, FeatureSupport::Supported);

        assert_eq!(observed.ingress_priority.get(), 0);
        assert_eq!(observed.egress_priority.get(), 0);
        assert!(
            observed
                .incomplete
                .iter()
                .any(|reason| reason.contains("signed integer"))
        );
        assert!(
            observed
                .incomplete
                .iter()
                .any(|reason| reason.contains("outside"))
        );
    }

    #[test]
    fn priority_degradation_keeps_zone_and_scope_identity() {
        let zone = ZoneName::parse("public").expect("valid zone fixture");

        let degraded = zone_priority_degradations(
            &zone,
            ConfigurationTarget::Permanent,
            vec!["missing ingress priority".to_owned()],
        );

        assert_eq!(degraded.len(), 1);
        assert_eq!(degraded[0].section, crate::domain::SnapshotSection::Zones);
        assert_eq!(degraded[0].target, Some(ConfigurationTarget::Permanent));
        assert_eq!(degraded[0].object.as_deref(), Some("public"));
    }

    #[test]
    fn method_error_maps_access_denied_to_permission_denied() {
        let error = map_method_error(
            "org.freedesktop.DBus.Error.AccessDenied",
            "denied",
            "rendered error".to_owned(),
        );

        assert!(matches!(error, FirewallError::PermissionDenied { .. }));
    }

    #[test]
    fn method_error_maps_firewalld_authorization_failures_to_permission_denied() {
        for (name, detail) in [
            (
                "org.fedoraproject.FirewallD1.Exception.NotAuthorized",
                "denied",
            ),
            (
                "org.fedoraproject.FirewallD1.Exception",
                "NOT_AUTHORIZED: action denied",
            ),
        ] {
            let error = map_method_error(name, detail, "rendered error".to_owned());
            assert!(matches!(error, FirewallError::PermissionDenied { .. }));
        }
    }

    #[test]
    fn method_error_maps_missing_daemon_names_to_daemon_not_running() {
        for name in [
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "org.freedesktop.DBus.Error.NameHasNoOwner",
        ] {
            let error = map_method_error(name, "missing", "rendered error".to_owned());
            assert!(matches!(error, FirewallError::DaemonNotRunning));
        }
    }

    #[test]
    fn method_error_preserves_unclassified_failure() {
        let error = map_method_error(
            "org.fedoraproject.FirewallD1.Exception.InvalidZone",
            "INVALID_ZONE: missing",
            "rendered error".to_owned(),
        );

        assert!(matches!(error, FirewallError::Process(message) if message == "rendered error"));
    }

    #[test]
    fn port_pair_parser_accepts_valid_pair_and_rejects_invalid_protocol() {
        assert_eq!(pair_to_port("443", "tcp"), "443/tcp".parse().ok());
        assert_eq!(pair_to_port("443", "invalid"), None);
    }

    #[test]
    fn parsed_values_drop_invalid_tokens() {
        let values = vec!["ssh".to_owned(), "bad service".to_owned()];
        let services = parsed(&values, ServiceName::parse);

        assert_eq!(
            services,
            vec![ServiceName::parse("ssh").expect("valid service fixture")]
        );
    }

    #[test]
    fn gate_rejects_everything_but_runtime() {
        let inv = vec!["addService".to_owned()];
        assert!(runtime_only(ConfigurationTarget::Runtime, &inv).is_ok());
        for target in [
            ConfigurationTarget::Permanent,
            ConfigurationTarget::RuntimeAndPermanent,
        ] {
            let failed = runtime_only(target, &inv).err();
            let failed = failed.expect("wider targets must fail loudly");
            assert_eq!(failed.invocation, inv, "failure names the method");
        }
    }

    #[test]
    fn transport_errors_map_to_process() {
        let err = zbus::Error::InvalidReply;
        assert!(matches!(dbus_err(err), FirewallError::Process(_)));
    }
}
