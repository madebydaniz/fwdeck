//! Conservative translation of legacy direct rules into policy-attached rich
//! rules. Unsupported syntax fails closed: the assistant never guesses at a
//! netfilter expression outside its mechanically translatable subset.

use super::{AddressFamily, PolicyName, PortSpec, RichRule, SourceAddress};

/// A base netfilter direction that has an exact firewalld policy-zone mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectChain {
    /// Traffic from any regular zone to the local host.
    Input,
    /// Traffic from the local host to any regular zone.
    Output,
    /// Traffic forwarded between regular zones.
    Forward,
}

impl DirectChain {
    /// Direct chain spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Input => "INPUT",
            Self::Output => "OUTPUT",
            Self::Forward => "FORWARD",
        }
    }

    /// Policy ingress symbolic zone.
    #[must_use]
    pub const fn ingress_zone(self) -> &'static str {
        match self {
            Self::Input | Self::Forward => "ANY",
            Self::Output => "HOST",
        }
    }

    /// Policy egress symbolic zone.
    #[must_use]
    pub const fn egress_zone(self) -> &'static str {
        match self {
            Self::Input => "HOST",
            Self::Output | Self::Forward => "ANY",
        }
    }
}

/// A direct rule whose meaning fits the verified migration subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectRuleTranslation {
    /// Original line returned by `--direct --get-all-rules`.
    pub source_rule: String,
    /// IP family applied to the generated rich rule.
    pub family: AddressFamily,
    /// Netfilter direction and corresponding policy-zone mapping.
    pub chain: DirectChain,
    /// Original direct priority, preserved as rich-rule priority.
    pub priority: i16,
    /// Validated rich-language replacement.
    pub rich_rule: RichRule,
}

impl DirectRuleTranslation {
    /// Binds a reviewed translation to a new user-created policy.
    #[must_use]
    pub fn into_migration(self, policy: PolicyName) -> DirectPolicyMigration {
        DirectPolicyMigration {
            policy,
            source_rule: self.source_rule,
            ingress_zone: self.chain.ingress_zone().to_owned(),
            egress_zone: self.chain.egress_zone().to_owned(),
            rich_rule: self.rich_rule,
        }
    }
}

/// One additive migration operation. The legacy rule deliberately remains in
/// place until the operator reloads and validates the replacement policy.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DirectPolicyMigration {
    /// New permanent policy name.
    policy: PolicyName,
    /// Auditable source rule; never executed or reconstructed.
    source_rule: String,
    /// Policy ingress zone (`ANY` or `HOST`).
    ingress_zone: String,
    /// Policy egress zone (`ANY` or `HOST`).
    egress_zone: String,
    /// Mechanically generated rich-rule candidate.
    rich_rule: RichRule,
}

impl DirectPolicyMigration {
    /// New policy name.
    #[must_use]
    pub const fn policy(&self) -> &PolicyName {
        &self.policy
    }

    /// Original direct-rule line retained for audit and stale-state checks.
    #[must_use]
    pub fn source_rule(&self) -> &str {
        &self.source_rule
    }

    /// Policy ingress zone.
    #[must_use]
    pub fn ingress_zone(&self) -> &str {
        &self.ingress_zone
    }

    /// Policy egress zone.
    #[must_use]
    pub fn egress_zone(&self) -> &str {
        &self.egress_zone
    }

    /// Generated rich rule.
    #[must_use]
    pub const fn rich_rule(&self) -> &RichRule {
        &self.rich_rule
    }
}

/// Why a direct rule cannot be translated without operator judgment.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct DirectMigrationError(String);

impl DirectMigrationError {
    fn unsupported(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// Translates the deliberately small, mechanically supported subset of direct
/// rules. A candidate still requires reload-time traffic validation because
/// direct and policy rule precedence are not identical abstractions.
///
/// Supported rules use the IPv4/IPv6 `filter` table, a base INPUT/OUTPUT/
/// FORWARD chain, optional source/destination CIDRs, one protocol or one
/// source/destination port match, and ACCEPT/DROP/REJECT.
pub fn translate_direct_rule(raw: &str) -> Result<DirectRuleTranslation, DirectMigrationError> {
    let tokens: Vec<&str> = raw.split_ascii_whitespace().collect();
    if tokens.len() < 6 {
        return Err(DirectMigrationError::unsupported(
            "malformed direct rule: expected family table chain priority and arguments",
        ));
    }
    if tokens.iter().any(|token| {
        token
            .chars()
            .any(|ch| ch.is_control() || matches!(ch, '\'' | '"' | '\\'))
    }) {
        return Err(DirectMigrationError::unsupported(
            "quoted, escaped, or control-character arguments require manual migration",
        ));
    }

    let (family, chain, priority) = parse_header(&tokens)?;
    let arguments = DirectArguments::parse(&tokens[4..])?;
    let rich_rule = arguments.into_rich_rule(family, priority)?;

    Ok(DirectRuleTranslation {
        source_rule: raw.to_owned(),
        family,
        chain,
        priority,
        rich_rule,
    })
}

fn parse_header(
    tokens: &[&str],
) -> Result<(AddressFamily, DirectChain, i16), DirectMigrationError> {
    let family = match tokens[0] {
        "ipv4" => AddressFamily::Ipv4,
        "ipv6" => AddressFamily::Ipv6,
        other => {
            return Err(DirectMigrationError::unsupported(format!(
                "family `{other}` has no safe policy translation"
            )));
        }
    };
    if tokens[1] != "filter" {
        return Err(DirectMigrationError::unsupported(format!(
            "table `{}` requires manual migration",
            tokens[1]
        )));
    }
    let chain = match tokens[2] {
        "INPUT" => DirectChain::Input,
        "OUTPUT" => DirectChain::Output,
        "FORWARD" => DirectChain::Forward,
        other => {
            return Err(DirectMigrationError::unsupported(format!(
                "custom chain `{other}` requires manual direction mapping"
            )));
        }
    };
    let priority = tokens[3].parse::<i16>().map_err(|_| {
        DirectMigrationError::unsupported(
            "direct priority is outside the rich-rule range -32768..=32767",
        )
    })?;
    Ok((family, chain, priority))
}

#[derive(Default)]
struct DirectArguments {
    protocol: Option<String>,
    module: Option<String>,
    source: Option<String>,
    destination: Option<String>,
    source_port: Option<String>,
    destination_port: Option<String>,
    action: Option<String>,
    reject_type: Option<String>,
}

impl DirectArguments {
    fn parse(tokens: &[&str]) -> Result<Self, DirectMigrationError> {
        let mut parsed = Self::default();
        let mut index = 0usize;
        while index < tokens.len() {
            let token = tokens[index];
            let value = || {
                tokens.get(index + 1).copied().ok_or_else(|| {
                    DirectMigrationError::unsupported(format!("`{token}` is missing its value"))
                })
            };
            match token {
                "-p" | "--protocol" => {
                    set_once(&mut parsed.protocol, value()?.to_ascii_lowercase(), token)?;
                }
                "-m" | "--match" => {
                    set_once(&mut parsed.module, value()?.to_ascii_lowercase(), token)?;
                }
                "-s" | "--source" => {
                    set_once(&mut parsed.source, value()?.to_owned(), token)?;
                }
                "-d" | "--destination" => {
                    set_once(&mut parsed.destination, value()?.to_owned(), token)?;
                }
                "--sport" | "--source-port" => {
                    set_once(&mut parsed.source_port, value()?.to_owned(), token)?;
                }
                "--dport" | "--destination-port" => {
                    set_once(&mut parsed.destination_port, value()?.to_owned(), token)?;
                }
                "-j" | "--jump" => {
                    set_once(&mut parsed.action, value()?.to_ascii_uppercase(), token)?;
                }
                "--reject-with" => {
                    set_once(&mut parsed.reject_type, value()?.to_owned(), token)?;
                }
                "!" => {
                    return Err(DirectMigrationError::unsupported(
                        "negated direct matches require manual review",
                    ));
                }
                other => {
                    return Err(DirectMigrationError::unsupported(format!(
                        "argument `{other}` is outside the supported migration subset"
                    )));
                }
            }
            index += 2;
        }
        Ok(parsed)
    }

    fn into_rich_rule(
        self,
        family: AddressFamily,
        priority: i16,
    ) -> Result<RichRule, DirectMigrationError> {
        if let Some(module) = &self.module
            && self.protocol.as_deref() != Some(module.as_str())
        {
            return Err(DirectMigrationError::unsupported(format!(
                "match module `{module}` is not redundant with the protocol"
            )));
        }
        let action = supported_action(self.action.as_deref())?;
        if self.reject_type.is_some() && action != "reject" {
            return Err(DirectMigrationError::unsupported(
                "`--reject-with` is only valid with REJECT",
            ));
        }
        let source = self
            .source
            .map(|value| validate_address(&value, family, "source"))
            .transpose()?;
        let destination = self
            .destination
            .map(|value| validate_address(&value, family, "destination"))
            .transpose()?;
        let element = rule_element(
            self.source_port,
            self.destination_port,
            self.protocol.as_deref(),
            source.is_some(),
            destination.is_some(),
        )?;
        build_rich_rule(
            family,
            priority,
            source.as_deref(),
            destination.as_deref(),
            &element,
            action,
            self.reject_type.as_deref(),
        )
    }
}

fn set_once(
    slot: &mut Option<String>,
    value: String,
    option: &str,
) -> Result<(), DirectMigrationError> {
    if slot.replace(value).is_some() {
        return Err(DirectMigrationError::unsupported(format!(
            "duplicate option `{option}` requires manual review"
        )));
    }
    Ok(())
}

fn supported_action(action: Option<&str>) -> Result<&'static str, DirectMigrationError> {
    match action {
        Some("ACCEPT") => Ok("accept"),
        Some("DROP") => Ok("drop"),
        Some("REJECT") => Ok("reject"),
        Some(other) => Err(DirectMigrationError::unsupported(format!(
            "jump target `{other}` requires manual migration"
        ))),
        None => Err(DirectMigrationError::unsupported(
            "rule has no terminal jump target",
        )),
    }
}

fn rule_element(
    source_port: Option<String>,
    destination_port: Option<String>,
    protocol: Option<&str>,
    has_source: bool,
    has_destination: bool,
) -> Result<String, DirectMigrationError> {
    match (source_port, destination_port, protocol) {
        (Some(port), None, Some(protocol)) => {
            let port = validate_port(&port, protocol)?;
            Ok(format!(
                "source-port port=\"{}\" protocol=\"{}\"",
                port.port,
                port.protocol.as_str()
            ))
        }
        (None, Some(port), Some(protocol)) => {
            let port = validate_port(&port, protocol)?;
            Ok(format!(
                "port port=\"{}\" protocol=\"{}\"",
                port.port,
                port.protocol.as_str()
            ))
        }
        (Some(_), None, None) | (None, Some(_), None) => Err(DirectMigrationError::unsupported(
            "port matches require an explicit transport protocol",
        )),
        (None, None, Some(protocol)) => Ok(format!("protocol value=\"{protocol}\"")),
        (None, None, None) if has_source && !has_destination => Ok(String::new()),
        (None, None, None) => Err(DirectMigrationError::unsupported(
            "an all-traffic or destination-only rule needs manual policy design",
        )),
        (Some(_), Some(_), _) => Err(DirectMigrationError::unsupported(
            "combined source and destination ports need manual rich-rule design",
        )),
    }
}

fn build_rich_rule(
    family: AddressFamily,
    priority: i16,
    source: Option<&str>,
    destination: Option<&str>,
    element: &str,
    action: &str,
    reject_type: Option<&str>,
) -> Result<RichRule, DirectMigrationError> {
    let mut parts = vec![
        "rule".to_owned(),
        format!("priority=\"{priority}\""),
        format!("family=\"{}\"", family.as_str()),
    ];
    if let Some(source) = source {
        parts.push(format!("source address=\"{source}\""));
    }
    if let Some(destination) = destination {
        parts.push(format!("destination address=\"{destination}\""));
    }
    if !element.is_empty() {
        parts.push(element.to_owned());
    }
    parts.push(reject_type.map_or_else(
        || action.to_owned(),
        |reject_type| format!("reject type=\"{reject_type}\""),
    ));
    RichRule::parse(&parts.join(" "))
        .map_err(|err| DirectMigrationError::unsupported(err.to_string()))
}

fn validate_address(
    raw: &str,
    family: AddressFamily,
    label: &str,
) -> Result<String, DirectMigrationError> {
    let parsed = SourceAddress::parse(raw).map_err(|_| {
        DirectMigrationError::unsupported(format!("invalid {label} address `{raw}`"))
    })?;
    if parsed.family() != Some(family) {
        return Err(DirectMigrationError::unsupported(format!(
            "{label} address `{raw}` does not match {}",
            family.as_str()
        )));
    }
    Ok(parsed.to_string())
}

fn validate_port(raw: &str, protocol: &str) -> Result<PortSpec, DirectMigrationError> {
    format!("{raw}/{protocol}").parse().map_err(|err| {
        DirectMigrationError::unsupported(format!("port `{raw}` cannot be translated: {err}"))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn translates_fixture_rule_to_input_policy() {
        let translated =
            translate_direct_rule("ipv4 filter INPUT 9 -p tcp --dport 12345 -j ACCEPT").unwrap();
        assert_eq!(translated.chain, DirectChain::Input);
        assert_eq!(translated.chain.ingress_zone(), "ANY");
        assert_eq!(translated.chain.egress_zone(), "HOST");
        assert_eq!(
            translated.rich_rule.as_str(),
            r#"rule priority="9" family="ipv4" port port="12345" protocol="tcp" accept"#
        );
    }

    #[test]
    fn translates_forward_source_drop() {
        let translated =
            translate_direct_rule("ipv6 filter FORWARD -10 -s 2001:db8::/32 -j DROP").unwrap();
        assert_eq!(translated.chain.ingress_zone(), "ANY");
        assert_eq!(translated.chain.egress_zone(), "ANY");
        assert!(translated.rich_rule.as_str().contains("source address="));
        assert!(translated.rich_rule.as_str().ends_with("drop"));
    }

    #[test]
    fn rejects_semantically_ambiguous_rules() {
        for rule in [
            "ipv4 nat PREROUTING 0 -p tcp --dport 80 -j DNAT",
            "ipv4 filter CUSTOM 0 -p tcp --dport 80 -j ACCEPT",
            "ipv4 filter INPUT 0 -m conntrack --ctstate NEW -j ACCEPT",
            "ipv4 filter INPUT 0 -p tcp --sport 10 --dport 20 -j ACCEPT",
            "ipv4 filter INPUT 0 -p tcp -p udp --dport 53 -j ACCEPT",
            "eb filter INPUT 0 -j ACCEPT",
        ] {
            assert!(translate_direct_rule(rule).is_err(), "must reject `{rule}`");
        }
    }

    #[test]
    fn rejects_address_family_mismatch() {
        let result = translate_direct_rule(
            "ipv4 filter OUTPUT 0 -d 2001:db8::1 -p tcp --dport 443 -j ACCEPT",
        );
        assert!(result.is_err());
    }
}
