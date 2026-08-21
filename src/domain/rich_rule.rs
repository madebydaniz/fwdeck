//! Rich rules are kept as validated raw strings. Parsing is display-only:
//! mutations always pass the original text back to firewalld, so we never
//! reconstruct (and therefore never corrupt) a rule.

use std::fmt;

use super::{
    AddressFamily, IpProtocol, PortSpec, RulePriority, ServiceName, SourceAddress, ValidationError,
};

const MAX_ANALYSIS_TOKENS: usize = 64;

/// A traffic-relevant terminal rich-rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RichRuleAction {
    /// Permit matching traffic.
    Accept,
    /// Reject matching traffic with an error response.
    Reject,
    /// Silently discard matching traffic.
    Drop,
}

impl RichRuleAction {
    /// Stable operator-facing keyword.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Drop => "drop",
        }
    }
}

/// One supported IP/CIDR matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichRuleAddressMatch {
    /// Validated IP address or CIDR.
    pub address: SourceAddress,
    /// Whether the match is inverted.
    pub inverted: bool,
}

/// The supported traffic-relevant subset of a rich rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RichRuleExpression {
    /// Optional IP family restriction.
    pub family: Option<AddressFamily>,
    /// Optional source IP/CIDR matcher.
    pub source: Option<RichRuleAddressMatch>,
    /// Optional destination IP/CIDR matcher.
    pub destination: Option<RichRuleAddressMatch>,
    /// Optional firewalld service matcher.
    pub service: Option<ServiceName>,
    /// Optional destination port/range and transport protocol.
    pub destination_port: Option<PortSpec>,
    /// Optional source port/range and transport protocol.
    pub source_port: Option<PortSpec>,
    /// Optional raw IP protocol matcher.
    pub protocol: Option<IpProtocol>,
    /// Firewalld rule priority (zero when omitted).
    pub priority: RulePriority,
    /// Terminal decision.
    pub action: RichRuleAction,
}

/// Relevant syntax that `FWDeck` deliberately does not evaluate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RichRuleUnsupported {
    /// Rate limiting changes temporal semantics.
    RateLimit,
    /// MAC matching is outside the approved IP model.
    MacAddress,
    /// Connection-tracking helper semantics are unsupported.
    Helper,
    /// Packet or connection mark mutation is unsupported.
    Mark,
    /// TCP MSS rewriting is unsupported.
    TcpMssClamp,
    /// Logging side effects are not evaluated.
    Log,
    /// Audit side effects are not evaluated.
    Audit,
    /// IP-set matching needs separate typed set semantics.
    IpSet,
    /// A future or unknown grammar element.
    UnknownElement(String),
    /// A singleton element appeared more than once.
    DuplicateElement(String),
    /// Two individually valid elements cannot be combined.
    ConflictingElements {
        /// First conflicting element.
        left: String,
        /// Second conflicting element.
        right: String,
    },
    /// The bounded parser input limit was exceeded.
    TooManyTokens {
        /// Maximum accepted token count.
        limit: usize,
    },
}

/// Malformed supported syntax. Evaluation must fail closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RichRuleMalformed {
    /// A quoted value was not closed.
    UnterminatedQuote,
    /// A known element omitted a required attribute.
    MissingAttribute {
        /// Element being parsed.
        element: String,
        /// Required attribute name.
        attribute: String,
    },
    /// A known attribute failed typed validation.
    InvalidValue {
        /// Element being parsed.
        element: String,
        /// Rejected raw value.
        value: String,
    },
    /// No terminal accept/reject/drop action was present.
    MissingAction,
}

/// Result of analyzing the original raw rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RichRuleAnalysis {
    /// Fully supported typed expression.
    Supported(Box<RichRuleExpression>),
    /// Well-formed but deliberately unsupported semantics.
    Unsupported(RichRuleUnsupported),
    /// Malformed supported syntax.
    Malformed(RichRuleMalformed),
}

#[derive(Default)]
struct ExpressionBuilder {
    family: Option<AddressFamily>,
    source: Option<RichRuleAddressMatch>,
    destination: Option<RichRuleAddressMatch>,
    service: Option<ServiceName>,
    destination_port: Option<PortSpec>,
    source_port: Option<PortSpec>,
    protocol: Option<IpProtocol>,
    priority: RulePriority,
    priority_seen: bool,
    action: Option<RichRuleAction>,
}

/// One firewalld rich rule, stored verbatim (trimmed only).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct RichRule(String);

impl<'de> serde::Deserialize<'de> for RichRule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl RichRule {
    /// Accepts trimmed text whose first whole word is `rule`; no deeper syntax
    /// check — firewalld stays the authority on rich rule grammar. Rejects
    /// control characters (a rich rule is a single line, and a newline would
    /// corrupt the audit trail) and `rule` used only as a prefix (`ruleset`,
    /// `rulefoo`).
    pub fn parse(raw: &str) -> Result<Self, ValidationError> {
        let trimmed = raw.trim();
        if trimmed.chars().any(char::is_control) {
            return Err(ValidationError::InvalidRichRule);
        }
        // `rule` must be a whole word followed by the rule body, so a bare
        // `rule`, `ruleset`, or `rulefoo` are all rejected.
        let Some(rest) = trimmed.strip_prefix("rule") else {
            return Err(ValidationError::InvalidRichRule);
        };
        if !rest.starts_with(char::is_whitespace) {
            return Err(ValidationError::InvalidRichRule);
        }
        Ok(Self(trimmed.to_owned()))
    }

    /// The mutation path passes this verbatim back to firewalld.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Best-effort `family="..."` extraction for table columns.
    #[must_use]
    pub fn family(&self) -> Option<&str> {
        let start = self.0.find("family=\"")? + "family=\"".len();
        self.0.get(start..)?.split('"').next()
    }

    /// Best-effort action keyword extraction for table columns.
    #[must_use]
    pub fn action(&self) -> Option<&'static str> {
        ["accept", "reject", "drop", "mark"]
            .into_iter()
            .find(|action| self.0.split_whitespace().any(|token| token == *action))
    }

    /// Parses the bounded, approved traffic-relevant subset without changing
    /// the raw mutation text.
    #[must_use]
    pub fn analyze(&self) -> RichRuleAnalysis {
        let tokens = match tokenize(&self.0) {
            Ok(tokens) => tokens,
            Err(reason) => return RichRuleAnalysis::Malformed(reason),
        };
        if tokens.len() > MAX_ANALYSIS_TOKENS {
            return RichRuleAnalysis::Unsupported(RichRuleUnsupported::TooManyTokens {
                limit: MAX_ANALYSIS_TOKENS,
            });
        }
        analyze_tokens(&tokens)
    }
}

fn analyze_tokens(tokens: &[String]) -> RichRuleAnalysis {
    let mut builder = ExpressionBuilder::default();
    let mut index = 1;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        let result = match token {
            token if token.starts_with("family=") => parse_family(token, &mut builder),
            token if token.starts_with("priority=") => parse_priority(token, &mut builder),
            "source" => parse_address_element(tokens, &mut index, true, &mut builder),
            "destination" => parse_address_element(tokens, &mut index, false, &mut builder),
            "service" => parse_service(tokens, &mut index, &mut builder),
            "port" => parse_port(tokens, &mut index, false, &mut builder),
            "source-port" => parse_port(tokens, &mut index, true, &mut builder),
            "protocol" => parse_protocol(tokens, &mut index, &mut builder),
            "accept" => set_action(&mut builder, RichRuleAction::Accept),
            "reject" => set_action(&mut builder, RichRuleAction::Reject),
            "drop" => set_action(&mut builder, RichRuleAction::Drop),
            "limit" => Err(RichRuleAnalysis::Unsupported(
                RichRuleUnsupported::RateLimit,
            )),
            "helper" => Err(RichRuleAnalysis::Unsupported(RichRuleUnsupported::Helper)),
            "mark" => Err(RichRuleAnalysis::Unsupported(RichRuleUnsupported::Mark)),
            "tcp-mss-clamp" => Err(RichRuleAnalysis::Unsupported(
                RichRuleUnsupported::TcpMssClamp,
            )),
            "log" => Err(RichRuleAnalysis::Unsupported(RichRuleUnsupported::Log)),
            "audit" => Err(RichRuleAnalysis::Unsupported(RichRuleUnsupported::Audit)),
            unknown => Err(RichRuleAnalysis::Unsupported(
                RichRuleUnsupported::UnknownElement(unknown.to_owned()),
            )),
        };
        if let Err(analysis) = result {
            return analysis;
        }
        index += 1;
    }

    if builder.service.is_some() && builder.destination_port.is_some() {
        return RichRuleAnalysis::Unsupported(RichRuleUnsupported::ConflictingElements {
            left: "service".to_owned(),
            right: "port".to_owned(),
        });
    }
    if builder.protocol.is_some()
        && (builder.service.is_some() || builder.destination_port.is_some())
    {
        return RichRuleAnalysis::Unsupported(RichRuleUnsupported::ConflictingElements {
            left: "protocol".to_owned(),
            right: if builder.service.is_some() {
                "service".to_owned()
            } else {
                "port".to_owned()
            },
        });
    }
    let Some(action) = builder.action else {
        return RichRuleAnalysis::Malformed(RichRuleMalformed::MissingAction);
    };
    RichRuleAnalysis::Supported(Box::new(RichRuleExpression {
        family: builder.family,
        source: builder.source,
        destination: builder.destination,
        service: builder.service,
        destination_port: builder.destination_port,
        source_port: builder.source_port,
        protocol: builder.protocol,
        priority: builder.priority,
        action,
    }))
}

fn tokenize(raw: &str) -> Result<Vec<String>, RichRuleMalformed> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for character in raw.chars() {
        match character {
            '"' => quoted = !quoted,
            character if character.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }
    if quoted {
        return Err(RichRuleMalformed::UnterminatedQuote);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

type ParseStep = Result<(), RichRuleAnalysis>;

fn parse_family(token: &str, builder: &mut ExpressionBuilder) -> ParseStep {
    if builder.family.is_some() {
        return duplicate("family");
    }
    builder.family = match value(token) {
        "ipv4" => Some(AddressFamily::Ipv4),
        "ipv6" => Some(AddressFamily::Ipv6),
        invalid => return malformed("family", invalid),
    };
    Ok(())
}

fn parse_priority(token: &str, builder: &mut ExpressionBuilder) -> ParseStep {
    if builder.priority_seen {
        return duplicate("priority");
    }
    builder.priority_seen = true;
    builder.priority = value(token)
        .parse()
        .map_err(|_| malformed_analysis("priority", value(token)))?;
    Ok(())
}

fn parse_address_element(
    tokens: &[String],
    index: &mut usize,
    source: bool,
    builder: &mut ExpressionBuilder,
) -> ParseStep {
    let label = if source { "source" } else { "destination" };
    if if source {
        builder.source.is_some()
    } else {
        builder.destination.is_some()
    } {
        return duplicate(label);
    }
    let mut inverted = false;
    let mut next = next_token(tokens, index, label, "address")?;
    if next.eq_ignore_ascii_case("not") {
        inverted = true;
        next = next_token(tokens, index, label, "address")?;
    } else if next.starts_with("invert=") {
        inverted = match value(next) {
            "true" | "yes" => true,
            "false" | "no" => false,
            invalid => return malformed("invert", invalid),
        };
        next = next_token(tokens, index, label, "address")?;
    }
    if next.starts_with("ipset=") {
        return Err(RichRuleAnalysis::Unsupported(RichRuleUnsupported::IpSet));
    }
    if next.starts_with("mac=") {
        return Err(RichRuleAnalysis::Unsupported(
            RichRuleUnsupported::MacAddress,
        ));
    }
    let Some(raw) = next.strip_prefix("address=") else {
        return Err(missing(label, "address"));
    };
    let address = SourceAddress::parse(raw).map_err(|_| malformed_analysis(label, raw))?;
    let Some(family) = address.family() else {
        return malformed(label, raw);
    };
    if builder.family.is_some_and(|expected| expected != family) {
        return malformed(label, raw);
    }
    let matcher = RichRuleAddressMatch { address, inverted };
    if source {
        builder.source = Some(matcher);
    } else {
        builder.destination = Some(matcher);
    }
    Ok(())
}

fn parse_service(
    tokens: &[String],
    index: &mut usize,
    builder: &mut ExpressionBuilder,
) -> ParseStep {
    if builder.service.is_some() {
        return duplicate("service");
    }
    let token = next_token(tokens, index, "service", "name")?;
    let Some(raw) = token.strip_prefix("name=") else {
        return Err(missing("service", "name"));
    };
    builder.service =
        Some(ServiceName::parse(raw).map_err(|_| malformed_analysis("service", raw))?);
    Ok(())
}

fn parse_port(
    tokens: &[String],
    index: &mut usize,
    source: bool,
    builder: &mut ExpressionBuilder,
) -> ParseStep {
    let label = if source { "source-port" } else { "port" };
    let slot = if source {
        &mut builder.source_port
    } else {
        &mut builder.destination_port
    };
    if slot.is_some() {
        return duplicate(label);
    }
    let port = next_token(tokens, index, label, "port")?;
    let Some(port) = port.strip_prefix("port=") else {
        return Err(missing(label, "port"));
    };
    let protocol = next_token(tokens, index, label, "protocol")?;
    let Some(protocol) = protocol.strip_prefix("protocol=") else {
        return Err(missing(label, "protocol"));
    };
    *slot = Some(
        format!("{port}/{protocol}")
            .parse()
            .map_err(|_| malformed_analysis(label, port))?,
    );
    Ok(())
}

fn parse_protocol(
    tokens: &[String],
    index: &mut usize,
    builder: &mut ExpressionBuilder,
) -> ParseStep {
    if builder.protocol.is_some() {
        return duplicate("protocol");
    }
    let token = next_token(tokens, index, "protocol", "value")?;
    let Some(raw) = token.strip_prefix("value=") else {
        return Err(missing("protocol", "value"));
    };
    builder.protocol =
        Some(IpProtocol::parse(raw).map_err(|_| malformed_analysis("protocol", raw))?);
    Ok(())
}

fn set_action(builder: &mut ExpressionBuilder, action: RichRuleAction) -> ParseStep {
    if builder.action.is_some() {
        return duplicate("action");
    }
    builder.action = Some(action);
    Ok(())
}

fn next_token<'a>(
    tokens: &'a [String],
    index: &mut usize,
    element: &str,
    attribute: &str,
) -> Result<&'a str, RichRuleAnalysis> {
    *index += 1;
    tokens
        .get(*index)
        .map(String::as_str)
        .ok_or_else(|| missing(element, attribute))
}

fn value(token: &str) -> &str {
    token.split_once('=').map_or("", |(_, value)| value)
}

fn duplicate(element: &str) -> ParseStep {
    Err(RichRuleAnalysis::Unsupported(
        RichRuleUnsupported::DuplicateElement(element.to_owned()),
    ))
}

fn missing(element: &str, attribute: &str) -> RichRuleAnalysis {
    RichRuleAnalysis::Malformed(RichRuleMalformed::MissingAttribute {
        element: element.to_owned(),
        attribute: attribute.to_owned(),
    })
}

fn malformed(element: &str, value: &str) -> ParseStep {
    Err(malformed_analysis(element, value))
}

fn malformed_analysis(element: &str, value: &str) -> RichRuleAnalysis {
    RichRuleAnalysis::Malformed(RichRuleMalformed::InvalidValue {
        element: element.to_owned(),
        value: value.to_owned(),
    })
}

impl fmt::Display for RichRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    const RULE: &str = r#"rule family="ipv4" source address="203.0.113.0/24" reject"#;
    const SUPPORTED: &str =
        include_str!("../../tests/fixtures/traffic_testing/rich_rules/supported.txt");
    const UNSUPPORTED: &str =
        include_str!("../../tests/fixtures/traffic_testing/rich_rules/unsupported.txt");
    const MALFORMED: &str =
        include_str!("../../tests/fixtures/traffic_testing/rich_rules/malformed.txt");

    fn fixture_rows(raw: &str) -> impl Iterator<Item = (&str, &str)> {
        raw.lines().map(|line| line.split_once('|').unwrap())
    }

    #[test]
    fn keeps_raw_text_verbatim() {
        let rule = RichRule::parse(RULE).unwrap();
        assert_eq!(rule.as_str(), RULE);
    }

    #[test]
    fn extracts_family_and_action() {
        let rule = RichRule::parse(RULE).unwrap();
        assert_eq!(rule.family(), Some("ipv4"));
        assert_eq!(rule.action(), Some("reject"));
    }

    #[test]
    fn supported_fixtures_produce_typed_traffic_expressions() {
        for (label, raw) in fixture_rows(SUPPORTED) {
            let rule = RichRule::parse(raw).unwrap();
            let RichRuleAnalysis::Supported(expression) = rule.analyze() else {
                panic!("supported fixture `{label}` was not supported");
            };
            assert_eq!(
                rule.as_str(),
                raw,
                "raw mutation text changed for `{label}`"
            );
            assert!(matches!(
                expression.action,
                RichRuleAction::Accept | RichRuleAction::Reject | RichRuleAction::Drop
            ));
        }
    }

    #[test]
    fn supported_fixture_fields_are_preserved_exactly() {
        let rules: std::collections::BTreeMap<_, _> = fixture_rows(SUPPORTED).collect();
        let analyze = |label: &str| {
            let RichRuleAnalysis::Supported(expression) =
                RichRule::parse(rules[label]).unwrap().analyze()
            else {
                panic!("fixture must be supported");
            };
            expression
        };

        let all = analyze("all-fields");
        assert_eq!(all.family, Some(AddressFamily::Ipv4));
        assert_eq!(all.priority.get(), -100);
        assert_eq!(all.service.unwrap().as_str(), "ssh");
        assert_eq!(all.source.unwrap().address.to_string(), "203.0.113.0/24");
        assert_eq!(all.destination.unwrap().address.to_string(), "192.0.2.10");

        let port = analyze("destination-port").destination_port.unwrap();
        assert_eq!(port.to_string(), "443-445/tcp");
        let source_port = analyze("source-port").source_port.unwrap();
        assert_eq!(source_port.to_string(), "1024-65535/udp");
        assert_eq!(analyze("raw-protocol").protocol.unwrap().as_str(), "gre");
        assert!(analyze("inverted-source").source.unwrap().inverted);
        assert!(
            analyze("inverted-destination")
                .destination
                .unwrap()
                .inverted
        );
    }

    #[test]
    fn unsupported_fixtures_return_typed_reasons() {
        for (label, raw) in fixture_rows(UNSUPPORTED) {
            let rule = RichRule::parse(raw).unwrap();
            let RichRuleAnalysis::Unsupported(reason) = rule.analyze() else {
                panic!("unsupported fixture `{label}` was not classified");
            };
            let exact = match label {
                "rate-limit" => matches!(reason, RichRuleUnsupported::RateLimit),
                "mac-source" => matches!(reason, RichRuleUnsupported::MacAddress),
                "helper" => matches!(reason, RichRuleUnsupported::Helper),
                "mark" => matches!(reason, RichRuleUnsupported::Mark),
                "tcp-mss-clamp" => matches!(reason, RichRuleUnsupported::TcpMssClamp),
                "log-only" => matches!(reason, RichRuleUnsupported::Log),
                "audit-only" => matches!(reason, RichRuleUnsupported::Audit),
                "ipset" => matches!(reason, RichRuleUnsupported::IpSet),
                "unknown" => matches!(reason, RichRuleUnsupported::UnknownElement(_)),
                "duplicate" => matches!(reason, RichRuleUnsupported::DuplicateElement(_)),
                "conflicting" => {
                    matches!(reason, RichRuleUnsupported::ConflictingElements { .. })
                }
                _ => false,
            };
            assert!(exact, "wrong unsupported reason for `{label}`: {reason:?}");
        }
    }

    #[test]
    fn malformed_fixtures_fail_closed() {
        for (label, raw) in fixture_rows(MALFORMED) {
            let rule = RichRule::parse(raw).unwrap();
            let RichRuleAnalysis::Malformed(reason) = rule.analyze() else {
                panic!("malformed fixture `{label}` was not rejected");
            };
            let exact = match label {
                "unterminated-quote" => matches!(reason, RichRuleMalformed::UnterminatedQuote),
                "invalid-cidr" | "invalid-priority" | "invalid-invert" => {
                    matches!(reason, RichRuleMalformed::InvalidValue { .. })
                }
                "missing-action" => matches!(reason, RichRuleMalformed::MissingAction),
                "dangling-source" => {
                    matches!(reason, RichRuleMalformed::MissingAttribute { .. })
                }
                _ => false,
            };
            assert!(exact, "wrong malformed reason for `{label}`: {reason:?}");
        }
    }

    #[test]
    fn rejects_non_rule_text() {
        assert!(RichRule::parse("drop everything").is_err());
    }

    #[test]
    fn requires_rule_as_a_whole_word() {
        assert!(
            RichRule::parse("ruleset foo").is_err(),
            "prefix is not a word"
        );
        assert!(RichRule::parse("rulefoo bar").is_err());
        assert!(
            RichRule::parse("rule").is_err(),
            "a bare `rule` has no body"
        );
    }

    #[test]
    fn rejects_control_characters() {
        // A newline could smuggle a second line into the audit trail / display.
        assert!(RichRule::parse("rule family=\"ipv4\"\ndrop").is_err());
        assert!(RichRule::parse("rule\taccept").is_err());
        assert!(RichRule::parse("rule accept\0").is_err());
    }
}
