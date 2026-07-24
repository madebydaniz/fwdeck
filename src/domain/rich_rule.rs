//! Rich rules are kept as validated raw strings. Parsing is display-only:
//! mutations always pass the original text back to firewalld, so we never
//! reconstruct (and therefore never corrupt) a rule.

use std::fmt;

use super::ids::ValidationError;

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
}

impl fmt::Display for RichRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const RULE: &str = r#"rule family="ipv4" source address="203.0.113.0/24" reject"#;

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
