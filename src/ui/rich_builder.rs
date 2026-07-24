//! Guided rich-rule builder: assembles valid firewalld rich-language syntax
//! from a few fields, so operators do not have to hand-write it. The output is
//! parsed through `RichRule::parse` before it can be applied, so a malformed
//! assembly is caught like any other input.

use std::fmt::Write as _;

/// The builder's ordered steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Step {
    /// Address family (ipv4/ipv6/any).
    #[default]
    Family,
    /// Source address or CIDR.
    Source,
    /// Match element (service, port, …).
    Element,
    /// Verdict: accept, reject, or drop.
    Action,
}

/// State of the guided rich-rule builder overlay: collected fields plus the
/// step currently being edited.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RichBuilder {
    /// The step currently being edited.
    pub step: Step,
    /// "ipv4" | "ipv6" | "" (any).
    pub family: String,
    /// Source address/CIDR, or empty for any.
    pub source: String,
    /// e.g. `service name="ssh"` or `port port="8080" protocol="tcp"`, freeform.
    pub element: String,
    /// accept | reject | drop.
    pub action: String,
    /// The current field's text buffer.
    pub buffer: String,
}

impl RichBuilder {
    /// Prompt and example for the current step.
    #[must_use]
    pub fn prompt(&self) -> (&'static str, &'static str) {
        match self.step {
            Step::Family => ("family", "ipv4 | ipv6 | (blank = any)"),
            Step::Source => ("source address", "10.0.0.0/8 | (blank = any)"),
            Step::Element => (
                "match",
                "service name=\"ssh\" | port port=\"80\" protocol=\"tcp\" | (blank)",
            ),
            Step::Action => ("action", "accept | reject | drop"),
        }
    }

    /// Commits the current buffer to the active field and advances. Returns the
    /// assembled rule string once the last step is committed.
    pub fn commit(&mut self) -> Option<String> {
        let value = self.buffer.trim().to_owned();
        self.buffer.clear();
        match self.step {
            Step::Family => {
                self.family = value;
                self.step = Step::Source;
                None
            }
            Step::Source => {
                self.source = value;
                self.step = Step::Element;
                None
            }
            Step::Element => {
                self.element = value;
                self.step = Step::Action;
                None
            }
            Step::Action => {
                self.action = value;
                Some(self.assemble())
            }
        }
    }

    /// Assembles the rich-rule string from the collected fields.
    #[must_use]
    pub fn assemble(&self) -> String {
        let mut rule = String::from("rule");
        if !self.family.is_empty() {
            let _ = write!(rule, " family=\"{}\"", self.family);
        }
        if !self.source.is_empty() {
            let _ = write!(rule, " source address=\"{}\"", self.source);
        }
        if !self.element.is_empty() {
            rule.push(' ');
            rule.push_str(&self.element);
        }
        if !self.action.is_empty() {
            rule.push(' ');
            rule.push_str(&self.action);
        }
        rule
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::field_reassign_with_default)]
mod tests {
    use super::*;
    use crate::domain::RichRule;

    #[test]
    fn builds_a_valid_rule_end_to_end() {
        let mut b = RichBuilder::default();
        b.buffer = "ipv4".into();
        assert!(b.commit().is_none());
        b.buffer = "203.0.113.0/24".into();
        assert!(b.commit().is_none());
        b.buffer = r#"service name="ssh""#.into();
        assert!(b.commit().is_none());
        b.buffer = "reject".into();
        let rule = b.commit().unwrap();
        assert_eq!(
            rule,
            r#"rule family="ipv4" source address="203.0.113.0/24" service name="ssh" reject"#
        );
        assert!(RichRule::parse(&rule).is_ok());
    }

    #[test]
    fn blank_fields_are_omitted() {
        let mut b = RichBuilder::default();
        for value in ["", "", "", "drop"] {
            b.buffer = value.into();
            b.commit();
        }
        assert_eq!(b.assemble(), "rule drop");
    }
}
