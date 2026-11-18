use regex::Regex;
use serde::{Deserialize, Serialize};

use proxmox_match_expression::Expression;
use proxmox_schema::api_types::SAFE_ID_REGEX;

use crate::{Error, Notification, api_types::expression::NotificationMatcher};

use super::MatchDirective;

/// Check if the notification metadata fields match
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", untagged, deny_unknown_fields)]
pub enum FieldMatcher {
    Exact {
        field: String,
        values: Vec<String>,
    },
    Regex {
        field: String,
        #[serde(with = "serde_regex")]
        regex: Regex,
    },
}

impl From<FieldMatcher> for Expression<NotificationMatcher> {
    fn from(value: FieldMatcher) -> Self {
        Expression::Match(NotificationMatcher::Field(value))
    }
}

// `Regex` does not implement `PartialEq`, so compare the regex patterns instead.
impl PartialEq for FieldMatcher {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Exact { field, values },
                Self::Exact {
                    field: other_field,
                    values: other_values,
                },
            ) => field == other_field && values == other_values,
            (
                Self::Regex { field, regex },
                Self::Regex {
                    field: other_field,
                    regex: other_regex,
                },
            ) => field == other_field && regex.as_str() == other_regex.as_str(),
            _ => false,
        }
    }
}

impl MatchDirective for FieldMatcher {
    fn matches(&self, notification: &Notification) -> Result<bool, Error> {
        Ok(match self {
            FieldMatcher::Exact { field, values } => {
                let value = notification.metadata.additional_fields.get(field);

                if let Some(value) = value {
                    values.contains(value)
                } else {
                    // Metadata field does not exist, so we do not match
                    false
                }
            }
            FieldMatcher::Regex { field, regex } => {
                let value = notification.metadata.additional_fields.get(field);

                if let Some(value) = value {
                    regex.is_match(value)
                } else {
                    // Metadata field does not exist, so we do not match
                    false
                }
            }
        })
    }

    fn validate(&self) -> Result<(), Error> {
        match self {
            FieldMatcher::Exact { field, values } => {
                if values.is_empty() {
                    return Err(Error::invalid_config(
                        "field matcher must contain values to match",
                    ));
                }
                if !SAFE_ID_REGEX.is_match(field) {
                    return Err(Error::invalid_config(format!(
                        "field name '{field}' does not match regex pattern",
                    )));
                }
            }
            FieldMatcher::Regex { field, .. } => {
                if !SAFE_ID_REGEX.is_match(field) {
                    return Err(Error::invalid_config(format!(
                        "field name '{field}' does not match regex pattern",
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(feature = "legacy-matchers")]
pub mod inline {
    use std::{fmt, str::FromStr};

    use const_format::concatcp;

    use proxmox_schema::{api_types::SAFE_ID_REGEX_STR, const_regex};

    use super::*;

    const_regex! {
        pub MATCH_FIELD_ENTRY_REGEX = concatcp!(r"^(?:(exact|regex):)?(", SAFE_ID_REGEX_STR, r")=(.*)$");
    }

    /// Check if the notification metadata fields match
    /// This is a wrapper that serializes into an inline format that can be used
    /// in a section config key-value pair.
    #[derive(Clone, Debug, PartialEq)]
    pub struct InlineFieldMatcher(FieldMatcher);

    impl MatchDirective for InlineFieldMatcher {
        fn matches(&self, notification: &Notification) -> Result<bool, Error> {
            self.0.matches(notification)
        }

        fn validate(&self) -> Result<(), Error> {
            self.0.validate()
        }
    }

    impl fmt::Display for InlineFieldMatcher {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            // Attention, Display is used to implement Serialize, do not
            // change the format.

            match &self.0 {
                FieldMatcher::Exact {
                    field,
                    values: matched_values,
                } => {
                    let values = matched_values.join(",");
                    write!(f, "exact:{field}={values}")
                }
                FieldMatcher::Regex {
                    field,
                    regex: matched_regex,
                } => {
                    let re = matched_regex.as_str();
                    write!(f, "regex:{field}={re}")
                }
            }
        }
    }

    impl FromStr for InlineFieldMatcher {
        type Err = Error;
        fn from_str(s: &str) -> Result<Self, Error> {
            if !MATCH_FIELD_ENTRY_REGEX.is_match(s) {
                return Err(Error::invalid_config(format!(
                    "invalid match-field statement: {s}"
                )));
            }

            if let Some(remaining) = s.strip_prefix("regex:") {
                match remaining.split_once('=') {
                    None => Err(Error::invalid_config(format!(
                        "invalid match-field statement: {s}"
                    ))),
                    Some((field, expected_value_regex)) => {
                        let regex = Regex::new(expected_value_regex).map_err(|err| {
                            Error::invalid_config_with_source("invalid regex", err)
                        })?;

                        Ok(Self(FieldMatcher::Regex {
                            field: field.into(),
                            regex,
                        }))
                    }
                }
            } else if let Some(remaining) = s.strip_prefix("exact:") {
                match remaining.split_once('=') {
                    None => Err(Error::invalid_config(format!(
                        "invalid match-field statement: {s}"
                    ))),
                    Some((field, expected_values)) => {
                        let values: Vec<String> = expected_values
                            .split(',')
                            .map(str::trim)
                            .map(String::from)
                            .collect();
                        Ok(Self(FieldMatcher::Exact {
                            field: field.into(),
                            values,
                        }))
                    }
                }
            } else {
                Err(Error::invalid_config(format!(
                    "invalid match-field statement: {s}"
                )))
            }
        }
    }

    impl InlineFieldMatcher {
        pub fn into_inner(self) -> FieldMatcher {
            self.0
        }
    }

    proxmox_serde::forward_deserialize_to_from_str!(InlineFieldMatcher);
    proxmox_serde::forward_serialize_to_display!(InlineFieldMatcher);

    #[cfg(test)]
    mod tests {
        use std::collections::HashMap;

        use serde_json::Value;

        use crate::Severity;

        use super::*;

        #[test]
        fn test_matching() {
            let mut fields = HashMap::new();
            fields.insert("foo".to_string(), "bar".to_string());

            let notification = Notification::template_builder("test", Value::Null)
                .fields(fields)
                .severity(Severity::Notice)
                .build()
                .unwrap();

            let matcher: InlineFieldMatcher = "exact:foo=bar".parse().unwrap();
            assert!(matcher.matches(&notification).unwrap());

            let matcher: InlineFieldMatcher = "regex:foo=b.*".parse().unwrap();
            assert!(matcher.matches(&notification).unwrap());

            let matcher: InlineFieldMatcher = "regex:notthere=b.*".parse().unwrap();
            assert!(!matcher.matches(&notification).unwrap());

            let matcher: InlineFieldMatcher = "exact:foo=bar,test".parse().unwrap();
            assert!(matcher.matches(&notification).unwrap());

            let mut fields = HashMap::new();
            fields.insert("foo".to_string(), "test".to_string());

            let notification = Notification::template_builder("test", Value::Null)
                .fields(fields)
                .severity(Severity::Notice)
                .build()
                .unwrap();
            assert!(matcher.matches(&notification).unwrap());

            let mut fields = HashMap::new();
            fields.insert("foo".to_string(), "notthere".to_string());

            let notification = Notification::template_builder("test", Value::Null)
                .fields(fields)
                .severity(Severity::Notice)
                .build()
                .unwrap();
            assert!(!matcher.matches(&notification).unwrap());

            assert!("regex:'3=b.*".parse::<InlineFieldMatcher>().is_err());
            assert!("invalid:'bar=b.*".parse::<InlineFieldMatcher>().is_err());
        }
    }
}

#[cfg(feature = "legacy-matchers")]
pub use inline::*;
