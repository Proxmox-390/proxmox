//! Types describing the outcome of sending a notification.
//!
//! Sending a notification yields a [`Receipt`], which records how the notification was routed and
//! whether it reached its destinations:
//!
//! - One [`MatcherReceipt`] per configured matcher, if the notification was routed through the
//!   matchers. It states whether the matcher matched, did not match, was disabled or failed to
//!   be evaluated. For evaluated matchers, it also contains the evaluated match expression, which
//!   shows why the notification was or was not matched.
//! - One [`TargetReceipt`] per target the notification was dispatched to, stating whether the
//!   notification was delivered, the target was disabled, or delivery failed. Notifications sent
//!   to email addresses directly get a single receipt listing these addresses instead of a target.
//!
//! Delivery failures are reported in the receipt rather than as an error, so that the caller can
//! inspect the result of every single target, even if only some of them failed.

use serde::{Deserialize, Serialize};

use proxmox_match_expression::EvaluatedExpressionWithResult;

use crate::api_types::expression::NotificationMatcher;

/// Outcome of sending a single notification.
///
/// Records which matchers were evaluated and which targets the notification was dispatched to,
/// together with the result for each of them.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct Receipt {
    pub(crate) target_receipts: Vec<TargetReceipt>,
    pub(crate) matcher_receipts: Vec<MatcherReceipt>,
}

impl Receipt {
    /// Returns the receipts of all targets the notification was dispatched to.
    pub fn target_receipts(&self) -> &[TargetReceipt] {
        &self.target_receipts
    }

    /// Returns the receipts of all matchers that were evaluated for the notification.
    ///
    /// This is empty if the notification was sent to a target or email recipient directly,
    /// without going through the matchers.
    pub fn matcher_receipts(&self) -> &[MatcherReceipt] {
        &self.matcher_receipts
    }
}

/// Destination a notification was dispatched to.
///
/// Serialized as a `target` or `mailto` property of the [`TargetReceipt`].
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ReceiptDestination {
    /// A configured target, identified by its name.
    Target(String),
    /// Email addresses the notification was sent to directly, without a configured target.
    Mailto(Vec<String>),
}

/// Result of dispatching a notification to a single target.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct TargetReceipt {
    #[serde(flatten)]
    pub(crate) destination: ReceiptDestination,
    #[serde(flatten)]
    pub(crate) status: TargetReceiptStatus,
    pub(crate) timestamp: i64,
}

impl TargetReceipt {
    /// Returns where the notification was dispatched to.
    pub fn destination(&self) -> &ReceiptDestination {
        &self.destination
    }

    /// Returns the name of the target, or `None` if the notification was sent to email addresses
    /// directly.
    pub fn target(&self) -> Option<&str> {
        match &self.destination {
            ReceiptDestination::Target(name) => Some(name),
            ReceiptDestination::Mailto(_) => None,
        }
    }

    /// Returns the delivery status for this target.
    pub fn status(&self) -> &TargetReceiptStatus {
        &self.status
    }

    /// Returns the time the delivery attempt finished, as seconds since the UNIX epoch.
    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }
}

/// Delivery status of a notification for a single target.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum TargetReceiptStatus {
    /// The notification was -- to the best of our knowledge -- delivered successfully.
    Delivered,
    /// Target was disabled.
    Disabled,
    /// The notification was -- to the best of our knowledge -- not delivered to the recipient.
    #[serde(rename_all = "kebab-case")]
    Error {
        /// Human-readable description of the error.
        error_message: String,
    },
}

/// Result of evaluating a single notification matcher.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub enum MatcherReceiptStatus {
    /// The matcher's expression matched the notification.
    #[serde(rename_all = "kebab-case")]
    Matched {
        /// The evaluated match expression, including the results of its sub-expressions.
        evaluated_expression: EvaluatedExpressionWithResult<NotificationMatcher>,
        /// Targets configured for this matcher, which the notification is dispatched to.
        targets: Vec<String>,
    },
    /// The matcher's expression did not match the notification.
    #[serde(rename_all = "kebab-case")]
    NoMatch {
        /// The evaluated match expression, including the results of its sub-expressions.
        evaluated_expression: EvaluatedExpressionWithResult<NotificationMatcher>,
    },
    /// Matcher was disabled and therefore not evaluated.
    Disabled,
    /// The matcher could not be evaluated. Its targets were not notified on its behalf.
    #[serde(rename_all = "kebab-case")]
    Error {
        /// Human-readable description of the error.
        error_message: String,
    },
}

/// Result of evaluating a single notification matcher, identified by its name.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MatcherReceipt {
    pub(crate) matcher: String,
    #[serde(flatten)]
    pub(crate) status: MatcherReceiptStatus,
}

impl MatcherReceipt {
    /// Returns the name of the matcher.
    pub fn matcher(&self) -> &str {
        &self.matcher
    }

    /// Returns the evaluation result of the matcher.
    pub fn status(&self) -> &MatcherReceiptStatus {
        &self.status
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn target_receipt_serialization() {
        let receipts = [
            (
                TargetReceipt {
                    destination: ReceiptDestination::Target("mail-to-root".into()),
                    status: TargetReceiptStatus::Delivered,
                    timestamp: 1000,
                },
                json!({"target": "mail-to-root", "status": "delivered", "timestamp": 1000}),
            ),
            (
                TargetReceipt {
                    destination: ReceiptDestination::Mailto(vec!["root@example.com".into()]),
                    status: TargetReceiptStatus::Error {
                        error_message: "failed".into(),
                    },
                    timestamp: 1000,
                },
                json!({
                    "mailto": ["root@example.com"],
                    "status": "error",
                    "error-message": "failed",
                    "timestamp": 1000,
                }),
            ),
        ];

        for (receipt, expected) in receipts {
            assert_eq!(serde_json::to_value(&receipt).unwrap(), expected);

            let deserialized: TargetReceipt = serde_json::from_value(expected).unwrap();
            assert_eq!(deserialized.destination, receipt.destination);
            assert_eq!(deserialized.status, receipt.status);
            assert_eq!(deserialized.timestamp, receipt.timestamp);
        }
    }
}
