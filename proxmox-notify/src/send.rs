use std::collections::{HashMap, HashSet};

use proxmox_section_config::typed::{convert_to_typed_array, lookup};
use tracing::{error, info};

use crate::api_types::{MatcherConfig, SendmailConfig};
use crate::config::{ConfigEntity, PrivateConfigEntity};
use crate::endpoints::Endpoint;
use crate::endpoints::gotify::GotifyEndpoint;
use crate::endpoints::sendmail::SendmailEndpoint;
use crate::endpoints::smtp::SmtpEndpoint;
use crate::endpoints::webhook::WebhookEndpoint;
use crate::{Config, Context, EmailRecipient, Error, Notification, Recipient};

/// Send a notification to a given target.
///
/// The caller is responsible for any needed permission checks.
/// Returns an `anyhow::Error` in case of an error.
pub fn send(context: &Context, config: &Config, notification: &Notification) -> Result<(), Error> {
    let bus = Bus::from_config(config)?;
    bus.send(context, notification);

    Ok(())
}

/// Notification bus - distributes notifications to all registered endpoints
// The reason for the split between `Config` and this struct is to make testing with mocked
// endpoints a bit easier.
#[derive(Default)]
struct Bus {
    endpoints: HashMap<String, Box<dyn Endpoint>>,
    matchers: Vec<MatcherConfig>,
}

fn log_missing_private_config(endpoint_name: &str) {
    error!("Could not instantiate endpoint '{endpoint_name}': private config does not exist");
}

impl Bus {
    /// Instantiate notification bus from a given configuration.
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut endpoints = HashMap::new();

        for endpoint_config in convert_to_typed_array!(config.config, ConfigEntity::Sendmail) {
            endpoints.insert(
                endpoint_config.name.clone(),
                Box::new(SendmailEndpoint {
                    config: endpoint_config.clone(),
                }) as Box<dyn Endpoint>,
            );
        }

        for endpoint_config in convert_to_typed_array!(config.config, ConfigEntity::Gotify) {
            if let Some(private_config) = lookup!(
                config.private_config,
                &endpoint_config.name,
                PrivateConfigEntity::Gotify
            ) {
                endpoints.insert(
                    endpoint_config.name.clone(),
                    Box::new(GotifyEndpoint {
                        config: endpoint_config.clone(),
                        private_config: private_config.clone(),
                    }) as Box<dyn Endpoint>,
                );
            } else {
                log_missing_private_config(&endpoint_config.name);
            }
        }

        for endpoint_config in convert_to_typed_array!(config.config, ConfigEntity::Webhook) {
            if let Some(private_config) = lookup!(
                config.private_config,
                &endpoint_config.name,
                PrivateConfigEntity::Webhook
            ) {
                endpoints.insert(
                    endpoint_config.name.clone(),
                    Box::new(WebhookEndpoint {
                        config: endpoint_config.clone(),
                        private_config: private_config.clone(),
                    }) as Box<dyn Endpoint>,
                );
            } else {
                log_missing_private_config(&endpoint_config.name);
            }
        }

        for endpoint_config in convert_to_typed_array!(config.config, ConfigEntity::Smtp) {
            if let Some(private_config) = lookup!(
                config.private_config,
                &endpoint_config.name,
                PrivateConfigEntity::Smtp
            ) {
                endpoints.insert(
                    endpoint_config.name.clone(),
                    Box::new(SmtpEndpoint {
                        config: endpoint_config.clone(),
                        private_config: private_config.clone(),
                    }) as Box<dyn Endpoint>,
                );
            } else {
                log_missing_private_config(&endpoint_config.name);
            }
        }

        let matchers = convert_to_typed_array!(config.config, ConfigEntity::Matcher)
            .into_iter()
            .cloned()
            .collect();

        Ok(Bus {
            endpoints,
            matchers,
        })
    }

    #[cfg(test)]
    pub(crate) fn add_endpoint(&mut self, endpoint: Box<dyn Endpoint>) {
        self.endpoints.insert(endpoint.name().to_string(), endpoint);
    }

    #[cfg(test)]
    pub(crate) fn add_matcher(&mut self, filter: MatcherConfig) {
        self.matchers.push(filter)
    }

    /// Send a notification. Notification matchers will determine which targets will receive
    /// the notification.
    ///
    /// Any errors will not be returned but only logged.
    pub fn send(&self, context: &Context, notification: &Notification) {
        match notification.recipient() {
            Recipient::Email(params) => self.send_to_email(context, notification, params),
            Recipient::Target(target) => {
                self.send_to_target(context, notification, target);
            }
            Recipient::Matcher => {
                let targets = self.check_matches(notification);

                for target in targets {
                    self.send_to_target(context, notification, target);
                }
            }
        }
    }

    fn send_to_email(
        &self,
        context: &Context,
        notification: &Notification,
        email_recipient: &EmailRecipient,
    ) {
        let recipient_list = email_recipient.mailto.join(", ");

        let endpoint = SendmailEndpoint {
            config: SendmailConfig {
                name: "legacy-sendmail".into(),
                mailto: email_recipient.mailto.clone(),
                author: email_recipient.author.clone(),
                ..Default::default()
            },
        };

        match endpoint.send(context, notification) {
            Ok(_) => {
                info!("notified via `{recipient_list}`");
            }
            Err(e) => {
                // Only log on errors, do not propagate fail to the caller.
                error!("could not notify via `{recipient_list}`: {e}");
            }
        }
    }

    fn send_to_target(&self, context: &Context, notification: &Notification, target: &str) {
        if let Some(endpoint) = self.endpoints.get(target) {
            let name = endpoint.name();

            if endpoint.disabled() {
                // Skip this target if it is disabled
                info!("skipping disabled target '{name}'");
                return;
            }

            match endpoint.send(context, notification) {
                Ok(_) => {
                    info!("notified via target `{name}`");
                }
                Err(e) => {
                    // Only log on errors, do not propagate fail to the caller.
                    error!("could not notify via target `{name}`: {e}");
                }
            }
        } else {
            error!("could not notify via target '{target}', it does not exist");
        }
    }

    fn check_matches(&self, notification: &Notification) -> HashSet<&str> {
        let mut targets = HashSet::new();
        let mut matching_matchers = Vec::new();

        for matcher in &self.matchers {
            if matcher.disable.unwrap_or_default() {
                // Skip this matcher if it is disabled
                info!("skipping disabled matcher '{name}'", name = matcher.name);
                continue;
            }

            match matcher.matches(notification) {
                Ok(Some(t)) => {
                    matching_matchers.push(matcher.name.as_str());
                    targets.extend(t.iter().map(|s| s.as_str()));
                }
                Ok(None) => {}
                Err(err) => error!("matcher '{matcher}' failed: {err}", matcher = matcher.name),
            }
        }

        if !matching_matchers.is_empty() {
            let target_list = Vec::from_iter(targets.iter().copied());

            info!(
                "notification matched the following matchers: {}. The following targets will be notified: {}",
                matching_matchers.join(", "),
                target_list.join(", ")
            );
        } else {
            info!("notification was not matched by any matcher");
        }

        targets
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use proxmox_match_expression::Expression;

    use crate::{
        Severity,
        api_types::{expression::NotificationMatcher, severity::SeverityMatcher},
        context::{Context, test},
    };

    use super::*;

    #[derive(Default, Clone)]
    struct MockEndpoint {
        name: &'static str,
        // Needs to be an Rc so that we can clone MockEndpoint before
        // passing it to Bus, while still retaining a handle to the Vec
        messages: Rc<RefCell<Vec<Notification>>>,
    }

    impl Endpoint for MockEndpoint {
        fn send(&self, _context: &Context, message: &Notification) -> Result<(), Error> {
            self.messages.borrow_mut().push(message.clone());

            Ok(())
        }

        fn name(&self) -> &str {
            self.name
        }

        fn disabled(&self) -> bool {
            false
        }
    }

    impl MockEndpoint {
        fn new(name: &'static str) -> Self {
            Self {
                name,
                ..Default::default()
            }
        }

        fn messages(&self) -> Vec<Notification> {
            self.messages.borrow().clone()
        }
    }

    fn expression_to_string(expression: Expression<NotificationMatcher>) -> String {
        serde_json::to_string(&expression).unwrap()
    }

    #[test]
    fn test_add_mock_endpoint() -> Result<(), Error> {
        let context = test::test_context();
        let mock = MockEndpoint::new("endpoint");

        let mut bus = Bus::default();
        bus.add_endpoint(Box::new(mock.clone()));

        let matcher = MatcherConfig {
            target: vec!["endpoint".into()],
            expression: Some(expression_to_string(Expression::Constant(true))),
            ..Default::default()
        };

        bus.add_matcher(matcher);

        // Send directly to endpoint
        bus.send(
            &context,
            &Notification::template_builder("test", None::<()>)
                .severity(Severity::Info)
                .build()
                .unwrap(),
        );
        let messages = mock.messages();
        assert_eq!(messages.len(), 1);

        Ok(())
    }

    #[test]
    fn test_multiple_endpoints_with_different_matchers() -> Result<(), Error> {
        let context = test::test_context();

        let endpoint1 = MockEndpoint::new("mock1");
        let endpoint2 = MockEndpoint::new("mock2");

        let mut bus = Bus::default();

        bus.add_endpoint(Box::new(endpoint1.clone()));
        bus.add_endpoint(Box::new(endpoint2.clone()));

        bus.add_matcher(MatcherConfig {
            name: "matcher1".into(),
            expression: Some(expression_to_string(
                SeverityMatcher {
                    severities: vec![Severity::Error, Severity::Warning],
                }
                .into(),
            )),
            target: vec!["mock1".into()],
            ..Default::default()
        });

        bus.add_matcher(MatcherConfig {
            name: "matcher2".into(),
            expression: Some(expression_to_string(
                SeverityMatcher {
                    severities: vec![Severity::Error],
                }
                .into(),
            )),
            target: vec!["mock2".into()],
            ..Default::default()
        });

        let send_with_severity = |severity| {
            let notification = Notification::template_builder("test", None::<()>)
                .severity(severity)
                .build()
                .unwrap();

            bus.send(&context, &notification);
        };

        send_with_severity(Severity::Info);
        assert_eq!(endpoint1.messages().len(), 0);
        assert_eq!(endpoint2.messages().len(), 0);

        send_with_severity(Severity::Warning);
        assert_eq!(endpoint1.messages().len(), 1);
        assert_eq!(endpoint2.messages().len(), 0);

        send_with_severity(Severity::Error);
        assert_eq!(endpoint1.messages().len(), 2);
        assert_eq!(endpoint2.messages().len(), 1);

        Ok(())
    }
}
