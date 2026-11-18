use std::collections::{HashMap, HashSet};

use proxmox_uuid::Uuid;
use serde::Deserialize;
use serde_json::json;
use tracing::{error, info};

use crate::api_types::{GOTIFY_TYPENAME, GotifyConfig, GotifyPrivateConfig};
use crate::api_types::{MATCHER_TYPENAME, MatcherConfig};
use crate::api_types::{SENDMAIL_TYPENAME, SendmailConfig};
use crate::api_types::{SMTP_TYPENAME, SmtpConfig, SmtpPrivateConfig};
use crate::api_types::{WEBHOOK_TYPENAME, WebhookConfig, WebhookPrivateConfig};
use crate::endpoints::Endpoint;
use crate::endpoints::gotify::GotifyEndpoint;
use crate::endpoints::sendmail::SendmailEndpoint;
use crate::endpoints::smtp::SmtpEndpoint;
use crate::endpoints::webhook::WebhookEndpoint;
use crate::{Config, Content, Context, Error, Metadata, Notification, Severity};

/// Send a notification to a given target.
///
/// The caller is responsible for any needed permission checks.
/// Returns an `anyhow::Error` in case of an error.
pub fn send(context: &Context, config: &Config, notification: &Notification) -> Result<(), Error> {
    let bus = Bus::from_config(config)?;
    bus.send(context, notification);

    Ok(())
}

/// Test target (group or single endpoint) identified by its `name`.
///
/// The caller is responsible for any needed permission checks.
/// Returns an `anyhow::Error` if sending via the endpoint failed.
pub fn test_target(context: &Context, config: &Config, endpoint: &str) -> Result<(), Error> {
    let bus = Bus::from_config(config)?;
    bus.test_target(context, endpoint)?;

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

macro_rules! parse_endpoints_with_private_config {
    ($config:ident, $public_config:ty, $private_config:ty, $endpoint_type:ident, $type_name:expr) => {
        (|| -> Result<Vec<Box<dyn Endpoint>>, Error> {
            let mut endpoints = Vec::<Box<dyn Endpoint>>::new();

            let configs: Vec<$public_config> = $config
                .config
                .convert_to_typed_array($type_name)
                .map_err(|err| Error::ConfigDeserialization(err.into()))?;

            for config in configs {
                match $config.private_config.sections.get(&config.name) {
                    Some((section_type_name, private_config)) => {
                        if $type_name != section_type_name {
                            error!(
                                "Could not instantiate endpoint '{name}': \
                                private config has wrong type",
                                name = config.name
                            );
                        }
                        let private_config = <$private_config>::deserialize(private_config)
                            .map_err(|err| Error::ConfigDeserialization(err.into()))?;

                        endpoints.push(Box::new($endpoint_type {
                            config,
                            private_config: private_config.clone(),
                        }));
                    }
                    None => error!(
                        "Could not instantiate endpoint '{name}': \
                            private config does not exist",
                        name = config.name
                    ),
                }
            }

            Ok(endpoints)
        })()
    };
}

macro_rules! parse_endpoints_without_private_config {
    ($config:ident, $public_config:ty, $endpoint_type:ident, $type_name:expr) => {
        (|| -> Result<Vec<Box<dyn Endpoint>>, Error> {
            let mut endpoints = Vec::<Box<dyn Endpoint>>::new();

            let configs: Vec<$public_config> = $config
                .config
                .convert_to_typed_array($type_name)
                .map_err(|err| Error::ConfigDeserialization(err.into()))?;

            for config in configs {
                endpoints.push(Box::new($endpoint_type { config }));
            }

            Ok(endpoints)
        })()
    };
}

impl Bus {
    /// Instantiate notification bus from a given configuration.
    pub fn from_config(config: &Config) -> Result<Self, Error> {
        let mut endpoints = HashMap::new();

        // Instantiate endpoints
        endpoints.extend(
            parse_endpoints_without_private_config!(
                config,
                SendmailConfig,
                SendmailEndpoint,
                SENDMAIL_TYPENAME
            )?
            .into_iter()
            .map(|e| (e.name().into(), e)),
        );

        endpoints.extend(
            parse_endpoints_with_private_config!(
                config,
                GotifyConfig,
                GotifyPrivateConfig,
                GotifyEndpoint,
                GOTIFY_TYPENAME
            )?
            .into_iter()
            .map(|e| (e.name().into(), e)),
        );

        endpoints.extend(
            parse_endpoints_with_private_config!(
                config,
                SmtpConfig,
                SmtpPrivateConfig,
                SmtpEndpoint,
                SMTP_TYPENAME
            )?
            .into_iter()
            .map(|e| (e.name().into(), e)),
        );

        endpoints.extend(
            parse_endpoints_with_private_config!(
                config,
                WebhookConfig,
                WebhookPrivateConfig,
                WebhookEndpoint,
                WEBHOOK_TYPENAME
            )?
            .into_iter()
            .map(|e| (e.name().into(), e)),
        );

        let matchers = config
            .config
            .convert_to_typed_array(MATCHER_TYPENAME)
            .map_err(|err| Error::ConfigDeserialization(err.into()))?;

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
        let targets = self.check_matches(notification);

        for target in targets {
            if let Some(endpoint) = self.endpoints.get(target) {
                let name = endpoint.name();

                if endpoint.disabled() {
                    // Skip this target if it is disabled
                    info!("skipping disabled target '{name}'");
                    continue;
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
    }

    /// Send a test notification to a target (endpoint or group).
    ///
    /// In contrast to the `send` function, this function will return
    /// any errors to the caller.
    pub fn test_target(&self, context: &Context, target: &str) -> Result<(), Error> {
        let notification = Notification {
            metadata: Metadata {
                severity: Severity::Info,
                // TODO: what fields would make sense for test notifications?
                additional_fields: Default::default(),
                timestamp: proxmox_time::epoch_i64(),
            },
            content: Content::Template {
                template_name: "test".to_string(),
                data: json!({ "target": target }),
            },
            id: Uuid::generate(),
        };

        if let Some(endpoint) = self.endpoints.get(target) {
            endpoint.send(context, &notification)?;
        } else {
            return Err(Error::target_does_not_exist(target));
        }

        Ok(())
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
            &Notification::from_template(
                Severity::Info,
                "test",
                Default::default(),
                Default::default(),
            ),
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
            let notification = Notification::from_template(
                severity,
                "test",
                Default::default(),
                Default::default(),
            );

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
