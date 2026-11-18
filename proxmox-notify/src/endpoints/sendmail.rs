use proxmox_sendmail::Mail;

use crate::api_types::SendmailConfig;
use crate::endpoints::common::mail;
use crate::renderer::TemplateType;
use crate::{Content, Context, Error, Notification, renderer};

use super::Endpoint;

/// A sendmail notification endpoint.
pub struct SendmailEndpoint {
    pub config: SendmailConfig,
}

impl Endpoint for SendmailEndpoint {
    fn send(&self, context: &Context, notification: &Notification) -> Result<(), Error> {
        let recipients = mail::get_recipients(
            context,
            self.config.mailto.as_slice(),
            self.config.mailto_user.as_slice(),
        );

        let recipients_str: Vec<&str> = recipients.iter().map(String::as_str).collect();
        let mailfrom = self
            .config
            .from_address
            .clone()
            .unwrap_or_else(|| context.default_sendmail_from());

        match &notification.content {
            Content::Template {
                template_name,
                data,
            } => {
                let subject =
                    renderer::render_template(context, TemplateType::Subject, template_name, data)?;
                let html_part = renderer::render_template(
                    context,
                    TemplateType::HtmlBody,
                    template_name,
                    data,
                )?;
                let text_part = renderer::render_template(
                    context,
                    TemplateType::PlaintextBody,
                    template_name,
                    data,
                )?;

                let author = self
                    .config
                    .author
                    .clone()
                    .unwrap_or_else(|| context.default_sendmail_author());

                let mut mail = Mail::new(&author, &mailfrom, &subject, &text_part)
                    .with_html_alt(&html_part)
                    .with_unmasked_recipients();

                recipients_str.iter().for_each(|r| mail.add_recipient(r));

                mail.send().map_err(|err| {
                    Error::other_with_source("could not send mail via sendmail", err)
                })
            }
            #[cfg(feature = "mail-forwarder")]
            Content::ForwardedMail { raw, uid, .. } => {
                Mail::forward(&recipients_str, &mailfrom, raw, *uid).map_err(|err| {
                    Error::other_with_source("could not forward mail via sendmail", err)
                })
            }
        }
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool {
        self.config.disable.unwrap_or_default()
    }
}
