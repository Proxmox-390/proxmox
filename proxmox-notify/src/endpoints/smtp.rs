use std::borrow::Cow;
use std::time::Duration;

use lettre::message::header::{HeaderName, HeaderValue};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::client::{Tls, TlsParameters};
use lettre::{Message, SmtpTransport, Transport, message::header::ContentType};

use crate::api_types::{SmtpConfig, SmtpMode, SmtpPrivateConfig};
use crate::endpoints::common::mail;
use crate::renderer::TemplateType;
use crate::{Content, Context, Error, Notification, renderer};

use super::Endpoint;

const SMTP_PORT: u16 = 25;
const SMTP_SUBMISSION_STARTTLS_PORT: u16 = 587;
const SMTP_SUBMISSION_TLS_PORT: u16 = 465;
const SMTP_TIMEOUT: u16 = 5;

/// A sendmail notification endpoint.
pub struct SmtpEndpoint {
    pub config: SmtpConfig,
    pub private_config: SmtpPrivateConfig,
}

impl Endpoint for SmtpEndpoint {
    fn send(&self, context: &Context, notification: &Notification) -> Result<(), Error> {
        let tls_parameters = TlsParameters::new(self.config.server.clone())
            .map_err(|err| Error::invalid_config_with_source("invalid SMTP server name", err))?;

        let (port, tls) = match self.config.mode.unwrap_or_default() {
            SmtpMode::Insecure => {
                let port = self.config.port.unwrap_or(SMTP_PORT);
                (port, Tls::None)
            }
            SmtpMode::StartTls => {
                let port = self.config.port.unwrap_or(SMTP_SUBMISSION_STARTTLS_PORT);
                (port, Tls::Required(tls_parameters))
            }
            SmtpMode::Tls => {
                let port = self.config.port.unwrap_or(SMTP_SUBMISSION_TLS_PORT);
                (port, Tls::Wrapper(tls_parameters))
            }
        };

        let mut transport_builder = SmtpTransport::builder_dangerous(&self.config.server)
            .tls(tls)
            .port(port)
            .timeout(Some(Duration::from_secs(SMTP_TIMEOUT.into())));

        if let Some(username) = self.config.username.as_deref() {
            if let Some(password) = self.private_config.password.as_deref() {
                transport_builder = transport_builder.credentials((username, password).into());
            } else {
                return Err(Error::invalid_config(
                    "username is set but no password was provided",
                ));
            }
        }

        let transport = transport_builder.build();

        let recipients = mail::get_recipients(
            context,
            self.config.mailto.as_slice(),
            self.config.mailto_user.as_slice(),
        );
        let mail_from = self.config.from_address.clone();

        let parse_address = |addr: &str| -> Result<Mailbox, Error> {
            addr.parse().map_err(|err| {
                Error::invalid_config_with_source(
                    format!("could not parse email address '{addr}'"),
                    err,
                )
            })
        };

        let author = self
            .config
            .author
            .clone()
            .unwrap_or_else(|| context.default_sendmail_author());

        let quoted_author = quote_name_if_needed(&author);

        let mut email_builder =
            Message::builder().from(parse_address(&format!("{quoted_author} <{mail_from}>"))?);

        for recipient in recipients {
            email_builder = email_builder.to(parse_address(&recipient)?);
        }

        let mut email = match &notification.content {
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

                email_builder = email_builder.subject(subject);

                email_builder
                    .multipart(
                        MultiPart::alternative()
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_PLAIN)
                                    .body(text_part),
                            )
                            .singlepart(
                                SinglePart::builder()
                                    .header(ContentType::TEXT_HTML)
                                    .body(html_part),
                            ),
                    )
                    .map_err(|err| {
                        Error::invalid_config_with_source("could not build email message", err)
                    })?
            }
            #[cfg(feature = "mail-forwarder")]
            Content::ForwardedMail { raw, .. } => build_forwarded_message(email_builder, raw)?,
        };

        // `Auto-Submitted` is defined in RFC 5436 and describes how
        // an automatic response (f.e. ooo replies, etc.) should behave on the
        // emails. When using `Auto-Submitted: auto-generated` (or any value
        // other than `none`) automatic replies won't be triggered.
        email.headers_mut().insert_raw(HeaderValue::new(
            HeaderName::new_from_ascii_str("Auto-Submitted"),
            "auto-generated;".into(),
        ));

        transport.send(&email).map_err(Error::smtp_error)?;

        Ok(())
    }

    fn name(&self) -> &str {
        &self.config.name
    }

    /// Check if the endpoint is disabled
    fn disabled(&self) -> bool {
        self.config.disable.unwrap_or_default()
    }
}

/// Construct a lettre `Message` from a raw email message.
#[cfg(feature = "mail-forwarder")]
fn build_forwarded_message(
    email_builder: lettre::message::MessageBuilder,
    raw: &[u8],
) -> Result<Message, Error> {
    use lettre::message::Body;
    use lettre::message::header::ContentTransferEncoding;
    use tracing::error;

    let parsed_message = mail_parser::MessageParser::default()
        .parse(raw)
        .ok_or_else(|| Error::invalid_forwarded_message("could not parse forwarded email"))?;

    let root_part = parsed_message
        .part(0)
        .ok_or_else(|| Error::invalid_forwarded_message("root message part not present"))?;

    let raw_body = &parsed_message.raw_message()
        [root_part.offset_body as usize..root_part.offset_end as usize];

    // We assume that the original message content is already properly
    // encoded, thus we add the original message body in 'Binary' encoding.
    // This prohibits lettre from trying to re-encode our raw body data.
    // lettre will automatically set the `Content-Transfer-Encoding: binary` header,
    // which we need to remove. The actual transfer encoding is later
    // copied from the original message headers.
    //
    // lettre sends byte bodies as they are and only dot-stuffs lines that follow a CRLF, so
    // forwarded mail with LF line endings needs normalizing first.
    let body = Body::new_with_encoding(
        proxmox_sendmail::normalize_line_endings(raw_body),
        ContentTransferEncoding::Binary,
    )
    .map_err(|_| Error::invalid_forwarded_message("could not create body from raw bytes"))?;
    let mut message = email_builder
        .subject(parsed_message.subject().unwrap_or_default())
        .body(body)
        .map_err(|err| {
            Error::invalid_forwarded_message_with_source("could not build email message", err)
        })?;
    message
        .headers_mut()
        .remove_raw("Content-Transfer-Encoding");

    // Copy over all headers that are relevant to display the original body correctly.
    // Unfortunately this is a bit cumbersome, as we use separate crates for mail parsing (mail-parser)
    // and creating/sending mails (lettre).
    // Note: Other MIME-Headers, such as Content-{ID,Description,Disposition} are only used
    // for body-parts in multipart messages, so we can ignore them for the messages headers.
    // Since we send the original raw body, the part-headers will be included any way.
    for header in parsed_message.headers() {
        let header_name = header.name.as_str();
        // Email headers are case-insensitive, so convert to lowercase...
        let value = match header_name.to_lowercase().as_str() {
            "content-type" => {
                if let mail_parser::HeaderValue::ContentType(ct) = header.value() {
                    // mail_parser does not give us access to the full decoded and unfolded
                    // header value, so we unfortunately need to reassemble it ourselves.
                    // Meh.
                    let mut value = ct.ctype().to_string();
                    if let Some(subtype) = ct.subtype() {
                        value.push('/');
                        value.push_str(subtype);
                    }
                    if let Some(attributes) = ct.attributes() {
                        use std::fmt::Write;

                        for attribute in attributes {
                            let _ =
                                write!(&mut value, "; {}=\"{}\"", attribute.name, attribute.value);
                        }
                    }
                    Some(value)
                } else {
                    None
                }
            }
            "content-transfer-encoding" | "mime-version" => {
                if let mail_parser::HeaderValue::Text(text) = header.value() {
                    Some(text.to_string())
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(value) = value {
            match HeaderName::new_from_ascii(header_name.into()) {
                Ok(name) => {
                    let header = HeaderValue::new(name, value);
                    message.headers_mut().insert_raw(header);
                }
                Err(e) => error!("could not set header: {e}"),
            }
        }
    }

    Ok(message)
}

/// Quote mail name if required by RFC5322.
fn quote_name_if_needed(name: &str) -> Cow<'_, str> {
    // See https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.3
    let needs_quotes = name.chars().any(|c| {
        matches!(
            c,
            '(' | ')' | '<' | '>' | '@' | ',' | ';' | ':' | '\\' | '"' | '[' | ']' | '='
        )
    });

    if needs_quotes {
        // Quoted strings may contain all printable chars except \ and ", they need to be
        // escaped. Non-ASCII UTF-8 characters are later encoded by lettre, we do not
        // need to care about them here.
        let mut result = name.replace(r#"\"#, r#"\\"#);
        result = result.replace(r#"""#, r#"\""#);
        Cow::Owned(format!("\"{result}\""))
    } else {
        Cow::Borrowed(name)
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_quote_mail_name() {
        assert_eq!(
            &quote_name_if_needed("Firstname Lastname"),
            "Firstname Lastname"
        );

        assert_eq!(
            &quote_name_if_needed("Firstname \"Nickname\" Lastname"),
            "\"Firstname \\\"Nickname\\\" Lastname\""
        );

        assert_eq!(
            &quote_name_if_needed("Proxmox VE (somehost)"),
            "\"Proxmox VE (somehost)\""
        );

        assert_eq!(
            &quote_name_if_needed("Firstname \\ Lastname"),
            "\"Firstname \\\\ Lastname\""
        );
    }

    #[cfg(feature = "mail-forwarder")]
    #[test]
    fn test_forward_message_from_raw() {
        use lettre::message::header::Date;

        let input = "testdata/test1.msg";
        let reference = "testdata/test_forward_message_from_raw.ref";

        let mut email_builder =
            Message::builder().from("Sender <sender@example.com>".parse().unwrap());

        email_builder = email_builder.to("Recipient <recipient@example.com>".parse().unwrap());

        let raw_mail = std::fs::read(input).unwrap();
        let mut message = build_forwarded_message(email_builder, &raw_mail).unwrap();

        // The Date header contains the current time, let's just remove it
        // for this test.
        message.headers_mut().remove::<Date>();

        let formatted = message.formatted();

        // Uncomment to update the reference file.
        // std::fs::write(reference, &formatted).unwrap();

        assert_eq!(formatted, std::fs::read(reference).unwrap());
    }
}
