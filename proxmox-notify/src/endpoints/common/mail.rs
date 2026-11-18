use crate::Context;
use crate::Error;

/// Get list of email recipients from a list of email addresses and users.
///
/// Any user passed in the user list will be looked up in the user configuration to
/// obtain this user's email address. The list of returned email addresses does
/// not contain any duplicates.
pub(crate) fn get_recipients(
    context: &Context,
    email_addrs: &[String],
    users: &[String],
) -> Vec<String> {
    let mut recipients = Vec::new();

    for addr in email_addrs {
        if !recipients.contains(addr) {
            recipients.push(addr.clone());
        }
    }

    for user in users {
        match context.lookup_email_for_user(user) {
            Some(address) => {
                if !recipients.contains(&address) {
                    recipients.push(address);
                }
            }
            None => tracing::warn!(
                "'{user}' does not have a configured email address in the user configuration - \
                not sending an email to this user"
            ),
        }
    }
    recipients
}

/// Parse raw email message and return subject and plaintext body
pub(crate) fn parse_subject_and_plaintext_body(raw_mail: &[u8]) -> Result<(String, String), Error> {
    let message = mail_parser::MessageParser::default()
        .parse(raw_mail)
        .ok_or_else(|| Error::invalid_forwarded_message("could not parse forwarded email"))?;

    let title = message.subject().unwrap_or_default().into();
    let body = message.body_text(0).unwrap_or_default().into();

    Ok((title, body))
}

#[cfg(test)]
mod tests {
    use crate::context::test;

    use super::*;

    #[test]
    fn test_get_recipients() {
        let emails = Vec::from(
            [
                "test1@example.com",
                "test2@example.com",
                "test2@example.com",
            ]
            .map(Into::into),
        );
        let users =
            Vec::from(["user1@pve", "user2@pve", "user2@pve", "user3@invalid"].map(Into::into));

        let expected = [
            "test1@example.com",
            "test2@example.com",
            "user1@example.com",
            "user2@example.com",
        ];

        let context = test::test_context();

        let addrs = get_recipients(&context, &emails, &users);

        assert_eq!(addrs, expected);
    }
}
