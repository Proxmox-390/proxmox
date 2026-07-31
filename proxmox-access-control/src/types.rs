use anyhow::{Error, bail};
use serde::{Deserialize, Serialize};

use const_format::concatcp;

use proxmox_auth_api::types::{Authid, PROXMOX_TOKEN_ID_SCHEMA, Tokenname, Userid};
use proxmox_schema::{
    ApiStringFormat, BooleanSchema, IntegerSchema, Schema, StringSchema, Updater, api,
    api_types::{COMMENT_SCHEMA, SAFE_ID_REGEX_STR, SINGLE_LINE_COMMENT_FORMAT},
    const_regex,
};

pub const ENABLE_USER_SCHEMA: Schema = BooleanSchema::new(
    "Enable the account (default). You can set this to '0' to disable the account.",
)
.default(true)
.schema();

pub const EXPIRE_USER_SCHEMA: Schema = IntegerSchema::new(
    "Account expiration date (seconds since epoch). '0' means no expiration date.",
)
.default(0)
.minimum(0)
.schema();

pub const FIRST_NAME_SCHEMA: Schema = StringSchema::new("First name.")
    .format(&SINGLE_LINE_COMMENT_FORMAT)
    .min_length(1)
    .max_length(64)
    .schema();

pub const LAST_NAME_SCHEMA: Schema = StringSchema::new("Last name.")
    .format(&SINGLE_LINE_COMMENT_FORMAT)
    .min_length(1)
    .max_length(64)
    .schema();

pub const EMAIL_SCHEMA: Schema = StringSchema::new("E-Mail Address.")
    .format(&SINGLE_LINE_COMMENT_FORMAT)
    .min_length(2)
    .max_length(64)
    .schema();

const_regex! {
    pub ACL_PATH_REGEX = concatcp!(r"^(?:/|", r"(?:/", SAFE_ID_REGEX_STR, ")+", r")$");
}

pub const ACL_PATH_FORMAT: ApiStringFormat = ApiStringFormat::Pattern(&ACL_PATH_REGEX);

pub const ACL_PATH_SCHEMA: Schema = StringSchema::new("Access control path.")
    .format(&ACL_PATH_FORMAT)
    .min_length(1)
    .max_length(128)
    .schema();

pub const ACL_PROPAGATE_SCHEMA: Schema =
    BooleanSchema::new("Allow to propagate (inherit) permissions.")
        .default(true)
        .schema();

#[api(
    properties: {
        user: {
            type: User,
            flatten: true,
        },
        tokens: {
            type: Array,
            optional: true,
            description: "List of user's API tokens.",
            items: {
                type: ApiToken
            },
        },
        "totp-locked": {
            type: bool,
            optional: true,
            default: false,
            description: "True if the user is currently locked out of TOTP factors",
        },
        "tfa-locked-until": {
            optional: true,
            description: "Contains a timestamp until when a user is locked out of 2nd factors",
        },
    }
)]
#[derive(Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// User properties with added list of ApiTokens
pub struct UserWithTokens {
    #[serde(flatten)]
    pub user: User,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub tokens: Vec<ApiToken>,
    #[serde(skip_serializing_if = "bool_is_false", default)]
    pub totp_locked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tfa_locked_until: Option<i64>,
}

fn bool_is_false(b: &bool) -> bool {
    !b
}

#[api(
    properties: {
        tokenid: {
            schema: PROXMOX_TOKEN_ID_SCHEMA,
        },
        comment: {
            optional: true,
            schema: COMMENT_SCHEMA,
        },
        enable: {
            optional: true,
            schema: ENABLE_USER_SCHEMA,
        },
        expire: {
            optional: true,
            schema: EXPIRE_USER_SCHEMA,
        },
    }
)]
#[derive(Serialize, Deserialize, Clone, PartialEq)]
/// ApiToken properties.
pub struct ApiToken {
    pub tokenid: Authid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
}

impl ApiToken {
    pub fn is_active(&self) -> bool {
        if !self.enable.unwrap_or(true) {
            return false;
        }
        if let Some(expire) = self.expire {
            let now = proxmox_time::epoch_i64();
            if expire > 0 && expire <= now {
                return false;
            }
        }
        true
    }
}

#[api]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "kebab-case")]
/// ApiToken id / secret pair
pub struct ApiTokenSecret {
    pub tokenid: Authid,
    /// The secret associated with the token.
    // rename to `value` as that is what it is called in the api
    #[serde(rename = "value")]
    pub secret: String,
}

#[api(
    properties: {
        token: { type: ApiToken },
    }
)]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// A Token Entry that contains the token-name
pub struct TokenApiEntry {
    /// The Token name
    pub token_name: Tokenname,
    #[serde(flatten)]
    pub token: ApiToken,
}

#[api(
    properties: {
        "require-expiry": {
            optional: true,
            default: false,
        },
        "max-lifetime": {
            optional: true,
            minimum: 1,
        },
        "disallow-expiry-extension": {
            optional: true,
            default: false,
        },
    },
)]
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Serialize, Updater)]
#[serde(rename_all = "kebab-case")]
/// Policy for the creation and update of API tokens.
///
/// Only token creation and updates are checked against the policy. Existing tokens stay valid, so
/// enabling a policy does not invalidate already deployed tokens.
pub struct TokenPolicy {
    /// Require an expiration date for new API tokens and when changing the expiration date of
    /// existing ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub require_expiry: Option<bool>,

    /// Maximum lifetime of API tokens in seconds, counted from when the expiration date is set,
    /// that is on creation or when an update changes it. Implies `require-expiry`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lifetime: Option<u64>,

    /// Disallow moving the expiration date of existing API tokens later or removing it, so that
    /// `max-lifetime` cannot be circumvented by extending tokens repeatedly. Shortening the
    /// expiration date or setting one on a token that has none remains possible, and tokens can
    /// still be deleted and recreated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disallow_expiry_extension: Option<bool>,
}

impl TokenPolicy {
    /// Check the expiration date of a new token against the policy, 0 or less meaning none.
    pub fn check_new_expiry(&self, expire: i64, now: i64) -> Result<(), Error> {
        self.check_expiry_bounds(expire, now)
    }

    /// Check an update of the expiration date of an existing token against the policy.
    ///
    /// `expire` is the submitted and `current` the stored expiration date, 0 or less meaning none.
    /// An unchanged date always passes, so updates of tokens that predate the policy keep working.
    pub fn check_expiry_update(&self, expire: i64, current: i64, now: i64) -> Result<(), Error> {
        if expire == current {
            return Ok(());
        }

        // removing the expiration date or moving it later extends the token
        if self.disallow_expiry_extension.unwrap_or_default()
            && current > 0
            && (expire <= 0 || expire > current)
        {
            bail!(
                "the token policy does not allow extending the expiration date of an existing token"
            );
        }

        self.check_expiry_bounds(expire, now)
    }

    fn check_expiry_bounds(&self, expire: i64, now: i64) -> Result<(), Error> {
        // a token that never expires exceeds any maximum lifetime
        if expire <= 0 && (self.require_expiry.unwrap_or_default() || self.max_lifetime.is_some()) {
            bail!("the token policy requires an expiration date");
        }

        if let Some(max_lifetime) = self.max_lifetime {
            // saturate, as an extreme configured lifetime would overflow
            if expire > now.saturating_add_unsigned(max_lifetime) {
                bail!(
                    "the expiration date exceeds the maximum token lifetime of {max_lifetime} \
                     seconds set by the token policy"
                );
            }
        }

        Ok(())
    }
}

#[api(
    properties: {
        userid: {
            type: Userid,
        },
        comment: {
            optional: true,
            schema: COMMENT_SCHEMA,
        },
        enable: {
            optional: true,
            schema: ENABLE_USER_SCHEMA,
        },
        expire: {
            optional: true,
            schema: EXPIRE_USER_SCHEMA,
        },
        firstname: {
            optional: true,
            schema: FIRST_NAME_SCHEMA,
        },
        lastname: {
            schema: LAST_NAME_SCHEMA,
            optional: true,
         },
        email: {
            schema: EMAIL_SCHEMA,
            optional: true,
        },
    }
)]
#[derive(Serialize, Deserialize, Updater, PartialEq, Eq, Clone)]
/// User properties.
pub struct User {
    #[updater(skip)]
    pub userid: Userid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expire: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firstname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lastname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
}

impl User {
    pub fn is_active(&self) -> bool {
        if !self.enable.unwrap_or(true) {
            return false;
        }
        if let Some(expire) = self.expire {
            let now = proxmox_time::epoch_i64();
            if expire > 0 && expire <= now {
                return false;
            }
        }
        true
    }
}

#[api]
/// Type of the 'ugid' property in the ACL entry list.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize, Hash)]
#[serde(rename_all = "lowercase")]
pub enum AclUgidType {
    /// An entry for a user (or token).
    User,
    /// An entry for a group.
    Group,
}

serde_plain::derive_display_from_serialize!(AclUgidType);
serde_plain::derive_fromstr_from_deserialize!(AclUgidType);

#[api(
    properties: {
        propagate: { schema: ACL_PROPAGATE_SCHEMA, },
        path: { schema: ACL_PATH_SCHEMA, },
        ugid_type: { type: AclUgidType },
        ugid: {
            type: String,
            description: "User or Group ID.",
        },
    }
)]
#[derive(Serialize, Deserialize, PartialEq, Clone, Hash)]
/// Access control list entry.
pub struct AclListItem {
    pub path: String,
    pub ugid: String,
    pub ugid_type: AclUgidType,
    pub propagate: bool,
    /// A role represented as a string.
    pub roleid: String,
}

#[api(
    properties: {
        privs: {
            type: Array,
            description: "List of Privileges",
            items: {
                type: String,
                description: "A Privilege",
            },
        },
        comment: {
            schema: COMMENT_SCHEMA,
            optional: true,
        }
    }
)]
/// A struct that the describes a role and shows the associated privileges.
#[derive(Serialize, Deserialize, PartialEq, Clone)]
pub struct RoleInfo {
    /// The id of the role
    pub roleid: String,
    /// The privileges the role holds
    pub privs: Vec<String>,
    /// A comment describing the role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[api()]
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
/// The set of properties that can be deleted from a token.
pub enum DeletableTokenProperty {
    /// Delete the comment property.
    Comment,
}

pub const REGENERATE_TOKEN_SCHEMA: Schema =
    BooleanSchema::new("Regenerate token secret while keeping permissions.")
        .default(false)
        .schema();

#[cfg(test)]
mod tests {
    use super::TokenPolicy;

    // fixed reference time and a 90 day maximum lifetime for deterministic bounds checks
    const NOW: i64 = 1_000_000_000;
    const MAX: i64 = 90 * 24 * 60 * 60;

    // the expiration date of the existing token in the update cases
    const CURRENT: i64 = NOW + 100;

    const EMPTY: TokenPolicy = TokenPolicy {
        require_expiry: None,
        max_lifetime: None,
        disallow_expiry_extension: None,
    };

    const REQUIRE_EXPIRY: TokenPolicy = TokenPolicy {
        require_expiry: Some(true),
        ..EMPTY
    };

    const MAX_LIFETIME: TokenPolicy = TokenPolicy {
        max_lifetime: Some(MAX as u64),
        ..EMPTY
    };

    const NO_EXTENSION: TokenPolicy = TokenPolicy {
        disallow_expiry_extension: Some(true),
        ..EMPTY
    };

    fn create_ok(policy: &TokenPolicy, expire: i64) -> bool {
        policy.check_new_expiry(expire, NOW).is_ok()
    }

    fn update_ok(policy: &TokenPolicy, expire: i64, current: i64) -> bool {
        policy.check_expiry_update(expire, current, NOW).is_ok()
    }

    #[test]
    fn empty_policy_allows_everything() {
        assert!(create_ok(&EMPTY, 0));
        assert!(create_ok(&EMPTY, NOW + 100));
        assert!(update_ok(&EMPTY, 0, CURRENT));
    }

    #[test]
    fn require_expiry() {
        assert!(!create_ok(&REQUIRE_EXPIRY, 0));
        assert!(create_ok(&REQUIRE_EXPIRY, NOW + 100));
        assert!(!update_ok(&REQUIRE_EXPIRY, 0, CURRENT));
        assert!(update_ok(&REQUIRE_EXPIRY, NOW + 200, CURRENT));
    }

    #[test]
    fn max_lifetime_implies_require_expiry() {
        assert!(!create_ok(&MAX_LIFETIME, 0));
        let explicitly_not_required = TokenPolicy {
            require_expiry: Some(false),
            ..MAX_LIFETIME
        };
        assert!(!create_ok(&explicitly_not_required, 0));
    }

    #[test]
    fn negative_expiry_means_none() {
        // `ApiToken::is_active` treats a negative expiration date as none, so the checks for a
        // missing one have to catch it as well
        assert!(!create_ok(&REQUIRE_EXPIRY, -1));
        assert!(!create_ok(&MAX_LIFETIME, -1));
        assert!(!update_ok(&REQUIRE_EXPIRY, -1, CURRENT));
        assert!(!update_ok(&NO_EXTENSION, -1, CURRENT));
        // a stored negative value counts as a token without an expiration date
        assert!(update_ok(&NO_EXTENSION, NOW + 100, -1));
    }

    #[test]
    fn max_lifetime_bounds() {
        assert!(create_ok(&MAX_LIFETIME, NOW + 100));
        assert!(create_ok(&MAX_LIFETIME, NOW + MAX));
        assert!(!create_ok(&MAX_LIFETIME, NOW + MAX + 1));
        // an expiration date in the past is odd, but within any bound
        assert!(create_ok(&MAX_LIFETIME, NOW - 100));
        assert!(update_ok(&MAX_LIFETIME, NOW + 200, CURRENT));
        assert!(!update_ok(&MAX_LIFETIME, NOW + MAX + 1, CURRENT));
    }

    #[test]
    fn extreme_max_lifetime_does_not_overflow() {
        let policy = TokenPolicy {
            max_lifetime: Some(u64::MAX),
            ..EMPTY
        };
        assert!(create_ok(&policy, NOW + 100));
        assert!(create_ok(&policy, i64::MAX));
    }

    #[test]
    fn unchanged_expiry_passes() {
        assert!(update_ok(&REQUIRE_EXPIRY, 0, 0));
        assert!(update_ok(&MAX_LIFETIME, NOW + MAX + 1, NOW + MAX + 1));
    }

    #[test]
    fn disallow_expiry_extension() {
        // moving the expiration date later or removing it is rejected
        assert!(!update_ok(&NO_EXTENSION, CURRENT + 1, CURRENT));
        assert!(!update_ok(&NO_EXTENSION, 0, CURRENT));
        // shortening it, even into the past, stays allowed
        assert!(update_ok(&NO_EXTENSION, CURRENT - 1, CURRENT));
        assert!(update_ok(&NO_EXTENSION, NOW - 100, CURRENT));
        // as does setting one on a token without any
        assert!(update_ok(&NO_EXTENSION, NOW + 100, 0));
        // creation is unaffected
        assert!(create_ok(&NO_EXTENSION, NOW + 100));
        assert!(create_ok(&NO_EXTENSION, 0));
    }

    #[test]
    fn disallow_expiry_extension_combined() {
        let policy = TokenPolicy {
            require_expiry: Some(true),
            ..NO_EXTENSION
        };
        // a compliant new date still gets rejected as an extension
        assert!(!update_ok(&policy, NOW + 200, CURRENT));
        assert!(create_ok(&policy, NOW + 200));
        // shortening under a maximum lifetime stays allowed as well
        let policy = TokenPolicy {
            max_lifetime: Some(MAX as u64),
            ..NO_EXTENSION
        };
        assert!(update_ok(&policy, CURRENT - 1, CURRENT));
    }
}
