//! Validation of client-supplied values that end up in SIP messages.
//!
//! Anything placed into a header must not be able to end the header line
//! or the header value: no CR/LF or other control characters anywhere, and
//! no characters that would break out of the URI or quoted string it is
//! placed in.

use crate::handoff::TransferTarget;

const MAX_USER_LEN: usize = 64;
const MAX_HOST_LEN: usize = 253;
const MAX_DISPLAY_NAME_LEN: usize = 128;

/// The user part of a SIP URI: unreserved characters plus the
/// user-unreserved `& = + $ ,` (no `;`, `?`, `@`, `:` or escapes).
pub fn is_valid_sip_user(user: &str) -> bool {
    (1..=MAX_USER_LEN).contains(&user.len())
        && user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.!~*'()&=+$,".contains(c))
}

/// A digest username: a SIP user, optionally `user@domain`.
pub fn is_valid_auth_user(user: &str) -> bool {
    match user.split_once('@') {
        Some((u, host)) => is_valid_sip_user(u) && is_valid_host(host),
        None => is_valid_sip_user(user),
    }
}

/// A hostname, IPv4 address or bracketed IPv6 address (no port).
pub fn is_valid_host(host: &str) -> bool {
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    (1..=MAX_HOST_LEN).contains(&host.len())
        && !host.starts_with(['.', '-'])
        && !host.ends_with('-')
        && !host.contains("..")
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// A supported transport name, normalised to lower case.
pub fn normalize_transport(transport: &str) -> Option<String> {
    let t = transport.to_ascii_lowercase();
    matches!(t.as_str(), "udp" | "tcp" | "tls").then_some(t)
}

/// A display name: printable text without control characters. It is
/// always sent as an escaped quoted-string.
pub fn is_valid_display_name(name: &str) -> bool {
    name.chars().count() <= MAX_DISPLAY_NAME_LEN && !name.chars().any(char::is_control)
}

/// The Request-URI for a call to `destination`: a number or extension
/// (placed in `domain`), `user@host`, or a `sip:`/`sips:` URI, validated
/// like a transfer target.
pub fn destination_uri(destination: &str, domain: &str) -> Option<String> {
    if destination.chars().any(char::is_control) {
        return None;
    }
    let raw = destination.trim();
    let lower = raw.to_ascii_lowercase();
    let candidate = if lower.starts_with("sip:") || lower.starts_with("sips:") || !raw.contains('@')
    {
        raw.to_string()
    } else {
        format!("sip:{raw}")
    };
    TransferTarget::parse(&candidate)
        .ok()
        .map(|t| t.refer_to_uri(domain))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sip_users() {
        for ok in ["1001", "alice", "a.b-c_d", "+15551234567", "x!~*'()&=+$,"] {
            assert!(is_valid_sip_user(ok), "{ok}");
        }
        for bad in [
            "",
            "a b",
            "a\r\nX: y",
            "a;b",
            "a?b",
            "a@b",
            "a:b",
            "a<b",
            "a>b",
            "a\"b",
            "%41",
            &"a".repeat(65),
        ] {
            assert!(!is_valid_sip_user(bad), "{bad:?}");
        }
        assert!(is_valid_auth_user("alice@pbx.example.com"));
        assert!(!is_valid_auth_user("alice\"@pbx"));
        assert!(!is_valid_auth_user("alice@pb x"));
    }

    #[test]
    fn hosts() {
        for ok in ["pbx.example.com", "10.0.0.1", "[::1]", "localhost", "a-b.c"] {
            assert!(is_valid_host(ok), "{ok}");
        }
        for bad in [
            "",
            "pbx.example.com:5060",
            "a b",
            "a\r\n",
            "-a",
            ".a",
            "a..b",
            "a/b",
            "[::1",
            "[zz]",
            "a>b",
            "a;transport=tcp",
        ] {
            assert!(!is_valid_host(bad), "{bad:?}");
        }
    }

    #[test]
    fn transports_and_display_names() {
        assert_eq!(normalize_transport("UDP").as_deref(), Some("udp"));
        assert_eq!(normalize_transport("tls").as_deref(), Some("tls"));
        assert_eq!(normalize_transport("udp\r\nX: y"), None);
        assert_eq!(normalize_transport("sctp"), None);
        assert!(is_valid_display_name("Bob \"The Builder\" \\ Jr."));
        assert!(is_valid_display_name(""));
        assert!(!is_valid_display_name("Bob\r\nX-Evil: 1"));
        assert!(!is_valid_display_name("Bob\u{0}"));
    }

    #[test]
    fn destinations() {
        assert_eq!(
            destination_uri("1002", "pbx.example.com").as_deref(),
            Some("sip:1002@pbx.example.com")
        );
        assert_eq!(
            destination_uri("bob@example.com", "pbx").as_deref(),
            Some("sip:bob@example.com")
        );
        assert_eq!(
            destination_uri("sip:bob@example.com;user=phone", "pbx").as_deref(),
            Some("sip:bob@example.com;user=phone")
        );
        for bad in [
            "",
            "sip:bob@example.com\r\nX-Evil: 1",
            "1002\r\nX: y",
            "1002\r\n",
            "sip:bob@example.com>",
            "<sip:bob@example.com>",
            "sip:a@b?Subject=x",
            "bob smith@example.com",
            "sip:a@b;method=BYE",
        ] {
            assert_eq!(destination_uri(bad, "pbx"), None, "{bad:?}");
        }
    }
}
