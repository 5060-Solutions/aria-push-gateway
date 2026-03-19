//! Integration tests for the Aria Push Gateway.

/// Test SIP message building and parsing through the gateway's message module.
mod sip_message {
    // We test through aria-sip-core's public API since the gateway re-exports it.
    use rsip::parser;
    use rsip::{generate_branch, generate_call_id, generate_tag};

    const SAMPLE_INVITE: &str = "\
INVITE sip:alice@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-test;rport\r\n\
Max-Forwards: 70\r\n\
From: \"Bob Smith\" <sip:bob@example.com>;tag=from123\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: test-call-id-001\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@10.0.0.1:5060>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: 100\r\n\
\r\n\
v=0\r\n\
o=bob 123 456 IN IP4 10.0.0.1\r\n\
s=Call\r\n\
c=IN IP4 10.0.0.1\r\n\
t=0 0\r\n\
m=audio 8000 RTP/AVP 0 8\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=rtpmap:8 PCMA/8000\r\n";

    const SAMPLE_REGISTER_200: &str = "\
SIP/2.0 200 OK\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg;rport=5060;received=203.0.113.1\r\n\
From: <sip:alice@example.com>;tag=reg456\r\n\
To: <sip:alice@example.com>;tag=srv789\r\n\
Call-ID: reg-call-id\r\n\
CSeq: 1 REGISTER\r\n\
Contact: <sip:alice@10.0.0.1:5060>;expires=3600\r\n\
Content-Length: 0\r\n\r\n";

    const SAMPLE_401: &str = "\
SIP/2.0 401 Unauthorized\r\n\
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-reg\r\n\
From: <sip:alice@example.com>;tag=reg456\r\n\
To: <sip:alice@example.com>;tag=srv789\r\n\
Call-ID: reg-call-id\r\n\
CSeq: 1 REGISTER\r\n\
WWW-Authenticate: Digest realm=\"example.com\", nonce=\"abc123\", algorithm=MD5, qop=\"auth\"\r\n\
Content-Length: 0\r\n\r\n";

    #[test]
    fn parse_invite_headers() {
        assert_eq!(
            parser::extract_header(SAMPLE_INVITE, "Call-ID"),
            Some("test-call-id-001".into())
        );
        assert_eq!(
            parser::extract_method(SAMPLE_INVITE),
            Some("INVITE".into())
        );
        assert!(parser::is_request(SAMPLE_INVITE));
    }

    #[test]
    fn parse_invite_caller_info() {
        let (user, domain) = parser::extract_from_uri(SAMPLE_INVITE).unwrap();
        assert_eq!(user, "bob");
        assert_eq!(domain, "example.com");

        let name = parser::extract_display_name(SAMPLE_INVITE);
        assert_eq!(name, Some("Bob Smith".into()));
    }

    #[test]
    fn parse_invite_sdp() {
        let body = SAMPLE_INVITE.split("\r\n\r\n").nth(1).unwrap();
        let (ip, port) = parser::parse_sdp_connection(body).unwrap();
        assert_eq!(ip, "10.0.0.1");
        assert_eq!(port, 8000);
    }

    #[test]
    fn parse_register_200() {
        assert_eq!(parser::parse_status_code(SAMPLE_REGISTER_200), Some(200));
        assert!(!parser::is_request(SAMPLE_REGISTER_200));
        assert_eq!(
            parser::extract_cseq_method(SAMPLE_REGISTER_200),
            Some("REGISTER".into())
        );
    }

    #[test]
    fn parse_401_challenge() {
        assert_eq!(parser::parse_status_code(SAMPLE_401), Some(401));

        let www_auth = parser::extract_header(SAMPLE_401, "WWW-Authenticate").unwrap();
        assert!(www_auth.contains("realm=\"example.com\""));
        assert!(www_auth.contains("nonce=\"abc123\""));
    }

    #[test]
    fn digest_auth_round_trip() {
        use rsip::sip_auth::DigestAuth;

        let www_auth = parser::extract_header(SAMPLE_401, "WWW-Authenticate").unwrap();
        let auth = DigestAuth::from_challenge(
            &www_auth,
            "alice",
            "secret",
            "sip:example.com",
            "REGISTER",
        )
        .unwrap();

        assert_eq!(auth.realm, "example.com");
        assert_eq!(auth.nonce, "abc123");
        assert_eq!(auth.algorithm, "MD5");

        let header = auth.to_header();
        assert!(header.starts_with("Digest username=\"alice\""));
        assert!(header.contains("realm=\"example.com\""));
        assert!(header.contains("response=\""));
        assert!(header.contains("qop=auth"));
    }

    #[test]
    fn generators_are_unique() {
        let b1 = generate_branch();
        let b2 = generate_branch();
        assert_ne!(b1, b2);

        let t1 = generate_tag();
        let t2 = generate_tag();
        // Tags *could* collide but it's astronomically unlikely
        assert_eq!(t1.len(), 8);
        assert_eq!(t2.len(), 8);

        let c1 = generate_call_id();
        let c2 = generate_call_id();
        assert_ne!(c1, c2);
    }
}

/// Test JWT token creation and verification.
mod auth {
    use aria_push_gateway::auth_test_helpers::{create_token, verify_token};

    #[test]
    fn token_round_trip() {
        let secret = "test-secret-key";
        let token = create_token("alice@example.com", secret, 3600).unwrap();
        let claims = verify_token(&token, secret).unwrap();
        assert_eq!(claims.sub, "alice@example.com");
    }

    #[test]
    fn token_wrong_secret_fails() {
        let token = create_token("alice@example.com", "secret1", 3600).unwrap();
        assert!(verify_token(&token, "secret2").is_err());
    }

    #[test]
    fn token_expired_fails() {
        // Create a token with exp in the past by building manually
        use jsonwebtoken::{encode, EncodingKey, Header};
        use serde::Serialize;

        #[derive(Serialize)]
        struct Claims { sub: String, exp: u64, iat: u64 }

        let claims = Claims {
            sub: "alice@example.com".to_string(),
            exp: 1000, // year ~1970
            iat: 999,
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        ).unwrap();

        assert!(verify_token(&token, "secret").is_err());
    }
}

/// Test config loading.
mod config {
    #[test]
    fn default_config_is_valid() {
        // When no config file exists, defaults should work
        let config = aria_push_gateway::config_test_helpers::load_default();
        assert_eq!(config.server.listen, "0.0.0.0:8080");
        assert!(config.push.apns.is_none());
        assert!(config.push.fcm.is_none());
    }

    #[test]
    fn parse_valid_toml() {
        let toml = r#"
[server]
listen = "127.0.0.1:9090"
public_url = "https://test.example.com"

[database]
url = "sqlite::memory:"

[auth]
secret = "test-secret"

[push]
"#;
        let config: aria_push_gateway::config_test_helpers::GatewayConfig =
            toml::from_str(toml).unwrap();
        assert_eq!(config.server.listen, "127.0.0.1:9090");
        assert_eq!(config.auth.secret, "test-secret");
    }
}
