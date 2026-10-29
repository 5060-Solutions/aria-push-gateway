//! SIP message building and parsing for the gateway.
//!
//! Parsing utilities are re-exported from `aria-sip-core`.
//! Message builders are gateway-specific (REGISTER, provisional responses).

// Re-export shared parsing utilities
pub use rsip::generators::{generate_branch, generate_call_id, generate_tag};
pub use rsip::sip_parser::{
    extract_all_headers, extract_cseq_method, extract_display_name, extract_from_uri,
    extract_header, extract_method, extract_to_tag, extract_via_branch, is_request,
    parse_sipfrag_status, parse_status_code,
};

/// Build a REGISTER request.
#[allow(clippy::too_many_arguments)]
pub fn build_register(
    username: &str,
    domain: &str,
    registrar: &str,
    local_ip: &str,
    local_port: u16,
    transport: &str,
    call_id: &str,
    cseq: u32,
    from_tag: &str,
    auth_header: Option<&str>,
    expires: u32,
) -> String {
    let branch = generate_branch();
    let tp = transport.to_uppercase();

    let mut msg = format!(
        "REGISTER sip:{registrar} SIP/2.0\r\n\
         Via: SIP/2.0/{tp} {local_ip}:{local_port};branch={branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:{username}@{domain}>;tag={from_tag}\r\n\
         To: <sip:{username}@{domain}>\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: <sip:{username}@{local_ip}:{local_port};transport={transport}>\r\n\
         Expires: {expires}\r\n\
         Allow: INVITE, ACK, CANCEL, BYE, OPTIONS, NOTIFY\r\n\
         User-Agent: Aria-Gateway/0.1.0\r\n",
    );

    if let Some(auth) = auth_header {
        msg.push_str(&format!("Authorization: {}\r\n", auth));
    }

    msg.push_str("Content-Length: 0\r\n\r\n");
    msg
}

/// Build a 100 Trying response for an incoming INVITE.
pub fn build_100_trying(request: &str) -> Option<String> {
    let via = extract_header(request, "Via")?;
    let from = extract_header(request, "From")?;
    let to = extract_header(request, "To")?;
    let call_id = extract_header(request, "Call-ID")?;
    let cseq = extract_header(request, "CSeq")?;

    Some(format!(
        "SIP/2.0 100 Trying\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// Build a 480 Temporarily Unavailable response.
pub fn build_480(request: &str) -> Option<String> {
    let via = extract_header(request, "Via")?;
    let from = extract_header(request, "From")?;
    let to = extract_header(request, "To")?;
    let call_id = extract_header(request, "Call-ID")?;
    let cseq = extract_header(request, "CSeq")?;

    Some(format!(
        "SIP/2.0 480 Temporarily Unavailable\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         User-Agent: Aria-Gateway/0.1.0\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// Build a 481 Call/Transaction Does Not Exist response, e.g. for a BYE on a
/// dialog the gateway doesn't know (RFC 3261 §15.1.2).
pub fn build_481(request: &str) -> Option<String> {
    let via = extract_header(request, "Via")?;
    let from = extract_header(request, "From")?;
    let to = extract_header(request, "To")?;
    let call_id = extract_header(request, "Call-ID")?;
    let cseq = extract_header(request, "CSeq")?;

    Some(format!(
        "SIP/2.0 481 Call/Transaction Does Not Exist\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         User-Agent: Aria-Gateway/0.1.0\r\n\
         Content-Length: 0\r\n\r\n"
    ))
}

/// Extract the media IP and port from an SDP body.
///
/// Looks for the `c=IN IP4 <addr>` connection line and `m=audio <port>` media line.
pub fn extract_sdp_media_address(sdp: &str) -> Option<(String, u16)> {
    let mut ip = None;
    let mut port = None;

    for line in sdp.lines() {
        let line = line.trim();
        // c=IN IP4 1.2.3.4
        if line.starts_with("c=IN IP4 ") || line.starts_with("c=IN IP4\t") {
            let parts: Vec<&str> = line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                // Handle potential "IP4 addr" with extra fields (e.g., TTL for multicast)
                let addr = parts[2].split('/').next().unwrap_or(parts[2]);
                ip = Some(addr.trim().to_string());
            }
        }
        // m=audio 12345 RTP/AVP ...
        if line.starts_with("m=audio ") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                port = parts[1].parse().ok();
            }
        }
    }

    match (ip, port) {
        (Some(ip), Some(port)) => Some((ip, port)),
        _ => None,
    }
}

/// Rewrite the media address in an SDP body.
///
/// Replaces the IP in `c=IN IP4 ...` lines and the port in `m=audio ...` lines.
pub fn rewrite_sdp_media_address(sdp: &str, new_ip: &str, new_port: u16) -> String {
    let mut result = Vec::new();

    for line in sdp.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("c=IN IP4 ") || trimmed.starts_with("c=IN IP4\t") {
            result.push(format!("c=IN IP4 {}", new_ip));
        } else if trimmed.starts_with("m=audio ") {
            // m=audio PORT RTP/AVP payload_types...
            let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                result.push(format!("m=audio {} {}", new_port, parts[2]));
            } else {
                result.push(line.to_string());
            }
        } else if trimmed.starts_with("o=") {
            // Also rewrite the origin line IP if present
            // o=- sess_id sess_version IN IP4 addr
            let parts: Vec<&str> = trimmed.splitn(6, ' ').collect();
            if parts.len() == 6 && parts[4] == "IP4" {
                result.push(format!(
                    "{} {} {} {} {} {}",
                    parts[0], parts[1], parts[2], parts[3], parts[4], new_ip
                ));
            } else {
                result.push(line.to_string());
            }
        } else {
            result.push(line.to_string());
        }
    }

    result.join("\r\n")
}

/// Build a 200 OK for an INVITE, forwarding the mobile app's SDP answer.
pub fn build_200_ok_invite(request: &str, sdp_answer: &str, contact_uri: &str) -> Option<String> {
    let via = extract_header(request, "Via")?;
    let from = extract_header(request, "From")?;
    let to_base = extract_header(request, "To")?;
    let call_id = extract_header(request, "Call-ID")?;
    let cseq = extract_header(request, "CSeq")?;

    let to_tag = generate_tag();
    let to = if to_base.contains("tag=") {
        to_base
    } else {
        format!("{};tag={}", to_base, to_tag)
    };

    Some(format!(
        "SIP/2.0 200 OK\r\n\
         Via: {via}\r\n\
         From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq}\r\n\
         Contact: <{contact_uri}>\r\n\
         Content-Type: application/sdp\r\n\
         User-Agent: Aria-Gateway/0.1.0\r\n\
         Content-Length: {len}\r\n\r\n{sdp_answer}",
        len = sdp_answer.len(),
    ))
}

/// Build a CANCEL for a pending INVITE (RFC 3261 §9.1): same Request-URI,
/// top Via (so the same branch), Route set, From, To, Call-ID and CSeq
/// number as the INVITE, with method CANCEL.
pub fn build_cancel(invite: &str) -> Option<String> {
    let request_uri = invite
        .lines()
        .next()?
        .strip_prefix("INVITE ")?
        .strip_suffix(" SIP/2.0")?;
    let via = extract_header(invite, "Via")?;
    let from = extract_header(invite, "From")?;
    let to = extract_header(invite, "To")?;
    let call_id = extract_header(invite, "Call-ID")?;
    let cseq = extract_header(invite, "CSeq")?;
    let cseq_num = cseq.split_whitespace().next()?;

    let mut msg = format!(
        "CANCEL {request_uri} SIP/2.0\r\n\
         Via: {via}\r\n\
         Max-Forwards: 70\r\n"
    );
    for route in extract_all_headers(invite, "Route") {
        msg.push_str(&format!("Route: {route}\r\n"));
    }
    msg.push_str(&format!(
        "From: {from}\r\n\
         To: {to}\r\n\
         Call-ID: {call_id}\r\n\
         CSeq: {cseq_num} CANCEL\r\n\
         User-Agent: Aria-Gateway/0.1.0\r\n\
         Content-Length: 0\r\n\r\n"
    ));
    Some(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_matches_the_invite_transaction() {
        let invite = "INVITE sip:2000@pbx.example.com SIP/2.0\r\n\
            Via: SIP/2.0/UDP 10.0.0.2:40000;branch=z9hG4bK-inv2;rport\r\n\
            Max-Forwards: 70\r\n\
            Route: <sip:edge.example.com;lr>\r\n\
            From: \"Bob\" <sip:1001@pbx.example.com>;tag=abc\r\n\
            To: <sip:2000@pbx.example.com>\r\n\
            Call-ID: cid-1\r\n\
            CSeq: 2 INVITE\r\n\
            Authorization: Digest x\r\n\
            Content-Type: application/sdp\r\n\
            Content-Length: 5\r\n\r\nv=0\r\n";
        let cancel = build_cancel(invite).unwrap();
        let lines: Vec<&str> = cancel.split("\r\n").collect();
        assert_eq!(lines[0], "CANCEL sip:2000@pbx.example.com SIP/2.0");
        for expected in [
            "Via: SIP/2.0/UDP 10.0.0.2:40000;branch=z9hG4bK-inv2;rport",
            "Route: <sip:edge.example.com;lr>",
            "From: \"Bob\" <sip:1001@pbx.example.com>;tag=abc",
            "To: <sip:2000@pbx.example.com>",
            "Call-ID: cid-1",
            "CSeq: 2 CANCEL",
            "Content-Length: 0",
        ] {
            assert!(
                lines.contains(&expected),
                "missing {expected:?} in\n{cancel}"
            );
        }
        assert!(!cancel.contains("Authorization"));
        assert!(!cancel.contains("v=0"));
        assert!(build_cancel("BYE sip:x SIP/2.0\r\n\r\n").is_none());
    }
}
