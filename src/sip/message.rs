//! SIP message building and parsing for the gateway.
//!
//! Start-line parsing and generators are re-exported from `sip-5060`. Header
//! lookup is local: it reads only the header section (never the body),
//! unfolds continuation lines, accepts whitespace before the colon and the
//! RFC 3261 compact header names, and can return every value of a header.

pub use rsip::generators::{generate_branch, generate_call_id, generate_tag};
pub use rsip::sip_parser::{extract_method, is_request, parse_sipfrag_status, parse_status_code};

/// Long name for an RFC 3261 §7.3.3 / RFC 3515 compact header name.
fn expand_compact(name: &str) -> &str {
    match name.to_ascii_lowercase().as_str() {
        "v" => "Via",
        "f" => "From",
        "t" => "To",
        "i" => "Call-ID",
        "m" => "Contact",
        "l" => "Content-Length",
        "c" => "Content-Type",
        "e" => "Content-Encoding",
        "k" => "Supported",
        "s" => "Subject",
        "r" => "Refer-To",
        "b" => "Referred-By",
        "o" => "Event",
        "u" => "Allow-Events",
        "x" => "Session-Expires",
        _ => name,
    }
}

/// The header lines of `msg` (start line excluded, body excluded), with
/// folded continuation lines joined, as `(name, value)` pairs in order.
fn header_fields(msg: &str) -> Vec<(&str, String)> {
    let mut fields: Vec<(&str, String)> = Vec::new();
    for line in msg.split('\n').skip(1) {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() {
            break; // end of headers; the body follows
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = fields.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            fields.push((name.trim(), value.trim().to_string()));
        }
    }
    fields
}

fn header_matches(field: &str, name: &str) -> bool {
    expand_compact(field).eq_ignore_ascii_case(expand_compact(name))
}

/// Every value of header `name` (long or compact form), in message order.
/// A line carrying several comma-separated values is returned as one value.
pub fn extract_all_headers(msg: &str, name: &str) -> Vec<String> {
    header_fields(msg)
        .into_iter()
        .filter(|(field, _)| header_matches(field, name))
        .map(|(_, value)| value)
        .collect()
}

/// The first value of header `name` (long or compact form).
pub fn extract_header(msg: &str, name: &str) -> Option<String> {
    header_fields(msg)
        .into_iter()
        .find(|(field, _)| header_matches(field, name))
        .map(|(_, value)| value)
}

/// A parameter of a header value (`tag`, `branch`, ...), looking only at the
/// header's own parameters: after the `>` of a name-addr, or after the URI
/// of an addr-spec — never inside the URI.
pub fn header_param(value: &str, param: &str) -> Option<String> {
    let params = match value.rfind('>') {
        Some(end) => &value[end + 1..],
        None => value.split_once(';').map_or("", |(_, rest)| rest),
    };
    params
        .split([';', ','])
        .map(str::trim)
        .filter_map(|p| p.split_once('=').or(Some((p, ""))))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(param))
        .map(|(_, v)| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// The method in the CSeq header.
pub fn extract_cseq_method(msg: &str) -> Option<String> {
    let cseq = extract_header(msg, "CSeq")?;
    cseq.split_whitespace().nth(1).map(str::to_string)
}

/// The tag of the To header.
pub fn extract_to_tag(msg: &str) -> Option<String> {
    header_param(&extract_header(msg, "To")?, "tag")
}

/// The branch of the topmost Via.
pub fn extract_via_branch(msg: &str) -> Option<String> {
    let via = extract_header(msg, "Via")?;
    let top = via.split(',').next().unwrap_or_default();
    top.split(';')
        .skip(1)
        .filter_map(|p| p.split_once('='))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("branch"))
        .map(|(_, v)| v.trim().to_string())
}

/// User and domain of the From header's `sip:` URI.
pub fn extract_from_uri(msg: &str) -> Option<(String, String)> {
    rsip::sip_parser::extract_sip_uri(&extract_header(msg, "From")?)
}

/// Quoted display name of the From header.
pub fn extract_display_name(msg: &str) -> Option<String> {
    rsip::sip_parser::extract_display_name_from_value(&extract_header(msg, "From")?)
}

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

/// Build a response to `request` (RFC 3261 §8.2.6):
///
/// - every Via, in order, plus From, Call-ID and CSeq copied verbatim;
/// - To copied, with `;tag=<to_tag>` added if the request's To has no tag
///   and `to_tag` is given (every response except 100 Trying should carry
///   one);
/// - Record-Route copied in order when `record_route` is set (2xx to a
///   dialog-creating request);
/// - `extra_headers` (CRLF-terminated lines) and an optional
///   `(content type, body)`.
pub fn build_response(
    request: &str,
    code: u16,
    reason: &str,
    to_tag: Option<&str>,
    record_route: bool,
    extra_headers: &str,
    body: Option<(&str, &str)>,
) -> Option<String> {
    let vias = extract_all_headers(request, "Via");
    if vias.is_empty() {
        return None;
    }
    let from = extract_header(request, "From")?;
    let mut to = extract_header(request, "To")?;
    let call_id = extract_header(request, "Call-ID")?;
    let cseq = extract_header(request, "CSeq")?;
    if let Some(tag) = to_tag {
        if header_param(&to, "tag").is_none() {
            to.push_str(&format!(";tag={tag}"));
        }
    }

    let mut msg = format!("SIP/2.0 {code} {reason}\r\n");
    for via in vias {
        msg.push_str(&format!("Via: {via}\r\n"));
    }
    if record_route {
        for rr in extract_all_headers(request, "Record-Route") {
            msg.push_str(&format!("Record-Route: {rr}\r\n"));
        }
    }
    msg.push_str(&format!(
        "From: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {cseq}\r\n"
    ));
    msg.push_str(extra_headers);
    msg.push_str("User-Agent: Aria-Gateway/0.1.0\r\n");
    match body {
        Some((content_type, body)) => msg.push_str(&format!(
            "Content-Type: {content_type}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )),
        None => msg.push_str("Content-Length: 0\r\n\r\n"),
    }
    Some(msg)
}

/// A bodiless response; a To tag is generated if the request has none.
pub fn build_simple_response(request: &str, code: u16, reason: &str) -> Option<String> {
    build_response(
        request,
        code,
        reason,
        Some(&generate_tag()),
        false,
        "",
        None,
    )
}

/// Build a 100 Trying response for an incoming INVITE.
pub fn build_100_trying(request: &str) -> Option<String> {
    build_response(request, 100, "Trying", None, false, "", None)
}

/// Build a 481 Call/Transaction Does Not Exist response, e.g. for a BYE on a
/// dialog the gateway doesn't know (RFC 3261 §15.1.2).
pub fn build_481(request: &str) -> Option<String> {
    build_simple_response(request, 481, "Call/Transaction Does Not Exist")
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

/// Build a 200 OK for an INVITE with our `to_tag`, the INVITE's
/// Record-Route, our Contact and an SDP body.
pub fn build_200_ok_invite(
    request: &str,
    sdp: &str,
    contact_uri: &str,
    to_tag: &str,
) -> Option<String> {
    build_response(
        request,
        200,
        "OK",
        Some(to_tag),
        true,
        &format!("Contact: <{contact_uri}>\r\nAllow: INVITE, ACK, CANCEL, BYE, OPTIONS, REFER, NOTIFY\r\n"),
        Some(("application/sdp", sdp)),
    )
}

/// Build the ACK for a non-2xx final `response` to `invite` (RFC 3261
/// §17.1.1.3): same Request-URI, top Via (branch), Route, From, Call-ID and
/// CSeq number as the INVITE, and the response's To (with its tag).
pub fn build_non2xx_ack(invite: &str, response: &str) -> Option<String> {
    let request_uri = invite
        .lines()
        .next()?
        .strip_prefix("INVITE ")?
        .strip_suffix(" SIP/2.0")?;
    let via = extract_header(invite, "Via")?;
    let from = extract_header(invite, "From")?;
    let to = extract_header(response, "To")?;
    let call_id = extract_header(invite, "Call-ID")?;
    let cseq_num = extract_header(invite, "CSeq")?
        .split_whitespace()
        .next()?
        .to_string();
    let mut msg = format!("ACK {request_uri} SIP/2.0\r\nVia: {via}\r\nMax-Forwards: 70\r\n");
    for route in extract_all_headers(invite, "Route") {
        msg.push_str(&format!("Route: {route}\r\n"));
    }
    msg.push_str(&format!(
        "From: {from}\r\nTo: {to}\r\nCall-ID: {call_id}\r\nCSeq: {cseq_num} ACK\r\n\
         Content-Length: 0\r\n\r\n"
    ));
    Some(msg)
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

    const INVITE_VIA_RR: &str = "INVITE sip:1001@10.0.0.2 SIP/2.0\r\n\
        Via: SIP/2.0/UDP edge.example.com;branch=z9hG4bK-a, SIP/2.0/UDP core;branch=z9hG4bK-b\r\n\
        v: SIP/2.0/UDP pbx;branch=z9hG4bK-c\r\n\
        Record-Route: <sip:edge.example.com;lr>\r\n\
        Record-Route: <sip:core.example.com;lr>\r\n\
        From: <sip:2000@pbx>;tag=pbx\r\n\
        To: <sip:1001@pbx>\r\n\
        Call-ID: c1\r\nCSeq: 5 INVITE\r\nContent-Length: 0\r\n\r\n";

    #[test]
    fn responses_copy_every_via_and_tag_the_to() {
        let r = build_response(
            INVITE_VIA_RR,
            486,
            "Busy Here",
            Some("ourtag"),
            false,
            "",
            None,
        )
        .unwrap();
        let lines: Vec<&str> = r.split("\r\n").collect();
        assert_eq!(lines[0], "SIP/2.0 486 Busy Here");
        assert_eq!(
            &lines[1..4],
            &[
                "Via: SIP/2.0/UDP edge.example.com;branch=z9hG4bK-a, SIP/2.0/UDP core;branch=z9hG4bK-b",
                "Via: SIP/2.0/UDP pbx;branch=z9hG4bK-c",
                "From: <sip:2000@pbx>;tag=pbx",
            ]
        );
        assert!(lines.contains(&"To: <sip:1001@pbx>;tag=ourtag"));
        assert!(!r.contains("Record-Route"));

        // An existing To tag is kept; 100 Trying gets none.
        let in_dialog = INVITE_VIA_RR.replace("To: <sip:1001@pbx>", "To: <sip:1001@pbx>;tag=x");
        let r = build_response(&in_dialog, 200, "OK", Some("y"), false, "", None).unwrap();
        assert!(r.contains("To: <sip:1001@pbx>;tag=x\r\n"));
        assert!(build_100_trying(INVITE_VIA_RR)
            .unwrap()
            .contains("To: <sip:1001@pbx>\r\n"));
        assert!(build_481(INVITE_VIA_RR)
            .unwrap()
            .contains("To: <sip:1001@pbx>;tag="));
    }

    #[test]
    fn invite_200_echoes_record_route_in_order() {
        let ok =
            build_200_ok_invite(INVITE_VIA_RR, "v=0\r\n", "sip:gw@10.0.0.2:5060", "t1").unwrap();
        let rr: Vec<&str> = ok
            .lines()
            .filter(|l| l.starts_with("Record-Route:"))
            .collect();
        assert_eq!(
            rr,
            vec![
                "Record-Route: <sip:edge.example.com;lr>",
                "Record-Route: <sip:core.example.com;lr>"
            ]
        );
        assert!(ok.contains("To: <sip:1001@pbx>;tag=t1\r\n"));
        assert!(ok.contains("Contact: <sip:gw@10.0.0.2:5060>\r\n"));
        assert!(ok.ends_with("Content-Length: 5\r\n\r\nv=0\r\n"));
    }

    const FOLDED: &str = "INVITE sip:a@b SIP/2.0\r\n\
        v: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK-2\r\n\
        Via : SIP/2.0/UDP 10.0.0.3;branch=z9hG4bK-3\r\n\
        f: \"Bob\" <sip:bob@b;tag=uri-param>;tag=ftag\r\n\
        t: <sip:a@b>\r\n\
        i: cid-9\r\n\
        Subject: first\r\n\t continued\r\n\
        CSeq: 7 INVITE\r\n\
        l: 30\r\n\r\n\
        Call-ID: in-the-body\r\nTo: <sip:x@y>;tag=body\r\n";

    #[test]
    fn header_lookup_handles_compact_forms_folding_and_the_body() {
        assert_eq!(extract_header(FOLDED, "Call-ID").as_deref(), Some("cid-9"));
        assert_eq!(extract_header(FOLDED, "i").as_deref(), Some("cid-9"));
        assert_eq!(
            extract_header(FOLDED, "Subject").as_deref(),
            Some("first continued")
        );
        assert_eq!(
            extract_all_headers(FOLDED, "Via"),
            vec![
                "SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK-1, SIP/2.0/UDP 10.0.0.2;branch=z9hG4bK-2",
                "SIP/2.0/UDP 10.0.0.3;branch=z9hG4bK-3",
            ]
        );
        assert_eq!(extract_via_branch(FOLDED).as_deref(), Some("z9hG4bK-1"));
        assert_eq!(
            header_param(&extract_header(FOLDED, "f").unwrap(), "tag").as_deref(),
            Some("ftag")
        );
        // Nothing is read from the body.
        assert_eq!(extract_to_tag(FOLDED), None);
        assert_eq!(extract_cseq_method(FOLDED).as_deref(), Some("INVITE"));
        assert_eq!(extract_display_name(FOLDED).as_deref(), Some("Bob"));
    }

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
