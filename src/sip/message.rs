//! SIP message building and parsing for the gateway.
//!
//! Parsing utilities are re-exported from `aria-sip-core`.
//! Message builders are gateway-specific (REGISTER, provisional responses).

// Re-export shared parsing utilities
pub use rsip::sip_parser::{
    extract_display_name, extract_from_uri, extract_header, extract_method, extract_cseq_method,
    extract_to_tag, is_request, parse_status_code,
};
pub use rsip::generators::{generate_branch, generate_call_id, generate_tag};

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
