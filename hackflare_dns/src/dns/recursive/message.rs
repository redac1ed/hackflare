use crate::dns::wire::{encode_name_labels_vec, parse_qname};

pub(super) fn tld_from_name(name: &str) -> Option<String> {
    name.split('.')
        .rev()
        .find(|label| !label.is_empty())
        .map(str::to_ascii_lowercase)
}

const TLD_DELEGATION_MIN_TTL_SECS: u64 = 3600;
const TLD_DELEGATION_MAX_TTL_SECS: u64 = 86400;

pub(super) fn clamp_tld_ttl(ttl_secs: u64) -> u64 {
    ttl_secs.clamp(TLD_DELEGATION_MIN_TTL_SECS, TLD_DELEGATION_MAX_TTL_SECS)
}

pub(super) fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&encode_name_labels_vec(qname));
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out
}

pub(super) fn response_matches_expected(
    resp: &[u8],
    expected_id: u16,
    expected_qname: &str,
    expected_qtype: u16,
) -> bool {
    if resp.len() < 12 {
        return false;
    }
    let id = u16::from_be_bytes([resp[0], resp[1]]);
    if id != expected_id {
        return false;
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    if qdcount != 1 {
        return false;
    }
    let mut pos = 12usize;
    let Some((qname, p2)) = parse_qname(resp, pos) else {
        return false;
    };
    pos = p2;
    if qname.trim_end_matches('.') != expected_qname.trim_end_matches('.') {
        return false;
    }
    if pos + 4 > resp.len() {
        return false;
    }
    let qtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
    qtype == expected_qtype
}

pub(super) fn parse_rrs(
    buf: &[u8],
    mut pos: usize,
    count: usize,
) -> Option<Vec<(u16, usize, usize, u32)>> {
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let (_, p2) = parse_qname(buf, pos)?;
        pos = p2;
        if pos + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let class = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
        if class != 1 {
            return None;
        }
        let ttl = u32::from_be_bytes([buf[pos + 4], buf[pos + 5], buf[pos + 6], buf[pos + 7]]);
        let rdlen = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > buf.len() {
            return None;
        }
        out.push((rtype, pos, rdlen, ttl));
        pos += rdlen;
    }
    Some(out)
}

pub(super) fn extract_ns_and_glue(
    buf: &[u8],
    authority_rrs: &[(u16, usize, usize, u32)],
    additional_rrs: &[(u16, usize, usize, u32)],
) -> (Vec<String>, Vec<String>) {
    let mut ns_names: Vec<String> = Vec::new();
    let mut glue_ips: Vec<String> = Vec::new();
    for (rtype, rpos, _rdlen, _ttl) in authority_rrs {
        if *rtype == 2
            && let Some((name, _)) = parse_qname(buf, *rpos)
        {
            ns_names.push(name);
        }
    }
    for (rtype, rpos, rdlen, _ttl) in additional_rrs {
        if *rtype == 1 && *rdlen == 4 {
            let ip = format!(
                "{}.{}.{}.{}",
                buf[*rpos],
                buf[*rpos + 1],
                buf[*rpos + 2],
                buf[*rpos + 3]
            );
            glue_ips.push(ip);
        } else if *rtype == 28
            && *rdlen == 16
            && let Ok(ipv6) = <[u8; 16]>::try_from(&buf[*rpos..*rpos + 16])
        {
            glue_ips.push(std::net::Ipv6Addr::from(ipv6).to_string());
        }
    }
    (ns_names, glue_ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tld_from_name_extracts_tld() {
        assert_eq!(tld_from_name("WWW.Example.COM."), Some("com".to_string()));
    }

    #[test]
    fn clamp_tld_ttl_clamps_values() {
        assert_eq!(clamp_tld_ttl(10), 3600);
        assert_eq!(clamp_tld_ttl(999_999), 86400);
    }

    #[test]
    fn build_query_and_response_matching() {
        let mut response = build_query(0x1234, "example.com", 1);
        response[2] |= 0x80;
        assert!(response_matches_expected(&response, 0x1234, "example.com", 1));
        assert!(!response_matches_expected(&response, 0x9999, "example.com", 1));
    }

    #[test]
    fn parse_rrs_accepts_class_in() {
        let name = encode_name_labels_vec("www.example.com");
        let mut rr = name.clone();
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&300u32.to_be_bytes());
        rr.extend_from_slice(&4u16.to_be_bytes());
        rr.extend_from_slice(&[192, 168, 1, 1]);
        let result = parse_rrs(&rr, 0, 1);
        assert!(result.is_some());
    }

    #[test]
    fn parse_rrs_rejects_non_in_class() {
        let name = encode_name_labels_vec("www.example.com");
        let mut rr = name.clone();
        rr.extend_from_slice(&1u16.to_be_bytes());
        rr.extend_from_slice(&3u16.to_be_bytes());
        rr.extend_from_slice(&300u32.to_be_bytes());
        rr.extend_from_slice(&4u16.to_be_bytes());
        rr.extend_from_slice(&[192, 168, 1, 1]);
        let result = parse_rrs(&rr, 0, 1);
        assert!(result.is_none());
    }
}
