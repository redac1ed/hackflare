use crate::dns::DnsConfig;
use rand::seq::SliceRandom;
use std::net::UdpSocket;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::cache;
use super::hints;
use super::message::{build_query, clamp_tld_ttl, extract_ns_and_glue, parse_rrs, tld_from_name};
use super::transport::{send_recv, tcp_send_recv};

use cache::{CacheValue, DelegationCacheValue, RootCacheValue};

const ROOT_CACHE_TTL_SECS: u64 = 86400;
const MAX_QUERY_CACHE_ENTRIES: usize = 10_000;
const MAX_ROOT_CACHE_ENTRIES: usize = 256;
const MAX_DELEGATION_CACHE_ENTRIES: usize = 1024;
const MAX_UPSTREAM_SERVERS_PER_ROUND: usize = 8;
const MAX_CONCURRENT_RESOLVES: usize = 128;

static ACTIVE_RESOLVES: std::sync::LazyLock<AtomicUsize> =
    std::sync::LazyLock::new(|| AtomicUsize::new(0));

static ROOT_HINTS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(hints::load_root_hint_servers);

fn debug_log(msg: &str, config: &DnsConfig) {
    if config.recursion_debug {
        eprintln!("[hackflare:dns:recursive] {msg}");
    }
}

struct ResolveGuard;

impl Drop for ResolveGuard {
    fn drop(&mut self) {
        ACTIVE_RESOLVES.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_resolve_slot() -> Option<ResolveGuard> {
    let mut current = ACTIVE_RESOLVES.load(Ordering::Acquire);
    loop {
        if current >= MAX_CONCURRENT_RESOLVES {
            return None;
        }
        match ACTIVE_RESOLVES.compare_exchange(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Some(ResolveGuard),
            Err(next) => current = next,
        }
    }
}

pub fn resolve(name: &str, qtype: u16, config: &DnsConfig) -> Option<Vec<u8>> {
    resolve_internal(name, qtype, config.recursion_rounds, config)
}

#[allow(
    clippy::too_many_lines,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::similar_names
)]
fn resolve_internal(
    name: &str,
    qtype: u16,
    max_depth: usize,
    config: &DnsConfig,
) -> Option<Vec<u8>> {
    if max_depth == 0 {
        return None;
    }
    let _resolve_guard = acquire_resolve_slot()?;
    let sock = UdpSocket::bind(("0.0.0.0", 0)).ok()?;
    let _ = sock.set_read_timeout(Some(config.udp_timeout));

    if let Ok(mut roots) = cache::ROOT_CACHE.lock()
        && {
            cache::prune_cache(
                &mut roots,
                MAX_ROOT_CACHE_ENTRIES,
                |(_, _, exp): &RootCacheValue| Instant::now() >= *exp,
            );
            !roots.contains_key("__root__")
        }
        && !ROOT_HINTS.is_empty()
    {
        let exp = Instant::now() + Duration::from_secs(ROOT_CACHE_TTL_SECS);
        roots.insert(
            "__root__".to_string(),
            (Vec::new(), ROOT_HINTS.clone(), exp),
        );
    }

    if let Ok(mut c) = cache::CACHE.lock()
        && {
            cache::prune_cache(
                &mut c,
                MAX_QUERY_CACHE_ENTRIES,
                |(_, exp): &CacheValue| Instant::now() >= *exp,
            );
            true
        }
        && let Some((data, exp)) = c.get(&(name.to_string(), qtype))
        && Instant::now() < *exp
    {
        return Some(data.clone());
    }

    let requested_tld = tld_from_name(name);

    let mut servers: Vec<String> = if let Some(tld) = requested_tld.as_ref()
        && let Ok(delegations) = cache::DELEGATION_CACHE.lock()
        && {
            drop(delegations);
            true
        }
        && let Ok(mut delegations) = cache::DELEGATION_CACHE.lock()
        && {
            cache::prune_cache(
                &mut delegations,
                MAX_DELEGATION_CACHE_ENTRIES,
                |(_, exp): &DelegationCacheValue| Instant::now() >= *exp,
            );
            true
        }
        && let Some((cached, exp)) = delegations.get(tld)
        && Instant::now() < *exp
        && !cached.is_empty()
    {
        cached.clone()
    } else if let Ok(roots) = cache::ROOT_CACHE.lock()
        && let Some((_ns_names, glue_ips, exp)) = roots.get("__root__")
        && Instant::now() < *exp
        && !glue_ips.is_empty()
    {
        glue_ips.clone()
    } else {
        ROOT_HINTS.clone()
    };
    if servers.len() > MAX_UPSTREAM_SERVERS_PER_ROUND {
        servers.truncate(MAX_UPSTREAM_SERVERS_PER_ROUND);
    }
    let mut qname = name.to_string();
    let mut tried_root_fallback = false;
    for _round in 0..max_depth {
        let qid = rand::random::<u16>();
        let req = build_query(qid, &qname, qtype);
        let mut next_servers: Vec<String> = Vec::new();
        let mut round_servers = servers.clone();
        round_servers.shuffle(&mut rand::rng());
        if round_servers.len() > MAX_UPSTREAM_SERVERS_PER_ROUND {
            round_servers.truncate(MAX_UPSTREAM_SERVERS_PER_ROUND);
        }
        for srv in &round_servers {
            let mut resp_opt = send_recv(&sock, srv, &req, qid, &qname, qtype, config);
            if resp_opt.is_none() {
                resp_opt = tcp_send_recv(srv, &req);
            }
            if let Some(mut resp) = resp_opt {
                let flags = if resp.len() >= 4 {
                    u16::from_be_bytes([resp[2], resp[3]])
                } else {
                    0
                };
                if flags & 0x0200 != 0
                    && let Some(tcp_resp) = tcp_send_recv(srv, &req)
                {
                    resp = tcp_resp;
                }
                if resp.len() < 12 {
                    debug_log(
                        &format!("short response from {srv} while resolving {qname}"),
                        config,
                    );
                    continue;
                }
                let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
                let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
                #[allow(clippy::similar_names)]
                let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;
                let mut pos = 12usize;
                let (_qn, p2) = crate::dns::wire::parse_qname(&resp, pos)?;
                pos = p2 + 4;
                if ancount > 0
                    && let Some(ans_rrs) = parse_rrs(&resp, pos, ancount)
                {
                    let mut min_ttl: Option<u32> = None;
                    for (rtype, rpos, _rdlen, ttl) in &ans_rrs {
                        if *rtype == qtype {
                            if let Ok(mut c) = cache::CACHE.lock() {
                                cache::prune_cache(
                                    &mut c,
                                    MAX_QUERY_CACHE_ENTRIES,
                                    |(_, exp): &CacheValue| Instant::now() >= *exp,
                                );
                                let exp = Instant::now() + Duration::from_secs((*ttl).into());
                                c.insert((name.to_string(), qtype), (resp.clone(), exp));
                            }
                            debug_log(&format!("resolved {name} type {qtype} via {srv}"), config);
                            return Some(resp.clone());
                        }
                        if let Some(mt) = min_ttl {
                            if *ttl < mt {
                                min_ttl = Some(*ttl);
                            }
                        } else {
                            min_ttl = Some(*ttl);
                        }
                        if *rtype == 5
                            && let Some((cname, _)) = crate::dns::wire::parse_qname(&resp, *rpos)
                        {
                            qname = cname;
                            next_servers.clear();
                            break;
                        }
                    }
                }
                let auth_pos = if ancount > 0
                    && let Some(list) = parse_rrs(&resp, pos, ancount)
                {
                    list.last().map_or(pos, |(_, p, rd, _)| p + rd)
                } else {
                    pos
                };
                let authority_rrs = parse_rrs(&resp, auth_pos, nscount).unwrap_or_default();
                let referral_ttl_secs = authority_rrs
                    .iter()
                    .map(|(_, _, _, ttl)| u64::from(*ttl))
                    .min()
                    .unwrap_or(ROOT_CACHE_TTL_SECS);
                let after_auth = authority_rrs
                    .last()
                    .map_or(auth_pos, |last| last.1 + last.2);
                let additional_rrs = parse_rrs(&resp, after_auth, arcount).unwrap_or_default();
                let (ns_names, glue_ips) =
                    extract_ns_and_glue(&resp, &authority_rrs, &additional_rrs);

                if _round == 0
                    && !ns_names.is_empty()
                    && let Ok(mut roots) = cache::ROOT_CACHE.lock()
                {
                    let exp = Instant::now() + Duration::from_secs(ROOT_CACHE_TTL_SECS);
                    roots.insert(
                        "__root__".to_string(),
                        (ns_names.clone(), glue_ips.clone(), exp),
                    );
                }

                if glue_ips.is_empty() {
                    for nsname in ns_names {
                        if let Some(ip_resp) =
                            resolve_internal(&nsname, 1, max_depth - 1, config)
                            && ip_resp.len() >= 12
                        {
                            let an = u16::from_be_bytes([ip_resp[6], ip_resp[7]]) as usize;
                            if an > 0 {
                                let mut p = 12usize;
                                let Some((_q, p2)) =
                                    crate::dns::wire::parse_qname(&ip_resp, p)
                                else {
                                    continue;
                                };
                                p = p2 + 4;
                                if let Some(a_rrs) = parse_rrs(&ip_resp, p, an) {
                                    for (rt, rpos, rdlen, _) in a_rrs {
                                        if rt == 1 && rdlen == 4 {
                                            let ip = format!(
                                                "{}.{}.{}.{}",
                                                ip_resp[rpos],
                                                ip_resp[rpos + 1],
                                                ip_resp[rpos + 2],
                                                ip_resp[rpos + 3]
                                            );
                                            next_servers.push(ip);
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else {
                    for ip in glue_ips {
                        next_servers.push(ip);
                    }
                }
                if !next_servers.is_empty() {
                    next_servers.sort();
                    next_servers.dedup();
                    if next_servers.len() > MAX_UPSTREAM_SERVERS_PER_ROUND {
                        next_servers.truncate(MAX_UPSTREAM_SERVERS_PER_ROUND);
                    }
                    #[allow(clippy::used_underscore_binding)]
                    if _round == 0
                        && let Some(tld) = requested_tld.as_ref()
                        && let Ok(mut delegations) = cache::DELEGATION_CACHE.lock()
                    {
                        cache::prune_cache(
                            &mut delegations,
                            MAX_DELEGATION_CACHE_ENTRIES,
                            |(_, exp): &DelegationCacheValue| Instant::now() >= *exp,
                        );
                        let ttl = clamp_tld_ttl(referral_ttl_secs);
                        let exp = Instant::now() + Duration::from_secs(ttl);
                        delegations.insert(tld.clone(), (next_servers.clone(), exp));
                    }
                    servers.clone_from(&next_servers);
                    break;
                }
            } else {
                debug_log(
                    &format!("no response from {srv} while resolving {qname}"),
                    config,
                );
            }
        }

        if next_servers.is_empty()
            && !tried_root_fallback
            && !servers.is_empty()
            && servers != *ROOT_HINTS
        {
            tried_root_fallback = true;
            servers.clone_from(&ROOT_HINTS);
            continue;
        }

        if next_servers.is_empty() && servers == *ROOT_HINTS {
            tried_root_fallback = true;
        }
    }
    debug_log(
        &format!("resolution failed for {name} type {qtype}"),
        config,
    );
    None
}
