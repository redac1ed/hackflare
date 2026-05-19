use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

pub(super) type CacheKey = (String, u16);
pub(super) type CacheValue = (Vec<u8>, Instant);
pub(super) type RootCacheValue = (Vec<String>, Vec<String>, Instant);
pub(super) type DelegationCacheValue = (Vec<String>, Instant);

pub(super) static CACHE: std::sync::LazyLock<Mutex<HashMap<CacheKey, CacheValue>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
pub(super) static ROOT_CACHE: std::sync::LazyLock<Mutex<HashMap<String, RootCacheValue>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));
pub(super) static DELEGATION_CACHE: std::sync::LazyLock<
    Mutex<HashMap<String, DelegationCacheValue>>,
> = std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

pub(super) fn prune_cache<K, V>(
    cache: &mut HashMap<K, V>,
    max_entries: usize,
    is_expired: impl Fn(&V) -> bool,
) where
    K: Clone + Eq + std::hash::Hash,
{
    cache.retain(|_, v| !is_expired(v));
    while cache.len() > max_entries {
        if let Some(key) = cache.keys().next().cloned() {
            cache.remove(&key);
        } else {
            break;
        }
    }
}
