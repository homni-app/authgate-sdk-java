package io.authgate.cache;

import io.authgate.application.port.CacheStore;

import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Default in-memory {@link CacheStore} backed by {@link ConcurrentHashMap}.
 * Expired entries are evicted lazily on access.
 */
public final class InMemoryCacheStore implements CacheStore {

    private static final int MAX_ENTRIES = 256;

    private final ConcurrentHashMap<String, Entry> store = new ConcurrentHashMap<>();

    @Override
    public String get(String key) {
        Entry entry = store.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            store.remove(key, entry);
            return null;
        }
        return entry.value();
    }

    @Override
    public void put(String key, String value, Duration ttl) {
        if (store.size() >= MAX_ENTRIES && !store.containsKey(key)) {
            evictExpired();
            evictOldest();
        }
        store.put(key, new Entry(value, Instant.now().plus(ttl)));
    }

    private void evictExpired() {
        store.entrySet().removeIf(e -> e.getValue().isExpired());
    }

    private void evictOldest() {
        store.entrySet().stream()
                .min(Comparator.comparing(e -> e.getValue().expiresAt()))
                .map(Map.Entry::getKey)
                .ifPresent(store::remove);
    }

    @Override
    public void evict(String key) {
        store.remove(key);
    }

    private record Entry(String value, Instant expiresAt) {
        boolean isExpired() {
            return Instant.now().isAfter(expiresAt);
        }
    }
}
