# ADR 0041 - Bound untrusted resource state

- **Status:** Accepted
- **Date:** 2026-08-02
- **Deciders:** gamlastan maintainers
- **Implementation:** `crates/gamlastan-mdq/src/{fetch,client}.rs`, `crates/gamlastan/src/metadata/cache.rs`, `crates/gamlastan-actix/src/config.rs`, `spid-sp-test/src/main.rs`

## Context

Remote MDQ responses and attacker-selected entity IDs influence memory usage.
The default fetcher allowed a 200 MiB response for each concurrent request and
the dynamic metadata cache had no entry bound. The SPID conformance harness also
retained pending request IDs indefinitely and could panic while logging a UTF-8
response preview at an arbitrary byte offset. The ready Actix SP's request-ID
tracker likewise grew with every hit on the unauthenticated login endpoint,
bounded only by the five-minute TTL window.

## Decision

1. The default MDQ response cap is 10 MiB and at most eight bodies are fetched
   concurrently. `ReqwestFetcher::with_limits` permits deliberate aggregate use.
2. Dynamic MDQ caches hold at most 1024 entries by default, purge invalid
   entries first, and evict the oldest fetch when full. Capacity is configurable;
   zero disables caching.
3. The SPID harness limits pending requests to 1024, expires them after five
   minutes, and consumes correlation atomically.
4. `InMemoryRequestIdTracker` holds at most 1024 outstanding request IDs by
   default (`with_limits` to change), purging expired entries first and
   evicting the oldest live entry at capacity. Eviction, not refusal: the
   current login proceeds and under a flood the evicted entries are
   overwhelmingly the flooder's own.
5. Diagnostic previews truncate by Unicode scalar boundary rather than byte
   offset.

## Consequences

- A single process has explicit default bounds for remote response buffering and
  attacker-driven metadata cardinality.
- Operators ingesting large federation aggregates must choose and configure a
  larger body limit rather than inheriting it from per-entity MDQ defaults.
- Capacity pressure returns an explicit response instead of growing memory
  without bound.
- A sustained login flood can evict legitimate outstanding request IDs (those
  logins fail at the ACS and must restart); this bounded-availability trade is
  preferred over unbounded memory growth.

