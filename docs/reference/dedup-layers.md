# Dedup Layers

Cross-request deduplication runs at three layers. Each one prevents a different waste or duplication problem at a different cost tier.

| Layer | Where | Key | Lifetime | Purpose |
|-------|-------|-----|----------|---------|
| **L1 — ContentFingerprint** | RAM (sharded dict) | `(conv_key, hash(field.text))` | TTL + LRU (default 30 min) | Skip re-scanning text already scanned in earlier requests of the same conversation |
| **L2 — FindingDedup** | RAM (sharded dict) | `(detector, type, hash(matched_value), session_id)` | TTL (default 30 min) | Skip re-recording the same finding within a session |
| **L3 — UNIQUE partial index** | SQLite `findings` table | `(content_hash, session_id, namespace_id)` where both non-empty | Persistent | Backstop after process restart; collapse on-conflict bumps `seen_count` |

Layered design means the right work is skipped at the right cost tier — L1 skips entire scans, L2 skips DB writes, L3 catches anything the in-memory layers miss.

---

## Layer 1 — ContentFingerprint

**Module:** `packages/proxy/lumen_argus/pipeline/_fingerprint.py`

**Problem solved:** Claude Code (and most AI tools) re-send the entire conversation history on every turn. Without dedup, scanning a 50-message conversation on its 50th turn would re-scan all 50 messages — O(n²) total work over the session.

**How it works:**

1. After extracting `ScanField`s from the request body, compute a SHA-256 hash of each field's text.
2. Look up `(conv_key, hash)` in the per-conversation `seen_hashes` set, where `conv_key = session.session_id`.
3. Fields whose hash is already present skip detection entirely.
4. New fields get scanned. On non-block actions, hashes are committed to the cache. On block, hashes stay "pending" until the proxy strips the offending content; only then are they committed.

**Storage:** 16 sharded dicts, each guarded by its own lock for low contention. LRU eviction once `max_conversations` is reached. TTL eviction (default 30 min) reclaims idle conversations.

**Block-then-strip invariant:** if a request is blocked and the hashes get committed prematurely, the same content would bypass scanning on retry. The two-phase commit (`filter_new_fields` returns hashes, `commit_hashes` is called only on success) prevents this.

**Empty `session_id`:** L1 is gated by `if conv_key:` and skipped entirely. Every field re-scans on every request — slower but correct (no global bucket).

---

## Layer 2 — FindingDedup

**Module:** `packages/proxy/lumen_argus/pipeline/_finding_dedup.py`

**Problem solved:** L1 prevents re-scanning, but if a scan was re-done (after L1 eviction, after a process restart, or because a block-retry path re-scanned the same content) and detected the same finding, you don't want a duplicate analytics row. L2 also collapses repeated findings within a single request (the same secret in two fields).

**How it works:**

1. Pipeline runs detection and policy. `result.findings` contains every detection.
2. `filter_new(findings, session_id)` looks up `(detector, type, hash(matched_value), session_id)` for each. New keys are returned; keys seen within the TTL window are dropped.
3. Only the filtered list is sent to `record_findings()` (analytics store).
4. **All** findings — new and dropped — still feed policy enforcement (block / redact / alert / log). Dedup never weakens action.

**Storage:** 16 sharded dicts, per-shard locks. Pure TTL eviction (default 30 min); no LRU.

**Empty `session_id`:** the cache is bypassed entirely (see [empty-session contract](#empty-session-id-contract)). Every finding is treated as new — no read, no write — so cross-user collapse is impossible by construction.

---

## Layer 3 — UNIQUE Partial Index

**Module:** `packages/proxy/lumen_argus/analytics/schema.py`, `analytics/findings.py`

**Problem solved:** L1 and L2 are in-memory only. After a process restart both are empty. Without L3, the same conversation re-sent post-restart would write duplicate rows. L3 also serves as a backstop for any code path that bypasses the in-memory layers (e.g. response-scan, MCP-scan, plugin paths).

**Index definition:**

```sql
CREATE UNIQUE INDEX idx_findings_dedup
  ON findings(content_hash, session_id, namespace_id)
  WHERE content_hash != '' AND session_id != '';
```

**Key fields:**

- `content_hash = sha256("detector|type|sha256(matched_value)[:16]")[:16]` — stored on the row.
- `session_id` — raw session id from `SessionContext`.
- `namespace_id` — multi-tenant scope (always `1` in community).

**Insert path:**

```sql
INSERT INTO findings (...)
VALUES (...)
ON CONFLICT(content_hash, session_id, namespace_id) WHERE content_hash != '' AND session_id != ''
DO UPDATE SET seen_count = seen_count + 1, timestamp = excluded.timestamp;
```

A new finding INSERTs with `seen_count = 1`. The same finding re-sent in the same session (e.g. after a restart wiped L2) UPDATEs the existing row and bumps `seen_count`. No duplicate rows.

**Predicate carve-outs:** `WHERE content_hash != '' AND session_id != ''` excludes two row classes from the constraint:

- `content_hash = ''` — legacy or migration rows that did not compute a hash.
- `session_id = ''` — requests with no resolvable session (see [empty-session contract](#empty-session-id-contract)). The constraint must not collapse multiple unknown-session users into a single row.

---

## Empty session_id contract {#empty-session-id-contract}

A `session_id` of `""` reaches the dedup layers when every extraction path failed: no `x-session-id` header, no `x-opencode-session` / `x-session-affinity`, no provider-metadata session, and the derived fingerprint had fewer than two parts to hash. This is rare on healthy traffic but reachable on malformed bodies, probes, or after a regression in `session.extract_session`.

The defended contract:

| Layer | Behavior with empty `session_id` |
|-------|----------------------------------|
| L1 ContentFingerprint | Skipped (`if conv_key:` gate) — every field re-scans |
| L2 FindingDedup | Cache bypassed — `is_new` and `filter_new` early-return; no read, no write |
| L3 UNIQUE partial index | Predicate excludes the row from the constraint — every insert lands as a new row |

Without these carve-outs, all unknown-session requests would share a single bucket per layer, and the first finding would suppress every subsequent one for the TTL window — across all users hitting the same condition.

**Observability:** two throttled WARNINGs surface the upstream condition without flooding the log:

- `argus.pipeline` — fired from `ScannerPipeline.scan` at the L2 boundary.
- `argus.analytics` — fired from `FindingsRepository.record` at the L3 boundary. Defence-in-depth: response-scan, MCP-scan, and reload-import paths reach `record()` without going through the pipeline, so the storage layer is the only place that catches every empty-session insert.

Each warning emits at most once per minute and rolls the suppressed count into the next emission. The implementation lives in `packages/proxy/lumen_argus/_throttled_log.py` (`ThrottledWarning`).

Per-user attribution for empty-session findings is preserved via the `source_ip`, `api_key_hash`, `hostname`, and `username` columns on each row.

---

## Worked example — populated session_id

Three turns of an Anthropic conversation on `session_id = "fp:a3b1c2d4"`. The first user message contains a secret. Constants:

- AWS access key: `AKIAIOSFODNN7EXAMPLE` (well-known example value)
- `value_hash = sha256("AKIAIOSFODNN7EXAMPLE")[:16] = "f3d8a91b2c4e5d6f"` (illustrative)
- `content_hash = sha256("secrets|aws_access_key|f3d8a91b2c4e5d6f")[:16] = "7a2b…"` (illustrative)

### Turn 1 — first request

Request:

```json
{
  "model": "claude-opus-4-7",
  "system": "You are a coding assistant. cwd=/Users/alice/proj",
  "messages": [
    {"role": "user", "content": "Help me debug this AWS key: AKIAIOSFODNN7EXAMPLE"}
  ]
}
```

Pipeline trace:

```
extractor.extract(...) returns 2 ScanFields:
  [0] path="system",              text="You are a coding assistant…"
  [1] path="messages[0].content", text="Help me debug this AWS key: AKIA…"

L1 ContentFingerprint:
  conv_key = "fp:a3b1c2d4"
  shard[7]["fp:a3b1c2d4"] absent → both fields are NEW
  pending_hashes = ("fp:a3b1c2d4", ["e4f1…", "9c7a…"])

Detection: hits AWS access key → Finding(detector="secrets", type="aws_access_key", …)
Policy:    action = "alert" → commit_hashes(pending_hashes)

L1 after Turn 1:
  shard[7] = {
    "fp:a3b1c2d4": ConversationCache(seen_hashes={"e4f1…", "9c7a…"}, last_access=now)
  }

L2 FindingDedup:
  key = ("secrets", "aws_access_key", "f3d8a91b2c4e5d6f", "fp:a3b1c2d4")
  shard[3][key] absent → new
  shard[3][key] = monotonic_now

L3 SQLite:
  INSERT … content_hash="7a2b…" session_id="fp:a3b1c2d4" seen_count=1
  (no conflict; partial-index predicate true)
```

DB state: 1 row, `seen_count = 1`.

### Turn 2 — conversation grows

Claude Code re-sends history plus a new assistant reply and a new user follow-up:

```json
{
  "messages": [
    {"role": "user",      "content": "Help me debug this AWS key: AKIAIOSFODNN7EXAMPLE"},
    {"role": "assistant", "content": "I see the AWS access key in your message…"},
    {"role": "user",      "content": "Should I rotate it?"}
  ]
}
```

```
L1 lookup on 4 fields (system + 3 messages):
  e4f1… in seen_hashes → SKIP
  9c7a… in seen_hashes → SKIP
  b8e2… NEW                ← assistant reply
  5d04… NEW                ← "Should I rotate it?"

skipped = 2 → bump_seen_counts("fp:a3b1c2d4")
  UPDATE findings SET seen_count = seen_count + 1 WHERE session_id = 'fp:a3b1c2d4';
  → Turn 1 row now has seen_count = 2.

Detection on the 2 new fields: clean. No findings.
L2: nothing to dedup.
L3: no INSERT.
```

DB state: 1 row, `seen_count = 2`.

### Turn 3 — user pastes the same key again

User: `"Just to confirm, this is the key: AKIAIOSFODNN7EXAMPLE"` (different surrounding text → different field hash).

```
L1: new field → scan
Detection: same matched_value as Turn 1
L2: key = ("secrets", "aws_access_key", "f3d8a91b2c4e5d6f", "fp:a3b1c2d4")
    present in shard[3] within TTL → is_new returns False → drop

record_findings called with empty list. No DB write.
```

DB state unchanged: 1 row, `seen_count = 2`.

If L1 had missed (cache evicted before Turn 3), the finding would have re-detected — and L3's `ON CONFLICT … DO UPDATE seen_count = seen_count + 1` would have caught the duplicate at the storage layer. Defence in depth.

---

## Worked example — empty session_id (the cross-user case)

Three users behind a central proxy, each sends a request whose extraction yielded `session_id = ""` and detection returned the same `aws_access_key` finding:

| User | source_ip | api_key_hash | session_id | matched_value |
|------|-----------|--------------|------------|---------------|
| A | 10.0.0.1 | aaaa1111 | `""` | `AKIAIOSFODNN7EXAMPLE` |
| B | 10.0.0.2 | bbbb2222 | `""` | `AKIAIOSFODNN7EXAMPLE` |
| C | 10.0.0.3 | cccc3333 | `""` | `AKIAIOSFODNN7EXAMPLE` |

```
L1: conv_key = "" → if conv_key: is False → L1 skipped for all three.

L2: with the empty-session contract in place,
    is_new(finding, session_id="") returns True without touching the cache.
    All 3 findings reach record_findings.

    Pipeline emits one throttled WARNING (1/min):
    WARNING argus.pipeline empty session_id at finding-dedup boundary:
      provider=anthropic findings=1 (dedup bypassed; 0 similar warnings
      suppressed in last 60s)

    Users B and C land inside the throttle window → counter increments.

L3: predicate WHERE content_hash != '' AND session_id != ''
    User A insert: '7a2b…' != ''  AND  '' != ''  → predicate FALSE
                   row not in partial index → no UNIQUE check → plain INSERT
    User B insert: same → plain INSERT
    User C insert: same → plain INSERT

    Storage emits one throttled WARNING (1/min):
    WARNING argus.analytics empty session_id at findings storage:
      provider=anthropic findings=1 (unique-index bypassed; 0 similar
      warnings suppressed in last 60s)
```

DB state:

```
id=1  source_ip=10.0.0.1  api_key_hash=aaaa1111  session_id=""  seen_count=1
id=2  source_ip=10.0.0.2  api_key_hash=bbbb2222  session_id=""  seen_count=1
id=3  source_ip=10.0.0.3  api_key_hash=cccc3333  session_id=""  seen_count=1
```

Per-user attribution preserved via the network/identity columns. Operator sees two distinct WARNINGs (one per layer) confirming the upstream extraction gap, without log flood.

---

## Failure-mode matrix

| Failure | L1 catches | L2 catches | L3 catches |
|---------|:----------:|:----------:|:----------:|
| Conversation history re-sent | ✓ skip re-scan | – | – |
| L1 evicted (TTL/LRU) before retry | ✗ | ✓ skip re-record | ✓ on-conflict bump |
| Process restart between requests | ✗ wiped | ✗ wiped | ✓ on-conflict bump |
| Same secret in two fields of one request | ✗ different field hashes | ✓ same `(detector, type, value)` key | ✓ same `content_hash` |
| Code path bypasses pipeline (response-scan, MCP, reload) | ✗ | ✗ | ✓ |

---

## Tuning

```yaml
# .lumen-argus.yaml
dedup:
  conversation_ttl_minutes: 30          # L1 TTL
  finding_ttl_minutes: 30               # L2 TTL
  max_conversations: 10000              # L1 LRU cap (must be >= 16, the shard count)
  max_hashes_per_conversation: 5000     # L1 per-conversation cap
```

L3 has no tunable — partial-index semantics are fixed in schema.

## Related modules

- `packages/proxy/lumen_argus/pipeline/_pipeline.py` — orchestration + L1/L2 call sites
- `packages/proxy/lumen_argus/pipeline/_fingerprint.py` — L1 implementation
- `packages/proxy/lumen_argus/pipeline/_finding_dedup.py` — L2 implementation
- `packages/proxy/lumen_argus/analytics/schema.py` — L3 index definition
- `packages/proxy/lumen_argus/analytics/findings.py` — L3 INSERT path
- `packages/proxy/lumen_argus/_throttled_log.py` — `ThrottledWarning` helper for both empty-session warnings
