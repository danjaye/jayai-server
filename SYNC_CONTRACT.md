# jay-ai sync contract — AGREED v1 + v8 addendum (IMPLEMENTED)

Goal: chats, memories, and settings follow the account across devices.
The server is the authority (ChatGPT/Claude-style): per-blob revs,
server-assigned timestamps, last-write-wins, deletes via tombstones.
Devices are fast caches + offline queues. Guest mode (no token) never syncs
and never prompts.

(v1 note, kept for history: the server was originally a backup + relay with
client-set timestamps and no chat deletes. v8 below supersedes that.)

Server half: implemented here. Client half: app helper (jay-ai generator).

## Data model

Three blob collections. Blob key = `(user, collection, id)`.

- `chats` — id = chat.id. data = full chat object
  `{ id, title, createdAt, activeRootId, messages: [...] }`.
  Merge rule (client): **union by message.id** (edits/regens only ever ADD
  nodes, so set-union is safe); `title`/`activeRootId`/per-node
  `activeChildId` last-write-wins by server `updatedAt`. Deletes ARE
  tombstones (v8): a delete on one device removes the chat on every device.
  Re-PUTing a tombstoned id resurrects it (a normal live blob again).
- `memories` — id = slug of the file path (`memories/foo-bar.md` → id
  `foo-bar`). data = `{ path, content, updatedAt }`. Merge (client):
  last-write-wins per path by `updatedAt`. Deletes ARE tombstones:
  data = `{ path, deleted: true, updatedAt }` (kept 30 days, then GC'd).
  Re-PUTing a tombstoned id resurrects it (a normal live blob again).
- `settings` — id MUST be `"main"` (anything else → 400). data =
  `{ userName, userAbout, customPrompt, memoriesEnabled, injections, version,
    updatedAt }`. Merge (client): whole-blob last-write-wins by `updatedAt`.
- OUT of v1: `images/` binaries (large, need separate upload flow). Phase 2.

Every blob carries `updatedAt` (ms epoch). Since v8 the server assigns it from
the server clock on every PUT/DELETE and returns it — client-sent `updatedAt`
is still required (positive number, back-compat) but ignored for ordering, so
device clock skew can never win last-write-wins. Server assigns `rev`
(monotonic int per blob, starts at 1) and stores `bytes` (byte length of the
canonical JSON of `data`).

## Endpoints (all Bearer token, all JSON)

- `GET /api/sync/:collection`
  → `200 { items: [{ id, rev, updatedAt, bytes, deleted? }] }`
  (manifest; `deleted` only for tombstoned chats/memories). Unknown collection → 404.
- `GET /api/sync/:collection/:id`
  → `200 { id, rev, updatedAt, data }`. Tombstone → same shape plus
  `deleted: true` (memories tombstone data carries the file `path`; chats
  tombstone data is `{ deleted: true, updatedAt }`).
  Missing → 404.
- `PUT /api/sync/:collection/:id` `{ updatedAt, data, baseRev? }`
  → `200 { id, rev, updatedAt }` (both server time), or
  `200 { id, rev, updatedAt, conflict: true, server: { rev, updatedAt } }`
  when `baseRev` is set and no longer current. The server ALWAYS writes
  (last write wins); `server.*` are the POST-write values so the client can
  update its base and pull-merge-repush. `baseRev` omitted/null = blind write,
  never a conflict.
  → `400` bad shape/id; `409` over per-blob size cap; `413` over user quota.
- `DELETE /api/sync/:collection/:id` → tombstone for `memories` AND `chats`
  (`200 { id, rev, updatedAt, deleted: true }`); for `settings` → `400`
  (client never deletes settings). Missing id → `404`. Tombstone
  `updatedAt` is server time (DELETE carries no body). PUT on a tombstoned id
  resurrects it as a normal live blob.

Validation: collection ∈ {chats, memories, settings}; id `[A-Za-z0-9_-]{1,128}`
(the charset alone blocks path traversal; tombstone paths are built
server-side as `memories/<id>.md`). `data` must be a JSON object (not null,
not an array).
Caps: chats 5 MB/PUT, memories 200 KB/PUT, settings 100 KB/PUT;
quota 50 MB/user (tunable via `SYNC_QUOTA_MB`, tombstones count toward it).

Rate limits: sync reads 60/min per user, writes 20/min per user — separate
bucket from search/fetch and auth. Auth: existing Bearer tokens, 30-day
lifetime; user isolation by token → user_id on EVERY query (no cross-user
reads, ever). SQLite: `blobs(user_id, collection, blob_id, rev, updated_at,
bytes, data, deleted)` + unique index on the key.

## Client behavior (app helper implements after server ships)

- Dirty tracking: wrap `saveState()` — mark collection dirty, debounce 20s,
  sync on `visibilitychange` hidden + after each assistant turn settles.
- Cycle per collection: manifest → pull server-newer (merge per rules above)
  → push local-dirty (with `baseRev` from last sync state in
  `localStorage["jay-ai-sync-state"]`).
- First login: if server manifest empty and local non-empty → push all; if
  local fresh and server non-empty → pull; if both → merge per rules. Never
  destructive: no mass deletes, tombstones only from explicit user deletes.
- UI: one row in the You menu — `Synced 12:03` / `Syncing…` / `Sync failed`
  (tap retries). Hidden entirely for guests. No model prompt changes: sync is
  invisible to all versions (no VERSIONING implications).

## Open questions — answered

1. **50 MB quota sane?** Yes. SQLite handles it easily; tunable via
   `SYNC_QUOTA_MB` without a code change.
2. **Tombstone GC at 30 days?** Yes, implemented: the periodic cleanup
   deletes tombstones older than 30 days.
3. **`images/` in v1?** No — deferred to phase 2 (binary upload + bandwidth
   is a separate project).
