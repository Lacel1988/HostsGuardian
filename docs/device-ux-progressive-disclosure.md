# Roadmap #4 — Device UX / Progressive Disclosure

Automated candidate; human acceptance pending. This is targeted polish, not a replacement architecture.

The existing independently scrollable list/details and collapsible Identity Details are retained. Friendly name/type editing now appears before technical details. Import and delivery labels show direction. Saving identity locally remains separate from sending the entire policy, because other policy changes may be included.

Registration remains explicit, unique-evidence guarded and backed by persisted registry membership. No orphan metadata resurrection. Unknown remains valid. Confirmed type overrides inference; classification retention is unchanged.

Workflow presentation derives from unsaved name/type comparisons, canonical local/baseline policy comparison and existing authenticated Engine confirmation/freshness. Unsaved edits take priority; pending is unconfirmed; failed or unavailable requests cannot claim success; saved locally does not imply delivery. Synchronization expires with existing status proof. No separate delivered-but-not-confirmed claim is available from the current API wrapper.

Import requires explicit confirmation and warns about unsaved/unsynchronized device changes. Cancel preserves them; confirm permits replacement, with orphan reconciliation. Sending is blocked until identity edits are saved. First-time baseline acquisition still requires import: perform it before registering/editing. No automatic ambiguous merge is introduced.

Engine executes. Monitor observes. WPF decides. No production deployment. Roadmap #5 is outside this checkpoint.
