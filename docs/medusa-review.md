# Medusa read-only review route

`/founder/medusa` is integrated into the existing founder session boundary. It compares submitted UTF-8 text against an expected SHA-256 and checks whether a quotation of at least 12 characters occurs verbatim. It never declares independent truth, grants authority, fetches remote targets or performs changes. No application-level storage is used. Submitted text is not echoed. This is a bounded evidence-review primitive, not the full offline Medusa assessment engine.

Six isolated Node tests passed locally. Two additional founder-session integration tests are committed for CI; the complete Worker build, current CI, authenticated preview and deployed behavior are not yet verified. Do not claim production launch on this commit alone.
