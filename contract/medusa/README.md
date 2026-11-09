# Medusa 1.1 · Offline evidence-aware red-team kit

This is a local, standard-library-only implementation of the standalone Medusa skill. It does **not** auto-generate red-team findings: a human or authorized reviewer fills the assessment JSON. The checker verifies in-scope artifact identity, exact quoted passages, required attack/adversary fields, rebuttal shape, custody, reversal, source-of-knowledge tags, and advisory verdict consistency. It cannot prove the truth of a source or any reviewer's personal identity.

## Start locally (no network required)

```bash
python3 -m unittest discover -s . -p 'test_medusa*.py' -v
python3 medusa.py gate assessment.example.json  # exits 2: incomplete on purpose
python3 medusa.py gate demo_assessment.json      # locally valid synthetic fixture
python3 medusa.py gate demo_assessment.json --only # always exits 2, diagnostic-only
python3 medusa.py snapshot demo_assessment.json --ledger ./demo-ledger.jsonl
python3 medusa.py verify-ledger ./demo-ledger.jsonl
python3 medusa.py protect demo_assessment.json --out ./demo-protected.json
```

To assess real material, copy the example JSON, fill actual preflight/adversaries/findings, name a local file in `material`, supply its SHA-256, and quote the exact passage in `stone.quote` and each `VERIFIED` finding. Mark unverifiable claims `UNVERIFIED` and include `check_needed`. `source_of_knowledge` is independent of `evidence_tag`. Do not use the synthetic demo as evidence for a real decision.

## Fetching is separate and explicitly authorized

```bash
# This command actually contacts a remote site: invoke only on an approved URL.
python3 medusa_fetch.py fetch https://example.org/ --out ./incoming --name home.html
python3 medusa_fetch.py admit ./incoming/home.html
```

`admit` validates local bytes against a manifest; it does **not** admit the file into a Medusa assessment or certify its content, origin, consent or trust. The reviewer must open it, decide whether it belongs in scope, and manually include the path, hash and relevant passage in the assessment. Only the fetcher uses sockets; `medusa.py`, `SKILL.md`, and assessment checks are offline.

Fetcher boundaries: one GET, HTTPS default, no redirect, no auth/cookies, public IP resolution pinned to TCP and TLS SNI, 5 MiB byte cap, allowed content types, redacted URL provenance, safe filenames, non-overwrite of both evidence and manifest, and symlink refusal. Client-side JavaScript rendering, private-page authentication and crawler features are deliberately absent.

## Assurance and authority boundary

A structural gate exiting `0` does **not** mean a security issue has been fixed, a human has approved it or a deployment may proceed. Every gate result contains `authority=evidence_only`, `can_authorize=false` and `independent_truth_verified=false`. `--only` exits 2 even for a complete diagnostic. Medusa remains read-only with respect to target projects; fetching requires a separate, human-invoked command. The redaction exporter is pattern-based and still requires manual review for broad audiences. Any filesystem writer with access to the assessment directory can race against later human use, so consuming gates must re-hash files at the point of decision.

No A–D deployment or Part E activation is implied. Before production use, run the complete suite on the actual target machine, perform source-authenticity and redaction review, verify release authority independently and run applicable real-path and CI checks at current `main` and exact feature head. No working exploit code, third-party probing or active retaliation is included.
