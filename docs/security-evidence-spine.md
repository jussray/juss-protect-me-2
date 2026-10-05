# Protect Me 2 — Security Evidence Spine

Protect Me 2 is the systems-first member of the Protect Me family. It protects repositories, AI agents, CI/CD, cloud runtimes, and edge traffic. It is intentionally different from Protect Me Model One, which protects people, accounts, devices, browsers, and personal identity.

## End-to-end security path

```text
request / agent / workflow / runtime signal
  -> Shield / Gate / provider readback
  -> individually addressable evidence receipt
  -> exact source + dependency + runtime identity check
  -> stale / blocked / failed / unknown cannot hide beside green proof
  -> required checks must each have current VERIFIED evidence
  -> separate founder approval bound to exact repository + commit
  -> governed action may proceed
```

## Non-negotiable invariants

1. **Evidence is not authority.** Every receipt is forced to `authority.level = evidence_only` and `canAuthorize = false`.
2. **No short identity.** Source authority requires a full 40-character Git SHA.
3. **Proof expires structurally.** A source, lockfile, runtime build, or deployment identity change makes prior proof stale.
4. **Green cannot hide red.** A blocked, failed, unknown, or stale receipt prevents governed action even when required checks are green.
5. **Each required layer is individually proven.** A passing typecheck cannot stand in for Playwright, provider smoke, or deployment identity.
6. **Shield receipts distinguish authenticity.** HMAC-backed observations may become `verified`; plain SHA-256 integrity receipts remain `inferred`.
7. **Founder approval is external to the ledger.** A receipt ID cannot be reused as an approval ID.
8. **No secret values in receipts.** Evidence references identify artifacts or observations without embedding provider credentials.

## Product boundary

Protect Me 2 should outshine Model One at:

- AI-agent authority boundaries;
- repository and patch governance;
- software-supply-chain identity;
- CI/CD and deployment proof;
- cloud/runtime drift detection;
- edge defense and scanner/bot classification;
- cross-repository blast-radius reasoning;
- tamper-evident technical incident receipts.

Model One should outshine Protect Me 2 at:

- consumer endpoint protection;
- account and identity protection;
- scam/deepfake protection for people;
- browser/device privacy;
- family safety and recovery.

Neither system may borrow the other's authority merely because it trusts the other's evidence.

## Competitive claim boundary

This architecture is a differentiation target, not proof that Protect Me 2 already outperforms established security vendors. Claims of superiority require independently reviewable evidence for the exact capability being compared.
